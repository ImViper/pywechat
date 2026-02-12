"""End-to-end acceptance runner for Hook batch comment flow.

This script automates the full lifecycle:
1. (Optional) restart WeChat process.
2. Open WeChat Moments UI.
3. Ensure DLL hook pipe is reachable (auto-inject optional).
4. Locate a target post from Moments feed.
5. (Optional) send one UI warmup comment to refresh hook capture state.
6. Run N rounds of batch comments and collect strict metrics.
7. Save JSON report.
8. Close WeChat process.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import statistics
import sys
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin
from urllib.request import Request, urlopen

import psutil
import pyautogui
import pythoncom
import win32con
import win32gui

PROJECT_ROOT = Path(__file__).resolve().parent.parent
MAX_BENCHMARK_ROUNDS = 10  # Reasonable limit for stability testing
sys.path.insert(0, str(PROJECT_ROOT))

from pyweixin.WeChatTools import Lists, Navigator, Tools
from pyweixin.comment_dispatcher import CommentDispatcher
from pyweixin.hook_bridge import HookBridge
from pyweixin.hook_injector import find_wechat_pid, inject_dll, is_dll_loaded
from pyweixin.moments_ext import comment_flow


def _log(msg: str) -> None:
    now = datetime.now().strftime("%H:%M:%S")
    print(f"[{now}] {msg}", flush=True)


def _iter_wechat_processes() -> list[psutil.Process]:
    procs: list[psutil.Process] = []
    for proc in psutil.process_iter(["pid", "name"]):
        if proc.info.get("name") == "Weixin.exe":
            procs.append(proc)
    return procs


def _terminate_wechat(force: bool, timeout_s: float = 6.0) -> None:
    procs = _iter_wechat_processes()
    if not procs:
        return
    for proc in procs:
        try:
            proc.terminate()
        except Exception:
            pass
    gone, alive = psutil.wait_procs(procs, timeout=timeout_s)
    if force and alive:
        for proc in alive:
            try:
                proc.kill()
            except Exception:
                pass
        psutil.wait_procs(alive, timeout=2.0)
    _log(f"WeChat processes terminated: {len(gone) + len(alive)}")


def _open_moments_with_retry(
    *,
    window_maximize: bool,
    retries: int,
    retry_delay_ms: int,
    open_attempt_timeout_s: float,
) -> Any:
    def _open_once(timeout_s: float) -> Any:
        if timeout_s <= 0:
            return Navigator.open_moments(is_maximize=False, close_weixin=False)

        holder: dict[str, Any] = {}
        err_holder: dict[str, BaseException] = {}
        done = threading.Event()

        def _worker() -> None:
            try:
                pythoncom.CoInitialize()
            except Exception:
                pass
            try:
                holder["value"] = Navigator.open_moments(is_maximize=False, close_weixin=False)
            except BaseException as exc:
                err_holder["err"] = exc
            finally:
                try:
                    pythoncom.CoUninitialize()
                except Exception:
                    pass
                done.set()

        t = threading.Thread(target=_worker, daemon=True)
        t.start()
        if not done.wait(timeout=max(timeout_s, 1.0)):
            raise TimeoutError(f"open_moments timeout after {timeout_s:.1f}s")
        if "err" in err_holder:
            raise err_holder["err"]
        return holder.get("value")

    last_exc: Exception | None = None
    for attempt in range(1, max(retries, 1) + 1):
        try:
            moments_window = _open_once(open_attempt_timeout_s)
            if window_maximize:
                try:
                    win32gui.SendMessage(
                        moments_window.handle,
                        win32con.WM_SYSCOMMAND,
                        win32con.SC_MAXIMIZE,
                        0,
                    )
                except Exception:
                    pass
            return moments_window
        except Exception as exc:
            last_exc = exc
            _log(f"Open Moments attempt {attempt}/{retries} failed: {exc}")
            if attempt < retries:
                time.sleep(max(retry_delay_ms, 200) / 1000.0)
    assert last_exc is not None
    raise RuntimeError(
        f"failed to open Moments after {retries} attempts: {last_exc}"
    ) from last_exc


def _normalize_text(text: str) -> str:
    return re.sub(r"\s+", " ", (text or "")).strip()


def _resolve_comment_anchor(moments_list, selected_item):
    try:
        items = moments_list.children(control_type="ListItem")
    except Exception:
        return None

    selected_idx = -1
    for idx, item in enumerate(items):
        if item == selected_item:
            selected_idx = idx
            break

    if selected_idx >= 0:
        for offset in range(1, 5):
            idx = selected_idx + offset
            if idx >= len(items):
                break
            candidate = items[idx]
            try:
                cls_name = candidate.class_name()
            except Exception:
                cls_name = ""
            if "TimelineCommentCell" in cls_name:
                return candidate

    try:
        return Tools.get_next_item(moments_list, selected_item)
    except Exception:
        return None


def _locate_target_item(moments_window, target_author: str, max_scan: int) -> dict[str, Any]:
    moments_list = moments_window.child_window(**Lists.MomentsList)
    try:
        moments_list.set_focus()
    except Exception:
        pass

    try:
        moments_list.type_keys("{HOME}")
    except Exception:
        pyautogui.press("home")
    time.sleep(0.08)

    skip_class_tokens = ("TimelineCommentCell", "TimelineCell", "TimelineAdGridImageCell")
    for i in range(max_scan):
        try:
            moments_list.type_keys("{DOWN}", pause=0.05)
        except Exception:
            pyautogui.press("down")

        try:
            focused = [li for li in moments_list.children(control_type="ListItem") if li.has_keyboard_focus()]
        except Exception:
            continue
        if not focused:
            continue

        item = focused[0]
        try:
            cls_name = item.class_name()
        except Exception:
            cls_name = ""
        if any(token in cls_name for token in skip_class_tokens):
            continue

        try:
            text = _normalize_text(item.window_text())
        except Exception:
            text = ""
        if not text:
            continue

        parts = text.split(" ", 1)
        author = parts[0].strip() if parts else ""
        if target_author and (target_author not in author):
            continue

        anchor = _resolve_comment_anchor(moments_list, item)
        return {
            "moments_list": moments_list,
            "content_item": item,
            "anchor": anchor,
            "author": author,
            "text_preview": text[:100],
            "scan_index": i + 1,
        }

    raise RuntimeError(
        f"cannot find target post in first {max_scan} items (target_author={target_author!r})"
    )


def _percentile(values: list[int], p: float) -> int:
    if not values:
        return 0
    if len(values) == 1:
        return int(values[0])
    ordered = sorted(values)
    idx = (len(ordered) - 1) * p
    lo = int(idx)
    hi = min(lo + 1, len(ordered) - 1)
    if lo == hi:
        return int(ordered[lo])
    frac = idx - lo
    return int(round(ordered[lo] * (1.0 - frac) + ordered[hi] * frac))


def _pick_dll_path(explicit_path: str | None) -> Path:
    candidates: list[Path] = []
    if explicit_path:
        candidates.append(Path(explicit_path))
    env_path = os.environ.get("PYWEIXIN_HOOK_DLL", "").strip()
    if env_path:
        candidates.append(Path(env_path))
    candidates.extend(
        [
            PROJECT_ROOT / "hook" / "build_opt10" / "bin" / "Release" / "pywechat_hook.dll",
            PROJECT_ROOT / "hook" / "build" / "bin" / "Release" / "pywechat_hook.dll",
            PROJECT_ROOT / "hook" / "build" / "Release" / "pywechat_hook.dll",
            PROJECT_ROOT / "hook" / "build" / "pywechat_hook.dll",
            PROJECT_ROOT / "pywechat_hook.dll",
        ]
    )

    for p in candidates:
        if p.is_file():
            return p.resolve()
    raise FileNotFoundError(
        "cannot locate pywechat_hook.dll; pass --dll-path or set PYWEIXIN_HOOK_DLL"
    )


def _ensure_hook_pipe(args, pid: int) -> tuple[HookBridge, bool]:
    bridge = HookBridge(timeout_ms=args.pipe_timeout_ms)
    if bridge.connect() and bridge.ping():
        return bridge, False

    if not args.auto_inject:
        raise RuntimeError("hook pipe unavailable and --auto-inject is disabled")

    dll_path = _pick_dll_path(args.dll_path)
    _log(f"Injecting DLL: {dll_path}")
    loaded_before = is_dll_loaded(pid)
    if not loaded_before:
        inject_dll(pid, str(dll_path))
    else:
        _log("DLL already loaded, waiting for pipe server")

    for _ in range(20):
        if bridge.connect() and bridge.ping():
            return bridge, not loaded_before
        time.sleep(0.2)
    raise RuntimeError("failed to connect hook pipe after injection/wait")


def _ensure_env(args) -> None:
    backend = str(getattr(args, "backend", "real")).strip().lower()
    http_provider = str(getattr(args, "http_provider", "")).strip().lower()
    if backend in {"http", "mock_http"}:
        # Keep hook management (inject/status/warmup) in this script, but avoid
        # creating a second hook pipe client inside dispatcher when using HTTP.
        os.environ["PYWEIXIN_COMMENT_BACKEND"] = "http_only"
        os.environ["PYWEIXIN_HTTP_BASE_URL"] = str(args.http_base_url).strip()
        os.environ["PYWEIXIN_HTTP_TIMEOUT_MS"] = str(args.http_timeout_ms)
        os.environ["PYWEIXIN_HTTP_COMMENT_PATH"] = str(args.http_comment_path).strip()
        os.environ["PYWEIXIN_HTTP_BATCH_PATH"] = str(args.http_batch_path).strip()
        if str(args.http_provider).strip():
            os.environ["PYWEIXIN_HTTP_PROVIDER"] = str(args.http_provider).strip().lower()
        else:
            os.environ.pop("PYWEIXIN_HTTP_PROVIDER", None)
        # UI bootstrap can be forced by CLI; otherwise keep legacy heuristic
        # (mainly for HTTP->real_hook piggyback mode).
        if args.http_bootstrap_ui is None:
            os.environ["PYWEIXIN_HTTP_BOOTSTRAP_UI"] = (
                "1" if (backend == "http" and http_provider in {"", "real_hook"}) else "0"
            )
        else:
            os.environ["PYWEIXIN_HTTP_BOOTSTRAP_UI"] = "1" if args.http_bootstrap_ui else "0"
        os.environ["PYWEIXIN_HTTP_BATCH_WAIT_MS"] = str(max(args.piggyback_timeout_ms, 1000))
        if str(args.http_authorization).strip():
            os.environ["PYWEIXIN_HTTP_AUTHORIZATION"] = str(args.http_authorization).strip()
        else:
            os.environ.pop("PYWEIXIN_HTTP_AUTHORIZATION", None)
    else:
        os.environ["PYWEIXIN_COMMENT_BACKEND"] = "hook_ui"

    os.environ["PYWEIXIN_HOOK_ENABLED"] = "1" if args.hook_enabled else "0"
    os.environ["PYWEIXIN_HOOK_BATCH_MODE"] = args.batch_mode
    os.environ["PYWEIXIN_HOOK_MAX_CONCURRENCY"] = str(args.concurrency)
    os.environ["PYWEIXIN_HOOK_PIGGYBACK_TIMEOUT_MS"] = str(args.piggyback_timeout_ms)
    os.environ["PYWEIXIN_HOOK_PIGGYBACK_UI_BOOTSTRAP"] = (
        "1" if args.piggyback_ui_bootstrap else "0"
    )
    os.environ["PYWEIXIN_HOOK_DISABLE_UI_FALLBACK_FOR_BENCH"] = (
        "1" if args.disable_ui_fallback else "0"
    )


def _check_sidecar_health(base_url: str, timeout_ms: int) -> dict[str, Any]:
    url = urljoin(base_url.rstrip("/") + "/", "health")
    req = Request(url=url, method="GET", headers={"Accept": "application/json"})
    timeout_s = max(int(timeout_ms), 50) / 1000.0
    try:
        with urlopen(req, timeout=timeout_s) as resp:
            raw = resp.read()
    except HTTPError as exc:
        raise RuntimeError(f"/health status {exc.code}: {exc.reason}") from exc
    except URLError as exc:
        raise RuntimeError(f"/health unavailable: {exc}") from exc
    except Exception as exc:
        raise RuntimeError(f"/health request failed: {exc}") from exc

    try:
        return json.loads((raw or b"{}").decode("utf-8", errors="replace"))
    except Exception as exc:
        raise RuntimeError(f"/health decode failed: {exc}") from exc


def _build_comments(prefix: str, round_idx: int, count: int) -> list[str]:
    return [f"{prefix}-r{round_idx + 1:02d}-c{i + 1:02d}" for i in range(count)]


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)


def _load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        obj = json.load(f)
    if not isinstance(obj, dict):
        raise ValueError(f"json object expected: {path}")
    return obj


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run Hook batch comment E2E acceptance from open WeChat to close WeChat."
    )
    parser.add_argument("target_author_pos", nargs="?", default="", help="Target author in Moments feed.")
    parser.add_argument("--target-author", default="", help="Target author in Moments feed. Empty = first valid post.")
    parser.add_argument(
        "--backend",
        choices=["real", "http", "mock_http"],
        default="real",
        help="Dispatch backend preference. 'real' keeps current hook/UI flow.",
    )
    parser.add_argument("--http-base-url", default="http://127.0.0.1:19080")
    parser.add_argument("--http-timeout-ms", type=int, default=1200)
    parser.add_argument("--http-comment-path", default="/api/comment")
    parser.add_argument("--http-batch-path", default="/api/comment/batch")
    parser.add_argument("--http-authorization", default="", help="Raw Authorization header value.")
    parser.add_argument(
        "--http-provider",
        default="",
        help="Optional provider hint forwarded to sidecar (e.g. native_http, real_hook, mock).",
    )
    parser.add_argument(
        "--http-bootstrap-ui",
        action=argparse.BooleanOptionalAction,
        default=None,
        help=(
            "Force PYWEIXIN_HTTP_BOOTSTRAP_UI on/off for HTTP backend. "
            "Unset keeps legacy auto behavior."
        ),
    )
    parser.add_argument(
        "--pure-http",
        action=argparse.BooleanOptionalAction,
        default=None,
        help=(
            "Force pure HTTP mode (no WeChat UI, no Hook). "
            "Default auto-on for backend=http + provider=native_http."
        ),
    )
    parser.add_argument(
        "--require-provider-match",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Fail when sidecar /health provider does not match --http-provider.",
    )
    parser.add_argument(
        "--rounds",
        type=int,
        default=MAX_BENCHMARK_ROUNDS,
        help=f"Number of benchmark rounds (1-{MAX_BENCHMARK_ROUNDS}).",
    )
    parser.add_argument("--count", type=int, default=10, help="Comments per round.")
    parser.add_argument("--target-ms", type=int, default=1000, help="Target latency threshold per round.")
    parser.add_argument("--batch-mode", choices=["piggyback", "parallel", "serial"], default="piggyback")
    parser.add_argument("--concurrency", type=int, default=1, help="Batch concurrency.")
    parser.add_argument("--piggyback-timeout-ms", type=int, default=30000)
    parser.add_argument(
        "--piggyback-ui-bootstrap",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Use UI bootstrap for first comment in piggyback mode.",
    )
    parser.add_argument("--comment-prefix", default="acc", help="Prefix used to generate comment text.")
    parser.add_argument("--sns-id", default="", help="Optional sns_id forwarded in HTTP mode.")
    parser.add_argument("--content-hash", default="", help="Optional content_hash forwarded in HTTP mode.")
    parser.add_argument("--reply-to", default="", help="Optional reply_to forwarded in HTTP mode.")
    parser.add_argument(
        "--use-latest-context",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Load sns_id/author from local_workspace/http_context/latest_context.json when available.",
    )
    parser.add_argument(
        "--context-file",
        default="local_workspace/http_context/latest_context.json",
        help="Context file path used by --use-latest-context.",
    )
    parser.add_argument(
        "--collect-context-only",
        action="store_true",
        help=(
            "Collect UI/Hook context (sns_id/author/status) and exit without benchmark rounds. "
            "Use this for discovery before pure HTTP integration."
        ),
    )
    parser.add_argument(
        "--context-out",
        default="local_workspace/http_context/latest_context.json",
        help="Output path for --collect-context-only.",
    )
    parser.add_argument("--round-interval-ms", type=int, default=300, help="Sleep interval between rounds.")
    parser.add_argument("--max-scan", type=int, default=25, help="Max feed items scanned to find target post.")
    parser.add_argument("--pipe-timeout-ms", type=int, default=3000)
    parser.add_argument("--open-retries", type=int, default=5, help="Retry count for opening Moments UI.")
    parser.add_argument("--open-retry-delay-ms", type=int, default=1200, help="Retry interval for opening Moments UI.")
    parser.add_argument(
        "--open-attempt-timeout-s",
        type=float,
        default=20.0,
        help="Timeout for each open_moments attempt (<=0 disables timeout).",
    )
    parser.add_argument("--dll-path", default="", help="Explicit DLL path.")
    parser.add_argument("--report-file", default="", help="JSON report output path.")
    parser.add_argument("--warmup-comment-text", default="acc-warmup")
    parser.add_argument(
        "--window-maximize",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Maximize Moments window.",
    )
    parser.add_argument(
        "--restart-wechat",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Restart WeChat before run.",
    )
    parser.add_argument(
        "--auto-inject",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Auto inject DLL when hook pipe is unavailable.",
    )
    parser.add_argument(
        "--disable-ui-fallback",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Disable UI fallback in batch dispatch.",
    )
    parser.add_argument("--skip-warmup", action="store_true", help="Skip warmup UI comment when hook state is stale.")
    parser.add_argument("--keep-wechat", action="store_true", help="Do not close WeChat on exit.")
    parser.add_argument(
        "--hook-enabled",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Enable hook dispatch path.",
    )
    parser.add_argument(
        "--fail-fast",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Stop immediately when a round is not strict-success.",
    )
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    if (not args.target_author) and args.target_author_pos:
        args.target_author = args.target_author_pos

    if args.use_latest_context:
        ctx_path = Path(args.context_file).expanduser().resolve()
        if ctx_path.is_file():
            try:
                ctx = _load_json(ctx_path)
                if not str(args.sns_id).strip():
                    args.sns_id = str(ctx.get("latest_sns_id", "")).strip()
                if not str(args.target_author).strip():
                    args.target_author = str(ctx.get("target_author", "")).strip()
                if not str(args.content_hash).strip():
                    args.content_hash = str(ctx.get("content_hash", "")).strip()
                _log(
                    "Loaded latest context: "
                    f"sns_id={bool(str(args.sns_id).strip())}, "
                    f"author={args.target_author!r}"
                )
            except Exception as exc:
                _log(f"Warning: failed to load context file {ctx_path}: {exc}")
        else:
            _log(f"Warning: context file not found: {ctx_path}")

    backend = str(getattr(args, "backend", "real")).strip().lower()
    http_provider = str(getattr(args, "http_provider", "")).strip().lower()

    if args.pure_http is None:
        pure_http_mode = backend == "http" and http_provider == "native_http"
    else:
        pure_http_mode = bool(args.pure_http)

    if args.collect_context_only and pure_http_mode:
        raise ValueError("--collect-context-only requires non-pure mode (needs UI/Hook context)")

    if pure_http_mode:
        if args.hook_enabled:
            _log("Pure HTTP mode: force disable hook path")
        if not args.disable_ui_fallback:
            _log("Pure HTTP mode: force disable UI fallback")
        if args.restart_wechat:
            _log("Pure HTTP mode: skip WeChat restart")
        args.hook_enabled = False
        args.disable_ui_fallback = True
        args.restart_wechat = False
        args.skip_warmup = True

    _ensure_env(args)

    if args.rounds < 1 or args.rounds > MAX_BENCHMARK_ROUNDS:
        raise ValueError(f"--rounds must be between 1 and {MAX_BENCHMARK_ROUNDS}")
    if args.count < 1:
        raise ValueError("--count must be >= 1")
    if args.concurrency < 1:
        raise ValueError("--concurrency must be >= 1")
    if (
        args.batch_mode == "piggyback"
        and args.concurrency > 1
        and (not pure_http_mode)
        and (backend == "real" or (backend == "http" and http_provider in {"", "real_hook"}))
    ):
        _log(
            "warning: piggyback parallel (>1) is currently experimental and may hit "
            "SEH in piggyback_parallel"
        )

    started_at = datetime.now().isoformat()
    report_dir = PROJECT_ROOT / "local_workspace" / "acceptance_reports"
    report_dir.mkdir(parents=True, exist_ok=True)
    report_path = (
        Path(args.report_file).expanduser().resolve()
        if args.report_file
        else report_dir / f"hook_e2e_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    )

    moments_window = None
    hook_pid = 0
    bridge: HookBridge | None = None
    injected_now = False
    rounds: list[dict[str, Any]] = []
    warmup_done = False
    warmup_ok = False
    status_before: dict[str, Any] = {}
    status_after_warmup: dict[str, Any] = {}
    sidecar_health: dict[str, Any] = {}
    collected_context: dict[str, Any] = {}
    target_ctx: dict[str, Any] = {
        "moments_list": None,
        "content_item": None,
        "anchor": None,
        "author": str(args.target_author).strip(),
        "text_preview": "",
        "scan_index": 0,
    }
    dispatcher: CommentDispatcher | None = None

    try:
        if pure_http_mode:
            _log("Pure HTTP mode enabled: no WeChat open, no Hook lifecycle, no UI fallback")
            sidecar_health = _check_sidecar_health(args.http_base_url, args.http_timeout_ms)
            sidecar_data = sidecar_health.get("data") or {}
            sidecar_provider = str(sidecar_data.get("provider", "")).strip().lower()
            sidecar_mode = str(sidecar_data.get("mode", "")).strip().lower()
            _log(f"Sidecar /health: provider={sidecar_provider or '?'} mode={sidecar_mode or '?'}")
            if sidecar_provider in {"real_hook", "real_ui"}:
                raise RuntimeError(
                    f"pure HTTP mode requires non-hook provider, got {sidecar_provider!r}"
                )
            if (
                args.require_provider_match
                and http_provider
                and sidecar_provider
                and sidecar_provider != http_provider
            ):
                raise RuntimeError(
                    f"provider mismatch: expected={http_provider}, got={sidecar_provider}"
                )
            dispatcher = CommentDispatcher.from_env()
        else:
            if args.restart_wechat:
                _log("Restarting WeChat before acceptance run")
                _terminate_wechat(force=True)
                time.sleep(0.6)

            _log("Opening WeChat Moments window")
            moments_window = _open_moments_with_retry(
                window_maximize=args.window_maximize,
                retries=args.open_retries,
                retry_delay_ms=args.open_retry_delay_ms,
                open_attempt_timeout_s=args.open_attempt_timeout_s,
            )

            hook_pid = find_wechat_pid() or 0
            if hook_pid <= 0:
                raise RuntimeError("cannot find WeChat main process pid")

            if args.hook_enabled:
                bridge, injected_now = _ensure_hook_pipe(args, hook_pid)
                status_resp = bridge.status()
                status_before = status_resp.data if status_resp.ok else {}
                _log(f"Hook status before warmup: {status_before}")
            else:
                _log("Hook path disabled, UI mode only")

            # Locate target once before warmup.
            target_ctx = _locate_target_item(
                moments_window=moments_window,
                target_author=args.target_author,
                max_scan=args.max_scan,
            )
            _log(
                f"Target located: author={target_ctx['author']!r}, scan_index={target_ctx['scan_index']}, "
                f"text={target_ctx['text_preview']!r}"
            )

            if args.hook_enabled and bridge is not None:
                captured = bool(status_before.get("state_captured"))
                context_fresh = bool(status_before.get("context_fresh"))
                need_warmup = (not captured) or (not context_fresh)
                if need_warmup and (not args.skip_warmup):
                    reason = []
                    if not captured:
                        reason.append("state_not_captured")
                    if not context_fresh:
                        reason.append("context_stale")
                    reason_text = ",".join(reason) if reason else "unknown"
                    _log(f"Hook warmup required ({reason_text}); sending warmup UI comment")
                    win_rect = moments_window.rectangle()
                    center = (win_rect.mid_point().x, win_rect.mid_point().y)
                    warmup_done = True
                    warmup_ok = comment_flow(
                        moments_window,
                        target_ctx["content_item"],
                        [args.warmup_comment_text],
                        anchor_mode="list",
                        anchor_source=target_ctx["anchor"],
                        use_offset_fix=False,
                        pre_move_coords=center,
                        clear_first=True,
                    )
                    time.sleep(0.3)
                    status_resp = bridge.status()
                    status_after_warmup = status_resp.data if status_resp.ok else {}
                    _log(f"Warmup sent={warmup_ok}, status after warmup: {status_after_warmup}")
                else:
                    status_after_warmup = status_before

                latest_sns_id = ""
                try:
                    latest_resp = bridge.get_latest_sns_id()
                    if latest_resp.ok:
                        latest_sns_id = str((latest_resp.data or {}).get("sns_id", "")).strip()
                except Exception:
                    latest_sns_id = ""
                collected_context = {
                    "captured_at": datetime.now().isoformat(),
                    "target_author": str(target_ctx.get("author", "")),
                    "target_text_preview": str(target_ctx.get("text_preview", "")),
                    "target_scan_index": int(target_ctx.get("scan_index", 0) or 0),
                    "latest_sns_id": latest_sns_id,
                    "hook_status_before": status_before,
                    "hook_status_after_warmup": status_after_warmup,
                }

                # Release management bridge before benchmark rounds.
                # Dispatcher.from_env() creates its own HookBridge connection.
                try:
                    bridge.disconnect()
                except Exception:
                    pass
                bridge = None
            elif args.collect_context_only:
                collected_context = {
                    "captured_at": datetime.now().isoformat(),
                    "target_author": str(target_ctx.get("author", "")),
                    "target_text_preview": str(target_ctx.get("text_preview", "")),
                    "target_scan_index": int(target_ctx.get("scan_index", 0) or 0),
                    "latest_sns_id": "",
                    "hook_status_before": status_before,
                    "hook_status_after_warmup": status_after_warmup,
                }

            if args.collect_context_only:
                out_path = Path(args.context_out).expanduser().resolve()
                _write_json(out_path, collected_context)
                _log(f"Context collected and saved: {out_path}")
                return 0

        for round_idx in range(args.rounds):
            if dispatcher is not None and dispatcher._hook_sender is not None:
                try:
                    dispatcher._hook_sender.bridge.disconnect()
                except Exception:
                    pass

            if not pure_http_mode:
                # Keep warmup target for round 1 to avoid jumping to a different
                # off-screen item right after successful bootstrap.
                if not (round_idx == 0 and warmup_done):
                    # Re-locate target every round to avoid stale UI handles.
                    # If re-location fails due feed shifts, keep previous target
                    # context for continuity instead of aborting the whole run.
                    try:
                        target_ctx = _locate_target_item(
                            moments_window=moments_window,
                            target_author=args.target_author,
                            max_scan=args.max_scan,
                        )
                    except Exception as exc:
                        _log(
                            "Target re-locate failed, fallback to previous target "
                            f"for round {round_idx + 1}: {exc}"
                        )
                win_rect = moments_window.rectangle()
                center = (win_rect.mid_point().x, win_rect.mid_point().y)
                dispatcher = CommentDispatcher.from_env(
                    moments_window=moments_window,
                    content_item=target_ctx["content_item"],
                    anchor_mode="list",
                    anchor_source=target_ctx["anchor"],
                    pre_move_coords=center,
                )
            elif dispatcher is None:
                dispatcher = CommentDispatcher.from_env()

            needs_local_hook_sender = (not pure_http_mode) and args.hook_enabled and backend == "real"
            if needs_local_hook_sender and dispatcher._hook_sender is None:
                raise RuntimeError(
                    "hook sender unavailable in benchmark round; "
                    "pipe may be disconnected or unavailable"
                )
            comments = _build_comments(args.comment_prefix, round_idx, args.count)

            _log(f"Round {round_idx + 1}/{args.rounds} start, comments={len(comments)}")
            t0 = time.perf_counter()
            batch_result = dispatcher.post_batch_comments(
                comments,
                sns_id=args.sns_id,
                author=target_ctx["author"],
                content_hash=args.content_hash,
                reply_to=args.reply_to,
                concurrency=args.concurrency,
            )
            elapsed_ms = int((time.perf_counter() - t0) * 1000)
            batch_latency_ms = int(batch_result.total_latency_ms or elapsed_ms)
            strict_ok = batch_result.succeeded == args.count
            under_target = batch_latency_ms < args.target_ms
            methods: dict[str, int] = {}
            for item in batch_result.results:
                methods[item.method] = methods.get(item.method, 0) + 1
            failed_items = [
                {
                    "index": i + 1,
                    "error_code": r.error_code,
                    "error_message": r.error_message,
                    "latency_ms": r.latency_ms,
                    "method": r.method,
                }
                for i, r in enumerate(batch_result.results)
                if not r.success
            ]
            rounds.append(
                {
                    "round": round_idx + 1,
                    "elapsed_ms": elapsed_ms,
                    "batch_latency_ms": batch_latency_ms,
                    "total": batch_result.total,
                    "succeeded": batch_result.succeeded,
                    "failed": batch_result.failed,
                    "strict_success": strict_ok,
                    "under_target": under_target,
                    "mode": batch_result.mode,
                    "raw_batch_total": batch_result.raw_batch_total,
                    "raw_batch_succeeded": batch_result.raw_batch_succeeded,
                    "raw_batch_failed": batch_result.raw_batch_failed,
                    "fallback_count": batch_result.fallback_count,
                    "method_counts": methods,
                    "failed_items": failed_items,
                }
            )
            _log(
                f"Round {round_idx + 1} result: {batch_result.succeeded}/{batch_result.total}, "
                f"batch_latency={batch_latency_ms}ms, strict_ok={strict_ok}, "
                f"raw={batch_result.raw_batch_succeeded}/{batch_result.raw_batch_total}, "
                f"fallback={batch_result.fallback_count}, under_target={under_target}"
            )
            if args.fail_fast and not strict_ok:
                _log("Fail-fast enabled: stopping after first failed round")
                break
            if args.round_interval_ms > 0 and round_idx < (args.rounds - 1):
                time.sleep(args.round_interval_ms / 1000.0)

        latencies = [r["batch_latency_ms"] for r in rounds]
        executed_rounds = len(rounds)
        strict_success_rounds = sum(1 for r in rounds if r["strict_success"])
        under_target_rounds = sum(1 for r in rounds if r["under_target"])
        summary = {
            "rounds": executed_rounds,
            "configured_rounds": args.rounds,
            "comments_per_round": args.count,
            "target_ms": args.target_ms,
            "strict_success_rounds": strict_success_rounds,
            "under_target_rounds": under_target_rounds,
            "strict_success_rate": (strict_success_rounds / executed_rounds) if executed_rounds else 0.0,
            "under_target_rate": (under_target_rounds / executed_rounds) if executed_rounds else 0.0,
            "latency_avg_ms": int(round(statistics.mean(latencies))) if latencies else 0,
            "latency_p50_ms": _percentile(latencies, 0.50),
            "latency_p95_ms": _percentile(latencies, 0.95),
            "latency_max_ms": max(latencies) if latencies else 0,
            "goal_passed": (
                executed_rounds > 0
                and strict_success_rounds == executed_rounds
                and _percentile(latencies, 0.95) < args.target_ms
            ),
        }

        report = {
            "started_at": started_at,
            "finished_at": datetime.now().isoformat(),
            "args": vars(args),
            "hook_pid": hook_pid,
            "injected_now": injected_now,
            "warmup_done": warmup_done,
            "warmup_ok": warmup_ok,
            "hook_status_before": status_before,
            "hook_status_after_warmup": status_after_warmup,
            "pure_http_mode": pure_http_mode,
            "sidecar_health": sidecar_health,
            "collected_context": collected_context,
            "rounds": rounds,
            "summary": summary,
        }
        _write_json(report_path, report)

        _log(f"Report saved: {report_path}")
        _log(
            "Summary: "
            f"strict={summary['strict_success_rounds']}/{summary['rounds']}, "
            f"P95={summary['latency_p95_ms']}ms, goal_passed={summary['goal_passed']}"
        )
        return 0
    finally:
        try:
            if dispatcher is not None and dispatcher._hook_sender is not None:
                try:
                    dispatcher._hook_sender.bridge.disconnect()
                except Exception:
                    pass
            if bridge is not None:
                bridge.disconnect()
        except Exception:
            pass
        if (not pure_http_mode) and (not args.keep_wechat):
            _log("Closing WeChat")
            _terminate_wechat(force=True)


if __name__ == "__main__":
    raise SystemExit(main())
