"""Standalone HTTP comment sidecar.

This sidecar keeps the public HTTP contract stable while allowing multiple
execution providers:
1. mock: synthetic low-latency benchmark provider.
2. real_hook: proxy to local HookBridge (legacy path).
3. native_http: proxy to an upstream HTTP comment service (non-hook path).
4. real_ui: direct UI execution without hook bridge (HTTP in, UI out).
"""

from __future__ import annotations

import argparse
import base64
import json
import random
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin
from urllib.request import Request, urlopen

import pyautogui
import pythoncom
import win32con
import win32gui
import sys

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from pyweixin.hook_bridge import HookBridge
from pyweixin.moments_ext import comment_flow
from pyweixin.WeChatTools import Lists, Navigator, Tools


def _log(msg: str) -> None:
    now = datetime.now().strftime("%H:%M:%S")
    print(f"[{now}] {msg}", flush=True)


def _safe_int(v, default: int = 0) -> int:
    try:
        return int(v)
    except Exception:
        return default


def _normalize_path(path: str) -> str:
    p = (path or "").strip()
    if not p or p == "-":
        return ""
    if not p.startswith("/"):
        p = "/" + p
    return p


def _normalize_text(text: str) -> str:
    return re.sub(r"\s+", " ", (text or "")).strip()


def _open_moments_with_retry(
    *,
    window_maximize: bool,
    retries: int,
    retry_delay_ms: int,
    open_attempt_timeout_s: float,
):
    def _open_once(timeout_s: float):
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
            _log(f"[real_ui] Open Moments attempt {attempt}/{retries} failed: {exc}")
            if attempt < retries:
                time.sleep(max(retry_delay_ms, 200) / 1000.0)
    assert last_exc is not None
    raise RuntimeError(
        f"failed to open Moments after {retries} attempts: {last_exc}"
    ) from last_exc


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


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Run local HTTP comment sidecar.")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=19080)
    p.add_argument("--mode", choices=["mock", "real_hook", "native_http", "real_ui"], default="mock")
    p.add_argument("--latency-ms", type=int, default=35, help="Base mock latency per item.")
    p.add_argument("--jitter-ms", type=int, default=5, help="Random additional latency per item.")
    p.add_argument("--fail-ratio", type=float, default=0.0, help="Failure ratio in [0,1].")
    p.add_argument("--max-batch-concurrency", type=int, default=20)
    p.add_argument("--real-pipe-timeout-ms", type=int, default=3000)
    p.add_argument(
        "--real-execution-mode",
        choices=["capture_thread", "pipe_thread"],
        default="capture_thread",
    )
    p.add_argument("--real-wait-timeout-ms", type=int, default=1200)
    p.add_argument(
        "--real-arg1-mode",
        choices=["template", "null", "zeroed", "captured_ptr"],
        default="template",
        help="Low-level arg1 mode for comment cmd (pipe_thread path).",
    )
    p.add_argument(
        "--real-tls-copy",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Enable TLS slot copy for direct comment call.",
    )
    p.add_argument(
        "--real-batch-strategy",
        choices=["serial", "batch", "parallel", "piggyback"],
        default="piggyback",
    )
    p.add_argument("--real-piggyback-timeout-ms", type=int, default=5000)
    p.add_argument("--real-ui-max-scan", type=int, default=120)
    p.add_argument("--real-ui-open-retries", type=int, default=3)
    p.add_argument("--real-ui-open-retry-delay-ms", type=int, default=1200)
    p.add_argument("--real-ui-open-attempt-timeout-s", type=float, default=20.0)
    p.add_argument(
        "--real-ui-window-maximize",
        action=argparse.BooleanOptionalAction,
        default=True,
    )
    p.add_argument(
        "--real-ui-reuse-target",
        action=argparse.BooleanOptionalAction,
        default=True,
    )
    p.add_argument("--real-ui-single-retries", type=int, default=1)
    p.add_argument("--native-upstream-base-url", default="", help="Upstream URL for native_http provider.")
    p.add_argument(
        "--native-upstream-kind",
        choices=["generic", "wxbot_sendtxt"],
        default="generic",
        help="Upstream protocol adapter kind for native_http provider.",
    )
    p.add_argument("--native-comment-path", default="/api/comment")
    p.add_argument(
        "--native-batch-path",
        default="/api/comment/batch",
        help="Use '-' or empty to disable upstream batch and fanout single requests.",
    )
    p.add_argument("--native-timeout-ms", type=int, default=1200)
    p.add_argument("--native-authorization", default="", help="Raw Authorization header for upstream.")
    p.add_argument(
        "--native-wxbot-wxid",
        default="",
        help="Default wxid when using native-upstream-kind=wxbot_sendtxt.",
    )
    p.add_argument(
        "--native-wxbot-api-prefix",
        default="/api",
        help="API prefix for wxbot endpoint path (default /api).",
    )
    p.add_argument(
        "--native-wxbot-success-code",
        type=int,
        default=200,
        help="Expected success code in wxbot response body.",
    )
    p.add_argument("--auth-user", default="", help="Optional Basic auth username.")
    p.add_argument("--auth-password", default="", help="Optional Basic auth password.")
    return p.parse_args()


class BaseProvider:
    name = "base"

    def __init__(self, service: "SidecarService"):
        self.service = service

    def handle_single(self, req: dict) -> dict:
        raise NotImplementedError

    def handle_batch(self, req: dict) -> dict:
        raise NotImplementedError

    @staticmethod
    def _empty_fail(req: dict, msg: str, code: int = 30) -> dict:
        return {
            "v": 1,
            "ok": False,
            "error_code": code,
            "error_message": msg,
            "latency_ms": 0,
            "data": {},
            "task_id": req.get("task_id", ""),
        }


class MockProvider(BaseProvider):
    name = "mock"

    def _delay_ms(self) -> int:
        return self.service.latency_ms + (
            random.randint(0, self.service.jitter_ms) if self.service.jitter_ms > 0 else 0
        )

    def _simulate_item(self) -> tuple[bool, int]:
        item_delay = self._delay_ms()
        if item_delay > 0:
            time.sleep(item_delay / 1000.0)
        ok = random.random() >= self.service.fail_ratio
        return ok, item_delay

    def handle_single(self, req: dict) -> dict:
        ok, lat = self._simulate_item()
        return {
            "v": 1,
            "ok": ok,
            "error_code": 0 if ok else 30,
            "error_message": "" if ok else "mock comment failed",
            "latency_ms": lat,
            "data": {
                "trace_id": f"mock-{req.get('task_id', '')}",
                "provider": self.name,
            },
            "task_id": req.get("task_id", ""),
        }

    def handle_batch(self, req: dict) -> dict:
        comments = req.get("comments") or []
        if not isinstance(comments, list):
            comments = []
        req_concurrency = _safe_int(req.get("concurrency", 1), 1)
        workers = max(
            1,
            min(req_concurrency, self.service.max_batch_concurrency, max(len(comments), 1)),
        )

        started = time.perf_counter()
        results: list[dict[str, Any]] = [None] * len(comments)  # type: ignore[assignment]
        succeeded = 0

        def _work(idx: int) -> tuple[int, bool, int]:
            ok, lat = self._simulate_item()
            return idx, ok, lat

        if comments:
            with ThreadPoolExecutor(max_workers=workers) as ex:
                futs = [ex.submit(_work, i) for i in range(len(comments))]
                for fut in as_completed(futs):
                    idx, ok, lat = fut.result()
                    if ok:
                        succeeded += 1
                    results[idx] = {
                        "success": ok,
                        "method": "http_mock",
                        "latency_ms": lat,
                        "error_code": 0 if ok else 30,
                        "error_message": "" if ok else "mock batch item failed",
                    }
        total = len(comments)
        failed = total - succeeded
        total_latency_ms = int((time.perf_counter() - started) * 1000)

        return {
            "v": 1,
            "ok": failed == 0,
            "error_code": 0 if failed == 0 else 30,
            "error_message": "" if failed == 0 else f"{failed}/{total} failed",
            "latency_ms": total_latency_ms,
            "data": {
                "provider": self.name,
                "total": total,
                "succeeded": succeeded,
                "failed": failed,
                "total_latency_ms": total_latency_ms,
                "results": results,
            },
            "task_id": req.get("task_id", ""),
        }


class RealHookProvider(BaseProvider):
    name = "real_hook"

    def _open_bridge(self) -> HookBridge:
        bridge = HookBridge(timeout_ms=self.service.real_pipe_timeout_ms)
        if not bridge.connect() or not bridge.ping():
            bridge.disconnect()
            raise RuntimeError("cannot connect to hook pipe")
        return bridge

    @staticmethod
    def _batch_to_payload(req: dict, sns_id: str, batch) -> dict:
        results = []
        for r in batch.results:
            results.append(
                {
                    "success": bool(r.success),
                    "method": str(r.method),
                    "latency_ms": int(r.latency_ms),
                    "error_code": int(r.error_code),
                    "error_message": str(r.error_message),
                }
            )
        return {
            "v": 1,
            "ok": int(batch.failed) == 0,
            "error_code": 0 if int(batch.failed) == 0 else 30,
            "error_message": "" if int(batch.failed) == 0 else f"{batch.failed}/{batch.total} failed",
            "latency_ms": int(batch.total_latency_ms),
            "data": {
                "provider": "real_hook",
                "sns_id": sns_id,
                "total": int(batch.total),
                "succeeded": int(batch.succeeded),
                "failed": int(batch.failed),
                "total_latency_ms": int(batch.total_latency_ms),
                "results": results,
            },
            "task_id": req.get("task_id", ""),
        }

    @staticmethod
    def _resolve_sns_id(req: dict, bridge: HookBridge) -> str:
        sns_id = str(req.get("sns_id", "")).strip()
        if sns_id:
            return sns_id
        author = str(req.get("author", "")).strip()
        content_hash = str(req.get("content_hash", "")).strip()
        if author or content_hash:
            q = bridge.query_sns_id(author, content_hash)
            if q.ok:
                sns_id = str((q.data or {}).get("sns_id", "")).strip()
        if sns_id:
            return sns_id
        latest = bridge.get_latest_sns_id()
        if latest.ok:
            sns_id = str((latest.data or {}).get("sns_id", "")).strip()
        return sns_id

    def handle_single(self, req: dict) -> dict:
        content = str(req.get("content", ""))
        reply_to = str(req.get("reply_to", ""))
        if not content:
            return self._empty_fail(req, "content is empty", 10)

        with self.service._bridge_lock:
            bridge = self._open_bridge()
            try:
                sns_id = self._resolve_sns_id(req, bridge)
                if not sns_id:
                    return self._empty_fail(req, "sns_id not available", 20)

                t0 = time.perf_counter()
                resp = bridge.send_comment(
                    content,
                    sns_id=sns_id,
                    reply_to=reply_to,
                    allow_queue_fallback=False,
                    execution_mode=self.service.real_execution_mode,
                    wait_timeout_ms=self.service.real_wait_timeout_ms,
                    prefer_arg1_template=True,
                    arg1_mode=self.service.real_arg1_mode,
                    tls_copy=self.service.real_tls_copy,
                )
                lat_ms = int((time.perf_counter() - t0) * 1000)
                return {
                    "v": 1,
                    "ok": bool(resp.ok),
                    "error_code": int(resp.error_code),
                    "error_message": str(resp.error_message),
                    "latency_ms": int(resp.latency_ms or lat_ms),
                    "data": {
                        "provider": self.name,
                        "sns_id": sns_id,
                        "method": "real_hook_single",
                    },
                    "task_id": req.get("task_id", ""),
                }
            finally:
                bridge.disconnect()

    def handle_batch(self, req: dict) -> dict:
        comments = req.get("comments") or []
        if not isinstance(comments, list):
            comments = []
        comments = [str(x) for x in comments if str(x)]
        if not comments:
            return self._empty_fail(req, "comments is empty", 10)
        req_concurrency = _safe_int(req.get("concurrency", 1), 1)
        req_concurrency = max(1, min(req_concurrency, self.service.max_batch_concurrency))
        reply_to = str(req.get("reply_to", ""))

        with self.service._bridge_lock:
            bridge = self._open_bridge()
            try:
                sns_id = self._resolve_sns_id(req, bridge)
                if not sns_id:
                    return self._empty_fail(req, "sns_id not available", 20)

                strategy = self.service.real_batch_strategy
                if strategy == "piggyback":
                    batch = bridge.send_piggyback_comments(
                        comments,
                        sns_id=sns_id,
                        reply_to=reply_to,
                        max_concurrency=req_concurrency,
                        timeout_ms=self.service.real_piggyback_timeout_ms,
                    )
                    return self._batch_to_payload(req, sns_id, batch)
                if strategy == "parallel":
                    batch = bridge.send_parallel_comments(
                        comments,
                        sns_id=sns_id,
                        reply_to=reply_to,
                        max_concurrency=req_concurrency,
                    )
                    return self._batch_to_payload(req, sns_id, batch)
                if strategy == "batch":
                    batch = bridge.send_batch_comments(
                        comments,
                        sns_id=sns_id,
                        reply_to=reply_to,
                        concurrency=req_concurrency,
                    )
                    return self._batch_to_payload(req, sns_id, batch)

                started = time.perf_counter()
                results = []
                succeeded = 0
                for c in comments:
                    resp = bridge.send_comment(
                        c,
                        sns_id=sns_id,
                        reply_to=reply_to,
                        allow_queue_fallback=False,
                        execution_mode=self.service.real_execution_mode,
                        wait_timeout_ms=self.service.real_wait_timeout_ms,
                        prefer_arg1_template=True,
                        arg1_mode=self.service.real_arg1_mode,
                        tls_copy=self.service.real_tls_copy,
                    )
                    ok = bool(resp.ok)
                    if ok:
                        succeeded += 1
                    results.append(
                        {
                            "success": ok,
                            "method": "real_hook_serial",
                            "latency_ms": int(resp.latency_ms),
                            "error_code": int(resp.error_code),
                            "error_message": str(resp.error_message),
                        }
                    )
                total = len(comments)
                failed = total - succeeded
                total_latency_ms = int((time.perf_counter() - started) * 1000)
                return {
                    "v": 1,
                    "ok": failed == 0,
                    "error_code": 0 if failed == 0 else 30,
                    "error_message": "" if failed == 0 else f"{failed}/{total} failed",
                    "latency_ms": total_latency_ms,
                    "data": {
                        "provider": self.name,
                        "sns_id": sns_id,
                        "total": total,
                        "succeeded": succeeded,
                        "failed": failed,
                        "total_latency_ms": total_latency_ms,
                        "results": results,
                    },
                    "task_id": req.get("task_id", ""),
                }
            finally:
                bridge.disconnect()


class RealUiProvider(BaseProvider):
    """Direct UI sender provider (no hook bridge)."""

    name = "real_ui"

    def __init__(self, service: "SidecarService"):
        super().__init__(service)
        self._ui_lock = threading.Lock()
        self._moments_window = None
        self._target_ctx: dict[str, Any] | None = None
        self._target_author = ""

    def _ensure_window(self):
        if self._moments_window is not None:
            try:
                _ = self._moments_window.rectangle()
                return self._moments_window
            except Exception:
                self._moments_window = None

        self._moments_window = _open_moments_with_retry(
            window_maximize=self.service.real_ui_window_maximize,
            retries=self.service.real_ui_open_retries,
            retry_delay_ms=self.service.real_ui_open_retry_delay_ms,
            open_attempt_timeout_s=self.service.real_ui_open_attempt_timeout_s,
        )
        return self._moments_window

    def _locate_target(self, req: dict) -> dict[str, Any]:
        author = str(req.get("author", "")).strip()
        if (
            self.service.real_ui_reuse_target
            and self._target_ctx is not None
            and author == self._target_author
        ):
            try:
                _ = self._target_ctx["content_item"].rectangle()
                return self._target_ctx
            except Exception:
                self._target_ctx = None

        moments_window = self._ensure_window()
        ctx = _locate_target_item(
            moments_window=moments_window,
            target_author=author,
            max_scan=self.service.real_ui_max_scan,
        )
        self._target_ctx = ctx
        self._target_author = author
        return ctx

    def _send_single_locked(self, req: dict, content: str) -> tuple[bool, str]:
        if not content:
            return False, "content is empty"

        retries = max(0, self.service.real_ui_single_retries)
        last_err = "real_ui comment_flow failed"
        for attempt in range(retries + 1):
            try:
                ctx = self._locate_target(req)
                moments_window = self._ensure_window()
                try:
                    moments_window.set_focus()
                except Exception:
                    pass
                try:
                    win32gui.SetForegroundWindow(moments_window.handle)
                except Exception:
                    pass
                time.sleep(0.05)

                win_rect = moments_window.rectangle()
                center = (win_rect.mid_point().x, win_rect.mid_point().y)
                ok = comment_flow(
                    moments_window,
                    ctx["content_item"],
                    [content],
                    anchor_mode="list",
                    anchor_source=ctx["anchor"],
                    use_offset_fix=False,
                    pre_move_coords=center,
                    clear_first=True,
                )
                if ok:
                    return True, ""
                last_err = "real_ui comment_flow failed"
            except Exception as exc:
                last_err = str(exc)

            # Reset cache/handle and retry once for transient UI-COM errors.
            self._target_ctx = None
            self._moments_window = None
            if attempt < retries:
                time.sleep(0.2)

        return False, last_err

    def handle_single(self, req: dict) -> dict:
        content = str(req.get("content", "")).strip()
        started = time.perf_counter()
        with self._ui_lock:
            ok, err = self._send_single_locked(req, content)
        lat = int((time.perf_counter() - started) * 1000)
        return {
            "v": 1,
            "ok": ok,
            "error_code": 0 if ok else 30,
            "error_message": "" if ok else err,
            "latency_ms": lat,
            "data": {
                "provider": self.name,
                "method": "real_ui_single",
            },
            "task_id": req.get("task_id", ""),
        }

    def handle_batch(self, req: dict) -> dict:
        comments = req.get("comments") or []
        if not isinstance(comments, list):
            comments = []
        comments = [str(c).strip() for c in comments if str(c).strip()]
        if not comments:
            return self._empty_fail(req, "comments is empty", 10)

        started = time.perf_counter()
        results: list[dict[str, Any]] = []
        succeeded = 0

        with self._ui_lock:
            for content in comments:
                t0 = time.perf_counter()
                ok, err = self._send_single_locked(req, content)
                lat = int((time.perf_counter() - t0) * 1000)
                if ok:
                    succeeded += 1
                results.append(
                    {
                        "success": ok,
                        "method": "real_ui_serial",
                        "latency_ms": lat,
                        "error_code": 0 if ok else 30,
                        "error_message": "" if ok else err,
                    }
                )

        total = len(comments)
        failed = total - succeeded
        total_latency_ms = int((time.perf_counter() - started) * 1000)
        return {
            "v": 1,
            "ok": failed == 0,
            "error_code": 0 if failed == 0 else 30,
            "error_message": "" if failed == 0 else f"{failed}/{total} failed",
            "latency_ms": total_latency_ms,
            "data": {
                "provider": self.name,
                "total": total,
                "succeeded": succeeded,
                "failed": failed,
                "total_latency_ms": total_latency_ms,
                "results": results,
            },
            "task_id": req.get("task_id", ""),
        }


class NativeHttpProvider(BaseProvider):
    name = "native_http"

    def _is_wxbot(self) -> bool:
        return self.service.native_upstream_kind == "wxbot_sendtxt"

    def _headers(self) -> dict[str, str]:
        h = {
            "Content-Type": "application/json; charset=utf-8",
            "Accept": "application/json",
        }
        if self.service.native_authorization:
            h["Authorization"] = self.service.native_authorization
        return h

    def _post_json(self, path: str, payload: dict) -> dict:
        p = _normalize_path(path)
        if not p:
            raise RuntimeError("upstream path is empty")
        if not self.service.native_upstream_base_url:
            raise RuntimeError("native upstream base url is not configured")
        url = urljoin(self.service.native_upstream_base_url, p.lstrip("/"))
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        req = Request(url=url, method="POST", data=body, headers=self._headers())
        timeout_s = max(self.service.native_timeout_ms / 1000.0, 0.05)
        try:
            with urlopen(req, timeout=timeout_s) as resp:
                raw = resp.read()
        except HTTPError as exc:
            raise RuntimeError(f"upstream status {exc.code}: {exc.reason}") from exc
        except URLError as exc:
            raise RuntimeError(f"upstream unavailable: {exc}") from exc
        except Exception as exc:
            raise RuntimeError(f"upstream request failed: {exc}") from exc
        try:
            if not raw:
                return {}
            return json.loads(raw.decode("utf-8", errors="replace"))
        except Exception as exc:
            raise RuntimeError(f"upstream response decode failed: {exc}") from exc

    def _wxbot_single(self, req: dict) -> dict:
        content = str(req.get("content", "")).strip()
        if not content:
            return self._empty_fail(req, "content is empty", 10)
        wxid = str(req.get("wxid", "")).strip() or self.service.native_wxbot_wxid
        if not wxid:
            return self._empty_fail(
                req,
                "wxid is required for wxbot_sendtxt upstream",
                10,
            )
        api_prefix = _normalize_path(self.service.native_wxbot_api_prefix) or "/api"
        send_path = f"{api_prefix.rstrip('/')}/sendtxtmsg"
        payload = {
            "wxid": wxid,
            "content": content,
        }
        try:
            raw = self._post_json(send_path, payload)
        except Exception as exc:
            return self._empty_fail(req, str(exc), 51)

        code = _safe_int(raw.get("code", raw.get("error_code", -1)), -1)
        msg = str(raw.get("msg", raw.get("message", raw.get("error_message", ""))))
        ok = code == int(self.service.native_wxbot_success_code)
        return {
            "v": 1,
            "ok": ok,
            "error_code": 0 if ok else (code if code >= 0 else 30),
            "error_message": "" if ok else (msg or "wxbot sendtxt failed"),
            "latency_ms": _safe_int(raw.get("latency_ms", 0), 0),
            "data": {
                "provider": "native_http",
                "upstream_kind": self.service.native_upstream_kind,
                "wxid": wxid,
                "method": "wxbot_sendtxt",
                "upstream_code": code,
                "upstream_msg": msg,
            },
            "task_id": str(req.get("task_id", "")),
        }

    @staticmethod
    def _adapt_single(req: dict, raw: dict) -> dict:
        ok = bool(raw.get("ok", False))
        data = raw.get("data") or {}
        latency_ms = _safe_int(raw.get("latency_ms", data.get("latency_ms", 0)), 0)
        return {
            "v": 1,
            "ok": ok,
            "error_code": _safe_int(raw.get("error_code", data.get("error_code", 0)), 0),
            "error_message": str(raw.get("error_message", data.get("error_message", ""))),
            "latency_ms": latency_ms,
            "data": {
                **data,
                "provider": "native_http",
            },
            "task_id": str(raw.get("task_id", req.get("task_id", ""))),
        }

    @staticmethod
    def _adapt_batch(req: dict, raw: dict, default_total: int) -> dict:
        ok = bool(raw.get("ok", False))
        data = raw.get("data") or {}
        total = _safe_int(data.get("total", default_total), default_total)
        succeeded = _safe_int(data.get("succeeded", 0), 0)
        failed = _safe_int(data.get("failed", max(total - succeeded, 0)), max(total - succeeded, 0))
        total_latency_ms = _safe_int(data.get("total_latency_ms", raw.get("latency_ms", 0)), 0)
        results = data.get("results")
        if not isinstance(results, list):
            results = []
        return {
            "v": 1,
            "ok": ok,
            "error_code": _safe_int(raw.get("error_code", 0), 0),
            "error_message": str(raw.get("error_message", "")),
            "latency_ms": total_latency_ms,
            "data": {
                **data,
                "provider": "native_http",
                "total": total,
                "succeeded": succeeded,
                "failed": failed,
                "total_latency_ms": total_latency_ms,
                "results": results,
            },
            "task_id": str(raw.get("task_id", req.get("task_id", ""))),
        }

    def handle_single(self, req: dict) -> dict:
        if self._is_wxbot():
            return self._wxbot_single(req)
        try:
            raw = self._post_json(self.service.native_comment_path, req)
        except Exception as exc:
            return self._empty_fail(req, str(exc), 51)
        return self._adapt_single(req, raw)

    def handle_batch(self, req: dict) -> dict:
        comments = req.get("comments") or []
        if not isinstance(comments, list):
            comments = []
        comments = [str(c) for c in comments if str(c)]
        if not comments:
            return self._empty_fail(req, "comments is empty", 10)

        if self._is_wxbot():
            req_concurrency = _safe_int(req.get("concurrency", 1), 1)
            workers = max(
                1,
                min(req_concurrency, self.service.max_batch_concurrency, max(len(comments), 1)),
            )
            started = time.perf_counter()
            results: list[dict[str, Any]] = [None] * len(comments)  # type: ignore[assignment]
            succeeded = 0

            def _work(idx: int, content: str) -> tuple[int, dict]:
                sub_req = dict(req)
                sub_req["content"] = content
                sub_req.pop("comments", None)
                out = self._wxbot_single(sub_req)
                return idx, out

            with ThreadPoolExecutor(max_workers=workers) as ex:
                futs = [ex.submit(_work, i, comments[i]) for i in range(len(comments))]
                for fut in as_completed(futs):
                    idx, out = fut.result()
                    item_ok = bool(out.get("ok", False))
                    if item_ok:
                        succeeded += 1
                    results[idx] = {
                        "success": item_ok,
                        "method": "native_wxbot_sendtxt",
                        "latency_ms": _safe_int(out.get("latency_ms", 0), 0),
                        "error_code": _safe_int(out.get("error_code", 0), 0),
                        "error_message": str(out.get("error_message", "")),
                    }

            total = len(comments)
            failed = total - succeeded
            total_latency_ms = int((time.perf_counter() - started) * 1000)
            return {
                "v": 1,
                "ok": failed == 0,
                "error_code": 0 if failed == 0 else 30,
                "error_message": "" if failed == 0 else f"{failed}/{total} failed",
                "latency_ms": total_latency_ms,
                "data": {
                    "provider": self.name,
                    "upstream_kind": self.service.native_upstream_kind,
                    "total": total,
                    "succeeded": succeeded,
                    "failed": failed,
                    "total_latency_ms": total_latency_ms,
                    "results": results,
                },
                "task_id": req.get("task_id", ""),
            }

        batch_path = _normalize_path(self.service.native_batch_path)
        if batch_path:
            try:
                raw = self._post_json(batch_path, req)
            except Exception as exc:
                return self._empty_fail(req, str(exc), 51)
            return self._adapt_batch(req, raw, len(comments))

        req_concurrency = _safe_int(req.get("concurrency", 1), 1)
        workers = max(
            1,
            min(req_concurrency, self.service.max_batch_concurrency, max(len(comments), 1)),
        )
        started = time.perf_counter()
        results: list[dict[str, Any]] = [None] * len(comments)  # type: ignore[assignment]
        succeeded = 0

        def _work(idx: int, content: str) -> tuple[int, dict]:
            sub_req = dict(req)
            sub_req["content"] = content
            sub_req.pop("comments", None)
            out = self.handle_single(sub_req)
            return idx, out

        with ThreadPoolExecutor(max_workers=workers) as ex:
            futs = [ex.submit(_work, i, comments[i]) for i in range(len(comments))]
            for fut in as_completed(futs):
                idx, out = fut.result()
                item_ok = bool(out.get("ok", False))
                if item_ok:
                    succeeded += 1
                results[idx] = {
                    "success": item_ok,
                    "method": "native_http_fanout",
                    "latency_ms": _safe_int(out.get("latency_ms", 0), 0),
                    "error_code": _safe_int(out.get("error_code", 0), 0),
                    "error_message": str(out.get("error_message", "")),
                }

        total = len(comments)
        failed = total - succeeded
        total_latency_ms = int((time.perf_counter() - started) * 1000)
        return {
            "v": 1,
            "ok": failed == 0,
            "error_code": 0 if failed == 0 else 30,
            "error_message": "" if failed == 0 else f"{failed}/{total} failed",
            "latency_ms": total_latency_ms,
            "data": {
                "provider": self.name,
                "total": total,
                "succeeded": succeeded,
                "failed": failed,
                "total_latency_ms": total_latency_ms,
                "results": results,
            },
            "task_id": req.get("task_id", ""),
        }


class SidecarService:
    def __init__(self, args: argparse.Namespace):
        self.mode = args.mode
        self.host = args.host
        self.port = args.port
        self.latency_ms = max(0, int(args.latency_ms))
        self.jitter_ms = max(0, int(args.jitter_ms))
        self.fail_ratio = min(max(float(args.fail_ratio), 0.0), 1.0)
        self.max_batch_concurrency = max(1, int(args.max_batch_concurrency))
        self.real_pipe_timeout_ms = max(300, int(args.real_pipe_timeout_ms))
        self.real_execution_mode = args.real_execution_mode
        self.real_wait_timeout_ms = max(100, int(args.real_wait_timeout_ms))
        self.real_arg1_mode = str(args.real_arg1_mode).strip()
        self.real_tls_copy = bool(args.real_tls_copy)
        self.real_batch_strategy = args.real_batch_strategy
        self.real_piggyback_timeout_ms = max(500, int(args.real_piggyback_timeout_ms))
        self.real_ui_max_scan = max(5, int(args.real_ui_max_scan))
        self.real_ui_open_retries = max(1, int(args.real_ui_open_retries))
        self.real_ui_open_retry_delay_ms = max(200, int(args.real_ui_open_retry_delay_ms))
        self.real_ui_open_attempt_timeout_s = float(args.real_ui_open_attempt_timeout_s)
        self.real_ui_window_maximize = bool(args.real_ui_window_maximize)
        self.real_ui_reuse_target = bool(args.real_ui_reuse_target)
        self.real_ui_single_retries = max(0, int(args.real_ui_single_retries))
        self.native_upstream_base_url = str(args.native_upstream_base_url).strip().rstrip("/") + "/"
        if not str(args.native_upstream_base_url).strip():
            self.native_upstream_base_url = ""
        self.native_upstream_kind = str(args.native_upstream_kind).strip().lower()
        self.native_comment_path = args.native_comment_path
        self.native_batch_path = args.native_batch_path
        self.native_timeout_ms = max(50, min(int(args.native_timeout_ms), 120000))
        self.native_authorization = str(args.native_authorization).strip()
        self.native_wxbot_wxid = str(args.native_wxbot_wxid).strip()
        self.native_wxbot_api_prefix = str(args.native_wxbot_api_prefix).strip()
        self.native_wxbot_success_code = int(args.native_wxbot_success_code)
        self.auth_user = args.auth_user.strip()
        self.auth_password = args.auth_password
        self._server: ThreadingHTTPServer | None = None
        self._bridge_lock = threading.Lock()
        self._provider = self._create_provider(self.mode)

    def _create_provider(self, mode: str) -> BaseProvider:
        if mode == "mock":
            return MockProvider(self)
        if mode == "real_hook":
            return RealHookProvider(self)
        if mode == "real_ui":
            return RealUiProvider(self)
        if mode == "native_http":
            return NativeHttpProvider(self)
        raise ValueError(f"unsupported mode: {mode}")

    def _needs_auth(self) -> bool:
        return bool(self.auth_user)

    def _check_auth(self, headers) -> bool:
        if not self._needs_auth():
            return True
        auth = str(headers.get("Authorization", "")).strip()
        if not auth.startswith("Basic "):
            return False
        token = auth[len("Basic ") :].strip()
        try:
            decoded = base64.b64decode(token).decode("utf-8", errors="replace")
        except Exception:
            return False
        return decoded == f"{self.auth_user}:{self.auth_password}"

    def run_forever(self) -> None:
        service = self

        class Handler(BaseHTTPRequestHandler):
            def _write_json(self, status: int, payload: dict) -> None:
                raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def _read_json(self) -> dict:
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                except Exception:
                    length = 0
                body = self.rfile.read(length) if length > 0 else b"{}"
                try:
                    return json.loads(body.decode("utf-8", errors="replace"))
                except Exception:
                    return {}

            def log_message(self, fmt: str, *args) -> None:
                return

            def do_GET(self) -> None:
                if self.path == "/health":
                    self._write_json(
                        200,
                        {
                            "v": 1,
                            "ok": True,
                            "error_code": 0,
                            "error_message": "",
                            "latency_ms": 0,
                            "data": {
                                "mode": service.mode,
                                "provider": service._provider.name,
                                "upstream_kind": service.native_upstream_kind,
                                "upstream_base_url": service.native_upstream_base_url,
                            },
                        },
                    )
                    return
                self._write_json(
                    404,
                    {
                        "v": 1,
                        "ok": False,
                        "error_code": 10,
                        "error_message": f"unknown path: {self.path}",
                        "latency_ms": 0,
                        "data": {},
                    },
                )

            def do_POST(self) -> None:
                if not service._check_auth(self.headers):
                    self._write_json(
                        401,
                        {
                            "v": 1,
                            "ok": False,
                            "error_code": 50,
                            "error_message": "unauthorized",
                            "latency_ms": 0,
                            "data": {},
                        },
                    )
                    return

                req = self._read_json()
                req_provider = str(req.get("provider", "")).strip().lower()
                if req_provider and req_provider != service._provider.name:
                    self._write_json(
                        400,
                        {
                            "v": 1,
                            "ok": False,
                            "error_code": 10,
                            "error_message": (
                                f"provider mismatch: request={req_provider}, "
                                f"service={service._provider.name}"
                            ),
                            "latency_ms": 0,
                            "data": {},
                            "task_id": req.get("task_id", ""),
                        },
                    )
                    return

                if self.path == "/api/comment":
                    self._write_json(200, service._provider.handle_single(req))
                    return
                if self.path == "/api/comment/batch":
                    self._write_json(200, service._provider.handle_batch(req))
                    return

                self._write_json(
                    404,
                    {
                        "v": 1,
                        "ok": False,
                        "error_code": 10,
                        "error_message": f"unknown path: {self.path}",
                        "latency_ms": 0,
                        "data": {},
                    },
                )

        self._server = ThreadingHTTPServer((self.host, self.port), Handler)
        _log(
            f"HTTP sidecar listening on http://{self.host}:{self.port} "
            f"(provider={self._provider.name}, mode={self.mode}, "
            f"mock_fail_ratio={self.fail_ratio}, mock_latency={self.latency_ms}ms, "
            f"upstream_kind={self.native_upstream_kind})"
        )
        stop_event = threading.Event()

        def _serve() -> None:
            assert self._server is not None
            self._server.serve_forever()
            stop_event.set()

        t = threading.Thread(target=_serve, daemon=False)
        t.start()
        try:
            while not stop_event.is_set():
                time.sleep(0.3)
        except KeyboardInterrupt:
            _log("sidecar shutting down...")
        finally:
            if self._server is not None:
                self._server.shutdown()
                self._server.server_close()
            t.join(timeout=3.0)


def main() -> int:
    args = _parse_args()
    sidecar = SidecarService(args)
    sidecar.run_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
