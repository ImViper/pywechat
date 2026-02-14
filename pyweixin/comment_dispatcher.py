"""
Viper Comment Dispatcher -- unified Hook + UI fallback with circuit breaker.
不修改 upstream 代码，只导入公共 API。
"""

from __future__ import annotations

import base64
import json
import os
import threading
import time
import uuid
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin
from urllib.request import Request, urlopen
from dataclasses import dataclass, field

try:
    from .hook_types import BatchCommentResult, CommentResult, CommentSender, HookErrorCode
    from .hook_bridge import HookBridge
except ImportError:  # pragma: no cover
    from hook_types import BatchCommentResult, CommentResult, CommentSender, HookErrorCode
    from hook_bridge import HookBridge


# ---------------------------------------------------------------------------
# Circuit breaker
# ---------------------------------------------------------------------------

@dataclass
class CircuitBreakerState:
    """Simple circuit breaker: CLOSED -> OPEN after *threshold* consecutive failures.

    While OPEN, ``is_open`` returns True for *recovery_sec* seconds, then
    transitions to HALF_OPEN (one attempt allowed).  A success resets to CLOSED;
    a failure re-opens.
    """
    threshold: int = 3
    recovery_sec: float = 30.0
    _failure_count: int = field(default=0, init=False, repr=False)
    _opened_at: float = field(default=0.0, init=False, repr=False)

    @property
    def is_open(self) -> bool:
        if self._failure_count < self.threshold:
            return False
        elapsed = time.time() - self._opened_at
        if elapsed >= self.recovery_sec:
            # half-open: allow one attempt
            return False
        return True

    def record_success(self) -> None:
        self._failure_count = 0
        self._opened_at = 0.0

    def record_failure(self) -> None:
        self._failure_count += 1
        if self._failure_count >= self.threshold:
            self._opened_at = time.time()


# ---------------------------------------------------------------------------
# HookCommentSender  (implements CommentSender)
# ---------------------------------------------------------------------------

class HookCommentSender:
    """Send comments via the injected DLL pipe."""

    def __init__(
        self,
        bridge: HookBridge,
        *,
        execution_mode: str = "capture_thread",
        wait_timeout_ms: int = 400,
        prefer_arg1_template: bool = True,
    ):
        self._bridge = bridge
        self._execution_mode = execution_mode
        self._wait_timeout_ms = wait_timeout_ms
        self._prefer_arg1_template = prefer_arg1_template

    @property
    def bridge(self) -> HookBridge:
        return self._bridge

    def is_hook_ready(self) -> bool:
        """Check if the hook is installed and the state is captured."""
        try:
            # ping checks if the bridge is alive, status checks the hook state.
            status_resp = self._bridge.status()
            if status_resp.ok:
                data = status_resp.data
                ready = bool(data.get("hook_installed")) and bool(
                    data.get("state_captured")
                )
                return ready
        except Exception:
            pass
        return False

    def get_capture_thread_id(self) -> int:
        """Get the capture thread ID from the DLL."""
        try:
            status_resp = self._bridge.status()
            if status_resp.ok:
                return int(status_resp.data.get("capture_thread_id", 0))
        except Exception:
            pass
        return 0

    def send_comment(
        self,
        content: str,
        *,
        sns_id: str = "",
        author: str = "",
        content_hash: str = "",
        reply_to: str = "",
    ) -> CommentResult:
        # If we have no sns_id, try to query via author+hash
        effective_sns_id = sns_id
        if not effective_sns_id and (author or content_hash):
            q = self._bridge.query_sns_id(author, content_hash)
            if q.ok:
                effective_sns_id = q.data.get("sns_id", "")
        # Fallback: use latest captured sns_id when key lookup misses.
        if not effective_sns_id:
            latest = self._bridge.get_latest_sns_id()
            if latest.ok:
                effective_sns_id = latest.data.get("sns_id", "")

        # Optimization: if using capture_thread but no capture thread id is found,
        # fail early to avoid the wait_timeout_ms (usually 400ms).
        if self._execution_mode == "capture_thread":
            tid = self.get_capture_thread_id()
            if tid == 0:
                return CommentResult(
                    success=False,
                    method="hook",
                    error_code=HookErrorCode.SNS_ID_NOT_FOUND,
                    error_message="capture_thread_id is 0, state not captured yet",
                )

        resp = self._bridge.send_comment(
            content,
            sns_id=effective_sns_id,
            reply_to=reply_to,
            allow_queue_fallback=False,
            execution_mode=self._execution_mode,
            wait_timeout_ms=self._wait_timeout_ms,
            prefer_arg1_template=self._prefer_arg1_template,
        )
        return CommentResult(
            success=resp.ok,
            method="hook",
            latency_ms=resp.latency_ms,
            error_code=resp.error_code,
            error_message=resp.error_message,
        )


class HttpCommentSender:
    """Send comments via local HTTP sidecar API."""

    def __init__(
        self,
        *,
        base_url: str,
        comment_path: str = "/api/comment",
        batch_path: str = "/api/comment/batch",
        timeout_ms: int = 1200,
        authorization: str = "",
        provider: str = "",
    ):
        self._base_url = base_url.rstrip("/") + "/"
        self._comment_path = comment_path
        self._batch_path = batch_path
        self._timeout_ms = max(50, min(int(timeout_ms), 120000))
        self._authorization = authorization.strip()
        self._provider = provider.strip().lower()

    @staticmethod
    def _normalize_path(path: str) -> str:
        p = (path or "").strip()
        if not p:
            return ""
        if not p.startswith("/"):
            p = "/" + p
        return p

    @staticmethod
    def _safe_int(v, default: int = 0) -> int:
        try:
            return int(v)
        except Exception:
            return default

    def _build_headers(self) -> dict[str, str]:
        headers = {
            "Content-Type": "application/json; charset=utf-8",
            "Accept": "application/json",
        }
        if self._authorization:
            headers["Authorization"] = self._authorization
        return headers

    def _http_post_json(self, path: str, payload: dict) -> dict:
        path = self._normalize_path(path)
        if not path:
            raise RuntimeError("HTTP path is empty")
        url = urljoin(self._base_url, path.lstrip("/"))
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        req = Request(url=url, method="POST", data=data, headers=self._build_headers())
        timeout_s = max(self._timeout_ms / 1000.0, 0.05)
        try:
            with urlopen(req, timeout=timeout_s) as resp:
                raw = resp.read()
        except HTTPError as exc:
            raise RuntimeError(f"http status {exc.code}: {exc.reason}") from exc
        except URLError as exc:
            raise RuntimeError(f"http unavailable: {exc}") from exc
        except Exception as exc:
            raise RuntimeError(f"http request failed: {exc}") from exc

        try:
            if not raw:
                return {}
            return json.loads(raw.decode("utf-8", errors="replace"))
        except Exception as exc:
            raise RuntimeError(f"http response decode failed: {exc}") from exc

    @classmethod
    def from_env(cls) -> "HttpCommentSender | None":
        base_url = os.environ.get("PYWEIXIN_HTTP_BASE_URL", "").strip()
        if not base_url:
            return None
        comment_path = os.environ.get("PYWEIXIN_HTTP_COMMENT_PATH", "/api/comment")
        batch_path = os.environ.get("PYWEIXIN_HTTP_BATCH_PATH", "/api/comment/batch")
        try:
            timeout_ms = int(os.environ.get("PYWEIXIN_HTTP_TIMEOUT_MS", "1200"))
        except Exception:
            timeout_ms = 1200

        auth = os.environ.get("PYWEIXIN_HTTP_AUTHORIZATION", "").strip()
        if not auth:
            auth_basic = os.environ.get("PYWEIXIN_HTTP_AUTH_BASIC", "").strip()
            if auth_basic:
                auth = f"Basic {auth_basic}"
            else:
                user = os.environ.get("PYWEIXIN_HTTP_USER", "").strip()
                password = os.environ.get("PYWEIXIN_HTTP_PASSWORD", "").strip()
                if user:
                    token = base64.b64encode(f"{user}:{password}".encode("utf-8")).decode("ascii")
                    auth = f"Basic {token}"
        provider = os.environ.get("PYWEIXIN_HTTP_PROVIDER", "").strip().lower()
        return cls(
            base_url=base_url,
            comment_path=comment_path,
            batch_path=batch_path,
            timeout_ms=timeout_ms,
            authorization=auth,
            provider=provider,
        )

    @staticmethod
    def _parse_ok(raw: dict) -> bool:
        if "ok" in raw:
            return bool(raw.get("ok"))
        code = raw.get("code")
        msg = str(raw.get("message", raw.get("msg", ""))).strip().lower()
        if code is not None:
            return int(code) == 200 and msg not in {"failed", "fail", "error"}
        return False

    def send_comment(
        self,
        content: str,
        *,
        sns_id: str = "",
        author: str = "",
        content_hash: str = "",
        reply_to: str = "",
    ) -> CommentResult:
        task_id = uuid.uuid4().hex[:12]
        payload = {
            "v": 1,
            "cmd": "comment",
            "task_id": task_id,
            "sns_id": sns_id,
            "author": author,
            "content_hash": content_hash,
            "reply_to": reply_to,
            "content": content,
        }
        if self._provider:
            payload["provider"] = self._provider
        raw = self._http_post_json(self._comment_path, payload)
        ok = self._parse_ok(raw)
        data = raw.get("data") or {}
        error_code = self._safe_int(raw.get("error_code", data.get("error_code", 0)), 0)
        error_message = str(raw.get("error_message", data.get("error_message", "")))
        latency_ms = self._safe_int(raw.get("latency_ms", data.get("latency_ms", 0)), 0)
        return CommentResult(
            success=ok,
            method="http",
            latency_ms=latency_ms,
            error_code=error_code if not ok else 0,
            error_message=error_message if not ok else "",
        )

    def send_batch_comments(
        self,
        comments: list[str],
        *,
        sns_id: str = "",
        author: str = "",
        content_hash: str = "",
        reply_to: str = "",
        max_concurrency: int = 10,
    ) -> BatchCommentResult:
        if not comments:
            return BatchCommentResult()
        if not self._normalize_path(self._batch_path):
            raise RuntimeError("http batch path is disabled")

        task_id = uuid.uuid4().hex[:12]
        payload = {
            "v": 1,
            "cmd": "batch_comment",
            "task_id": task_id,
            "sns_id": sns_id,
            "author": author,
            "content_hash": content_hash,
            "reply_to": reply_to,
            "comments": comments,
            "concurrency": max(1, min(int(max_concurrency), 100)),
        }
        if self._provider:
            payload["provider"] = self._provider
        raw = self._http_post_json(self._batch_path, payload)
        ok = self._parse_ok(raw)
        data = raw.get("data") or {}

        total = self._safe_int(data.get("total", len(comments)), len(comments))
        succeeded = self._safe_int(data.get("succeeded", 0), 0)
        failed = self._safe_int(data.get("failed", max(total - succeeded, 0)), max(total - succeeded, 0))
        total_latency_ms = self._safe_int(data.get("total_latency_ms", raw.get("latency_ms", 0)), 0)
        raw_results = data.get("results") or []

        results: list[CommentResult] = []
        for item in raw_results:
            item_ok = bool(item.get("success", False))
            item_method = str(item.get("method", item.get("call_method", "http")))
            results.append(
                CommentResult(
                    success=item_ok,
                    method=item_method,
                    latency_ms=self._safe_int(item.get("latency_ms", 0), 0),
                    error_code=self._safe_int(item.get("error_code", 0), 0),
                    error_message=str(item.get("error_message", "")),
                )
            )

        if not results:
            # Compatible fallback when server only returns top-level ok.
            for _ in range(len(comments)):
                results.append(
                    CommentResult(
                        success=ok,
                        method="http",
                        latency_ms=0,
                        error_code=0 if ok else self._safe_int(raw.get("error_code", 30), 30),
                        error_message="" if ok else str(raw.get("error_message", "http batch failed")),
                    )
                )
            total = len(comments)
            succeeded = len(comments) if ok else 0
            failed = len(comments) - succeeded

        return BatchCommentResult(
            total=total,
            succeeded=succeeded,
            failed=failed,
            total_latency_ms=total_latency_ms,
            results=results,
            mode="http",
            raw_batch_total=total,
            raw_batch_succeeded=succeeded,
            raw_batch_failed=failed,
            fallback_count=0,
        )


# ---------------------------------------------------------------------------
# UICommentSender  (implements CommentSender, wraps existing UI automation)
# ---------------------------------------------------------------------------

class UICommentSender:
    """Send comments via the existing UI automation path.

    Parameters mirror what ``comment_flow`` needs: moments_window,
    content_item, anchor_mode, anchor_source, pre_move_coords.
    """

    def __init__(
        self,
        moments_window,
        content_item,
        anchor_mode: str = "list",
        anchor_source=None,
        pre_move_coords: tuple | None = None,
    ):
        self._moments_window = moments_window
        self._content_item = content_item
        self._anchor_mode = anchor_mode
        self._anchor_source = anchor_source
        self._pre_move_coords = pre_move_coords

    def send_comment(
        self,
        content: str,
        *,
        sns_id: str = "",
        author: str = "",
        content_hash: str = "",
        reply_to: str = "",
    ) -> CommentResult:
        start = time.time()
        try:
            from .moments_ext import comment_flow
        except ImportError:  # pragma: no cover
            from moments_ext import comment_flow

        ok = comment_flow(
            self._moments_window,
            self._content_item,
            [content],
            anchor_mode=self._anchor_mode,
            anchor_source=self._anchor_source,
            use_offset_fix=False,
            clear_first=False,
            pre_move_coords=self._pre_move_coords,
        )
        elapsed = int((time.time() - start) * 1000)
        return CommentResult(
            success=bool(ok),
            method="ui",
            latency_ms=elapsed,
            error_code=0 if ok else HookErrorCode.COMMENT_FAILED,
            error_message="" if ok else "UI comment_flow returned False",
        )


# ---------------------------------------------------------------------------
# CommentDispatcher
# ---------------------------------------------------------------------------

class CommentDispatcher:
    """Unified comment entry point: HTTP first, Hook second, UI fallback.

    Usage::

        dispatcher = CommentDispatcher.from_env(...)
        result = dispatcher.post_comment("5男")
    """

    def __init__(
        self,
        http_sender: HttpCommentSender | None = None,
        hook_sender: HookCommentSender | None = None,
        ui_sender: UICommentSender | None = None,
        circuit_breaker: CircuitBreakerState | None = None,
    ):
        self._http_sender = http_sender
        self._hook_sender = hook_sender
        self._ui_sender = ui_sender
        self._breaker = circuit_breaker or CircuitBreakerState()

    @classmethod
    def from_env(
        cls,
        moments_window=None,
        content_item=None,
        anchor_mode: str = "list",
        anchor_source=None,
        pre_move_coords: tuple | None = None,
    ) -> "CommentDispatcher":
        """Create a dispatcher based on environment variables.

        ``PYWEIXIN_HOOK_ENABLED=1`` activates the Hook path.
        """
        backend = os.environ.get("PYWEIXIN_COMMENT_BACKEND", "hook_ui").strip().lower()
        http_sender: HttpCommentSender | None = None
        if backend in {"http", "mock_http", "http_only"}:
            http_sender = HttpCommentSender.from_env()

        hook_sender: HookCommentSender | None = None

        hook_enabled = os.environ.get("PYWEIXIN_HOOK_ENABLED", "0") == "1"
        if backend == "http_only":
            hook_enabled = False
        if hook_enabled:
            bridge = HookBridge()
            if bridge.connect() and bridge.ping():
                execution_mode = os.environ.get(
                    "PYWEIXIN_HOOK_EXECUTION_MODE", "capture_thread"
                )
                try:
                    wait_timeout_ms = int(
                        os.environ.get("PYWEIXIN_HOOK_WAIT_TIMEOUT_MS", "400")
                    )
                except ValueError:
                    wait_timeout_ms = 400
                if wait_timeout_ms < 100:
                    wait_timeout_ms = 100
                if wait_timeout_ms > 30000:
                    wait_timeout_ms = 30000
                prefer_arg1_template = os.environ.get(
                    "PYWEIXIN_HOOK_PREFER_ARG1_TEMPLATE", "1"
                ) not in {"0", "false", "False"}

                hook_sender = HookCommentSender(
                    bridge,
                    execution_mode=execution_mode,
                    wait_timeout_ms=wait_timeout_ms,
                    prefer_arg1_template=prefer_arg1_template,
                )

        ui_sender: UICommentSender | None = None
        if moments_window is not None and content_item is not None:
            ui_sender = UICommentSender(
                moments_window,
                content_item,
                anchor_mode=anchor_mode,
                anchor_source=anchor_source,
                pre_move_coords=pre_move_coords,
            )

        return cls(http_sender=http_sender, hook_sender=hook_sender, ui_sender=ui_sender)

    def post_comment(
        self,
        content: str,
        *,
        sns_id: str = "",
        author: str = "",
        content_hash: str = "",
        reply_to: str = "",
    ) -> CommentResult:
        """Try HTTP first; then Hook; finally fall back to UI."""
        kwargs = dict(
            content=content,
            sns_id=sns_id,
            author=author,
            content_hash=content_hash,
            reply_to=reply_to,
        )

        # HTTP path
        if self._http_sender is not None:
            try:
                http_result = self._http_sender.send_comment(**kwargs)
            except Exception as exc:
                http_result = CommentResult(
                    success=False,
                    method="http",
                    error_code=HookErrorCode.COMMENT_FAILED,
                    error_message=f"http sender error: {exc}",
                )
            if http_result.success:
                return http_result
            print(
                f"[http-dispatch] http failed ({http_result.error_message}), "
                "fallback to hook/UI"
            )

        # Hook path
        if self._hook_sender is not None and not self._breaker.is_open:
            result = self._hook_sender.send_comment(**kwargs)
            if result.success:
                self._breaker.record_success()
                return result
            else:
                self._breaker.record_failure()
                print(
                    f"[hook-dispatch] hook failed ({result.error_message}), "
                    f"fallback to UI"
                )

        # UI fallback
        if self._ui_sender is not None:
            return self._ui_sender.send_comment(**kwargs)

        return CommentResult(
            success=False,
            method="none",
            error_code=HookErrorCode.COMMENT_FAILED,
            error_message="no sender available",
        )

    def post_batch_comments(
        self,
        comments: list[str],
        *,
        sns_id: str = "",
        author: str = "",
        content_hash: str = "",
        reply_to: str = "",
        concurrency: int = 10,
    ) -> BatchCommentResult:
        """Send comments in batch with strict success criteria.

        Modes (from ``PYWEIXIN_HOOK_BATCH_MODE``):
          - ``piggyback`` (default): queue remaining comments then trigger one
            bootstrap comment to drain inside hook callback.
          - ``parallel``: use ``parallel_comment`` then serial fallback.
          - ``serial``: purely serial ``send_comment`` path.
        """
        if not comments:
            return BatchCommentResult()

        results: list[CommentResult] = []
        batch_start = time.time()
        raw_batch_total = 0
        raw_batch_succeeded = 0
        raw_batch_failed = 0
        fallback_count = 0

        batch_mode = os.environ.get("PYWEIXIN_HOOK_BATCH_MODE", "piggyback").strip().lower()
        if batch_mode not in {"piggyback", "parallel", "serial"}:
            batch_mode = "piggyback"

        # Auto-upgrade optimization: if batch mode is piggyback but the hook is READY
        # (state captured), upgrade to parallel mode immediately. Parallel mode
        # is faster (no UI bootstrap) and is safe once state is captured.
        if batch_mode == "piggyback" and self._hook_sender is not None:
            if self._hook_sender.is_hook_ready():
                print("[batch-dispatch] Hook ready (state captured), upgrading piggyback -> parallel")
                batch_mode = "parallel"

        try:
            piggyback_timeout_ms = int(
                os.environ.get("PYWEIXIN_HOOK_PIGGYBACK_TIMEOUT_MS", "30000")
            )
        except ValueError:
            piggyback_timeout_ms = 30000
        if piggyback_timeout_ms < 100:
            piggyback_timeout_ms = 100
        if piggyback_timeout_ms > 120000:
            piggyback_timeout_ms = 120000

        disable_ui_fallback = os.environ.get(
            "PYWEIXIN_HOOK_DISABLE_UI_FALLBACK_FOR_BENCH", "0"
        ) in {"1", "true", "True", "yes", "on"}
        piggyback_ui_bootstrap = os.environ.get(
            "PYWEIXIN_HOOK_PIGGYBACK_UI_BOOTSTRAP", "1"
        ) in {"1", "true", "True", "yes", "on"}
        http_ui_bootstrap = os.environ.get(
            "PYWEIXIN_HTTP_BOOTSTRAP_UI", "0"
        ) in {"1", "true", "True", "yes", "on"}
        try:
            http_batch_wait_ms = int(
                os.environ.get("PYWEIXIN_HTTP_BATCH_WAIT_MS", "30000")
            )
        except ValueError:
            http_batch_wait_ms = 30000
        if http_batch_wait_ms < 100:
            http_batch_wait_ms = 100
        if http_batch_wait_ms > 120000:
            http_batch_wait_ms = 120000

        if concurrency < 1:
            concurrency = 1
        if concurrency > 20:
            concurrency = 20

        # --- Resolve SNS ID once for batch ---
        effective_sns_id = sns_id
        if not effective_sns_id and self._hook_sender is not None:
            bridge = self._hook_sender.bridge
            resp = bridge.get_latest_sns_id()
            if resp.ok:
                effective_sns_id = resp.data.get("sns_id", "")
                print(f"[batch-dispatch] got latest sns_id: {effective_sns_id}")

        def _send_one_serial(comment_text: str) -> CommentResult:
            last_hook_error: CommentResult | None = None
            if self._hook_sender is not None and not self._breaker.is_open:
                hook_kwargs = dict(
                    content=comment_text,
                    sns_id=effective_sns_id,
                    author=author if not effective_sns_id else "",
                    content_hash=content_hash if not effective_sns_id else "",
                    reply_to=reply_to,
                )
                hr = self._hook_sender.send_comment(**hook_kwargs)
                if hr.success:
                    self._breaker.record_success()
                    return hr
                last_hook_error = hr
                self._breaker.record_failure()

            if self._ui_sender is not None and not disable_ui_fallback:
                return self._ui_sender.send_comment(
                    comment_text,
                    sns_id=effective_sns_id,
                    author=author if not effective_sns_id else "",
                    content_hash=content_hash if not effective_sns_id else "",
                    reply_to=reply_to,
                )

            if last_hook_error is not None:
                return last_hook_error

            return CommentResult(
                success=False,
                method="none",
                error_code=HookErrorCode.COMMENT_FAILED,
                error_message="no sender available for batch item",
            )

        if self._http_sender is not None:
            http_batch_exc: Exception | None = None
            http_batch_resp: BatchCommentResult | None = None
            http_batch_comments = comments
            if http_ui_bootstrap and self._ui_sender is not None and len(comments) > 1:
                # For real HTTP->hook piggyback backends, queue batch first and
                # then trigger one UI comment to fire the hook callback.
                holder: dict[str, BatchCommentResult] = {}
                holder_exc: dict[str, Exception] = {}
                remaining = comments[1:]
                http_batch_comments = remaining

                def _run_http_batch() -> None:
                    try:
                        holder["res"] = self._http_sender.send_batch_comments(
                            remaining,
                            sns_id=effective_sns_id,
                            author=author if not effective_sns_id else "",
                            content_hash=content_hash if not effective_sns_id else "",
                            reply_to=reply_to,
                            max_concurrency=concurrency,
                        )
                    except Exception as exc:  # pragma: no cover
                        holder_exc["err"] = exc

                t = threading.Thread(target=_run_http_batch, daemon=True)
                t.start()
                time.sleep(0.05)

                first = self._ui_sender.send_comment(
                    comments[0],
                    sns_id=effective_sns_id,
                    author=author if not effective_sns_id else "",
                    content_hash=content_hash if not effective_sns_id else "",
                    reply_to=reply_to,
                )
                results.append(first)

                if not first.success:
                    t.join(timeout=1.0)
                else:
                    t.join(timeout=(http_batch_wait_ms / 1000.0) + 1.0)

                if "err" in holder_exc:
                    http_batch_exc = holder_exc["err"]
                elif "res" in holder:
                    http_batch_resp = holder["res"]
                else:
                    http_batch_exc = RuntimeError("http batch did not finish in time")
            else:
                try:
                    http_batch_resp = self._http_sender.send_batch_comments(
                        comments,
                        sns_id=effective_sns_id,
                        author=author if not effective_sns_id else "",
                        content_hash=content_hash if not effective_sns_id else "",
                        reply_to=reply_to,
                        max_concurrency=concurrency,
                    )
                except Exception as exc:
                    http_batch_exc = exc

            if http_batch_exc is None and http_batch_resp is not None:
                raw_batch_total = int(http_batch_resp.total)
                raw_batch_succeeded = int(http_batch_resp.succeeded)
                raw_batch_failed = int(http_batch_resp.failed)
                print(
                    f"[batch-dispatch] http: {raw_batch_succeeded}/"
                    f"{raw_batch_total} in {http_batch_resp.total_latency_ms}ms"
                )

                for idx, comment_text in enumerate(http_batch_comments):
                    if idx < len(http_batch_resp.results):
                        item_res = http_batch_resp.results[idx]
                    else:
                        item_res = CommentResult(
                            success=False,
                            method="http",
                            error_code=HookErrorCode.COMMENT_FAILED,
                            error_message="missing http batch result entry",
                        )
                    if item_res.success:
                        results.append(item_res)
                    else:
                        if disable_ui_fallback:
                            results.append(item_res)
                            continue
                        fallback = _send_one_serial(comment_text)
                        results.append(fallback)
                        fallback_count += 1

                elapsed = int((time.time() - batch_start) * 1000)
                succeeded = sum(1 for r in results if r.success)
                return BatchCommentResult(
                    total=len(comments),
                    succeeded=succeeded,
                    failed=len(comments) - succeeded,
                    total_latency_ms=elapsed,
                    results=results,
                    mode="http",
                    raw_batch_total=raw_batch_total,
                    raw_batch_succeeded=raw_batch_succeeded,
                    raw_batch_failed=raw_batch_failed,
                    fallback_count=fallback_count,
                )

            if http_batch_exc is not None:
                print(f"[batch-dispatch] http batch failed: {http_batch_exc}")
                if self._hook_sender is None:
                    # No hook sender to continue fallback chain. Finalize here
                    # to avoid overriding already-sent bootstrap success.
                    pending = list(http_batch_comments)
                    if disable_ui_fallback:
                        for _ in pending:
                            results.append(
                                CommentResult(
                                    success=False,
                                    method="http",
                                    error_code=HookErrorCode.COMMENT_FAILED,
                                    error_message=f"http batch failed in strict mode: {http_batch_exc}",
                                )
                            )
                    else:
                        for c in pending:
                            fallback = _send_one_serial(c)
                            results.append(fallback)
                            fallback_count += 1

                    elapsed = int((time.time() - batch_start) * 1000)
                    succeeded = sum(1 for r in results if r.success)
                    return BatchCommentResult(
                        total=len(comments),
                        succeeded=succeeded,
                        failed=len(comments) - succeeded,
                        total_latency_ms=elapsed,
                        results=results,
                        mode="http",
                        raw_batch_total=raw_batch_total,
                        raw_batch_succeeded=raw_batch_succeeded,
                        raw_batch_failed=raw_batch_failed,
                        fallback_count=fallback_count,
                    )

        # Degenerate/small cases use strict serial behavior.
        if len(comments) == 1 or batch_mode == "serial":
            for c in comments:
                results.append(_send_one_serial(c))
            elapsed = int((time.time() - batch_start) * 1000)
            succeeded = sum(1 for r in results if r.success)
            return BatchCommentResult(
                total=len(comments),
                succeeded=succeeded,
                failed=len(comments) - succeeded,
                total_latency_ms=elapsed,
                results=results,
                mode=batch_mode,
                raw_batch_total=0,
                raw_batch_succeeded=0,
                raw_batch_failed=0,
                fallback_count=0,
            )

        remaining = comments[1:]
        can_use_hook_batch = (
            self._hook_sender is not None
            and not self._breaker.is_open
            and bool(effective_sns_id)
        )

        if not remaining:
            results.append(_send_one_serial(comments[0]))
            elapsed = int((time.time() - batch_start) * 1000)
            succeeded = sum(1 for r in results if r.success)
            return BatchCommentResult(
                total=len(comments),
                succeeded=succeeded,
                failed=len(comments) - succeeded,
                total_latency_ms=elapsed,
                results=results,
                mode=batch_mode,
                raw_batch_total=0,
                raw_batch_succeeded=0,
                raw_batch_failed=0,
                fallback_count=0,
            )

        if not can_use_hook_batch:
            print("[batch-dispatch] hook batch unavailable, serial fallback")
            if disable_ui_fallback:
                elapsed = int((time.time() - batch_start) * 1000)
                fail_results = [
                    CommentResult(
                        success=False,
                        method=batch_mode,
                        error_code=HookErrorCode.COMMENT_FAILED,
                        error_message="hook batch unavailable in strict no-fallback mode",
                    )
                    for _ in comments
                ]
                return BatchCommentResult(
                    total=len(comments),
                    succeeded=0,
                    failed=len(comments),
                    total_latency_ms=elapsed,
                    results=fail_results,
                    mode=batch_mode,
                    raw_batch_total=0,
                    raw_batch_succeeded=0,
                    raw_batch_failed=0,
                    fallback_count=0,
                )
            results.append(_send_one_serial(comments[0]))
            for c in remaining:
                results.append(_send_one_serial(c))
            fallback_count += len(remaining)
            elapsed = int((time.time() - batch_start) * 1000)
            succeeded = sum(1 for r in results if r.success)
            return BatchCommentResult(
                total=len(comments),
                succeeded=succeeded,
                failed=len(comments) - succeeded,
                total_latency_ms=elapsed,
                results=results,
                mode=batch_mode,
                raw_batch_total=0,
                raw_batch_succeeded=0,
                raw_batch_failed=0,
                fallback_count=fallback_count,
            )

        bridge = self._hook_sender.bridge
        batch_resp: BatchCommentResult | None = None
        batch_exc: Exception | None = None

        if batch_mode == "parallel":
            results.append(_send_one_serial(comments[0]))
            try:
                batch_resp = bridge.send_parallel_comments(
                    remaining,
                    sns_id=effective_sns_id,
                    reply_to=reply_to,
                    max_concurrency=concurrency,
                )
            except Exception as exc:
                batch_exc = exc
        else:
            # piggyback: queue first, then trigger via bootstrap comment.
            holder: dict[str, BatchCommentResult] = {}
            holder_exc: dict[str, Exception] = {}

            def _run_piggyback() -> None:
                try:
                    holder["res"] = bridge.send_piggyback_comments(
                        remaining,
                        sns_id=effective_sns_id,
                        reply_to=reply_to,
                        max_concurrency=concurrency,
                        timeout_ms=piggyback_timeout_ms,
                    )
                except Exception as exc:  # pragma: no cover
                    holder_exc["err"] = exc

            t = threading.Thread(target=_run_piggyback, daemon=True)
            t.start()
            # Give pipe request a tiny head start before bootstrap comment.
            time.sleep(0.05)

            # Trigger hook callback after piggyback queue is installed.
            if self._ui_sender is not None and piggyback_ui_bootstrap:
                first = self._ui_sender.send_comment(
                    comments[0],
                    sns_id=effective_sns_id,
                    author=author if not effective_sns_id else "",
                    content_hash=content_hash if not effective_sns_id else "",
                    reply_to=reply_to,
                )
            else:
                first = _send_one_serial(comments[0])
            results.append(first)

            if not first.success:
                # Bootstrap failed; still wait briefly in case queue drains later.
                t.join(timeout=1.0)
            else:
                t.join(timeout=(piggyback_timeout_ms / 1000.0) + 1.0)

            if "err" in holder_exc:
                batch_exc = holder_exc["err"]
            elif "res" in holder:
                batch_resp = holder["res"]
            else:
                batch_exc = RuntimeError("piggyback batch did not finish in time")

        if batch_exc is not None:
            print(f"[batch-dispatch] {batch_mode} batch failed: {batch_exc}")
            if disable_ui_fallback:
                elapsed = int((time.time() - batch_start) * 1000)
                # Keep already executed first result, mark remaining as failed.
                for _ in remaining:
                    results.append(
                        CommentResult(
                            success=False,
                            method=batch_mode,
                            error_code=HookErrorCode.COMMENT_FAILED,
                            error_message=f"{batch_mode} batch failed in strict mode: {batch_exc}",
                        )
                    )
                succeeded = sum(1 for r in results if r.success)
                return BatchCommentResult(
                    total=len(comments),
                    succeeded=succeeded,
                    failed=len(comments) - succeeded,
                    total_latency_ms=elapsed,
                    results=results,
                    mode=batch_mode,
                    raw_batch_total=raw_batch_total,
                    raw_batch_succeeded=raw_batch_succeeded,
                    raw_batch_failed=raw_batch_failed,
                    fallback_count=0,
                )
            for c in remaining:
                results.append(_send_one_serial(c))
            fallback_count += len(remaining)
        else:
            assert batch_resp is not None
            raw_batch_total = int(batch_resp.total)
            raw_batch_succeeded = int(batch_resp.succeeded)
            raw_batch_failed = int(batch_resp.failed)
            print(
                f"[batch-dispatch] {batch_mode}: {batch_resp.succeeded}/"
                f"{batch_resp.total} in {batch_resp.total_latency_ms}ms"
            )
            # Strict: keep batch successes, fallback only failed items.
            for idx, comment_text in enumerate(remaining):
                if idx < len(batch_resp.results):
                    item_res = batch_resp.results[idx]
                else:
                    item_res = CommentResult(
                        success=False,
                        method=batch_mode,
                        error_code=HookErrorCode.COMMENT_FAILED,
                        error_message="missing batch result entry",
                    )
                if item_res.success:
                    results.append(item_res)
                else:
                    if disable_ui_fallback:
                        results.append(item_res)
                        continue
                    fallback = _send_one_serial(comment_text)
                    results.append(fallback)
                    fallback_count += 1

        elapsed = int((time.time() - batch_start) * 1000)
        succeeded = sum(1 for r in results if r.success)
        return BatchCommentResult(
            total=len(comments),
            succeeded=succeeded,
            failed=len(comments) - succeeded,
            total_latency_ms=elapsed,
            results=results,
            mode=batch_mode,
            raw_batch_total=raw_batch_total,
            raw_batch_succeeded=raw_batch_succeeded,
            raw_batch_failed=raw_batch_failed,
            fallback_count=fallback_count,
        )
