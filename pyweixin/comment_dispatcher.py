"""
Viper Comment Dispatcher -- unified Hook + UI fallback with circuit breaker.
不修改 upstream 代码，只导入公共 API。
"""

from __future__ import annotations

import os
import time
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
    """Unified comment entry point: Hook first, UI fallback.

    Usage::

        dispatcher = CommentDispatcher.from_env(...)
        result = dispatcher.post_comment("5男")
    """

    def __init__(
        self,
        hook_sender: HookCommentSender | None = None,
        ui_sender: UICommentSender | None = None,
        circuit_breaker: CircuitBreakerState | None = None,
    ):
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
        hook_sender: HookCommentSender | None = None

        if os.environ.get("PYWEIXIN_HOOK_ENABLED", "0") == "1":
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

        return cls(hook_sender=hook_sender, ui_sender=ui_sender)

    def post_comment(
        self,
        content: str,
        *,
        sns_id: str = "",
        author: str = "",
        content_hash: str = "",
        reply_to: str = "",
    ) -> CommentResult:
        """Try Hook first; on failure fall back to UI."""
        kwargs = dict(
            content=content,
            sns_id=sns_id,
            author=author,
            content_hash=content_hash,
            reply_to=reply_to,
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
        """Send N comments: 1st via UI (triggers hook), rest via parallel DLL.

        Strategy (parallel-first):
          1. First comment goes through normal post_comment() (UI triggers hook).
          2. Remaining comments sent via DLL parallel_comment (thread pool
             with TLS context copy) for ~618ms total.
          3. Falls back to serial capture_thread if parallel unavailable.
          4. Falls back to sequential UI if hook is unavailable.
        """
        if not comments:
            return BatchCommentResult()

        results: list[CommentResult] = []
        batch_start = time.time()

        # --- Step 1: Bootstrap first comment (UI path triggers hook) ---
        first = self.post_comment(
            comments[0],
            sns_id=sns_id,
            author=author,
            content_hash=content_hash,
            reply_to=reply_to,
        )
        results.append(first)

        if len(comments) == 1:
            elapsed = int((time.time() - batch_start) * 1000)
            return BatchCommentResult(
                total=1,
                succeeded=1 if first.success else 0,
                failed=0 if first.success else 1,
                total_latency_ms=elapsed,
                results=results,
            )

        remaining = comments[1:]

        # --- Step 2: Resolve SNS ID ---
        effective_sns_id = sns_id
        if not effective_sns_id and self._hook_sender is not None:
            bridge = self._hook_sender.bridge
            resp = bridge.get_latest_sns_id()
            if resp.ok:
                effective_sns_id = resp.data.get("sns_id", "")
                print(f"[batch-dispatch] got latest sns_id: {effective_sns_id}")

        # --- Step 3: Try parallel path first, then serial fallback ---
        if effective_sns_id and self._hook_sender is not None and not self._breaker.is_open:
            bridge = self._hook_sender.bridge

            # 3a. Parallel path: send all remaining via DLL thread pool
            parallel_ok = False
            try:
                par = bridge.send_parallel_comments(
                    remaining,
                    sns_id=effective_sns_id,
                    reply_to=reply_to,
                    max_concurrency=concurrency,
                )
                if par.succeeded > 0:
                    parallel_ok = True
                    results.extend(par.results)
                    self._breaker.record_success()
                    print(
                        f"[batch-dispatch] parallel: {par.succeeded}/{par.total} ok "
                        f"in {par.total_latency_ms}ms"
                    )
            except Exception as exc:
                print(f"[batch-dispatch] parallel failed: {exc}")

            # 3b. Serial fallback via capture_thread
            if not parallel_ok:
                print("[batch-dispatch] parallel unavailable, serial capture_thread")
                for c in remaining:
                    r = self._hook_sender.send_comment(
                        c,
                        sns_id=effective_sns_id,
                        reply_to=reply_to,
                    )
                    results.append(r)
                    if r.success:
                        self._breaker.record_success()
                    else:
                        self._breaker.record_failure()
                        if self._ui_sender is not None:
                            print("[batch-dispatch] capture_thread failed, UI fallback")
                            break
        else:
            # Fallback: sequential post_comment for each remaining
            print("[batch-dispatch] no sns_id or hook unavailable, sequential fallback")
            for c in remaining:
                r = self.post_comment(
                    c,
                    sns_id=effective_sns_id,
                    author=author,
                    content_hash=content_hash,
                    reply_to=reply_to,
                )
                results.append(r)

        elapsed = int((time.time() - batch_start) * 1000)
        succeeded = sum(1 for r in results if r.success)
        return BatchCommentResult(
            total=len(comments),
            succeeded=succeeded,
            failed=len(comments) - succeeded,
            total_latency_ms=elapsed,
            results=results,
        )
