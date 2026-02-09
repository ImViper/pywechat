"""
Viper Comment Dispatcher -- unified Hook + UI fallback with circuit breaker.
不修改 upstream 代码，只导入公共 API。
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field

try:
    from .hook_types import CommentResult, CommentSender, HookErrorCode
    from .hook_bridge import HookBridge
except ImportError:  # pragma: no cover
    from hook_types import CommentResult, CommentSender, HookErrorCode
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

    def __init__(self, bridge: HookBridge):
        self._bridge = bridge

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

        resp = self._bridge.send_comment(
            content, sns_id=effective_sns_id, reply_to=reply_to
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
                hook_sender = HookCommentSender(bridge)

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
