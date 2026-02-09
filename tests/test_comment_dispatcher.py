"""Tests for comment_dispatcher -- mock senders, circuit breaker, fallback."""

import sys
import os
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pyweixin.hook_types import CommentResult, HookErrorCode
from pyweixin.comment_dispatcher import (
    CircuitBreakerState,
    CommentDispatcher,
)


# ---------------------------------------------------------------------------
# Mock senders
# ---------------------------------------------------------------------------

class MockHookSender:
    """Configurable mock that implements CommentSender."""
    def __init__(self, results: list[CommentResult] | None = None):
        self._results = list(results or [])
        self._call_count = 0

    def send_comment(self, content, *, sns_id="", author="",
                     content_hash="", reply_to="") -> CommentResult:
        self._call_count += 1
        if self._results:
            return self._results.pop(0)
        return CommentResult(success=True, method="hook", latency_ms=5)

    @property
    def call_count(self):
        return self._call_count


class MockUISender:
    """Always-succeeds UI mock."""
    def __init__(self, success: bool = True):
        self._success = success
        self._call_count = 0

    def send_comment(self, content, *, sns_id="", author="",
                     content_hash="", reply_to="") -> CommentResult:
        self._call_count += 1
        return CommentResult(success=self._success, method="ui", latency_ms=800)

    @property
    def call_count(self):
        return self._call_count


# ---------------------------------------------------------------------------
# Circuit breaker tests
# ---------------------------------------------------------------------------

class TestCircuitBreaker:
    def test_starts_closed(self):
        cb = CircuitBreakerState(threshold=3)
        assert cb.is_open is False

    def test_opens_after_threshold(self):
        cb = CircuitBreakerState(threshold=3, recovery_sec=60)
        cb.record_failure()
        cb.record_failure()
        assert cb.is_open is False
        cb.record_failure()
        assert cb.is_open is True

    def test_success_resets(self):
        cb = CircuitBreakerState(threshold=2)
        cb.record_failure()
        cb.record_failure()
        assert cb.is_open is True
        cb.record_success()
        assert cb.is_open is False

    def test_half_open_after_recovery(self):
        cb = CircuitBreakerState(threshold=1, recovery_sec=0.1)
        cb.record_failure()
        assert cb.is_open is True
        time.sleep(0.15)
        assert cb.is_open is False  # half-open


# ---------------------------------------------------------------------------
# Dispatcher tests
# ---------------------------------------------------------------------------

class TestCommentDispatcher:
    def test_hook_success(self):
        hook = MockHookSender()
        ui = MockUISender()
        d = CommentDispatcher(hook_sender=hook, ui_sender=ui)
        result = d.post_comment("hello")
        assert result.success is True
        assert result.method == "hook"
        assert hook.call_count == 1
        assert ui.call_count == 0

    def test_hook_fail_fallback_to_ui(self):
        fail_result = CommentResult(
            success=False, method="hook",
            error_code=HookErrorCode.COMMENT_NOT_IMPLEMENTED,
            error_message="not implemented"
        )
        hook = MockHookSender(results=[fail_result])
        ui = MockUISender(success=True)
        d = CommentDispatcher(hook_sender=hook, ui_sender=ui)
        result = d.post_comment("hello")
        assert result.success is True
        assert result.method == "ui"
        assert hook.call_count == 1
        assert ui.call_count == 1

    def test_circuit_breaker_skips_hook(self):
        fail = CommentResult(
            success=False, method="hook",
            error_code=HookErrorCode.COMMENT_FAILED,
            error_message="fail"
        )
        hook = MockHookSender(results=[fail, fail, fail])
        ui = MockUISender(success=True)
        cb = CircuitBreakerState(threshold=3, recovery_sec=60)
        d = CommentDispatcher(hook_sender=hook, ui_sender=ui, circuit_breaker=cb)

        # First 3 calls: hook fails, falls to UI each time, breaker records failures
        for _ in range(3):
            d.post_comment("test")

        # 4th call: breaker is open, hook skipped
        hook_4 = MockHookSender()  # would succeed if called
        d._hook_sender = hook_4
        result = d.post_comment("test")
        assert result.method == "ui"
        assert hook_4.call_count == 0

    def test_no_senders(self):
        d = CommentDispatcher()
        result = d.post_comment("hello")
        assert result.success is False
        assert result.method == "none"

    def test_ui_only(self):
        ui = MockUISender(success=True)
        d = CommentDispatcher(ui_sender=ui)
        result = d.post_comment("hello")
        assert result.success is True
        assert result.method == "ui"
