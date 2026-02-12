"""Tests for comment_dispatcher -- mock senders, circuit breaker, fallback."""

import sys
import os
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pyweixin.hook_types import (
    BatchCommentResult,
    CommentResult,
    HookErrorCode,
    PipeResponse,
)
from pyweixin.comment_dispatcher import (
    CircuitBreakerState,
    CommentDispatcher,
    HookCommentSender,
    HttpCommentSender,
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


class MockHTTPSender:
    """Configurable mock HTTP sender."""
    def __init__(
        self,
        *,
        single_results: list[CommentResult] | None = None,
        batch_result: BatchCommentResult | None = None,
        batch_exc: Exception | None = None,
    ):
        self._single_results = list(single_results or [])
        self._batch_result = batch_result
        self._batch_exc = batch_exc
        self.single_call_count = 0
        self.batch_call_count = 0

    def send_comment(self, content, *, sns_id="", author="", content_hash="", reply_to="") -> CommentResult:
        self.single_call_count += 1
        if self._single_results:
            return self._single_results.pop(0)
        return CommentResult(success=True, method="http", latency_ms=20)

    def send_batch_comments(
        self,
        comments,
        *,
        sns_id="",
        author="",
        content_hash="",
        reply_to="",
        max_concurrency=10,
    ) -> BatchCommentResult:
        self.batch_call_count += 1
        if self._batch_exc is not None:
            raise self._batch_exc
        if self._batch_result is not None:
            return self._batch_result
        return BatchCommentResult(
            total=len(comments),
            succeeded=len(comments),
            failed=0,
            total_latency_ms=50,
            results=[CommentResult(success=True, method="http", latency_ms=5) for _ in comments],
        )


class MockBridge:
    def __init__(
        self,
        *,
        query_ok=False,
        latest_ok=False,
        sns_id="q123",
        parallel_result: BatchCommentResult | None = None,
        piggyback_result: BatchCommentResult | None = None,
    ):
        self.query_ok = query_ok
        self.latest_ok = latest_ok
        self.sns_id = sns_id
        self.last_send_sns_id = None
        self.last_send_kwargs = {}
        self.send_comment_calls = 0
        self.parallel_calls = 0
        self.piggyback_calls = 0
        self._parallel_result = parallel_result
        self._piggyback_result = piggyback_result

    def query_sns_id(self, author, content_hash):
        if self.query_ok:
            return PipeResponse(ok=True, data={"sns_id": self.sns_id})
        return PipeResponse(ok=False, error_code=HookErrorCode.SNS_ID_NOT_FOUND)

    def get_latest_sns_id(self):
        if self.latest_ok:
            return PipeResponse(ok=True, data={"sns_id": self.sns_id})
        return PipeResponse(ok=False, error_code=HookErrorCode.SNS_ID_NOT_FOUND)

    def send_comment(
        self,
        content,
        *,
        sns_id="",
        reply_to="",
        allow_queue_fallback=False,
        prefer_arg1_template=True,
        execution_mode="pipe_thread",
        wait_timeout_ms=1500,
    ):
        self.send_comment_calls += 1
        self.last_send_sns_id = sns_id
        self.last_send_kwargs = {
            "reply_to": reply_to,
            "allow_queue_fallback": allow_queue_fallback,
            "prefer_arg1_template": prefer_arg1_template,
            "execution_mode": execution_mode,
            "wait_timeout_ms": wait_timeout_ms,
        }
        return PipeResponse(ok=True, error_code=0, latency_ms=5, data={})

    def send_parallel_comments(
        self,
        comments,
        *,
        sns_id="",
        reply_to="",
        max_concurrency=10,
        tls_mode="implicit",
    ):
        self.parallel_calls += 1
        if self._parallel_result is not None:
            return self._parallel_result
        return BatchCommentResult(
            total=len(comments),
            succeeded=len(comments),
            failed=0,
            total_latency_ms=10,
            results=[
                CommentResult(success=True, method="hook_parallel", latency_ms=5)
                for _ in comments
            ],
        )

    def send_piggyback_comments(
        self,
        comments,
        *,
        sns_id="",
        reply_to="",
        max_concurrency=10,
        timeout_ms=30000,
    ):
        self.piggyback_calls += 1
        if self._piggyback_result is not None:
            return self._piggyback_result
        return BatchCommentResult(
            total=len(comments),
            succeeded=len(comments),
            failed=0,
            total_latency_ms=10,
            results=[
                CommentResult(success=True, method="piggyback", latency_ms=5)
                for _ in comments
            ],
        )


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
    def test_http_success_skips_hook_and_ui(self):
        http = MockHTTPSender(
            single_results=[CommentResult(success=True, method="http", latency_ms=12)]
        )
        hook = MockHookSender()
        ui = MockUISender()
        d = CommentDispatcher(http_sender=http, hook_sender=hook, ui_sender=ui)
        result = d.post_comment("hello")
        assert result.success is True
        assert result.method == "http"
        assert http.single_call_count == 1
        assert hook.call_count == 0
        assert ui.call_count == 0

    def test_http_fail_fallback_to_hook(self):
        http = MockHTTPSender(
            single_results=[
                CommentResult(
                    success=False,
                    method="http",
                    error_code=HookErrorCode.COMMENT_FAILED,
                    error_message="http down",
                )
            ]
        )
        hook = MockHookSender()
        ui = MockUISender()
        d = CommentDispatcher(http_sender=http, hook_sender=hook, ui_sender=ui)
        result = d.post_comment("hello")
        assert result.success is True
        assert result.method == "hook"
        assert http.single_call_count == 1
        assert hook.call_count == 1
        assert ui.call_count == 0

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

    def test_post_batch_parallel_partial_triggers_serial_fallback(self, monkeypatch):
        monkeypatch.setenv("PYWEIXIN_HOOK_BATCH_MODE", "parallel")
        partial = BatchCommentResult(
            total=2,
            succeeded=1,
            failed=1,
            total_latency_ms=12,
            results=[
                CommentResult(success=True, method="hook_parallel", latency_ms=3),
                CommentResult(
                    success=False,
                    method="hook_parallel",
                    latency_ms=3,
                    error_code=HookErrorCode.COMMENT_FAILED,
                    error_message="partial",
                ),
            ],
        )
        bridge = MockBridge(parallel_result=partial)
        sender = HookCommentSender(bridge)
        d = CommentDispatcher(hook_sender=sender, ui_sender=None)

        r = d.post_batch_comments(["c1", "c2", "c3"], sns_id="sid")

        assert bridge.parallel_calls == 1
        # Strict mode fallback: first comment + one failed item replayed serially.
        assert bridge.send_comment_calls == 2
        assert r.total == 3
        assert r.succeeded == 3
        assert r.failed == 0

    def test_post_batch_piggyback_uses_ui_bootstrap(self, monkeypatch):
        monkeypatch.setenv("PYWEIXIN_HOOK_BATCH_MODE", "piggyback")
        pig = BatchCommentResult(
            total=2,
            succeeded=2,
            failed=0,
            total_latency_ms=15,
            results=[
                CommentResult(success=True, method="piggyback", latency_ms=7),
                CommentResult(success=True, method="piggyback", latency_ms=8),
            ],
        )
        bridge = MockBridge(piggyback_result=pig)
        sender = HookCommentSender(bridge)
        ui = MockUISender(success=True)
        d = CommentDispatcher(hook_sender=sender, ui_sender=ui)

        r = d.post_batch_comments(["b1", "b2", "b3"], sns_id="sid")

        assert bridge.piggyback_calls == 1
        assert ui.call_count == 1
        # First comment uses UI bootstrap, remaining come from piggyback batch.
        assert bridge.send_comment_calls == 0
        assert r.total == 3
        assert r.succeeded == 3

    def test_parallel_strict_no_fallback_keeps_failures(self, monkeypatch):
        monkeypatch.setenv("PYWEIXIN_HOOK_BATCH_MODE", "parallel")
        monkeypatch.setenv("PYWEIXIN_HOOK_DISABLE_UI_FALLBACK_FOR_BENCH", "1")
        partial = BatchCommentResult(
            total=2,
            succeeded=0,
            failed=2,
            total_latency_ms=8,
            results=[
                CommentResult(
                    success=False,
                    method="hook_parallel",
                    latency_ms=4,
                    error_code=HookErrorCode.COMMENT_FAILED,
                    error_message="p1",
                ),
                CommentResult(
                    success=False,
                    method="hook_parallel",
                    latency_ms=4,
                    error_code=HookErrorCode.COMMENT_FAILED,
                    error_message="p2",
                ),
            ],
        )
        bridge = MockBridge(parallel_result=partial)
        sender = HookCommentSender(bridge)
        d = CommentDispatcher(hook_sender=sender, ui_sender=None)

        r = d.post_batch_comments(["c1", "c2", "c3"], sns_id="sid")

        assert r.total == 3
        assert r.succeeded == 1
        assert r.failed == 2
        assert r.fallback_count == 0
        assert r.raw_batch_total == 2
        assert r.raw_batch_succeeded == 0
        assert r.raw_batch_failed == 2
        assert bridge.send_comment_calls == 1  # first comment only

    def test_piggyback_strict_mode_still_ui_bootstrap(self, monkeypatch):
        monkeypatch.setenv("PYWEIXIN_HOOK_BATCH_MODE", "piggyback")
        monkeypatch.setenv("PYWEIXIN_HOOK_DISABLE_UI_FALLBACK_FOR_BENCH", "1")
        monkeypatch.setenv("PYWEIXIN_HOOK_PIGGYBACK_UI_BOOTSTRAP", "1")
        pig = BatchCommentResult(
            total=2,
            succeeded=2,
            failed=0,
            total_latency_ms=10,
            results=[
                CommentResult(success=True, method="piggyback", latency_ms=5),
                CommentResult(success=True, method="piggyback", latency_ms=5),
            ],
        )
        bridge = MockBridge(piggyback_result=pig)
        sender = HookCommentSender(bridge)
        ui = MockUISender(success=True)
        d = CommentDispatcher(hook_sender=sender, ui_sender=ui)

        r = d.post_batch_comments(["b1", "b2", "b3"], sns_id="sid")

        assert ui.call_count == 1  # bootstrap still happens
        assert r.total == 3
        assert r.succeeded == 3
        assert r.failed == 0
        assert r.fallback_count == 0

    def test_http_batch_partial_triggers_hook_fallback(self):
        http = MockHTTPSender(
            batch_result=BatchCommentResult(
                total=3,
                succeeded=2,
                failed=1,
                total_latency_ms=20,
                results=[
                    CommentResult(success=True, method="http", latency_ms=4),
                    CommentResult(success=False, method="http", latency_ms=4, error_code=30, error_message="x"),
                    CommentResult(success=True, method="http", latency_ms=4),
                ],
            )
        )
        hook = MockHookSender()
        d = CommentDispatcher(http_sender=http, hook_sender=hook, ui_sender=None)

        r = d.post_batch_comments(["c1", "c2", "c3"], sns_id="sid")

        assert http.batch_call_count == 1
        assert hook.call_count == 1
        assert r.total == 3
        assert r.succeeded == 3
        assert r.failed == 0
        assert r.mode == "http"
        assert r.raw_batch_total == 3
        assert r.raw_batch_succeeded == 2
        assert r.raw_batch_failed == 1
        assert r.fallback_count == 1

    def test_http_batch_ui_bootstrap_flow(self, monkeypatch):
        monkeypatch.setenv("PYWEIXIN_HTTP_BOOTSTRAP_UI", "1")
        http = MockHTTPSender(
            batch_result=BatchCommentResult(
                total=2,
                succeeded=2,
                failed=0,
                total_latency_ms=18,
                results=[
                    CommentResult(success=True, method="http", latency_ms=8),
                    CommentResult(success=True, method="http", latency_ms=10),
                ],
            )
        )
        ui = MockUISender(success=True)
        d = CommentDispatcher(http_sender=http, hook_sender=None, ui_sender=ui)

        r = d.post_batch_comments(["b1", "b2", "b3"], sns_id="sid")

        assert http.batch_call_count == 1
        assert ui.call_count == 1
        assert r.total == 3
        assert r.succeeded == 3
        assert r.failed == 0
        assert r.raw_batch_total == 2
        assert r.raw_batch_succeeded == 2

    def test_http_batch_error_preserves_bootstrap_result(self, monkeypatch):
        monkeypatch.setenv("PYWEIXIN_HTTP_BOOTSTRAP_UI", "1")
        monkeypatch.setenv("PYWEIXIN_HOOK_DISABLE_UI_FALLBACK_FOR_BENCH", "1")
        http = MockHTTPSender(batch_exc=TimeoutError("http timeout"))
        ui = MockUISender(success=True)
        d = CommentDispatcher(http_sender=http, hook_sender=None, ui_sender=ui)

        r = d.post_batch_comments(["b1", "b2", "b3"], sns_id="sid")

        assert http.batch_call_count == 1
        assert ui.call_count == 1
        assert r.total == 3
        assert r.succeeded == 1
        assert r.failed == 2
        assert r.mode == "http"


class TestHookCommentSender:
    def test_fallback_to_latest_sns_id(self):
        bridge = MockBridge(query_ok=False, latest_ok=True, sns_id="q_latest")
        sender = HookCommentSender(bridge)
        r = sender.send_comment("hello", author="a", content_hash="h")
        assert r.success is True
        assert bridge.last_send_sns_id == "q_latest"

    def test_query_hit_priority_over_latest(self):
        bridge = MockBridge(query_ok=True, latest_ok=True, sns_id="q_query")
        sender = HookCommentSender(bridge)
        r = sender.send_comment("hello", author="a", content_hash="h")
        assert r.success is True
        assert bridge.last_send_sns_id == "q_query"

    def test_default_execution_mode_is_capture_thread(self):
        bridge = MockBridge(query_ok=True, latest_ok=True, sns_id="q_query")
        sender = HookCommentSender(bridge)
        sender.send_comment("hello", author="a", content_hash="h")
        assert bridge.last_send_kwargs["execution_mode"] == "capture_thread"
        assert bridge.last_send_kwargs["wait_timeout_ms"] == 400


class TestHttpCommentSender:
    def test_parse_ok_from_code_message(self):
        sender = HttpCommentSender(base_url="http://127.0.0.1:19080")

        def fake_post(path, payload):
            return {
                "code": 200,
                "message": "success",
                "latency_ms": 18,
                "data": {},
            }

        sender._http_post_json = fake_post
        r = sender.send_comment("hello", sns_id="sid")
        assert r.success is True
        assert r.method == "http"
        assert r.latency_ms == 18

    def test_batch_compat_without_results(self):
        sender = HttpCommentSender(base_url="http://127.0.0.1:19080")

        def fake_post(path, payload):
            return {
                "ok": True,
                "latency_ms": 12,
                "data": {
                    "total": 3,
                    "succeeded": 3,
                    "failed": 0,
                    "total_latency_ms": 12,
                },
            }

        sender._http_post_json = fake_post
        r = sender.send_batch_comments(["a", "b", "c"], sns_id="sid")
        assert r.total == 3
        assert r.succeeded == 3
        assert r.failed == 0
        assert len(r.results) == 3
        assert all(x.success for x in r.results)
        assert r.raw_batch_total == 3
        assert r.raw_batch_succeeded == 3
