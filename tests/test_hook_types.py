"""Tests for hook_types -- serialization, error codes, protocol."""

import json
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pyweixin.hook_types import (
    CommentCommand,
    CommentResult,
    HookErrorCode,
    PingCommand,
    PipeResponse,
    QuerySnsIdCommand,
    VersionCommand,
    PROTOCOL_VERSION,
)


class TestHookErrorCode:
    def test_values(self):
        assert HookErrorCode.OK == 0
        assert HookErrorCode.COMMENT_NOT_IMPLEMENTED == 31
        assert HookErrorCode.PIPE_DISCONNECTED == 2

    def test_enum_name(self):
        assert HookErrorCode(0).name == "OK"
        assert HookErrorCode(31).name == "COMMENT_NOT_IMPLEMENTED"


class TestPipeCommands:
    def test_ping_json(self):
        cmd = PingCommand()
        d = json.loads(cmd.to_json())
        assert d["v"] == PROTOCOL_VERSION
        assert d["cmd"] == "ping"
        assert "task_id" in d

    def test_version_json(self):
        cmd = VersionCommand()
        d = json.loads(cmd.to_json())
        assert d["cmd"] == "version"

    def test_comment_json(self):
        cmd = CommentCommand(sns_id="12345", content="5男", reply_to="")
        d = json.loads(cmd.to_json())
        assert d["cmd"] == "comment"
        assert d["sns_id"] == "12345"
        assert d["content"] == "5男"
        assert d["reply_to"] == ""

    def test_query_sns_id_json(self):
        cmd = QuerySnsIdCommand(author="小蔡", content_hash="fp_abc")
        d = json.loads(cmd.to_json())
        assert d["cmd"] == "query_sns_id"
        assert d["author"] == "小蔡"
        assert d["content_hash"] == "fp_abc"

    def test_task_id_unique(self):
        a = PingCommand()
        b = PingCommand()
        assert a.task_id != b.task_id


class TestPipeResponse:
    def test_from_json_ok(self):
        raw = json.dumps({
            "v": 1, "ok": True, "error_code": 0,
            "error_message": "", "latency_ms": 5,
            "data": {"key": "val"}, "task_id": "abc"
        })
        resp = PipeResponse.from_json(raw)
        assert resp.ok is True
        assert resp.latency_ms == 5
        assert resp.data == {"key": "val"}
        assert resp.task_id == "abc"

    def test_from_json_error(self):
        raw = json.dumps({
            "v": 1, "ok": False, "error_code": 31,
            "error_message": "not implemented", "latency_ms": 0,
            "data": {}, "task_id": "xyz"
        })
        resp = PipeResponse.from_json(raw)
        assert resp.ok is False
        assert resp.error_code == 31

    def test_roundtrip(self):
        resp = PipeResponse(ok=True, latency_ms=10, task_id="rt")
        raw = resp.to_json()
        resp2 = PipeResponse.from_json(raw)
        assert resp2.ok == resp.ok
        assert resp2.latency_ms == resp.latency_ms
        assert resp2.task_id == resp.task_id


class TestCommentResult:
    def test_creation(self):
        r = CommentResult(success=True, method="hook", latency_ms=50)
        assert r.success is True
        assert r.method == "hook"
        assert r.latency_ms == 50
        assert r.error_code == 0
