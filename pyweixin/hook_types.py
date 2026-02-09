"""
Viper Hook Comment Types -- wire protocol, error codes, sender protocol.
不修改 upstream 代码，纯类型定义。
"""

from __future__ import annotations

import enum
import json
import uuid
from dataclasses import dataclass, field
from typing import Any, Protocol


# ---------------------------------------------------------------------------
# Error codes (shared between Python and C++ DLL)
# ---------------------------------------------------------------------------

class HookErrorCode(enum.IntEnum):
    OK = 0
    UNKNOWN = 1
    PIPE_DISCONNECTED = 2
    PIPE_TIMEOUT = 3
    INVALID_COMMAND = 10
    SNS_ID_NOT_FOUND = 20
    COMMENT_FAILED = 30
    COMMENT_NOT_IMPLEMENTED = 31
    WECHAT_VERSION_MISMATCH = 40
    HOOK_NOT_INSTALLED = 50


# ---------------------------------------------------------------------------
# Wire protocol commands  (Python -> DLL)
# ---------------------------------------------------------------------------

PROTOCOL_VERSION = 1


def _new_task_id() -> str:
    return uuid.uuid4().hex[:12]


@dataclass(slots=True)
class PipeCommand:
    """Base command sent from Python to the DLL over Named Pipe."""
    cmd: str
    task_id: str = field(default_factory=_new_task_id)
    v: int = PROTOCOL_VERSION

    def to_json(self) -> str:
        return json.dumps(self._as_dict(), ensure_ascii=False)

    def _as_dict(self) -> dict[str, Any]:
        return {"v": self.v, "cmd": self.cmd, "task_id": self.task_id}


@dataclass(slots=True)
class PingCommand(PipeCommand):
    cmd: str = field(default="ping", init=False)


@dataclass(slots=True)
class VersionCommand(PipeCommand):
    cmd: str = field(default="version", init=False)


@dataclass(slots=True)
class CommentCommand(PipeCommand):
    sns_id: str = ""
    content: str = ""
    reply_to: str = ""
    cmd: str = field(default="comment", init=False)

    def _as_dict(self) -> dict[str, Any]:
        d = PipeCommand._as_dict(self)
        d.update(sns_id=self.sns_id, content=self.content, reply_to=self.reply_to)
        return d


@dataclass(slots=True)
class QuerySnsIdCommand(PipeCommand):
    author: str = ""
    content_hash: str = ""
    cmd: str = field(default="query_sns_id", init=False)

    def _as_dict(self) -> dict[str, Any]:
        d = PipeCommand._as_dict(self)
        d.update(author=self.author, content_hash=self.content_hash)
        return d


# ---------------------------------------------------------------------------
# Wire protocol response  (DLL -> Python)
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class PipeResponse:
    """Response received from the DLL."""
    v: int = PROTOCOL_VERSION
    ok: bool = False
    error_code: int = 0
    error_message: str = ""
    latency_ms: int = 0
    data: dict[str, Any] = field(default_factory=dict)
    task_id: str = ""

    @classmethod
    def from_json(cls, raw: str) -> "PipeResponse":
        d = json.loads(raw)
        return cls(
            v=int(d.get("v", PROTOCOL_VERSION)),
            ok=bool(d.get("ok", False)),
            error_code=int(d.get("error_code", 0)),
            error_message=str(d.get("error_message", "")),
            latency_ms=int(d.get("latency_ms", 0)),
            data=d.get("data") or {},
            task_id=str(d.get("task_id", "")),
        )

    def to_json(self) -> str:
        return json.dumps({
            "v": self.v,
            "ok": self.ok,
            "error_code": self.error_code,
            "error_message": self.error_message,
            "latency_ms": self.latency_ms,
            "data": self.data,
            "task_id": self.task_id,
        }, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Comment result (returned by dispatchers)
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class CommentResult:
    """Unified result for a comment attempt (Hook or UI)."""
    success: bool
    method: str  # "hook" | "ui" | "none"
    latency_ms: int = 0
    error_code: int = 0
    error_message: str = ""


# ---------------------------------------------------------------------------
# CommentSender protocol  (analogous to AIAnswerProvider in rush_ai.py)
# ---------------------------------------------------------------------------

class CommentSender(Protocol):
    """Implement this protocol to plug a comment backend (Hook / UI)."""

    def send_comment(
        self,
        content: str,
        *,
        sns_id: str = "",
        author: str = "",
        content_hash: str = "",
        reply_to: str = "",
    ) -> CommentResult:
        ...


# ---------------------------------------------------------------------------
# Default pipe name
# ---------------------------------------------------------------------------

DEFAULT_PIPE_NAME = r"\\.\pipe\pywechat_hook"
