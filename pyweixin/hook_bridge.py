"""
Viper Hook Bridge -- Named Pipe client for communicating with the injected DLL.
不修改 upstream 代码，只导入 hook_types。

Wire format:  [4-byte LE uint32 length][UTF-8 JSON payload]
Pipe name default:  \\\\.\\pipe\\pywechat_hook
"""

from __future__ import annotations

import json
import os
import struct
import time
from typing import Any

try:
    from .hook_types import (
        DEFAULT_PIPE_NAME,
        CommentCommand,
        CommentResult,
        HookErrorCode,
        PingCommand,
        PipeCommand,
        PipeResponse,
        QuerySnsIdCommand,
        VersionCommand,
    )
except ImportError:  # pragma: no cover - direct module import
    from hook_types import (
        DEFAULT_PIPE_NAME,
        CommentCommand,
        CommentResult,
        HookErrorCode,
        PingCommand,
        PipeCommand,
        PipeResponse,
        QuerySnsIdCommand,
        VersionCommand,
    )


# ---------------------------------------------------------------------------
# win32file lazy import (only available on Windows with pywin32)
# ---------------------------------------------------------------------------

def _import_win32():
    """Lazy import of win32file / win32pipe; returns (win32file, win32pipe) or raises."""
    import win32file  # type: ignore[import-untyped]
    import win32pipe  # type: ignore[import-untyped]
    return win32file, win32pipe


# ---------------------------------------------------------------------------
# HookBridge
# ---------------------------------------------------------------------------

class HookBridge:
    """Named Pipe client that talks to the pywechat_hook DLL inside WeChat."""

    def __init__(
        self,
        pipe_name: str | None = None,
        timeout_ms: int = 3000,
    ):
        self._pipe_name = pipe_name or os.environ.get(
            "PYWEIXIN_HOOK_PIPE_NAME", DEFAULT_PIPE_NAME
        )
        self._timeout_ms = timeout_ms
        self._handle: Any = None  # win32file handle

    # -- connection ---------------------------------------------------------

    @property
    def connected(self) -> bool:
        return self._handle is not None

    def connect(self) -> bool:
        """Connect to the DLL pipe server. Returns True on success."""
        if self._handle is not None:
            return True
        try:
            win32file, win32pipe = _import_win32()
        except ImportError:
            return False
        try:
            # Wait for pipe to become available
            win32pipe.WaitNamedPipe(self._pipe_name, self._timeout_ms)
            handle = win32file.CreateFile(
                self._pipe_name,
                win32file.GENERIC_READ | win32file.GENERIC_WRITE,
                0,
                None,
                win32file.OPEN_EXISTING,
                0,
                None,
            )
            # Set pipe to message mode
            win32pipe.SetNamedPipeHandleState(
                handle, win32pipe.PIPE_READMODE_BYTE, None, None
            )
            self._handle = handle
            return True
        except Exception:
            self._handle = None
            return False

    def disconnect(self) -> None:
        """Close the pipe handle."""
        if self._handle is not None:
            try:
                win32file, _ = _import_win32()
                win32file.CloseHandle(self._handle)
            except Exception:
                pass
            self._handle = None

    # -- low-level send/recv -----------------------------------------------

    def _send_raw(self, data: bytes) -> None:
        win32file, _ = _import_win32()
        header = struct.pack("<I", len(data))
        win32file.WriteFile(self._handle, header + data)

    def _recv_raw(self) -> bytes:
        win32file, _ = _import_win32()
        # Read 4-byte length header
        _, header = win32file.ReadFile(self._handle, 4)
        length = struct.unpack("<I", header)[0]
        # Read payload
        _, payload = win32file.ReadFile(self._handle, length)
        return payload

    def _send_command(self, cmd: PipeCommand) -> PipeResponse:
        """Send a command and wait for the response."""
        if not self.connected and not self.connect():
            return PipeResponse(
                ok=False,
                error_code=HookErrorCode.PIPE_DISCONNECTED,
                error_message="cannot connect to pipe",
                task_id=cmd.task_id,
            )
        try:
            payload = cmd.to_json().encode("utf-8")
            self._send_raw(payload)
            raw = self._recv_raw()
            return PipeResponse.from_json(raw.decode("utf-8"))
        except Exception as exc:
            self.disconnect()
            return PipeResponse(
                ok=False,
                error_code=HookErrorCode.PIPE_DISCONNECTED,
                error_message=str(exc),
                task_id=cmd.task_id,
            )

    # -- high-level API ----------------------------------------------------

    def ping(self) -> bool:
        """Ping the DLL. Returns True if it responds OK."""
        resp = self._send_command(PingCommand())
        return resp.ok

    def send_comment(
        self,
        content: str,
        *,
        sns_id: str = "",
        reply_to: str = "",
    ) -> PipeResponse:
        """Send a comment via Hook."""
        return self._send_command(
            CommentCommand(sns_id=sns_id, content=content, reply_to=reply_to)
        )

    def query_sns_id(self, author: str, content_hash: str) -> PipeResponse:
        """Query the DLL's SNS ID cache for a post."""
        return self._send_command(
            QuerySnsIdCommand(author=author, content_hash=content_hash)
        )

    def version(self) -> PipeResponse:
        """Query WeChat version detected by the DLL."""
        return self._send_command(VersionCommand())

    # -- context manager ---------------------------------------------------

    def __enter__(self) -> "HookBridge":
        self.connect()
        return self

    def __exit__(self, *exc: Any) -> None:
        self.disconnect()
