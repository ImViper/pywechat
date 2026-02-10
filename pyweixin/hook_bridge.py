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
        BatchCommentCommand,
        BatchCommentResult,
        CommentCommand,
        CommentResult,
        GetLatestSnsIdCommand,
        HookCommentCommand,
        HookErrorCode,
        ParallelCommentCommand,
        PiggybackCommentCommand,
        PingCommand,
        PipeCommand,
        PipeResponse,
        QuerySnsIdCommand,
        ReadMemoryCommand,
        StatusCommand,
        TlsDiagCommand,
        VersionCommand,
    )
except ImportError:  # pragma: no cover - direct module import
    from hook_types import (
        DEFAULT_PIPE_NAME,
        BatchCommentCommand,
        BatchCommentResult,
        CommentCommand,
        CommentResult,
        GetLatestSnsIdCommand,
        HookCommentCommand,
        HookErrorCode,
        ParallelCommentCommand,
        PiggybackCommentCommand,
        PingCommand,
        PipeCommand,
        PipeResponse,
        QuerySnsIdCommand,
        ReadMemoryCommand,
        StatusCommand,
        TlsDiagCommand,
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
        allow_queue_fallback: bool = False,
        prefer_arg1_template: bool = True,
        execution_mode: str = "pipe_thread",
        wait_timeout_ms: int = 1500,
    ) -> PipeResponse:
        """Send a comment via Hook."""
        return self._send_command(
            CommentCommand(
                sns_id=sns_id,
                content=content,
                reply_to=reply_to,
                allow_queue_fallback=allow_queue_fallback,
                prefer_arg1_template=prefer_arg1_template,
                execution_mode=execution_mode,
                wait_timeout_ms=wait_timeout_ms,
            )
        )

    def query_sns_id(self, author: str, content_hash: str) -> PipeResponse:
        """Query the DLL's SNS ID cache for a post."""
        return self._send_command(
            QuerySnsIdCommand(author=author, content_hash=content_hash)
        )

    def version(self) -> PipeResponse:
        """Query WeChat version detected by the DLL."""
        return self._send_command(VersionCommand())

    def hook_comment(
        self,
        content: str,
        *,
        sns_id: str = "",
        reply_to: str = "",
    ) -> PipeResponse:
        """Queue a comment for injection via the hook (next legitimate call)."""
        return self._send_command(
            HookCommentCommand(sns_id=sns_id, content=content, reply_to=reply_to)
        )

    def status(self) -> PipeResponse:
        """Query DLL status (hook installed, state captured, etc.)."""
        return self._send_command(StatusCommand())

    def get_latest_sns_id(self) -> PipeResponse:
        """Get the latest SNS ID captured by the hook.

        Returns PipeResponse with data={"sns_id": "..."} on success.
        """
        return self._send_command(GetLatestSnsIdCommand())

    def send_batch_comments(
        self,
        comments: list[str],
        *,
        sns_id: str = "",
        reply_to: str = "",
        concurrency: int = 10,
    ) -> BatchCommentResult:
        """Send multiple comments concurrently via DLL thread pool.

        Returns BatchCommentResult with per-comment results.
        """
        resp = self._send_command(
            BatchCommentCommand(
                sns_id=sns_id,
                comments=comments,
                reply_to=reply_to,
                concurrency=concurrency,
            )
        )
        if not resp.ok and not resp.data:
            return BatchCommentResult(
                total=len(comments),
                failed=len(comments),
                results=[
                    CommentResult(
                        success=False,
                        method="hook",
                        error_code=resp.error_code,
                        error_message=resp.error_message,
                    )
                    for _ in comments
                ],
            )

        data = resp.data
        results = []
        for r in data.get("results", []):
            results.append(
                CommentResult(
                    success=r.get("success", False),
                    method="hook",
                    latency_ms=r.get("latency_ms", 0),
                    error_code=r.get("error_code", 0),
                    error_message=r.get("error_message", ""),
                )
            )
        return BatchCommentResult(
            total=data.get("total", len(comments)),
            succeeded=data.get("succeeded", 0),
            failed=data.get("failed", len(comments)),
            total_latency_ms=data.get("total_latency_ms", 0),
            results=results,
        )

    def read_memory(self, rva: int, size: int = 64) -> PipeResponse:
        """Read N bytes from Weixin.dll base + rva (for crash-site disassembly)."""
        return self._send_command(ReadMemoryCommand(rva=rva, size=size))

    def tls_diag(self) -> PipeResponse:
        """Collect implicit TLS and FLS diagnostics from the DLL."""
        return self._send_command(TlsDiagCommand())

    def send_parallel_comments(
        self,
        comments: list[str],
        *,
        sns_id: str = "",
        reply_to: str = "",
        max_concurrency: int = 10,
        tls_mode: str = "implicit",
    ) -> BatchCommentResult:
        """Send multiple comments in parallel with TLS context copy.

        Unlike send_batch_comments (which uses standard TLS copy only),
        this uses the new parallel_comment pipe command that copies
        implicit TLS and/or FLS from the capture thread.
        """
        resp = self._send_command(
            ParallelCommentCommand(
                sns_id=sns_id,
                comments=comments,
                reply_to=reply_to,
                max_concurrency=max_concurrency,
                tls_mode=tls_mode,
            )
        )
        if not resp.ok and not resp.data:
            return BatchCommentResult(
                total=len(comments),
                failed=len(comments),
                results=[
                    CommentResult(
                        success=False,
                        method="hook_parallel",
                        error_code=resp.error_code,
                        error_message=resp.error_message,
                    )
                    for _ in comments
                ],
            )

        data = resp.data
        results = []
        for r in data.get("results", []):
            results.append(
                CommentResult(
                    success=r.get("success", False),
                    method="hook_parallel",
                    latency_ms=r.get("latency_ms", 0),
                    error_code=r.get("error_code", 0),
                    error_message=r.get("error_message", ""),
                )
            )
        return BatchCommentResult(
            total=data.get("total", len(comments)),
            succeeded=data.get("succeeded", 0),
            failed=data.get("failed", len(comments)),
            total_latency_ms=data.get("total_latency_ms", 0),
            results=results,
        )

    def send_piggyback_comments(
        self,
        comments: list[str],
        *,
        sns_id: str = "",
        reply_to: str = "",
        max_concurrency: int = 10,
        timeout_ms: int = 30000,
    ) -> BatchCommentResult:
        """Queue comments for piggyback execution inside next hook callback.

        This is the safest parallel path: comments are executed inside the
        hook callback where arg1 is guaranteed valid. The call blocks until
        the hook fires (triggered by a UI comment) and drains the batch.
        """
        resp = self._send_command(
            PiggybackCommentCommand(
                sns_id=sns_id,
                comments=comments,
                reply_to=reply_to,
                max_concurrency=max_concurrency,
                timeout_ms=timeout_ms,
            )
        )
        if not resp.ok and not resp.data:
            return BatchCommentResult(
                total=len(comments),
                failed=len(comments),
                results=[
                    CommentResult(
                        success=False,
                        method="piggyback",
                        error_code=resp.error_code,
                        error_message=resp.error_message,
                    )
                    for _ in comments
                ],
            )

        data = resp.data
        results = []
        for r in data.get("results", []):
            results.append(
                CommentResult(
                    success=r.get("success", False),
                    method="piggyback",
                    latency_ms=r.get("latency_ms", 0),
                    error_code=r.get("error_code", 0),
                    error_message=r.get("error_message", ""),
                )
            )
        return BatchCommentResult(
            total=data.get("total", len(comments)),
            succeeded=data.get("succeeded", 0),
            failed=data.get("failed", len(comments)),
            total_latency_ms=data.get("total_latency_ms", 0),
            results=results,
        )

    def __enter__(self) -> "HookBridge":
        self.connect()
        return self

    def __exit__(self, *exc: Any) -> None:
        self.disconnect()
