"""Tests for hook_bridge -- mock pipe server for protocol verification.

These tests create a real Named Pipe server in-process to test the
HookBridge client against, verifying the length-prefix wire protocol.
"""

import json
import os
import struct
import sys
import threading
import time

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pyweixin.hook_types import PipeResponse

# Skip all tests if not on Windows or win32file unavailable
pytestmark = pytest.mark.skipif(
    sys.platform != "win32",
    reason="Named Pipe tests only run on Windows"
)

try:
    import win32file
    import win32pipe
    HAS_WIN32 = True
except ImportError:
    HAS_WIN32 = False


PIPE_NAME = r"\\.\pipe\pywechat_hook_test_" + str(os.getpid())


def _mock_pipe_server(pipe_name: str, handler, ready_event: threading.Event,
                      stop_event: threading.Event):
    """Simple mock pipe server that handles one connection."""
    pipe = win32pipe.CreateNamedPipe(
        pipe_name,
        win32pipe.PIPE_ACCESS_DUPLEX,
        win32pipe.PIPE_TYPE_BYTE | win32pipe.PIPE_READMODE_BYTE | win32pipe.PIPE_WAIT,
        1,
        65536,
        65536,
        1000,
        None,
    )
    ready_event.set()
    win32pipe.ConnectNamedPipe(pipe, None)

    try:
        while not stop_event.is_set():
            # Read length header
            try:
                _, header = win32file.ReadFile(pipe, 4)
            except Exception:
                break
            length = struct.unpack("<I", header)[0]
            _, payload = win32file.ReadFile(pipe, length)

            request = json.loads(payload.decode("utf-8"))
            response = handler(request)
            resp_bytes = json.dumps(response).encode("utf-8")

            resp_header = struct.pack("<I", len(resp_bytes))
            win32file.WriteFile(pipe, resp_header + resp_bytes)
            win32file.FlushFileBuffers(pipe)
    finally:
        win32pipe.DisconnectNamedPipe(pipe)
        win32file.CloseHandle(pipe)


@pytest.fixture
def mock_server():
    """Start a mock pipe server and yield its pipe name."""
    if not HAS_WIN32:
        pytest.skip("win32file not available")

    ready = threading.Event()
    stop = threading.Event()

    def handler(req):
        cmd = req.get("cmd", "")
        task_id = req.get("task_id", "")
        if cmd == "ping":
            return {"v": 1, "ok": True, "error_code": 0,
                    "error_message": "", "latency_ms": 1,
                    "data": {}, "task_id": task_id}
        elif cmd == "comment":
            return {"v": 1, "ok": False, "error_code": 31,
                    "error_message": "not implemented", "latency_ms": 0,
                    "data": {}, "task_id": task_id}
        elif cmd == "version":
            return {"v": 1, "ok": True, "error_code": 0,
                    "error_message": "", "latency_ms": 0,
                    "data": {"wechat_version": "4.0.1.23"}, "task_id": task_id}
        else:
            return {"v": 1, "ok": False, "error_code": 10,
                    "error_message": f"unknown: {cmd}", "latency_ms": 0,
                    "data": {}, "task_id": task_id}

    t = threading.Thread(target=_mock_pipe_server,
                         args=(PIPE_NAME, handler, ready, stop),
                         daemon=True)
    t.start()
    ready.wait(timeout=5)
    yield PIPE_NAME
    stop.set()


@pytest.mark.skipif(not HAS_WIN32, reason="win32file not available")
class TestHookBridge:
    def test_ping(self, mock_server):
        from pyweixin.hook_bridge import HookBridge
        bridge = HookBridge(pipe_name=mock_server)
        assert bridge.connect() is True
        assert bridge.ping() is True
        bridge.disconnect()

    def test_comment_not_implemented(self, mock_server):
        from pyweixin.hook_bridge import HookBridge
        bridge = HookBridge(pipe_name=mock_server)
        bridge.connect()
        resp = bridge.send_comment("5男", sns_id="12345")
        assert resp.ok is False
        assert resp.error_code == 31
        bridge.disconnect()

    def test_version(self, mock_server):
        from pyweixin.hook_bridge import HookBridge
        bridge = HookBridge(pipe_name=mock_server)
        bridge.connect()
        resp = bridge.version()
        assert resp.ok is True
        assert resp.data["wechat_version"] == "4.0.1.23"
        bridge.disconnect()

    def test_context_manager(self, mock_server):
        from pyweixin.hook_bridge import HookBridge
        with HookBridge(pipe_name=mock_server) as bridge:
            assert bridge.ping() is True
        assert bridge.connected is False

    def test_disconnected_returns_error(self):
        from pyweixin.hook_bridge import HookBridge
        bridge = HookBridge(pipe_name=r"\\.\pipe\nonexistent_test_pipe")
        assert bridge.ping() is False
