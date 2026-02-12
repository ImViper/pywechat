"""Mock upstream service for native_http sidecar provider.

Used to validate the two-hop path:
dispatcher -> sidecar(native_http) -> upstream mock.
"""

from __future__ import annotations

import argparse
import json
import random
import threading
import time
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any


def _log(msg: str) -> None:
    now = datetime.now().strftime("%H:%M:%S")
    print(f"[{now}] {msg}", flush=True)


def _safe_int(v, default: int = 0) -> int:
    try:
        return int(v)
    except Exception:
        return default


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Run mock upstream for native_http provider.")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=29080)
    p.add_argument("--mode", choices=["generic", "wxbot"], default="generic")
    p.add_argument("--latency-ms", type=int, default=30)
    p.add_argument("--jitter-ms", type=int, default=5)
    p.add_argument("--fail-ratio", type=float, default=0.0)
    return p.parse_args()


class UpstreamMock:
    def __init__(self, args: argparse.Namespace):
        self.host = args.host
        self.port = args.port
        self.mode = args.mode
        self.latency_ms = max(0, int(args.latency_ms))
        self.jitter_ms = max(0, int(args.jitter_ms))
        self.fail_ratio = min(max(float(args.fail_ratio), 0.0), 1.0)
        self._server: ThreadingHTTPServer | None = None
        self._request_count = 0

    def _is_wxbot_mode(self) -> bool:
        return self.mode == "wxbot"

    def _sleep_latency(self) -> int:
        d = self.latency_ms + (random.randint(0, self.jitter_ms) if self.jitter_ms > 0 else 0)
        if d > 0:
            time.sleep(d / 1000.0)
        return d

    def _ok(self) -> bool:
        return random.random() >= self.fail_ratio

    def run_forever(self) -> None:
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def _write_json(self, status: int, payload: dict) -> None:
                raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def _read_json(self) -> dict:
                try:
                    n = int(self.headers.get("Content-Length", "0"))
                except Exception:
                    n = 0
                body = self.rfile.read(n) if n > 0 else b"{}"
                try:
                    return json.loads(body.decode("utf-8", errors="replace"))
                except Exception:
                    return {}

            def log_message(self, fmt: str, *args) -> None:
                return

            def do_GET(self) -> None:
                if self.path == "/health":
                    self._write_json(
                        200,
                        {
                            "v": 1,
                            "ok": True,
                            "error_code": 0,
                            "error_message": "",
                            "latency_ms": 0,
                            "data": {
                                "service": "native_http_upstream_mock",
                                "mode": outer.mode,
                                "request_count": outer._request_count,
                            },
                        },
                    )
                    return
                self._write_json(
                    404,
                    {
                        "v": 1,
                        "ok": False,
                        "error_code": 10,
                        "error_message": f"unknown path: {self.path}",
                        "latency_ms": 0,
                        "data": {},
                    },
                )

            def do_POST(self) -> None:
                outer._request_count += 1
                req = self._read_json()
                wxbot_paths = {
                    "/api/sendtxtmsg",
                    "/api/sendTxtMsg",
                    "/api/send-txt-msg",
                    "/api/send_txt_msg",
                    "/sendtxtmsg",
                }
                generic_single_path = "/api/comment"
                generic_batch_path = "/api/comment/batch"

                if self.path in wxbot_paths:
                    if not outer._is_wxbot_mode():
                        self._write_json(
                            404,
                            {
                                "v": 1,
                                "ok": False,
                                "error_code": 10,
                                "error_message": "wxbot endpoint disabled in generic mode",
                                "latency_ms": 0,
                                "data": {"mode": outer.mode},
                            },
                        )
                        return
                    lat = outer._sleep_latency()
                    ok = outer._ok()
                    wxid = str(req.get("wxid", "")).strip()
                    content = str(req.get("content", "")).strip()
                    if (not wxid) or (not content):
                        ok = False
                    self._write_json(
                        200,
                        {
                            "code": 200 if ok else 500,
                            "msg": "success" if ok else "failed",
                            "latency_ms": lat,
                            "data": {
                                "mode": outer.mode,
                                "wxid": wxid,
                                "content_len": len(content),
                            },
                        },
                    )
                    return

                if self.path == generic_single_path:
                    if outer._is_wxbot_mode():
                        self._write_json(
                            404,
                            {
                                "v": 1,
                                "ok": False,
                                "error_code": 10,
                                "error_message": "generic endpoint disabled in wxbot mode",
                                "latency_ms": 0,
                                "data": {"mode": outer.mode},
                            },
                        )
                        return
                    lat = outer._sleep_latency()
                    ok = outer._ok()
                    self._write_json(
                        200,
                        {
                            "v": 1,
                            "ok": ok,
                            "error_code": 0 if ok else 30,
                            "error_message": "" if ok else "upstream single failed",
                            "latency_ms": lat,
                            "data": {
                                "method": "native_upstream_single",
                                "mode": outer.mode,
                            },
                            "task_id": req.get("task_id", ""),
                        },
                    )
                    return

                if self.path == generic_batch_path:
                    if outer._is_wxbot_mode():
                        self._write_json(
                            404,
                            {
                                "v": 1,
                                "ok": False,
                                "error_code": 10,
                                "error_message": "generic endpoint disabled in wxbot mode",
                                "latency_ms": 0,
                                "data": {"mode": outer.mode},
                            },
                        )
                        return
                    comments = req.get("comments") or []
                    if not isinstance(comments, list):
                        comments = []
                    started = time.perf_counter()
                    results: list[dict[str, Any]] = []
                    succeeded = 0
                    for _ in comments:
                        lat = outer._sleep_latency()
                        ok = outer._ok()
                        if ok:
                            succeeded += 1
                        results.append(
                            {
                                "success": ok,
                                "method": "native_upstream_batch",
                                "latency_ms": lat,
                                "error_code": 0 if ok else 30,
                                "error_message": "" if ok else "upstream batch item failed",
                            }
                        )
                    total = len(comments)
                    failed = total - succeeded
                    total_latency_ms = int((time.perf_counter() - started) * 1000)
                    self._write_json(
                        200,
                        {
                            "v": 1,
                            "ok": failed == 0,
                            "error_code": 0 if failed == 0 else 30,
                            "error_message": "" if failed == 0 else f"{failed}/{total} failed",
                            "latency_ms": total_latency_ms,
                            "data": {
                                "total": total,
                                "succeeded": succeeded,
                                "failed": failed,
                                "total_latency_ms": total_latency_ms,
                                "mode": outer.mode,
                                "results": results,
                            },
                            "task_id": req.get("task_id", ""),
                        },
                    )
                    return

                self._write_json(
                    404,
                    {
                        "v": 1,
                        "ok": False,
                        "error_code": 10,
                        "error_message": f"unknown path: {self.path}",
                        "latency_ms": 0,
                        "data": {},
                    },
                )

        self._server = ThreadingHTTPServer((self.host, self.port), Handler)
        _log(
            f"native upstream mock listening on http://{self.host}:{self.port} "
            f"(mode={self.mode}, latency={self.latency_ms}ms, jitter={self.jitter_ms}ms, fail_ratio={self.fail_ratio})"
        )
        stop_event = threading.Event()

        def _serve() -> None:
            assert self._server is not None
            self._server.serve_forever()
            stop_event.set()

        t = threading.Thread(target=_serve, daemon=False)
        t.start()
        try:
            while not stop_event.is_set():
                time.sleep(0.3)
        except KeyboardInterrupt:
            _log("upstream mock shutting down...")
        finally:
            if self._server is not None:
                self._server.shutdown()
                self._server.server_close()
            t.join(timeout=3.0)


def main() -> int:
    args = _parse_args()
    s = UpstreamMock(args)
    s.run_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
