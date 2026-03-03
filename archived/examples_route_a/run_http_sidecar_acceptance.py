"""HTTP sidecar acceptance runner (no WeChat UI dependency).

Use this script to quickly validate HTTP backend throughput/stability before
integrating a real sidecar implementation.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import statistics
import threading
import time
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

PROJECT_ROOT = Path(__file__).resolve().parent.parent
MAX_BENCHMARK_ROUNDS = 5

import sys

sys.path.insert(0, str(PROJECT_ROOT))
from pyweixin.comment_dispatcher import CommentDispatcher


def _log(msg: str) -> None:
    now = datetime.now().strftime("%H:%M:%S")
    print(f"[{now}] {msg}", flush=True)


def _percentile(values: list[int], p: float) -> int:
    if not values:
        return 0
    if len(values) == 1:
        return int(values[0])
    ordered = sorted(values)
    idx = (len(ordered) - 1) * p
    lo = int(idx)
    hi = min(lo + 1, len(ordered) - 1)
    if lo == hi:
        return int(ordered[lo])
    frac = idx - lo
    return int(round(ordered[lo] * (1.0 - frac) + ordered[hi] * frac))


def _build_comments(prefix: str, round_idx: int, count: int) -> list[str]:
    return [f"{prefix}-r{round_idx + 1:02d}-c{i + 1:02d}" for i in range(count)]


class _MockSidecar:
    def __init__(
        self,
        *,
        host: str,
        port: int,
        latency_ms: int,
        jitter_ms: int,
        fail_ratio: float,
    ):
        self.host = host
        self.port = port
        self.latency_ms = max(0, latency_ms)
        self.jitter_ms = max(0, jitter_ms)
        self.fail_ratio = min(max(fail_ratio, 0.0), 1.0)
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    def _sleep_latency(self) -> None:
        delay_ms = self.latency_ms
        if self.jitter_ms > 0:
            delay_ms += random.randint(0, self.jitter_ms)
        if delay_ms > 0:
            time.sleep(delay_ms / 1000.0)

    def _ok(self) -> bool:
        return random.random() >= self.fail_ratio

    def start(self) -> None:
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def _write_json(self, code: int, payload: dict) -> None:
                raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
                self.send_response(code)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def log_message(self, format: str, *args) -> None:
                return

            def do_POST(self) -> None:
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                except Exception:
                    length = 0
                body = self.rfile.read(length) if length > 0 else b"{}"
                try:
                    req = json.loads(body.decode("utf-8", errors="replace"))
                except Exception:
                    req = {}

                if self.path == "/api/comment":
                    outer._sleep_latency()
                    ok = outer._ok()
                    self._write_json(
                        200,
                        {
                            "v": 1,
                            "ok": ok,
                            "error_code": 0 if ok else 30,
                            "error_message": "" if ok else "mock http single failed",
                            "latency_ms": outer.latency_ms,
                            "data": {},
                            "task_id": req.get("task_id", ""),
                        },
                    )
                    return

                if self.path == "/api/comment/batch":
                    comments = req.get("comments") or []
                    if not isinstance(comments, list):
                        comments = []
                    outer._sleep_latency()
                    results: list[dict[str, Any]] = []
                    succeeded = 0
                    for _ in comments:
                        ok = outer._ok()
                        if ok:
                            succeeded += 1
                        results.append(
                            {
                                "success": ok,
                                "method": "http_mock",
                                "latency_ms": outer.latency_ms,
                                "error_code": 0 if ok else 30,
                                "error_message": "" if ok else "mock http batch failed",
                            }
                        )
                    total = len(comments)
                    failed = total - succeeded
                    self._write_json(
                        200,
                        {
                            "v": 1,
                            "ok": failed == 0,
                            "error_code": 0 if failed == 0 else 30,
                            "error_message": "" if failed == 0 else f"{failed}/{total} failed",
                            "latency_ms": outer.latency_ms,
                            "data": {
                                "total": total,
                                "succeeded": succeeded,
                                "failed": failed,
                                "total_latency_ms": outer.latency_ms,
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
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        _log(f"mock sidecar started at http://{self.host}:{self.port}")

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Run HTTP sidecar acceptance.")
    p.add_argument("--rounds", type=int, default=1, help=f"Benchmark rounds (1-{MAX_BENCHMARK_ROUNDS})")
    p.add_argument("--count", type=int, default=10, help="Comments per round.")
    p.add_argument("--concurrency", type=int, default=10, help="Batch concurrency.")
    p.add_argument("--target-ms", type=int, default=1000, help="Target latency threshold per round.")
    p.add_argument("--comment-prefix", default="http-acc")
    p.add_argument("--round-interval-ms", type=int, default=100)
    p.add_argument("--fail-fast", action=argparse.BooleanOptionalAction, default=True)
    p.add_argument("--report-file", default="")
    p.add_argument("--http-base-url", default="http://127.0.0.1:19080")
    p.add_argument("--http-timeout-ms", type=int, default=1200)
    p.add_argument("--http-comment-path", default="/api/comment")
    p.add_argument("--http-batch-path", default="/api/comment/batch")
    p.add_argument(
        "--http-provider",
        default="",
        help="Optional provider hint forwarded to sidecar (e.g. native_http, real_hook, mock).",
    )
    p.add_argument("--backend", choices=["http", "mock_http"], default="mock_http")
    p.add_argument("--mock-latency-ms", type=int, default=35)
    p.add_argument("--mock-jitter-ms", type=int, default=5)
    p.add_argument("--mock-fail-ratio", type=float, default=0.0)
    return p.parse_args()


def _ensure_env(args: argparse.Namespace) -> None:
    os.environ["PYWEIXIN_COMMENT_BACKEND"] = "http_only"
    os.environ["PYWEIXIN_HTTP_BASE_URL"] = args.http_base_url
    os.environ["PYWEIXIN_HTTP_TIMEOUT_MS"] = str(args.http_timeout_ms)
    os.environ["PYWEIXIN_HTTP_COMMENT_PATH"] = args.http_comment_path
    os.environ["PYWEIXIN_HTTP_BATCH_PATH"] = args.http_batch_path
    if str(args.http_provider).strip():
        os.environ["PYWEIXIN_HTTP_PROVIDER"] = str(args.http_provider).strip().lower()
    else:
        os.environ.pop("PYWEIXIN_HTTP_PROVIDER", None)
    os.environ["PYWEIXIN_HTTP_BOOTSTRAP_UI"] = "0"
    os.environ["PYWEIXIN_HOOK_ENABLED"] = "0"
    os.environ["PYWEIXIN_HOOK_DISABLE_UI_FALLBACK_FOR_BENCH"] = "1"


def main() -> int:
    args = _parse_args()
    if args.rounds < 1 or args.rounds > MAX_BENCHMARK_ROUNDS:
        raise ValueError(f"--rounds must be between 1 and {MAX_BENCHMARK_ROUNDS}")
    if args.count < 1:
        raise ValueError("--count must be >= 1")
    if args.concurrency < 1:
        raise ValueError("--concurrency must be >= 1")

    _ensure_env(args)

    mock_server: _MockSidecar | None = None
    if args.backend == "mock_http":
        parsed = urlparse(args.http_base_url)
        host = parsed.hostname or "127.0.0.1"
        port = parsed.port or 19080
        mock_server = _MockSidecar(
            host=host,
            port=port,
            latency_ms=args.mock_latency_ms,
            jitter_ms=args.mock_jitter_ms,
            fail_ratio=args.mock_fail_ratio,
        )
        mock_server.start()

    started_at = datetime.now().isoformat()
    report_dir = PROJECT_ROOT / "local_workspace" / "acceptance_reports"
    report_dir.mkdir(parents=True, exist_ok=True)
    report_path = (
        Path(args.report_file).expanduser().resolve()
        if args.report_file
        else report_dir / f"http_sidecar_e2e_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    )

    rounds: list[dict[str, Any]] = []
    dispatcher = CommentDispatcher.from_env()
    try:
        for round_idx in range(args.rounds):
            comments = _build_comments(args.comment_prefix, round_idx, args.count)
            _log(f"Round {round_idx + 1}/{args.rounds} start, comments={len(comments)}")
            t0 = time.perf_counter()
            batch_result = dispatcher.post_batch_comments(
                comments,
                sns_id="http-sidecar-sns",
                author="http-sidecar-author",
                content_hash="",
                concurrency=args.concurrency,
            )
            elapsed_ms = int((time.perf_counter() - t0) * 1000)
            batch_latency_ms = int(batch_result.total_latency_ms or elapsed_ms)
            strict_ok = batch_result.succeeded == args.count
            under_target = batch_latency_ms < args.target_ms
            methods: dict[str, int] = {}
            for item in batch_result.results:
                methods[item.method] = methods.get(item.method, 0) + 1
            failed_items = [
                {
                    "index": i + 1,
                    "error_code": r.error_code,
                    "error_message": r.error_message,
                    "latency_ms": r.latency_ms,
                    "method": r.method,
                }
                for i, r in enumerate(batch_result.results)
                if not r.success
            ]
            rounds.append(
                {
                    "round": round_idx + 1,
                    "elapsed_ms": elapsed_ms,
                    "batch_latency_ms": batch_latency_ms,
                    "total": batch_result.total,
                    "succeeded": batch_result.succeeded,
                    "failed": batch_result.failed,
                    "strict_success": strict_ok,
                    "under_target": under_target,
                    "mode": batch_result.mode,
                    "raw_batch_total": batch_result.raw_batch_total,
                    "raw_batch_succeeded": batch_result.raw_batch_succeeded,
                    "raw_batch_failed": batch_result.raw_batch_failed,
                    "fallback_count": batch_result.fallback_count,
                    "method_counts": methods,
                    "failed_items": failed_items,
                }
            )
            _log(
                f"Round {round_idx + 1} result: {batch_result.succeeded}/{batch_result.total}, "
                f"batch_latency={batch_latency_ms}ms, strict_ok={strict_ok}, "
                f"raw={batch_result.raw_batch_succeeded}/{batch_result.raw_batch_total}, "
                f"fallback={batch_result.fallback_count}, under_target={under_target}"
            )
            if args.fail_fast and not strict_ok:
                _log("Fail-fast enabled: stopping after first failed round")
                break
            if args.round_interval_ms > 0 and round_idx < (args.rounds - 1):
                time.sleep(args.round_interval_ms / 1000.0)

        latencies = [r["batch_latency_ms"] for r in rounds]
        executed_rounds = len(rounds)
        strict_success_rounds = sum(1 for r in rounds if r["strict_success"])
        under_target_rounds = sum(1 for r in rounds if r["under_target"])
        summary = {
            "rounds": executed_rounds,
            "configured_rounds": args.rounds,
            "comments_per_round": args.count,
            "target_ms": args.target_ms,
            "strict_success_rounds": strict_success_rounds,
            "under_target_rounds": under_target_rounds,
            "strict_success_rate": (strict_success_rounds / executed_rounds) if executed_rounds else 0.0,
            "under_target_rate": (under_target_rounds / executed_rounds) if executed_rounds else 0.0,
            "latency_avg_ms": int(round(statistics.mean(latencies))) if latencies else 0,
            "latency_p50_ms": _percentile(latencies, 0.50),
            "latency_p95_ms": _percentile(latencies, 0.95),
            "latency_max_ms": max(latencies) if latencies else 0,
            "goal_passed": (
                executed_rounds > 0
                and strict_success_rounds == executed_rounds
                and _percentile(latencies, 0.95) < args.target_ms
            ),
        }
        report = {
            "started_at": started_at,
            "finished_at": datetime.now().isoformat(),
            "args": vars(args),
            "rounds": rounds,
            "summary": summary,
        }
        with report_path.open("w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
        _log(f"Report saved: {report_path}")
        _log(
            "Summary: "
            f"strict={summary['strict_success_rounds']}/{summary['rounds']}, "
            f"P95={summary['latency_p95_ms']}ms, goal_passed={summary['goal_passed']}"
        )
        return 0
    finally:
        if mock_server is not None:
            mock_server.stop()


if __name__ == "__main__":
    raise SystemExit(main())
