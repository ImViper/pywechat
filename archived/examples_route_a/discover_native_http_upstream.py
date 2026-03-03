"""Discover candidate upstream HTTP APIs for native_http sidecar.

This script probes common localhost ports/paths and prints a recommended
`run_http_comment_sidecar.py` command when it finds a compatible upstream.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _log(msg: str) -> None:
    now = datetime.now().strftime("%H:%M:%S")
    print(f"[{now}] {msg}", flush=True)


def _normalize_base(url: str) -> str:
    u = str(url or "").strip()
    if not u:
        return ""
    if not u.startswith("http://") and not u.startswith("https://"):
        u = "http://" + u
    return u.rstrip("/")


def _url_join(base: str, path: str) -> str:
    p = str(path or "").strip()
    if not p.startswith("/"):
        p = "/" + p
    return _normalize_base(base) + p


def _safe_json_load(raw: bytes) -> tuple[bool, Any]:
    try:
        if not raw:
            return True, {}
        return True, json.loads(raw.decode("utf-8", errors="replace"))
    except Exception:
        return False, None


def _http_get_json(url: str, timeout_ms: int) -> dict[str, Any]:
    req = Request(url=url, method="GET", headers={"Accept": "application/json"})
    timeout_s = max(int(timeout_ms), 50) / 1000.0
    t0 = time.perf_counter()
    try:
        with urlopen(req, timeout=timeout_s) as resp:
            raw = resp.read()
            ok_json, data = _safe_json_load(raw)
            return {
                "ok": True,
                "status": int(getattr(resp, "status", 200)),
                "latency_ms": int((time.perf_counter() - t0) * 1000),
                "json_ok": ok_json,
                "json": data if ok_json else {},
                "error": "",
            }
    except HTTPError as exc:
        return {
            "ok": False,
            "status": int(exc.code),
            "latency_ms": int((time.perf_counter() - t0) * 1000),
            "json_ok": False,
            "json": {},
            "error": f"http {exc.code}: {exc.reason}",
        }
    except URLError as exc:
        return {
            "ok": False,
            "status": 0,
            "latency_ms": int((time.perf_counter() - t0) * 1000),
            "json_ok": False,
            "json": {},
            "error": f"url error: {exc}",
        }
    except Exception as exc:
        return {
            "ok": False,
            "status": 0,
            "latency_ms": int((time.perf_counter() - t0) * 1000),
            "json_ok": False,
            "json": {},
            "error": str(exc),
        }


def _http_post_json(url: str, payload: dict[str, Any], timeout_ms: int) -> dict[str, Any]:
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = Request(
        url=url,
        method="POST",
        data=body,
        headers={
            "Content-Type": "application/json; charset=utf-8",
            "Accept": "application/json",
        },
    )
    timeout_s = max(int(timeout_ms), 50) / 1000.0
    t0 = time.perf_counter()
    try:
        with urlopen(req, timeout=timeout_s) as resp:
            raw = resp.read()
            ok_json, data = _safe_json_load(raw)
            return {
                "ok": True,
                "status": int(getattr(resp, "status", 200)),
                "latency_ms": int((time.perf_counter() - t0) * 1000),
                "json_ok": ok_json,
                "json": data if ok_json else {},
                "error": "",
            }
    except HTTPError as exc:
        return {
            "ok": False,
            "status": int(exc.code),
            "latency_ms": int((time.perf_counter() - t0) * 1000),
            "json_ok": False,
            "json": {},
            "error": f"http {exc.code}: {exc.reason}",
        }
    except URLError as exc:
        return {
            "ok": False,
            "status": 0,
            "latency_ms": int((time.perf_counter() - t0) * 1000),
            "json_ok": False,
            "json": {},
            "error": f"url error: {exc}",
        }
    except Exception as exc:
        return {
            "ok": False,
            "status": 0,
            "latency_ms": int((time.perf_counter() - t0) * 1000),
            "json_ok": False,
            "json": {},
            "error": str(exc),
        }


def _is_generic_ok(raw: dict[str, Any]) -> bool:
    if not raw.get("ok", False):
        return False
    body = raw.get("json") or {}
    if not isinstance(body, dict):
        return False
    if "ok" in body:
        return bool(body.get("ok"))
    code = body.get("code")
    if code is not None:
        try:
            c = int(code)
        except Exception:
            return False
        if c in {0, 200}:
            msg = str(body.get("message", body.get("msg", ""))).strip().lower()
            return msg not in {"fail", "failed", "error"}
    return False


def _is_wxbot_ok(raw: dict[str, Any], success_code: int) -> bool:
    if not raw.get("ok", False):
        return False
    body = raw.get("json") or {}
    if not isinstance(body, dict):
        return False
    try:
        code = int(body.get("code", body.get("error_code", -1)))
    except Exception:
        code = -1
    return code == int(success_code)


@dataclass
class ProbeCandidate:
    base_url: str
    kind: str
    score: int
    detail: str
    comment_path: str = ""
    batch_path: str = ""
    wxbot_api_prefix: str = "/api"
    wxbot_wxid: str = ""
    probes: dict[str, Any] | None = None

    def sidecar_cmd(self, host: str, port: int) -> str:
        if self.kind == "wxbot_sendtxt":
            return (
                "python examples/run_http_comment_sidecar.py "
                f"--host {host} --port {port} --mode native_http "
                f"--native-upstream-base-url {self.base_url} "
                "--native-upstream-kind wxbot_sendtxt "
                f"--native-wxbot-api-prefix {self.wxbot_api_prefix} "
                f"--native-wxbot-wxid {self.wxbot_wxid}"
            )
        batch_arg = self.batch_path if self.batch_path else "-"
        return (
            "python examples/run_http_comment_sidecar.py "
            f"--host {host} --port {port} --mode native_http "
            f"--native-upstream-base-url {self.base_url} "
            "--native-upstream-kind generic "
            f"--native-comment-path {self.comment_path} "
            f"--native-batch-path {batch_arg}"
        )


def _probe_one_base(args: argparse.Namespace, base_url: str) -> list[ProbeCandidate]:
    out: list[ProbeCandidate] = []
    health_paths = ["/health", "/api/health", "/status", "/api/status"]
    health_hits = []
    for hp in health_paths:
        u = _url_join(base_url, hp)
        resp = _http_get_json(u, args.timeout_ms)
        if resp["ok"] and resp["status"] < 500:
            health_hits.append({"path": hp, "status": resp["status"], "json": resp.get("json", {})})

    # Generic probe
    generic_single_paths = ["/api/comment", "/comment", "/v1/comment"]
    generic_batch_paths = ["/api/comment/batch", "/comment/batch", "/v1/comment/batch"]
    single_ok_path = ""
    batch_ok_path = ""
    generic_probes: dict[str, Any] = {"health_hits": health_hits, "single": [], "batch": []}
    for p in generic_single_paths:
        payload = {
            "v": 1,
            "cmd": "comment",
            "task_id": "probe-single",
            "sns_id": args.sns_id,
            "author": args.author,
            "content_hash": args.content_hash,
            "reply_to": "",
            "content": "probe-generic-single",
        }
        r = _http_post_json(_url_join(base_url, p), payload, args.timeout_ms)
        generic_probes["single"].append({"path": p, "resp": r})
        if _is_generic_ok(r):
            single_ok_path = p
            break
    for p in generic_batch_paths:
        payload = {
            "v": 1,
            "cmd": "batch_comment",
            "task_id": "probe-batch",
            "sns_id": args.sns_id,
            "author": args.author,
            "content_hash": args.content_hash,
            "reply_to": "",
            "comments": ["probe-b1", "probe-b2"],
            "concurrency": 2,
        }
        r = _http_post_json(_url_join(base_url, p), payload, args.timeout_ms)
        generic_probes["batch"].append({"path": p, "resp": r})
        if _is_generic_ok(r):
            batch_ok_path = p
            break
    if single_ok_path:
        score = 100 if batch_ok_path else 85
        detail = f"generic single={single_ok_path}, batch={batch_ok_path or '-(fanout)'}"
        out.append(
            ProbeCandidate(
                base_url=base_url,
                kind="generic",
                score=score,
                detail=detail,
                comment_path=single_ok_path,
                batch_path=batch_ok_path,
                probes=generic_probes,
            )
        )

    # wxbot probe
    wxbot_paths = ["/api/sendtxtmsg", "/sendtxtmsg"]
    wxbot_ok = ""
    wxbot_api_prefix = "/api"
    wxbot_probes: dict[str, Any] = {"health_hits": health_hits, "sendtxt": []}
    for p in wxbot_paths:
        payload = {"wxid": args.wxid, "content": "probe-wxbot-sendtxt"}
        r = _http_post_json(_url_join(base_url, p), payload, args.timeout_ms)
        wxbot_probes["sendtxt"].append({"path": p, "resp": r})
        if _is_wxbot_ok(r, args.wxbot_success_code):
            wxbot_ok = p
            wxbot_api_prefix = "/api" if p.startswith("/api/") else "/"
            break
    if wxbot_ok:
        detail = f"wxbot sendtxt={wxbot_ok}"
        out.append(
            ProbeCandidate(
                base_url=base_url,
                kind="wxbot_sendtxt",
                score=90,
                detail=detail,
                wxbot_api_prefix=wxbot_api_prefix,
                wxbot_wxid=args.wxid,
                probes=wxbot_probes,
            )
        )
    return out


def _parse_ports(text: str) -> list[int]:
    out: list[int] = []
    for part in str(text or "").split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo_s, hi_s = part.split("-", 1)
            lo = int(lo_s)
            hi = int(hi_s)
            if lo > hi:
                lo, hi = hi, lo
            for p in range(lo, hi + 1):
                if 1 <= p <= 65535:
                    out.append(p)
        else:
            p = int(part)
            if 1 <= p <= 65535:
                out.append(p)
    # preserve order + unique
    seen = set()
    uniq = []
    for p in out:
        if p in seen:
            continue
        seen.add(p)
        uniq.append(p)
    return uniq


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Discover native HTTP upstream candidates.")
    p.add_argument(
        "--base-urls",
        default="",
        help="Comma-separated base URLs. Empty means scan localhost ports.",
    )
    p.add_argument(
        "--hosts",
        default="127.0.0.1,localhost",
        help="Hosts for scan mode (comma-separated).",
    )
    p.add_argument(
        "--ports",
        default="8060,8080,10010,19080,29080,3000,5000,5001,8888",
        help="Ports/ranges for scan mode, e.g. 8060,8080,10000-10020",
    )
    p.add_argument("--timeout-ms", type=int, default=450, help="HTTP probe timeout.")
    p.add_argument("--wxid", default="filehelper", help="wxid used for wxbot probe.")
    p.add_argument("--wxbot-success-code", type=int, default=200)
    p.add_argument("--sns-id", default="")
    p.add_argument("--author", default="")
    p.add_argument("--content-hash", default="")
    p.add_argument("--sidecar-host", default="127.0.0.1")
    p.add_argument("--sidecar-port", type=int, default=19080)
    p.add_argument(
        "--output",
        default="local_workspace/http_context/discovered_upstream.json",
        help="Output json file for probe results.",
    )
    return p.parse_args()


def main() -> int:
    args = _parse_args()
    timeout_ms = max(80, min(int(args.timeout_ms), 10000))
    args.timeout_ms = timeout_ms

    bases: list[str] = []
    if str(args.base_urls).strip():
        for u in str(args.base_urls).split(","):
            nu = _normalize_base(u)
            if nu:
                bases.append(nu)
    else:
        hosts = [h.strip() for h in str(args.hosts).split(",") if h.strip()]
        ports = _parse_ports(args.ports)
        for h in hosts:
            for p in ports:
                bases.append(_normalize_base(f"http://{h}:{p}"))

    # unique order
    uniq = []
    seen = set()
    for b in bases:
        if b in seen:
            continue
        seen.add(b)
        uniq.append(b)
    bases = uniq

    if not bases:
        raise ValueError("no base URLs to probe")

    _log(f"probing {len(bases)} upstream base URLs")
    all_candidates: list[ProbeCandidate] = []
    for idx, b in enumerate(bases, start=1):
        _log(f"[{idx}/{len(bases)}] probe {b}")
        try:
            cand = _probe_one_base(args, b)
        except Exception as exc:
            _log(f"probe failed for {b}: {exc}")
            cand = []
        all_candidates.extend(cand)

    all_candidates.sort(key=lambda x: x.score, reverse=True)
    best = all_candidates[0] if all_candidates else None

    report = {
        "generated_at": datetime.now().isoformat(),
        "timeout_ms": timeout_ms,
        "inputs": {
            "base_urls": args.base_urls,
            "hosts": args.hosts,
            "ports": args.ports,
            "wxid": args.wxid,
            "wxbot_success_code": args.wxbot_success_code,
            "sns_id": args.sns_id,
            "author": args.author,
            "content_hash": args.content_hash,
        },
        "candidate_count": len(all_candidates),
        "candidates": [
            {
                "base_url": c.base_url,
                "kind": c.kind,
                "score": c.score,
                "detail": c.detail,
                "comment_path": c.comment_path,
                "batch_path": c.batch_path,
                "wxbot_api_prefix": c.wxbot_api_prefix,
                "wxbot_wxid": c.wxbot_wxid,
                "probes": c.probes or {},
                "recommended_sidecar_cmd": c.sidecar_cmd(args.sidecar_host, args.sidecar_port),
            }
            for c in all_candidates
        ],
        "recommended": (
            {
                "base_url": best.base_url,
                "kind": best.kind,
                "score": best.score,
                "detail": best.detail,
                "sidecar_cmd": best.sidecar_cmd(args.sidecar_host, args.sidecar_port),
                "acceptance_cmd": (
                    "python examples/run_hook_e2e_acceptance.py 小蔡 "
                    "--backend http --http-provider native_http "
                    f"--http-base-url http://{args.sidecar_host}:{args.sidecar_port} "
                    "--pure-http --rounds 1 --concurrency 10"
                ),
            }
            if best
            else None
        ),
    }

    out_path = Path(args.output).expanduser().resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)

    _log(f"probe report saved: {out_path}")
    if best is None:
        _log("no compatible upstream detected")
        return 2

    _log(f"best candidate: kind={best.kind} score={best.score} base={best.base_url}")
    print("")
    print("Recommended sidecar command:")
    print(best.sidecar_cmd(args.sidecar_host, args.sidecar_port))
    print("")
    print("Recommended acceptance command:")
    print(
        "python examples/run_hook_e2e_acceptance.py 小蔡 "
        "--backend http --http-provider native_http "
        f"--http-base-url http://{args.sidecar_host}:{args.sidecar_port} "
        "--pure-http --rounds 1 --concurrency 10"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

