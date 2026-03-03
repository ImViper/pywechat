"""Profile Weixin.exe outbound TCP endpoints during a comment trigger action."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import threading
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _log(msg: str) -> None:
    now = datetime.now().strftime("%H:%M:%S")
    print(f"[{now}] {msg}", flush=True)


def _run_ps_json(script: str) -> Any:
    cp = subprocess.run(
        ["powershell", "-NoProfile", "-Command", script],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    out = cp.stdout.strip()
    if cp.returncode != 0:
        raise RuntimeError(f"powershell failed ({cp.returncode}): {out}")
    if not out:
        return []
    return json.loads(out)


def _get_weixin_pids() -> list[int]:
    script = (
        "Get-Process -Name Weixin -ErrorAction SilentlyContinue | "
        "Select-Object -ExpandProperty Id | ConvertTo-Json -Compress"
    )
    data = _run_ps_json(script)
    if isinstance(data, int):
        return [data]
    if isinstance(data, list):
        out = []
        for x in data:
            try:
                out.append(int(x))
            except Exception:
                pass
        return out
    return []


def _sample_conns_for_pids(pids: list[int]) -> list[dict[str, Any]]:
    if not pids:
        return []
    pid_csv = ",".join(str(int(x)) for x in sorted(set(pids)))
    script = (
        f"$p=@({pid_csv}); "
        "Get-NetTCPConnection -ErrorAction SilentlyContinue | "
        "Where-Object { $p -contains $_.OwningProcess } | "
        "Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,OwningProcess,State | "
        "ConvertTo-Json -Compress"
    )
    data = _run_ps_json(script)
    if isinstance(data, dict):
        return [data]
    if isinstance(data, list):
        return data
    return []


def _is_public(addr: str) -> bool:
    s = str(addr or "").strip().lower()
    if not s:
        return False
    if s in {"127.0.0.1", "::1", "0.0.0.0", "::"}:
        return False
    if s.startswith("10.") or s.startswith("192.168."):
        return False
    if s.startswith("172."):
        try:
            sec = int(s.split(".")[1])
            if 16 <= sec <= 31:
                return False
        except Exception:
            pass
    if s.startswith("fe80:") or s.startswith("fc") or s.startswith("fd"):
        return False
    return True


def _collect_window(
    pids: list[int],
    *,
    duration_s: float,
    interval_ms: int,
) -> dict[str, dict[str, int]]:
    seen: dict[str, dict[str, int]] = defaultdict(lambda: {"hits": 0, "pids": 0})
    deadline = time.time() + max(duration_s, 0.5)
    while time.time() < deadline:
        conns = _sample_conns_for_pids(pids)
        pids_seen = set()
        for c in conns:
            ra = str(c.get("RemoteAddress", ""))
            rp = int(c.get("RemotePort", 0) or 0)
            if not _is_public(ra) or rp <= 0:
                continue
            key = f"{ra}:{rp}"
            seen[key]["hits"] += 1
            try:
                pids_seen.add(int(c.get("OwningProcess", 0) or 0))
            except Exception:
                pass
        for pid in pids_seen:
            for k in list(seen.keys()):
                # mark we have seen at least one pid; not precise per-endpoint,
                # but enough for quick profiling.
                seen[k]["pids"] = max(seen[k]["pids"], 1)
        time.sleep(max(interval_ms, 80) / 1000.0)
    return seen


def _merge_stats_diff(
    baseline: dict[str, dict[str, int]],
    action: dict[str, dict[str, int]],
) -> list[dict[str, Any]]:
    keys = sorted(set(baseline.keys()) | set(action.keys()))
    rows: list[dict[str, Any]] = []
    for k in keys:
        b = baseline.get(k, {"hits": 0})
        a = action.get(k, {"hits": 0})
        rows.append(
            {
                "endpoint": k,
                "baseline_hits": int(b.get("hits", 0)),
                "action_hits": int(a.get("hits", 0)),
                "delta_hits": int(a.get("hits", 0)) - int(b.get("hits", 0)),
            }
        )
    rows.sort(key=lambda x: (x["delta_hits"], x["action_hits"]), reverse=True)
    return rows


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Profile Weixin outbound TCP endpoints.")
    p.add_argument("--target-author", default="小蔡")
    p.add_argument("--baseline-seconds", type=float, default=4.0)
    p.add_argument("--interval-ms", type=int, default=120)
    p.add_argument(
        "--action-cmd",
        default="",
        help=(
            "Optional action command. Empty uses context-only collection command."
        ),
    )
    p.add_argument("--workdir", default=str(PROJECT_ROOT))
    p.add_argument(
        "--output",
        default="local_workspace/http_context/wechat_connection_profile.json",
    )
    return p.parse_args()


def main() -> int:
    args = _parse_args()
    out_path = Path(args.output).expanduser().resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)

    pids = _get_weixin_pids()
    if not pids:
        raise RuntimeError("cannot find Weixin.exe process")
    _log(f"Weixin pids: {pids}")

    _log(f"baseline sampling: {args.baseline_seconds}s")
    baseline = _collect_window(
        pids,
        duration_s=float(args.baseline_seconds),
        interval_ms=int(args.interval_ms),
    )

    action_cmd_text = str(args.action_cmd).strip()
    if action_cmd_text:
        action_cmd = action_cmd_text.split()
    else:
        action_cmd = [
            "python",
            "examples/run_hook_e2e_acceptance.py",
            args.target_author,
            "--collect-context-only",
            "--no-restart-wechat",
            "--keep-wechat",
            "--open-retries",
            "1",
            "--open-attempt-timeout-s",
            "6",
        ]

    stop_evt = threading.Event()
    action_samples: dict[str, dict[str, int]] = defaultdict(lambda: {"hits": 0, "pids": 0})

    def _sampler() -> None:
        nonlocal action_samples
        while not stop_evt.is_set():
            chunk = _collect_window(pids, duration_s=0.25, interval_ms=int(args.interval_ms))
            for k, v in chunk.items():
                action_samples[k]["hits"] += int(v.get("hits", 0))
                action_samples[k]["pids"] = max(action_samples[k]["pids"], int(v.get("pids", 0)))
            time.sleep(max(int(args.interval_ms), 80) / 1000.0)

    _log("action sampling: trigger one comment action")
    t = threading.Thread(target=_sampler, daemon=True)
    t.start()
    cwd = os.getcwd()
    try:
        os.chdir(str(Path(args.workdir).expanduser().resolve()))
        cp = subprocess.run(
            action_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    finally:
        os.chdir(cwd)
        stop_evt.set()
        t.join(timeout=2.0)

    rows = _merge_stats_diff(baseline, action_samples)
    top = [r for r in rows if r["delta_hits"] > 0][:30]

    report = {
        "generated_at": datetime.now().isoformat(),
        "args": vars(args),
        "weixin_pids": pids,
        "action_cmd": action_cmd,
        "action_returncode": int(cp.returncode),
        "action_output_tail": (cp.stdout or "")[-4000:],
        "top_delta_endpoints": top,
        "all_deltas": rows[:200],
    }
    with out_path.open("w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)

    _log(f"connection profile saved: {out_path}")
    if top:
        _log("top delta endpoints:")
        for r in top[:10]:
            _log(
                f"  {r['endpoint']} delta_hits={r['delta_hits']} "
                f"action_hits={r['action_hits']} baseline_hits={r['baseline_hits']}"
            )
    else:
        _log("no positive delta endpoints found")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
