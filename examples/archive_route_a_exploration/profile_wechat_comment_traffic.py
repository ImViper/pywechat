"""Profile WeChat comment traffic using built-in pktmon (no third-party tools).

Workflow:
1. Capture baseline traffic for N seconds.
2. Capture traffic while triggering one UI comment action.
3. Parse pktmon text and diff endpoints to highlight likely comment-related flows.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import socket
import subprocess
import time
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _log(msg: str) -> None:
    now = datetime.now().strftime("%H:%M:%S")
    print(f"[{now}] {msg}", flush=True)


def _run(cmd: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    cp = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if check and cp.returncode != 0:
        raise RuntimeError(f"command failed ({cp.returncode}): {' '.join(cmd)}\n{cp.stdout}")
    return cp


def _pktmon_stop() -> None:
    _run(["pktmon", "stop"], check=False)


def _pktmon_capture(*, etl_path: Path, duration_s: float) -> None:
    if etl_path.exists():
        etl_path.unlink()
    _run(
        [
            "pktmon",
            "start",
            "--capture",
            "--comp",
            "nics",
            "--pkt-size",
            "0",
            "--file-name",
            str(etl_path),
        ]
    )
    time.sleep(max(duration_s, 0.5))
    _pktmon_stop()


def _pktmon_capture_with_action(*, etl_path: Path, action_cmd: list[str]) -> subprocess.CompletedProcess[str]:
    if etl_path.exists():
        etl_path.unlink()
    _run(
        [
            "pktmon",
            "start",
            "--capture",
            "--comp",
            "nics",
            "--pkt-size",
            "0",
            "--file-name",
            str(etl_path),
        ]
    )
    try:
        cp = _run(action_cmd, check=False)
    finally:
        _pktmon_stop()
    return cp


def _pktmon_format(etl_path: Path, txt_path: Path) -> None:
    if txt_path.exists():
        txt_path.unlink()
    _run(["pktmon", "format", str(etl_path), "-o", str(txt_path)])


def _is_private_or_local(ip: str) -> bool:
    try:
        obj = ipaddress.ip_address(ip)
    except Exception:
        return False
    return obj.is_private or obj.is_loopback or obj.is_link_local


LINE_RE = re.compile(
    r"length\s+(?P<plen>\d+):\s+"
    r"(?P<src>[0-9a-fA-F:.]+)\.(?P<srcp>\d+)\s*>\s*"
    r"(?P<dst>[0-9a-fA-F:.]+)\.(?P<dstp>\d+):"
)


@dataclass
class EndpointStat:
    packets: int = 0
    bytes: int = 0

    def add(self, b: int) -> None:
        self.packets += 1
        self.bytes += max(int(b), 0)


def _parse_pktmon_txt(txt_path: Path) -> dict[str, EndpointStat]:
    stats: dict[str, EndpointStat] = defaultdict(EndpointStat)
    raw = txt_path.read_bytes()
    if raw.startswith(b"\xff\xfe") or raw.startswith(b"\xfe\xff"):
        text = raw.decode("utf-16", errors="replace")
    else:
        text = raw.decode("utf-8", errors="replace")

    for line in text.splitlines():
        m = LINE_RE.search(line)
        if not m:
            continue
        plen = int(m.group("plen"))
        src = m.group("src")
        srcp = int(m.group("srcp"))
        dst = m.group("dst")
        dstp = int(m.group("dstp"))

        src_local = _is_private_or_local(src)
        dst_local = _is_private_or_local(dst)
        if src_local and (not dst_local):
            key = f"{dst}:{dstp}"
        elif dst_local and (not src_local):
            key = f"{src}:{srcp}"
        else:
            # skip local-local or public-public ambiguous lines
            continue
        stats[key].add(plen)
    return stats


def _reverse_dns(ip: str) -> str:
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        return host
    except Exception:
        return ""


def _diff_stats(
    baseline: dict[str, EndpointStat],
    action: dict[str, EndpointStat],
    *,
    resolve_dns: bool,
) -> list[dict[str, Any]]:
    keys = sorted(set(baseline.keys()) | set(action.keys()))
    rows: list[dict[str, Any]] = []
    for k in keys:
        b = baseline.get(k, EndpointStat())
        a = action.get(k, EndpointStat())
        d_packets = a.packets - b.packets
        d_bytes = a.bytes - b.bytes
        ip, _, port = k.rpartition(":")
        rows.append(
            {
                "endpoint": k,
                "ip": ip,
                "port": int(port) if port.isdigit() else 0,
                "reverse_dns": _reverse_dns(ip) if resolve_dns else "",
                "baseline_packets": b.packets,
                "baseline_bytes": b.bytes,
                "action_packets": a.packets,
                "action_bytes": a.bytes,
                "delta_packets": d_packets,
                "delta_bytes": d_bytes,
            }
        )
    rows.sort(key=lambda x: (x["delta_bytes"], x["delta_packets"]), reverse=True)
    return rows


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Profile WeChat comment traffic with pktmon.")
    p.add_argument("--target-author", default="小蔡")
    p.add_argument("--baseline-seconds", type=float, default=5.0)
    p.add_argument(
        "--action-cmd",
        default="",
        help=(
            "Optional custom action command. Empty uses: "
            "python examples/run_hook_e2e_acceptance.py <target> --collect-context-only "
            "--no-restart-wechat --keep-wechat"
        ),
    )
    p.add_argument(
        "--workdir",
        default=str(PROJECT_ROOT),
        help="Working dir for action command (default project root).",
    )
    p.add_argument(
        "--output",
        default="local_workspace/http_context/wechat_comment_traffic_profile.json",
    )
    p.add_argument(
        "--resolve-dns",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Resolve reverse DNS for endpoint IPs (may be slow).",
    )
    return p.parse_args()


def main() -> int:
    args = _parse_args()
    out_path = Path(args.output).expanduser().resolve()
    out_dir = out_path.parent
    out_dir.mkdir(parents=True, exist_ok=True)

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    baseline_etl = out_dir / f"pktmon_baseline_{ts}.etl"
    baseline_txt = out_dir / f"pktmon_baseline_{ts}.txt"
    action_etl = out_dir / f"pktmon_action_{ts}.etl"
    action_txt = out_dir / f"pktmon_action_{ts}.txt"

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
        ]

    # Ensure no stale capture session.
    _pktmon_stop()
    _run(["pktmon", "filter", "remove"], check=False)

    _log(f"capture baseline: {args.baseline_seconds}s")
    _pktmon_capture(etl_path=baseline_etl, duration_s=float(args.baseline_seconds))
    _pktmon_format(baseline_etl, baseline_txt)

    _log("capture action while triggering one comment context collection")
    cwd = os.getcwd()
    try:
        os.chdir(str(Path(args.workdir).expanduser().resolve()))
        action_cp = _pktmon_capture_with_action(etl_path=action_etl, action_cmd=action_cmd)
    finally:
        os.chdir(cwd)
    _pktmon_format(action_etl, action_txt)

    baseline_stats = _parse_pktmon_txt(baseline_txt)
    action_stats = _parse_pktmon_txt(action_txt)
    rows = _diff_stats(baseline_stats, action_stats, resolve_dns=bool(args.resolve_dns))
    top = [r for r in rows if r["delta_packets"] > 0][:30]

    report = {
        "generated_at": datetime.now().isoformat(),
        "args": vars(args),
        "files": {
            "baseline_etl": str(baseline_etl),
            "baseline_txt": str(baseline_txt),
            "action_etl": str(action_etl),
            "action_txt": str(action_txt),
        },
        "action_cmd": action_cmd,
        "action_returncode": int(action_cp.returncode),
        "action_output_tail": action_cp.stdout[-4000:] if action_cp.stdout else "",
        "top_delta_endpoints": top,
        "all_deltas": rows[:200],
    }

    with out_path.open("w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)

    _log(f"traffic profile saved: {out_path}")
    if top:
        _log("top delta endpoints:")
        for r in top[:10]:
            host = r.get("reverse_dns") or "-"
            _log(
                f"  {r['endpoint']} host={host} "
                f"delta_packets={r['delta_packets']} delta_bytes={r['delta_bytes']}"
            )
    else:
        _log("no positive delta endpoints found")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
