"""Extract CGI endpoint strings from Weixin.dll.

Useful for protocol reconnaissance (e.g. confirming mmsnscomment presence).
"""

from __future__ import annotations

import argparse
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any


DEFAULT_DLL = r"C:\Program Files\Tencent\Weixin\4.1.7.30\Weixin.dll"


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Extract CGI endpoints from Weixin.dll")
    p.add_argument("--dll", default=DEFAULT_DLL, help="Path to Weixin.dll")
    p.add_argument(
        "--output",
        default="local_workspace/http_context/weixin_cgi_catalog.json",
        help="Output JSON path.",
    )
    return p.parse_args()


def _log(msg: str) -> None:
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}", flush=True)


def _extract_cgi(binary: bytes) -> list[str]:
    pat = re.compile(rb"/cgi-bin/micromsg-bin/[a-z0-9\-_\/]+")
    seen: set[str] = set()
    out: list[str] = []
    for m in pat.finditer(binary):
        try:
            s = m.group(0).decode("ascii", errors="ignore")
        except Exception:
            continue
        if not s or s in seen:
            continue
        seen.add(s)
        out.append(s)
    return sorted(out)


def _build_report(args: argparse.Namespace, cgis: list[str]) -> dict[str, Any]:
    key_targets = [
        "/cgi-bin/micromsg-bin/mmsnscomment",
        "/cgi-bin/micromsg-bin/mmsnstimeline",
        "/cgi-bin/micromsg-bin/mmsnsobjectdetail",
        "/cgi-bin/micromsg-bin/mmsnspost",
        "/cgi-bin/micromsg-bin/mmsnssync",
    ]
    sns = [x for x in cgis if "sns" in x.lower()]
    hits = {k: (k in cgis) for k in key_targets}
    return {
        "generated_at": datetime.now().isoformat(),
        "dll": str(Path(args.dll).expanduser().resolve()),
        "summary": {
            "total_cgi": len(cgis),
            "sns_related": len(sns),
            "key_target_hits": hits,
        },
        "sns_endpoints": sns,
        "all_endpoints": cgis,
    }


def main() -> int:
    args = _parse_args()
    dll_path = Path(args.dll).expanduser().resolve()
    if not dll_path.exists():
        raise FileNotFoundError(f"dll not found: {dll_path}")

    raw = dll_path.read_bytes()
    cgis = _extract_cgi(raw)
    report = _build_report(args, cgis)

    out = Path(args.output).expanduser().resolve()
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)

    _log(f"report saved: {out}")
    _log(
        f"summary: total_cgi={report['summary']['total_cgi']}, "
        f"sns_related={report['summary']['sns_related']}, "
        f"mmsnscomment={report['summary']['key_target_hits']['/cgi-bin/micromsg-bin/mmsnscomment']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

