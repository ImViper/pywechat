"""Probe Frida attachability for Weixin/WeChatAppEx processes.

Outputs a JSON report to help decide where protocol hooks can run.
"""

from __future__ import annotations

import argparse
import json
import time
from datetime import datetime
from pathlib import Path
from typing import Any


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Probe Frida attachability for WeChat processes.")
    p.add_argument(
        "--name-patterns",
        default="Weixin.exe,WeChatAppEx.exe",
        help="Comma-separated process names to include.",
    )
    p.add_argument(
        "--output",
        default="local_workspace/http_context/frida_attach_report.json",
        help="Output report path.",
    )
    p.add_argument("--attach-timeout-s", type=float, default=2.5)
    return p.parse_args()


def _log(msg: str) -> None:
    now = datetime.now().strftime("%H:%M:%S")
    print(f"[{now}] {msg}", flush=True)


def _run_probe(args: argparse.Namespace) -> dict[str, Any]:
    import frida

    device = frida.get_local_device()
    names = {x.strip().lower() for x in str(args.name_patterns).split(",") if x.strip()}
    processes = [p for p in device.enumerate_processes() if p.name.lower() in names]
    results: list[dict[str, Any]] = []

    js_probe = """
    'use strict';
    const ws = Process.findModuleByName('ws2_32.dll');
    const wx = Process.findModuleByName('Weixin.dll');
    send({
      ws2_32_loaded: !!ws,
      ws2_32_base: ws ? ws.base.toString() : '',
      weixin_dll_loaded: !!wx,
      weixin_dll_base: wx ? wx.base.toString() : ''
    });
    """

    for proc in sorted(processes, key=lambda p: p.pid):
        item: dict[str, Any] = {
            "pid": int(proc.pid),
            "name": proc.name,
            "attach_ok": False,
            "error": "",
            "probe": {},
            "latency_ms": 0,
        }
        t0 = time.perf_counter()
        session = None
        try:
            session = device.attach(proc.pid)
            item["attach_ok"] = True

            payload_box: dict[str, Any] = {}

            script = session.create_script(js_probe)

            def _on_message(msg: dict, _data: bytes | None) -> None:
                if msg.get("type") == "send":
                    payload = msg.get("payload")
                    if isinstance(payload, dict):
                        payload_box.update(payload)

            script.on("message", _on_message)
            script.load()
            deadline = time.time() + max(float(args.attach_timeout_s), 0.3)
            while time.time() < deadline:
                if payload_box:
                    break
                time.sleep(0.05)
            item["probe"] = payload_box
            try:
                script.unload()
            except Exception:
                pass
        except Exception as exc:
            item["error"] = str(exc)
        finally:
            if session is not None:
                try:
                    session.detach()
                except Exception:
                    pass
        item["latency_ms"] = int((time.perf_counter() - t0) * 1000)
        results.append(item)

    summary = {
        "total": len(results),
        "attach_ok": sum(1 for r in results if r.get("attach_ok")),
        "attach_failed": sum(1 for r in results if not r.get("attach_ok")),
        "ws2_32_loaded_in_attachable": sum(
            1 for r in results if r.get("attach_ok") and bool((r.get("probe") or {}).get("ws2_32_loaded"))
        ),
    }

    return {
        "generated_at": datetime.now().isoformat(),
        "args": vars(args),
        "summary": summary,
        "processes": results,
    }


def main() -> int:
    args = _parse_args()
    report = _run_probe(args)
    out = Path(args.output).expanduser().resolve()
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    _log(f"report saved: {out}")
    _log(
        "summary: "
        f"total={report['summary']['total']}, "
        f"attach_ok={report['summary']['attach_ok']}, "
        f"ws2_32_loaded_in_attachable={report['summary']['ws2_32_loaded_in_attachable']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

