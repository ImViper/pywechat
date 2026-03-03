"""Attach a Frida JS probe to Weixin processes and run one trigger action.

This is used for protocol reconnaissance:
1) auto-attach to attachable Weixin/WeChatAppEx processes with Weixin.dll loaded
2) load one Frida JS probe script
3) run an action command (for example one real UI comment run)
4) collect probe events and save a JSON report
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import threading
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _log(msg: str) -> None:
    now = datetime.now().strftime("%H:%M:%S")
    print(f"[{now}] {msg}", flush=True)


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Run Frida JS probe + action command.")
    p.add_argument("--script", required=True, help="Frida JS probe file path.")
    p.add_argument(
        "--name-patterns",
        default="Weixin.exe,WeChatAppEx.exe",
        help="Comma-separated process names to include.",
    )
    p.add_argument(
        "--action-cmd",
        default="",
        help="Optional command to trigger action while probe is attached.",
    )
    p.add_argument(
        "--workdir",
        default=str(PROJECT_ROOT),
        help="Working directory used for --action-cmd.",
    )
    p.add_argument("--action-timeout-s", type=float, default=120.0)
    p.add_argument("--pre-capture-s", type=float, default=0.8)
    p.add_argument("--post-capture-s", type=float, default=2.5)
    p.add_argument("--max-events", type=int, default=5000)
    p.add_argument("--detach-timeout-s", type=float, default=2.0)
    p.add_argument(
        "--output",
        default="",
        help="Output JSON report path. Empty uses timestamp file in local_workspace/http_context.",
    )
    return p.parse_args()


def _probe_mod_loaded(session, module_name: str) -> bool:
    probe_js = f"""
    'use strict';
    const m = Process.findModuleByName('{module_name}');
    send({{ok: !!m, base: m ? m.base.toString() : ''}});
    """
    box: dict[str, Any] = {}
    done = threading.Event()
    script = session.create_script(probe_js)

    def _on_msg(msg: dict, _data: bytes | None) -> None:
        if msg.get("type") == "send":
            payload = msg.get("payload")
            if isinstance(payload, dict):
                box.update(payload)
                done.set()

    script.on("message", _on_msg)
    script.load()
    done.wait(timeout=1.5)
    try:
        script.unload()
    except Exception:
        pass
    return bool(box.get("ok"))


@dataclass
class AttachTarget:
    pid: int
    name: str
    session: Any
    script: Any | None = None


def _discover_targets(device, names: set[str]) -> list[AttachTarget]:
    targets: list[AttachTarget] = []
    for proc in sorted(device.enumerate_processes(), key=lambda x: x.pid):
        if proc.name.lower() not in names:
            continue
        session = None
        try:
            session = device.attach(proc.pid)
            if not _probe_mod_loaded(session, "Weixin.dll"):
                session.detach()
                continue
            targets.append(AttachTarget(pid=int(proc.pid), name=proc.name, session=session))
        except Exception:
            if session is not None:
                try:
                    session.detach()
                except Exception:
                    pass
    return targets


def _run_action(cmd: str, cwd: Path, timeout_s: float) -> dict[str, Any]:
    if not cmd.strip():
        return {
            "ran": False,
            "returncode": 0,
            "timeout": False,
            "duration_ms": 0,
            "output_tail": "",
            "cmd": "",
        }

    started = time.perf_counter()
    timeout = False
    cp = None
    try:
        cp = subprocess.run(
            cmd,
            cwd=str(cwd),
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=max(timeout_s, 1.0),
        )
    except subprocess.TimeoutExpired as exc:
        timeout = True
        cp = subprocess.CompletedProcess(
            args=cmd,
            returncode=124,
            stdout=(exc.stdout or "") + "\n[action timeout]",
        )

    elapsed = int((time.perf_counter() - started) * 1000)
    out = cp.stdout if isinstance(cp.stdout, str) else str(cp.stdout or "")
    return {
        "ran": True,
        "returncode": int(cp.returncode),
        "timeout": timeout,
        "duration_ms": elapsed,
        "output_tail": out[-5000:],
        "cmd": cmd,
    }


def _call_with_timeout(fn, timeout_s: float) -> tuple[bool, str]:
    done = threading.Event()
    err: list[str] = []

    def _runner() -> None:
        try:
            fn()
        except Exception as exc:  # pragma: no cover
            err.append(str(exc))
        finally:
            done.set()

    t = threading.Thread(target=_runner, daemon=True)
    t.start()
    ok = done.wait(timeout=max(timeout_s, 0.2))
    if not ok:
        return False, "timeout"
    if err:
        return False, err[0]
    return True, ""


def main() -> int:
    args = _parse_args()
    script_path = Path(args.script).expanduser().resolve()
    if not script_path.is_file():
        raise FileNotFoundError(f"probe script not found: {script_path}")
    js_code = script_path.read_text(encoding="utf-8")

    import frida

    names = {x.strip().lower() for x in str(args.name_patterns).split(",") if x.strip()}
    device = frida.get_local_device()
    targets = _discover_targets(device, names)
    if not targets:
        raise RuntimeError("no attachable target process with Weixin.dll loaded")

    _log(f"attach targets: {[f'{t.pid}:{t.name}' for t in targets]}")

    lock = threading.Lock()
    events: list[dict[str, Any]] = []
    dropped = 0

    def _push_event(item: dict[str, Any]) -> None:
        nonlocal dropped
        with lock:
            if len(events) >= max(int(args.max_events), 1):
                dropped += 1
                return
            events.append(item)

    def _build_handler(pid: int):
        def _on_message(msg: dict, data: bytes | None) -> None:
            payload = msg.get("payload")
            item = {
                "ts": datetime.now().isoformat(timespec="milliseconds"),
                "pid": pid,
                "type": str(msg.get("type", "")),
                "payload": payload,
            }
            if data is not None:
                item["data_len"] = len(data)
            _push_event(item)

        return _on_message

    loaded = 0
    for t in targets:
        try:
            s = t.session.create_script(js_code)
            s.on("message", _build_handler(t.pid))
            s.load()
            t.script = s
            loaded += 1
        except Exception as exc:
            _push_event(
                {
                    "ts": datetime.now().isoformat(timespec="milliseconds"),
                    "pid": t.pid,
                    "type": "error",
                    "payload": f"script load failed: {exc}",
                }
            )
    if loaded == 0:
        raise RuntimeError("failed to load probe script in any target process")

    _log(f"probe script loaded into {loaded} process(es)")
    time.sleep(max(float(args.pre_capture_s), 0.0))

    action = _run_action(
        str(args.action_cmd),
        Path(args.workdir).expanduser().resolve(),
        float(args.action_timeout_s),
    )
    if action["ran"]:
        _log(
            f"action done: returncode={action['returncode']} timeout={action['timeout']} "
            f"duration_ms={action['duration_ms']}"
        )
    else:
        _log("no action command; probe-only capture")

    time.sleep(max(float(args.post_capture_s), 0.0))

    detach_errors: list[dict[str, Any]] = []
    for t in targets:
        if t.script is not None:
            ok, err = _call_with_timeout(t.script.unload, float(args.detach_timeout_s))
            if not ok:
                detach_errors.append({"pid": t.pid, "op": "unload", "error": err})
        ok, err = _call_with_timeout(t.session.detach, float(args.detach_timeout_s))
        if not ok:
            detach_errors.append({"pid": t.pid, "op": "detach", "error": err})

    out_path = (
        Path(args.output).expanduser().resolve()
        if str(args.output).strip()
        else (
            PROJECT_ROOT
            / "local_workspace"
            / "http_context"
            / f"frida_capture_{script_path.stem}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        )
    )
    out_path.parent.mkdir(parents=True, exist_ok=True)
    report = {
        "generated_at": datetime.now().isoformat(),
        "args": vars(args),
        "script": str(script_path),
        "targets": [{"pid": t.pid, "name": t.name} for t in targets],
        "loaded_targets": loaded,
        "event_count": len(events),
        "dropped_events": dropped,
        "action": action,
        "detach_errors": detach_errors,
        "events": events,
    }
    with out_path.open("w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    _log(f"capture saved: {out_path}")
    _log(f"events={len(events)}, dropped={dropped}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
