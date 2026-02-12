"""
Simple monitor: Just wait for manual comment and capture HTTP.
No automation needed.
"""

import frida
import sys
import time
import json
from pathlib import Path
from datetime import datetime
import psutil

output_dir = Path("local_workspace/http_captures")
output_dir.mkdir(parents=True, exist_ok=True)

captured = []

def on_message(message, data):
    global captured
    if message['type'] == 'send':
        payload = message['payload']
        if payload.get('type') == 'info':
            print(f"[Frida] {payload.get('msg')}")
        elif payload.get('type') == 'probe-hit':
            ascii_preview = payload.get('ascii_preview', '')
            if 'snscomment' in ascii_preview.lower() or 'mmsnscomment' in ascii_preview.lower():
                cap = {
                    'timestamp': datetime.now().isoformat(),
                    'size': payload.get('size', 0),
                    'ascii': ascii_preview,
                    'hex': payload.get('hex_preview', ''),
                }
                captured.append(cap)
                print(f"\n{'='*60}")
                print(f"[CAPTURED #{len(captured)}] Comment HTTP Request!")
                print(f"{'='*60}")
                print(f"Size: {cap['size']} bytes")
                print(f"Preview: {ascii_preview[:150]}")
                print(f"{'='*60}\n")

def main():
    # Find WeChat
    weixin_pids = [(p.pid, p.memory_info().rss) for p in psutil.process_iter(['pid', 'name'])
                   if p.name() == 'Weixin.exe']
    weixin_pids.sort(key=lambda x: x[1], reverse=True)
    main_pid = weixin_pids[0][0]

    print(f"\n[*] Attaching to WeChat (PID {main_pid})...")
    session = frida.attach(main_pid)
    print(f"[*] Attached!")

    script_path = Path("examples/frida_wsasend_probe.js")
    script_code = script_path.read_text(encoding='utf-8')
    script = session.create_script(script_code)
    script.on('message', on_message)
    script.load()

    print(f"\n{'='*60}")
    print(f"READY TO CAPTURE!")
    print(f"{'='*60}")
    print(f"Now MANUALLY:")
    print(f"  1. Open WeChat Moments")
    print(f"  2. Find any post")
    print(f"  3. Send a comment")
    print(f"  4. Wait for capture confirmation above")
    print(f"\nListening... (Ctrl+C to stop)")
    print(f"{'='*60}\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print(f"\n\n[*] Stopping...")

    print(f"\n{'='*60}")
    print(f"RESULTS")
    print(f"{'='*60}")
    print(f"Captured: {len(captured)} comment HTTP requests")

    if captured:
        filepath = output_dir / "manual_test.json"
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(captured, f, indent=2, ensure_ascii=False)
        print(f"Saved to: {filepath}")
        print(f"\n[SUCCESS] WSASend Hook WORKS!")
        print(f"          Route A is FEASIBLE!")
        return 0
    else:
        print(f"\n[NEGATIVE] No HTTP requests captured")
        print(f"           Check if you sent a comment")
        return 1

if __name__ == "__main__":
    sys.exit(main())
