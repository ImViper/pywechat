"""
Quick test: Hook WSASend and send one comment via Hook DLL.
This will tell us if Hook DLL triggers WSASend or bypasses it.
"""

import frida
import sys
import time
import json
from pathlib import Path
from datetime import datetime

project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from pyweixin.hook_bridge import HookBridge

captured_requests = []

def on_message(message, data):
    if message['type'] == 'send':
        payload = message['payload']
        if payload.get('type') == 'probe-hit':
            ascii_preview = payload.get('ascii_preview', '')
            if 'snscomment' in ascii_preview.lower() or 'mmsnscomment' in ascii_preview.lower():
                captured_requests.append({
                    'timestamp': datetime.now().isoformat(),
                    'size': payload.get('size', 0),
                    'ascii': ascii_preview[:500],
                    'hex': payload.get('hex_preview', '')[:1000],
                })
                print(f"\n[CAPTURED] Comment HTTP request!")
                print(f"           Size: {payload.get('size', 0)} bytes")
                print(f"           Preview: {ascii_preview[:100]}")

def main():
    # Find main WeChat PID
    import psutil
    weixin_pids = [(p.pid, p.memory_info().rss) for p in psutil.process_iter(['pid', 'name'])
                   if p.name() == 'Weixin.exe']
    weixin_pids.sort(key=lambda x: x[1], reverse=True)

    if not weixin_pids:
        print("[ERROR] Weixin.exe not found!")
        return 1

    main_pid = weixin_pids[0][0]
    print(f"[*] Main WeChat PID: {main_pid}")

    # Attach Frida
    print(f"[*] Attaching Frida...")
    session = frida.attach(main_pid)
    print(f"[*] Attached successfully")

    # Load WSASend hook script
    script_path = Path("examples/frida_wsasend_probe.js")
    script_code = script_path.read_text(encoding='utf-8')
    script = session.create_script(script_code)
    script.on('message', on_message)
    script.load()
    print(f"[*] WSASend hook loaded\n")

    time.sleep(2)  # Let hooks stabilize

    # Check Hook DLL connection
    print(f"[*] Connecting to Hook DLL...")
    bridge = HookBridge()
    if not bridge.ping():
        print("[ERROR] Hook DLL not responding!")
        print("        Please inject pywechat_hook.dll first")
        return 1

    status = bridge.status()
    print(f"[*] Hook DLL connected")
    print(f"    State captured: {status.data.get('state_captured')}")

    if not status.data.get('state_captured'):
        print("\n[WARNING] Hook state not captured!")
        print("          Please send a warmup comment first")
        print("          Run: python local_workspace/auto_warmup.py")
        return 1

    # Send ONE test comment
    print(f"\n[*] Sending test comment via Hook DLL...")
    result = bridge.send_comment(
        sns_id=status.data.get('last_sns_id', 0) or 14111111111111111111,
        content="Frida HTTP捕获测试",
        reply_comment_id=0
    )

    print(f"[*] Hook DLL response: code={result.code}, msg={result.message}")

    # Wait for HTTP capture
    print(f"\n[*] Waiting 3 seconds for HTTP capture...")
    time.sleep(3)

    # Results
    print(f"\n{'='*80}")
    print(f"RESULTS")
    print(f"{'='*80}")
    print(f"HTTP requests captured: {len(captured_requests)}")

    if captured_requests:
        print(f"\n[SUCCESS] Hook DLL DOES trigger WSASend!")
        print(f"          Route A (Hook WSASend) is FEASIBLE!")
        print(f"\nCaptured data saved to: local_workspace/http_captures/quick_test.json")

        output_dir = Path("local_workspace/http_captures")
        output_dir.mkdir(parents=True, exist_ok=True)
        with open(output_dir / "quick_test.json", 'w', encoding='utf-8') as f:
            json.dump(captured_requests, f, indent=2, ensure_ascii=False)
    else:
        print(f"\n[NEGATIVE] Hook DLL does NOT trigger WSASend")
        print(f"           This means Hook calls CGI function directly")
        print(f"           Route A (WSASend Hook) will NOT work")
        print(f"\n[ALTERNATIVE] We need to:")
        print(f"  1. Hook a higher-level function (protobuf layer)")
        print(f"  2. Or instrument Hook DLL itself to log requests")

    script.unload()
    session.detach()

    return 0 if captured_requests else 1

if __name__ == "__main__":
    sys.exit(main())
