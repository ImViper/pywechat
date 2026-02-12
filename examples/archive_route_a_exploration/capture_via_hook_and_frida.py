"""
Capture HTTP requests by sending comments via Hook DLL.

This combines:
1. Frida hooking WSASend to capture HTTP requests
2. Hook DLL sending comments to trigger requests

Usage:
    python examples/capture_via_hook_and_frida.py [sns_id]
"""

import frida
import sys
import time
import json
import threading
from pathlib import Path
from datetime import datetime

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from pyweixin.hook_bridge import HookBridge
from pyweixin.comment_dispatcher import CommentDispatcher

# Output directory
CAPTURE_DIR = Path("local_workspace/http_captures")
CAPTURE_DIR.mkdir(parents=True, exist_ok=True)

class FridaCapture:
    """Frida session for capturing HTTP requests."""

    def __init__(self):
        self.session = None
        self.script = None
        self.comment_requests = []
        self.lock = threading.Lock()

    def on_message(self, message, data):
        if message['type'] == 'send':
            payload = message['payload']
            msg_type = payload.get('type')

            if msg_type == 'info':
                print(f"[Frida] {payload.get('msg')}")

            elif msg_type == 'probe-hit':
                ascii_preview = payload.get('ascii_preview', '')

                # Check if comment request
                if 'snscomment' in ascii_preview.lower() or 'mmsnscomment' in ascii_preview.lower():
                    capture = {
                        'timestamp': datetime.now().isoformat(),
                        'tag': payload.get('tag', ''),
                        'size': payload.get('size', 0),
                        'ascii_preview': ascii_preview,
                        'hex_preview': payload.get('hex_preview', ''),
                        'backtrace': payload.get('backtrace', []),
                    }

                    with self.lock:
                        idx = len(self.comment_requests) + 1
                        self.comment_requests.append(capture)

                        # Save individual capture
                        filepath = CAPTURE_DIR / f"hook_comment_{idx:02d}.json"
                        with open(filepath, 'w', encoding='utf-8') as f:
                            json.dump(capture, f, indent=2, ensure_ascii=False)

                    print(f"\n[CAPTURED #{idx}] Comment HTTP request ({capture['size']} bytes)")
                    print(f"             Saved to: {filepath.name}")

    def start(self):
        print("[*] Attaching Frida to Weixin.exe...")
        self.session = frida.attach("Weixin.exe")
        print(f"[*] Attached to PID {self.session._impl.pid}")

        script_path = Path("examples/frida_wsasend_probe.js")
        script_code = script_path.read_text(encoding='utf-8')

        self.script = self.session.create_script(script_code)
        self.script.on('message', self.on_message)
        self.script.load()

        print("[*] Frida hooks installed\n")
        time.sleep(1)  # Let hooks stabilize

    def stop(self):
        if self.script:
            self.script.unload()
        if self.session:
            self.session.detach()

    def get_count(self):
        with self.lock:
            return len(self.comment_requests)

    def save_summary(self):
        with self.lock:
            summary = {
                'total_captures': len(self.comment_requests),
                'timestamp': datetime.now().isoformat(),
                'captures': self.comment_requests,
            }

        summary_path = CAPTURE_DIR / f"hook_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(summary_path, 'w', encoding='utf-8') as f:
            json.dump(summary, f, indent=2, ensure_ascii=False)

        print(f"\n[*] Summary saved: {summary_path}")
        return summary


def send_comments_via_hook(sns_id, count=10):
    """Send comments using Hook DLL (Serial Mode)."""
    print(f"\n{'='*80}")
    print(f"Sending {count} comments via Hook DLL")
    print(f"{'='*80}\n")

    bridge = HookBridge()
    if not bridge.ping():
        print("[ERROR] Hook bridge connection failed!")
        return 0

    dispatcher = CommentDispatcher(
        hook_bridge=bridge,
        max_concurrency=1,  # Serial mode only
        piggyback_timeout_ms=60000
    )

    comments = [f"HTTP捕获测试 {i+1:02d}" for i in range(count)]

    print(f"[*] Dispatching {count} comments...")
    results = dispatcher.dispatch_batch(
        sns_id=sns_id,
        comments=comments,
        reply_to="",
        backend="real",
        batch_mode="piggyback",
        concurrency=1
    )

    success = results.strict_success_count
    print(f"\n[*] Hook dispatch complete: {success}/{count} successful")
    return success


def main():
    sns_id_str = sys.argv[1] if len(sys.argv) > 1 else None

    if not sns_id_str:
        print("Usage: python examples/capture_via_hook_and_frida.py <sns_id>")
        print("\nExample:")
        print("  python examples/capture_via_hook_and_frida.py 14111111111111111111")
        print("\nTo get sns_id:")
        print("  1. Open WeChat Moments")
        print("  2. Right-click on target post")
        print("  3. Copy link")
        print("  4. Extract the number from URL")
        return 1

    try:
        sns_id = int(sns_id_str)
    except ValueError:
        print(f"[ERROR] Invalid sns_id: {sns_id_str}")
        return 1

    print("\n" + "="*80)
    print("HTTP CAPTURE VIA HOOK + FRIDA")
    print("="*80)
    print(f"SNS ID: {sns_id}")
    print(f"Comments: 10")
    print("="*80 + "\n")

    # Start Frida capture
    capture = FridaCapture()
    try:
        capture.start()
    except Exception as e:
        print(f"[ERROR] Failed to start Frida: {e}")
        return 1

    # Give Frida time to initialize
    time.sleep(2)

    # Send comments via Hook
    try:
        sent_count = send_comments_via_hook(sns_id, count=10)
    except Exception as e:
        print(f"[ERROR] Hook dispatch failed: {e}")
        import traceback
        traceback.print_exc()
        sent_count = 0
    finally:
        # Wait for pending captures
        time.sleep(3)

    # Results
    captured_count = capture.get_count()
    print(f"\n{'='*80}")
    print("RESULTS")
    print(f"{'='*80}")
    print(f"Comments sent (Hook): {sent_count}")
    print(f"HTTP requests captured (Frida): {captured_count}")
    print(f"{'='*80}\n")

    if captured_count == 0:
        print("[WARNING] No HTTP requests captured!")
        print("Possible reasons:")
        print("  1. Hook DLL bypasses network layer (calls CGI directly)")
        print("  2. Requests are buffered/merged")
        print("  3. Different network API used")

    # Save summary
    capture.save_summary()
    capture.stop()

    print(f"\n[*] Output directory: {CAPTURE_DIR}")
    print(f"[*] Captured count: {captured_count}")

    if captured_count > 0:
        print(f"\n[NEXT STEPS]")
        print(f"  1. Analyze captured HTTP requests")
        print(f"  2. Identify request format (headers, protobuf)")
        print(f"  3. Determine if WSASend Hook is feasible")
        return 0
    else:
        print(f"\n[FALLBACK PLAN]")
        print(f"  If Hook bypasses WSASend, we need to:")
        print(f"  1. Hook a higher-level function (protobuf layer)")
        print(f"  2. Or modify Hook DLL to log HTTP requests")
        return 1

if __name__ == "__main__":
    sys.exit(main())
