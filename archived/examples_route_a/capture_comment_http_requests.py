"""
Capture HTTP requests when sending WeChat Moments comments.

Usage:
1. python examples/capture_comment_http_requests.py
2. Manually send a comment in WeChat Moments
3. Script will capture and analyze the HTTP request
4. Repeat 10 times to collect samples

Output: local_workspace/http_captures/comment_request_{timestamp}.json
"""

import frida
import sys
import time
import json
from pathlib import Path
from datetime import datetime

# Output directory
CAPTURE_DIR = Path("local_workspace/http_captures")
CAPTURE_DIR.mkdir(parents=True, exist_ok=True)

class CommentHTTPCapturer:
    def __init__(self):
        self.session = None
        self.script = None
        self.captures = []
        self.sample_count = 0

    def on_message(self, message, data):
        if message['type'] == 'send':
            payload = message['payload']
            msg_type = payload.get('type')

            if msg_type == 'info':
                print(f"[INFO] {payload.get('msg')}")

            elif msg_type == 'probe-hit':
                # Found interesting request
                tag = payload.get('tag', '')
                size = payload.get('size', 0)
                ascii_preview = payload.get('ascii_preview', '')
                hex_preview = payload.get('hex_preview', '')
                backtrace = payload.get('backtrace', [])

                print(f"\n{'='*80}")
                print(f"[HIT] {tag} - Size: {size} bytes")
                print(f"ASCII Preview:\n{ascii_preview}")
                print(f"\nHex Preview (first 256 bytes):")
                print(hex_preview[:512])
                print(f"\nBacktrace:")
                for i, frame in enumerate(backtrace[:5]):
                    print(f"  {i}: {frame}")
                print(f"{'='*80}\n")

                # Save capture
                capture = {
                    'timestamp': datetime.now().isoformat(),
                    'tag': tag,
                    'size': size,
                    'ascii_preview': ascii_preview,
                    'hex_preview': hex_preview,
                    'backtrace': backtrace,
                }
                self.captures.append(capture)

                # Check if this is a comment request
                if 'snscomment' in ascii_preview.lower() or 'mmsnscomment' in ascii_preview.lower():
                    print("[COMMENT DETECTED] This looks like a comment request!")
                    self.save_capture(capture)

            elif msg_type == 'probe-sample':
                # Background sample (not interesting)
                pass

    def save_capture(self, capture):
        """Save capture to JSON file."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        filepath = CAPTURE_DIR / f"comment_request_{timestamp}.json"

        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(capture, f, indent=2, ensure_ascii=False)

        print(f"[SAVED] Capture saved to {filepath}")
        self.sample_count += 1

    def attach_and_run(self, process_name="Weixin.exe"):
        """Attach to WeChat and start capturing."""
        print(f"[*] Attaching to {process_name}...")

        try:
            session = frida.attach(process_name)
        except frida.ProcessNotFoundError:
            print(f"[ERROR] Process '{process_name}' not found!")
            print("Please start WeChat first.")
            sys.exit(1)

        print(f"[*] Attached to PID {session._impl.pid}")

        # Load Frida script
        script_path = Path("examples/frida_wsasend_probe.js")
        if not script_path.exists():
            print(f"[ERROR] Script not found: {script_path}")
            sys.exit(1)

        print(f"[*] Loading script: {script_path}")
        script_code = script_path.read_text(encoding='utf-8')

        script = session.create_script(script_code)
        script.on('message', self.on_message)
        script.load()

        self.session = session
        self.script = script

        print("\n" + "="*80)
        print("READY TO CAPTURE")
        print("="*80)
        print("Instructions:")
        print("1. Open WeChat Moments")
        print("2. Find any post")
        print("3. Send a comment")
        print("4. Repeat 10 times with different comments")
        print("5. Press Ctrl+C when done")
        print("="*80 + "\n")

        try:
            while True:
                time.sleep(0.5)

                # Print status every 30 seconds
                if int(time.time()) % 30 == 0:
                    print(f"[STATUS] Captured {self.sample_count} comment requests so far...")

        except KeyboardInterrupt:
            print("\n\n[*] Stopping capture...")
            print(f"[*] Total captures: {len(self.captures)}")
            print(f"[*] Comment requests: {self.sample_count}")

            # Save summary
            summary_path = CAPTURE_DIR / f"capture_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            summary = {
                'total_captures': len(self.captures),
                'comment_requests': self.sample_count,
                'captures': self.captures,
            }
            with open(summary_path, 'w', encoding='utf-8') as f:
                json.dump(summary, f, indent=2, ensure_ascii=False)
            print(f"[*] Summary saved to {summary_path}")

        finally:
            if self.script:
                self.script.unload()
            if self.session:
                self.session.detach()

def main():
    capturer = CommentHTTPCapturer()
    capturer.attach_and_run()

if __name__ == "__main__":
    main()
