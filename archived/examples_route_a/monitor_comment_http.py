"""
Simple HTTP request monitor for WeChat.
Captures HTTP requests when you MANUALLY send comments.

Usage:
1. python examples/monitor_comment_http.py
2. Script will start capturing
3. YOU manually open WeChat Moments and send comments
4. Press Ctrl+C when done

Output: local_workspace/http_captures/
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

comment_count = 0
all_captures = []

def on_message(message, data):
    """Handle Frida messages."""
    global comment_count, all_captures

    if message['type'] == 'send':
        payload = message['payload']
        msg_type = payload.get('type')

        if msg_type == 'info':
            print(f"[INFO] {payload.get('msg')}")

        elif msg_type == 'probe-hit':
            tag = payload.get('tag', '')
            size = payload.get('size', 0)
            ascii_preview = payload.get('ascii_preview', '')
            hex_preview = payload.get('hex_preview', '')
            backtrace = payload.get('backtrace', [])

            capture = {
                'timestamp': datetime.now().isoformat(),
                'tag': tag,
                'size': size,
                'ascii_preview': ascii_preview,
                'hex_preview': hex_preview,
                'backtrace': backtrace,
            }

            all_captures.append(capture)

            # Check if this is a comment request
            ascii_lower = ascii_preview.lower()
            if 'snscomment' in ascii_lower or 'mmsnscomment' in ascii_lower:
                comment_count += 1
                print(f"\n{'='*80}")
                print(f"[COMMENT #{comment_count}] HTTP Request Captured!")
                print(f"{'='*80}")
                print(f"Size: {size} bytes")
                print(f"\nASCII Preview (first 200 chars):")
                print(ascii_preview[:200])
                print(f"\nHex Preview (first 256 bytes):")
                print(hex_preview[:512])
                print(f"\nBacktrace (top 5 frames):")
                for i, frame in enumerate(backtrace[:5]):
                    print(f"  {i}: {frame}")
                print(f"{'='*80}\n")

                # Save to file
                filepath = CAPTURE_DIR / f"comment_{comment_count:02d}_{datetime.now().strftime('%H%M%S')}.json"
                with open(filepath, 'w', encoding='utf-8') as f:
                    json.dump(capture, f, indent=2, ensure_ascii=False)
                print(f"[SAVED] {filepath}\n")

def main():
    print("\n" + "="*80)
    print("HTTP REQUEST MONITOR FOR WECHAT MOMENTS COMMENTS")
    print("="*80)
    print("Instructions:")
    print("1. This script will capture HTTP requests")
    print("2. YOU need to manually send comments in WeChat Moments")
    print("3. Capture at least 10 comments with different content")
    print("4. Press Ctrl+C when done")
    print("="*80 + "\n")

    # Attach to WeChat
    print("[*] Attaching to Weixin.exe...")
    try:
        session = frida.attach("Weixin.exe")
    except frida.ProcessNotFoundError:
        print("[ERROR] WeChat (Weixin.exe) is not running!")
        print("Please start WeChat first.")
        return 1

    print(f"[*] Attached to PID {session._impl.pid}")

    # Load Frida script
    script_path = Path("examples/frida_wsasend_probe.js")
    if not script_path.exists():
        print(f"[ERROR] Script not found: {script_path}")
        return 1

    print(f"[*] Loading script: {script_path}")
    script_code = script_path.read_text(encoding='utf-8')

    script = session.create_script(script_code)
    script.on('message', on_message)
    script.load()

    print("\n" + "="*80)
    print("READY TO CAPTURE!")
    print("="*80)
    print("Now YOU can:")
    print("1. Open WeChat Moments")
    print("2. Find any post")
    print("3. Send a comment (e.g., '测试1')")
    print("4. Wait for capture confirmation")
    print("5. Repeat 10 times with different comments")
    print("\nPress Ctrl+C when done capturing...")
    print("="*80 + "\n")

    try:
        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        print("\n\n[*] Stopping capture...")
        print(f"[*] Total comment requests captured: {comment_count}")

        # Save summary
        summary_path = CAPTURE_DIR / f"summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        summary = {
            'total_captures': len(all_captures),
            'comment_requests': comment_count,
            'timestamp': datetime.now().isoformat(),
            'captures': all_captures,
        }
        with open(summary_path, 'w', encoding='utf-8') as f:
            json.dump(summary, f, indent=2, ensure_ascii=False)

        print(f"[*] Summary saved to: {summary_path}")
        print(f"\n[*] Next steps:")
        print(f"    1. Analyze captured requests in: {CAPTURE_DIR}")
        print(f"    2. Look for HTTP headers, protobuf patterns")
        print(f"    3. Identify if requests can be replayed")

    finally:
        script.unload()
        session.detach()

    return 0

if __name__ == "__main__":
    sys.exit(main())
