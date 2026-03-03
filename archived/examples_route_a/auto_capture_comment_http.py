"""
Automated HTTP request capture for WeChat Moments comments.

This script:
1. Starts Frida to hook WSASend
2. Uses UI automation to send 10 comments
3. Captures all HTTP requests
4. Analyzes the request format

Usage:
    python examples/auto_capture_comment_http.py [target_name]
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

import pyautogui
from pyweixin.WeChatTools import Tools, Navigator, Lists
from pyweixin.moments_ext import comment_flow, open_comment_editor, paste_and_send_comment

# Output directory
CAPTURE_DIR = Path("local_workspace/http_captures")
CAPTURE_DIR.mkdir(parents=True, exist_ok=True)


def locate_target_item(moments_window, target_author, max_scan=10):
    """Find a Moments post from the specified author."""
    moments_list = moments_window.child_window(**Lists.MomentsList)
    try:
        moments_list.set_focus()
    except Exception:
        pass

    try:
        moments_list.type_keys("{HOME}")
    except Exception:
        pyautogui.press("home")
    time.sleep(0.1)

    skip_class_tokens = ("TimelineCommentCell", "TimelineCell", "TimelineAdGridImageCell")

    for i in range(max_scan):
        try:
            moments_list.type_keys("{DOWN}", pause=0.05)
        except Exception:
            pyautogui.press("down")

        try:
            focused = [li for li in moments_list.children(control_type="ListItem") if li.has_keyboard_focus()]
        except Exception:
            continue

        if not focused:
            continue

        item = focused[0]
        try:
            cls_name = item.class_name()
        except Exception:
            cls_name = ""

        if any(tok in cls_name for tok in skip_class_tokens):
            continue

        try:
            text = item.window_text()
        except Exception:
            continue

        if target_author and target_author in text:
            return item, i, text, moments_list

    return None, -1, "", None

class HTTPCaptureSession:
    """Manages Frida session for capturing HTTP requests."""

    def __init__(self):
        self.session = None
        self.script = None
        self.captures = []
        self.comment_requests = []
        self.lock = threading.Lock()
        self.running = False

    def on_message(self, message, data):
        """Handle Frida messages."""
        if message['type'] == 'send':
            payload = message['payload']
            msg_type = payload.get('type')

            if msg_type == 'info':
                print(f"[Frida] {payload.get('msg')}")

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

                with self.lock:
                    self.captures.append(capture)

                # Check if this is a comment request
                ascii_lower = ascii_preview.lower()
                if 'snscomment' in ascii_lower or 'mmsnscomment' in ascii_lower:
                    print(f"\n[CAPTURED] Comment HTTP request detected! Size: {size} bytes")
                    print(f"Preview: {ascii_preview[:100]}...")

                    with self.lock:
                        self.comment_requests.append(capture)
                        self._save_capture(capture, len(self.comment_requests))

    def _save_capture(self, capture, index):
        """Save individual capture to file."""
        filepath = CAPTURE_DIR / f"comment_request_{index:02d}.json"
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(capture, f, indent=2, ensure_ascii=False)
        print(f"[SAVED] {filepath}")

    def start(self, process_name="Weixin.exe"):
        """Start Frida session."""
        print(f"[*] Attaching Frida to {process_name}...")

        try:
            self.session = frida.attach(process_name)
        except frida.ProcessNotFoundError:
            print(f"[ERROR] Process '{process_name}' not found!")
            return False

        print(f"[*] Attached to PID {self.session._impl.pid}")

        # Load script
        script_path = Path("examples/frida_wsasend_probe.js")
        script_code = script_path.read_text(encoding='utf-8')

        self.script = self.session.create_script(script_code)
        self.script.on('message', self.on_message)
        self.script.load()

        self.running = True
        print("[*] Frida capture started\n")
        return True

    def stop(self):
        """Stop Frida session."""
        if self.script:
            self.script.unload()
        if self.session:
            self.session.detach()
        self.running = False

    def get_comment_count(self):
        """Get number of captured comment requests."""
        with self.lock:
            return len(self.comment_requests)

    def save_summary(self):
        """Save capture summary."""
        summary_path = CAPTURE_DIR / f"summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

        with self.lock:
            summary = {
                'total_captures': len(self.captures),
                'comment_requests': len(self.comment_requests),
                'timestamp': datetime.now().isoformat(),
                'captures': self.captures,
            }

        with open(summary_path, 'w', encoding='utf-8') as f:
            json.dump(summary, f, indent=2, ensure_ascii=False)

        print(f"\n[*] Summary saved: {summary_path}")
        print(f"[*] Total captures: {summary['total_captures']}")
        print(f"[*] Comment requests: {summary['comment_requests']}")

        return summary


def send_test_comments(target_name, count=10):
    """Send test comments using UI automation."""
    print(f"\n{'='*80}")
    print(f"Starting UI automation to send {count} comments")
    print(f"{'='*80}\n")

    # Open Moments
    print("[1/4] Opening Moments...")
    moments_window = Navigator.open_moments(is_maximize=True)

    if not moments_window:
        print("[ERROR] Failed to open Moments window")
        return 0

    time.sleep(2)

    # Locate target post
    print(f"[2/4] Locating post from '{target_name}'...")
    content_item, scan_idx, text_preview, moments_list = locate_target_item(
        moments_window,
        target_author=target_name,
        max_scan=15
    )

    if not content_item:
        print(f"[ERROR] Could not find post from '{target_name}'")
        return 0

    print(f"[3/4] Found target post at index {scan_idx}")
    print(f"     Preview: {text_preview[:60]}...")

    success_count = 0

    for i in range(count):
        comment_text = f"HTTP捕获测试 {i+1:02d}"

        try:
            print(f"\n[{i+1}/{count}] Sending comment: '{comment_text}'")

            # Open comment editor
            opened = open_comment_editor(
                moments_window,
                content_item,
                use_offset_fix=False,
                pre_move_coords=(283, 696)
            )

            if not opened:
                print(f"[{i+1}/{count}] ERROR: Failed to open comment editor")
                time.sleep(1)
                continue

            # Send comment (this triggers HTTP request)
            ok = paste_and_send_comment(
                moments_window,
                text=comment_text,
                anchor_mode="list",
                anchor_source=moments_list,
                clear_first=True,
                skip_editor_check=False
            )

            if ok:
                print(f"[{i+1}/{count}] ✓ Comment sent successfully")
                success_count += 1
            else:
                print(f"[{i+1}/{count}] ✗ Failed to send comment")

            # Wait between comments
            time.sleep(1.5)

        except Exception as e:
            print(f"[{i+1}/{count}] ERROR: {e}")
            continue

    print(f"\n[4/4] Comment sequence complete: {success_count}/{count} successful")
    return success_count


def main():
    target_name = sys.argv[1] if len(sys.argv) > 1 else "小蔡"
    comment_count = 10

    print("\n" + "="*80)
    print("AUTOMATED HTTP CAPTURE FOR WECHAT MOMENTS COMMENTS")
    print("="*80)
    print(f"Target: {target_name}")
    print(f"Comment count: {comment_count}")
    print("="*80 + "\n")

    # Start Frida capture
    capture = HTTPCaptureSession()
    if not capture.start():
        print("[ERROR] Failed to start Frida capture")
        return 1

    # Give Frida time to initialize hooks
    time.sleep(2)

    try:
        # Send comments via UI automation
        sent_count = send_test_comments(target_name, comment_count)

        # Wait a bit for any pending captures
        print("\n[*] Waiting for pending captures...")
        time.sleep(3)

        # Check results
        captured_count = capture.get_comment_count()
        print(f"\n{'='*80}")
        print("CAPTURE RESULTS")
        print(f"{'='*80}")
        print(f"Comments sent: {sent_count}")
        print(f"HTTP requests captured: {captured_count}")
        print(f"{'='*80}\n")

        if captured_count == 0:
            print("[WARNING] No comment HTTP requests were captured!")
            print("Possible reasons:")
            print("1. Comments were sent too fast (requests merged)")
            print("2. Frida hook didn't work properly")
            print("3. WeChat uses a different network API")
            print("\nCheck the summary file for all captured traffic.")

        # Save summary
        summary = capture.save_summary()

        return 0 if captured_count > 0 else 1

    finally:
        capture.stop()
        print("[*] Frida capture stopped")


if __name__ == "__main__":
    sys.exit(main())
