"""Global moments refresh listener (persistent window mode)."""

from __future__ import annotations

import json
import os
import re
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path

import win32con
import win32gui

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from pyweixin.rush_ai import ArkChatProvider, PaddleOCRProvider


def load_api_key() -> str:
    """Load ARK API key from local config or environment."""
    key_file = PROJECT_ROOT / "config" / ".local_secrets.json"
    if key_file.exists():
        try:
            with open(key_file, "r", encoding="utf-8-sig") as f:
                data = json.load(f)
                return str(data.get("ARK_API_KEY", ""))
        except Exception as exc:
            print(f"Warning: failed to read {key_file}: {exc}")
    return os.getenv("ARK_API_KEY", "")


def main() -> None:
    if len(sys.argv) < 3:
        print("Usage: python examples/run_feed_refresh_listener.py <publish_time_HH:MM> <target_author> [poll_interval_sec] [--suffix 男]")
        print("Example: python examples/run_feed_refresh_listener.py 19:15 小蔡")
        print("Example: python examples/run_feed_refresh_listener.py 19:15 小蔡 0.5")
        print("Example: python examples/run_feed_refresh_listener.py 19:15 小蔡 0.5 --suffix 男  (拼车模式)")
        return

    publish_time_str = sys.argv[1]
    target_author = sys.argv[2]

    # Parse --suffix from anywhere in argv
    answer_suffix = None
    filtered_argv = []
    i = 3
    while i < len(sys.argv):
        if sys.argv[i] == "--suffix" and i + 1 < len(sys.argv):
            answer_suffix = sys.argv[i + 1]
            i += 2
        else:
            filtered_argv.append(sys.argv[i])
            i += 1

    poll_interval = 0.5
    if filtered_argv:
        try:
            poll_interval = float(filtered_argv[0])
        except Exception:
            print(f"Warning: invalid poll interval '{filtered_argv[0]}', fallback to 0.5s")
            poll_interval = 0.5
    poll_interval = max(0.2, poll_interval)

    try:
        hour, minute = map(int, publish_time_str.split(":"))
        today = datetime.now().date()
        publish_dt = datetime.combine(today, datetime.min.time()).replace(hour=hour, minute=minute)
        start_dt = publish_dt - timedelta(minutes=2)
        end_dt = publish_dt + timedelta(minutes=5)
    except Exception:
        print(f"Error: invalid time format '{publish_time_str}', expected HH:MM")
        return

    api_key = load_api_key()
    if not api_key:
        print("Error: missing ARK_API_KEY")
        print("Set config/.local_secrets.json or environment variable ARK_API_KEY")
        return

    ai_provider = ArkChatProvider(api_key=api_key)
    compare_with_ai_after_ocr_hit = os.getenv("PYWEIXIN_COMPARE_AI_AFTER_OCR_HIT", "").strip().lower() in {
        "1",
        "true",
        "yes",
    }
    force_reset_commented_state = os.getenv("PYWEIXIN_FORCE_RESET_COMMENTED", "1").strip().lower() in {
        "1",
        "true",
        "yes",
    }

    ocr_provider = None
    try:
        print("Loading OCR model...")
        ocr_provider = PaddleOCRProvider(
            lang="ch",
            show_log=False,
            use_angle_cls=False,
            enable_mkldnn=False,
            text_detection_model_name=os.getenv("PYWEIXIN_OCR_DET_MODEL", "PP-OCRv5_mobile_det"),
            text_recognition_model_name=os.getenv("PYWEIXIN_OCR_REC_MODEL", "PP-OCRv5_mobile_rec"),
            cpu_threads=int(os.getenv("PYWEIXIN_OCR_CPU_THREADS", "8")),
            text_det_limit_side_len=int(os.getenv("PYWEIXIN_OCR_MAX_SIDE", "1200")),
            text_det_limit_type=os.getenv("PYWEIXIN_OCR_LIMIT_TYPE", "max"),
        )
        ocr_provider._get_ocr()
        print("OCR model loaded")
    except Exception:
        ocr_provider = None
        print("Warning: PaddleOCR unavailable, OCR assist disabled")

    output_dir = f"rush_moments_cache_feed_{target_author}"
    state_file = f"rush_state_feed_{target_author}.json"
    include_keywords = [
        "\u9898\u76ee",
        "\u62a2\u7b54",
        "\u56fe\u4e2d",
        "\u591a\u5c11",
        "\u51e0\u4e2a",
        "\u51e0\u4f4d",
    ]
    exclude_keywords = ["\u65e0\u6548", "\u53d6\u6d88"]
    os.makedirs(output_dir, exist_ok=True)
    hold_window_after_comment = True

    print("=" * 60)
    print("Global Moments Refresh Listener (persistent window)")
    print("=" * 60)
    print(f"Target author: {target_author}")
    print(f"Publish time:  {publish_dt.strftime('%Y-%m-%d %H:%M')}")
    print(f"Monitor start: {start_dt.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Monitor end:   {end_dt.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Poll interval: {poll_interval:.2f}s")
    print(f"Output dir:    {output_dir}")
    if answer_suffix:
        print(f"Mode:          拼车模式 (suffix={answer_suffix})")
    print("=" * 60)

    state: dict = {}
    if os.path.exists(state_file):
        try:
            with open(state_file, "r", encoding="utf-8") as f:
                state = json.load(f)
        except Exception:
            state = {}

    def save_state() -> None:
        with open(state_file, "w", encoding="utf-8") as f:
            json.dump(state, f, ensure_ascii=False, indent=2)

    # Use streaming callback: answers are pushed to a queue as they arrive (OCR first)
    from pyweixin.rush_callback import create_streaming_callback

    # Known character/item names for OCR keyword matching (fallback when no quotes in question)
    known_keywords = [
        "百里辞", "楚凭阑", "晋王", "晏如晦", "从嘉", "方驰",
        "耶律洪", "萧寻", "红袖", "胡不医", "顾知意", "赵岚",
    ]

    ai_callback = create_streaming_callback(
        ocr_provider=ocr_provider,
        ai_provider=ai_provider,
        verbose=True,
        known_keywords=known_keywords,
        answer_suffix=answer_suffix,
    )


    from pyweixin.moments_ext import fetch_and_comment_from_moments_feed
    from pyweixin.WeChatTools import Navigator

    loops = 0
    last_fingerprint = state.get("last_fingerprint", "")
    already_commented = bool(state.get("commented", False))
    commented_this_run = False
    moments_window = None

    if already_commented:
        if force_reset_commented_state:
            print("Already commented in previous state, force reset enabled")
            already_commented = False
            state["commented"] = False
            save_state()
        else:
            print("Already commented in previous state, stop to avoid duplicate comments")
            print("Set PYWEIXIN_FORCE_RESET_COMMENTED=1 to continue anyway")
            return

    try:
        while True:
            now = datetime.now()

            if now < start_dt:
                wait = min(poll_interval, (start_dt - now).total_seconds())
                time.sleep(wait)
                continue

            if now > end_dt:
                print(f"[{now.strftime('%H:%M:%S')}] monitoring window ended")
                break

            if already_commented:
                print(f"[{now.strftime('%H:%M:%S')}] already commented, exit")
                break

            loops += 1
            print(f"[{now.strftime('%H:%M:%S')}] poll #{loops}")

            if moments_window is None:
                try:
                    moments_window = Navigator.open_moments(is_maximize=False, close_weixin=False)
                    try:
                        win32gui.SendMessage(moments_window.handle, win32con.WM_SYSCOMMAND, win32con.SC_MAXIMIZE, 0)
                    except Exception:
                        pass
                    print(f"[{now.strftime('%H:%M:%S')}] opened moments window")
                except Exception as exc:
                    print(f"[{now.strftime('%H:%M:%S')}] open moments failed: {exc}")
                    time.sleep(poll_interval)
                    continue

            result = fetch_and_comment_from_moments_feed(
                target_author=target_author,
                ai_callback=ai_callback,
                target_folder=output_dir,
                is_maximize=True,
                close_weixin=False,
                include_keywords=include_keywords,
                exclude_keywords=exclude_keywords,
                last_fingerprint=last_fingerprint,
                refresh_first=True,
                moments_window=moments_window,
            )

            if not result.get("success"):
                print(f"[{now.strftime('%H:%M:%S')}] fetch failed: {result.get('error', 'unknown error')}")
                if result.get("error"):
                    if moments_window is not None:
                        try:
                            moments_window.close()
                        except Exception:
                            pass
                    moments_window = None
                time.sleep(poll_interval)
                continue

            fingerprint = str(result.get("fingerprint", ""))
            content = str(result.get("content", ""))
            author = str(result.get("author", ""))
            preview = (content[:60] + "...") if content else "(empty)"
            print(f"[{now.strftime('%H:%M:%S')}] author={author or '(unknown)'} content={preview}")

            if result.get("ai_answer"):
                if (not bool(result.get("comment_attempted"))) and (not bool(result.get("comment_posted"))):
                    print(
                        f"[{now.strftime('%H:%M:%S')}] ai answered but comment flow did not start, retrying"
                    )
                    if result.get("error"):
                        print(f"[{now.strftime('%H:%M:%S')}] reason: {result.get('error')}")
                    if moments_window is not None:
                        try:
                            moments_window.close()
                        except Exception:
                            pass
                    moments_window = None
                    time.sleep(poll_interval)
                    continue

                last_fingerprint = fingerprint
                state["last_fingerprint"] = fingerprint
                state["commented"] = True
                commented_this_run = True
                state["comment_text"] = str(result.get("ai_answer"))
                state["comment_time"] = now.isoformat()
                state["comment_posted"] = bool(result.get("comment_posted"))
                save_state()
                print("=" * 60)
                if result.get("comment_posted"):
                    print(f"Posted comment: {result.get('ai_answer')}")
                else:
                    print(f"Attempted comment: {result.get('ai_answer')} (post status unknown)")
                print("=" * 60)
                break

            if fingerprint == last_fingerprint:
                print(f"[{now.strftime('%H:%M:%S')}] no new post")
                time.sleep(poll_interval)
                continue

            last_fingerprint = fingerprint
            state["last_fingerprint"] = fingerprint
            state["last_author"] = author
            state["last_content"] = content[:100] if content else ""
            state["last_time"] = now.isoformat()
            save_state()
            time.sleep(poll_interval)

    except KeyboardInterrupt:
        print("\nInterrupted by user")
    except Exception as exc:
        print(f"\nError: {exc}")
    finally:
        should_hold_open = hold_window_after_comment and commented_this_run
        if should_hold_open and moments_window is not None:
            print("\nMoments window is intentionally kept open for inspection")
        elif moments_window is not None:
            try:
                moments_window.close()
            except Exception:
                pass

    print("\nMonitoring finished")
    print(f"Final state: {state}")


if __name__ == "__main__":
    main()
