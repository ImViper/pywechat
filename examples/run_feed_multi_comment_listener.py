"""Multi-Comment Moments Refresh Listener — 多评论队列监听器

支持快速首评 + 队列后续评论的朋友圈监听脚本。

Usage:
    python examples/run_feed_multi_comment_listener.py <publish_time> <target_author> [options]

Examples:
    # 基础模式（OCR + AI）
    python examples/run_feed_multi_comment_listener.py 19:15 小蔡

    # 添加预制话术
    python examples/run_feed_multi_comment_listener.py 19:15 小蔡 --canned "666,厉害,沙发"

    # 启用 OCR 重试
    python examples/run_feed_multi_comment_listener.py 19:15 小蔡 --ocr-retry --max-comments 5

    # 完整配置
    python examples/run_feed_multi_comment_listener.py 19:15 小蔡 ^
        --canned "666,厉害,沙发,第一" ^
        --ocr-retry ^
        --max-comments 5 ^
        --poll-interval 0.5 ^
        --suffix 男
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path

import win32con
import win32gui

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from pyweixin.rush_ai import ArkChatProvider, PaddleOCRProvider
from pyweixin.rush_callback_multi import (
    OCRCommentSource,
    AICommentSource,
    CannedCommentSource,
    OCRRetryCommentSource,
    create_multi_source_streaming_callback,
)
from pyweixin.moments_ext import fetch_and_comment_from_moments_feed
from pyweixin.WeChatTools import Navigator


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
    parser = argparse.ArgumentParser(
        description="Multi-Comment Moments Refresh Listener"
    )
    parser.add_argument("publish_time", help="Expected publish time (HH:MM)")
    parser.add_argument("target_author", help="Target author name")
    parser.add_argument(
        "--poll-interval", type=float, default=0.5, help="Poll interval (seconds)"
    )
    parser.add_argument(
        "--suffix", type=str, default=None, help="Answer suffix (e.g., '男')"
    )
    parser.add_argument(
        "--canned", type=str, default=None, help="Canned comments (comma-separated)"
    )
    parser.add_argument(
        "--ocr-retry", action="store_true", help="Enable OCR retry with alt params"
    )
    parser.add_argument(
        "--max-comments", type=int, default=5, help="Max comments per post (default: 5)"
    )

    args = parser.parse_args()

    publish_time_str = args.publish_time
    target_author = args.target_author
    poll_interval = max(0.2, args.poll_interval)
    answer_suffix = args.suffix
    max_comments = args.max_comments

    # Parse publish time
    try:
        hour, minute = map(int, publish_time_str.split(":"))
        today = datetime.now().date()
        publish_dt = datetime.combine(today, datetime.min.time()).replace(
            hour=hour, minute=minute
        )
        start_dt = publish_dt - timedelta(minutes=2)
        end_dt = publish_dt + timedelta(minutes=5)
    except Exception:
        print(f"Error: invalid time format '{publish_time_str}', expected HH:MM")
        return

    # Load API key
    api_key = load_api_key()
    if not api_key:
        print("Error: missing ARK_API_KEY")
        return

    # Initialize providers
    ai_provider = ArkChatProvider(api_key=api_key)

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
        print("Warning: PaddleOCR unavailable, OCR disabled")

    # Build comment sources
    known_keywords = [
        "百里辞", "楚凭阑", "晋王", "晏如晦", "从嘉", "方驰",
        "耶律洪", "萧寻", "红袖", "胡不医", "顾知意", "赵岚",
    ]

    sources = []

    # Source 1: OCR (priority 0, fastest)
    if ocr_provider:
        sources.append(
            OCRCommentSource(ocr_provider, known_keywords, answer_suffix)
        )

    # Source 2: AI (priority 1)
    if ai_provider:
        sources.append(AICommentSource(ai_provider))

    # Source 3: Canned comments (priority 2, instant)
    if args.canned:
        canned_list = [c.strip() for c in args.canned.split(",") if c.strip()]
        if canned_list:
            sources.append(CannedCommentSource(canned_list, max_select=2))

    # Source 4: OCR retry (priority 3)
    if args.ocr_retry and ocr_provider:
        retry_params = {"text_det_limit_side_len": 1600}  # 更高分辨率
        sources.append(
            OCRRetryCommentSource(ocr_provider, retry_params, known_keywords)
        )

    if not sources:
        print("Error: no comment sources available")
        return

    # Create multi-source callback
    ai_callback = create_multi_source_streaming_callback(
        sources=sources,
        max_comments=max_comments,
        dedup=True,
        verbose=True,
    )

    # Output directory
    output_dir = f"rush_moments_cache_feed_{target_author}_multi"
    state_file = f"rush_state_feed_{target_author}_multi.json"
    os.makedirs(output_dir, exist_ok=True)

    # Filter keywords
    include_keywords = ["题目", "抢答", "图中", "多少", "几个", "几位"]
    exclude_keywords = ["无效", "取消"]

    # Print config
    print("=" * 60)
    print("Multi-Comment Moments Refresh Listener")
    print("=" * 60)
    print(f"Target author: {target_author}")
    print(f"Publish time:  {publish_dt.strftime('%Y-%m-%d %H:%M')}")
    print(f"Monitor start: {start_dt.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Monitor end:   {end_dt.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Poll interval: {poll_interval:.2f}s")
    print(f"Max comments:  {max_comments}")
    print(f"Comment sources: {[s.__class__.__name__ for s in sources]}")
    print(f"Output dir:    {output_dir}")
    print("=" * 60)

    # Load state
    state = {}
    if os.path.exists(state_file):
        try:
            with open(state_file, "r", encoding="utf-8") as f:
                state = json.load(f)
        except Exception:
            state = {}

    def save_state():
        with open(state_file, "w", encoding="utf-8") as f:
            json.dump(state, f, ensure_ascii=False, indent=2)

    # Check if already commented
    already_commented = bool(state.get("commented", False))
    force_reset = os.getenv("PYWEIXIN_FORCE_RESET_COMMENTED", "1").strip().lower() in {
        "1", "true", "yes"
    }

    if already_commented:
        if force_reset:
            print("Already commented in previous state, force reset enabled")
            already_commented = False
            state["commented"] = False
            save_state()
        else:
            print("Already commented in previous state, stop to avoid duplicate")
            print("Set PYWEIXIN_FORCE_RESET_COMMENTED=1 to continue anyway")
            return

    # Set environment for fast_first_batch mode
    os.environ["PYWEIXIN_HOOK_ENABLED"] = "1"
    os.environ["PYWEIXIN_HOOK_BATCH_MODE"] = "fast_first_batch"
    os.environ["PYWEIXIN_HOOK_MAX_CONCURRENCY"] = "1"  # Serial Mode

    loops = 0
    last_fingerprint = state.get("last_fingerprint", "")
    commented_this_run = False
    moments_window = None

    try:
        while True:
            now = datetime.now()

            # Time window check
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

            # Open moments window
            if moments_window is None:
                try:
                    moments_window = Navigator.open_moments(
                        is_maximize=False, close_weixin=False
                    )
                    try:
                        win32gui.SendMessage(
                            moments_window.handle, win32con.WM_SYSCOMMAND,
                            win32con.SC_MAXIMIZE, 0
                        )
                    except Exception:
                        pass
                    print(f"[{now.strftime('%H:%M:%S')}] opened moments window")
                except Exception as exc:
                    print(f"[{now.strftime('%H:%M:%S')}] open moments failed: {exc}")
                    time.sleep(poll_interval)
                    continue

            # Fetch and comment
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

            # Handle result
            if not result.get("success"):
                print(f"[{now.strftime('%H:%M:%S')}] fetch failed: {result.get('error', 'unknown')}")
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
            print(f"[{now.strftime('%H:%M:%S')}] author={author} content={preview}")

            # Check if commented
            if result.get("ai_answer"):
                if not result.get("comment_attempted"):
                    print(f"[{now.strftime('%H:%M:%S')}] answer ready but comment not attempted, retry")
                    if moments_window is not None:
                        try:
                            moments_window.close()
                        except Exception:
                            pass
                    moments_window = None
                    time.sleep(poll_interval)
                    continue

                # Success
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
                    print(f"Posted comments: {result.get('ai_answer')}")
                else:
                    print(f"Attempted comments: {result.get('ai_answer')} (status unknown)")
                print("=" * 60)
                break

            # No new post
            if fingerprint == last_fingerprint:
                print(f"[{now.strftime('%H:%M:%S')}] no new post")
                time.sleep(poll_interval)
                continue

            # Update state
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
        import traceback
        traceback.print_exc()
    finally:
        # Keep window open after comment
        hold_window = commented_this_run
        if hold_window and moments_window is not None:
            print("\nMoments window kept open for inspection")
        elif moments_window is not None:
            try:
                moments_window.close()
            except Exception:
                pass

    print("\nMonitoring finished")
    print(f"Final state: {state}")


if __name__ == "__main__":
    main()
