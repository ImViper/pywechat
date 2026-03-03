"""One-click friend moments monitor and auto-reply test runner."""

from __future__ import annotations

import json
import os
import re
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
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
    if len(sys.argv) < 2:
        print("Usage: python start_test.py <publish_time_HH:MM> [friend_remark]")
        print("Example: python start_test.py 19:15")
        print("Example: python start_test.py 19:15 小蔡")
        return

    publish_time_str = sys.argv[1]
    friend_remark = sys.argv[2] if len(sys.argv) > 2 else "\u5c0f\u8521"

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
    force_reset_commented_state = os.getenv("PYWEIXIN_FORCE_RESET_COMMENTED", "").strip().lower() in {
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

    output_dir = f"rush_moments_cache_test_{friend_remark}"
    state_file = f"rush_state_test_{friend_remark}.json"
    include_keywords = [
        "\u9898\u76ee",
        "\u62a2\u7b54",
        "\u56fe\u4e2d",
        "\u591a\u5c11",
        "\u51e0\u4e2a",
        "\u51e0\u4f4d",
    ]
    exclude_keywords = ["\u65e0\u6548", "\u53d6\u6d88"]
    poll_interval = 1.0

    os.makedirs(output_dir, exist_ok=True)

    print("=" * 60)
    print("Friend Moments Auto-Reply (single-open flow)")
    print("=" * 60)
    print(f"Target friend: {friend_remark}")
    print(f"Publish time: {publish_dt.strftime('%Y-%m-%d %H:%M')}")
    print(f"Monitor start: {start_dt.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Monitor end:   {end_dt.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Output dir:    {output_dir}")
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

    # Use concurrent callback for parallel OCR+AI with dual commenting
    from pyweixin.rush_callback import create_concurrent_callback

    concurrent_cb = create_concurrent_callback(
        ocr_provider=ocr_provider,
        ai_provider=ai_provider,
        verbose=True,
    )

    def ai_callback(content: str, image_paths: list[str]) -> list[str] | str | None:
        """Wrapper that calls concurrent callback and returns unique answers as list."""
        results = concurrent_cb(content, image_paths)
        if not results:
            return None
        
        # Deduplicate answers while preserving order (fastest first)
        seen = set()
        unique_answers = []
        for r in results:
            if r.answer not in seen:
                seen.add(r.answer)
                unique_answers.append(r.answer)
        
        if not unique_answers:
            return None
        if len(unique_answers) == 1:
            return unique_answers[0]
        
        # Multiple different answers: return all for dual commenting
        print(f"[dual] posting {len(unique_answers)} different answers: {unique_answers}")
        return unique_answers


    from pyweixin.WeChatAuto import Moments

    loops = 0
    last_fingerprint = state.get("last_fingerprint", "")
    already_commented = bool(state.get("commented", False))

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

            result = Moments.fetch_and_comment_friend_moment(
                friend=friend_remark,
                ai_callback=ai_callback,
                target_folder=output_dir,
                is_maximize=True,
                close_weixin=False,
                include_keywords=include_keywords,
                exclude_keywords=exclude_keywords,
                last_fingerprint=last_fingerprint,
            )

            if not result.get("success"):
                print(f"[{now.strftime('%H:%M:%S')}] fetch failed: {result.get('error', 'unknown error')}")
                time.sleep(poll_interval)
                continue

            fingerprint = str(result.get("fingerprint", ""))
            content = str(result.get("content", ""))
            print(f"[{now.strftime('%H:%M:%S')}] content: {(content[:60] + '...') if content else '(empty)'}")

            if result.get("comment_posted") and result.get("ai_answer"):
                last_fingerprint = fingerprint
                state["last_fingerprint"] = fingerprint
                state["commented"] = True
                state["comment_text"] = str(result.get("ai_answer"))
                state["comment_time"] = now.isoformat()
                save_state()
                print("=" * 60)
                print(f"Posted comment: {result.get('ai_answer')}")
                print("=" * 60)
                break

            if fingerprint == last_fingerprint:
                print(f"[{now.strftime('%H:%M:%S')}] no new post")
                time.sleep(poll_interval)
                continue

            last_fingerprint = fingerprint
            state["last_fingerprint"] = fingerprint
            state["last_content"] = content[:100] if content else ""
            state["last_time"] = now.isoformat()
            save_state()
            time.sleep(poll_interval)

    except KeyboardInterrupt:
        print("\nInterrupted by user")
    except Exception as exc:
        print(f"\nError: {exc}")

    print("\nMonitoring finished")
    print(f"Final state: {state}")


if __name__ == "__main__":
    main()
