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
        print("Usage: python examples/run_feed_refresh_listener.py <publish_time_HH:MM> <target_author> [poll_interval_sec]")
        print("Example: python examples/run_feed_refresh_listener.py 19:15 小蔡")
        print("Example: python examples/run_feed_refresh_listener.py 19:15 小蔡 0.5")
        return

    publish_time_str = sys.argv[1]
    target_author = sys.argv[2]

    poll_interval = 0.5
    if len(sys.argv) > 3:
        try:
            poll_interval = float(sys.argv[3])
        except Exception:
            print(f"Warning: invalid poll interval '{sys.argv[3]}', fallback to 0.5s")
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

    def try_ocr_count(content: str, image_paths: list[str]) -> str | None:
        if ocr_provider is None or not image_paths:
            return None

        target = None
        m = re.search(r'[\u201c"](.*?)[\u201d"]', content)
        if m:
            target = m.group(1).strip()

        if not target:
            print("[OCR] No quoted keyword found in question, skip OCR counting")
            return None

        print(f"[OCR] target keyword: {target}")
        start_time = time.time()

        total_count = 0
        for img_path in image_paths:
            try:
                ocr_text = ocr_provider.extract_text(img_path)
                if not ocr_text:
                    print(f"[OCR] {os.path.basename(img_path)}: no text")
                    continue
                texts = [line.strip() for line in ocr_text.splitlines() if line.strip()]
                count = sum(txt.count(target) for txt in texts)
                total_count += count
                print(f"[OCR] {os.path.basename(img_path)}: lines={len(texts)} matched={count}")
            except Exception as exc:
                print(f"[OCR] failed on {img_path}: {exc}")

        elapsed = int((time.time() - start_time) * 1000)
        if total_count > 0:
            answer = f"{total_count}{target}"
            print(f"[OCR] answer={answer} ({elapsed}ms)")
            return answer

        print(f"[OCR] no match for '{target}', fallback to AI ({elapsed}ms)")
        return None

    def try_ai_answer(content: str, image_paths: list[str]) -> str | None:
        start_time = time.time()
        try:
            result = ai_provider.answer_from_text_and_images(content, image_paths, [])
            elapsed = int((time.time() - start_time) * 1000)
            if result is None:
                print(f"[AI] no answer ({elapsed}ms)")
                return None

            answer = ""
            if hasattr(result, "answer") and result.answer:
                answer = result.answer
            elif isinstance(result, dict) and result.get("answer"):
                answer = str(result.get("answer", ""))
            elif isinstance(result, str):
                answer = result

            answer = str(answer).strip()
            bad_patterns = ["AnswerResult(", "confidence=", "source=", "latency_ms=", "extra={"]
            for pattern in bad_patterns:
                if pattern in answer:
                    match = re.search(r"answer=['\"]([^'\"]+)['\"]", answer)
                    if match:
                        answer = match.group(1).strip()
                    else:
                        return None
                    break

            if answer:
                print(f"[AI] answer={answer} ({elapsed}ms)")
                return answer
            print(f"[AI] empty answer ({elapsed}ms)")
            return None
        except Exception as exc:
            print(f"[AI] failed: {exc}")
            return None

    def ai_callback(content: str, image_paths: list[str]):
        """Prefer OCR answer first; fallback to AI. Return one final answer only."""
        print(f"[recognize] start text_len={len(content)} images={len(image_paths)}")
        callback_start = time.time()

        ocr_answer = try_ocr_count(content, image_paths)
        if ocr_answer:
            if not compare_with_ai_after_ocr_hit:
                elapsed = int((time.time() - callback_start) * 1000)
                print(f"[recognize] OCR hit, skip AI ({elapsed}ms)")
                return ocr_answer
            print("[recognize] OCR hit, compare mode enabled, continue with AI")

        ai_answer = try_ai_answer(content, image_paths)
        if ocr_answer:
            elapsed = int((time.time() - callback_start) * 1000)
            if ai_answer:
                if ai_answer == ocr_answer:
                    print(f"[recognize] OCR/AI consistent: {ocr_answer} ({elapsed}ms)")
                else:
                    print(f"[recognize] OCR/AI mismatch: OCR={ocr_answer}, AI={ai_answer} ({elapsed}ms)")
            else:
                print(f"[recognize] OCR hit, AI empty, use OCR ({elapsed}ms)")
            return ocr_answer

        if ai_answer:
            elapsed = int((time.time() - callback_start) * 1000)
            print(f"[recognize] use AI answer: {ai_answer} ({elapsed}ms)")
            return ai_answer
        return None

    from pyweixin.WeChatAuto import Moments
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

            result = Moments.fetch_and_comment_from_moments_feed(
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

            if result.get("comment_posted") and result.get("ai_answer"):
                last_fingerprint = fingerprint
                state["last_fingerprint"] = fingerprint
                state["commented"] = True
                commented_this_run = True
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
