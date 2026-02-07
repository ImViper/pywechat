"""鎬绘湅鍙嬪湀鍒锋柊鐩戝惉妯″紡锛堝父椹荤獥鍙ｏ級.

鐢ㄦ硶:
    python examples/run_feed_refresh_listener.py 19:15 灏忚敗 [杞绉掓暟]

璇存槑:
    - 绗竴涓弬鏁? 鍙戝竷鏃堕棿锛堝 19:15锛?
    - 绗簩涓弬鏁? 鐩爣浣滆€咃紙鎬绘湅鍙嬪湀涓鐩戝惉鐨勪綔鑰呭叧閿瓧锛?
    - 鑷姩璁剧疆: 鎻愬墠2鍒嗛挓寮€濮嬬洃鎺э紝鍙戝竷鍚?鍒嗛挓缁撴潫锛堝叡7鍒嗛挓锛?
"""

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


def load_api_key():
    """浠庨厤缃枃浠跺姞杞?API key"""
    key_file = PROJECT_ROOT / "config" / ".local_secrets.json"
    if key_file.exists():
        try:
            with open(key_file, "r", encoding="utf-8-sig") as f:
                data = json.load(f)
                return data.get("ARK_API_KEY", "")
        except Exception as e:
            print(f"璀﹀憡: 璇诲彇閰嶇疆鏂囦欢澶辫触: {e}")
    return os.getenv("ARK_API_KEY", "")


def main():
    if len(sys.argv) < 3:
        print("鐢ㄦ硶: python examples/run_feed_refresh_listener.py <鍙戝竷鏃堕棿> <鐩爣浣滆€? [杞绉掓暟]")
        print()
        print("绀轰緥:")
        print("  python examples/run_feed_refresh_listener.py 19:15 灏忚敗")
        print("  python examples/run_feed_refresh_listener.py 13:45 瀛欏ぇ鐐?0.5")
        sys.exit(1)

    publish_time_str = sys.argv[1]
    target_author = sys.argv[2]
    poll_interval = 0.5
    if len(sys.argv) > 3:
        try:
            poll_interval = float(sys.argv[3])
        except Exception:
            print(f"璀﹀憡: 杞绉掓暟鏍煎紡鏃犳晥 '{sys.argv[3]}'锛屾敼鐢ㄩ粯璁?0.5s")
            poll_interval = 0.5
    # 澶皬瀹规槗瑙﹀彂 UI 涓嶇ǔ瀹氾紝璁剧疆瀹夊叏涓嬮檺
    poll_interval = max(0.2, poll_interval)

    try:
        hour, minute = map(int, publish_time_str.split(":"))
        today = datetime.now().date()
        publish_dt = datetime.combine(today, datetime.min.time()).replace(hour=hour, minute=minute)
        start_dt = publish_dt - timedelta(minutes=2)
        end_dt = publish_dt + timedelta(minutes=5)
    except Exception:
        print(f"閿欒: 鏃堕棿鏍煎紡涓嶆纭?'{publish_time_str}'")
        print("姝ｇ‘鏍煎紡: 1:52 鎴?13:45")
        sys.exit(1)

    api_key = load_api_key()
    if not api_key:
        print("閿欒: 鏈壘鍒?ARK_API_KEY")
        print("璇峰湪 config/.local_secrets.json 涓厤缃垨璁剧疆鐜鍙橀噺")
        sys.exit(1)

    ai_provider = ArkChatProvider(api_key=api_key)
    compare_with_ai_after_ocr_hit = os.getenv("PYWEIXIN_COMPARE_AI_AFTER_OCR_HIT", "").strip().lower() in {
        "1",
        "true",
        "yes",
    }

    ocr_provider = None
    try:
        print("姝ｅ湪鍔犺浇 OCR 妯″瀷...")
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
        # 棰勭儹妯″瀷锛岄伩鍏嶉娆¤瘑鍒椂鍗￠】
        ocr_provider._get_ocr()
        print("OCR 妯″瀷鍔犺浇瀹屾垚")
    except Exception:
        ocr_provider = None
        print("警告：PaddleOCR 未安装，跳过 OCR 辅助（pip install paddleocr paddlepaddle）")

    output_dir = f"rush_moments_cache_feed_{target_author}"
    state_file = f"rush_state_feed_{target_author}.json"
    include_keywords = ["棰樼洰", "鎶㈢瓟", "鍥句腑", "澶氬皯", "鍑犱釜", "鍑犱綅"]
    exclude_keywords = ["鏃犳晥", "鍙栨秷"]
    os.makedirs(output_dir, exist_ok=True)
    hold_window_after_comment = True

    print("=" * 60)
    print("鎬绘湅鍙嬪湀鍒锋柊鐩戝惉锛堝父椹荤獥鍙?+ 鍒锋柊鎸夐挳锛?")
    print("=" * 60)
    print(f"鐩爣浣滆€? {target_author}")
    print(f"棰勮鍙戝竷: {publish_dt.strftime('%Y-%m-%d %H:%M')}")
    print(f"鐩戞帶寮€濮? {start_dt.strftime('%Y-%m-%d %H:%M:%S')} (鎻愬墠2鍒嗛挓)")
    print(f"鐩戞帶缁撴潫: {end_dt.strftime('%Y-%m-%d %H:%M:%S')} (鍙戝竷鍚?鍒嗛挓)")
    print(f"鐩戞帶鏃堕暱: 7 鍒嗛挓")
    print(f"杞闂撮殧: {poll_interval:.2f} 绉?")
    print(f"杈撳嚭鐩綍: {output_dir}")
    print("=" * 60)
    print()
    print("绛夊緟鐩戞帶鏃堕棿绐楀彛...")
    print("鎸?Ctrl+C 鍙殢鏃跺仠姝?")
    print()

    state = {}
    if os.path.exists(state_file):
        try:
            with open(state_file, "r", encoding="utf-8") as f:
                state = json.load(f)
        except Exception:
            pass

    def save_state():
        with open(state_file, "w", encoding="utf-8") as f:
            json.dump(state, f, ensure_ascii=False, indent=2)

    def try_ocr_count(content, image_paths):
        """灏濊瘯鐢?OCR 鐩存帴璁℃暟鍥炵瓟锛岃繑鍥炵瓟妗堝瓧绗︿覆鎴?None"""
        if ocr_provider is None or not image_paths:
            return None

        import re
        target = None
        m = re.search(r'[\u201c"](.*?)[\u201d"]', content)
        if m:
            target = m.group(1)

        if not target:
            print("[OCR] 鏈粠棰樼洰涓彁鍙栧埌寮曞彿鍏抽敭璇嶏紝璺宠繃 OCR")
            return None

        print(f"[OCR] 鐩爣鍏抽敭璇? '{target}'")
        start_time = time.time()

        total_count = 0
        for img_path in image_paths:
            try:
                ocr_text = ocr_provider.extract_text(img_path)
                if not ocr_text:
                    print(f"[OCR] {os.path.basename(img_path)}: 鏈瘑鍒埌鏂囨湰")
                    continue

                texts = [line.strip() for line in ocr_text.splitlines() if line.strip()]
                count = sum(txt.count(target) for txt in texts)
                total_count += count
                print(f"[OCR] {os.path.basename(img_path)}: 璇嗗埆 {len(texts)} 涓枃鏈? 鍖归厤 '{target}' {count} 娆?")
            except Exception as e:
                print(f"[OCR] 璇嗗埆澶辫触 {img_path}: {e}")

        elapsed = int((time.time() - start_time) * 1000)
        if total_count > 0:
            answer = f"{total_count}{target}"
            print(f"[OCR] 璁℃暟瀹屾垚: '{answer}' (鑰楁椂 {elapsed}ms)")
            return answer

        print(f"[OCR] 鏈尮閰嶅埌 '{target}'锛屽洖閫€ AI (鑰楁椂 {elapsed}ms)")
        return None

    def try_ai_answer(content, image_paths):
        """璋冪敤 AI 璇嗗埆锛岃繑鍥炵瓟妗堝瓧绗︿覆鎴?None"""
        start_time = time.time()
        try:
            result = ai_provider.answer_from_text_and_images(content, image_paths, [])
            elapsed = int((time.time() - start_time) * 1000)
            if result is None:
                print(f"[AI] 鏈繑鍥炵瓟妗?(鑰楁椂 {elapsed}ms)")
                return None

            answer = ""
            if hasattr(result, "answer") and result.answer:
                answer = result.answer
            elif isinstance(result, dict) and result.get("answer"):
                answer = result.get("answer", "")
            elif isinstance(result, str):
                answer = result

            if not isinstance(answer, str):
                answer = str(answer)
            answer = answer.strip()

            bad_patterns = ["AnswerResult(", "confidence=", "source=", "latency_ms=", "extra={"]
            for pattern in bad_patterns:
                if pattern in answer:
                    import re
                    match = re.search(r"answer=['\"]([^'\"]+)['\"]", answer)
                    if match:
                        answer = match.group(1).strip()
                    else:
                        return None
                    break

            if answer:
                print(f"[AI] 璇嗗埆瀹屾垚: '{answer}' (鑰楁椂 {elapsed}ms)")
                return answer
            print(f"[AI] 绛旀涓虹┖ (鑰楁椂 {elapsed}ms)")
            return None
        except Exception as e:
            print(f"[AI] 璇嗗埆澶辫触: {e}")
            import traceback
            traceback.print_exc()
            return None

    def ai_callback(content, image_paths):
        """Prefer OCR result first; call AI as fallback."""
        print(f"[识别] 开始... 内容长度={len(content)}, 图片数={len(image_paths)}")
        callback_start = time.time()
        answers = []

        ocr_answer = try_ocr_count(content, image_paths)
        if ocr_answer:
            answers.append(ocr_answer)
            if not compare_with_ai_after_ocr_hit:
                elapsed = int((time.time() - callback_start) * 1000)
                print(f"[识别] OCR命中，跳过AI，直接使用OCR答案 (总耗时 {elapsed}ms)")
                return answers
            print("[识别] OCR命中，但已开启对比模式，继续调用AI...")

        print("[识别] 调用AI...")
        ai_answer = try_ai_answer(content, image_paths)
        if ai_answer and ai_answer not in answers:
            answers.append(ai_answer)

        if answers:
            elapsed = int((time.time() - callback_start) * 1000)
            print(f"[识别] 最终答案列表: {answers} (总耗时 {elapsed}ms)")
            return answers
        return None
    from pyweixin.WeChatAuto import Moments
    from pyweixin.WeChatTools import Navigator

    loops = 0
    last_fingerprint = state.get("last_fingerprint", "")
    already_commented = state.get("commented", False)
    commented_this_run = False
    moments_window = None

    if already_commented:
        print("妫€娴嬪埌宸茶瘎璁鸿繃锛?绉掑悗缁х画鐩戝惉锛堜細閲嶇疆鐘舵€侊級...")
        time.sleep(3)
        already_commented = False
        state["commented"] = False

    try:
        while True:
            now = datetime.now()

            if now < start_dt:
                wait = min(poll_interval, (start_dt - now).total_seconds())
                time.sleep(wait)
                continue

            if now > end_dt:
                print(f"[{now.strftime('%H:%M:%S')}] 鐩戞帶鏃堕棿缁撴潫")
                break

            if already_commented:
                print(f"[{now.strftime('%H:%M:%S')}] 宸茶瘎璁烘垚鍔燂紝閫€鍑虹洃鎺?")
                break

            loops += 1
            print(f"[{now.strftime('%H:%M:%S')}] 杞 #{loops}...")

            if moments_window is None:
                try:
                    moments_window = Navigator.open_moments(is_maximize=False, close_weixin=False)
                    try:
                        win32gui.SendMessage(moments_window.handle, win32con.WM_SYSCOMMAND, win32con.SC_MAXIMIZE, 0)
                    except Exception:
                        pass
                    print(f"[{now.strftime('%H:%M:%S')}] 宸叉墦寮€鎬绘湅鍙嬪湀绐楀彛锛堝父椹伙級")
                except Exception as e:
                    print(f"[{now.strftime('%H:%M:%S')}] 鎵撳紑鎬绘湅鍙嬪湀澶辫触: {e}")
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
                moments_window=moments_window
            )

            if not result["success"]:
                print(f"[{now.strftime('%H:%M:%S')}] 鑾峰彇澶辫触: {result.get('error', '鏈煡閿欒')}")
                if result.get("error"):
                    if moments_window is not None:
                        try:
                            moments_window.close()
                        except Exception:
                            pass
                    moments_window = None
                time.sleep(poll_interval)
                continue

            fingerprint = result["fingerprint"]
            content = result["content"]
            author = result.get("author", "")
            print(f"[{now.strftime('%H:%M:%S')}] 浣滆€? {author or '(鏈煡)'} 鍐呭: {content[:60] if content else '(绌?'}...")

            if result["comment_posted"] and result["ai_answer"]:
                last_fingerprint = fingerprint
                state["last_fingerprint"] = fingerprint
                state["commented"] = True
                commented_this_run = True
                state["comment_text"] = result["ai_answer"]
                state["comment_time"] = now.isoformat()
                save_state()
                print()
                print("=" * 60)
                print(f"宸茶瘎璁? {result['ai_answer']}")
                print("濡傛灉鑷姩鍙戦€佸け璐ワ紝璇锋墜鍔ㄧ偣鍑诲彂閫佹寜閽紒")
                print("=" * 60)
                break

            if fingerprint == last_fingerprint:
                print(f"[{now.strftime('%H:%M:%S')}] 鏃犳柊甯栧瓙")
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
        print("\n鐢ㄦ埛涓柇")
    except Exception as e:
        print(f"\n閿欒: {e}")
        import traceback
        traceback.print_exc()
    finally:
        should_hold_open = hold_window_after_comment and commented_this_run
        if should_hold_open and moments_window is not None:
            print("\n宸叉寜璋冭瘯妯″紡淇濈暀鏈嬪弸鍦堢獥鍙ｏ紙鏈叧闂級锛屽彲鐩存帴鎴浘瑙傚療銆?")
        elif moments_window is not None:
            try:
                moments_window.close()
            except Exception:
                pass

    print("\n鐩戞帶瀹屾垚锛?")
    print(f"鏈€缁堢姸鎬? {state}")


if __name__ == "__main__":
    main()
