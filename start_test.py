"""涓€閿惎鍔ㄦ湅鍙嬪湀鎶㈢瓟娴嬭瘯锛堜紭鍖栫増锛氫竴娆℃墦寮€瀹屾垚璇诲彇+AI+璇勮锛?

鐢ㄦ硶锛?
    python start_test.py 1:52 灏忚敗

璇存槑锛?
    - 绗竴涓弬鏁帮細鍙戝竷鏃堕棿锛堝 1:52 鎴?13:45锛?
    - 绗簩涓弬鏁帮細濂藉弸澶囨敞锛堥粯璁?灏忚敗"锛?
    - 鑷姩璁剧疆锛氭彁鍓?鍒嗛挓寮€濮嬬洃鎺э紝鍙戝竷鍚?鍒嗛挓缁撴潫锛堝叡7鍒嗛挓锛?
"""

import hashlib
import json
import os
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path

# 娣诲姞椤圭洰璺緞
PROJECT_ROOT = Path(__file__).resolve().parent
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
            print(f"璀﹀憡锛氳鍙栭厤缃枃浠跺け璐? {e}")
    return os.getenv("ARK_API_KEY", "")


def main():
    if len(sys.argv) < 2:
        print("鐢ㄦ硶: python start_test.py <鍙戝竷鏃堕棿> [濂藉弸澶囨敞]")
        print()
        print("绀轰緥:")
        print("  python start_test.py 1:52          # 浠婂ぉ1:52鍙戝竷锛岀洃鎺уソ鍙?灏忚敗'")
        print("  python start_test.py 13:45 灏忕帇    # 浠婂ぉ13:45鍙戝竷锛岀洃鎺уソ鍙?灏忕帇'")
        sys.exit(1)

    # 瑙ｆ瀽鍙傛暟
    publish_time_str = sys.argv[1]
    friend_remark = sys.argv[2] if len(sys.argv) > 2 else "灏忚敗"

    # 瑙ｆ瀽鏃堕棿
    try:
        hour, minute = map(int, publish_time_str.split(":"))
        today = datetime.now().date()
        publish_dt = datetime.combine(today, datetime.min.time()).replace(hour=hour, minute=minute)
        start_dt = publish_dt - timedelta(minutes=2)
        end_dt = publish_dt + timedelta(minutes=5)
    except:
        print(f"閿欒锛氭椂闂存牸寮忎笉姝ｇ‘ '{publish_time_str}'")
        print("姝ｇ‘鏍煎紡: 1:52 鎴?13:45")
        sys.exit(1)

    # 鍔犺浇 API key
    api_key = load_api_key()
    if not api_key:
        print("閿欒锛氭湭鎵惧埌 ARK_API_KEY")
        print("璇峰湪 config/.local_secrets.json 涓厤缃垨璁剧疆鐜鍙橀噺")
        sys.exit(1)

    # 鍒濆鍖?AI Provider
    ai_provider = ArkChatProvider(api_key=api_key)
    compare_with_ai_after_ocr_hit = os.getenv("PYWEIXIN_COMPARE_AI_AFTER_OCR_HIT", "").strip().lower() in {
        "1",
        "true",
        "yes",
    }

    # 棰勫姞杞?OCR锛堥伩鍏嶈疆璇㈡椂鍒濆鍖栧欢杩燂級
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

    # 閰嶇疆
    output_dir = f"rush_moments_cache_test_{friend_remark}"
    state_file = f"rush_state_test_{friend_remark}.json"
    include_keywords = ["棰樼洰", "鎶㈢瓟", "鍥句腑", "澶氬皯", "鍑犱釜", "鍑犱綅"]
    exclude_keywords = ["鏃犳晥", "鍙栨秷"]
    poll_interval = 1.0  # 1绉掕疆璇?

    os.makedirs(output_dir, exist_ok=True)

    # 鎵撳嵃閰嶇疆
    print("="*60)
    print("鏈嬪弸鍦堟姠绛旀祴璇曪紙浼樺寲鐗堬細涓€娆℃墦寮€瀹屾垚鍏ㄩ儴娴佺▼锛?")
    print("="*60)
    print(f"濂藉弸澶囨敞: {friend_remark}")
    print(f"棰勮鍙戝竷: {publish_dt.strftime('%Y-%m-%d %H:%M')}")
    print(f"鐩戞帶寮€濮? {start_dt.strftime('%Y-%m-%d %H:%M:%S')} (鎻愬墠2鍒嗛挓)")
    print(f"鐩戞帶缁撴潫: {end_dt.strftime('%Y-%m-%d %H:%M:%S')} (鍙戝竷鍚?鍒嗛挓)")
    print(f"鐩戞帶鏃堕暱: 7 鍒嗛挓")
    print(f"杈撳嚭鐩綍: {output_dir}")
    print("="*60)
    print()
    print("绛夊緟鐩戞帶鏃堕棿绐楀彛...")
    print("鎸?Ctrl+C 鍙殢鏃跺仠姝?")
    print()

    # 鍔犺浇鐘舵€?
    state = {}
    if os.path.exists(state_file):
        try:
            with open(state_file, "r", encoding="utf-8") as f:
                state = json.load(f)
        except:
            pass

    def save_state():
        with open(state_file, "w", encoding="utf-8") as f:
            json.dump(state, f, ensure_ascii=False, indent=2)

    # OCR 璁℃暟鍑芥暟
    def try_ocr_count(content, image_paths):
        """灏濊瘯鐢?OCR 鐩存帴璁℃暟鍥炵瓟锛岃繑鍥炵瓟妗堝瓧绗︿覆鎴?None"""
        if ocr_provider is None or not image_paths:
            return None

        # 浠庨鐩腑鎻愬彇寮曞彿鍐呯殑鍏抽敭璇嶏紙濡?"绾㈣"锛?
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

    # AI 璇嗗埆鍑芥暟
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
            if hasattr(result, 'answer') and result.answer:
                answer = result.answer
            elif isinstance(result, dict) and result.get("answer"):
                answer = result.get("answer", "")
            elif isinstance(result, str):
                answer = result

            if not isinstance(answer, str):
                answer = str(answer)
            answer = answer.strip()

            # 瀹夊叏妫€鏌?
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

    # AI 鍥炶皟鍑芥暟锛圤CR + AI 鍙屽彂锛岃繑鍥炵瓟妗堝垪琛級
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

    # 涓诲惊鐜?
    from pyweixin.WeChatAuto import Moments

    loops = 0
    last_fingerprint = state.get("last_fingerprint", "")
    already_commented = state.get("commented", False)

    # 妫€鏌ユ槸鍚﹀凡缁忚瘎璁鸿繃锛堜粠涓婃鐘舵€侊級
    if already_commented:
        print("妫€娴嬪埌宸茶瘎璁鸿繃锛屾槸鍚﹂噸鏂板紑濮嬶紵鎸?Ctrl+C 閫€鍑猴紝鎴栫瓑寰呯户缁?..")
        time.sleep(3)
        # 閲嶇疆鐘舵€?
        already_commented = False
        state['commented'] = False

    try:
        while True:
            now = datetime.now()

            # 妫€鏌ユ椂闂寸獥鍙?
            if now < start_dt:
                wait = min(poll_interval, (start_dt - now).total_seconds())
                time.sleep(wait)
                continue

            if now > end_dt:
                print(f"[{now.strftime('%H:%M:%S')}] 鐩戞帶鏃堕棿缁撴潫")
                break

            # 宸茬粡璇勮鎴愬姛锛岄€€鍑?
            if already_commented:
                print(f"[{now.strftime('%H:%M:%S')}] 宸茶瘎璁烘垚鍔燂紝閫€鍑虹洃鎺?")
                break

            loops += 1
            print(f"[{now.strftime('%H:%M:%S')}] 杞 #{loops}...")

            # 涓€娆℃墦寮€鏈嬪弸鍦堬紝瀹屾垚璇诲彇+AI+璇勮
            result = Moments.fetch_and_comment_friend_moment(
                friend=friend_remark,
                ai_callback=ai_callback,
                target_folder=output_dir,
                is_maximize=True,
                close_weixin=False,
                include_keywords=include_keywords,
                exclude_keywords=exclude_keywords,
                last_fingerprint=last_fingerprint
            )

            if not result['success']:
                print(f"[{now.strftime('%H:%M:%S')}] 鑾峰彇澶辫触: {result.get('error', '鏈煡閿欒')}")
                time.sleep(poll_interval)
                continue

            fingerprint = result['fingerprint']
            content = result['content']
            print(f"[{now.strftime('%H:%M:%S')}] 鍐呭: {content[:60] if content else '(绌?'}...")

            # 璇勮宸茬矘璐达紝绔嬪埢閫€鍑?
            if result['comment_posted'] and result['ai_answer']:
                last_fingerprint = fingerprint
                state['last_fingerprint'] = fingerprint
                state['commented'] = True
                state['comment_text'] = result['ai_answer']
                state['comment_time'] = now.isoformat()
                save_state()
                print()
                print("="*60)
                print(f"宸茶瘎璁? {result['ai_answer']}")
                print("濡傛灉鑷姩鍙戦€佸け璐ワ紝璇锋墜鍔ㄧ偣鍑诲彂閫佹寜閽紒")
                print("="*60)
                break

            # 鎸囩汗鐩稿悓 = 鏃у笘瀛愶紝缁х画绛?
            if fingerprint == last_fingerprint:
                print(f"[{now.strftime('%H:%M:%S')}] 鏃犳柊甯栧瓙")
                time.sleep(poll_interval)
                continue

            # 鏂板笘瀛愪絾鏈瘎璁猴紙鍏抽敭璇嶄笉鍖归厤鎴朅I鏃犵瓟妗堬級
            last_fingerprint = fingerprint
            state['last_fingerprint'] = fingerprint
            state['last_content'] = content[:100] if content else ''
            state['last_time'] = now.isoformat()
            save_state()
            time.sleep(poll_interval)

    except KeyboardInterrupt:
        print("\n鐢ㄦ埛涓柇")
    except Exception as e:
        print(f"\n閿欒: {e}")
        import traceback
        traceback.print_exc()

    print("\n鐩戞帶瀹屾垚锛?")
    print(f"鏈€缁堢姸鎬? {state}")


if __name__ == "__main__":
    main()
