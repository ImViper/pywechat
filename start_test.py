"""一键启动朋友圈抢答测试（优化版：一次打开完成读取+AI+评论）

用法：
    python start_test.py 1:52 小蔡

说明：
    - 第一个参数：发布时间（如 1:52 或 13:45）
    - 第二个参数：好友备注（默认"小蔡"）
    - 自动设置：提前2分钟开始监控，发布后5分钟结束（共7分钟）
"""

import hashlib
import json
import os
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path

# 添加项目路径
PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from pyweixin.rush_ai import ArkChatProvider


def load_api_key():
    """从配置文件加载 API key"""
    key_file = PROJECT_ROOT / "config" / ".local_secrets.json"
    if key_file.exists():
        try:
            with open(key_file, "r", encoding="utf-8-sig") as f:
                data = json.load(f)
                return data.get("ARK_API_KEY", "")
        except Exception as e:
            print(f"警告：读取配置文件失败: {e}")
    return os.getenv("ARK_API_KEY", "")


def main():
    if len(sys.argv) < 2:
        print("用法: python start_test.py <发布时间> [好友备注]")
        print()
        print("示例:")
        print("  python start_test.py 1:52          # 今天1:52发布，监控好友'小蔡'")
        print("  python start_test.py 13:45 小王    # 今天13:45发布，监控好友'小王'")
        sys.exit(1)

    # 解析参数
    publish_time_str = sys.argv[1]
    friend_remark = sys.argv[2] if len(sys.argv) > 2 else "小蔡"

    # 解析时间
    try:
        hour, minute = map(int, publish_time_str.split(":"))
        today = datetime.now().date()
        publish_dt = datetime.combine(today, datetime.min.time()).replace(hour=hour, minute=minute)
        start_dt = publish_dt - timedelta(minutes=2)
        end_dt = publish_dt + timedelta(minutes=5)
    except:
        print(f"错误：时间格式不正确 '{publish_time_str}'")
        print("正确格式: 1:52 或 13:45")
        sys.exit(1)

    # 加载 API key
    api_key = load_api_key()
    if not api_key:
        print("错误：未找到 ARK_API_KEY")
        print("请在 config/.local_secrets.json 中配置或设置环境变量")
        sys.exit(1)

    # 初始化 AI Provider
    ai_provider = ArkChatProvider(api_key=api_key)

    # 预加载 OCR（避免轮询时初始化延迟）
    ocr_reader = None
    try:
        import easyocr
        print("正在加载 OCR 模型...")
        ocr_reader = easyocr.Reader(["ch_sim"], gpu=False, verbose=False)
        print("OCR 模型加载完成")
    except ImportError:
        print("警告：easyocr 未安装，跳过 OCR 辅助（pip install easyocr）")

    # 配置
    output_dir = f"rush_moments_cache_test_{friend_remark}"
    state_file = f"rush_state_test_{friend_remark}.json"
    include_keywords = ["题目", "抢答", "图中", "多少", "几个", "几位"]
    exclude_keywords = ["无效", "取消"]
    poll_interval = 1.0  # 1秒轮询

    os.makedirs(output_dir, exist_ok=True)

    # 打印配置
    print("="*60)
    print("朋友圈抢答测试（优化版：一次打开完成全部流程）")
    print("="*60)
    print(f"好友备注: {friend_remark}")
    print(f"预计发布: {publish_dt.strftime('%Y-%m-%d %H:%M')}")
    print(f"监控开始: {start_dt.strftime('%Y-%m-%d %H:%M:%S')} (提前2分钟)")
    print(f"监控结束: {end_dt.strftime('%Y-%m-%d %H:%M:%S')} (发布后5分钟)")
    print(f"监控时长: 7 分钟")
    print(f"输出目录: {output_dir}")
    print("="*60)
    print()
    print("等待监控时间窗口...")
    print("按 Ctrl+C 可随时停止")
    print()

    # 加载状态
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

    # OCR 计数函数
    def try_ocr_count(content, image_paths):
        """尝试用 OCR 直接计数回答，返回答案字符串或 None"""
        if ocr_reader is None or not image_paths:
            return None

        def load_image_for_ocr(img_path):
            """兼容中文路径读取图片，避免 cv2.imread 在 Windows 下失败"""
            try:
                import cv2
                import numpy as np
            except Exception:
                return img_path

            has_non_ascii = any(ord(ch) > 127 for ch in img_path)
            if not has_non_ascii:
                image = cv2.imread(img_path)
                if image is not None:
                    return image

            try:
                file_bytes = np.fromfile(img_path, dtype=np.uint8)
                if file_bytes.size == 0:
                    return None
                return cv2.imdecode(file_bytes, cv2.IMREAD_COLOR)
            except Exception:
                return None

        # 从题目中提取引号内的关键词（如 "红袖"）
        import re
        target = None
        m = re.search(r'[\u201c"](.*?)[\u201d"]', content)
        if m:
            target = m.group(1)

        if not target:
            print("[OCR] 未从题目中提取到引号关键词，跳过 OCR")
            return None

        print(f"[OCR] 目标关键词: '{target}'")
        start_time = time.time()

        total_count = 0
        for img_path in image_paths:
            try:
                image_input = load_image_for_ocr(img_path)
                if image_input is None:
                    print(f"[OCR] 图片读取失败（可能是路径编码问题）: {img_path}")
                    continue

                results = ocr_reader.readtext(image_input)
                texts = [text for _, text, conf in results if conf > 0.3]
                count = sum(1 for txt in texts if target in txt)
                total_count += count
                print(f"[OCR] {os.path.basename(img_path)}: 识别 {len(texts)} 个文本, 匹配 '{target}' {count} 次")
            except Exception as e:
                print(f"[OCR] 识别失败 {img_path}: {e}")

        elapsed = int((time.time() - start_time) * 1000)

        if total_count > 0:
            answer = f"{total_count}{target}"
            print(f"[OCR] 计数完成: '{answer}' (耗时 {elapsed}ms)")
            return answer

        print(f"[OCR] 未匹配到 '{target}'，回退 AI (耗时 {elapsed}ms)")
        return None

    # AI 识别函数
    def try_ai_answer(content, image_paths):
        """调用 AI 识别，返回答案字符串或 None"""
        start_time = time.time()
        try:
            result = ai_provider.answer_from_text_and_images(content, image_paths, [])
            elapsed = int((time.time() - start_time) * 1000)
            if result is None:
                print(f"[AI] 未返回答案 (耗时 {elapsed}ms)")
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

            # 安全检查
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
                print(f"[AI] 识别完成: '{answer}' (耗时 {elapsed}ms)")
                return answer
            print(f"[AI] 答案为空 (耗时 {elapsed}ms)")
            return None
        except Exception as e:
            print(f"[AI] 识别失败: {e}")
            import traceback
            traceback.print_exc()
            return None

    # AI 回调函数（OCR + AI 双发，返回答案列表）
    def ai_callback(content, image_paths):
        """OCR 和 AI 都执行，返回答案列表（去重），逐条发送评论增加容错"""
        print(f"[识别] 开始... 内容长度={len(content)}, 图片数={len(image_paths)}")
        answers = []

        # OCR 计数
        ocr_answer = try_ocr_count(content, image_paths)
        if ocr_answer:
            answers.append(ocr_answer)

        # AI 识别
        print("[识别] 调用 AI...")
        ai_answer = try_ai_answer(content, image_paths)
        if ai_answer and ai_answer not in answers:
            answers.append(ai_answer)

        if answers:
            print(f"[识别] 最终答案列表: {answers}")
            return answers
        return None

    # 主循环
    from pyweixin.WeChatAuto import Moments

    loops = 0
    last_fingerprint = state.get("last_fingerprint", "")
    already_commented = state.get("commented", False)

    # 检查是否已经评论过（从上次状态）
    if already_commented:
        print("检测到已评论过，是否重新开始？按 Ctrl+C 退出，或等待继续...")
        time.sleep(3)
        # 重置状态
        already_commented = False
        state['commented'] = False

    try:
        while True:
            now = datetime.now()

            # 检查时间窗口
            if now < start_dt:
                wait = min(poll_interval, (start_dt - now).total_seconds())
                time.sleep(wait)
                continue

            if now > end_dt:
                print(f"[{now.strftime('%H:%M:%S')}] 监控时间结束")
                break

            # 已经评论成功，退出
            if already_commented:
                print(f"[{now.strftime('%H:%M:%S')}] 已评论成功，退出监控")
                break

            loops += 1
            print(f"[{now.strftime('%H:%M:%S')}] 轮询 #{loops}...")

            # 一次打开朋友圈，完成读取+AI+评论
            result = Moments.fetch_and_comment_friend_moment(
                friend=friend_remark,
                ai_callback=ai_callback,
                target_folder=output_dir,
                is_maximize=False,
                close_weixin=False,
                include_keywords=include_keywords,
                exclude_keywords=exclude_keywords,
                last_fingerprint=last_fingerprint
            )

            if not result['success']:
                print(f"[{now.strftime('%H:%M:%S')}] 获取失败: {result.get('error', '未知错误')}")
                time.sleep(poll_interval)
                continue

            fingerprint = result['fingerprint']
            content = result['content']
            print(f"[{now.strftime('%H:%M:%S')}] 内容: {content[:60] if content else '(空)'}...")

            # 评论已粘贴，立刻退出
            if result['comment_posted'] and result['ai_answer']:
                last_fingerprint = fingerprint
                state['last_fingerprint'] = fingerprint
                state['commented'] = True
                state['comment_text'] = result['ai_answer']
                state['comment_time'] = now.isoformat()
                save_state()
                print()
                print("="*60)
                print(f"已评论: {result['ai_answer']}")
                print("如果自动发送失败，请手动点击发送按钮！")
                print("="*60)
                break

            # 指纹相同 = 旧帖子，继续等
            if fingerprint == last_fingerprint:
                print(f"[{now.strftime('%H:%M:%S')}] 无新帖子")
                time.sleep(poll_interval)
                continue

            # 新帖子但未评论（关键词不匹配或AI无答案）
            last_fingerprint = fingerprint
            state['last_fingerprint'] = fingerprint
            state['last_content'] = content[:100] if content else ''
            state['last_time'] = now.isoformat()
            save_state()
            time.sleep(poll_interval)

    except KeyboardInterrupt:
        print("\n用户中断")
    except Exception as e:
        print(f"\n错误: {e}")
        import traceback
        traceback.print_exc()

    print("\n监控完成！")
    print(f"最终状态: {state}")


if __name__ == "__main__":
    main()
