"""总朋友圈刷新监听模式（常驻窗口）.

用法:
    python examples/run_feed_refresh_listener.py 19:15 小蔡 [轮询秒数]

说明:
    - 第一个参数: 发布时间（如 19:15）
    - 第二个参数: 目标作者（总朋友圈中要监听的作者关键字）
    - 自动设置: 提前2分钟开始监控，发布后5分钟结束（共7分钟）
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
    """从配置文件加载 API key"""
    key_file = PROJECT_ROOT / "config" / ".local_secrets.json"
    if key_file.exists():
        try:
            with open(key_file, "r", encoding="utf-8-sig") as f:
                data = json.load(f)
                return data.get("ARK_API_KEY", "")
        except Exception as e:
            print(f"警告: 读取配置文件失败: {e}")
    return os.getenv("ARK_API_KEY", "")


def main():
    if len(sys.argv) < 3:
        print("用法: python examples/run_feed_refresh_listener.py <发布时间> <目标作者> [轮询秒数]")
        print()
        print("示例:")
        print("  python examples/run_feed_refresh_listener.py 19:15 小蔡")
        print("  python examples/run_feed_refresh_listener.py 13:45 孙大炮 0.5")
        sys.exit(1)

    publish_time_str = sys.argv[1]
    target_author = sys.argv[2]
    poll_interval = 0.5
    if len(sys.argv) > 3:
        try:
            poll_interval = float(sys.argv[3])
        except Exception:
            print(f"警告: 轮询秒数格式无效 '{sys.argv[3]}'，改用默认 0.5s")
            poll_interval = 0.5
    # 太小容易触发 UI 不稳定，设置安全下限
    poll_interval = max(0.2, poll_interval)

    try:
        hour, minute = map(int, publish_time_str.split(":"))
        today = datetime.now().date()
        publish_dt = datetime.combine(today, datetime.min.time()).replace(hour=hour, minute=minute)
        start_dt = publish_dt - timedelta(minutes=2)
        end_dt = publish_dt + timedelta(minutes=5)
    except Exception:
        print(f"错误: 时间格式不正确 '{publish_time_str}'")
        print("正确格式: 1:52 或 13:45")
        sys.exit(1)

    api_key = load_api_key()
    if not api_key:
        print("错误: 未找到 ARK_API_KEY")
        print("请在 config/.local_secrets.json 中配置或设置环境变量")
        sys.exit(1)

    ai_provider = ArkChatProvider(api_key=api_key)

    ocr_provider = None
    try:
        print("正在加载 OCR 模型...")
        ocr_provider = PaddleOCRProvider(lang="ch", show_log=False)
        # 预热模型，避免首次识别时卡顿
        ocr_provider._get_ocr()
        print("OCR 模型加载完成")
    except Exception:
        ocr_provider = None
        print("警告: PaddleOCR 未安装，跳过 OCR 辅助（pip install paddleocr paddlepaddle）")

    output_dir = f"rush_moments_cache_feed_{target_author}"
    state_file = f"rush_state_feed_{target_author}.json"
    include_keywords = ["题目", "抢答", "图中", "多少", "几个", "几位"]
    exclude_keywords = ["无效", "取消"]
    os.makedirs(output_dir, exist_ok=True)
    hold_window_after_comment = True

    print("=" * 60)
    print("总朋友圈刷新监听（常驻窗口 + 刷新按钮）")
    print("=" * 60)
    print(f"目标作者: {target_author}")
    print(f"预计发布: {publish_dt.strftime('%Y-%m-%d %H:%M')}")
    print(f"监控开始: {start_dt.strftime('%Y-%m-%d %H:%M:%S')} (提前2分钟)")
    print(f"监控结束: {end_dt.strftime('%Y-%m-%d %H:%M:%S')} (发布后5分钟)")
    print(f"监控时长: 7 分钟")
    print(f"轮询间隔: {poll_interval:.2f} 秒")
    print(f"输出目录: {output_dir}")
    print("=" * 60)
    print()
    print("等待监控时间窗口...")
    print("按 Ctrl+C 可随时停止")
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
        """尝试用 OCR 直接计数回答，返回答案字符串或 None"""
        if ocr_provider is None or not image_paths:
            return None

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
                ocr_text = ocr_provider.extract_text(img_path)
                if not ocr_text:
                    print(f"[OCR] {os.path.basename(img_path)}: 未识别到文本")
                    continue

                texts = [line.strip() for line in ocr_text.splitlines() if line.strip()]
                count = sum(txt.count(target) for txt in texts)
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
                print(f"[AI] 识别完成: '{answer}' (耗时 {elapsed}ms)")
                return answer
            print(f"[AI] 答案为空 (耗时 {elapsed}ms)")
            return None
        except Exception as e:
            print(f"[AI] 识别失败: {e}")
            import traceback
            traceback.print_exc()
            return None

    def ai_callback(content, image_paths):
        """OCR 和 AI 都执行，返回答案列表（去重）"""
        print(f"[识别] 开始... 内容长度={len(content)}, 图片数={len(image_paths)}")
        answers = []

        ocr_answer = try_ocr_count(content, image_paths)
        if ocr_answer:
            answers.append(ocr_answer)

        print("[识别] 调用 AI...")
        ai_answer = try_ai_answer(content, image_paths)
        if ai_answer and ai_answer not in answers:
            answers.append(ai_answer)

        if answers:
            print(f"[识别] 最终答案列表: {answers}")
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
        print("检测到已评论过，3秒后继续监听（会重置状态）...")
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
                print(f"[{now.strftime('%H:%M:%S')}] 监控时间结束")
                break

            if already_commented:
                print(f"[{now.strftime('%H:%M:%S')}] 已评论成功，退出监控")
                break

            loops += 1
            print(f"[{now.strftime('%H:%M:%S')}] 轮询 #{loops}...")

            if moments_window is None:
                try:
                    moments_window = Navigator.open_moments(is_maximize=False, close_weixin=False)
                    try:
                        win32gui.SendMessage(moments_window.handle, win32con.WM_SYSCOMMAND, win32con.SC_MAXIMIZE, 0)
                    except Exception:
                        pass
                    print(f"[{now.strftime('%H:%M:%S')}] 已打开总朋友圈窗口（常驻）")
                except Exception as e:
                    print(f"[{now.strftime('%H:%M:%S')}] 打开总朋友圈失败: {e}")
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
                print(f"[{now.strftime('%H:%M:%S')}] 获取失败: {result.get('error', '未知错误')}")
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
            print(f"[{now.strftime('%H:%M:%S')}] 作者: {author or '(未知)'} 内容: {content[:60] if content else '(空)'}...")

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
                print(f"已评论: {result['ai_answer']}")
                print("如果自动发送失败，请手动点击发送按钮！")
                print("=" * 60)
                break

            if fingerprint == last_fingerprint:
                print(f"[{now.strftime('%H:%M:%S')}] 无新帖子")
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
        print("\n用户中断")
    except Exception as e:
        print(f"\n错误: {e}")
        import traceback
        traceback.print_exc()
    finally:
        should_hold_open = hold_window_after_comment and commented_this_run
        if should_hold_open and moments_window is not None:
            print("\n已按调试模式保留朋友圈窗口（未关闭），可直接截图观察。")
        elif moments_window is not None:
            try:
                moments_window.close()
            except Exception:
                pass

    print("\n监控完成！")
    print(f"最终状态: {state}")


if __name__ == "__main__":
    main()
