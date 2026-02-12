"""
使用 pywinauto 精确定位和操作朋友圈

这个版本使用 UI 自动化来精确找到朋友圈元素
"""

import sys
import time
import os
import re
from pathlib import Path
from pathlib import Path

# 设置 UTF-8 输出
if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except:
        pass

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))
from hook_log_utils import resolve_log_path

LOG_PATH = str(resolve_log_path(project_root=PROJECT_ROOT))

def get_log_size():
    if os.path.exists(LOG_PATH):
        return os.path.getsize(LOG_PATH)
    return 0

def read_new_log_lines(last_size):
    if not os.path.exists(LOG_PATH):
        return []

    current_size = os.path.getsize(LOG_PATH)
    if current_size <= last_size:
        return []

    with open(LOG_PATH, 'r', encoding='utf-8', errors='ignore') as f:
        f.seek(last_size)
        return f.readlines()

def trigger_moments_refresh_simple():
    """简化版本：只通过键盘操作"""
    print("\n[方法] 使用键盘快捷键操作...")

    try:
        import pyautogui

        # 确保微信窗口激活
        print("   1. 尝试激活微信窗口...")
        # 点击任意位置激活窗口
        pyautogui.click(500, 500)
        time.sleep(0.5)

        # 尝试使用 Alt+3 切换到朋友圈（如果有快捷键的话）
        print("   2. 尝试快捷键 Alt+3...")
        pyautogui.hotkey('alt', '3')
        time.sleep(2)

        # 尝试使用 F5 刷新
        print("   3. 尝试按 F5 刷新...")
        pyautogui.press('f5')
        time.sleep(1)

        # 或者尝试 Ctrl+R
        print("   4. 尝试 Ctrl+R 刷新...")
        pyautogui.hotkey('ctrl', 'r')
        time.sleep(1)

        print("   [OK] 已执行键盘操作")
        return True

    except Exception as e:
        print(f"   [ERROR] 键盘操作失败: {e}")
        return False

def monitor_log_for_callback(timeout=10):
    """监控日志等待回调触发"""
    print(f"\n[监控] 等待回调触发 (超时 {timeout}s)...\n")

    last_size = get_log_size()
    start_time = time.time()

    callback_triggered = False
    callback_info = {}

    while (time.time() - start_time) < timeout:
        new_lines = read_new_log_lines(last_size)

        if new_lines:
            last_size = get_log_size()

            for line in new_lines:
                if '[SNS_POC]' in line:
                    print(f"   [LOG] {line.strip()}")

                    if 'TRIGGERED' in line:
                        callback_triggered = True
                        callback_info['triggered'] = True

                    if 'Timestamp:' in line:
                        match = re.search(r'Timestamp: (\d+) ms', line)
                        if match:
                            callback_info['timestamp'] = int(match.group(1))

                    if 'content:' in line:
                        match = re.search(r'content: (.+)', line)
                        if match:
                            callback_info['content'] = match.group(1).strip()

        if callback_triggered:
            break

        time.sleep(0.5)

    return callback_triggered, callback_info

def main():
    print("="*70)
    print("Phase 0 - 简化自动化测试（键盘操作）")
    print("="*70)

    if not os.path.exists(LOG_PATH):
        print(f"\n[ERROR] 找不到日志文件: {LOG_PATH}")
        return

    print(f"\n[OK] 日志文件: {LOG_PATH}")
    print(f"     当前大小: {get_log_size()} 字节\n")

    print("此脚本将：")
    print("  1. 尝试通过键盘快捷键操作微信")
    print("  2. 监控日志等待回调")
    print()

    response = input("开始测试? (y/n): ")
    if response.lower() != 'y':
        print("已取消")
        return

    print("\n" + "="*70)

    # 执行键盘操作
    if not trigger_moments_refresh_simple():
        print("\n[WARNING] 自动操作可能失败")

    # 监控日志
    success, info = monitor_log_for_callback(timeout=15)

    print("\n" + "="*70)
    print("结果")
    print("="*70)

    if success:
        print("\n[SUCCESS] Hook 回调成功触发！")
        print(f"  时间戳: {info.get('timestamp', 'N/A')} ms")

        content = info.get('content', '')
        if content and content != '<empty>':
            print(f"  内容: {content[:80]}...")
            print("\n[NEXT] 继续运行性能测试：")
            print("  python examples/phase0_timing_test.py")
        else:
            print("  [WARNING] 内容为空，可能需要调整偏移")

    else:
        print("\n[FAIL] 未检测到回调")
        print("\n请手动操作：")
        print("  1. 在微信中打开朋友圈")
        print("  2. 下拉刷新")
        print("  3. 等待几秒后运行：")
        print(f'     tail "{LOG_PATH}"')

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[INTERRUPTED]")
    except Exception as e:
        print(f"\n\n[ERROR] {e}")
        import traceback
        traceback.print_exc()
