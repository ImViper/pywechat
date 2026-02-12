"""
Phase 0 完全自动化测试脚本

自动执行以下操作：
1. 使用 pyautogui 打开微信朋友圈
2. 模拟下拉刷新操作
3. 监控日志文件等待回调触发
4. 验证回调成功并提取时间戳
"""

import sys
import time
import os
import re
import pyautogui
import subprocess
from pathlib import Path

# 设置 UTF-8 输出（避免 Windows 编码问题）
if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except:
        pass

LOG_PATH = r"C:\Program Files\Tencent\Weixin\4.1.7.30\pywechat_hook.log"

def get_log_size():
    """获取日志文件大小"""
    if os.path.exists(LOG_PATH):
        return os.path.getsize(LOG_PATH)
    return 0

def read_new_log_lines(last_size):
    """读取日志文件的新内容"""
    if not os.path.exists(LOG_PATH):
        return []

    current_size = os.path.getsize(LOG_PATH)
    if current_size <= last_size:
        return []

    with open(LOG_PATH, 'r', encoding='utf-8', errors='ignore') as f:
        f.seek(last_size)
        new_lines = f.readlines()

    return new_lines

def find_wechat_window():
    """查找微信窗口"""
    try:
        # 尝试激活微信窗口
        result = subprocess.run(
            ['powershell', '-Command',
             '$w = Get-Process | Where-Object {$_.MainWindowTitle -like "*微信*"}; if($w){$w.MainWindowHandle}'],
            capture_output=True,
            text=True,
            timeout=5
        )

        if result.stdout.strip():
            return True
    except:
        pass

    return False

def open_moments_and_refresh():
    """打开朋友圈并刷新"""
    print("\n[1/5] 查找微信窗口...")

    if not find_wechat_window():
        print("   ❌ 未找到微信窗口，请确保微信已打开")
        return False

    print("   ✅ 找到微信窗口")

    # 等待一下确保窗口激活
    time.sleep(1)

    print("\n[2/5] 模拟点击朋友圈...")

    # 方法1：尝试使用快捷键（如果有）
    # 方法2：模拟鼠标点击朋友圈图标

    # 由于不同微信版本界面可能不同，我们使用通用方法：
    # 1. 点击窗口中间偏左的位置（通常是朋友圈图标所在）

    try:
        # 获取屏幕尺寸
        screen_width, screen_height = pyautogui.size()

        # 假设微信窗口在屏幕左侧，朋友圈图标在左侧栏
        # 这里使用相对保守的坐标
        click_x = 100  # 左侧栏大约位置
        click_y = 400  # 中间偏下

        print(f"   尝试点击位置: ({click_x}, {click_y})")
        pyautogui.click(click_x, click_y)

        time.sleep(2)  # 等待朋友圈窗口打开

        print("   ✅ 已点击（假设打开了朋友圈）")

    except Exception as e:
        print(f"   ⚠️ 自动点击失败: {e}")
        print("   请手动打开朋友圈窗口")
        input("   按 Enter 继续...")

    print("\n[3/5] 模拟下拉刷新...")

    try:
        # 获取当前鼠标位置
        current_x, current_y = pyautogui.position()

        # 在朋友圈区域中心位置下拉
        # 假设朋友圈窗口在屏幕中央偏右
        refresh_start_x = screen_width // 2 + 200
        refresh_start_y = 200

        # 向下拖动模拟刷新
        pyautogui.moveTo(refresh_start_x, refresh_start_y, duration=0.2)
        pyautogui.drag(0, 200, duration=0.5, button='left')

        print(f"   ✅ 已执行下拉刷新动作")

        time.sleep(1)

    except Exception as e:
        print(f"   ⚠️ 自动刷新失败: {e}")
        print("   请手动下拉刷新朋友圈")
        input("   按 Enter 继续...")

    return True

def monitor_log_for_callback(timeout=10):
    """监控日志等待回调触发"""
    print(f"\n[4/5] 监控日志文件 (最多等待 {timeout} 秒)...")

    last_size = get_log_size()
    start_time = time.time()

    callback_triggered = False
    callback_timestamp = None
    callback_content = None

    while (time.time() - start_time) < timeout:
        new_lines = read_new_log_lines(last_size)

        if new_lines:
            last_size = get_log_size()

            for line in new_lines:
                # 检查是否有 TRIGGERED
                if '[SNS_POC]' in line and 'TRIGGERED' in line:
                    callback_triggered = True
                    print(f"   🎯 检测到回调触发！")
                    print(f"      {line.strip()}")

                # 提取时间戳
                if '[SNS_POC]' in line and 'Timestamp:' in line:
                    match = re.search(r'Timestamp: (\d+) ms', line)
                    if match:
                        callback_timestamp = int(match.group(1))
                        print(f"   ⏰ 回调时间戳: {callback_timestamp} ms")

                # 提取 content
                if '[SNS_POC]' in line and 'content:' in line:
                    match = re.search(r'content: (.+)', line)
                    if match:
                        callback_content = match.group(1).strip()
                        print(f"   📝 读取到内容: {callback_content[:50]}...")

        if callback_triggered:
            break

        time.sleep(0.5)

    print("\n[5/5] 验证结果...")

    if callback_triggered:
        print("   ✅ Hook 回调成功触发！")

        if callback_content and callback_content != '<empty>':
            print("   ✅ 成功读取到 post 内容！")
            print(f"\n   内容预览: {callback_content[:100]}")
        else:
            print("   ⚠️ 读取到的内容为空")
            print("   可能需要调整数据结构偏移")

        return True, callback_timestamp
    else:
        print("   ❌ 超时：未检测到回调触发")
        print("   可能原因：")
        print("   1. 朋友圈没有成功刷新")
        print("   2. Hook 函数地址不正确")
        print("   3. 朋友圈刷新使用了不同的 API")
        return False, None

def main():
    print("="*70)
    print("Phase 0 - 完全自动化测试")
    print("="*70)
    print("\n目标：自动打开朋友圈、刷新、验证 Hook 回调")
    print()

    # 检查日志文件
    if not os.path.exists(LOG_PATH):
        print(f"❌ 错误：找不到日志文件")
        print(f"   路径: {LOG_PATH}")
        return

    print(f"✅ 日志文件: {LOG_PATH}")
    print(f"   当前大小: {get_log_size()} 字节")
    print()

    # 安全提示
    print("⚠️ 注意：此脚本将控制鼠标和键盘")
    print("   如需中断，请移动鼠标到屏幕角落（pyautogui 安全机制）")
    print()

    response = input("准备开始自动化测试？(y/n): ")
    if response.lower() != 'y':
        print("已取消")
        return

    print("\n开始自动化测试...\n")

    # 执行自动化操作
    if not open_moments_and_refresh():
        print("\n自动化操作失败，请手动操作")
        return

    # 监控日志
    success, timestamp = monitor_log_for_callback(timeout=15)

    print("\n" + "="*70)
    print("测试结果总结")
    print("="*70)

    if success:
        print("\n🎉 Phase 0 自动化测试：成功！")
        print(f"   回调时间戳: {timestamp} ms")
        print("\n✅ Hook 功能正常，可以继续 Phase 1-4")
        print("\n下一步：运行性能对比测试")
        print("   python examples/phase0_timing_test.py")
    else:
        print("\n⚠️ Phase 0 自动化测试：未完成")
        print("\n建议手动操作：")
        print("   1. 打开微信朋友圈")
        print("   2. 下拉刷新")
        print("   3. 检查日志：")
        print(f'      tail "C:\\Program Files\\Tencent\\Weixin\\4.1.7.30\\pywechat_hook.log"')

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n测试被用户中断")
    except Exception as e:
        print(f"\n\n错误: {e}")
        import traceback
        traceback.print_exc()
