"""
Phase 0 - Hook 回调时间验证脚本（使用现有代码模式）

参考 run_feed_refresh_listener.py 的模式来触发朋友圈刷新，
对比 Hook 回调时间 vs UI 可见时间。
"""
import sys
import time
import os
import re
from pathlib import Path
from datetime import datetime

# 设置 UTF-8 输出
if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except:
        pass

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "scripts"))

from pyweixin.WeChatTools import Navigator, Lists, mouse
from hook_log_utils import resolve_log_path, extract_latest_timestamp_ms

LOG_PATH = str(resolve_log_path(project_root=PROJECT_ROOT))

def get_log_size():
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
        return f.readlines()

def extract_hook_callback_time(log_lines):
    """从日志行中提取 Hook 回调的时间戳"""
    return extract_latest_timestamp_ms(log_lines)

def check_ui_visibility(moments_window, timeout=10):
    """检查朋友圈 UI 是否可见（有任何帖子显示）"""
    start_time = time.time()

    while (time.time() - start_time) < timeout:
        try:
            # 尝试定位朋友圈列表
            if moments_window is None or not moments_window.exists(timeout=0.1):
                time.sleep(0.2)
                continue

            # 获取朋友圈列表
            feed_list = moments_window.child_window(**Lists.MomentsList)
            if not feed_list.exists(timeout=0.2):
                time.sleep(0.2)
                continue

            # 尝试获取第一个 ListItem
            items = feed_list.children(control_type='ListItem')
            if items and len(items) > 0:
                # UI 可见！
                ui_time_ms = int(time.time() * 1000)
                return ui_time_ms

        except Exception as e:
            # print(f"[DEBUG] check_ui_visibility error: {e}")
            pass

        time.sleep(0.2)

    return None

def main():
    print("=" * 70)
    print("Phase 0 - Hook 回调时间验证（使用现有代码模式）")
    print("=" * 70)

    if not os.path.exists(LOG_PATH):
        print(f"\n[ERROR] 找不到日志文件: {LOG_PATH}")
        print("请确保 Hook DLL 已注入微信")
        return

    print(f"\n[OK] 日志文件: {LOG_PATH}")
    print(f"     当前大小: {get_log_size()} 字节\n")

    print("此脚本将：")
    print("  1. 使用 Navigator.open_moments() 打开朋友圈窗口")
    print("  2. 触发朋友圈刷新")
    print("  3. 同时监控 Hook 回调时间 和 UI 可见时间")
    print("  4. 对比两者，验证 Hook 是否更早\n")

    # Auto-start mode (no user prompt)
    print("自动开始测试...\n")

    print("\n" + "=" * 70)
    print("开始测试...\n")

    # 记录初始日志大小
    initial_log_size = get_log_size()

    # 使用现有模式打开朋友圈
    print("[1/4] 打开朋友圈窗口...")
    try:
        moments_window = Navigator.open_moments(is_maximize=False, close_weixin=False)
        print("     ✅ 朋友圈窗口已打开")
    except Exception as e:
        print(f"     ❌ 打开失败: {e}")
        return

    # 记录刷新开始时间
    refresh_start_time = time.time()
    print(f"\n[2/4] 触发朋友圈刷新... (T=0 at {datetime.now().strftime('%H:%M:%S.%f')[:-3]})")

    # 触发刷新的方式：向下滚动然后向上滚动（模拟下拉刷新）
    try:
        feed_list = moments_window.child_window(**Lists.MomentsList)
        if feed_list.exists(timeout=1):
            feed_list.set_focus()

            # 模拟下拉刷新：快速向上滚动
            for _ in range(3):
                mouse.scroll(coords=feed_list.rectangle().mid_point(), wheel_dist=5)
                time.sleep(0.05)

            print("     ✅ 已触发刷新动作")
        else:
            print("     ⚠️ 未找到朋友圈列表，刷新可能失败")
    except Exception as e:
        print(f"     ⚠️ 刷新动作执行失败: {e}")

    # 同时监控两个时间点
    print("\n[3/4] 同时监控 Hook 回调和 UI 可见...\n")

    hook_callback_time = None
    ui_visible_time = None

    last_log_size = initial_log_size

    # 监控 15 秒
    monitor_timeout = 15
    monitor_start = time.time()

    while (time.time() - monitor_start) < monitor_timeout:
        current_time = time.time() - refresh_start_time

        # 检查 Hook 回调
        if hook_callback_time is None:
            new_lines = read_new_log_lines(last_log_size)
            if new_lines:
                last_log_size = get_log_size()
                callback_ts = extract_hook_callback_time(new_lines)
                if callback_ts:
                    hook_callback_time = callback_ts
                    hook_latency = (callback_ts - int(refresh_start_time * 1000)) / 1000.0
                    print(f"     🎯 Hook 回调触发！ T+{hook_latency:.3f}s")

        # 检查 UI 可见
        if ui_visible_time is None:
            ui_ts = check_ui_visibility(moments_window, timeout=0.5)
            if ui_ts:
                ui_visible_time = ui_ts
                ui_latency = (ui_ts - int(refresh_start_time * 1000)) / 1000.0
                print(f"     👁️  UI 可见！     T+{ui_latency:.3f}s")

        # 如果两个都检测到了，退出
        if hook_callback_time and ui_visible_time:
            break

        time.sleep(0.1)

    # 分析结果
    print("\n" + "=" * 70)
    print("[4/4] 分析结果")
    print("=" * 70)

    if hook_callback_time and ui_visible_time:
        hook_latency = (hook_callback_time - int(refresh_start_time * 1000)) / 1000.0
        ui_latency = (ui_visible_time - int(refresh_start_time * 1000)) / 1000.0

        time_diff = hook_latency - ui_latency

        print(f"\n  Hook 回调时间: T+{hook_latency:.3f}s")
        print(f"  UI 可见时间:   T+{ui_latency:.3f}s")
        print(f"  时间差:        {time_diff:.3f}s")
        print()

        if time_diff < -2.0:
            print("  ✅ 优秀！Hook 比 UI 早 2+ 秒")
            print("  ✅ Route B 有巨大潜力，建议继续 Phase 1-4")
        elif time_diff < -1.0:
            print("  ✅ 良好！Hook 比 UI 早 1-2 秒")
            print("  ✅ Route B 有明显收益，建议继续实施")
        elif time_diff < -0.5:
            print("  ⚠️ 一般。Hook 比 UI 早 0.5-1 秒")
            print("  ⚠️ Route B 有一定收益，但提升有限")
        elif time_diff < 0.5:
            print("  ⚠️ 收益很小（<0.5 秒差异）")
            print("  ⚠️ Route B 可能不值得投入")
        else:
            print("  ❌ Hook 比 UI 更晚或几乎同时")
            print("  ❌ Route B 无效，建议放弃或改用其他方案")

    elif hook_callback_time:
        print("\n  🎯 Hook 回调：已触发")
        print("  ❌ UI 可见：未检测到")
        print("\n  可能原因：")
        print("    - UI 自动化检测逻辑有问题")
        print("    - 朋友圈内容为空")
        print("  建议：手动查看微信窗口，检查是否真的刷新了")

    elif ui_visible_time:
        print("\n  ❌ Hook 回调：未触发")
        print("  👁️  UI 可见：已检测到")
        print("\n  可能原因：")
        print("    - Hook 函数地址不正确")
        print("    - 朋友圈刷新没有调用这个函数")
        print("    - Hook 回调有异常但未记录")
        print("  建议：检查完整日志文件")
        print(f"    type \"{LOG_PATH}\"")

    else:
        print("\n  ❌ Hook 回调：未触发")
        print("  ❌ UI 可见：未检测到")
        print("\n  可能原因：")
        print("    - 朋友圈刷新失败")
        print("    - Hook 未正确安装")
        print("    - 网络延迟或无新内容")
        print("  建议：")
        print("    1. 手动在微信中刷新朋友圈")
        print("    2. 检查日志文件是否有任何 [SNS_POC] 输出")
        print("    3. 重新注入 Hook DLL")

    print("\n" + "=" * 70)

    # 清理
    try:
        moments_window.close()
    except:
        pass

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[INTERRUPTED] 测试被用户中断")
    except Exception as e:
        print(f"\n\n[ERROR] {e}")
        import traceback
        traceback.print_exc()
