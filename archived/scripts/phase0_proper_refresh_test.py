"""
Phase 0 - 正确的刷新测试（使用现有 UI 自动化能力）

参考 moments_ext.py 的实现：点击 RefreshButton 触发真实网络请求
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

from pyweixin.WeChatTools import Navigator, Lists, Buttons
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
            if moments_window is None or not moments_window.exists(timeout=0.1):
                time.sleep(0.2)
                continue

            feed_list = moments_window.child_window(**Lists.MomentsList)
            if not feed_list.exists(timeout=0.2):
                time.sleep(0.2)
                continue

            items = feed_list.children(control_type='ListItem')
            if items and len(items) > 0:
                ui_time_ms = int(time.time() * 1000)
                return ui_time_ms

        except Exception:
            pass

        time.sleep(0.2)

    return None

def main():
    print("=" * 70)
    print("Phase 0 - 正确的刷新测试（点击 RefreshButton）")
    print("=" * 70)

    if not os.path.exists(LOG_PATH):
        print(f"\n[ERROR] 找不到日志文件: {LOG_PATH}")
        print("请确保 Hook DLL 已注入微信")
        return

    print(f"\n[OK] 日志文件: {LOG_PATH}")
    print(f"     当前大小: {get_log_size()} 字节\n")

    print("此方法使用现有 UI 自动化能力：")
    print("  1. 打开朋友圈窗口")
    print("  2. 点击 RefreshButton（触发真实网络请求）")
    print("  3. 对比 Hook 回调时间 vs UI 可见时间\n")

    print("自动开始测试...\n")
    print("=" * 70)

    # 记录初始日志大小
    initial_log_size = get_log_size()

    # 打开朋友圈
    print("\n[1/4] 打开朋友圈窗口...")
    try:
        moments_window = Navigator.open_moments(is_maximize=False, close_weixin=False)
        print("     ✅ 朋友圈窗口已打开")
    except Exception as e:
        print(f"     ❌ 打开失败: {e}")
        return

    # 等待窗口稳定
    time.sleep(0.5)

    # 记录开始时间
    refresh_start_time = time.time()
    print(f"\n[2/4] 点击刷新按钮... (T=0 at {datetime.now().strftime('%H:%M:%S.%f')[:-3]})")

    # 点击 RefreshButton（这是关键！）
    try:
        refresh_button = moments_window.child_window(**Buttons.RefreshButton)
        if refresh_button.exists(timeout=0.5):
            refresh_button.click_input()
            print("     ✅ 已点击刷新按钮（触发网络请求）")
            time.sleep(0.15)  # 等待一小段时间让请求发出
        else:
            print("     ⚠️ 未找到刷新按钮")
            print("     提示：可能朋友圈界面已经是最新状态")
    except Exception as e:
        print(f"     ⚠️ 点击刷新按钮失败: {e}")

    # 同时监控两个时间点
    print("\n[3/4] 监控 Hook 回调和 UI 可见...\n")

    hook_callback_time = None
    ui_visible_time = None

    last_log_size = initial_log_size

    # 监控 15 秒
    monitor_timeout = 15
    monitor_start = time.time()

    while (time.time() - monitor_start) < monitor_timeout:
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
        print(f"  时间差:        {time_diff:+.3f}s (负数 = Hook 更早)")
        print()

        if time_diff < -2.0:
            print("  ✅ 优秀！Hook 比 UI 早 2+ 秒")
            print("  ✅ Route B 有巨大潜力，强烈建议继续 Phase 1-4")
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

        print("\n" + "=" * 70)
        print("Phase 0 核心假设验证结果")
        print("=" * 70)

        if time_diff < -1.0:
            print("\n✅ 成功！Hook 确实比 UI 更早获取数据")
            print(f"   提速潜力: {abs(time_diff):.1f} 秒")
            print("\n下一步: 继续实施 Phase 1-4")
        else:
            print("\n⚠️ Route B 收益有限或无效")
            print(f"   实际提速: {abs(time_diff):.1f} 秒")

    elif hook_callback_time:
        print("\n  🎯 Hook 回调：已触发")
        print("  ❌ UI 可见：未检测到")

    elif ui_visible_time:
        print("\n  ❌ Hook 回调：未触发")
        print("  👁️  UI 可见：已检测到")
        print("\n  分析：")
        print("    - 刷新按钮点击成功，UI 已更新")
        print("    - 但 Hook 未触发，可能原因：")
        print("      1. 朋友圈数据完全来自缓存（无网络请求）")
        print("      2. WeChat 4.1.7.30 使用了不同的刷新 API")
        print("      3. Hook 函数地址虽匹配但实际不是 OnSnsTimeLineSceneFinish")
        print("\n  建议：")
        print("    - 查看完整日志确认 Hook 安装状态")
        print("    - 尝试等待一段时间后再刷新（清除缓存）")
        print("    - 或手动发布新朋友圈后立即刷新")

    else:
        print("\n  ❌ Hook 回调：未触发")
        print("  ❌ UI 可见：未检测到")

    print("\n" + "=" * 70)

    # 保持窗口打开
    print("\n朋友圈窗口保持打开以便检查。")
    print("测试完成。\n")

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[INTERRUPTED] 测试被用户中断")
    except Exception as e:
        print(f"\n\n[ERROR] {e}")
        import traceback
        traceback.print_exc()
