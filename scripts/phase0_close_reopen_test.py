"""
Phase 0 - 最简单验证方式：关闭重开朋友圈

这个方法最可靠：
1. 关闭朋友圈窗口
2. 重新打开（触发首次网络加载）
3. 对比 Hook 回调时间 vs UI 可见时间
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

from pyweixin.WeChatTools import Navigator, Lists
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

        except Exception:
            pass

        time.sleep(0.2)

    return None

def main():
    print("=" * 70)
    print("Phase 0 - Hook 回调验证（关闭重开法）")
    print("=" * 70)

    if not os.path.exists(LOG_PATH):
        print(f"\n[ERROR] 找不到日志文件: {LOG_PATH}")
        print("请确保 Hook DLL 已注入微信")
        return

    print(f"\n[OK] 日志文件: {LOG_PATH}")
    print(f"     当前大小: {get_log_size()} 字节\n")

    print("此方法最可靠：")
    print("  1. 完全关闭朋友圈窗口")
    print("  2. 重新打开（触发首次网络加载 = GetSNSFirstPage）")
    print("  3. 对比 Hook 回调时间 vs UI 可见时间\n")

    print("自动开始测试...\n")
    print("=" * 70)

    # 先打开朋友圈（如果已经打开会找到现有窗口）
    print("\n[1/5] 查找现有朋友圈窗口...")
    try:
        from pywinauto import Desktop
        desktop = Desktop(backend='uia')
        moments_window = desktop.window(**{"title_re": ".*朋友圈.*", "control_type": "Window"})

        if moments_window.exists(timeout=1):
            print("     ✅ 找到现有窗口，准备关闭...")
            moments_window.close()
            time.sleep(2)
            print("     ✅ 已关闭")
        else:
            print("     ℹ️  未找到现有窗口")
    except Exception as e:
        print(f"     ℹ️  查找窗口失败: {e}（可以继续）")

    # 记录初始日志大小
    initial_log_size = get_log_size()

    print("\n[2/5] 准备重新打开朋友圈...")
    print("     ⏰ 这将触发网络请求，Hook 应该会触发")
    time.sleep(1)

    # 记录开始时间
    refresh_start_time = time.time()
    print(f"\n[3/5] 重新打开朋友圈... (T=0 at {datetime.now().strftime('%H:%M:%S.%f')[:-3]})\n")

    # 重新打开朋友圈
    try:
        moments_window = Navigator.open_moments(is_maximize=False, close_weixin=False)
        print("     ✅ 朋友圈窗口已打开")
    except Exception as e:
        print(f"     ❌ 打开失败: {e}")
        return

    # 同时监控两个时间点
    print("\n[4/5] 监控 Hook 回调和 UI 可见...\n")

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
    print("[5/5] 分析结果")
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
            print("   1. Phase 1: 完整的 Hook 回调和内存快照")
            print("   2. Phase 2: Named Pipe 命令集成")
            print("   3. Phase 3: Python 轮询监控器")
            print("   4. Phase 4: 端到端性能验证")
        else:
            print("\n⚠️ Route B 收益有限或无效")
            print(f"   实际提速: {abs(time_diff):.1f} 秒")
            print("\n建议:")
            print("   - 如果 <1 秒：考虑放弃 Route B")
            print("   - 或探索其他优化方向（Route A 并发发送）")

    elif hook_callback_time:
        print("\n  🎯 Hook 回调：已触发")
        print("  ❌ UI 可见：未检测到")
        print("\n  可能原因：")
        print("    - UI 检测逻辑有误")
        print("    - 朋友圈加载超时")

    elif ui_visible_time:
        print("\n  ❌ Hook 回调：未触发")
        print("  👁️  UI 可见：已检测到")
        print("\n  可能原因：")
        print("    - Hook 地址不正确（虽然签名匹配）")
        print("    - 首次打开没有触发网络请求（数据已缓存）")
        print("    - Hook 回调有异常但未记录")
        print("\n  建议:")
        print("    1. 多试几次（关闭重开）")
        print("    2. 或手动下拉刷新触发")
        print("    3. 检查完整日志")

    else:
        print("\n  ❌ Hook 回调：未触发")
        print("  ❌ UI 可见：未检测到")
        print("\n  可能原因：")
        print("    - 朋友圈打开失败")
        print("    - 网络延迟过长")
        print("\n  建议：手动检查微信窗口")

    print("\n" + "=" * 70)

    # 保持窗口打开以便检查
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
