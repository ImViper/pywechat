"""
Phase 0 - 持续刷新朋友圈测试（2 分钟）

每隔 10 秒点击一次 RefreshButton，持续 2 分钟
实时监控 Hook 回调，任何时候触发都会立即显示
"""
import sys
import time
import os
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

from pyweixin.WeChatTools import Navigator, Buttons, desktop, Windows
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

def check_for_hook_trigger(last_log_size):
    """检查是否有新的 Hook 触发"""
    new_lines = read_new_log_lines(last_log_size)
    if not new_lines:
        return None, last_log_size

    # 更新 log size
    new_log_size = get_log_size()

    # 检查是否有触发
    trigger_time = extract_latest_timestamp_ms(new_lines)
    if trigger_time:
        # 打印完整的触发信息
        print("\n" + "=" * 70)
        print("🎯 Hook 回调触发！")
        print("=" * 70)
        for line in new_lines:
            if '[SNS_POC]' in line:
                print(f"  {line.strip()}")
        print("=" * 70 + "\n")
        return trigger_time, new_log_size

    return None, new_log_size

def main():
    print("=" * 70)
    print("Phase 0 - 持续刷新测试（2 分钟）")
    print("=" * 70)

    if not os.path.exists(LOG_PATH):
        print(f"\n[ERROR] 找不到日志文件: {LOG_PATH}")
        print("请确保 Hook DLL 已注入微信")
        return

    print(f"\n[OK] 日志文件: {LOG_PATH}")
    print(f"     当前大小: {get_log_size()} 字节\n")

    print("测试策略：")
    print("  - 持续时间: 2 分钟")
    print("  - 刷新间隔: 10 秒")
    print("  - 预计刷新次数: ~12 次")
    print("  - 实时监控 Hook 日志\n")

    print("提示：如果期间有新朋友圈发布，更容易触发 Hook！\n")
    print("开始测试...\n")
    print("=" * 70)

    # 打开朋友圈
    print("\n[1/3] 查找或打开朋友圈窗口...")
    moments_window = None

    # 先尝试查找已存在的朋友圈窗口
    try:
        from pyweixin.WeChatTools import desktop, Windows
        existing_window = desktop.window(**Windows.MomentsWindow)
        if existing_window.exists(timeout=1):
            moments_window = existing_window
            print("     ✅ 找到已打开的朋友圈窗口\n")
    except Exception:
        pass

    # 如果没有找到，尝试打开
    if moments_window is None:
        try:
            moments_window = Navigator.open_moments(is_maximize=False, close_weixin=False)
            print("     ✅ 朋友圈窗口已打开\n")
        except Exception as e:
            print(f"     ❌ 打开失败: {e}")
            print("\n提示：请手动打开微信朋友圈，然后重新运行此脚本")
            return

    # 初始日志大小
    last_log_size = get_log_size()

    # 测试参数
    total_duration = 120  # 2 分钟
    refresh_interval = 10  # 10 秒刷新一次
    start_time = time.time()
    refresh_count = 0
    hook_triggered = False
    hook_trigger_times = []

    print("[2/3] 开始持续刷新...\n")

    try:
        while (time.time() - start_time) < total_duration:
            elapsed = time.time() - start_time
            remaining = total_duration - elapsed

            # 刷新操作
            refresh_count += 1
            timestamp = datetime.now().strftime('%H:%M:%S')
            print(f"[{timestamp}] 刷新 #{refresh_count} (剩余 {int(remaining)}s)...", end=' ')

            try:
                refresh_button = moments_window.child_window(**Buttons.RefreshButton)
                if refresh_button.exists(timeout=0.5):
                    refresh_button.click_input()
                    print("✅ 已点击")
                else:
                    print("⚠️ 未找到刷新按钮")
            except Exception as e:
                print(f"❌ 失败: {e}")

            # 等待并持续监控 Hook 日志
            monitor_start = time.time()
            while (time.time() - monitor_start) < refresh_interval:
                # 检查 Hook 触发
                trigger_time, last_log_size = check_for_hook_trigger(last_log_size)
                if trigger_time:
                    hook_triggered = True
                    hook_trigger_times.append({
                        'refresh_num': refresh_count,
                        'timestamp': trigger_time,
                        'elapsed': time.time() - start_time
                    })

                # 检查是否到了总时长
                if (time.time() - start_time) >= total_duration:
                    break

                time.sleep(0.1)  # 每 100ms 检查一次日志

            # 如果到了总时长，退出
            if (time.time() - start_time) >= total_duration:
                break

    except KeyboardInterrupt:
        print("\n\n⚠️ 用户中断测试")
        elapsed = time.time() - start_time
        print(f"已运行 {elapsed:.1f} 秒，执行了 {refresh_count} 次刷新")

    # 最后再检查一次日志（可能有延迟的触发）
    print("\n检查最终日志...")
    time.sleep(0.5)
    trigger_time, last_log_size = check_for_hook_trigger(last_log_size)
    if trigger_time and not hook_triggered:
        hook_triggered = True
        hook_trigger_times.append({
            'refresh_num': refresh_count,
            'timestamp': trigger_time,
            'elapsed': time.time() - start_time
        })

    # 分析结果
    print("\n" + "=" * 70)
    print("[3/3] 测试结果")
    print("=" * 70)

    elapsed_total = time.time() - start_time
    print(f"\n  总运行时间: {elapsed_total:.1f} 秒")
    print(f"  刷新次数:   {refresh_count} 次")
    print(f"  Hook 触发:  {'✅ 是' if hook_triggered else '❌ 否'}")

    if hook_triggered:
        print(f"\n  🎯 Hook 触发详情:")
        for i, trigger in enumerate(hook_trigger_times, 1):
            print(f"     触发 #{i}:")
            print(f"       - 时间戳: {trigger['timestamp']} ms")
            print(f"       - 发生在第 {trigger['refresh_num']} 次刷新后")
            print(f"       - 测试进行到 {trigger['elapsed']:.1f} 秒时")

        print("\n" + "=" * 70)
        print("✅ Phase 0 验证成功！")
        print("=" * 70)
        print("\nHook 确实可以被触发！这意味着：")
        print("  1. Hook 函数地址正确")
        print("  2. WeChat 4.1.7.30 确实调用了 OnSnsTimeLineSceneFinish")
        print("  3. Route B 是可行的！")
        print("\n下一步: 继续实施 Phase 1-4")
        print("  - Phase 1: 完整的 Hook 回调和内存快照")
        print("  - Phase 2: Named Pipe 命令集成")
        print("  - Phase 3: Python 轮询监控器")
        print("  - Phase 4: 端到端性能验证")

    else:
        print("\n  分析:")
        print(f"    - 执行了 {refresh_count} 次刷新，持续 {elapsed_total:.1f} 秒")
        print("    - Hook 从未触发")
        print("\n  可能原因:")
        print("    1. 朋友圈没有新内容（最可能）")
        print("       → 建议：发布新朋友圈或等朋友发布后再测试")
        print("    2. WeChat 4.1.7.30 不再使用此函数")
        print("       → 建议：需要逆向新版本找到新的函数")
        print("    3. RefreshButton 只刷新 UI 缓存，不发起网络请求")
        print("       → 建议：尝试其他触发方式（滚动到底部加载更多）")
        print("\n  建议下一步:")
        print("    - 方案 1: 发布一条测试朋友圈后立即重新运行此脚本")
        print("    - 方案 2: 使用 Wireshark/Fiddler 监控网络请求")
        print("    - 方案 3: 放弃 Route B，专注 Route A 优化")

    print("\n" + "=" * 70)
    print("\n朋友圈窗口保持打开。测试完成。\n")

if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        print(f"\n\n[ERROR] {e}")
        import traceback
        traceback.print_exc()
