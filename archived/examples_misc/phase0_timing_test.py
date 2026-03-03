"""
Phase 0: Route B 去风险实验 - 时间对比测试

验证 Hook OnSnsTimeLineSceneFinish 回调是否比 UI 刷新更早拿到数据。

测试流程：
1. 打开朋友圈窗口
2. 提示用户手动刷新朋友圈（下拉刷新）
3. 轮询 UI，检测第一条帖子何时可见
4. 记录 UI 可见时间戳
5. 读取 DLL log (pywechat_hook.log)，提取 Hook 回调时间戳
6. 对比时间差，判断 Hook 是否比 UI 更早

成功标准：
- Hook 回调比 UI 可见提前 ≥2 秒 → 继续 Phase 1
- Hook 回调比 UI 可见提前 <1 秒 → 收益有限，重新评估
- Hook 回调和 UI 几乎同时或更晚 → Route B 无效，放弃
"""

import os
import sys
import time
from datetime import datetime
from pathlib import Path

from pyweixin.WeChatTools import Navigator, Desktop, Tools
from pyweixin.Uielements import Windows, Lists

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
from scripts.hook_log_utils import extract_timestamps_ms, resolve_log_path

desktop = Desktop(backend='uia')

LOG_PATH = resolve_log_path(project_root=PROJECT_ROOT)


def parse_dll_log_timestamps(log_path: Path = LOG_PATH) -> list[int]:
    """解析 DLL log，提取 [SNS_POC] 回调触发的时间戳（毫秒）"""
    if not log_path.exists():
        print(f"[WARNING] DLL log not found at: {log_path}")
        return []

    # 读取最后 500 行（避免读取整个文件）
    with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()
        recent_lines = lines[-500:] if len(lines) > 500 else lines
    return extract_timestamps_ms(recent_lines)


def wait_for_first_post_visible(moments_window, timeout: float = 10.0) -> tuple[int, str]:
    """
    轮询朋友圈窗口，等待第一条帖子可见。

    Returns:
        (timestamp_ms, content_preview) - 帖子可见时的时间戳（毫秒）和内容预览
        如果超时，返回 (0, "")
    """
    start_time = time.time()
    poll_interval = 0.1  # 100ms 轮询间隔

    print("[UI_POLL] Waiting for first post to appear in UI...")

    while (time.time() - start_time) < timeout:
        try:
            # 定位朋友圈列表
            moments_list = moments_window.child_window(**Lists.MomentsList)

            if not moments_list.exists(timeout=0.1):
                time.sleep(poll_interval)
                continue

            # 获取列表中的第一个 ListItem
            items = moments_list.children(control_type='ListItem')

            if not items or len(items) == 0:
                time.sleep(poll_interval)
                continue

            # 找到第一个有效帖子（跳过"朋友圈"标题）
            for item in items[:3]:  # 只检查前 3 个
                try:
                    # 尝试提取文本内容
                    text_children = item.descendants(control_type='Text')
                    if text_children:
                        # 简单启发式：找到第一个非空文本
                        for text_ctrl in text_children:
                            content = text_ctrl.window_text()
                            if content and len(content) > 5:
                                # 找到了有效内容
                                ts_ms = int(time.time() * 1000)
                                preview = content[:100]
                                print(f"[UI_POLL] First post detected: {preview}")
                                return (ts_ms, preview)

                except Exception as e:
                    # 单个 item 解析失败，继续下一个
                    pass

            time.sleep(poll_interval)

        except Exception as e:
            # UI 结构还没准备好，继续轮询
            time.sleep(poll_interval)

    # 超时
    print("[UI_POLL] Timeout - no post detected in UI")
    return (0, "")


def run_single_test(moments_window, test_num: int) -> dict:
    """
    运行单次测试：
    1. 提示用户手动刷新朋友圈
    2. 同时开始轮询 UI
    3. 对比 Hook 回调时间戳和 UI 可见时间戳
    """
    print(f"\n{'='*60}")
    print(f"Test #{test_num}")
    print(f"{'='*60}")

    # 记录已有回调时间戳数量，避免误用历史日志。
    existing_timestamps = parse_dll_log_timestamps()
    existing_count = len(existing_timestamps)

    input("[INSTRUCTION] 按 Enter 后，请立即手动下拉刷新朋友圈...")
    test_start_ms = int(time.time() * 1000)

    # 开始轮询 UI
    ui_ts_ms, content_preview = wait_for_first_post_visible(moments_window, timeout=15.0)

    if ui_ts_ms == 0:
        print("[ERROR] UI 超时，未检测到帖子")
        return {
            'test_num': test_num,
            'success': False,
            'error': 'UI timeout'
        }

    ui_latency = (ui_ts_ms - test_start_ms) / 1000.0
    print(f"[UI_VISIBLE] T={ui_latency:.2f}s, content={content_preview[:50]}")

    # 等待 2 秒，确保 DLL log 已写入
    time.sleep(2)

    # 读取 DLL log，提取 Hook 回调时间戳
    dll_timestamps = parse_dll_log_timestamps()

    if not dll_timestamps:
        print("[ERROR] 未在 DLL log 中找到 [SNS_POC] 时间戳")
        print("[HINT] 检查 Hook 是否安装成功，查看 pywechat_hook.log")
        return {
            'test_num': test_num,
            'success': False,
            'error': 'No DLL callback detected'
        }

    # 仅看本轮新增日志，再按时间过滤。
    new_timestamps = dll_timestamps[existing_count:]
    recent_ts = [ts for ts in new_timestamps if ts >= test_start_ms]

    if not recent_ts:
        fallback_ts = [ts for ts in dll_timestamps if ts >= test_start_ms]
        if not fallback_ts:
            print("[ERROR] DLL log 中没有本次测试的时间戳")
            return {
                'test_num': test_num,
                'success': False,
                'error': 'No matching DLL timestamp'
            }
        recent_ts = fallback_ts
        print("[WARNING] 未定位到本轮新增时间戳，回退使用全量日志过滤结果")

    # 使用本轮最早触发的回调，避免选到后续噪声回调。
    hook_ts_ms = recent_ts[0]
    hook_latency = (hook_ts_ms - test_start_ms) / 1000.0

    print(f"[HOOK_CALLBACK] T={hook_latency:.2f}s (from DLL log)")

    # 计算时间差
    delta_s = (ui_ts_ms - hook_ts_ms) / 1000.0

    print(f"\n[RESULT] Hook 回调 vs UI 可见:")
    print(f"  Hook:  T={hook_latency:.2f}s")
    print(f"  UI:    T={ui_latency:.2f}s")
    print(f"  Delta: {delta_s:.2f}s")

    if delta_s > 2.0:
        print(f"  ✅ Hook 提前 {delta_s:.2f}s，Route B 有效！")
        verdict = "success_major"
    elif delta_s > 1.0:
        print(f"  ⚠️  Hook 提前 {delta_s:.2f}s，收益有限")
        verdict = "success_minor"
    elif delta_s > 0:
        print(f"  ⚠️  Hook 提前 {delta_s:.2f}s，几乎同时")
        verdict = "marginal"
    else:
        print(f"  ❌ Hook 更晚 {-delta_s:.2f}s，Route B 无效")
        verdict = "fail"

    return {
        'test_num': test_num,
        'success': True,
        'hook_latency': hook_latency,
        'ui_latency': ui_latency,
        'delta': delta_s,
        'verdict': verdict,
    }


def main():
    """主测试流程"""
    print("="*70)
    print("Phase 0: Route B 去风险实验")
    print("="*70)
    print()
    print("测试目标：验证 Hook OnSnsTimeLineSceneFinish 是否比 UI 刷新更早")
    print()
    print("前置条件：")
    print("  1. Hook DLL 已编译并注入微信")
    print("  2. 在 pywechat_hook.log 中能看到 [SNS_POC] 日志")
    print("  3. 朋友圈有足够的测试帖子（建议发布 5-10 条）")
    print()

    input("按 Enter 开始测试...")

    # 打开朋友圈窗口
    print("[SETUP] Opening Moments window...")
    moments_window = Navigator.open_moments(is_maximize=False, close_weixin=False)
    print("[SETUP] Moments window opened")

    # 运行 5 次测试
    num_tests = 5
    results = []

    for i in range(1, num_tests + 1):
        result = run_single_test(moments_window, i)
        results.append(result)

        if i < num_tests:
            print("\n等待 3 秒后进行下一次测试...")
            time.sleep(3)

    # 汇总结果
    print("\n" + "="*70)
    print("测试汇总")
    print("="*70)

    successful_results = [r for r in results if r['success']]

    if not successful_results:
        print("❌ 所有测试都失败了，无法判断 Hook 是否有效")
        print("   请检查：")
        print("   1. Hook DLL 是否正确注入")
        print("   2. pywechat_hook.log 中是否有 [SNS_POC] 日志")
        print("   3. 函数签名是否正确（可能需要从 IDA 提取）")
        return

    deltas = [r['delta'] for r in successful_results]
    avg_delta = sum(deltas) / len(deltas)
    max_delta = max(deltas)
    min_delta = min(deltas)

    print(f"\n成功测试数: {len(successful_results)}/{num_tests}")
    print(f"平均提前: {avg_delta:.2f}s")
    print(f"最大提前: {max_delta:.2f}s")
    print(f"最小提前: {min_delta:.2f}s")

    # 判断
    print("\n" + "="*70)
    print("最终判断")
    print("="*70)

    if avg_delta >= 2.0:
        print(f"✅ Phase 0 成功！")
        print(f"   Hook 回调平均提前 {avg_delta:.2f}s，Route B 值得推进")
        print(f"   预期提速：13s → {13 - avg_delta:.1f}s")
        print(f"\n下一步：开始 Phase 1 - 实现完整 Hook + 内存快照")
    elif avg_delta >= 1.0:
        print(f"⚠️  Phase 0 部分成功")
        print(f"   Hook 回调平均提前 {avg_delta:.2f}s，收益有限")
        print(f"   预期提速：13s → {13 - avg_delta:.1f}s")
        print(f"\n建议：评估 ROI，考虑是否值得继续")
    else:
        print(f"❌ Phase 0 失败")
        print(f"   Hook 回调平均提前 {avg_delta:.2f}s，几乎无收益")
        print(f"\n建议：放弃 Route B，考虑其他方案：")
        print(f"   1. Hook UI 渲染函数（Windows GDI/DirectX）")
        print(f"   2. 监听 Windows 消息队列（WM_PAINT）")
        print(f"   3. 接受当前 13s 性能，优化其他环节")

    print()


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n测试被用户中断")
    except Exception as e:
        print(f"\n\n[ERROR] 测试异常: {e}")
        import traceback
        traceback.print_exc()
