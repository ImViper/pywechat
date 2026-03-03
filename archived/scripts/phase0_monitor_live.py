"""
Phase 0 - 实时监控模式

这个脚本持续监控日志文件，你只需要在微信中随便操作朋友圈即可。
无需精确的自动化操作，任何朋友圈相关操作都可能触发回调。
"""

import sys
import time
import os
import re
from pathlib import Path

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

def monitor_log_continuously():
    """持续监控日志文件"""
    print("="*70)
    print("Phase 0 - 实时监控模式")
    print("="*70)

    if not os.path.exists(LOG_PATH):
        print(f"\n[ERROR] 找不到日志文件: {LOG_PATH}")
        return

    print(f"\n[OK] 正在监控: {LOG_PATH}")
    print(f"     当前大小: {get_log_size()} 字节\n")

    print("="*70)
    print("等待 Hook 回调...")
    print("="*70)
    print("\n请在微信中执行以下任意操作：")
    print("  - 打开朋友圈")
    print("  - 刷新朋友圈（下拉）")
    print("  - 点击任意朋友圈帖子")
    print("  - 发布朋友圈")
    print("  - 点赞或评论")
    print("\n任何朋友圈相关操作都可能触发回调！")
    print("按 Ctrl+C 停止监控\n")
    print("-"*70)

    last_size = get_log_size()
    callback_detected = False
    callback_info = {}

    try:
        while True:
            time.sleep(0.5)

            current_size = get_log_size()
            if current_size <= last_size:
                continue

            # 读取新内容
            with open(LOG_PATH, 'r', encoding='utf-8', errors='ignore') as f:
                f.seek(last_size)
                new_lines = f.readlines()

            last_size = current_size

            # 处理新行
            for line in new_lines:
                # 显示所有 SNS_POC 相关日志
                if '[SNS_POC]' in line:
                    timestamp = time.strftime('%H:%M:%S')

                    if 'TRIGGERED' in line:
                        print(f"\n[{timestamp}] >>> Hook 回调触发！<<<")
                        print(f"    {line.strip()}")
                        callback_detected = True
                        callback_info['triggered'] = True

                    elif 'Timestamp:' in line:
                        match = re.search(r'Timestamp: (\d+) ms', line)
                        if match:
                            ts = int(match.group(1))
                            callback_info['timestamp'] = ts
                            print(f"[{timestamp}]     回调时间戳: {ts} ms")

                    elif 'content:' in line:
                        match = re.search(r'content: (.+)', line)
                        if match:
                            content = match.group(1).strip()
                            callback_info['content'] = content

                            if content and content != '<empty>':
                                print(f"[{timestamp}]     内容: {content[:60]}...")
                            else:
                                print(f"[{timestamp}]     内容: <空> (可能需要调整偏移)")

                    elif 'sns_id:' in line:
                        print(f"[{timestamp}]     {line.strip()}")

                    elif 'create_time:' in line:
                        print(f"[{timestamp}]     {line.strip()}")

                    elif 'Array range:' in line:
                        print(f"[{timestamp}]     {line.strip()}")

                    elif 'Detected' in line and 'posts' in line:
                        print(f"[{timestamp}]     {line.strip()}")

            # 如果检测到回调，等待完整信息后总结
            if callback_detected and 'content' in callback_info:
                time.sleep(2)  # 等待后续日志
                print("\n" + "="*70)
                print("检测结果总结")
                print("="*70)
                print("\n[SUCCESS] Hook 回调成功触发！\n")

                print(f"  回调时间戳: {callback_info.get('timestamp', 'N/A')} ms")

                content = callback_info.get('content', '')
                if content and content != '<empty>':
                    print(f"  读取内容: 成功")
                    print(f"  内容预览: {content[:100]}\n")
                    print("[CONCLUSION] Phase 0 验证成功！")
                    print("\n下一步：运行性能对比测试")
                    print("  python examples/phase0_timing_test.py\n")
                else:
                    print(f"  读取内容: 为空")
                    print("\n[WARNING] 需要调整数据结构偏移")
                    print("  当前偏移: +0x48")
                    print("  可能需要在 sns_moments_poc.cpp 中调整\n")

                print("="*70)
                break

    except KeyboardInterrupt:
        print("\n\n[INTERRUPTED] 监控已停止")

        if not callback_detected:
            print("\n[INFO] 未检测到回调触发")
            print("\n可能原因：")
            print("  1. Hook 函数不是在这些操作时触发")
            print("  2. 需要特定的朋友圈操作（如：下拉刷新）")
            print("  3. 函数地址可能不正确")
            print("\n建议：")
            print("  - 尝试更多不同的朋友圈操作")
            print("  - 检查日志文件完整内容：")
            print(f'    type "{LOG_PATH}"')

if __name__ == '__main__':
    try:
        monitor_log_continuously()
    except Exception as e:
        print(f"\n[ERROR] {e}")
        import traceback
        traceback.print_exc()
