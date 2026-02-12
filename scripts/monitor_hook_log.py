"""
实时监控 pywechat_hook.log 中的 SNS_POC 回调

当手动刷新朋友圈时，这个脚本会显示回调触发的信息。
"""

import time
import os

LOG_PATH = r"C:\Program Files\Tencent\Weixin\4.1.7.30\pywechat_hook.log"

def tail_log(filepath, num_lines=10):
    """读取文件最后 N 行"""
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            return f.readlines()[-num_lines:]
    except:
        return []

def main():
    print("="*70)
    print("Phase 0 - 实时日志监控")
    print("="*70)
    print(f"\n监控文件: {LOG_PATH}")
    print("\n等待朋友圈刷新触发 Hook 回调...")
    print("请在微信中：")
    print("  1. 打开朋友圈")
    print("  2. 下拉刷新")
    print("\n按 Ctrl+C 停止监控\n")

    last_size = 0
    if os.path.exists(LOG_PATH):
        last_size = os.path.getsize(LOG_PATH)

    try:
        while True:
            time.sleep(1)

            if not os.path.exists(LOG_PATH):
                continue

            current_size = os.path.getsize(LOG_PATH)

            # 如果文件有新内容
            if current_size > last_size:
                # 读取新增的行
                with open(LOG_PATH, 'r', encoding='utf-8', errors='ignore') as f:
                    f.seek(last_size)
                    new_lines = f.readlines()

                # 过滤 SNS_POC 相关的行
                for line in new_lines:
                    if '[SNS_POC]' in line:
                        # 高亮显示重要信息
                        if 'TRIGGERED' in line:
                            print(f"\n🎯 {line.strip()}")
                        elif 'content' in line.lower():
                            print(f"📝 {line.strip()}")
                        elif 'Timestamp' in line:
                            print(f"⏰ {line.strip()}")
                        else:
                            print(f"   {line.strip()}")

                last_size = current_size

    except KeyboardInterrupt:
        print("\n\n监控已停止")

if __name__ == '__main__':
    main()
