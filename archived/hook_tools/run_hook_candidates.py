"""
运行 Frida hook 候选函数脚本，将输出保存到日志文件。

用法:
    python run_hook_candidates.py
    python run_hook_candidates.py --pid 38360
    python run_hook_candidates.py --timeout 120

在微信朋友圈手动发一条评论后, 按 Ctrl+C 停止，查看 hook_candidates_log.txt
"""

import argparse
import datetime
import os
import sys
import time

try:
    import frida
except ImportError:
    print("ERROR: pip install frida frida-tools")
    sys.exit(1)

try:
    import psutil
except ImportError:
    psutil = None


def find_wechat_pid():
    """找到加载了 Weixin.dll 的主微信进程."""
    if psutil is None:
        raise RuntimeError("psutil not installed, specify --pid manually")
    candidates = []
    for p in psutil.process_iter(['pid', 'name', 'create_time']):
        if p.info['name'] and p.info['name'].lower() in ('weixin.exe', 'wechat.exe'):
            candidates.append(p)
    if not candidates:
        raise RuntimeError("WeChat process not found")
    for p in candidates:
        try:
            for m in p.memory_maps():
                if 'weixin.dll' in m.path.lower():
                    return p.pid
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            continue
    candidates.sort(key=lambda p: p.info['create_time'])
    return candidates[0].pid


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--pid", type=int, default=0)
    parser.add_argument("--timeout", type=int, default=300,
                        help="Max seconds to wait (default: 300)")
    parser.add_argument("--output", default="hook_candidates_log.txt")
    args = parser.parse_args()

    pid = args.pid or find_wechat_pid()
    print(f"[*] Attaching to PID {pid}...")

    # Load JS
    script_dir = os.path.dirname(os.path.abspath(__file__))
    js_path = os.path.join(script_dir, "hook_candidates.js")
    with open(js_path, "r", encoding="utf-8") as f:
        js_code = f.read()

    # Open log
    log_path = os.path.join(script_dir, args.output)
    log = open(log_path, "w", encoding="utf-8")
    log.write(f"# Hook Candidates Log - {datetime.datetime.now()}\n")
    log.write(f"# PID: {pid}\n\n")

    def on_message(message, data):
        if message['type'] == 'send':
            payload = message['payload']
            print(payload)
            log.write(payload + "\n")
            log.flush()
        elif message['type'] == 'error':
            err = message.get('description', str(message))
            print(f"[ERROR] {err}")
            log.write(f"[ERROR] {err}\n")
            log.flush()

    session = frida.attach(pid)
    script = session.create_script(js_code)
    script.on('message', on_message)
    script.load()

    print(f"\n[*] Hooks active! Waiting up to {args.timeout}s...")
    print(f"[*] Go to WeChat Moments and post a comment NOW")
    print(f"[*] Log file: {log_path}")
    print(f"[*] Press Ctrl+C to stop early\n")

    try:
        start = time.time()
        while time.time() - start < args.timeout:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Interrupted by user")

    print("[*] Detaching...")
    script.unload()
    session.detach()
    log.close()
    print(f"[*] Log saved to: {log_path}")


if __name__ == "__main__":
    main()
