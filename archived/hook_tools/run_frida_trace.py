"""
Frida 动态追踪启动器 —— 自动附加到微信进程并加载追踪脚本。

使用方法:
    python run_frida_trace.py                    # 自动查找微信进程
    python run_frida_trace.py --pid 12345        # 指定 PID
    python run_frida_trace.py --hook 0x1A51DD0   # 直接 hook 某个偏移

前置条件:
    pip install frida frida-tools

工作流程:
    1. 运行本脚本, 附加到微信
    2. 在微信中手动发一条朋友圈评论
    3. 观察输出中 WeChatWin.dll+0x... 的调用栈
    4. 记录候选偏移, 使用 --hook 进一步分析参数
"""

from __future__ import annotations

import argparse
import os
import sys
import time

# 确保能导入项目模块
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))


def find_wechat_pid() -> int | None:
    """查找微信主进程 PID。"""
    try:
        import psutil
    except ImportError:
        print("需要 psutil: pip install psutil")
        return None

    for proc in psutil.process_iter(["pid", "name", "cmdline"]):
        if proc.info["name"] == "Weixin.exe":
            cmdline = proc.info.get("cmdline") or []
            if not any("--type" in arg for arg in cmdline):
                return proc.info["pid"]
    return None


def run_trace(pid: int, hook_offsets: list[str] | None = None,
              script_path: str | None = None):
    """附加 Frida 到微信并运行追踪脚本。"""
    try:
        import frida
    except ImportError:
        print("需要 frida: pip install frida frida-tools")
        print("注意: frida 版本需与目标进程架构匹配 (x64)")
        sys.exit(1)

    # 加载 JS 脚本
    if script_path is None:
        script_path = os.path.join(os.path.dirname(__file__), "frida_trace_comment.js")

    with open(script_path, "r", encoding="utf-8") as f:
        js_code = f.read()

    print(f"[*] Attaching to PID {pid}...")
    try:
        session = frida.attach(pid)
    except frida.ProcessNotFoundError:
        print(f"[!] Process {pid} not found")
        sys.exit(1)
    except frida.PermissionError:
        print("[!] Permission denied. Run as Administrator.")
        sys.exit(1)

    def on_message(message, data):
        if message["type"] == "send":
            print(f"[frida] {message['payload']}")
        elif message["type"] == "error":
            print(f"[frida ERROR] {message.get('description', message)}")

    script = session.create_script(js_code)
    script.on("message", on_message)

    print("[*] Loading script...")
    script.load()

    # 如果指定了 --hook, 发送命令动态 hook
    if hook_offsets:
        for offset in hook_offsets:
            print(f"[*] Sending hook command for offset {offset}")
            script.post({"type": "hook_address", "offset": offset})
            time.sleep(0.5)

    print()
    print("=" * 60)
    print("  Frida 追踪已就绪")
    print("  现在请在微信朋友圈手动发一条评论")
    print("  观察输出中的 WeChatWin.dll+0x... 调用栈")
    print("  按 Ctrl+C 停止")
    print("=" * 60)
    print()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Detaching...")
        session.detach()
        print("[*] Done")


def main():
    parser = argparse.ArgumentParser(
        description="Frida 动态追踪 - 定位微信朋友圈评论函数"
    )
    parser.add_argument("--pid", type=int, help="微信进程 PID (不指定则自动查找)")
    parser.add_argument("--hook", action="append", metavar="OFFSET",
                        help="动态 hook WeChatWin.dll 中的偏移 (可多次指定, 如 --hook 0x1A51DD0)")
    parser.add_argument("--script", help="自定义 Frida JS 脚本路径")
    args = parser.parse_args()

    pid = args.pid
    if pid is None:
        pid = find_wechat_pid()
        if pid is None:
            print("[!] 未找到微信进程, 请确认微信已启动或用 --pid 指定")
            sys.exit(1)
        print(f"[*] Found WeChat PID: {pid}")

    run_trace(pid, hook_offsets=args.hook, script_path=args.script)


if __name__ == "__main__":
    main()
