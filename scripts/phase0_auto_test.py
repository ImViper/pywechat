"""
Phase 0 自动化测试脚本

简化编译、注入、验证流程。

用法:
    python scripts/phase0_auto_test.py --build       # 只编译 DLL
    python scripts/phase0_auto_test.py --inject      # 只注入 DLL
    python scripts/phase0_auto_test.py --all         # 全流程（推荐）
"""

import os
import sys
import time
import subprocess
import argparse
from pathlib import Path

# 项目根目录
PROJECT_ROOT = Path(__file__).parent.parent
HOOK_BUILD_DIR = PROJECT_ROOT / "hook" / "build"
DLL_PATH = HOOK_BUILD_DIR / "bin" / "Release" / "pywechat_hook.dll"
LOG_PATH = PROJECT_ROOT / "pywechat_hook.log"


def run_command(cmd: str, cwd: Path = None, shell: bool = True) -> bool:
    """运行命令，返回是否成功"""
    print(f"[CMD] {cmd}")
    try:
        result = subprocess.run(
            cmd,
            shell=shell,
            cwd=cwd,
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='ignore'
        )
        if result.returncode != 0:
            print(f"[ERROR] Command failed with code {result.returncode}")
            if result.stderr:
                print(f"[STDERR] {result.stderr}")
            return False
        if result.stdout:
            print(result.stdout)
        return True
    except Exception as e:
        print(f"[ERROR] Exception: {e}")
        return False


def kill_wechat():
    """关闭微信进程"""
    print("\n[STEP 1] Killing WeChat...")
    run_command("taskkill /F /IM Weixin.exe", shell=True)
    time.sleep(3)
    print("[OK] WeChat killed")


def start_wechat():
    """启动微信"""
    print("\n[STEP 2] Starting WeChat...")
    wechat_path = r"C:\Program Files\Tencent\Weixin\Weixin.exe"

    if not os.path.exists(wechat_path):
        wechat_path = r"C:\Program Files (x86)\Tencent\Weixin\Weixin.exe"

    if not os.path.exists(wechat_path):
        print(f"[ERROR] WeChat not found at default paths")
        return False

    subprocess.Popen(f'start "" "{wechat_path}"', shell=True)

    print("[WAIT] Waiting 5 seconds for WeChat to initialize...")
    time.sleep(5)
    print("[OK] WeChat started")
    return True


def get_wechat_pid() -> int:
    """获取微信主进程 PID（内存 >100MB 的那个）"""
    print("\n[STEP 3] Finding WeChat main process...")

    try:
        result = subprocess.run(
            'tasklist /FI "IMAGENAME eq Weixin.exe" /FO CSV /NH',
            shell=True,
            capture_output=True,
            text=True,
            encoding='gbk'
        )

        lines = result.stdout.strip().split('\n')
        candidates = []

        for line in lines:
            if 'Weixin.exe' in line:
                parts = line.replace('"', '').split(',')
                if len(parts) >= 5:
                    pid = int(parts[1].strip())
                    # 提取内存（格式: "123,456 K"）
                    mem_str = parts[4].strip().replace(' K', '').replace(',', '')
                    mem_kb = int(mem_str)
                    candidates.append((pid, mem_kb))

        # 选择内存 >100MB 的进程
        main_processes = [(pid, mem) for pid, mem in candidates if mem > 100000]

        if not main_processes:
            print(f"[ERROR] No main WeChat process found (memory >100MB)")
            print(f"[DEBUG] Found processes: {candidates}")
            return 0

        # 选择内存最大的（通常是主进程）
        pid, mem = max(main_processes, key=lambda x: x[1])
        print(f"[OK] Found main process: PID={pid}, Memory={mem/1024:.1f}MB")
        return pid

    except Exception as e:
        print(f"[ERROR] Failed to get WeChat PID: {e}")
        return 0


def build_dll():
    """编译 Hook DLL"""
    print("\n[STEP 4] Building Hook DLL...")

    if not HOOK_BUILD_DIR.exists():
        print(f"[ERROR] Build directory not found: {HOOK_BUILD_DIR}")
        print(f"[HINT] Run: cd hook && mkdir build && cd build && cmake ..")
        return False

    if not run_command("cmake --build . --config Release", cwd=HOOK_BUILD_DIR):
        print(f"[ERROR] Build failed")
        return False

    if not DLL_PATH.exists():
        print(f"[ERROR] DLL not found: {DLL_PATH}")
        return False

    print(f"[OK] DLL built: {DLL_PATH}")
    return True


def inject_dll(pid: int):
    """注入 DLL"""
    print(f"\n[STEP 5] Injecting DLL into PID {pid}...")

    if not DLL_PATH.exists():
        print(f"[ERROR] DLL not found: {DLL_PATH}")
        return False

    # 使用 Python 代码注入
    inject_code = f"""
import sys
sys.path.insert(0, r'{PROJECT_ROOT}')
from pyweixin.hook_injector import inject_dll
result = inject_dll({pid}, r'{DLL_PATH}')
print('[OK] DLL injected' if result else '[ERROR] Injection failed')
"""

    result = subprocess.run(
        [sys.executable, '-c', inject_code],
        capture_output=True,
        text=True,
        encoding='utf-8',
        errors='ignore'
    )

    print(result.stdout)
    if result.stderr:
        print(f"[STDERR] {result.stderr}")

    return result.returncode == 0


def verify_hook():
    """验证 Hook 是否安装成功"""
    print("\n[STEP 6] Verifying Hook installation...")

    # 等待 2 秒让 DLL 初始化
    time.sleep(2)

    if not LOG_PATH.exists():
        print(f"[ERROR] Log file not found: {LOG_PATH}")
        print(f"[HINT] DLL might not be loaded")
        return False

    # 读取最后 50 行
    with open(LOG_PATH, 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()
        recent_lines = lines[-50:] if len(lines) > 50 else lines

    # 检查关键日志
    hook_installed = False
    poc_installed = False

    for line in recent_lines:
        if '[SNS_POC] Hook installed successfully' in line:
            poc_installed = True
        if 'comment hook installed' in line:
            hook_installed = True

    print("\n[VERIFICATION]")
    print(f"  Comment hook: {'✅' if hook_installed else '❌'}")
    print(f"  SNS PoC hook: {'✅' if poc_installed else '⚠️  NOT INSTALLED'}")

    if not poc_installed:
        print("\n[HINT] SNS PoC hook not installed. Possible reasons:")
        print("  1. Function signature is wrong (need to extract from IDA)")
        print("  2. Check log for error messages:")
        print(f"\n[LOG TAIL]")
        for line in recent_lines[-10:]:
            print(f"  {line.rstrip()}")
        return False

    print("\n[OK] Hook verification passed!")
    print(f"\n[NEXT STEP] Run: python examples/phase0_timing_test.py")
    return True


def main():
    parser = argparse.ArgumentParser(description='Phase 0 自动化测试脚本')
    parser.add_argument('--build', action='store_true', help='只编译 DLL')
    parser.add_argument('--inject', action='store_true', help='只注入 DLL（不重启微信）')
    parser.add_argument('--all', action='store_true', help='全流程（推荐）')
    parser.add_argument('--skip-build', action='store_true', help='跳过编译（使用已有 DLL）')

    args = parser.parse_args()

    if not any([args.build, args.inject, args.all]):
        print("请指定操作: --build, --inject, 或 --all")
        print("推荐使用: python scripts/phase0_auto_test.py --all")
        sys.exit(1)

    print("="*70)
    print("Phase 0 自动化测试脚本")
    print("="*70)

    # 只编译
    if args.build:
        if build_dll():
            print("\n[SUCCESS] DLL compiled successfully")
        else:
            print("\n[FAILED] DLL compilation failed")
            sys.exit(1)
        return

    # 只注入
    if args.inject:
        pid = get_wechat_pid()
        if pid == 0:
            print("\n[FAILED] Cannot find WeChat process")
            sys.exit(1)

        if inject_dll(pid):
            verify_hook()
        else:
            print("\n[FAILED] Injection failed")
            sys.exit(1)
        return

    # 全流程
    if args.all:
        # Step 1-2: 重启微信
        kill_wechat()
        if not start_wechat():
            print("\n[FAILED] Cannot start WeChat")
            sys.exit(1)

        # Step 3: 获取 PID
        pid = get_wechat_pid()
        if pid == 0:
            print("\n[FAILED] Cannot find WeChat process")
            sys.exit(1)

        # Step 4: 编译 DLL
        if not args.skip_build:
            if not build_dll():
                print("\n[FAILED] Build failed")
                sys.exit(1)
        else:
            print("\n[SKIP] Build skipped (using existing DLL)")

        # Step 5: 注入 DLL
        if not inject_dll(pid):
            print("\n[FAILED] Injection failed")
            sys.exit(1)

        # Step 6: 验证
        if verify_hook():
            print("\n" + "="*70)
            print("✅ Phase 0 准备完成！")
            print("="*70)
            print("\n下一步：运行性能测试")
            print("  python examples/phase0_timing_test.py")
            print("\n手动刷新朋友圈 5 次，观察 Hook 是否比 UI 更早")
        else:
            print("\n" + "="*70)
            print("⚠️  Hook 安装失败")
            print("="*70)
            print("\n可能原因：")
            print("  1. 函数签名不正确（需要从 IDA Pro 提取）")
            print("  2. WeChat 版本不匹配")
            print("\n请检查日志：tail -f pywechat_hook.log")


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[INTERRUPTED] User cancelled")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n[ERROR] Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
