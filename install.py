"""环境安装与检测脚本 — 纯 stdlib，无需预装任何依赖。

Usage:
    python install.py          # 完整安装
    python install.py --check  # 仅检测环境是否就绪
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
VENV_DIR = PROJECT_ROOT / ".venv"
VENV_PYTHON = VENV_DIR / "Scripts" / "python.exe"
SECRETS_FILE = PROJECT_ROOT / "config" / ".local_secrets.json"
ENV_BAT = PROJECT_ROOT / "config" / ".local_env.bat"
REQUIREMENTS = PROJECT_ROOT / "requirements.txt"

REQUIRED_PACKAGES = [
    "psutil", "pyautogui", "pycaw", "win32api",  # pywin32
    "pywinauto", "PIL", "emoji",
]
OPTIONAL_PACKAGES = [
    ("paddleocr", "PaddleOCR 本地识别"),
    ("volcenginesdkarkruntime", "ARK AI 视觉识别"),
]

PIP_COMMON_ARGS = ["--isolated", "--retries", "2", "--timeout", "30"]
PROXY_ENV_KEYS = [
    "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
    "http_proxy", "https_proxy", "all_proxy",
]
PIP_FALLBACK_SOURCES = [
    ("default", []),
    (
        "pypi-trusted",
        [
            "-i", "https://pypi.org/simple",
            "--trusted-host", "pypi.org",
            "--trusted-host", "files.pythonhosted.org",
        ],
    ),
    (
        "tuna-mirror",
        [
            "-i", "https://pypi.tuna.tsinghua.edu.cn/simple",
            "--trusted-host", "pypi.tuna.tsinghua.edu.cn",
        ],
    ),
]


def ok(msg: str) -> None:
    print(f"  [OK] {msg}")


def fail(msg: str) -> None:
    print(f"  [X]  {msg}")


def warn(msg: str) -> None:
    print(f"  [!]  {msg}")


def run_pip_with_fallbacks(args: list[str], step_name: str) -> bool:
    has_proxy_env = any(os.getenv(k) for k in PROXY_ENV_KEYS)
    for source_name, source_args in PIP_FALLBACK_SOURCES:
        if source_name != "default":
            warn(f"{step_name} 重试: {source_name}")
        cmd = [str(VENV_PYTHON), "-m", "pip", *args, *PIP_COMMON_ARGS, *source_args]
        r = subprocess.run(cmd, check=False)
        if r.returncode == 0:
            if source_name != "default":
                ok(f"{step_name} 成功 ({source_name})")
            return True
        if has_proxy_env:
            env = os.environ.copy()
            for key in PROXY_ENV_KEYS:
                env.pop(key, None)
            warn(f"{step_name} 重试: {source_name} (禁用代理变量)")
            r = subprocess.run(cmd, check=False, env=env)
            if r.returncode == 0:
                ok(f"{step_name} 成功 ({source_name}, 无代理)")
                return True
    return False


def _pause() -> None:
    try:
        input("\n按回车退出...")
    except EOFError:
        pass


def check_python_version() -> bool:
    v = sys.version_info
    if v.major == 3 and 9 <= v.minor <= 12:
        ok(f"Python {v.major}.{v.minor}.{v.micro}")
        return True
    fail(f"Python {v.major}.{v.minor} — 需要 3.9-3.12")
    return False


def check_venv() -> bool:
    if VENV_DIR.exists() and VENV_PYTHON.exists():
        ok(".venv 虚拟环境存在")
        return True
    fail(".venv 虚拟环境不存在")
    return False


def check_packages() -> bool:
    all_ok = True
    for pkg in REQUIRED_PACKAGES:
        r = subprocess.run(
            [str(VENV_PYTHON), "-c", f"import {pkg}"],
            capture_output=True, timeout=30,
        )
        if r.returncode == 0:
            ok(pkg)
        else:
            fail(f"{pkg} 未安装")
            all_ok = False

    for pkg, desc in OPTIONAL_PACKAGES:
        r = subprocess.run(
            [str(VENV_PYTHON), "-c", f"import {pkg}"],
            capture_output=True, timeout=30,
        )
        if r.returncode == 0:
            ok(f"{pkg} ({desc})")
        else:
            warn(f"{pkg} 未安装 — {desc}，可选")
    return all_ok


def check_api_key() -> bool:
    if ENV_BAT.exists():
        for line in ENV_BAT.read_text(errors="ignore").splitlines():
            if "ARK_API_KEY=" in line.upper() and line.split("=", 1)[1].strip():
                ok("ARK_API_KEY (config/.local_env.bat)")
                return True
    if SECRETS_FILE.exists():
        try:
            data = json.loads(SECRETS_FILE.read_text(encoding="utf-8-sig"))
            if data.get("ARK_API_KEY"):
                ok("ARK_API_KEY (config/.local_secrets.json)")
                return True
        except Exception:
            pass
    if os.getenv("ARK_API_KEY"):
        ok("ARK_API_KEY (环境变量)")
        return True
    fail("ARK_API_KEY 未配置")
    return False


def run_check() -> bool:
    print("=" * 50)
    print("           环境检测")
    print("=" * 50)

    print("\n[1] Python 版本")
    py_ok = check_python_version()

    print("\n[2] 虚拟环境")
    venv_ok = check_venv()

    pkg_ok = False
    if venv_ok:
        print("\n[3] 依赖包")
        pkg_ok = check_packages()
    else:
        print("\n[3] 依赖包 — 跳过 (无 .venv)")

    print("\n[4] API Key")
    key_ok = check_api_key()

    print("\n" + "=" * 50)
    all_ok = py_ok and venv_ok and pkg_ok and key_ok
    if all_ok:
        print("环境就绪! 运行方式:")
        print("  双击 start.bat")
        print("  或: .venv\\Scripts\\activate && python 启动抢答.py")
    else:
        print("环境未就绪，请运行: python install.py")
    print("=" * 50)
    return all_ok


def run_install() -> None:
    print("=" * 50)
    print("           环境安装")
    print("=" * 50)

    print("\n[1/5] 检查 Python 版本...")
    if not check_python_version():
        print("\n请安装 Python 3.9-3.12:")
        print("https://www.python.org/downloads/")
        print("安装时务必勾选 Add Python to PATH")
        _pause()
        return

    print("\n[2/5] 创建虚拟环境...")
    if not VENV_DIR.exists():
        subprocess.run([sys.executable, "-m", "venv", str(VENV_DIR)], check=True)
        ok("已创建 .venv")
    else:
        ok(".venv 已存在，跳过")

    print("\n[3/5] 更新 pip...")
    if run_pip_with_fallbacks(["install", "--upgrade", "pip"], "更新 pip"):
        ok("pip 已更新")
    else:
        warn("更新 pip 失败，继续安装依赖（可能仍可成功）")

    print("\n[4/5] 安装基础依赖...")
    if run_pip_with_fallbacks(
        ["install", "-r", str(REQUIREMENTS)],
        "安装基础依赖",
    ):
        ok("基础依赖安装完成")
    else:
        warn("部分依赖安装失败，请截屏反馈")

    print("\n[5/5] 安装 PaddleOCR (可选)...")
    if run_pip_with_fallbacks(
        ["install", "paddleocr", "paddlepaddle"],
        "安装 PaddleOCR",
    ):
        ok("PaddleOCR 安装完成")
    else:
        warn("PaddleOCR 安装失败，但仍可使用 AI 视觉识别")

    # API Key
    print()
    if not check_api_key():
        print("\n需要配置 ARK_API_KEY (用于 AI 识别)")
        print("如果作者已提供 config/.local_env.bat，放入 config/ 目录即可")
        key = input("或在此输入 ARK_API_KEY (回车跳过): ").strip()
        if key:
            ENV_BAT.parent.mkdir(parents=True, exist_ok=True)
            ENV_BAT.write_text(f"@echo off\nset ARK_API_KEY={key}\n")
            ok("已保存到 config/.local_env.bat")
        else:
            print("跳过，请稍后手动配置")

    print()
    run_check()


def main() -> None:
    if "--check" in sys.argv:
        run_check()
    else:
        run_install()
    _pause()


if __name__ == "__main__":
    main()
