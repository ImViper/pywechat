"""一键启动抢答 — 替代 bat 脚本，无编码问题。

Usage:
    python 启动抢答.py
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent


def _pause() -> None:
    try:
        input("按回车退出...")
    except EOFError:
        pass


def load_api_key() -> str:
    """Load ARK_API_KEY from config/.local_env.bat or config/.local_secrets.json."""
    # Try .local_env.bat (set ARK_API_KEY=xxx)
    env_bat = PROJECT_ROOT / "config" / ".local_env.bat"
    if env_bat.exists():
        for line in env_bat.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = line.strip()
            if line.lower().startswith("set ark_api_key="):
                return line.split("=", 1)[1].strip()

    # Try .local_secrets.json
    secrets = PROJECT_ROOT / "config" / ".local_secrets.json"
    if secrets.exists():
        try:
            data = json.loads(secrets.read_text(encoding="utf-8-sig"))
            return str(data.get("ARK_API_KEY", ""))
        except Exception:
            pass

    return os.getenv("ARK_API_KEY", "")


def main() -> None:
    print("=" * 56)
    print("          PyWechat 朋友圈抢答助手")
    print("=" * 56)
    print("提示：微信 4.1+ 请先开讲述人 (Win+Ctrl+Enter)，")
    print("登录微信后保持 5 分钟再关闭，然后运行此脚本。")
    print("=" * 56)
    print()

    # Load API key
    api_key = load_api_key()
    if not api_key:
        print("[错误] 未找到 ARK_API_KEY")
        print("请在 config/.local_secrets.json 或 config/.local_env.bat 中配置")
        _pause()
        return
    os.environ["ARK_API_KEY"] = api_key

    # OCR optimization
    os.environ["PADDLE_PDX_DISABLE_MODEL_SOURCE_CHECK"] = "True"
    os.environ["PYWEIXIN_OCR_DET_MODEL"] = "PP-OCRv5_mobile_det"
    os.environ["PYWEIXIN_OCR_REC_MODEL"] = "PP-OCRv5_mobile_rec"
    os.environ["PYWEIXIN_OCR_CPU_THREADS"] = "8"
    os.environ["PYWEIXIN_OCR_MAX_SIDE"] = "560"
    os.environ["PYWEIXIN_OCR_LIMIT_TYPE"] = "max"
    os.environ.setdefault("PYWEIXIN_OCR_COUNT_MAX", "20")
    # Fast-first stability/perf defaults
    os.environ.setdefault("PYWEIXIN_FAST_FIRST_PRE_HOOK", "0")
    os.environ.setdefault("PYWEIXIN_FAST_FIRST_DEFER_IMAGES", "1")
    os.environ.setdefault("PYWEIXIN_FAST_FIRST_EDITOR_PRELOAD", "0")
    os.environ.setdefault("PYWEIXIN_FAST_FIRST_COLLECT_TIMEOUT_S", "6")
    os.environ.setdefault("PYWEIXIN_FAST_FIRST_QUICK_CAPTURE", "0")
    os.environ.setdefault("PYWEIXIN_FAST_FIRST_FLUSH_EARLY", "0")
    os.environ.setdefault("PYWEIXIN_FAST_FIRST_FLUSH_MIN_READY", "1")
    # Early hook scatter shot after first UI comment (speed strategy).
    os.environ.setdefault("PYWEIXIN_FAST_FIRST_SCATTER", "0")
    os.environ.setdefault("PYWEIXIN_FAST_FIRST_SCATTER_VALUES", "1,2,3")
    os.environ.setdefault("PYWEIXIN_FAST_FIRST_SCATTER_MAX", "3")
    os.environ.setdefault("PYWEIXIN_FAST_FIRST_SCATTER_STOP_ON_FAIL", "1")
    os.environ.setdefault("PYWEIXIN_FAST_FIRST_SCATTER_MODE", "capture_thread")
    os.environ.setdefault("PYWEIXIN_FAST_FIRST_SCATTER_WAIT_MS", "650")
    os.environ.setdefault("PYWEIXIN_FAST_FIRST_SCATTER_SETTLE_MS", "140")
    os.environ.setdefault("PYWEIXIN_FAST_FIRST_SCATTER_STRATEGY", "dispatcher_serial")
    os.environ.setdefault("PYWEIXIN_FAST_FIRST_SCATTER_GAP_MS", "90")
    os.environ.setdefault("PYWEIXIN_FAST_FIRST_SCATTER_HOOK_WAIT_MS", "650")
    os.environ.setdefault("PYWEIXIN_FAST_FIRST_SCATTER_UI_FALLBACK", "0")
    os.environ.setdefault("PYWEIXIN_FAST_FIRST_POST_FIRST_REMAINING_EARLY", "0")
    os.environ.setdefault("PYWEIXIN_UI_SEND_RETRY", "1")
    os.environ.setdefault("PYWEIXIN_UI_SEND_RETRY_GAP_MS", "120")
    # AI optimization (keep model unchanged, reduce image upload/infer cost)
    os.environ.setdefault("PYWEIXIN_AI_IMAGE_OPTIMIZE", "1")
    os.environ.setdefault("PYWEIXIN_AI_IMAGE_MAX_SIDE", "960")
    os.environ.setdefault("PYWEIXIN_AI_IMAGE_JPEG_QUALITY", "84")
    os.environ.setdefault("PYWEIXIN_AI_IMAGE_OPT_MIN_SIDE", "1100")
    os.environ.setdefault("PYWEIXIN_ARK_MAX_TOKENS", "16")
    os.environ.setdefault("PYWEIXIN_ARK_TEMPERATURE", "0.0")
    os.environ.setdefault("PYWEIXIN_ARK_TOP_P", "0.6")
    os.environ.setdefault("PYWEIXIN_ARK_TIMEOUT_SEC", "4.5")

    # User input
    target_author = input("[必填] 请输入要抢答的好友名称: ").strip()
    if not target_author:
        print("名称不能为空")
        _pause()
        return

    publish_time = input("[必填] 请输入预计的发圈时间 (如 19:15): ").strip()
    if not publish_time:
        print("时间不能为空")
        _pause()
        return

    print()
    print("以下选填，不填直接回车跳过")
    suffix = input("1. 抢答后缀 (如 男): ").strip()
    canned = input("2. 预制话术 (逗号分隔, 如 666,沙发): ").strip()

    # Build command
    cmd = [
        sys.executable,
        str(PROJECT_ROOT / "examples" / "run_feed_multi_comment_listener.py"),
        publish_time,
        target_author,
    ]
    if suffix:
        cmd += ["--suffix", suffix]
    if canned:
        cmd += ["--canned", canned]

    print()
    print("正在启动抢答脚本...")
    print("=" * 56)
    print(" ".join(cmd))
    print("=" * 56)
    print()

    try:
        subprocess.run(cmd, cwd=str(PROJECT_ROOT))
    except KeyboardInterrupt:
        print("\n已中断")
    except Exception as exc:
        print(f"\n运行出错: {exc}")

    print()
    print("=" * 56)
    print("运行结束")
    print("=" * 56)
    _pause()


if __name__ == "__main__":
    main()
