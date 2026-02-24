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

from pyweixin.runtime_env import apply_runtime_env, load_and_apply_runtime_env

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

    # Runtime tuning now comes from config/rush_runtime_env.json (profile=startup).
    # Fallback to a tiny in-code baseline if config file is missing.
    fallback_defaults = {
        "PYTHONIOENCODING": "utf-8",
        "PYTHONUTF8": "1",
        "PADDLE_PDX_DISABLE_MODEL_SOURCE_CHECK": "True",
        "PYWEIXIN_HOOK_ENABLED": "1",
        "PYWEIXIN_HOOK_BATCH_MODE": "fast_first_batch",
        "PYWEIXIN_HOOK_MAX_CONCURRENCY": "1",
    }
    apply_runtime_env(fallback_defaults, only_if_missing=True)
    runtime_path, runtime_profile, runtime_applied = load_and_apply_runtime_env(
        config_path=PROJECT_ROOT / "config" / "rush_runtime_env.json",
        profile="startup",
        only_if_missing=True,
    )
    if runtime_applied:
        print(
            f"[config] loaded runtime profile={runtime_profile or 'startup'} "
            f"from {runtime_path} ({len(runtime_applied)} keys)"
        )
    else:
        print(f"[config] runtime config not loaded from {runtime_path}, using fallback defaults")
    print("[config] effective runtime params:")
    for key in [
        "PYWEIXIN_FIRST_ANSWER_MODE",
        "PYWEIXIN_ARK_MODEL",
        "PYWEIXIN_ARK_IMAGE_DETAIL",
        "PYWEIXIN_ARK_TIMEOUT_SEC",
        "PYWEIXIN_AI_IMAGE_OPTIMIZE",
        "PYWEIXIN_AI_IMAGE_MAX_SIDE",
        "PYWEIXIN_AI_IMAGE_JPEG_QUALITY",
        "PYWEIXIN_DISABLE_OCR",
        "PYWEIXIN_HOOK_ENABLED",
        "PYWEIXIN_HOOK_BATCH_MODE",
    ]:
        print(f"  {key}={os.getenv(key, '')}")

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
        "--runtime-config",
        str(PROJECT_ROOT / "config" / "rush_runtime_env.json"),
        "--runtime-profile",
        "startup",
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
