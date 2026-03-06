"""一键启动抢答 — 替代 bat 脚本，无编码问题。

Usage:
    python 启动抢答.py
"""

from __future__ import annotations

import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path

from pyweixin.rush_ai import build_default_ai_provider, normalize_ai_provider_name
from pyweixin.runtime_env import apply_runtime_env, load_and_apply_runtime_env

PROJECT_ROOT = Path(__file__).resolve().parent


def _pause() -> None:
    try:
        input("按回车退出...")
    except EOFError:
        pass


def main() -> None:
    print("=" * 56)
    print("          PyWechat 朋友圈抢答助手")
    print("=" * 56)
    print("提示：微信 4.1+ 请先开讲述人 (Win+Ctrl+Enter)，")
    print("登录微信后保持 5 分钟再关闭，然后运行此脚本。")
    print("=" * 56)
    print()

    try:
        provider_name = normalize_ai_provider_name(None)
        ai_provider = build_default_ai_provider(config_dir=str(PROJECT_ROOT / "config"))
    except ValueError as exc:
        print(f"[错误] {exc}")
        _pause()
        return
    print(f"[config] AI provider={provider_name} model={getattr(ai_provider, 'model', '')}")

    # Runtime tuning now comes from config/rush_runtime_env.json (profile=startup).
    # Fallback to a tiny in-code baseline if config file is missing.
    fallback_defaults = {
        "PYTHONIOENCODING": "utf-8",
        "PYTHONUTF8": "1",
        "PADDLE_PDX_DISABLE_MODEL_SOURCE_CHECK": "True",
        "PYWEIXIN_HOOK_ENABLED": "0",
        "PYWEIXIN_HOOK_BATCH_MODE": "fast_first_batch",
        "PYWEIXIN_HOOK_MAX_CONCURRENCY": "1",
    }
    apply_runtime_env(fallback_defaults, only_if_missing=True)
    runtime_profile_name = os.getenv("PYWEIXIN_RUNTIME_PROFILE", "startup").strip() or "startup"
    runtime_path, runtime_profile, runtime_applied = load_and_apply_runtime_env(
        config_path=PROJECT_ROOT / "config" / "rush_runtime_env.json",
        profile=runtime_profile_name,
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
        "PYWEIXIN_ANSWER_MODE",
        "PYWEIXIN_AI_PROVIDER",
        "PYWEIXIN_ARK_MODEL",
        "PYWEIXIN_DASHSCOPE_MODEL",
        "PYWEIXIN_ARK_IMAGE_DETAIL",
        "PYWEIXIN_ARK_TIMEOUT_SEC",
        "PYWEIXIN_DASHSCOPE_TIMEOUT_SEC",
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

    default_publish_time = datetime.now().strftime("%H:%M")
    publish_time = input(
        f"[可选] 请输入预计的发圈时间 (如 19:15，默认当前时间 {default_publish_time}): "
    ).strip()
    if not publish_time:
        publish_time = default_publish_time

    print()
    print("以下选填，不填直接回车跳过")
    default_answer_mode = (os.getenv("PYWEIXIN_ANSWER_MODE", "standard") or "standard").strip().lower()
    default_mode_choice = "2" if default_answer_mode == "count_suffix" else "1"
    mode_choice = input(
        f"1. 抢答模式 (1=标准抢答, 2=拼车数数题, 默认{default_mode_choice}): "
    ).strip()
    answer_mode = "count_suffix" if mode_choice == "2" else "standard"
    if not mode_choice and default_answer_mode == "count_suffix":
        answer_mode = "count_suffix"

    suffix = ""
    if answer_mode == "count_suffix":
        suffix = input("2. 拼车后缀 (如 男): ").strip()
        if not suffix:
            print("拼车数数题模式必须填写后缀")
            _pause()
            return
    canned = input("3. 预制话术 (逗号分隔, 如 666,沙发): ").strip()

    # Build command
    cmd = [
        sys.executable,
        str(PROJECT_ROOT / "examples" / "run_feed_multi_comment_listener.py"),
        publish_time,
        target_author,
        "--runtime-config",
        str(PROJECT_ROOT / "config" / "rush_runtime_env.json"),
        "--runtime-profile",
        runtime_profile_name,
        "--answer-mode",
        answer_mode,
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
