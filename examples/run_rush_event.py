"""Run Moments rush loop with config file."""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import sys

# Allow direct execution: `python examples/run_rush_event.py`
PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from pyweixin.rush_ai import (
    ArkChatProvider,
    ArkResponsesProvider,
    NullAIProvider,
    SiliconFlowOpenAIProvider,
    NullOCRProvider,
    PaddleOCRProvider,
)
from pyweixin.rush_engine import load_rush_config, run_rush_loop


def _load_api_key_from_file(path: str, env_name: str) -> str:
    if not path or not os.path.exists(path):
        return ""
    try:
        with open(path, "r", encoding="utf-8-sig") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return ""
        candidate_keys = [env_name, "ARK_API_KEY", "SILICONFLOW_API_KEY", "api_key"]
        seen = set()
        for key in candidate_keys:
            if not key or key in seen:
                continue
            seen.add(key)
            value = data.get(key)
            if value:
                return str(value).strip()
        return ""
    except (OSError, json.JSONDecodeError):
        return ""


def main() -> None:
    parser = argparse.ArgumentParser(description="Run WeChat Moments rush loop.")
    parser.add_argument(
        "--config",
        default="config/rush_event.json",
        help="Path to rush config file (.json recommended, .yaml/.yml supported)",
    )
    parser.add_argument(
        "--provider",
        default="ark",
        choices=["ark", "siliconflow", "null"],
        help="AI provider. Default: ark. Use 'null' to disable AI fallback.",
    )
    parser.add_argument(
        "--model",
        default="",
        help="Model name. Default: doubao-seed-1-8-251228 for ark, Qwen/Qwen3-VL-32B-Instruct for siliconflow.",
    )
    parser.add_argument(
        "--base-url",
        default="",
        help="API base URL. Default: ark->https://ark.cn-beijing.volces.com/api/v3, siliconflow->https://api.siliconflow.cn/v1",
    )
    parser.add_argument(
        "--api-key-env",
        default="",
        help="Environment variable name for API key. Default follows provider: ark->ARK_API_KEY, siliconflow->SILICONFLOW_API_KEY",
    )
    parser.add_argument(
        "--key-file",
        default="config/.local_secrets.json",
        help="Local secrets JSON file. Example: {\"ARK_API_KEY\":\"...\",\"SILICONFLOW_API_KEY\":\"...\"}",
    )
    parser.add_argument(
        "--ocr",
        default="paddle",
        choices=["paddle", "null"],
        help="OCR provider. 'paddle' for PaddleOCR (local, free), 'null' to disable.",
    )
    args = parser.parse_args()

    config = load_rush_config(args.config)

    # Setup AI provider
    if args.provider == "null":
        ai_provider = NullAIProvider()
    elif args.provider == "ark":
        env_name = args.api_key_env or "ARK_API_KEY"
        api_key = os.getenv(env_name, "")
        if not api_key:
            api_key = _load_api_key_from_file(args.key_file, env_name)
        if not api_key:
            raise RuntimeError(f"Missing API key for provider 'ark'. Set env {env_name} or provide it in {args.key_file}.")
        # 使用新的 ArkChatProvider（Chat API，速度更快）
        ai_provider = ArkChatProvider(
            api_key=api_key,
            model=(args.model or "doubao-seed-1-8-251228"),
            base_url=(args.base_url or "https://ark.cn-beijing.volces.com/api/v3"),
        )
    else:
        env_name = args.api_key_env or "SILICONFLOW_API_KEY"
        api_key = os.getenv(env_name, "")
        if not api_key:
            api_key = _load_api_key_from_file(args.key_file, env_name)
        if not api_key:
            raise RuntimeError(
                f"Missing API key for provider 'siliconflow'. Set env {env_name} or provide it in {args.key_file}."
            )
        ai_provider = SiliconFlowOpenAIProvider(
            api_key=api_key,
            model=(args.model or "Qwen/Qwen3-VL-32B-Instruct"),
            base_url=(args.base_url or "https://api.siliconflow.cn/v1"),
        )

    # Setup OCR provider
    if args.ocr == "null":
        ocr_provider = NullOCRProvider()
    else:  # paddle
        try:
            ocr_provider = PaddleOCRProvider()
            print("PaddleOCR initialized successfully (local, no API key needed)")
        except RuntimeError as exc:
            print(f"Warning: {exc}")
            print("Falling back to NullOCRProvider. Install with: pip install paddleocr paddlepaddle")
            ocr_provider = NullOCRProvider()

    final_state = run_rush_loop(config, ai_provider=ai_provider, ocr_provider=ocr_provider)
    print("Rush loop finished.")
    print(final_state)


if __name__ == "__main__":
    main()
