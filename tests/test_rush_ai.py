from __future__ import annotations

import json
import pathlib
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]
PYWEIXIN_DIR = ROOT / "pyweixin"
sys.path.insert(0, str(PYWEIXIN_DIR))

from rush_ai import (  # noqa: E402
    AliyunDashScopeOpenAIProvider,
    ArkResponsesProvider,
    build_default_ai_provider,
    normalize_ai_provider_name,
)


def test_ark_build_input_contains_text_and_image_data_url(tmp_path):
    image = tmp_path / "x.png"
    image.write_bytes(b"\x89PNG\r\n\x1a\nfake")
    provider = ArkResponsesProvider(api_key="k")
    payload = provider._build_input("题目：2+5=?", [str(image)], None)
    assert isinstance(payload, list)
    assert payload[0]["role"] == "user"
    content = payload[0]["content"]
    assert content[0]["type"] == "input_text"
    assert content[1]["type"] == "input_image"
    assert content[1]["image_url"].startswith("data:image/png;base64,")


def test_ark_extract_response_text_from_mapping():
    response = {
        "output": [
            {
                "content": [
                    {"type": "output_text", "text": "7男"},
                ]
            }
        ]
    }
    assert ArkResponsesProvider._extract_response_text(response) == "7男"


def test_aliyun_payload_build_with_image(tmp_path):
    image = tmp_path / "x.png"
    image.write_bytes(b"\x89PNG\r\n\x1a\nfake")
    provider = AliyunDashScopeOpenAIProvider(api_key="k")
    payload = provider._build_payload("数图里的人", [str(image)], None)
    assert payload["model"] == "qwen3.5-plus"
    assert payload["enable_thinking"] is False
    assert payload["messages"][0]["role"] == "system"
    user_content = payload["messages"][1]["content"]
    assert isinstance(user_content, list)
    assert user_content[0]["type"] == "text"
    assert user_content[1]["type"] == "image_url"
    assert user_content[1]["image_url"]["url"].startswith("data:image/png;base64,")


def test_normalize_ai_provider_name_aliases():
    assert normalize_ai_provider_name("ark") == "ark"
    assert normalize_ai_provider_name("dashscope") == "aliyun"
    assert normalize_ai_provider_name("qwen3.5-plus") == "aliyun"
    assert normalize_ai_provider_name("siliconflow") == "siliconflow"


def test_build_default_ai_provider_reads_dashscope_key_from_local_secrets(tmp_path, monkeypatch):
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    (config_dir / ".local_secrets.json").write_text(
        json.dumps({"DASHSCOPE_API_KEY": "sk-test"}, ensure_ascii=False),
        encoding="utf-8",
    )
    monkeypatch.setenv("PYWEIXIN_AI_PROVIDER", "aliyun")
    monkeypatch.delenv("DASHSCOPE_API_KEY", raising=False)
    monkeypatch.delenv("ALIYUN_BAILIAN_API_KEY", raising=False)
    monkeypatch.delenv("BAILIAN_API_KEY", raising=False)
    monkeypatch.setenv("PYWEIXIN_DASHSCOPE_MODEL", "qwen3.5-plus")

    provider = build_default_ai_provider(config_dir=str(config_dir))
    assert isinstance(provider, AliyunDashScopeOpenAIProvider)
    assert provider.api_key == "sk-test"
    assert provider.model == "qwen3.5-plus"
