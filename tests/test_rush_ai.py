from __future__ import annotations

import pathlib
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]
PYWEIXIN_DIR = ROOT / "pyweixin"
sys.path.insert(0, str(PYWEIXIN_DIR))

from rush_ai import ArkResponsesProvider  # noqa: E402


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
