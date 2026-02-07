from __future__ import annotations

import pathlib
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]
PYWEIXIN_DIR = ROOT / "pyweixin"
sys.path.insert(0, str(PYWEIXIN_DIR))

from rush_engine import build_post_fingerprint, parse_answer_from_templates, resolve_answer, run_rush_loop
from rush_ai import SiliconFlowOpenAIProvider
from rush_types import AnswerResult, QuestionTemplate, RushConfig


class DummyAI:
    def __init__(self, answer: str):
        self.answer = answer

    def answer_from_text_and_images(self, question_text, image_paths, templates_hint=None):
        _ = (question_text, image_paths, templates_hint)
        return AnswerResult(answer=self.answer, confidence=0.42, source="ai:dummy")


def test_parse_template_answer():
    templates = [
        QuestionTemplate(
            name="nianhua",
            trigger_patterns=[r"年华"],
            answer_patterns=[r"(?P<value>\d+)\s*年华", r"年华\s*(?P<value>\d+)"],
            answer_format="{value}年华",
            priority=1,
        )
    ]
    result = parse_answer_from_templates("图里是 年华 4", templates)
    assert result is not None
    assert result.answer == "4年华"
    assert result.source == "template:nianhua"


def test_resolve_answer_ai_fallback():
    result = resolve_answer(
        post_content="问题: 图里有几个角色",
        detail_text="",
        image_paths=[],
        templates=[],
        ai_provider=DummyAI("7年华"),
        ai_enabled=True,
        ai_timeout_ms=500,
        confidence_threshold=0.0,
    )
    assert result is not None
    assert result.answer == "7年华"
    assert result.source == "ai:dummy"


def test_build_post_fingerprint_stable():
    fp1 = build_post_fingerprint("abc", "2分钟前", [])
    fp2 = build_post_fingerprint("abc", "2分钟前", [])
    assert fp1 == fp2


def test_run_loop_comment_once(tmp_path):
    state_file = tmp_path / "rush_state.json"
    out_dir = tmp_path / "cache"
    config = RushConfig(
        event_id="evt-1",
        target_friend_remark="客服",
        poll_interval_sec=0.01,
        templates=[
            QuestionTemplate(
                name="simple",
                trigger_patterns=[r"题目"],
                answer_patterns=[r"(?P<value>\d+)年华"],
                answer_format="{value}年华",
            )
        ],
        state_file=str(state_file),
        output_dir=str(out_dir),
        include_keywords=["题目"],
        comment_once=True,
    )

    context = {
        "内容": "题目: 本次答案是4年华",
        "发布时间": "1分钟前",
        "image_paths": [],
        "detail_folder": "",
        "fingerprint": "fp-post-1",
    }
    fetch_calls = {"n": 0}
    comment_calls = {"n": 0}

    def fetch_latest_post(**kwargs):
        _ = kwargs
        fetch_calls["n"] += 1
        return context

    def comment_post(**kwargs):
        _ = kwargs
        comment_calls["n"] += 1
        return True

    final_state = run_rush_loop(
        config,
        fetch_latest_post=fetch_latest_post,
        comment_post=comment_post,
        max_loops=5,
    )
    assert fetch_calls["n"] >= 1
    assert comment_calls["n"] == 1
    assert final_state["commented"] is True
    assert final_state["comment_text"] == "4年华"


def test_siliconflow_payload_build_with_image(tmp_path):
    image = tmp_path / "x.png"
    image.write_bytes(b"\x89PNG\r\n\x1a\nfake")
    provider = SiliconFlowOpenAIProvider(api_key="k", model="Qwen/Qwen3-VL-32B-Instruct")
    payload = provider._build_payload(
        question_text="count objects",
        image_paths=[str(image)],
        templates_hint=[QuestionTemplate(name="t1")],
    )
    assert payload["model"] == "Qwen/Qwen3-VL-32B-Instruct"
    assert payload["messages"][0]["role"] == "system"
    user_content = payload["messages"][1]["content"]
    assert isinstance(user_content, list)
    assert user_content[0]["type"] == "text"
    assert user_content[1]["type"] == "image_url"
    assert user_content[1]["image_url"]["url"].startswith("data:image/png;base64,")
