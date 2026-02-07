from __future__ import annotations

import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from pyweixin.moments_question_miner import (  # noqa: E402
    QuestionFilter,
    extract_question_snippets,
    match_question_post,
    normalize_lines,
)


def test_normalize_lines():
    text = "a\r\n\n b \n\nc"
    assert normalize_lines(text) == ["a", "b", "c"]


def test_extract_question_snippets():
    text = "活动说明\n请观察图中角色数量\n答案格式：4年华\n普通文案"
    snippets = extract_question_snippets(text)
    assert "请观察图中角色数量" in snippets
    assert "答案格式：4年华" in snippets


def test_match_question_post_keywords_and_regex():
    flt = QuestionFilter(
        include_keywords=["观察", "答案"],
        exclude_keywords=["测试无效"],
        regex_patterns=[r"\d+\s*年华"],
    )
    assert match_question_post("请观察图中角色，答案格式4年华", flt) is True
    assert match_question_post("请观察图中角色，答案格式四个年华", flt) is False
    assert match_question_post("测试无效，答案格式4年华", flt) is False

