"""Utilities for mining question-like content from friend moments."""

from __future__ import annotations

import re
from dataclasses import dataclass


DEFAULT_QUESTION_KEYWORDS = [
    "题",
    "问题",
    "观察",
    "请看图",
    "请回答",
    "数量",
    "几个",
    "多少",
    "答案",
    "评论",
    "格式",
]


@dataclass(slots=True)
class QuestionFilter:
    """Filter config for identifying target question posts."""

    include_keywords: list[str]
    exclude_keywords: list[str]
    regex_patterns: list[str]


def normalize_lines(text: str) -> list[str]:
    """Split and normalize text into non-empty lines."""
    if not text:
        return []
    lines = [ln.strip() for ln in text.replace("\r", "\n").split("\n")]
    return [ln for ln in lines if ln]


def match_question_post(text: str, flt: QuestionFilter) -> bool:
    """Determine if a post looks like a target question post."""
    normalized = text or ""
    if flt.include_keywords and not any(k in normalized for k in flt.include_keywords):
        return False
    if flt.exclude_keywords and any(k in normalized for k in flt.exclude_keywords):
        return False
    if flt.regex_patterns:
        return any(re.search(p, normalized, flags=re.IGNORECASE) for p in flt.regex_patterns)
    return True


def extract_question_snippets(text: str) -> list[str]:
    """Extract lines likely to describe a question/rule."""
    lines = normalize_lines(text)
    snippets: list[str] = []
    for line in lines:
        if any(k in line for k in DEFAULT_QUESTION_KEYWORDS):
            snippets.append(line)
            continue
        # Keep lines that include a numeric + keyword style format hints.
        if re.search(r"\d+\s*(个|位|名|年华|角色|题)", line):
            snippets.append(line)
    # de-duplicate while preserving order
    unique: list[str] = []
    for item in snippets:
        if item not in unique:
            unique.append(item)
    return unique

