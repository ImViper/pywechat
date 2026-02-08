"""Types for Moments rush automation."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


def parse_datetime(value: str | None) -> datetime | None:
    """Parse common datetime string formats."""
    if not value:
        return None
    text = value.strip()
    if not text:
        return None
    fmts = (
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M",
        "%Y/%m/%d %H:%M:%S",
        "%Y/%m/%d %H:%M",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%dT%H:%M",
    )
    for fmt in fmts:
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        return None


@dataclass(slots=True)
class QuestionTemplate:
    """Template rule for fast answer extraction."""

    name: str
    trigger_patterns: list[str] = field(default_factory=list)
    answer_patterns: list[str] = field(default_factory=list)
    answer_format: str = "{value}"
    priority: int = 100

    @classmethod
    def from_mapping(cls, data: dict[str, Any]) -> "QuestionTemplate":
        return cls(
            name=str(data.get("name", "template")),
            trigger_patterns=[str(x) for x in data.get("trigger_patterns", [])],
            answer_patterns=[str(x) for x in data.get("answer_patterns", [])],
            answer_format=str(data.get("answer_format", "{value}")),
            priority=int(data.get("priority", 100)),
        )


@dataclass(slots=True)
class AnswerResult:
    """Result from template/AI answer generation."""

    answer: str
    confidence: float
    source: str
    latency_ms: int = 0
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class RushConfig:
    """Runtime config for rush loop."""

    event_id: str
    target_friend_remark: str
    monitor_start: str | None = None
    monitor_end: str | None = None
    publish_time: str | None = None
    poll_interval_sec: float = 2.0
    include_keywords: list[str] = field(default_factory=list)
    exclude_keywords: list[str] = field(default_factory=list)
    templates: list[QuestionTemplate] = field(default_factory=list)
    ai_enabled: bool = True
    ai_timeout_ms: int = 1200
    confidence_threshold: float = 0.5
    comment_once: bool = True
    state_file: str = "rush_state.json"
    output_dir: str = "rush_moments_cache"
    is_maximize: bool = False
    close_weixin: bool = True
    default_answer: str | None = None

    @classmethod
    def from_mapping(cls, data: dict[str, Any]) -> "RushConfig":
        templates = [QuestionTemplate.from_mapping(x) for x in data.get("templates", [])]
        return cls(
            event_id=str(data.get("event_id", "rush-event")),
            target_friend_remark=str(data.get("target_friend_remark", "")),
            monitor_start=data.get("monitor_start"),
            monitor_end=data.get("monitor_end"),
            publish_time=data.get("publish_time"),
            poll_interval_sec=float(data.get("poll_interval_sec", 2.0)),
            include_keywords=[str(x) for x in data.get("include_keywords", [])],
            exclude_keywords=[str(x) for x in data.get("exclude_keywords", [])],
            templates=templates,
            ai_enabled=bool(data.get("ai_enabled", True)),
            ai_timeout_ms=int(data.get("ai_timeout_ms", 1200)),
            confidence_threshold=float(data.get("confidence_threshold", 0.5)),
            comment_once=bool(data.get("comment_once", True)),
            state_file=str(data.get("state_file", "rush_state.json")),
            output_dir=str(data.get("output_dir", "rush_moments_cache")),
            is_maximize=bool(data.get("is_maximize", False)),
            close_weixin=bool(data.get("close_weixin", True)),
            default_answer=(None if data.get("default_answer") in (None, "") else str(data.get("default_answer"))),
        )

