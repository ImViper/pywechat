"""Utilities for locating and parsing pywechat hook logs."""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Iterable


_TIMESTAMP_RE = re.compile(r"\[SNS_POC\]\s+Timestamp:\s+(\d+)\s+ms")


def candidate_log_paths(project_root: Path | None = None) -> list[Path]:
    """Return log path candidates ordered by likelihood."""
    candidates: list[Path] = []
    env_path = os.environ.get("PYWEIXIN_HOOK_LOG_PATH")
    if env_path:
        candidates.append(Path(env_path))

    candidates.extend(
        [
            Path(r"C:\Program Files\Tencent\Weixin\4.1.7.30\pywechat_hook.log"),
            Path(r"C:\Program Files\Tencent\Weixin\pywechat_hook.log"),
            Path(r"C:\Program Files (x86)\Tencent\Weixin\pywechat_hook.log"),
            Path.cwd() / "pywechat_hook.log",
        ]
    )

    if project_root is not None:
        candidates.append(project_root / "pywechat_hook.log")

    # Keep order but remove duplicates.
    unique_candidates: list[Path] = []
    seen: set[str] = set()
    for candidate in candidates:
        key = str(candidate).lower()
        if key in seen:
            continue
        seen.add(key)
        unique_candidates.append(candidate)
    return unique_candidates


def resolve_log_path(project_root: Path | None = None) -> Path:
    """Return the first existing log path or the top candidate."""
    candidates = candidate_log_paths(project_root=project_root)
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return candidates[0]


def extract_timestamps_ms(lines: Iterable[str]) -> list[int]:
    """Extract all SNS_POC callback timestamps from log lines."""
    result: list[int] = []
    for line in lines:
        match = _TIMESTAMP_RE.search(line)
        if not match:
            continue
        result.append(int(match.group(1)))
    return result


def extract_latest_timestamp_ms(lines: Iterable[str]) -> int | None:
    """Extract latest SNS_POC callback timestamp from log lines."""
    timestamps = extract_timestamps_ms(lines)
    if not timestamps:
        return None
    return timestamps[-1]
