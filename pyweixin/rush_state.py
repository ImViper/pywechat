"""Persistent state storage for rush loop."""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass
from typing import Any


@dataclass(slots=True)
class RushStateStore:
    """JSON-backed state store with atomic writes."""

    path: str

    def _default_state(self) -> dict[str, Any]:
        return {
            "event_id": "",
            "last_post_fingerprint": "",
            "last_seen_time": "",
            "commented": False,
            "comment_text": "",
            "comment_time": "",
            "status": "",
            "answer_source": "",
            "answer_confidence": 0.0,
        }

    def load(self) -> dict[str, Any]:
        if not os.path.exists(self.path):
            return self._default_state()
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if not isinstance(data, dict):
                return self._default_state()
            state = self._default_state()
            state.update(data)
            return state
        except (json.JSONDecodeError, OSError):
            return self._default_state()

    def save(self, state: dict[str, Any]) -> None:
        folder = os.path.dirname(os.path.abspath(self.path))
        if folder:
            os.makedirs(folder, exist_ok=True)
        fd, tmp_path = tempfile.mkstemp(prefix="rush_state_", suffix=".json", dir=folder or None, text=True)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(state, f, ensure_ascii=False, indent=2)
            os.replace(tmp_path, self.path)
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def update(self, **changes: Any) -> dict[str, Any]:
        state = self.load()
        state.update(changes)
        self.save(state)
        return state

    def reset_for_event(self, event_id: str) -> dict[str, Any]:
        state = self._default_state()
        state["event_id"] = event_id
        self.save(state)
        return state

