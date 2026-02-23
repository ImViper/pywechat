"""Runtime env loader backed by JSON config file."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Mapping


def _project_root() -> Path:
    return Path(__file__).resolve().parent.parent


def default_runtime_config_path() -> Path:
    return _project_root() / "config" / "rush_runtime_env.json"


def _normalize_env_mapping(raw: object) -> dict[str, str]:
    if not isinstance(raw, dict):
        return {}
    env_map: dict[str, str] = {}
    for key, value in raw.items():
        env_key = str(key).strip()
        if not env_key:
            continue
        if value is None:
            continue
        if isinstance(value, bool):
            env_map[env_key] = "1" if value else "0"
        else:
            env_map[env_key] = str(value)
    return env_map


def load_runtime_env_config(config_path: str | Path | None = None) -> tuple[Path, dict]:
    path = Path(config_path) if config_path else default_runtime_config_path()
    if not path.is_file():
        return path, {}
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except Exception:
        return path, {}
    if not isinstance(data, dict):
        return path, {}
    return path, data


def build_runtime_env(
    config: dict, profile: str | None = None
) -> tuple[dict[str, str], str | None]:
    env_map = _normalize_env_mapping(config.get("defaults", {}))

    profiles = config.get("profiles", {})
    active_profile = (profile or "").strip() or str(config.get("active_profile", "")).strip() or None
    if active_profile and isinstance(profiles, dict):
        env_map.update(_normalize_env_mapping(profiles.get(active_profile, {})))
    return env_map, active_profile


def apply_runtime_env(
    env_map: Mapping[str, str], only_if_missing: bool = True
) -> dict[str, str]:
    applied: dict[str, str] = {}
    for key, value in env_map.items():
        if only_if_missing:
            current = os.environ.get(key, "")
            if str(current).strip():
                continue
            os.environ.setdefault(key, value)
        else:
            os.environ[key] = value
        applied[key] = os.environ.get(key, value)
    return applied


def load_and_apply_runtime_env(
    config_path: str | Path | None = None,
    profile: str | None = None,
    only_if_missing: bool = True,
) -> tuple[Path, str | None, dict[str, str]]:
    path, config = load_runtime_env_config(config_path=config_path)
    if not config:
        return path, None, {}
    env_map, resolved_profile = build_runtime_env(config=config, profile=profile)
    applied = apply_runtime_env(env_map=env_map, only_if_missing=only_if_missing)
    return path, resolved_profile, applied
