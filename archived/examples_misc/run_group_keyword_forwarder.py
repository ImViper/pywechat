"""Forward keyword-matched group messages to a target friend.

Usage:
    python examples/run_group_keyword_forwarder.py --config config/group_keyword_forwarder.json
    python examples/run_group_keyword_forwarder.py --config config/group_keyword_forwarder.json --dry-run
    python examples/run_group_keyword_forwarder.py --config config/group_keyword_forwarder.json --once
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any
import win32api
import win32con
import win32gui

# Allow direct execution: `python examples/run_group_keyword_forwarder.py`
PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from pyweixin import Messages, Navigator


DEFAULT_CONFIG_PATH = "config/group_keyword_forwarder.json"
DEFAULT_MAX_MESSAGE_LEN = 500
DEFAULT_WINDOW_TAIL_SCAN_COUNT = 80
DEFAULT_TEMPLATE = (
    "[群关键词提醒]\n"
    "群：{group}\n"
    "关键词：{keyword}\n"
    "转发时间：{time}\n"
    "发送人：{sender}\n"
    "消息时间：{send_time}\n"
    "原文内容：{message}"
)


@dataclass(frozen=True)
class ForwarderConfig:
    target_friend: str
    groups: tuple[str, ...]
    keywords: tuple[str, ...]
    exclude_keywords: tuple[str, ...]
    poll_interval_sec: float
    dedupe_ttl_sec: float
    case_sensitive: bool
    use_regex: bool
    send_delay_sec: float
    max_send_per_cycle: int
    message_template: str
    is_maximize: bool
    close_weixin_on_exit: bool
    use_direct_poll: bool
    pull_count: int
    use_window_listener: bool
    window_minimize: bool
    window_tail_scan_count: int
    listener_window_offset_x: int


@dataclass
class WindowListenerState:
    dialog_window: Any
    chat_list: Any | None = None
    seen_item_keys: set[str] = field(default_factory=set)
    item_key_order: list[str] = field(default_factory=list)
    max_tracked_item_keys: int = 3000
    last_time_hint: str = ""
    warmup_on_next_collect: bool = False

    def mark_seen(self, item_key: str) -> bool:
        if item_key in self.seen_item_keys:
            return False
        self.seen_item_keys.add(item_key)
        self.item_key_order.append(item_key)

        overflow = len(self.item_key_order) - self.max_tracked_item_keys
        for _ in range(max(0, overflow)):
            old_item_key = self.item_key_order.pop(0)
            self.seen_item_keys.discard(old_item_key)
        return True


class FingerprintCache:
    """Simple TTL cache for message fingerprints."""

    def __init__(self, ttl_seconds: float) -> None:
        self.ttl_seconds = max(0.0, float(ttl_seconds))
        self._expiries: dict[str, float] = {}

    def cleanup(self, now: float) -> None:
        expired_keys = [key for key, expires_at in self._expiries.items() if expires_at <= now]
        for key in expired_keys:
            self._expiries.pop(key, None)

    def contains(self, key: str, now: float) -> bool:
        expires_at = self._expiries.get(key)
        return expires_at is not None and expires_at > now

    def add(self, key: str, now: float) -> None:
        if self.ttl_seconds <= 0:
            return
        self._expiries[key] = now + self.ttl_seconds


class KeywordMatcher:
    def __init__(
        self,
        keywords: tuple[str, ...],
        exclude_keywords: tuple[str, ...],
        case_sensitive: bool,
        use_regex: bool,
    ) -> None:
        self.keywords = keywords
        self.exclude_keywords = exclude_keywords
        self.case_sensitive = case_sensitive
        self.use_regex = use_regex

        if use_regex:
            flags = 0 if case_sensitive else re.IGNORECASE
            self.keyword_patterns = [re.compile(pattern, flags=flags) for pattern in keywords]
            self.exclude_patterns = [re.compile(pattern, flags=flags) for pattern in exclude_keywords]
        else:
            self.keyword_patterns = []
            self.exclude_patterns = []
            if case_sensitive:
                self.keywords_normalized = keywords
                self.exclude_keywords_normalized = exclude_keywords
            else:
                self.keywords_normalized = tuple(item.casefold() for item in keywords)
                self.exclude_keywords_normalized = tuple(item.casefold() for item in exclude_keywords)

    def match_keyword(self, message: str) -> str | None:
        if self.use_regex:
            for pattern, raw_keyword in zip(self.keyword_patterns, self.keywords):
                if pattern.search(message):
                    return raw_keyword
            return None

        source = message if self.case_sensitive else message.casefold()
        for raw_keyword, normalized_keyword in zip(self.keywords, self.keywords_normalized):
            if normalized_keyword in source:
                return raw_keyword
        return None

    def is_excluded(self, message: str) -> bool:
        if self.use_regex:
            return any(pattern.search(message) for pattern in self.exclude_patterns)

        source = message if self.case_sensitive else message.casefold()
        return any(keyword in source for keyword in self.exclude_keywords_normalized)


def _normalize_string_list(raw: Any, field_name: str) -> tuple[str, ...]:
    if not isinstance(raw, list):
        raise ValueError(f"`{field_name}` must be a list of strings.")
    cleaned: list[str] = []
    for item in raw:
        if not isinstance(item, str):
            raise ValueError(f"`{field_name}` contains non-string item: {item!r}")
        value = item.strip()
        if value:
            cleaned.append(value)
    return tuple(cleaned)


def _load_config(config_path: pathlib.Path) -> ForwarderConfig:
    if not config_path.exists():
        raise FileNotFoundError(
            f"Config file not found: {config_path}. "
            "Copy `config/group_keyword_forwarder.example.json` to create it."
        )

    try:
        with config_path.open("r", encoding="utf-8-sig") as f:
            raw = json.load(f)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON in config: {exc}") from exc

    if not isinstance(raw, dict):
        raise ValueError("Config root must be a JSON object.")

    target_friend = str(raw.get("target_friend", "")).strip()
    if not target_friend:
        raise ValueError("`target_friend` must be a non-empty string.")

    groups = _normalize_string_list(raw.get("groups", []), "groups")
    keywords = _normalize_string_list(raw.get("keywords", []), "keywords")
    exclude_keywords = _normalize_string_list(raw.get("exclude_keywords", []), "exclude_keywords")

    if not groups:
        raise ValueError("`groups` must contain at least one group name.")
    if not keywords:
        raise ValueError("`keywords` must contain at least one keyword.")
    if target_friend in groups:
        raise ValueError("`target_friend` cannot appear in `groups`.")

    poll_interval_sec = float(raw.get("poll_interval_sec", 1.0))
    dedupe_ttl_sec = float(raw.get("dedupe_ttl_sec", 600))
    send_delay_sec = float(raw.get("send_delay_sec", 0.15))
    max_send_per_cycle = int(raw.get("max_send_per_cycle", 10))
    case_sensitive = bool(raw.get("case_sensitive", False))
    use_regex = bool(raw.get("use_regex", False))
    message_template = str(raw.get("message_template", DEFAULT_TEMPLATE))
    is_maximize = bool(raw.get("is_maximize", False))
    close_weixin_on_exit = bool(raw.get("close_weixin_on_exit", False))
    use_direct_poll = bool(raw.get("use_direct_poll", True))
    pull_count = int(raw.get("pull_count", 5))
    use_window_listener = bool(raw.get("use_window_listener", True))
    window_minimize = bool(raw.get("window_minimize", True))
    window_tail_scan_count = int(raw.get("window_tail_scan_count", DEFAULT_WINDOW_TAIL_SCAN_COUNT))
    listener_window_offset_x = int(raw.get("listener_window_offset_x", -260))

    if poll_interval_sec <= 0:
        raise ValueError("`poll_interval_sec` must be > 0.")
    if dedupe_ttl_sec < 0:
        raise ValueError("`dedupe_ttl_sec` must be >= 0.")
    if send_delay_sec < 0:
        raise ValueError("`send_delay_sec` must be >= 0.")
    if max_send_per_cycle <= 0:
        raise ValueError("`max_send_per_cycle` must be > 0.")
    if pull_count <= 0:
        raise ValueError("`pull_count` must be > 0.")
    if window_tail_scan_count <= 0:
        raise ValueError("`window_tail_scan_count` must be > 0.")

    if use_regex:
        flags = 0 if case_sensitive else re.IGNORECASE
        for pattern in keywords:
            re.compile(pattern, flags=flags)
        for pattern in exclude_keywords:
            re.compile(pattern, flags=flags)

    return ForwarderConfig(
        target_friend=target_friend,
        groups=groups,
        keywords=keywords,
        exclude_keywords=exclude_keywords,
        poll_interval_sec=poll_interval_sec,
        dedupe_ttl_sec=dedupe_ttl_sec,
        case_sensitive=case_sensitive,
        use_regex=use_regex,
        send_delay_sec=send_delay_sec,
        max_send_per_cycle=max_send_per_cycle,
        message_template=message_template,
        is_maximize=is_maximize,
        close_weixin_on_exit=close_weixin_on_exit,
        use_direct_poll=use_direct_poll,
        pull_count=pull_count,
        use_window_listener=use_window_listener,
        window_minimize=window_minimize,
        window_tail_scan_count=window_tail_scan_count,
        listener_window_offset_x=listener_window_offset_x,
    )


def _extract_message_texts(payload: Any) -> list[str]:
    """Normalize check_new_messages payload to a list of message texts."""
    if payload is None:
        return []
    if isinstance(payload, str):
        return [payload]
    if isinstance(payload, list):
        return [str(item) for item in payload if str(item).strip()]
    if isinstance(payload, tuple):
        return [str(item) for item in payload if str(item).strip()]
    if isinstance(payload, dict):
        for key in ("消息内容", "messages", "texts"):
            value = payload.get(key)
            if isinstance(value, list):
                return [str(item) for item in value if str(item).strip()]
        return [str(payload)]
    return [str(payload)]


def _truncate_message(message: str, max_len: int = DEFAULT_MAX_MESSAGE_LEN) -> str:
    if len(message) <= max_len:
        return message
    return f"{message[:max_len]}...(截断)"


def _build_fingerprint(group: str, message: str) -> str:
    raw = f"{group}|{message}".encode("utf-8")
    return hashlib.sha1(raw).hexdigest()


def _runtime_id_to_key(runtime_id: Any) -> str:
    if runtime_id is None:
        return ""
    if isinstance(runtime_id, (list, tuple)):
        return ",".join(str(part) for part in runtime_id)
    return str(runtime_id)


def _resolve_chat_list(dialog_window: Any) -> Any | None:
    """Get chat list from separate dialog window with robust fallback."""
    try:
        chat_list = dialog_window.child_window(title="消息", control_type="List")
        if chat_list.exists(timeout=0.1):
            return chat_list
    except Exception:
        pass

    try:
        candidates = dialog_window.descendants(control_type="List")
    except Exception:
        return None

    best_candidate = None
    best_count = -1
    for candidate in candidates:
        try:
            count = len(candidate.children(control_type="ListItem"))
        except Exception:
            continue
        if count > best_count:
            best_candidate = candidate
            best_count = count
    return best_candidate


def _reopen_listener_window(
    group: str,
    state: WindowListenerState,
    config: ForwarderConfig,
    debug: bool,
) -> bool:
    try:
        try:
            state.dialog_window.close()
        except Exception:
            pass
        dialog_window = Navigator.open_seperate_dialog_window(
            friend=group,
            is_maximize=config.is_maximize,
            window_minimize=config.window_minimize,
            close_weixin=False,
        )
        _apply_listener_window_offset(dialog_window, config.listener_window_offset_x)
        state.dialog_window = dialog_window
        state.chat_list = None
        state.seen_item_keys.clear()
        state.item_key_order.clear()
        state.last_time_hint = ""
        state.warmup_on_next_collect = True
        print(f"[INFO] reopened listener window for: {group}")
        return True
    except Exception as exc:
        print(f"[WARN] failed to reopen listener window '{group}': {exc}")
        if debug:
            print(f"[DEBUG] listener window reopen failed for group={group}")
        return False


def _ensure_listener_window_ready(
    group: str,
    state: WindowListenerState,
    config: ForwarderConfig,
    debug: bool,
) -> bool:
    try:
        if not state.dialog_window.exists(timeout=0.1):
            if debug:
                print(f"[DEBUG] listener window missing for group={group}, reopening...")
            return _reopen_listener_window(group, state, config, debug)
    except Exception:
        if debug:
            print(f"[DEBUG] listener window check failed for group={group}, reopening...")
        return _reopen_listener_window(group, state, config, debug)

    chat_list = _resolve_chat_list(state.dialog_window)
    if chat_list is None:
        if debug:
            print(f"[DEBUG] chat list missing for group={group}, reopening...")
        return _reopen_listener_window(group, state, config, debug)

    state.chat_list = chat_list
    return True


def _collect_new_messages_from_dialog_window(
    group: str,
    state: WindowListenerState,
    tail_scan_count: int,
    warmup: bool,
    debug: bool,
) -> list[str]:
    effective_warmup = warmup or state.warmup_on_next_collect

    refreshed_chat_list = _resolve_chat_list(state.dialog_window)
    if refreshed_chat_list is not None:
        state.chat_list = refreshed_chat_list

    if state.chat_list is None:
        state.chat_list = _resolve_chat_list(state.dialog_window)
        if state.chat_list is None:
            if debug:
                print(f"[DEBUG] group={group} chat list not found.")
            return []

    try:
        chat_items = state.chat_list.children(control_type="ListItem")
    except Exception:
        state.chat_list = _resolve_chat_list(state.dialog_window)
        if state.chat_list is None:
            if debug:
                print(f"[DEBUG] group={group} chat list refresh failed.")
            return []
        chat_items = state.chat_list.children(control_type="ListItem")

    if not chat_items:
        if debug:
            print(f"[DEBUG] group={group} chat list is empty.")
        return []

    start_index = max(0, len(chat_items) - tail_scan_count)
    new_item_count = 0
    texts: list[str] = []

    for item in chat_items[start_index:]:
        runtime_id = _runtime_id_to_key(getattr(item.element_info, "runtime_id", None))
        text = str(item.window_text() or "").strip()
        if not runtime_id:
            runtime_id = "runtime-missing"

        class_name = "unknown"
        try:
            class_name = item.class_name() or "unknown"
        except Exception:
            pass

        text_digest = hashlib.sha1(text.encode("utf-8")).hexdigest() if text else "empty"
        item_key = f"{runtime_id}|{class_name}|{text_digest}"
        if not state.mark_seen(item_key):
            continue
        new_item_count += 1

        if effective_warmup:
            continue

        if not text:
            continue
        if _looks_like_time_line(text):
            state.last_time_hint = text
            if debug:
                print(f"[DEBUG] time hint group={group} send_time={text}")
            continue
        texts.append(text)

        if debug:
            preview = _truncate_message(text, max_len=80).replace("\n", " ")
            print(f"[DEBUG] capture group={group} class={class_name} message={preview}")

    if debug:
        print(
            f"[DEBUG] group={group} total_items={len(chat_items)} "
            f"scanned={len(chat_items) - start_index} new_items={new_item_count} "
            f"text_messages={len(texts)} warmup={effective_warmup}"
        )

    if state.warmup_on_next_collect:
        state.warmup_on_next_collect = False
        if debug:
            print(f"[DEBUG] reopen warmup complete for group={group}")

    return texts


def _apply_listener_window_offset(dialog_window: Any, offset_x: int) -> None:
    """Shift listener window horizontally to avoid covering the main window."""
    if offset_x == 0:
        return
    try:
        rect = dialog_window.rectangle()
        width = rect.width()
        height = rect.height()
        target_x = rect.left + int(offset_x)
        target_y = rect.top

        screen_width = win32api.GetSystemMetrics(win32con.SM_CXSCREEN)
        screen_height = win32api.GetSystemMetrics(win32con.SM_CYSCREEN)
        max_x = max(0, screen_width - width)
        max_y = max(0, screen_height - height)
        target_x = max(0, min(target_x, max_x))
        target_y = max(0, min(target_y, max_y))

        win32gui.MoveWindow(dialog_window.handle, target_x, target_y, width, height, True)
    except Exception as exc:
        print(f"[WARN] failed to move listener window: {exc}")


def _reactivate_listener_windows(
    window_states: dict[str, WindowListenerState],
    debug: bool = False,
) -> None:
    """After sending messages, bring listener windows back to active chat-bottom state."""
    if not window_states:
        return
    for group, state in window_states.items():
        try:
            if not state.dialog_window.exists(timeout=0.1):
                continue
            try:
                state.dialog_window.set_focus()
            except Exception:
                pass
            state.chat_list = _resolve_chat_list(state.dialog_window)
            if state.chat_list is not None:
                try:
                    state.chat_list.type_keys("{END}", pause=0.01)
                except Exception:
                    pass
            if debug:
                print(f"[DEBUG] reactivated listener window: {group}")
        except Exception as exc:
            print(f"[WARN] failed to reactivate listener window '{group}': {exc}")


_TIME_LINE_PATTERNS = (
    re.compile(r"^\d{1,2}:\d{2}(?::\d{2})?$"),
    re.compile(r"^\d{4}[-/]\d{1,2}[-/]\d{1,2}\s+\d{1,2}:\d{2}(?::\d{2})?$"),
    re.compile(r"^(?:today|yesterday)\s+\d{1,2}:\d{2}(?::\d{2})?$", flags=re.IGNORECASE),
    re.compile(r"^(?:今天|昨天)\s*\d{1,2}:\d{2}(?::\d{2})?$"),
    re.compile(r"^(?:星期|周)[一二三四五六日天]\s*\d{1,2}:\d{2}(?::\d{2})?$"),
)


def _looks_like_time_line(line: str) -> bool:
    text = line.strip()
    return bool(text) and any(pattern.match(text) for pattern in _TIME_LINE_PATTERNS)


def _is_probable_sender_name(text: str) -> bool:
    """Heuristic guard to avoid treating normal message content as sender name."""
    candidate = text.strip()
    if not candidate:
        return False
    if len(candidate) > 24:
        return False
    if _looks_like_time_line(candidate):
        return False
    # Typical content markers in your chat records; unlikely to be a nickname.
    if any(token in candidate for token in ("年", "月", "日", "点", "🈳")):
        return False
    if re.search(r"\d", candidate):
        return False
    if re.search(r"[，,。；;！？?!]", candidate):
        return False
    return True


def _extract_sender_and_time(raw_message: str) -> tuple[str, str]:
    """Best-effort extraction of sender and message time from raw message text."""
    lines = [line.strip() for line in raw_message.splitlines() if line.strip()]
    if not lines:
        return "未知发送者", "未知时间"

    sender = ""
    send_time = ""

    for index, line in enumerate(lines):
        if _looks_like_time_line(line):
            send_time = line
            if index > 0:
                previous = lines[index - 1]
                if _is_probable_sender_name(previous):
                    sender = previous
            break

    if not sender:
        sender_prefix = re.match(r"^([^:：]{1,40})[:：]\s*.+$", lines[0])
        if sender_prefix:
            prefix_sender = sender_prefix.group(1).strip()
            if _is_probable_sender_name(prefix_sender):
                sender = prefix_sender

    if not sender and len(lines) >= 2:
        first_line = lines[0]
        if _is_probable_sender_name(first_line):
            sender = first_line

    if sender and len(sender) > 40:
        sender = ""

    if not sender:
        sender = "未知发送者"
    if not send_time:
        send_time = "未知时间"
    return sender, send_time


def _render_forward_message(
    template: str,
    group: str,
    keyword: str,
    message: str,
    sender: str,
    send_time: str,
) -> str:
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    safe_message = _truncate_message(message)
    try:
        return template.format(
            group=group,
            keyword=keyword,
            time=current_time,
            message=safe_message,
            sender=sender,
            send_time=send_time,
        )
    except Exception:
        return DEFAULT_TEMPLATE.format(
            group=group,
            keyword=keyword,
            time=current_time,
            message=safe_message,
            sender=sender,
            send_time=send_time,
        )


def _collect_notifications(
    config: ForwarderConfig,
    matcher: KeywordMatcher,
    cache: FingerprintCache,
    window_states: dict[str, WindowListenerState] | None = None,
    warmup: bool = False,
    debug: bool = False,
) -> list[str]:
    notifications: list[str] = []
    now = time.time()
    cache.cleanup(now)

    group_payloads: dict[str, Any] = {}
    if window_states:
        for group, state in window_states.items():
            if not _ensure_listener_window_ready(
                group=group,
                state=state,
                config=config,
                debug=debug,
            ):
                continue
            try:
                texts = _collect_new_messages_from_dialog_window(
                    group=group,
                    state=state,
                    tail_scan_count=config.window_tail_scan_count,
                    warmup=warmup,
                    debug=debug,
                )
            except Exception as exc:
                print(f"[WARN] window listener failed for '{group}': {exc}")
                continue
            if texts:
                group_payloads[group] = texts
    elif config.use_direct_poll:
        for group in config.groups:
            try:
                payload = Messages.pull_messages(
                    friend=group,
                    number=config.pull_count,
                    search_pages=0,
                    is_maximize=config.is_maximize,
                    close_weixin=False,
                )
            except Exception as exc:
                print(f"[WARN] pull_messages failed for '{group}': {exc}")
                continue
            group_payloads[group] = payload
    else:
        raw_messages = Messages.check_new_messages(
            close_weixin=False,
            is_maximize=config.is_maximize,
        )
        if not raw_messages:
            return notifications
        if not isinstance(raw_messages, dict):
            print(f"[WARN] Unexpected message payload type: {type(raw_messages).__name__}")
            return notifications
        for group in config.groups:
            payload = raw_messages.get(group)
            if payload is not None:
                group_payloads[group] = payload

    for group, payload in group_payloads.items():
        for message in _extract_message_texts(payload):
            text = message.strip()
            if not text:
                continue
            if matcher.is_excluded(text):
                continue

            matched_keyword = matcher.match_keyword(text)
            if matched_keyword is None:
                continue

            if not window_states:
                # Poll fallback mode can repeatedly read the same latest messages,
                # so we keep content-level TTL dedupe there.
                fingerprint = _build_fingerprint(group, text)
                if cache.contains(fingerprint, now):
                    continue
                cache.add(fingerprint, now)
            if warmup:
                continue

            sender, send_time = _extract_sender_and_time(text)
            if window_states:
                if send_time == "未知时间":
                    state = window_states.get(group)
                    if state and state.last_time_hint:
                        send_time = state.last_time_hint
                    else:
                        send_time = datetime.now().strftime("%H:%M:%S")
            notification = _render_forward_message(
                template=config.message_template,
                group=group,
                keyword=matched_keyword,
                message=text,
                sender=sender,
                send_time=send_time,
            )
            notifications.append(notification)

            preview = _truncate_message(text, max_len=80).replace("\n", " ")
            print(
                f"[MATCH] group={group} keyword={matched_keyword} "
                f"sender={sender} send_time={send_time} message={preview}"
            )

            if len(notifications) >= config.max_send_per_cycle:
                print(
                    "[WARN] Reached max_send_per_cycle="
                    f"{config.max_send_per_cycle}, remaining matches will wait next cycle."
                )
                return notifications

    if debug and window_states and not group_payloads:
        print("[DEBUG] no new chat items detected in current cycle.")

    return notifications

def _close_weixin_if_needed(is_maximize: bool) -> None:
    try:
        from pyweixin import Navigator

        main_window = Navigator.open_weixin(is_maximize=is_maximize)
        main_window.close()
        print("[INFO] WeChat window closed.")
    except Exception as exc:
        print(f"[WARN] Failed to close WeChat window: {exc}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Forward group keyword messages to a target friend.")
    parser.add_argument(
        "--config",
        default=DEFAULT_CONFIG_PATH,
        help="Path to config JSON file. Default: config/group_keyword_forwarder.json",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Only print matched messages, do not send.",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Run one polling cycle and exit.",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Print listener debug output for each polling cycle.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    config_path = pathlib.Path(args.config)
    if not config_path.is_absolute():
        config_path = PROJECT_ROOT / config_path

    try:
        config = _load_config(config_path)
    except Exception as exc:
        print(f"[ERROR] {exc}")
        raise SystemExit(2)

    matcher = KeywordMatcher(
        keywords=config.keywords,
        exclude_keywords=config.exclude_keywords,
        case_sensitive=config.case_sensitive,
        use_regex=config.use_regex,
    )
    cache = FingerprintCache(ttl_seconds=config.dedupe_ttl_sec)

    print("=" * 60)
    print("Group Keyword Forwarder started")
    print("=" * 60)
    print(f"Config: {config_path}")
    print(f"Target friend: {config.target_friend}")
    print(f"Groups: {list(config.groups)}")
    print(f"Keywords: {list(config.keywords)}")
    print(f"Exclude keywords: {list(config.exclude_keywords)}")
    print(f"Poll interval: {config.poll_interval_sec}s")
    print(f"Dedupe TTL: {config.dedupe_ttl_sec}s")
    print(f"Use window listener: {config.use_window_listener}")
    print(f"Window tail scan count: {config.window_tail_scan_count}")
    print(f"Window minimize: {config.window_minimize}")
    print(f"Listener window offset x: {config.listener_window_offset_x}px")
    print(f"Use direct poll: {config.use_direct_poll}")
    print(f"Pull count: {config.pull_count}")
    print(f"Dry run: {args.dry_run}")
    print(f"Once: {args.once}")
    print(f"Debug: {args.debug}")
    print("=" * 60)

    window_states: dict[str, WindowListenerState] = {}
    if config.use_window_listener:
        for group in config.groups:
            try:
                dialog_window = Navigator.open_seperate_dialog_window(
                    friend=group,
                    is_maximize=config.is_maximize,
                    window_minimize=config.window_minimize,
                    close_weixin=False,
                )
                _apply_listener_window_offset(dialog_window, config.listener_window_offset_x)
                window_states[group] = WindowListenerState(dialog_window=dialog_window)
                print(f"[INFO] opened window listener for: {group}")
            except Exception as exc:
                print(f"[WARN] failed to open window for '{group}': {exc}")
        if not window_states:
            print("[WARN] no dialog window opened, fallback to polling mode.")
        else:
            print("[INFO] using persistent window runtime-id listener (no per-cycle search).")

    try:
        _collect_notifications(
            config=config,
            matcher=matcher,
            cache=cache,
            window_states=window_states if window_states else None,
            warmup=True,
            debug=args.debug,
        )
        print("[INFO] warmup complete, history messages skipped.")
    except Exception as exc:
        print(f"[WARN] warmup failed: {exc}")

    try:
        while True:
            loop_start = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print(f"[{loop_start}] polling...")

            try:
                notifications = _collect_notifications(
                    config=config,
                    matcher=matcher,
                    cache=cache,
                    window_states=window_states if window_states else None,
                    debug=args.debug,
                )
            except Exception as exc:
                print(f"[ERROR] polling failed: {exc}")
                notifications = []

            if notifications:
                if args.dry_run:
                    for index, notification in enumerate(notifications, start=1):
                        print(f"[DRY-RUN] notification#{index}\n{notification}\n")
                else:
                    try:
                        Messages.send_messages_to_friend(
                            friend=config.target_friend,
                            messages=notifications,
                            send_delay=config.send_delay_sec,
                            is_maximize=config.is_maximize,
                            close_weixin=False,
                        )
                        print(f"[INFO] sent {len(notifications)} notification(s).")
                    except Exception as exc:
                        print(f"[ERROR] sending failed: {exc}")
                    finally:
                        if window_states:
                            _reactivate_listener_windows(window_states, debug=args.debug)
            else:
                print("[INFO] no matched messages in this cycle.")

            if args.once:
                break

            time.sleep(config.poll_interval_sec)

    except KeyboardInterrupt:
        print("\n[INFO] interrupted by user.")
    finally:
        for state in window_states.values():
            try:
                state.dialog_window.close()
            except Exception:
                pass
        if config.close_weixin_on_exit:
            _close_weixin_if_needed(is_maximize=config.is_maximize)
        print("[INFO] forwarder exited.")


if __name__ == "__main__":
    main()

