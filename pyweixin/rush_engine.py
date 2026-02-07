"""Fast Moments rush engine (template-first, AI fallback)."""

from __future__ import annotations

import concurrent.futures
import json
import logging
import os
import re
import time
import hashlib
from datetime import datetime
from typing import Any, Callable

try:
    from .rush_ai import AIAnswerProvider, OCRProvider, NullAIProvider, NullOCRProvider
    from .rush_state import RushStateStore
    from .rush_types import AnswerResult, QuestionTemplate, RushConfig, parse_datetime
except ImportError:  # pragma: no cover - for direct module import in local tests
    from rush_ai import AIAnswerProvider, OCRProvider, NullAIProvider, NullOCRProvider
    from rush_state import RushStateStore
    from rush_types import AnswerResult, QuestionTemplate, RushConfig, parse_datetime


def load_rush_config(config_path: str) -> RushConfig:
    """Load rush config from YAML or JSON."""
    if not os.path.exists(config_path):
        raise FileNotFoundError(f"Config file not found: {config_path}")
    suffix = os.path.splitext(config_path)[1].lower()
    if suffix in (".yml", ".yaml"):
        try:
            import yaml  # type: ignore
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError("PyYAML is required to load .yaml config files.") from exc
        with open(config_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
    else:
        with open(config_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError("Config content must be a dictionary/mapping.")
    return RushConfig.from_mapping(data)


def _normalize_config(config: RushConfig | dict[str, Any] | str) -> RushConfig:
    if isinstance(config, RushConfig):
        return config
    if isinstance(config, str):
        return load_rush_config(config)
    if isinstance(config, dict):
        return RushConfig.from_mapping(config)
    raise TypeError("config must be RushConfig, dict, or config path.")


def _read_text_if_exists(path: str) -> str:
    if not path or not os.path.exists(path):
        return ""
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read().strip()
    except OSError:
        return ""


def _file_sha1(path: str) -> str:
    if not path or not os.path.isfile(path):
        return ""
    hasher = hashlib.sha1()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 64), b""):
                hasher.update(chunk)
        return hasher.hexdigest()
    except OSError:
        return ""


def build_post_fingerprint(content: str, publish_time: str, image_paths: list[str]) -> str:
    """Build deterministic fingerprint from post content and first image hash."""
    hasher = hashlib.sha1()
    hasher.update((content or "").encode("utf-8"))
    hasher.update((publish_time or "").encode("utf-8"))
    if image_paths:
        hasher.update(_file_sha1(image_paths[0]).encode("utf-8"))
    return hasher.hexdigest()


def post_matches_filters(content: str, include_keywords: list[str], exclude_keywords: list[str]) -> bool:
    """Apply include/exclude keyword filters."""
    text = content or ""
    if include_keywords and not any(k in text for k in include_keywords):
        return False
    if exclude_keywords and any(k in text for k in exclude_keywords):
        return False
    return True


def _extract_match_value(match: re.Match[str]) -> tuple[str, dict[str, str]]:
    groups = {k: v for k, v in match.groupdict().items() if v is not None}
    if "value" in groups and groups["value"]:
        return groups["value"], groups
    for value in match.groups():
        if value is not None and value != "":
            return value, groups
    if groups:
        first = next(iter(groups.values()))
        return first, groups
    return match.group(0), groups


def parse_answer_from_templates(question_text: str, templates: list[QuestionTemplate]) -> AnswerResult | None:
    """Try template matching first for fastest answer extraction."""
    if not templates:
        return None
    ordered = sorted(templates, key=lambda t: t.priority)
    for template in ordered:
        if template.trigger_patterns:
            if not any(re.search(pattern, question_text, flags=re.IGNORECASE) for pattern in template.trigger_patterns):
                continue
        for pattern in template.answer_patterns:
            match = re.search(pattern, question_text, flags=re.IGNORECASE)
            if not match:
                continue
            value, groups = _extract_match_value(match)
            value = value.strip()
            if not value:
                continue
            format_kwargs = dict(groups)
            format_kwargs.setdefault("value", value)
            answer = template.answer_format.format(**format_kwargs).strip()
            if answer:
                return AnswerResult(
                    answer=answer,
                    confidence=0.95,
                    source=f"template:{template.name}",
                    extra={"template": template.name, "value": value},
                )
    return None


def _collect_ocr_text(image_paths: list[str], ocr_provider: OCRProvider | None) -> str:
    if not ocr_provider:
        return ""
    chunks: list[str] = []
    for path in image_paths:
        try:
            text = ocr_provider.extract_text(path)
            if text:
                chunks.append(text.strip())
        except Exception:
            continue
    return "\n".join(chunks).strip()


def _normalize_ai_result(ai_result: Any) -> AnswerResult | None:
    if ai_result is None:
        return None
    if isinstance(ai_result, AnswerResult):
        return ai_result
    if isinstance(ai_result, str):
        answer = ai_result.strip()
        if not answer:
            return None
        return AnswerResult(answer=answer, confidence=0.5, source="ai")
    if isinstance(ai_result, dict):
        answer = str(ai_result.get("answer", "")).strip()
        if not answer:
            return None
        return AnswerResult(
            answer=answer,
            confidence=float(ai_result.get("confidence", 0.5)),
            source=str(ai_result.get("source", "ai")),
            latency_ms=int(ai_result.get("latency_ms", 0)),
            extra=dict(ai_result.get("extra", {})),
        )
    return None


def _call_ai_with_timeout(
    ai_provider: AIAnswerProvider,
    question_text: str,
    image_paths: list[str],
    templates: list[QuestionTemplate],
    timeout_ms: int,
) -> AnswerResult | None:
    timeout_s = max(timeout_ms, 1) / 1000.0
    executor = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    future = executor.submit(ai_provider.answer_from_text_and_images, question_text, image_paths, templates)
    try:
        result = future.result(timeout=timeout_s)
    except concurrent.futures.TimeoutError:
        future.cancel()
        executor.shutdown(wait=False, cancel_futures=True)
        return None
    except Exception:
        executor.shutdown(wait=False, cancel_futures=True)
        raise
    executor.shutdown(wait=False, cancel_futures=True)
    return _normalize_ai_result(result)


def resolve_answer(
    *,
    post_content: str,
    detail_text: str,
    image_paths: list[str],
    templates: list[QuestionTemplate],
    ocr_provider: OCRProvider | None = None,
    ai_provider: AIAnswerProvider | None = None,
    ai_enabled: bool = True,
    ai_timeout_ms: int = 1200,
    confidence_threshold: float = 0.0,
    default_answer: str | None = None,
) -> AnswerResult | None:
    """Resolve answer via template first, AI fallback."""
    start = time.perf_counter()
    ocr_text = _collect_ocr_text(image_paths, ocr_provider)
    question_text = "\n".join(
        part.strip()
        for part in (post_content or "", detail_text or "", ocr_text or "")
        if part and part.strip()
    ).strip()
    if not question_text:
        question_text = (post_content or "").strip()

    result = parse_answer_from_templates(question_text, templates)
    if result:
        result.latency_ms = int((time.perf_counter() - start) * 1000)
        return result

    if ai_enabled and ai_provider:
        try:
            ai_result = _call_ai_with_timeout(ai_provider, question_text, image_paths, templates, ai_timeout_ms)
        except Exception:
            ai_result = None
        if ai_result and ai_result.answer:
            if ai_result.confidence >= confidence_threshold:
                ai_result.latency_ms = int((time.perf_counter() - start) * 1000)
                return ai_result

    if default_answer:
        return AnswerResult(
            answer=default_answer.strip(),
            confidence=0.0,
            source="default",
            latency_ms=int((time.perf_counter() - start) * 1000),
        )
    return None


def _build_logger(config: RushConfig) -> logging.Logger:
    logger = logging.getLogger(f"pyweixin.rush.{config.event_id}")
    if logger.handlers:
        return logger
    logger.setLevel(logging.INFO)

    # 文件日志
    log_dir = os.path.join(config.output_dir, "logs")
    os.makedirs(log_dir, exist_ok=True)
    file_path = os.path.join(log_dir, f"rush_{datetime.now().strftime('%Y%m%d')}.log")
    file_handler = logging.FileHandler(file_path, encoding="utf-8")
    file_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
    logger.addHandler(file_handler)

    # 终端日志（实时显示）
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(logging.Formatter("[%(asctime)s] %(message)s", datefmt="%H:%M:%S"))
    logger.addHandler(console_handler)

    return logger


def run_rush_loop(
    config: RushConfig | dict[str, Any] | str,
    *,
    ai_provider: AIAnswerProvider | None = None,
    ocr_provider: OCRProvider | None = None,
    fetch_latest_post: Callable[..., dict[str, Any] | None] | None = None,
    comment_post: Callable[..., bool] | None = None,
    max_loops: int | None = None,
    logger: logging.Logger | None = None,
) -> dict[str, Any]:
    """
    Main rush loop.
    - Detects latest post from target friend.
    - Resolves answer from templates and AI fallback.
    - Auto-comments once matched.
    """
    cfg = _normalize_config(config)
    if not cfg.target_friend_remark:
        raise ValueError("target_friend_remark is required.")

    if ai_provider is None:
        ai_provider = NullAIProvider()
    if ocr_provider is None:
        ocr_provider = NullOCRProvider()
    if logger is None:
        logger = _build_logger(cfg)

    if fetch_latest_post is None or comment_post is None:
        from .WeChatAuto import Moments

        if fetch_latest_post is None:
            fetch_latest_post = Moments.get_latest_friend_moment
        if comment_post is None:
            comment_post = Moments.comment_friend_moment

    os.makedirs(cfg.output_dir, exist_ok=True)
    state_store = RushStateStore(cfg.state_file)
    state = state_store.load()
    if state.get("event_id") != cfg.event_id:
        state = state_store.reset_for_event(cfg.event_id)

    start_at = parse_datetime(cfg.monitor_start)
    end_at = parse_datetime(cfg.monitor_end)
    loops = 0

    while True:
        if max_loops is not None and loops >= max_loops:
            logger.info("max_loops reached, exit.")
            break
        loops += 1
        now = datetime.now()
        if end_at and now > end_at:
            logger.info("monitor_end reached, exit.")
            break
        if start_at and now < start_at:
            wait = min(cfg.poll_interval_sec, max((start_at - now).total_seconds(), 0.2))
            time.sleep(wait)
            continue

        state = state_store.load()
        if state.get("event_id") != cfg.event_id:
            state = state_store.reset_for_event(cfg.event_id)
        if bool(state.get("commented")) and cfg.comment_once:
            logger.info("already commented for current event, exit.")
            break

        logger.info("polling... (loop %d)", loops)

        context = fetch_latest_post(
            friend=cfg.target_friend_remark,
            target_folder=cfg.output_dir,
            is_maximize=cfg.is_maximize,
            close_weixin=cfg.close_weixin,
        )
        if not context:
            logger.info("no new post found, continue polling")
            time.sleep(cfg.poll_interval_sec)
            continue

        content = str(context.get("内容", ""))
        publish_time = str(context.get("发布时间", ""))
        image_count = context.get("图片数量", 0)
        image_paths = list(context.get("image_paths", []))
        screenshot_path = str(context.get("screenshot_path", ""))

        logger.info("fetched post: time=%s images=%d text_len=%d", publish_time, image_count, len(content))

        fingerprint = str(context.get("fingerprint", "")) or build_post_fingerprint(content, publish_time, image_paths)
        if fingerprint == state.get("last_post_fingerprint"):
            logger.info("duplicate post (same fingerprint), skip")
            time.sleep(cfg.poll_interval_sec)
            continue

        state_store.update(
            event_id=cfg.event_id,
            last_post_fingerprint=fingerprint,
            last_seen_time=now.isoformat(timespec="seconds"),
            status="new_post_detected",
        )
        logger.info("new post detected: %s", publish_time)

        if not post_matches_filters(content, cfg.include_keywords, cfg.exclude_keywords):
            state_store.update(status="filtered_out")
            logger.info("post filtered out by keyword rules")
            time.sleep(cfg.poll_interval_sec)
            continue

        logger.info("post passed keyword filter, start AI recognition")

        # 使用截图路径用于AI识别（如果有图片题）
        ai_image_paths = image_paths if image_paths else ([screenshot_path] if screenshot_path and image_count > 0 else [])

        detail_folder = str(context.get("detail_folder", ""))
        detail_text = _read_text_if_exists(os.path.join(detail_folder, "内容.txt")) if detail_folder else ""

        logger.info("calling AI with %d images...", len(ai_image_paths))
        answer_result = resolve_answer(
            post_content=content,
            detail_text=detail_text,
            image_paths=ai_image_paths,
            templates=cfg.templates,
            ocr_provider=ocr_provider,
            ai_provider=ai_provider,
            ai_enabled=cfg.ai_enabled,
            ai_timeout_ms=cfg.ai_timeout_ms,
            confidence_threshold=cfg.confidence_threshold,
            default_answer=cfg.default_answer,
        )

        if not answer_result or not answer_result.answer.strip():
            state_store.update(status="no_answer")
            logger.info("no answer generated from AI")
            time.sleep(cfg.poll_interval_sec)
            continue

        comment_text = answer_result.answer.strip()
        logger.info("AI answer: %s (confidence=%.2f, latency=%dms, source=%s)",
                   comment_text, answer_result.confidence, answer_result.latency_ms, answer_result.source)
        logger.info("posting comment...")

        success = False
        try:
            success = bool(
                comment_post(
                    friend=cfg.target_friend_remark,
                    comment_text=comment_text,
                    is_maximize=cfg.is_maximize,
                    close_weixin=cfg.close_weixin,
                )
            )
        except Exception as exc:
            logger.exception("comment failed with exception: %s", exc)

        state_store.update(
            event_id=cfg.event_id,
            status=("comment_success" if success else "comment_failed"),
            commented=bool(success),
            comment_text=comment_text,
            comment_time=datetime.now().isoformat(timespec="seconds"),
            answer_source=answer_result.source,
            answer_confidence=answer_result.confidence,
        )
        logger.info(
            "comment attempt result=%s source=%s confidence=%.3f latency_ms=%d text=%s",
            success,
            answer_result.source,
            answer_result.confidence,
            answer_result.latency_ms,
            comment_text,
        )

        if success:
            logger.info("="*60)
            logger.info("SUCCESS: Comment posted - '%s'", comment_text)
            logger.info("="*60)
        else:
            logger.warning("FAILED: Comment was not posted (check WeChat UI)")

        if success and cfg.comment_once:
            logger.info("comment_once=True, exiting monitoring loop")
            break
        time.sleep(cfg.poll_interval_sec)

    return state_store.load()
