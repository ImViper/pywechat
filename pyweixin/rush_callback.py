"""Reusable AI callback for moments rush (production + testing)."""

from __future__ import annotations

import os
import re
import time
from typing import Any

ANSWER_MODE_STANDARD = "standard"
ANSWER_MODE_COUNT_SUFFIX = "count_suffix"


def _normalize_answer_mode(answer_mode: str | None) -> str:
    mode = str(answer_mode or ANSWER_MODE_STANDARD).strip().lower()
    if mode in {"count_suffix", "suffix", "count_only"}:
        return ANSWER_MODE_COUNT_SUFFIX
    return ANSWER_MODE_STANDARD


def _is_count_suffix_mode(answer_mode: str | None, answer_suffix: str | None) -> bool:
    return _normalize_answer_mode(answer_mode) == ANSWER_MODE_COUNT_SUFFIX and bool(answer_suffix)


def _provider_name(ai_provider: Any) -> str:
    return str(
        getattr(ai_provider, "name", "")
        or getattr(ai_provider, "__class__", type(ai_provider)).__name__
    )


def _provider_model(ai_provider: Any) -> str:
    return str(getattr(ai_provider, "model", "") or "")


def _set_last_ai_metadata(
    ai_provider: Any,
    *,
    latency_ms: int,
    answer: str = "",
    raw_answer: str = "",
    ok: bool = False,
    error: str = "",
) -> dict[str, Any]:
    meta = {
        "provider": _provider_name(ai_provider),
        "model": _provider_model(ai_provider),
        "latency_ms": int(latency_ms),
        "answer": str(answer or ""),
        "raw_answer": str(raw_answer or ""),
        "ok": bool(ok),
        "error": str(error or ""),
    }
    try:
        setattr(ai_provider, "_pyweixin_last_ai_metadata", meta)
    except Exception:
        pass
    return meta


def get_last_ai_metadata(ai_provider: Any) -> dict[str, Any]:
    meta = getattr(ai_provider, "_pyweixin_last_ai_metadata", None)
    return dict(meta) if isinstance(meta, dict) else {}


def try_ocr_count(
    content: str,
    image_paths: list[str],
    ocr_provider: Any,
    verbose: bool = True,
    known_keywords: list[str] | None = None,
) -> str | None:
    """
    Extract target keyword from question and count occurrences in OCR text.

    Keyword extraction priority:
      1. Quoted text in question (Chinese/English quotes, brackets)
      2. Known keywords list matched against question text
    """
    if ocr_provider is None or not image_paths:
        return None

    # Extract target keyword from quoted text or brackets in question
    # Matches: \u201c keyword \u201d, "keyword", [keyword]
    target = None
    # Normalize escaped quotes from Windows UI Automation (\" → ")
    content = content.replace('\\"', '"').replace("\\'", "'")
    patterns = [
        '[\u201c\u201d](.+?)[\u201c\u201d]',     # Chinese double quotes \u201c\u201d
        '[\u2018\u2019](.+?)[\u2018\u2019]',     # Chinese single quotes \u2018\u2019
        '[\u300c\u300d](.+?)[\u300c\u300d]',     # Corner brackets \u300c\u300d
        '\uff02(.+?)\uff02',                       # Fullwidth quotation mark \uff02
        r'"(.+?)"',                               # English double quotes
        r'\[([^\[\]]+?)\]',                       # Square brackets (exclude nested)
    ]
    if verbose:
        # Debug: show content and quote characters
        quote_like = [f'{c} U+{ord(c):04X}' for c in content if ord(c) in (
            0x0022, 0x0027, 0x201C, 0x201D, 0x2018, 0x2019, 0x300C, 0x300D, 0xFF02,
        )]
        print(f"[OCR:debug] content (first 120): {content[:120]!r}")
        print(f"[OCR:debug] quote-like chars: {quote_like}")
    for pattern in patterns:
        m = re.search(pattern, content)
        if m:
            candidate = m.group(1).strip()
            if verbose:
                print(f"[OCR:debug] pattern matched candidate: {candidate!r}")
            # Skip generic patterns like “正确答案+性别” or format instructions
            if candidate and not any(x in candidate for x in ["正确答案", "格式", "评论"]):
                target = candidate
                break
            elif verbose:
                print(f"[OCR:debug] skipped (contains filter word)")

    if not target:
        # Fallback: match known keywords against question text
        if known_keywords:
            for kw in known_keywords:
                if kw in content:
                    target = kw
                    if verbose:
                        print(f"[OCR] matched known keyword: {target!r}")
                    break
        if not target:
            if verbose:
                print("[OCR] No keyword found in question, skip OCR counting")
            return None

    if verbose:
        print(f"[OCR] target keyword: {target}")
    start_time = time.time()

    total_count = 0
    for img_path in image_paths:
        try:
            ocr_text = ocr_provider.extract_text(img_path)
            if not ocr_text:
                if verbose:
                    print(f"[OCR] {os.path.basename(img_path)}: no text")
                continue
            texts = [line.strip() for line in ocr_text.splitlines() if line.strip()]
            count = sum(txt.count(target) for txt in texts)
            total_count += count
            if verbose:
                print(f"[OCR] {os.path.basename(img_path)}: lines={len(texts)} matched={count}")
        except Exception as exc:
            if verbose:
                print(f"[OCR] failed on {img_path}: {exc}")

    elapsed = int((time.time() - start_time) * 1000)
    if total_count > 0:
        try:
            max_count = int(os.environ.get("PYWEIXIN_OCR_COUNT_MAX", "20"))
        except Exception:
            max_count = 20
        if max_count > 0 and total_count > max_count:
            if verbose:
                print(
                    f"[OCR] suspicious high count={total_count} (> {max_count}), "
                    "drop OCR answer and fallback to AI"
                )
            return None
        answer = f"{total_count}{target}"
        if verbose:
            print(f"[OCR] answer={answer} ({elapsed}ms)")
        return answer

    if verbose:
        print(f"[OCR] no match for '{target}', fallback to AI ({elapsed}ms)")
    return None


def _extract_first_number(text: str) -> str:
    if not text:
        return ""
    match = re.search(r"(\d+)", text)
    if not match:
        return ""
    return match.group(1)


def _apply_answer_suffix(answer: str, answer_suffix: str | None) -> str:
    if not answer_suffix:
        return answer.strip()
    number = _extract_first_number(answer)
    if not number:
        return ""
    return f"{number}{answer_suffix}"


def _build_ai_question_text(
    content: str,
    answer_mode: str | None,
    answer_suffix: str | None,
) -> str:
    if not _is_count_suffix_mode(answer_mode, answer_suffix):
        return content
    return (
        f"{content}\n\n"
        "拼车模式补充要求：\n"
        "1. 这是数数题时，只输出最终阿拉伯数字。\n"
        "2. 不要角色名，不要对象名，不要单位，不要解释。\n"
        "3. 例如“有多少个葫芦”“多少把剑”“多少个人”都只输出数字。\n"
        "4. 如果无法判断，输出 SKIP。"
    )


def try_ai_answer(
    content: str,
    image_paths: list[str],
    ai_provider: Any,
    verbose: bool = True,
    answer_mode: str = ANSWER_MODE_STANDARD,
    answer_suffix: str | None = None,
) -> str | None:
    """
    Call AI provider to get answer.
    
    This is the standard AI answer logic used in production.
    """
    if ai_provider is None:
        return None

    ai_question_text = _build_ai_question_text(content, answer_mode, answer_suffix)
    start_time = time.time()
    try:
        result = ai_provider.answer_from_text_and_images(ai_question_text, image_paths, [])
        elapsed = int((time.time() - start_time) * 1000)
        if result is None:
            _set_last_ai_metadata(ai_provider, latency_ms=elapsed, ok=False)
            if verbose:
                print(f"[AI] no answer ({elapsed}ms)")
            return None

        answer = ""
        raw_answer = ""
        if hasattr(result, "answer") and result.answer:
            answer = result.answer
        elif isinstance(result, dict) and result.get("answer"):
            answer = str(result.get("answer", ""))
        elif isinstance(result, str):
            answer = result
        raw_answer = str(answer).strip()

        answer = str(answer).strip()
        # Handle malformed AnswerResult string representation
        bad_patterns = ["AnswerResult(", "confidence=", "source=", "latency_ms=", "extra={"]
        for pattern in bad_patterns:
            if pattern in answer:
                match = re.search(r"answer=['\"]([^'\"]+)['\"]", answer)
                if match:
                    answer = match.group(1).strip()
                else:
                    _set_last_ai_metadata(
                        ai_provider,
                        latency_ms=elapsed,
                        answer="",
                        raw_answer=raw_answer,
                        ok=False,
                    )
                    return None
                break

        if _is_count_suffix_mode(answer_mode, answer_suffix):
            normalized = _apply_answer_suffix(answer, answer_suffix)
            if not normalized:
                _set_last_ai_metadata(
                    ai_provider,
                    latency_ms=elapsed,
                    answer="",
                    raw_answer=raw_answer or answer,
                    ok=False,
                )
                if verbose:
                    print(f"[AI] no numeric answer for suffix mode ({elapsed}ms)")
                return None
            answer = normalized

        if answer:
            _set_last_ai_metadata(
                ai_provider,
                latency_ms=elapsed,
                answer=answer,
                raw_answer=raw_answer or answer,
                ok=True,
            )
            if verbose:
                print(f"[AI] answer={answer} ({elapsed}ms)")
            return answer
        _set_last_ai_metadata(
            ai_provider,
            latency_ms=elapsed,
            answer="",
            raw_answer=raw_answer,
            ok=False,
        )
        if verbose:
            print(f"[AI] empty answer ({elapsed}ms)")
        return None
    except Exception as exc:
        elapsed = int((time.time() - start_time) * 1000)
        _set_last_ai_metadata(
            ai_provider,
            latency_ms=elapsed,
            ok=False,
            error=str(exc),
        )
        if verbose:
            print(f"[AI] failed: {exc}")
        return None


def create_ai_callback(
    ocr_provider: Any = None,
    ai_provider: Any = None,
    compare_mode: bool = False,
    verbose: bool = True,
    known_keywords: list[str] | None = None,
    answer_mode: str = ANSWER_MODE_STANDARD,
    answer_suffix: str | None = None,
):
    """
    Create the standard ai_callback function used in production.
    
    Args:
        ocr_provider: PaddleOCRProvider instance or None
        ai_provider: ArkChatProvider instance or None
        compare_mode: If True, always run AI even when OCR hits (for comparison)
        verbose: If True, print progress logs
    
    Returns:
        Callable that takes (content, image_paths) and returns answer string or None
    """
    def ai_callback(content: str, image_paths: list[str]) -> str | None:
        """Prefer OCR answer first; fallback to AI. Return one final answer only."""
        if verbose:
            print(f"[recognize] start text_len={len(content)} images={len(image_paths)}")
        callback_start = time.time()

        ocr_answer = try_ocr_count(content, image_paths, ocr_provider, verbose=verbose, known_keywords=known_keywords)
        if ocr_answer:
            if not compare_mode:
                elapsed = int((time.time() - callback_start) * 1000)
                if verbose:
                    print(f"[recognize] OCR hit, skip AI ({elapsed}ms)")
                return ocr_answer
            if verbose:
                print("[recognize] OCR hit, compare mode enabled, continue with AI")

        ai_answer = try_ai_answer(
            content,
            image_paths,
            ai_provider,
            verbose=verbose,
            answer_mode=answer_mode,
            answer_suffix=answer_suffix,
        )
        if ocr_answer:
            elapsed = int((time.time() - callback_start) * 1000)
            if ai_answer:
                if ai_answer == ocr_answer:
                    if verbose:
                        print(f"[recognize] OCR/AI consistent: {ocr_answer} ({elapsed}ms)")
                else:
                    if verbose:
                        print(f"[recognize] OCR/AI mismatch: OCR={ocr_answer}, AI={ai_answer} ({elapsed}ms)")
            else:
                if verbose:
                    print(f"[recognize] OCR hit, AI empty, use OCR ({elapsed}ms)")
            return ocr_answer

        if ai_answer:
            elapsed = int((time.time() - callback_start) * 1000)
            if verbose:
                print(f"[recognize] use AI answer: {ai_answer} ({elapsed}ms)")
            return ai_answer
        return None

    return ai_callback


from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, as_completed


@dataclass
class AnswerWithTiming:
    """Answer result with timing and source info."""
    answer: str
    source: str  # "ocr" or "ai"
    elapsed_ms: int


def create_concurrent_callback(
    ocr_provider: Any = None,
    ai_provider: Any = None,
    verbose: bool = True,
    known_keywords: list[str] | None = None,
    answer_mode: str = ANSWER_MODE_STANDARD,
    answer_suffix: str | None = None,
):
    """
    Create a concurrent callback that runs OCR and AI in parallel.
    
    Returns multiple answers for dual commenting strategy.
    
    Args:
        ocr_provider: PaddleOCRProvider instance or None
        ai_provider: ArkChatProvider instance or None
        verbose: If True, print progress logs
    
    Returns:
        Callable that takes (content, image_paths) and returns list[AnswerWithTiming]
        The list contains 0-2 answers, ordered by completion time (fastest first).
    """
    def concurrent_callback(content: str, image_paths: list[str]) -> list[AnswerWithTiming]:
        """Run OCR and AI concurrently, return all valid answers ordered by speed."""
        if verbose:
            print(f"[concurrent] start text_len={len(content)} images={len(image_paths)}")
        callback_start = time.time()
        
        results: list[AnswerWithTiming] = []
        
        def run_ocr():
            start = time.time()
            answer = try_ocr_count(content, image_paths, ocr_provider, verbose=verbose, known_keywords=known_keywords)
            elapsed = int((time.time() - start) * 1000)
            if answer:
                return AnswerWithTiming(answer=answer, source="ocr", elapsed_ms=elapsed)
            return None
        
        def run_ai():
            start = time.time()
            answer = try_ai_answer(
                content,
                image_paths,
                ai_provider,
                verbose=verbose,
                answer_mode=answer_mode,
                answer_suffix=answer_suffix,
            )
            elapsed = int((time.time() - start) * 1000)
            if answer:
                return AnswerWithTiming(answer=answer, source="ai", elapsed_ms=elapsed)
            return None
        
        # Run both in parallel
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = []
            if ocr_provider and image_paths:
                futures.append(executor.submit(run_ocr))
            if ai_provider:
                futures.append(executor.submit(run_ai))
            
            # Collect results as they complete (fastest first)
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        results.append(result)
                except Exception as exc:
                    if verbose:
                        print(f"[concurrent] task failed: {exc}")
        
        total_elapsed = int((time.time() - callback_start) * 1000)
        
        if verbose:
            if not results:
                print(f"[concurrent] no answers ({total_elapsed}ms)")
            elif len(results) == 1:
                r = results[0]
                print(f"[concurrent] single answer: {r.answer} ({r.source}, {r.elapsed_ms}ms)")
            else:
                # Check if answers match
                if results[0].answer == results[1].answer:
                    print(f"[concurrent] both match: {results[0].answer} "
                          f"(ocr={next((r.elapsed_ms for r in results if r.source=='ocr'), '-')}ms, "
                          f"ai={next((r.elapsed_ms for r in results if r.source=='ai'), '-')}ms)")
                else:
                    print(f"[concurrent] different: "
                          f"{results[0].source}={results[0].answer} ({results[0].elapsed_ms}ms), "
                          f"{results[1].source}={results[1].answer} ({results[1].elapsed_ms}ms)")
        
        return results

    return concurrent_callback


def create_streaming_callback(
    ocr_provider: Any = None,
    ai_provider: Any = None,
    verbose: bool = True,
    known_keywords: list[str] | None = None,
    answer_mode: str = ANSWER_MODE_STANDARD,
    answer_suffix: str | None = None,
):
    """
    Create a streaming callback: answers are pushed to a queue as they arrive.

    Returns:
        Callable that takes (content, image_paths) and returns queue.Queue.
        The queue receives str answers as they complete (fastest first).
        A None sentinel marks that all tasks are done.
    """
    import queue
    from threading import Thread

    def streaming_callback(content: str, image_paths: list[str]) -> queue.Queue:
        answer_queue: queue.Queue = queue.Queue()
        setattr(answer_queue, "ai_metadata", {})
        if verbose:
            print(f"[streaming] start text_len={len(content)} images={len(image_paths)}")
        callback_start = time.time()
        seen: set[str] = set()
        count_suffix_mode = _is_count_suffix_mode(answer_mode, answer_suffix)

        def push(answer: str, source: str, elapsed: int):
            if count_suffix_mode:
                m = re.match(r'^(\d+)', answer)
                if m:
                    answer = f"{m.group(1)}{answer_suffix}"
            if answer and answer not in seen:
                seen.add(answer)
                if verbose:
                    print(f"[streaming] {source} ready: {answer} ({elapsed}ms) -> queue")
                answer_queue.put(answer)
            elif answer and verbose:
                print(f"[streaming] {source} duplicate: {answer} ({elapsed}ms), skip")

        def run_ocr():
            start = time.time()
            answer = try_ocr_count(content, image_paths, ocr_provider, verbose=verbose, known_keywords=known_keywords)
            elapsed = int((time.time() - start) * 1000)
            if answer:
                push(answer, "ocr", elapsed)

        def run_ai():
            start = time.time()
            answer = try_ai_answer(
                content,
                image_paths,
                ai_provider,
                verbose=verbose,
                answer_mode=answer_mode,
                answer_suffix=answer_suffix,
            )
            setattr(answer_queue, "ai_metadata", get_last_ai_metadata(ai_provider))
            elapsed = int((time.time() - start) * 1000)
            if answer:
                push(answer, "ai", elapsed)

        def run_all():
            with ThreadPoolExecutor(max_workers=2) as executor:
                futures = []
                if ocr_provider and image_paths:
                    futures.append(executor.submit(run_ocr))
                if ai_provider:
                    futures.append(executor.submit(run_ai))
                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception as exc:
                        if verbose:
                            print(f"[streaming] task failed: {exc}")
            total = int((time.time() - callback_start) * 1000)
            if verbose:
                print(f"[streaming] all done ({total}ms), {len(seen)} unique answers")
            answer_queue.put(None)  # sentinel

        Thread(target=run_all, daemon=True).start()
        return answer_queue

    return streaming_callback
