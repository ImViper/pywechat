"""Unified benchmark for Moments answer recognition.

This is the only official evaluation entry.
It is aligned with production answer flow in `pyweixin.rush_engine.resolve_answer`:
template -> OCR-assisted template -> AI -> default answer.
"""

from __future__ import annotations

import argparse
import json
import os
import statistics
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from pyweixin.rush_ai import (
    ArkChatProvider,
    NullAIProvider,
    NullOCRProvider,
    PaddleOCRProvider,
    SiliconFlowOpenAIProvider,
)
from pyweixin.rush_engine import load_rush_config
from pyweixin.rush_callback import create_ai_callback


DEFAULT_TEST_FILE = PROJECT_ROOT / "dataset" / "test_cases.json"
DEFAULT_OUTPUT_DIR = PROJECT_ROOT / "dataset" / "results"


@dataclass(slots=True)
class EvalContext:
    dataset_file: Path
    config_path: str
    ai_provider_name: str
    ocr_provider_name: str
    ai_enabled: bool
    ai_timeout_ms: int
    confidence_threshold: float


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8-sig") as f:
        return json.load(f)


def load_test_cases(path: Path) -> list[dict[str, Any]]:
    data = load_json(path)
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]
    if isinstance(data, dict):
        rows = data.get("test_cases", [])
        if isinstance(rows, list):
            return [x for x in rows if isinstance(x, dict)]
    raise ValueError("test file must be a list or {'test_cases': [...]}")


def load_api_key_from_file(path: Path, env_name: str) -> str:
    if not path.exists():
        return ""
    try:
        data = load_json(path)
    except Exception:
        return ""
    if not isinstance(data, dict):
        return ""
    candidate_keys = [env_name, "ARK_API_KEY", "SILICONFLOW_API_KEY", "api_key"]
    for key in candidate_keys:
        value = data.get(key)
        if value:
            return str(value).strip()
    return ""


def normalize_text(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def resolve_image_path(raw: str, dataset_file: Path) -> Path:
    raw_path = Path(raw)
    if raw_path.is_absolute():
        return raw_path
    project_candidate = (PROJECT_ROOT / raw_path).resolve()
    if project_candidate.exists():
        return project_candidate
    dataset_candidate = (dataset_file.parent / raw_path).resolve()
    if dataset_candidate.exists():
        return dataset_candidate
    # Keep project-relative as stable fallback in output.
    return project_candidate


def classify_method(source: str) -> str:
    if not source:
        return "none"
    if source.startswith("template:"):
        return "template"
    if source.startswith("ai:") or source == "ai":
        return "ai"
    if source == "default":
        return "default"
    return "other"


def percentile(values: list[int], p: float) -> float:
    if not values:
        return 0.0
    if len(values) == 1:
        return float(values[0])
    ordered = sorted(values)
    idx = (len(ordered) - 1) * p
    lo = int(idx)
    hi = min(lo + 1, len(ordered) - 1)
    frac = idx - lo
    return float(ordered[lo] * (1.0 - frac) + ordered[hi] * frac)


def extract_expected_answers(case: dict[str, Any]) -> list[str]:
    values: list[str] = []
    raw_many = case.get("accepted_answers")
    if isinstance(raw_many, list):
        for item in raw_many:
            text = normalize_text(item)
            if text:
                values.append(text)
    raw_one = normalize_text(case.get("expected_answer"))
    if raw_one and raw_one not in values:
        values.append(raw_one)
    return values


def evaluate_case(
    case: dict[str, Any],
    *,
    case_index: int,
    dataset_file: Path,
    config: Any,
    ai_provider: Any,
    ocr_provider: Any,
    ai_callback: Any = None,  # NEW: use production callback directly
) -> dict[str, Any]:
    case_id = normalize_text(case.get("id") or case.get("case_id") or f"case_{case_index:04d}")
    post_content = normalize_text(case.get("post_content") or case.get("question_text"))
    detail_text = normalize_text(case.get("detail_text"))

    image_raw = case.get("image_paths")
    resolved_image_paths: list[str] = []
    existing_image_paths: list[str] = []
    missing_images: list[str] = []
    if isinstance(image_raw, list):
        for entry in image_raw:
            raw = normalize_text(entry)
            if not raw:
                continue
            resolved = resolve_image_path(raw, dataset_file)
            resolved_text = str(resolved)
            resolved_image_paths.append(resolved_text)
            if resolved.exists():
                existing_image_paths.append(resolved_text)
            else:
                missing_images.append(resolved_text)

    expected_answers = extract_expected_answers(case)
    is_labeled = bool(expected_answers)

    # Extract classification hints (keep for reporting)
    method_hint = normalize_text(case.get("method_hint"))
    question_type = normalize_text(case.get("question_type"))

    record: dict[str, Any] = {
        "id": case_id,
        "index": case_index,
        "enabled": bool(case.get("enabled", True)),
        "tags": case.get("tags", []),
        "method_hint": method_hint,
        "question_type": question_type,
        "post_content": post_content,
        "detail_text": detail_text,
        "image_paths": resolved_image_paths,
        "used_image_paths": existing_image_paths,
        "missing_images": missing_images,
        "expected_answers": expected_answers,
        "is_labeled": is_labeled,
        "answer": "",
        "source": "",
        "method": "none",
        "confidence": None,
        "elapsed_ms": 0,
        "engine_latency_ms": None,
        "is_correct": None,
        "error": None,
    }

    # Combine post_content and detail_text like production
    full_content = "\n".join(
        part.strip() for part in (post_content, detail_text) if part and part.strip()
    ).strip()

    started = time.perf_counter()
    try:
        if ai_callback:
            # Use production callback directly (preferred)
            answer = ai_callback(full_content, existing_image_paths)
            record["answer"] = normalize_text(answer)
            record["source"] = "callback"  # Generic source for callback
            record["method"] = "callback" if answer else "none"
        else:
            # Fallback to old resolve_answer (for backward compatibility)
            from pyweixin.rush_engine import resolve_answer
            answer_result = resolve_answer(
                post_content=post_content,
                detail_text=detail_text,
                image_paths=existing_image_paths,
                templates=config.templates,
                ocr_provider=ocr_provider,
                ai_provider=ai_provider,
                ai_enabled=config.ai_enabled,
                ai_timeout_ms=config.ai_timeout_ms,
                confidence_threshold=config.confidence_threshold,
                default_answer=config.default_answer,
            )
            if answer_result:
                answer = normalize_text(getattr(answer_result, "answer", ""))
                source = normalize_text(getattr(answer_result, "source", ""))
                confidence = getattr(answer_result, "confidence", None)
                engine_latency = getattr(answer_result, "latency_ms", None)
                record["answer"] = answer
                record["source"] = source
                record["method"] = classify_method(source)
                record["confidence"] = float(confidence) if isinstance(confidence, (int, float)) else None
                if isinstance(engine_latency, int):
                    record["engine_latency_ms"] = engine_latency
            else:
                record["method"] = "none" if not record["error"] else "error"
    except Exception as exc:  # pragma: no cover - integration path
        record["error"] = str(exc)
        record["method"] = "error"

    elapsed_ms = int((time.perf_counter() - started) * 1000)
    record["elapsed_ms"] = elapsed_ms

    if is_labeled:
        if record["error"]:
            record["is_correct"] = False
            return record
        expected_upper = {x.upper() for x in expected_answers}
        answer_text = record["answer"]
        if "SKIP" in expected_upper:
            # SKIP means this case should produce no answer.
            record["is_correct"] = answer_text == ""
        else:
            record["is_correct"] = answer_text in expected_answers

    return record


def _map_method_to_hint(method: str) -> str:
    """Map actual method to expected method_hint for comparison."""
    if method == "template":
        return "ocr_template"  # template includes ocr-assisted template
    if method == "ai":
        return "ai_vision"  # could be ai_vision or ai_text, simplified
    return ""


def build_summary(results: list[dict[str, Any]]) -> dict[str, Any]:
    total = len(results)
    answered = sum(1 for r in results if r.get("answer"))
    labeled = [r for r in results if r.get("is_labeled")]
    correct = sum(1 for r in labeled if r.get("is_correct") is True)
    errors = sum(1 for r in results if r.get("error"))

    method_counts: dict[str, int] = {}
    for row in results:
        method = normalize_text(row.get("method")) or "none"
        method_counts[method] = method_counts.get(method, 0) + 1

    # Statistics by method_hint
    by_method_hint: dict[str, dict[str, int]] = {}
    for row in labeled:
        hint = normalize_text(row.get("method_hint")) or "unknown"
        if hint not in by_method_hint:
            by_method_hint[hint] = {"total": 0, "correct": 0}
        by_method_hint[hint]["total"] += 1
        if row.get("is_correct") is True:
            by_method_hint[hint]["correct"] += 1

    # Statistics by question_type
    by_question_type: dict[str, dict[str, int]] = {}
    for row in labeled:
        qtype = normalize_text(row.get("question_type")) or "unknown"
        if qtype not in by_question_type:
            by_question_type[qtype] = {"total": 0, "correct": 0}
        by_question_type[qtype]["total"] += 1
        if row.get("is_correct") is True:
            by_question_type[qtype]["correct"] += 1

    elapsed_values = [int(r.get("elapsed_ms", 0)) for r in results if isinstance(r.get("elapsed_ms"), int)]
    if elapsed_values:
        avg_elapsed = statistics.fmean(elapsed_values)
        p50_elapsed = percentile(elapsed_values, 0.50)
        p95_elapsed = percentile(elapsed_values, 0.95)
        max_elapsed = max(elapsed_values)
    else:
        avg_elapsed = 0.0
        p50_elapsed = 0.0
        p95_elapsed = 0.0
        max_elapsed = 0

    return {
        "total_cases": total,
        "answered_cases": answered,
        "answer_rate": (answered / total) if total else 0.0,
        "labeled_cases": len(labeled),
        "correct_cases": correct,
        "accuracy": (correct / len(labeled)) if labeled else None,
        "error_cases": errors,
        "method_counts": method_counts,
        "by_method_hint": by_method_hint,
        "by_question_type": by_question_type,
        "latency_ms": {
            "avg": round(avg_elapsed, 3),
            "p50": round(p50_elapsed, 3),
            "p95": round(p95_elapsed, 3),
            "max": int(max_elapsed),
        },
    }


def print_summary(summary: dict[str, Any]) -> None:
    print("\n" + "=" * 72)
    print("Unified Evaluation Summary")
    print("=" * 72)
    print(f"Total cases   : {summary['total_cases']}")
    print(f"Answered      : {summary['answered_cases']} ({summary['answer_rate'] * 100:.1f}%)")
    print(f"Labeled       : {summary['labeled_cases']}")
    if summary["accuracy"] is None:
        print("Accuracy      : N/A (no labeled cases)")
    else:
        print(f"Accuracy      : {summary['correct_cases']}/{summary['labeled_cases']} ({summary['accuracy'] * 100:.1f}%)")
    print(f"Errors        : {summary['error_cases']}")
    print(f"Method counts : {summary['method_counts']}")

    # Print by_method_hint breakdown
    by_hint = summary.get("by_method_hint", {})
    if by_hint:
        print("\nAccuracy by method_hint:")
        for hint, stats in sorted(by_hint.items()):
            t, c = stats["total"], stats["correct"]
            pct = (c / t * 100) if t else 0
            print(f"  {hint:15s}: {c}/{t} ({pct:.1f}%)")

    # Print by_question_type breakdown
    by_qtype = summary.get("by_question_type", {})
    if by_qtype:
        print("\nAccuracy by question_type:")
        for qtype, stats in sorted(by_qtype.items()):
            t, c = stats["total"], stats["correct"]
            pct = (c / t * 100) if t else 0
            print(f"  {qtype:15s}: {c}/{t} ({pct:.1f}%)")

    latency = summary["latency_ms"]
    print(
        "\nLatency (ms)  : "
        f"avg={latency['avg']:.1f}, p50={latency['p50']:.1f}, p95={latency['p95']:.1f}, max={latency['max']}"
    )


def build_ai_provider(
    provider: str,
    *,
    model: str,
    base_url: str,
    api_key_env: str,
    key_file: Path,
) -> tuple[Any, str]:
    if provider == "null":
        return NullAIProvider(), "null"

    if provider == "ark":
        env_name = api_key_env or "ARK_API_KEY"
        api_key = os.getenv(env_name, "").strip() or load_api_key_from_file(key_file, env_name)
        if not api_key:
            raise RuntimeError(f"Missing API key for ark provider. Set {env_name} or {key_file}.")
        return (
            ArkChatProvider(
                api_key=api_key,
                model=(model or "doubao-seed-1-8-251228"),
                base_url=(base_url or "https://ark.cn-beijing.volces.com/api/v3"),
            ),
            "ark",
        )

    if provider == "siliconflow":
        env_name = api_key_env or "SILICONFLOW_API_KEY"
        api_key = os.getenv(env_name, "").strip() or load_api_key_from_file(key_file, env_name)
        if not api_key:
            raise RuntimeError(f"Missing API key for siliconflow provider. Set {env_name} or {key_file}.")
        return (
            SiliconFlowOpenAIProvider(
                api_key=api_key,
                model=(model or "Qwen/Qwen3-VL-32B-Instruct"),
                base_url=(base_url or "https://api.siliconflow.cn/v1"),
            ),
            "siliconflow",
        )

    raise ValueError(f"Unsupported provider: {provider}")


def build_ocr_provider(provider: str) -> tuple[Any, str]:
    if provider == "null":
        return NullOCRProvider(), "null"
    if provider == "paddle":
        ocr = PaddleOCRProvider(
            lang="ch",
            show_log=False,
            use_angle_cls=False,
            enable_mkldnn=False,
            text_detection_model_name=os.getenv("PYWEIXIN_OCR_DET_MODEL", "PP-OCRv5_mobile_det"),
            text_recognition_model_name=os.getenv("PYWEIXIN_OCR_REC_MODEL", "PP-OCRv5_mobile_rec"),
            cpu_threads=int(os.getenv("PYWEIXIN_OCR_CPU_THREADS", "8")),
            text_det_limit_side_len=int(os.getenv("PYWEIXIN_OCR_MAX_SIDE", "1200")),
            text_det_limit_type=os.getenv("PYWEIXIN_OCR_LIMIT_TYPE", "max"),
        )
        # Fail fast so benchmark results are explicit.
        ocr._get_ocr()
        return ocr, "paddle"
    raise ValueError(f"Unsupported OCR provider: {provider}")


def should_keep_case(
    case: dict[str, Any],
    selected_ids: set[str],
    selected_tags: set[str],
    selected_method_hints: set[str],
    selected_question_types: set[str],
) -> bool:
    if not bool(case.get("enabled", True)):
        return False

    case_id = normalize_text(case.get("id") or case.get("case_id"))
    if selected_ids and case_id not in selected_ids:
        return False

    if selected_tags:
        tags = case.get("tags", [])
        normalized_tags = {normalize_text(x) for x in tags} if isinstance(tags, list) else set()
        if not normalized_tags.intersection(selected_tags):
            return False

    if selected_method_hints:
        hint = normalize_text(case.get("method_hint"))
        if hint not in selected_method_hints:
            return False

    if selected_question_types:
        qtype = normalize_text(case.get("question_type"))
        if qtype not in selected_question_types:
            return False

    return True


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Unified benchmark aligned with rush_engine.resolve_answer"
    )
    parser.add_argument("--test-file", default=str(DEFAULT_TEST_FILE), help="Path to test case json file")
    parser.add_argument("--config", default="config/rush_event.json", help="Path to rush config")
    parser.add_argument(
        "--provider",
        default="ark",
        choices=["ark", "siliconflow", "null"],
        help="AI provider used by resolve_answer",
    )
    parser.add_argument(
        "--ocr",
        default="paddle",
        choices=["paddle", "null"],
        help="OCR provider used by resolve_answer",
    )
    parser.add_argument("--model", default="", help="Override AI model")
    parser.add_argument("--base-url", default="", help="Override AI base URL")
    parser.add_argument("--api-key-env", default="", help="API key env name")
    parser.add_argument("--key-file", default="config/.local_secrets.json", help="Local secrets JSON")
    parser.add_argument("--ai-timeout", type=int, default=None, help="Override ai_timeout_ms")
    parser.add_argument(
        "--confidence-threshold",
        type=float,
        default=None,
        help="Override confidence_threshold",
    )
    parser.add_argument(
        "--ai-enabled",
        choices=["auto", "on", "off"],
        default="auto",
        help="Use config.ai_enabled by default, or force on/off",
    )
    parser.add_argument("--max-cases", type=int, default=0, help="Evaluate first N filtered cases")
    parser.add_argument("--case-id", action="append", default=[], help="Only evaluate given case id (repeatable)")
    parser.add_argument("--tag", action="append", default=[], help="Only evaluate cases containing tag (repeatable)")
    parser.add_argument("--method-hint", action="append", default=[], help="Filter by method_hint (repeatable)")
    parser.add_argument("--question-type", action="append", default=[], help="Filter by question_type (repeatable)")
    parser.add_argument("--output", default="", help="Output json path")
    args = parser.parse_args()

    dataset_file = Path(args.test_file).resolve()
    if not dataset_file.exists():
        raise FileNotFoundError(f"Test file not found: {dataset_file}")

    key_file = Path(args.key_file).resolve()
    config = load_rush_config(args.config)
    if args.ai_timeout is not None:
        config.ai_timeout_ms = int(args.ai_timeout)
    if args.confidence_threshold is not None:
        config.confidence_threshold = float(args.confidence_threshold)
    if args.ai_enabled == "on":
        config.ai_enabled = True
    elif args.ai_enabled == "off":
        config.ai_enabled = False

    ai_provider, ai_provider_name = build_ai_provider(
        args.provider,
        model=args.model,
        base_url=args.base_url,
        api_key_env=args.api_key_env,
        key_file=key_file,
    )
    ocr_provider, ocr_provider_name = build_ocr_provider(args.ocr)

    selected_ids = {normalize_text(x) for x in args.case_id if normalize_text(x)}
    selected_tags = {normalize_text(x) for x in args.tag if normalize_text(x)}
    selected_method_hints = {normalize_text(x) for x in args.method_hint if normalize_text(x)}
    selected_question_types = {normalize_text(x) for x in args.question_type if normalize_text(x)}

    all_cases = load_test_cases(dataset_file)
    filtered_cases = [
        x for x in all_cases
        if should_keep_case(x, selected_ids, selected_tags, selected_method_hints, selected_question_types)
    ]
    if args.max_cases and args.max_cases > 0:
        filtered_cases = filtered_cases[: args.max_cases]
    if not filtered_cases:
        raise RuntimeError("No test cases selected.")

    context = EvalContext(
        dataset_file=dataset_file,
        config_path=args.config,
        ai_provider_name=ai_provider_name,
        ocr_provider_name=ocr_provider_name,
        ai_enabled=bool(config.ai_enabled),
        ai_timeout_ms=int(config.ai_timeout_ms),
        confidence_threshold=float(config.confidence_threshold),
    )

    print(f"[init] test_file={dataset_file}")
    print(
        "[init] providers: "
        f"ai={context.ai_provider_name}, ocr={context.ocr_provider_name}, "
        f"ai_enabled={context.ai_enabled}, ai_timeout_ms={context.ai_timeout_ms}, "
        f"confidence_threshold={context.confidence_threshold}"
    )
    print(f"[init] selected_cases={len(filtered_cases)} / {len(all_cases)}")

    # Create ai_callback using production flow
    ai_callback = create_ai_callback(
        ocr_provider=ocr_provider,
        ai_provider=ai_provider if config.ai_enabled else None,
        compare_mode=False,
        verbose=True,
    )
    print("[init] using production ai_callback flow")

    results: list[dict[str, Any]] = []
    for idx, case in enumerate(filtered_cases, start=1):
        case_id = normalize_text(case.get("id") or case.get("case_id") or f"case_{idx:04d}")
        print(f"[{idx}/{len(filtered_cases)}] {case_id}", flush=True)
        row = evaluate_case(
            case,
            case_index=idx,
            dataset_file=dataset_file,
            config=config,
            ai_provider=ai_provider,
            ocr_provider=ocr_provider,
            ai_callback=ai_callback,  # Use production callback
        )
        if row.get("error"):
            print(f"  -> error: {row['error']}", flush=True)
        elif row.get("answer"):
            judge = ""
            if row.get("is_correct") is True:
                judge = " [OK]"
            elif row.get("is_correct") is False:
                judge = " [FAIL]"
            print(
                f"  -> answer={row['answer']} method={row['method']} "
                f"elapsed={row['elapsed_ms']}ms{judge}",
                flush=True,
            )
        else:
            print(f"  -> no answer elapsed={row['elapsed_ms']}ms", flush=True)
        results.append(row)

    summary = build_summary(results)
    print_summary(summary)

    if args.output:
        output_path = Path(args.output).resolve()
    else:
        DEFAULT_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = DEFAULT_OUTPUT_DIR / f"evaluation_{ts}.json"

    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "context": {
            "dataset_file": str(context.dataset_file),
            "config_path": context.config_path,
            "ai_provider": context.ai_provider_name,
            "ocr_provider": context.ocr_provider_name,
            "ai_enabled": context.ai_enabled,
            "ai_timeout_ms": context.ai_timeout_ms,
            "confidence_threshold": context.confidence_threshold,
        },
        "summary": summary,
        "results": results,
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)

    print(f"\nSaved: {output_path}")


if __name__ == "__main__":
    main()
