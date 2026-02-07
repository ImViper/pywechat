"""Evaluate local OCR/AI benchmark testset.

Usage:
    python examples/evaluate_local_ocr_ai_testset.py --mode ocr
    python examples/evaluate_local_ocr_ai_testset.py --mode ai
    python examples/evaluate_local_ocr_ai_testset.py --mode both
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from pyweixin.rush_ai import ArkChatProvider, PaddleOCRProvider
from PIL import Image

DEFAULT_TESTSET_ROOT = PROJECT_ROOT / "local_workspace" / "testsets" / "moments_ocr_ai_v1"
DEFAULT_MANIFEST = DEFAULT_TESTSET_ROOT / "manifest.jsonl"


def load_manifest(path: Path) -> list[dict]:
    rows: list[dict] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rows.append(json.loads(line))
    return rows


def normalize_answer(raw: object) -> str:
    if raw is None:
        return ""
    if isinstance(raw, str):
        return raw.strip()
    if hasattr(raw, "answer") and isinstance(getattr(raw, "answer"), str):
        return getattr(raw, "answer").strip()
    if isinstance(raw, dict) and isinstance(raw.get("answer"), str):
        return raw["answer"].strip()
    return str(raw).strip()


def run_ocr_case(row: dict, image_path: Path, ocr_provider: PaddleOCRProvider) -> dict:
    started = time.time()
    text = ocr_provider.extract_text(str(image_path))
    elapsed_ms = int((time.time() - started) * 1000)

    keyword = str(row.get("target_keyword") or "").strip()
    ocr_count = None
    ocr_answer = ""

    if keyword:
        ocr_count = text.count(keyword)
        ocr_answer = f"{ocr_count}{keyword}"

    expected_answer = row.get("expected_answer")
    is_correct = None
    if expected_answer and ocr_answer:
        is_correct = ocr_answer == expected_answer

    return {
        "ocr_text": text,
        "ocr_count": ocr_count,
        "ocr_answer": ocr_answer,
        "ocr_elapsed_ms": elapsed_ms,
        "ocr_is_correct": is_correct,
    }


def prepare_image_for_ocr(image_path: Path, max_side: int, resized_dir: Path) -> Path:
    if max_side <= 0:
        return image_path
    with Image.open(image_path) as img:
        w, h = img.size
        long_side = max(w, h)
        if long_side <= max_side:
            return image_path
        scale = max_side / float(long_side)
        new_w = max(1, int(w * scale))
        new_h = max(1, int(h * scale))
        resized_dir.mkdir(parents=True, exist_ok=True)
        out_path = resized_dir / f"{image_path.stem}_max{max_side}{image_path.suffix.lower()}"
        img.resize((new_w, new_h), Image.Resampling.LANCZOS).save(out_path)
        return out_path


def load_api_key() -> str:
    env_key = os.getenv("ARK_API_KEY", "").strip()
    if env_key:
        return env_key

    local_secret = PROJECT_ROOT / "config" / ".local_secrets.json"
    if local_secret.exists():
        try:
            with local_secret.open("r", encoding="utf-8-sig") as f:
                data = json.load(f)
            key = str(data.get("ARK_API_KEY") or "").strip()
            if key:
                return key
        except Exception:
            return ""
    return ""


def run_ai_case(row: dict, image_path: Path, ai_provider: ArkChatProvider) -> dict:
    prompt = str(row.get("question_text") or "").strip()
    keyword = str(row.get("target_keyword") or "").strip()
    if not prompt and keyword:
        prompt = f"图中共有几位{keyword}角色？"
    if not prompt:
        prompt = "请直接给出图中问题的答案。"

    started = time.time()
    result = ai_provider.answer_from_text_and_images(prompt, [str(image_path)], [])
    elapsed_ms = int((time.time() - started) * 1000)

    ai_answer = normalize_answer(result)
    expected_answer = row.get("expected_answer")
    ai_is_correct = None
    if expected_answer and ai_answer:
        ai_is_correct = ai_answer == expected_answer

    return {
        "ai_answer": ai_answer,
        "ai_elapsed_ms": elapsed_ms,
        "ai_is_correct": ai_is_correct,
    }


def summarize(results: list[dict]) -> dict:
    def avg(values: list[int]) -> float:
        return (sum(values) / len(values)) if values else 0.0

    labeled = [r for r in results if r.get("labeled")]

    ocr_labeled = [r for r in labeled if r.get("ocr_is_correct") is not None]
    ai_labeled = [r for r in labeled if r.get("ai_is_correct") is not None]

    ocr_correct = sum(1 for r in ocr_labeled if r.get("ocr_is_correct") is True)
    ai_correct = sum(1 for r in ai_labeled if r.get("ai_is_correct") is True)

    ocr_times = [int(r["ocr_elapsed_ms"]) for r in results if isinstance(r.get("ocr_elapsed_ms"), int)]
    ai_times = [int(r["ai_elapsed_ms"]) for r in results if isinstance(r.get("ai_elapsed_ms"), int)]

    return {
        "total_cases": len(results),
        "labeled_cases": len(labeled),
        "ocr_eval_cases": len(ocr_labeled),
        "ocr_correct": ocr_correct,
        "ocr_correct_rate": (ocr_correct / len(ocr_labeled)) if ocr_labeled else None,
        "ai_eval_cases": len(ai_labeled),
        "ai_correct": ai_correct,
        "ai_correct_rate": (ai_correct / len(ai_labeled)) if ai_labeled else None,
        "ocr_avg_ms": avg(ocr_times),
        "ai_avg_ms": avg(ai_times),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate local OCR/AI benchmark testset")
    parser.add_argument(
        "--manifest",
        default=str(DEFAULT_MANIFEST),
        help="Path to manifest.jsonl",
    )
    parser.add_argument(
        "--mode",
        choices=["ocr", "ai", "both"],
        default="both",
        help="Evaluation mode",
    )
    parser.add_argument(
        "--max-side",
        type=int,
        default=2200,
        help="Resize image long side before OCR (0 to disable)",
    )
    parser.add_argument(
        "--max-cases",
        type=int,
        default=0,
        help="Only evaluate first N cases (0 means all)",
    )
    args = parser.parse_args()

    manifest_path = Path(args.manifest)
    if not manifest_path.exists():
        raise FileNotFoundError(f"Manifest not found: {manifest_path}")

    rows = load_manifest(manifest_path)
    if not rows:
        raise RuntimeError("Manifest is empty")
    if args.max_cases and args.max_cases > 0:
        rows = rows[: args.max_cases]

    use_ocr = args.mode in {"ocr", "both"}
    use_ai = args.mode in {"ai", "both"}

    ocr_provider = None
    if use_ocr:
        print("[init] loading PaddleOCR...")
        ocr_provider = PaddleOCRProvider(
            lang="ch",
            show_log=False,
            use_angle_cls=False,
            enable_mkldnn=False,
            text_detection_model_name=os.getenv("PYWEIXIN_OCR_DET_MODEL", "PP-OCRv5_mobile_det"),
            text_recognition_model_name=os.getenv("PYWEIXIN_OCR_REC_MODEL", "PP-OCRv5_mobile_rec"),
            cpu_threads=int(os.getenv("PYWEIXIN_OCR_CPU_THREADS", "8")),
            text_det_limit_side_len=int(os.getenv("PYWEIXIN_OCR_MAX_SIDE", str(args.max_side))),
            text_det_limit_type=os.getenv("PYWEIXIN_OCR_LIMIT_TYPE", "max"),
        )
        ocr_provider._get_ocr()

    ai_provider = None
    if use_ai:
        api_key = load_api_key()
        if not api_key:
            raise RuntimeError("ARK_API_KEY not found for AI evaluation")
        ai_provider = ArkChatProvider(api_key=api_key)

    results: list[dict] = []
    for idx, row in enumerate(rows, start=1):
        image_path = manifest_path.parent / row["image"]
        case = {
            "case_id": row.get("case_id"),
            "labeled": bool(row.get("labeled")),
            "image": row.get("image"),
            "source": row.get("source"),
            "expected_answer": row.get("expected_answer"),
            "target_keyword": row.get("target_keyword"),
        }

        if not image_path.exists():
            case["error"] = f"image not found: {image_path}"
            results.append(case)
            print(f"[{idx}/{len(rows)}] {case['case_id']} -> missing image")
            continue

        try:
            if use_ocr and ocr_provider is not None:
                ocr_input = prepare_image_for_ocr(
                    image_path,
                    max_side=args.max_side,
                    resized_dir=manifest_path.parent / "_resized_for_ocr",
                )
                case.update(run_ocr_case(row, ocr_input, ocr_provider))
                case["ocr_input"] = str(ocr_input)
            if use_ai and ai_provider is not None:
                case.update(run_ai_case(row, image_path, ai_provider))
            print(f"[{idx}/{len(rows)}] {case['case_id']} -> ok", flush=True)
        except Exception as exc:
            case["error"] = str(exc)
            print(f"[{idx}/{len(rows)}] {case['case_id']} -> error: {exc}", flush=True)

        results.append(case)

    summary = summarize(results)

    print("=" * 60)
    print("Benchmark Summary")
    print("=" * 60)
    print(json.dumps(summary, ensure_ascii=False, indent=2))

    results_dir = manifest_path.parent / "results"
    results_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_path = results_dir / f"benchmark_{ts}.json"

    payload = {
        "manifest": str(manifest_path),
        "mode": args.mode,
        "summary": summary,
        "results": results,
    }

    with output_path.open("w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)

    print(f"Saved: {output_path}")


if __name__ == "__main__":
    main()
