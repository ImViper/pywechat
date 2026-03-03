"""Benchmark Ark vision parameters for speed and accuracy on fixed images.

Usage example:
    python examples/benchmark_ark_vision_params.py ^
        --image "rush_moments_cache_feed_孙大炮_multi/孙大炮_1771909773892/0.png" ^
        --question "图中有多少个楚凭阑？只输出数字+楚凭阑" ^
        --expected-count 5 ^
        --detail-values "low,high" ^
        --max-side-values "0,960,1280" ^
        --quality-values "84,90" ^
        --repeat 3
"""

from __future__ import annotations

import argparse
import json
import os
import re
import statistics
import sys
import time
from dataclasses import dataclass
from datetime import datetime
from itertools import product
from pathlib import Path
from typing import Any

try:
    from PIL import Image
except Exception:  # pragma: no cover - optional dependency
    Image = None

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from pyweixin.rush_ai import ArkChatProvider


@dataclass(slots=True)
class Combo:
    detail: str
    max_side: int
    quality: int
    image_min_pixels: int
    image_max_pixels: int

    def key(self) -> str:
        return (
            f"detail={self.detail},max_side={self.max_side},quality={self.quality},"
            f"min_pixels={self.image_min_pixels},max_pixels={self.image_max_pixels}"
        )


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8-sig") as f:
        return json.load(f)


def load_api_key(key_file: Path, env_name: str = "ARK_API_KEY") -> str:
    value = os.getenv(env_name, "").strip()
    if value:
        return value
    if not key_file.is_file():
        return ""
    try:
        data = load_json(key_file)
    except Exception:
        return ""
    if not isinstance(data, dict):
        return ""
    for key in (env_name, "ARK_API_KEY", "api_key"):
        v = str(data.get(key, "")).strip()
        if v:
            return v
    return ""


def parse_csv_str(raw: str) -> list[str]:
    return [x.strip() for x in str(raw).split(",") if x.strip()]


def parse_csv_int(raw: str) -> list[int]:
    out: list[int] = []
    for part in parse_csv_str(raw):
        out.append(int(part))
    return out


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


def parse_answer_count(answer: str) -> int | None:
    text = str(answer or "").strip()
    if not text:
        return None
    match = re.search(r"-?\d+", text)
    if not match:
        return None
    try:
        return int(match.group(0))
    except Exception:
        return None


def optimize_image_for_ai(
    src: Path,
    combo: Combo,
    temp_dir: Path,
) -> tuple[Path, bool]:
    """Return optimized path for this combo (or original if no resize needed)."""
    if combo.max_side <= 0:
        return src, False
    if Image is None:
        return src, False
    try:
        resample = Image.Resampling.BILINEAR
    except Exception:  # Pillow < 9.1
        resample = Image.BILINEAR
    with Image.open(src) as im:
        width, height = im.size
        long_side = max(width, height)
        if long_side <= combo.max_side:
            return src, False
        scale = combo.max_side / float(long_side)
        new_w = max(1, int(width * scale))
        new_h = max(1, int(height * scale))
        resized = im.convert("RGB").resize((new_w, new_h), resample)
        suffix = (
            f".bench_d{combo.detail}_ms{combo.max_side}_q{combo.quality}"
            f"_min{combo.image_min_pixels}_max{combo.image_max_pixels}.jpg"
        )
        out_path = temp_dir / f"{src.stem}{suffix}"
        resized.save(out_path, format="JPEG", quality=combo.quality)
        return out_path, True


def build_provider(
    *,
    api_key: str,
    model: str,
    base_url: str,
    timeout_sec: float,
    max_tokens: int,
    temperature: float,
    top_p: float,
    combo: Combo,
) -> ArkChatProvider:
    provider = ArkChatProvider(
        api_key=api_key,
        model=model,
        base_url=base_url,
        timeout_sec=timeout_sec,
    )
    # Enforce test settings after __post_init__ (which can read env overrides).
    provider.model = model
    provider.timeout_sec = timeout_sec
    provider.max_tokens = max_tokens
    provider.temperature = temperature
    provider.top_p = top_p
    provider.image_detail = combo.detail
    provider.image_min_pixels = combo.image_min_pixels
    provider.image_max_pixels = combo.image_max_pixels
    return provider


def summarize_group(rows: list[dict[str, Any]], expected_count: int) -> dict[str, Any]:
    latencies = [int(r["latency_ms"]) for r in rows if isinstance(r.get("latency_ms"), int)]
    total = len(rows)
    correct = sum(1 for r in rows if r.get("count_correct") is True)
    answered = sum(1 for r in rows if r.get("answer_text"))
    parseable = sum(1 for r in rows if r.get("parsed_count") is not None)
    errors = sum(1 for r in rows if r.get("error"))

    answers_freq: dict[str, int] = {}
    for row in rows:
        text = str(row.get("answer_text") or "").strip()
        if not text:
            text = "<EMPTY>"
        answers_freq[text] = answers_freq.get(text, 0) + 1

    latency = {
        "avg": round(statistics.fmean(latencies), 3) if latencies else 0.0,
        "p50": round(percentile(latencies, 0.50), 3) if latencies else 0.0,
        "p95": round(percentile(latencies, 0.95), 3) if latencies else 0.0,
        "min": min(latencies) if latencies else 0,
        "max": max(latencies) if latencies else 0,
    }

    return {
        "expected_count": expected_count,
        "total_runs": total,
        "answered_runs": answered,
        "parseable_runs": parseable,
        "correct_runs": correct,
        "accuracy": (correct / total) if total else 0.0,
        "error_runs": errors,
        "latency_ms": latency,
        "answer_frequency": dict(sorted(answers_freq.items(), key=lambda x: (-x[1], x[0]))),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Benchmark Ark vision parameter combinations")
    parser.add_argument("--image", action="append", required=True, help="Image path (repeatable)")
    parser.add_argument("--question", required=True, help="Question text for the model")
    parser.add_argument("--expected-count", type=int, required=True, help="Ground-truth count (e.g. 5)")
    parser.add_argument("--repeat", type=int, default=3, help="Runs per combo per image")
    parser.add_argument("--sleep-ms", type=int, default=0, help="Sleep between requests")

    parser.add_argument("--model", default="doubao-seed-1-8-251228", help="Ark model id")
    parser.add_argument("--base-url", default="https://ark.cn-beijing.volces.com/api/v3", help="Ark base url")
    parser.add_argument("--timeout-sec", type=float, default=8.0, help="HTTP timeout seconds")
    parser.add_argument("--max-tokens", type=int, default=16, help="max_tokens in request")
    parser.add_argument("--temperature", type=float, default=0.0, help="temperature in request")
    parser.add_argument("--top-p", type=float, default=0.6, help="top_p in request")

    parser.add_argument("--detail-values", default="low,high", help="CSV details: auto/low/high/xhigh")
    parser.add_argument("--max-side-values", default="0,960,1280", help="CSV resize long-side (0=no resize)")
    parser.add_argument("--quality-values", default="84,90", help="CSV JPEG quality (used when resized)")
    parser.add_argument("--image-min-pixels-values", default="0", help="CSV image_pixel_limit.min_pixels")
    parser.add_argument("--image-max-pixels-values", default="0", help="CSV image_pixel_limit.max_pixels")

    parser.add_argument("--key-file", default="config/.local_secrets.json", help="Secrets json path")
    parser.add_argument("--api-key-env", default="ARK_API_KEY", help="API key env name")
    parser.add_argument("--output", default="", help="Output JSON path")
    parser.add_argument("--keep-temp", action="store_true", help="Keep optimized temp images")
    args = parser.parse_args()

    key_file = (PROJECT_ROOT / args.key_file).resolve() if not Path(args.key_file).is_absolute() else Path(args.key_file).resolve()
    api_key = load_api_key(key_file=key_file, env_name=args.api_key_env)
    if not api_key:
        raise RuntimeError(f"Missing API key. Set {args.api_key_env} or put it in {key_file}")

    detail_values = parse_csv_str(args.detail_values)
    max_side_values = parse_csv_int(args.max_side_values)
    quality_values = parse_csv_int(args.quality_values)
    min_pixels_values = parse_csv_int(args.image_min_pixels_values)
    max_pixels_values = parse_csv_int(args.image_max_pixels_values)

    valid_details = {"auto", "low", "high", "xhigh"}
    for d in detail_values:
        if d not in valid_details:
            raise ValueError(f"Invalid detail value: {d}; valid={sorted(valid_details)}")

    image_paths: list[Path] = []
    for raw in args.image:
        p = Path(raw)
        if not p.is_absolute():
            p = (PROJECT_ROOT / p).resolve()
        if not p.is_file():
            raise FileNotFoundError(f"Image not found: {p}")
        image_paths.append(p)

    combos = [
        Combo(detail=d, max_side=ms, quality=q, image_min_pixels=minp, image_max_pixels=maxp)
        for d, ms, q, minp, maxp in product(
            detail_values, max_side_values, quality_values, min_pixels_values, max_pixels_values
        )
    ]
    if not combos:
        raise RuntimeError("No parameter combinations to run.")

    temp_dir = PROJECT_ROOT / "tmp" / "benchmark_ark_vision_params"
    temp_dir.mkdir(parents=True, exist_ok=True)

    started_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print("=" * 72)
    print("Ark Vision Param Benchmark")
    print("=" * 72)
    print(f"start_time    : {started_at}")
    print(f"images        : {len(image_paths)}")
    print(f"combinations  : {len(combos)}")
    print(f"repeat        : {args.repeat}")
    print(f"expected_count: {args.expected_count}")
    print(f"model         : {args.model}")
    print("=" * 72)

    rows: list[dict[str, Any]] = []
    total_runs = len(image_paths) * len(combos) * args.repeat
    run_index = 0

    for combo_i, combo in enumerate(combos, start=1):
        print(f"[combo {combo_i}/{len(combos)}] {combo.key()}")
        for image in image_paths:
            prepared_image, resized = optimize_image_for_ai(image, combo, temp_dir)
            for attempt in range(1, args.repeat + 1):
                run_index += 1
                provider = build_provider(
                    api_key=api_key,
                    model=args.model,
                    base_url=args.base_url,
                    timeout_sec=args.timeout_sec,
                    max_tokens=args.max_tokens,
                    temperature=args.temperature,
                    top_p=args.top_p,
                    combo=combo,
                )

                t0 = time.perf_counter()
                answer_text = ""
                error = ""
                try:
                    result = provider.answer_from_text_and_images(
                        args.question,
                        [str(prepared_image)],
                        [],
                    )
                    if result is not None and getattr(result, "answer", None):
                        answer_text = str(result.answer).strip()
                except Exception as exc:
                    error = f"{type(exc).__name__}: {exc}"
                latency_ms = int((time.perf_counter() - t0) * 1000)
                parsed_count = parse_answer_count(answer_text)
                count_correct = (parsed_count == args.expected_count) if parsed_count is not None else False

                row = {
                    "run_index": run_index,
                    "total_runs": total_runs,
                    "combo": combo.key(),
                    "detail": combo.detail,
                    "max_side": combo.max_side,
                    "quality": combo.quality,
                    "image_min_pixels": combo.image_min_pixels,
                    "image_max_pixels": combo.image_max_pixels,
                    "image_path": str(image),
                    "input_image_path": str(prepared_image),
                    "resized": resized,
                    "attempt": attempt,
                    "answer_text": answer_text,
                    "parsed_count": parsed_count,
                    "expected_count": args.expected_count,
                    "count_correct": count_correct,
                    "latency_ms": latency_ms,
                    "error": error or None,
                    "timestamp": datetime.now().isoformat(timespec="seconds"),
                }
                rows.append(row)

                verdict = "OK" if count_correct else "FAIL"
                if error:
                    verdict = "ERROR"
                print(
                    f"  - run {run_index}/{total_runs} img={image.name} try={attempt} "
                    f"lat={latency_ms}ms answer={answer_text or '<EMPTY>'} parsed={parsed_count} [{verdict}]"
                )
                if args.sleep_ms > 0:
                    time.sleep(args.sleep_ms / 1000.0)

    grouped: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        grouped.setdefault(row["combo"], []).append(row)

    summary_rows: list[dict[str, Any]] = []
    for combo_key, group_rows in grouped.items():
        stat = summarize_group(group_rows, expected_count=args.expected_count)
        summary_rows.append(
            {
                "combo": combo_key,
                "detail": group_rows[0]["detail"],
                "max_side": group_rows[0]["max_side"],
                "quality": group_rows[0]["quality"],
                "image_min_pixels": group_rows[0]["image_min_pixels"],
                "image_max_pixels": group_rows[0]["image_max_pixels"],
                **stat,
            }
        )

    summary_rows.sort(
        key=lambda x: (
            -float(x["accuracy"]),
            float(x["latency_ms"]["avg"]),
            -int(x["correct_runs"]),
        )
    )

    print("\n" + "=" * 72)
    print("Ranked Summary (accuracy desc, avg latency asc)")
    print("=" * 72)
    for idx, item in enumerate(summary_rows, start=1):
        lat = item["latency_ms"]
        print(
            f"{idx:>2}. acc={item['accuracy'] * 100:5.1f}% "
            f"({item['correct_runs']}/{item['total_runs']}) "
            f"avg={lat['avg']:7.1f}ms p50={lat['p50']:7.1f}ms p95={lat['p95']:7.1f}ms "
            f"| {item['combo']}"
        )

    payload = {
        "meta": {
            "start_time": started_at,
            "end_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "project_root": str(PROJECT_ROOT),
            "model": args.model,
            "base_url": args.base_url,
            "question": args.question,
            "expected_count": args.expected_count,
            "repeat": args.repeat,
            "images": [str(x) for x in image_paths],
            "combo_count": len(combos),
            "total_runs": total_runs,
        },
        "summary": summary_rows,
        "runs": rows,
    }

    if args.output:
        output_path = Path(args.output)
        if not output_path.is_absolute():
            output_path = (PROJECT_ROOT / output_path).resolve()
    else:
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = (PROJECT_ROOT / "dataset" / "results" / f"ark_vision_param_benchmark_{stamp}.json").resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\nSaved result JSON: {output_path}")

    if not args.keep_temp and temp_dir.is_dir():
        for path in temp_dir.glob("*"):
            try:
                path.unlink()
            except Exception:
                pass
        try:
            temp_dir.rmdir()
        except Exception:
            pass


if __name__ == "__main__":
    main()
