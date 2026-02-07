"""Build local OCR/AI benchmark testset from existing images.

Output directory (gitignored):
    local_workspace/testsets/moments_ocr_ai_v1
"""

from __future__ import annotations

import hashlib
import json
import shutil
from dataclasses import dataclass
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
TESTSET_ROOT = PROJECT_ROOT / "local_workspace" / "testsets" / "moments_ocr_ai_v1"
IMAGES_DIR = TESTSET_ROOT / "images"
MANIFEST_PATH = TESTSET_ROOT / "manifest.jsonl"


@dataclass
class LabeledCase:
    case_id: str
    globs: list[str]
    question_text: str
    target_keyword: str
    expected_count: int

    @property
    def expected_answer(self) -> str:
        return f"{self.expected_count}{self.target_keyword}"


def sha1_file(path: Path) -> str:
    h = hashlib.sha1()
    with path.open("rb") as f:
        while True:
            block = f.read(1024 * 1024)
            if not block:
                break
            h.update(block)
    return h.hexdigest()


def choose_latest_match(patterns: list[str]) -> Path | None:
    candidates: list[Path] = []
    for pattern in patterns:
        candidates.extend(PROJECT_ROOT.glob(pattern))
    candidates = [p for p in candidates if p.is_file()]
    if not candidates:
        return None
    candidates.sort(key=lambda p: str(p))
    return candidates[-1]


def copy_into_testset(src: Path, case_id: str, used_sha1: dict[str, str]) -> tuple[Path, str]:
    digest = sha1_file(src)
    if digest in used_sha1:
        # Reuse previously copied image if duplicated source content.
        return IMAGES_DIR / used_sha1[digest], digest

    ext = src.suffix.lower() or ".png"
    dst_name = f"{case_id}_{digest[:8]}{ext}"
    dst = IMAGES_DIR / dst_name
    shutil.copy2(src, dst)
    used_sha1[digest] = dst_name
    return dst, digest


def build_manifest_entries() -> list[dict]:
    labeled_cases = [
        LabeledCase(
            case_id="red_sleeve_count_4",
            globs=[
                "rush_moments_cache_feed_小蔡/小蔡_1770486617276/0.png",
                "rush_moments_cache_feed_小蔡/小蔡_1770484725930/0.png",
                "rush_moments_cache_feed_孙大炮/孙大炮_1770470547042/0.png",
                "rush_moments_cache_feed_孙大炮/孙大炮_1770470154978/0.png",
            ],
            question_text="图中共有几位红袖角色？",
            target_keyword="红袖",
            expected_count=4,
        ),
        LabeledCase(
            case_id="hu_buyi_count_6",
            globs=[
                "rush_moments_cache_test_孙大炮/孙大炮_1770462973432/0.png",
            ],
            question_text="图中共有几位胡不医角色？",
            target_keyword="胡不医",
            expected_count=6,
        ),
    ]

    entries: list[dict] = []
    used_sha1: dict[str, str] = {}

    # 1) Add labeled benchmark cases first.
    for case in labeled_cases:
        src = choose_latest_match(case.globs)
        if src is None:
            continue
        copied, digest = copy_into_testset(src, case.case_id, used_sha1)
        entries.append(
            {
                "case_id": case.case_id,
                "labeled": True,
                "image": str(copied.relative_to(TESTSET_ROOT)).replace("\\", "/"),
                "source": str(src.relative_to(PROJECT_ROOT)).replace("\\", "/"),
                "sha1": digest,
                "question_text": case.question_text,
                "target_keyword": case.target_keyword,
                "expected_count": case.expected_count,
                "expected_answer": case.expected_answer,
                "tags": ["counting", "ocr", "ai", "moments"],
            }
        )

    # 2) Add unlabeled regression pool from existing images.
    extra_patterns = [
        "images/*",
        "dataset/test_images/*",
        "dataset/moments_questions_*/*/*/0.png",
        "local_workspace/artifacts/*.png",
        "rush_moments_cache_feed_*/*/0.png",
        "rush_moments_cache_test_*/*/0.png",
    ]

    pool: list[Path] = []
    for pattern in extra_patterns:
        pool.extend([p for p in PROJECT_ROOT.glob(pattern) if p.is_file()])

    # deterministic order
    pool.sort(key=lambda p: str(p))

    max_unlabeled = 12
    count_unlabeled = 0

    for src in pool:
        if count_unlabeled >= max_unlabeled:
            break

        digest = sha1_file(src)
        if digest in used_sha1:
            continue

        case_id = f"unlabeled_{count_unlabeled + 1:03d}"
        copied, digest = copy_into_testset(src, case_id, used_sha1)
        entries.append(
            {
                "case_id": case_id,
                "labeled": False,
                "image": str(copied.relative_to(TESTSET_ROOT)).replace("\\", "/"),
                "source": str(src.relative_to(PROJECT_ROOT)).replace("\\", "/"),
                "sha1": digest,
                "question_text": "",
                "target_keyword": "",
                "expected_count": None,
                "expected_answer": None,
                "tags": ["regression", "moments"],
            }
        )
        count_unlabeled += 1

    return entries


def main() -> None:
    IMAGES_DIR.mkdir(parents=True, exist_ok=True)
    TESTSET_ROOT.mkdir(parents=True, exist_ok=True)

    entries = build_manifest_entries()
    if not entries:
        raise RuntimeError("No source images found. Please run monitor scripts first.")

    with MANIFEST_PATH.open("w", encoding="utf-8") as f:
        for row in entries:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")

    labeled = sum(1 for e in entries if e.get("labeled"))
    unlabeled = len(entries) - labeled

    print("=" * 60)
    print("Local OCR/AI testset built")
    print("=" * 60)
    print(f"Output: {TESTSET_ROOT}")
    print(f"Manifest: {MANIFEST_PATH}")
    print(f"Total: {len(entries)} (labeled={labeled}, unlabeled={unlabeled})")


if __name__ == "__main__":
    main()
