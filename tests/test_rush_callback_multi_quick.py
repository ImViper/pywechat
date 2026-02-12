"""Quick test for multi-source comment callback"""
import sys
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import queue
import time
from pyweixin.rush_callback_multi import (
    CannedCommentSource,
    DynamicCommentSource,
    create_multi_source_streaming_callback,
)


def test_canned_source():
    """Test CannedCommentSource"""
    print("\n=== Test 1: CannedCommentSource ===")
    source = CannedCommentSource(["666", "Amazing", "First"], max_select=2)
    result = source.generate("Test content", [])
    print(f"Result: {result}")
    assert isinstance(result, list)
    assert len(result) == 2
    print("[OK] CannedCommentSource OK")


def test_dynamic_source():
    """Test DynamicCommentSource"""
    print("\n=== Test 2: DynamicCommentSource ===")

    def custom_generator(content: str, image_paths: list[str]) -> str:
        return f"Dynamic: {len(content)} chars"

    source = DynamicCommentSource(custom_generator)
    result = source.generate("Test content", [])
    print(f"Result: {result}")
    assert result == "Dynamic: 12 chars"
    print("[OK] DynamicCommentSource OK")


def test_multi_source_callback():
    """Test create_multi_source_streaming_callback"""
    print("\n=== Test 3: Multi-Source Callback ===")

    # Mock sources
    sources = [
        CannedCommentSource(["First", "Second"], max_select=1),
        CannedCommentSource(["Third"], max_select=1),
        DynamicCommentSource(lambda c, i: "Fourth"),
    ]

    callback = create_multi_source_streaming_callback(
        sources=sources,
        max_comments=5,
        dedup=True,
        verbose=True,
    )

    # Run callback
    start = time.time()
    answer_queue = callback("Test content", [])

    # Collect results
    results = []
    while True:
        try:
            answer = answer_queue.get(timeout=2.0)
            if answer is None:
                break
            results.append(answer)
        except queue.Empty:
            break

    elapsed = time.time() - start
    print(f"\nCollected {len(results)} answers in {elapsed:.3f}s")
    print(f"Results: {results}")

    assert len(results) >= 3  # At least 3 sources should work
    print("[OK] Multi-Source Callback OK")


if __name__ == "__main__":
    print("=" * 60)
    print("Multi-Source Comment Callback Quick Test")
    print("=" * 60)

    try:
        test_canned_source()
        test_dynamic_source()
        test_multi_source_callback()

        print("\n" + "=" * 60)
        print("[OK] All tests passed!")
        print("=" * 60)

    except Exception as exc:
        print(f"\n[FAIL] Test failed: {exc}")
        import traceback
        traceback.print_exc()
        exit(1)
