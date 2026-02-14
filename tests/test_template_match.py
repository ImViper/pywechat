"""Tests for TemplateMatchCommentSource — instant text-match first comment."""
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import queue
import time

from pyweixin.rush_callback_multi import (
    CannedCommentSource,
    TemplateMatchCommentSource,
    NumberGuessCommentSource,
    PriorityAnswerQueue,
    create_multi_source_streaming_callback,
)


def test_template_match_math():
    """数学题 2+5=? → 7"""
    print("\n=== Test: math solving ===")
    source = TemplateMatchCommentSource(enable_math=True)

    # Basic addition
    result = source.generate("⚡️ 抢答开始！题目：【2+5= ？】", [])
    print(f"  2+5=? → {result!r}")
    assert result == "7", f"Expected '7', got {result!r}"

    # Subtraction
    result = source.generate("题目：【10-3= ？】", [])
    print(f"  10-3=? → {result!r}")
    assert result == "7", f"Expected '7', got {result!r}"

    # Multiplication
    result = source.generate("题目：【3×4= ？】", [])
    print(f"  3×4=? → {result!r}")
    assert result == "12", f"Expected '12', got {result!r}"

    # Division
    result = source.generate("题目：【9÷3= ？】", [])
    print(f"  9÷3=? → {result!r}")
    assert result == "3", f"Expected '3', got {result!r}"

    print("  [OK] math solving passed")


def test_template_match_math_disabled():
    """数学功能禁用时不匹配"""
    print("\n=== Test: math disabled ===")
    source = TemplateMatchCommentSource(enable_math=False)
    result = source.generate("题目：【2+5= ？】", [])
    assert result is None, f"Expected None when math disabled, got {result!r}"
    print("  [OK] math disabled passed")


def test_template_match_known_answer():
    """已知答案映射"""
    print("\n=== Test: known answer mapping ===")
    source = TemplateMatchCommentSource(
        known_answers={"楚凭阑": "5楚凭阑", "胡不医": "6胡不医"},
        enable_math=False,
    )

    result = source.generate("⚡️题目：下方图片中有多少个楚凭阑？", [])
    print(f"  楚凭阑 → {result!r}")
    assert result == "5楚凭阑", f"Expected '5楚凭阑', got {result!r}"

    result = source.generate("图中共有几位[胡不医]角色？", [])
    print(f"  胡不医 → {result!r}")
    assert result == "6胡不医", f"Expected '6胡不医', got {result!r}"

    # Unknown keyword → None
    result = source.generate("图中有几个葫芦？", [])
    print(f"  葫芦(not in mapping) → {result!r}")
    assert result is None, f"Expected None for unknown keyword, got {result!r}"

    print("  [OK] known answer mapping passed")


def test_template_match_suffix():
    """拼车模式 suffix 处理"""
    print("\n=== Test: suffix mode ===")
    source = TemplateMatchCommentSource(
        known_answers={"楚凭阑": "5楚凭阑"},
        answer_suffix="男",
        enable_math=True,
    )

    # Known answer with suffix: 5楚凭阑 → 5男
    result = source.generate("下方图片中有多少个楚凭阑？", [])
    print(f"  楚凭阑 + suffix=男 → {result!r}")
    assert result == "5男", f"Expected '5男', got {result!r}"

    # Math with suffix: 7 → 7男
    result = source.generate("题目：【2+5= ？】", [])
    print(f"  2+5 + suffix=男 → {result!r}")
    assert result == "7男", f"Expected '7男', got {result!r}"

    print("  [OK] suffix mode passed")


def test_template_match_no_match():
    """无匹配时返回 None"""
    print("\n=== Test: no match ===")
    source = TemplateMatchCommentSource(
        known_answers={"楚凭阑": "5楚凭阑"},
        enable_math=True,
    )

    # No keyword, no math pattern
    result = source.generate("今天天气真好", [])
    assert result is None, f"Expected None for unrelated text, got {result!r}"

    result = source.generate("请观察下方图片中出现了几个拿剑的人物？", [])
    assert result is None, f"Expected None for AI-only question, got {result!r}"

    print("  [OK] no match passed")


def test_number_guess_basic():
    """NumberGuessCommentSource 基础散弹"""
    print("\n=== Test: number guess basic ===")
    source = NumberGuessCommentSource(guess_range=(3, 7), suffix="男")
    result = source.generate("图中有几个楚凭阑？", [])
    print(f"  Guesses: {result}")
    assert result == ["3男", "4男", "5男", "6男", "7男"]
    assert source.QUEUE_PRIORITY == 20  # 队列最低优先级
    print("  [OK] number guess basic passed")


def test_number_guess_skip():
    """NumberGuessCommentSource 跳过特定值"""
    print("\n=== Test: number guess skip ===")
    source = NumberGuessCommentSource(
        guess_range=(3, 7), suffix="男", skip_values={"5男"}
    )
    result = source.generate("", [])
    print(f"  Guesses (skip 5男): {result}")
    assert "5男" not in result
    assert len(result) == 4
    print("  [OK] number guess skip passed")


def test_priority_queue_ordering():
    """PriorityAnswerQueue: AI(p0) 在散弹(p20) 前面被取出"""
    print("\n=== Test: priority queue ordering ===")
    pq = PriorityAnswerQueue()

    # 模拟场景：散弹先入队，AI 后入队
    pq.put("3男", priority=20)  # scatter shot
    pq.put("4男", priority=20)  # scatter shot
    pq.put("5男", priority=20)  # scatter shot
    pq.put("6拿扇子", priority=0)  # AI answer (highest priority)
    pq.put("6男", priority=20)  # scatter shot

    # AI 答案应该最先被取出
    first = pq.get(timeout=1)
    print(f"  First out: {first!r} (should be AI)")
    assert first == "6拿扇子", f"Expected AI answer first, got {first!r}"

    # 然后是散弹按入队顺序
    second = pq.get(timeout=1)
    print(f"  Second out: {second!r}")
    assert second == "3男"

    print("  [OK] priority queue ordering passed")


def test_priority_in_multi_source_callback():
    """AI(queue_priority=0) 在散弹(queue_priority=20) 前被消费（慢消费者场景）"""
    print("\n=== Test: priority in multi-source callback ===")

    # Slow AI source (~300ms)
    class FakeAI:
        priority = 1
        def generate(self, content, image_paths):
            time.sleep(0.3)
            return "6拿扇子"

    sources = [
        NumberGuessCommentSource(guess_range=(4, 6), suffix="男"),  # 3 guesses
        FakeAI(),
    ]

    callback = create_multi_source_streaming_callback(
        sources=sources, max_comments=10, dedup=True, verbose=True,
    )

    answer_queue = callback("图中有几个拿扇子的？", [])

    # Simulate SLOW consumer (UI mode, ~300ms per read)
    # Wait for all sources to finish so items coexist in queue
    time.sleep(0.5)  # AI finishes at ~300ms, all items now in queue

    results = []
    while True:
        try:
            ans = answer_queue.get(timeout=1.0)
            if ans is None:
                break
            results.append(ans)
        except queue.Empty:
            break

    print(f"  Slow consumer order: {results}")

    # With PriorityQueue, AI (p0) should be before scatter shots (p20)
    ai_idx = results.index("6拿扇子") if "6拿扇子" in results else -1
    print(f"  AI answer position: {ai_idx}")
    assert ai_idx == 0, f"AI answer (p0) should be first in slow consumer mode, got position {ai_idx}"

    # Scatter shots should follow
    assert "4男" in results
    assert "5男" in results
    assert "6男" in results

    print("  [OK] priority in multi-source callback passed")


def test_load_known_answers_file():
    """load_known_answers 从 JSON 文件加载"""
    print("\n=== Test: load_known_answers ===")
    import json
    import tempfile
    import os

    data = {"楚凭阑": "5楚凭阑", "红袖": "4红袖"}
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", delete=False, encoding="utf-8"
    ) as f:
        json.dump(data, f, ensure_ascii=False)
        tmp_file = f.name

    try:
        loaded = TemplateMatchCommentSource.load_known_answers(tmp_file)
        print(f"  Loaded: {loaded}")
        assert loaded == data, f"Mismatch: {loaded}"

        # Non-existent file returns empty
        empty = TemplateMatchCommentSource.load_known_answers("/tmp/nonexistent_12345.json")
        assert empty == {}, f"Expected empty dict for nonexistent file, got {empty}"
    finally:
        os.unlink(tmp_file)

    print("  [OK] load_known_answers passed")


if __name__ == "__main__":
    print("=" * 60)
    print("TemplateMatch + NumberGuess + PriorityQueue Tests")
    print("=" * 60)

    try:
        test_template_match_math()
        test_template_match_math_disabled()
        test_template_match_known_answer()
        test_template_match_suffix()
        test_template_match_no_match()
        test_number_guess_basic()
        test_number_guess_skip()
        test_priority_queue_ordering()
        test_priority_in_multi_source_callback()
        test_load_known_answers_file()

        print("\n" + "=" * 60)
        print("[OK] All tests passed!")
        print("=" * 60)

    except Exception as exc:
        print(f"\n[FAIL] Test failed: {exc}")
        import traceback
        traceback.print_exc()
        exit(1)

