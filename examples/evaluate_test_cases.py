"""基于标准测试集评估 AI 答题准确度"""

import json
import sys
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent.parent))

from pyweixin.rush_engine import resolve_answer, load_rush_config
from pyweixin.rush_ai import ArkChatProvider, NullOCRProvider


def load_test_cases(test_file: str) -> list[dict[str, Any]]:
    """加载测试集"""
    with open(test_file, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data.get("test_cases", [])


def load_api_key_from_file(path: str, env_name: str) -> str:
    """从文件中加载 API 密钥"""
    import os
    if not path or not os.path.exists(path):
        return ""
    try:
        with open(path, "r", encoding="utf-8-sig") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return ""
        candidate_keys = [env_name, "ARK_API_KEY", "api_key"]
        for key in candidate_keys:
            value = data.get(key)
            if value:
                return str(value).strip()
    except Exception:
        pass
    return ""


def evaluate_test_case(
    test_case: dict[str, Any],
    config,
    ai_provider,
    ocr_provider
) -> dict[str, Any]:
    """评估单条测试用例"""
    question_text = test_case.get("question_text", "")
    image_paths = test_case.get("image_paths", [])
    expected_answer = test_case.get("expected_answer")

    result = {
        "id": test_case.get("id"),
        "question_type": test_case.get("question_type"),
        "expected_answer": expected_answer,
        "ai_answer": None,
        "method": None,
        "elapsed_ms": 0,
        "is_correct": None,
        "error": None
    }

    start_time = time.time()

    try:
        answer_result = resolve_answer(
            post_content=question_text,
            detail_text="",
            image_paths=image_paths,
            templates=config.templates,
            ocr_provider=ocr_provider,
            ai_provider=ai_provider,
            ai_enabled=True,
            ai_timeout_ms=config.ai_timeout_ms,
            confidence_threshold=config.confidence_threshold
        )

        if answer_result:
            result["ai_answer"] = answer_result.answer
            if "template:" in answer_result.source:
                result["method"] = "template"
            else:
                result["method"] = "ai"

            # 判断是否正确
            if expected_answer is not None:
                if expected_answer == "SKIP":
                    result["is_correct"] = (answer_result.answer is None)
                else:
                    result["is_correct"] = (answer_result.answer == expected_answer)
        else:
            # 没有答案
            if expected_answer == "SKIP":
                result["is_correct"] = True  # 正确过滤

    except Exception as e:
        result["error"] = str(e)

    result["elapsed_ms"] = int((time.time() - start_time) * 1000)

    return result


def print_results(results: list[dict[str, Any]]):
    """打印评估结果"""
    print(f"\n{'='*80}")
    print("测试集评估结果")
    print(f"{'='*80}\n")

    total = len(results)
    answered = sum(1 for r in results if r["ai_answer"] is not None)

    # 可判定题的准确率
    judgeable = [r for r in results if r["expected_answer"] is not None]
    correct = sum(1 for r in judgeable if r["is_correct"] is True)

    print(f"总题数: {total}")
    print(f"已答题: {answered}/{total} ({answered/total*100:.1f}%)")
    print(f"可判定: {len(judgeable)} 条")
    if judgeable:
        print(f"准确率: {correct}/{len(judgeable)} ({correct/len(judgeable)*100:.1f}%)")
    print()

    # 按方法统计
    template_count = sum(1 for r in results if r["method"] == "template")
    ai_count = sum(1 for r in results if r["method"] == "ai")
    print(f"模板匹配: {template_count}")
    print(f"AI 答题: {ai_count}")
    print()

    # 耗时统计
    elapsed_times = [r["elapsed_ms"] for r in results if r["elapsed_ms"] > 0]
    if elapsed_times:
        print(f"平均耗时: {sum(elapsed_times)/len(elapsed_times):.0f} ms")
        print(f"最快耗时: {min(elapsed_times)} ms")
        print(f"最慢耗时: {max(elapsed_times)} ms")
    print()

    # 详细结果
    print("详细结果:")
    print("-" * 80)
    for r in results:
        status = "[Y]" if r["ai_answer"] else "[N]"
        if r["is_correct"] is not None:
            status += " OK" if r["is_correct"] else " FAIL"

        method = r["method"] or "N/A"
        answer = r["ai_answer"] or "无答案"
        expected = r["expected_answer"] or "未标注"

        print(f"{status} [{r['id']}] {method:8s} | {r['elapsed_ms']:4d}ms")
        print(f"    类型: {r['question_type']}")
        print(f"    期望: {expected}")
        print(f"    实际: {answer}")
        if r["error"]:
            print(f"    错误: {r['error']}")
        print()


def main():
    import argparse
    import os

    parser = argparse.ArgumentParser(description="基于标准测试集评估 AI 答题准确度")
    parser.add_argument(
        "--test-file",
        default="dataset/test_cases.json",
        help="测试集文件路径"
    )
    parser.add_argument(
        "--config",
        default="config/rush_event.json",
        help="Rush 配置文件路径"
    )
    parser.add_argument(
        "--ai-timeout",
        type=int,
        help="AI 超时时间（毫秒）"
    )
    parser.add_argument(
        "--output",
        help="输出结果到 JSON 文件"
    )

    args = parser.parse_args()

    # 加载配置
    print(f"加载配置: {args.config}")
    config = load_rush_config(args.config)

    if args.ai_timeout:
        print(f"覆盖 AI 超时: {args.ai_timeout}ms")
        config.ai_timeout_ms = args.ai_timeout

    # 初始化 AI Provider
    print("初始化 Ark Chat API Provider...")
    api_key = os.getenv("ARK_API_KEY")
    if not api_key:
        api_key = load_api_key_from_file("config/.local_secrets.json", "ARK_API_KEY")
    if not api_key:
        raise RuntimeError("缺少 ARK_API_KEY")

    ai_provider = ArkChatProvider(api_key=api_key)
    ocr_provider = NullOCRProvider()

    # 加载测试集
    print(f"加载测试集: {args.test_file}")
    test_cases = load_test_cases(args.test_file)
    print(f"找到 {len(test_cases)} 条测试用例\n")

    # 逐条评估
    results = []
    for i, test_case in enumerate(test_cases, 1):
        print(f"[{i}/{len(test_cases)}] 评估 {test_case['id']}...")
        result = evaluate_test_case(test_case, config, ai_provider, ocr_provider)
        results.append(result)

        # 实时显示
        if result["ai_answer"]:
            status = "OK" if result["is_correct"] else "FAIL" if result["is_correct"] is False else "?"
            print(f"  [{status}] {result['ai_answer']} (方法: {result['method']}, 耗时: {result['elapsed_ms']}ms)")
        else:
            print(f"  [N] 未获得答案 (耗时: {result['elapsed_ms']}ms)")

    # 打印汇总
    print_results(results)

    # 保存结果
    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(results, f, ensure_ascii=False, indent=2)

        print(f"\n结果已保存到: {output_path}")


if __name__ == "__main__":
    main()
