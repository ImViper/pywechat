"""离线评估 Ark API 答题准确度。

从已采集的 question_candidates.json 中读取题目，使用 Ark API 进行答题，
评估准确率、耗时等指标。
"""

import json
import os
import sys
import time
from pathlib import Path
from typing import Any

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from pyweixin.rush_engine import load_rush_config, parse_answer_from_templates, resolve_answer
from pyweixin.rush_ai import ArkChatProvider, NullOCRProvider


def load_api_key_from_file(path: str, env_name: str) -> str:
    """从文件中加载 API 密钥。"""
    if not path or not os.path.exists(path):
        return ""
    try:
        with open(path, "r", encoding="utf-8-sig") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return ""
        candidate_keys = [env_name, "ARK_API_KEY", "api_key"]
        seen = set()
        for key in candidate_keys:
            if not key or key in seen:
                continue
            seen.add(key)
            value = data.get(key)
            if value:
                return str(value).strip()
    except Exception:
        pass
    return ""


def load_candidates(dataset_dir: str) -> list[dict[str, Any]]:
    """加载候选题目。"""
    candidates_file = Path(dataset_dir) / "question_candidates.json"
    if not candidates_file.exists():
        raise FileNotFoundError(f"找不到候选题目文件: {candidates_file}")

    with open(candidates_file, "r", encoding="utf-8") as f:
        return json.load(f)


def read_image_paths(detail_folder: str) -> list[str]:
    """读取详情文件夹中的图片路径。"""
    if not detail_folder or not os.path.exists(detail_folder):
        return []

    folder = Path(detail_folder)
    image_files = []

    # 查找所有图片文件（按数字排序）
    # 图片文件名格式：0.png, 1.png, 2.png, ...
    for i in range(0, 100):  # 从 0 开始，假设最多 100 张图片
        for ext in ['.png', '.jpg', '.jpeg']:
            img_path = folder / f"{i}{ext}"
            if img_path.exists():
                image_files.append(str(img_path))
                break

    return image_files


def evaluate_one(
    candidate: dict[str, Any],
    config,
    ai_provider,
    ocr_provider,
    mode: str = "template+ai"
) -> dict[str, Any]:
    """评估单条题目。

    Args:
        candidate: 候选题目数据
        config: rush 配置
        ai_provider: AI 答题提供者
        ocr_provider: OCR 提供者
        mode: 评估模式
            - "template_only": 仅使用模板匹配
            - "template+ai": 模板优先，失败时用 AI（默认）
            - "ai_only": 仅使用 AI

    Returns:
        包含评估结果的字典
    """
    content = candidate.get("内容", "")
    detail_folder = candidate.get("detail_folder", "")
    image_paths = read_image_paths(detail_folder)

    result = {
        "index": candidate.get("index"),
        "content": content,
        "image_count": len(image_paths),
        "mode": mode,
        "answer": None,
        "confidence": 0.0,
        "method": None,
        "elapsed_ms": 0,
        "error": None
    }

    start_time = time.time()

    try:
        if mode == "template_only":
            # 仅模板匹配
            answer_result = parse_answer_from_templates(content, config.templates)
            if answer_result:
                result["answer"] = answer_result.answer
                result["confidence"] = answer_result.confidence
                result["method"] = "template"

        elif mode == "ai_only":
            # 仅 AI（关闭模板）
            answer_result = resolve_answer(
                post_content=content,
                detail_text="",
                image_paths=image_paths,
                templates=[],  # 不使用模板
                ocr_provider=ocr_provider,
                ai_provider=ai_provider,
                ai_enabled=True,
                ai_timeout_ms=config.ai_timeout_ms,
                confidence_threshold=config.confidence_threshold
            )
            if answer_result:
                result["answer"] = answer_result.answer
                result["confidence"] = answer_result.confidence
                result["method"] = "ai"

        else:  # template+ai (默认)
            # 模板优先，AI兜底
            answer_result = resolve_answer(
                post_content=content,
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
                result["answer"] = answer_result.answer
                result["confidence"] = answer_result.confidence
                # 判断是模板还是 AI
                if "template:" in answer_result.source:
                    result["method"] = "template"
                else:
                    result["method"] = "ai"

    except Exception as e:
        result["error"] = str(e)

    result["elapsed_ms"] = int((time.time() - start_time) * 1000)

    return result


def print_summary(results: list[dict[str, Any]], mode: str):
    """打印评估摘要。"""
    print(f"\n{'='*80}")
    print(f"评估模式: {mode}")
    print(f"{'='*80}\n")

    total = len(results)
    answered = sum(1 for r in results if r["answer"] is not None)
    errors = sum(1 for r in results if r["error"] is not None)

    template_count = sum(1 for r in results if r["method"] == "template")
    ai_count = sum(1 for r in results if r["method"] == "ai")

    elapsed_times = [r["elapsed_ms"] for r in results if r["elapsed_ms"] > 0]
    avg_elapsed = sum(elapsed_times) / len(elapsed_times) if elapsed_times else 0

    print(f"总题数: {total}")
    print(f"已答题: {answered} ({answered/total*100:.1f}%)")
    print(f"未答题: {total - answered} ({(total-answered)/total*100:.1f}%)")
    print(f"出错数: {errors}")
    print()
    print(f"模板匹配: {template_count}")
    print(f"AI 答题: {ai_count}")
    print()
    print(f"平均耗时: {avg_elapsed:.0f} ms")
    print(f"最快耗时: {min(elapsed_times) if elapsed_times else 0} ms")
    print(f"最慢耗时: {max(elapsed_times) if elapsed_times else 0} ms")
    print()

    # 打印每条结果
    print("详细结果:")
    print("-" * 80)
    for r in results:
        status = "[Y]" if r["answer"] else "[N]"
        method = r["method"] or "N/A"
        answer = r["answer"] or "无答案"
        error_info = f" (错误: {r['error']})" if r["error"] else ""

        try:
            print(f"{status} [#{r['index']:2d}] {method:8s} | "
                  f"{r['elapsed_ms']:4d}ms | {answer:20s}{error_info}")

            # 打印题目内容（前 50 字符，仅 ASCII）
            content_preview = r['content'].replace('\n', ' ')[:50]
            # 过滤非 ASCII 字符避免编码问题
            content_ascii = ''.join(c if ord(c) < 128 else '?' for c in content_preview)
            print(f"    题目: {content_ascii}...")
            print()
        except UnicodeEncodeError:
            print(f"{status} [#{r['index']:2d}] {method:8s} | {r['elapsed_ms']:4d}ms")
            print()


def main():
    """主函数。"""
    import argparse

    parser = argparse.ArgumentParser(description="离线评估 Ark API 答题准确度")
    parser.add_argument(
        "--dataset",
        default="dataset/moments_questions_第七人格_20260207_001820",
        help="数据集目录路径（包含 question_candidates.json）"
    )
    parser.add_argument(
        "--config",
        default="config/rush_event.json",
        help="Rush 配置文件路径"
    )
    parser.add_argument(
        "--mode",
        choices=["template_only", "template+ai", "ai_only"],
        default="template+ai",
        help="评估模式"
    )
    parser.add_argument(
        "--output",
        help="输出结果到 JSON 文件"
    )
    parser.add_argument(
        "--ai-timeout",
        type=int,
        help="AI 超时时间（毫秒），覆盖配置文件中的设置"
    )

    args = parser.parse_args()

    # 加载配置
    print(f"加载配置: {args.config}")
    config = load_rush_config(args.config)

    # 覆盖 AI 超时设置
    if args.ai_timeout:
        print(f"覆盖 AI 超时: {args.ai_timeout}ms")
        config.ai_timeout_ms = args.ai_timeout

    # 初始化 AI Provider（仅在需要时）
    ai_provider = None
    if args.mode in ["template+ai", "ai_only"]:
        print("初始化 Ark Chat API Provider (优化版)...")

        # 读取 API 密钥
        api_key = os.getenv("ARK_API_KEY")
        if not api_key:
            key_file = "config/.local_secrets.json"
            api_key = load_api_key_from_file(key_file, "ARK_API_KEY")
        if not api_key:
            raise RuntimeError(
                "缺少 ARK_API_KEY。请设置环境变量或在 config/.local_secrets.json 中配置。"
            )

        # 使用新的 ArkChatProvider（使用 Chat API + reasoning_effort="minimal"）
        ai_provider = ArkChatProvider(api_key=api_key)
        print(f"  API Key: {api_key[:8]}...{api_key[-4:]}")
        print(f"  优化: reasoning_effort=minimal, detail=low, max_tokens={ai_provider.max_tokens}")

    ocr_provider = NullOCRProvider()

    # 加载候选题目
    print(f"加载候选题目: {args.dataset}")
    candidates = load_candidates(args.dataset)
    print(f"找到 {len(candidates)} 条候选题目\n")

    # 逐条评估
    results = []
    for i, candidate in enumerate(candidates, 1):
        print(f"[{i}/{len(candidates)}] 评估 index={candidate.get('index')}...")
        result = evaluate_one(candidate, config, ai_provider, ocr_provider, args.mode)
        results.append(result)

        # 实时显示结果
        if result["answer"]:
            print(f"  [Y] 答案: {result['answer']} (方法: {result['method']}, 耗时: {result['elapsed_ms']}ms)")
        else:
            print(f"  [N] 未获得答案 (耗时: {result['elapsed_ms']}ms)")
            if result["error"]:
                print(f"    错误: {result['error']}")

    # 打印汇总
    print_summary(results, args.mode)

    # 保存结果
    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(results, f, ensure_ascii=False, indent=2)

        print(f"\n结果已保存到: {output_path}")


if __name__ == "__main__":
    main()
