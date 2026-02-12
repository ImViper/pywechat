"""Viper Multi-Source Comment Callback — 多源评论生成器
不修改 upstream 代码，扩展流式回调机制。
"""
from __future__ import annotations

import os
import queue
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Thread
from typing import Any, Callable, Protocol


class CommentSource(Protocol):
    """评论来源协议"""

    priority: int  # 优先级（0=最高）

    def generate(self, content: str, image_paths: list[str]) -> str | list[str] | None:
        """生成一条或多条评论。返回 None 表示不适用。"""
        ...


class OCRCommentSource:
    """OCR 快速识别评论"""

    priority = 0  # 最高优先级（最快）

    def __init__(
        self,
        ocr_provider: Any,
        known_keywords: list[str] | None = None,
        answer_suffix: str | None = None,
    ):
        self.ocr_provider = ocr_provider
        self.known_keywords = known_keywords
        self.answer_suffix = answer_suffix

    def generate(self, content: str, image_paths: list[str]) -> str | None:
        from .rush_callback import try_ocr_count

        answer = try_ocr_count(
            content,
            image_paths,
            self.ocr_provider,
            verbose=True,
            known_keywords=self.known_keywords,
        )
        if answer and self.answer_suffix:
            import re

            m = re.match(r"^(\d+)", answer)
            if m:
                answer = f"{m.group(1)}{self.answer_suffix}"
        return answer


class AICommentSource:
    """AI 精确识别评论"""

    priority = 1

    def __init__(self, ai_provider: Any):
        self.ai_provider = ai_provider

    def generate(self, content: str, image_paths: list[str]) -> str | None:
        from .rush_callback import try_ai_answer

        return try_ai_answer(content, image_paths, self.ai_provider, verbose=True)


class CannedCommentSource:
    """预制话术评论（固定文本，立即返回）"""

    priority = 2

    def __init__(self, canned_list: list[str], max_select: int = 2):
        """
        Args:
            canned_list: 预制话术列表，如 ['666', '厉害', '沙发']
            max_select: 最多选择几条（默认 2）
        """
        self.canned = canned_list
        self.max_select = max_select
        self._used_index = 0

    def generate(self, content: str, image_paths: list[str]) -> list[str]:
        """返回多条预制评论"""
        results = []
        for i in range(min(self.max_select, len(self.canned))):
            idx = (self._used_index + i) % len(self.canned)
            results.append(self.canned[idx])
        self._used_index = (self._used_index + self.max_select) % len(self.canned)
        return results


class OCRRetryCommentSource:
    """OCR 重试评论（不同参数再识别）"""

    priority = 3

    def __init__(
        self,
        ocr_provider: Any,
        retry_params: dict[str, Any],
        known_keywords: list[str] | None = None,
    ):
        """
        Args:
            retry_params: OCR 参数，如 {'text_det_limit_side_len': 1600}
        """
        self.ocr_provider = ocr_provider
        self.retry_params = retry_params
        self.known_keywords = known_keywords

    def generate(self, content: str, image_paths: list[str]) -> str | None:
        # 临时修改 OCR 参数
        original_params = {}
        for key, value in self.retry_params.items():
            if hasattr(self.ocr_provider, key):
                original_params[key] = getattr(self.ocr_provider, key)
                setattr(self.ocr_provider, key, value)

        try:
            from .rush_callback import try_ocr_count

            return try_ocr_count(
                content,
                image_paths,
                self.ocr_provider,
                verbose=True,
                known_keywords=self.known_keywords,
            )
        finally:
            # 恢复原参数
            for key, value in original_params.items():
                setattr(self.ocr_provider, key, value)


class DynamicCommentSource:
    """动态生成评论（基于规则或上下文）"""

    priority = 4

    def __init__(self, generator_func: Callable[[str, list[str]], str | None]):
        """
        Args:
            generator_func: 函数签名 (content: str, image_paths: list) -> str | None
        """
        self.generator = generator_func

    def generate(self, content: str, image_paths: list[str]) -> str | None:
        return self.generator(content, image_paths)


def create_multi_source_streaming_callback(
    sources: list[CommentSource],
    max_comments: int = 5,
    dedup: bool = True,
    verbose: bool = True,
) -> Callable[[str, list[str]], queue.Queue]:
    """创建多源流式回调。

    Args:
        sources: 评论来源列表（按 priority 排序）
        max_comments: 最多生成几条评论（默认 5）
        dedup: 是否去重（默认 True）
        verbose: 是否打印日志（默认 True）

    Returns:
        回调函数，签名为 (content: str, image_paths: list[str]) -> queue.Queue
        Queue 中的答案按完成顺序推送，None 表示结束
    """

    def callback(content: str, image_paths: list[str]) -> queue.Queue:
        answer_queue: queue.Queue = queue.Queue()
        if verbose:
            print(
                f"[multi_source] start, {len(sources)} sources, max={max_comments}"
            )

        callback_start = time.time()
        seen: set[str] = set()
        count = 0

        def push(answer: str, source_name: str, elapsed_ms: int) -> bool:
            nonlocal count
            if count >= max_comments:
                return False

            # 归一化比较（去除空格、统一大小写）
            normalized = "".join(answer.split()).lower()

            if dedup and normalized in seen:
                if verbose:
                    print(
                        f"[multi_source] {source_name} duplicate: {answer} ({elapsed_ms}ms), skip"
                    )
                return False

            seen.add(normalized)
            answer_queue.put(answer)
            count += 1
            if verbose:
                print(
                    f"[multi_source] {source_name} ready: {answer} ({elapsed_ms}ms) -> queue ({count}/{max_comments})"
                )
            return True

        def run_source(source: CommentSource, source_idx: int) -> None:
            """运行单个评论源"""
            start = time.time()
            source_name = source.__class__.__name__.replace("CommentSource", "")

            try:
                result = source.generate(content, image_paths)
                elapsed = int((time.time() - start) * 1000)

                # 处理单条或多条结果
                if result is None:
                    if verbose:
                        print(f"[multi_source] {source_name} no result ({elapsed}ms)")
                elif isinstance(result, list):
                    for answer in result:
                        if answer:
                            push(str(answer).strip(), source_name, elapsed)
                else:
                    answer = str(result).strip()
                    if answer:
                        push(answer, source_name, elapsed)

            except Exception as exc:
                elapsed = int((time.time() - start) * 1000)
                if verbose:
                    print(f"[multi_source] {source_name} failed ({elapsed}ms): {exc}")

        def run_all() -> None:
            """并行运行所有评论源"""
            with ThreadPoolExecutor(max_workers=len(sources)) as executor:
                futures = {
                    executor.submit(run_source, source, idx): source
                    for idx, source in enumerate(sources)
                }

                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception as exc:
                        if verbose:
                            print(f"[multi_source] task exception: {exc}")

                    # 如果已达到最大评论数，取消剩余任务
                    if count >= max_comments:
                        for f in futures:
                            if not f.done():
                                f.cancel()
                        break

            total_ms = int((time.time() - callback_start) * 1000)
            if verbose:
                print(
                    f"[multi_source] all done ({total_ms}ms), {count} unique answers"
                )
            answer_queue.put(None)  # 哨兵

        Thread(target=run_all, daemon=True).start()
        return answer_queue

    return callback
