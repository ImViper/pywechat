"""Viper Multi-Source Comment Callback — 多源评论生成器
不修改 upstream 代码，扩展流式回调机制。
"""
from __future__ import annotations

import json
import os
import queue
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Thread
from typing import Any, Callable, Protocol


# ---------------------------------------------------------------------------
# Priority Answer Queue — 优先级队列（AI 答案可以插队散弹猜测）
# ---------------------------------------------------------------------------

class PriorityAnswerQueue:
    """兼容 queue.Queue 接口的优先级队列。

    低 priority 数字 = 高优先级。消费端调用 .get() 返回纯字符串，
    与 queue.Queue 行为一致，不需要改 moments_ext.py 消费逻辑。
    """

    _SENTINEL_PRIORITY = 9999

    def __init__(self):
        self._q: queue.PriorityQueue = queue.PriorityQueue()
        self._counter = 0  # tie-breaker，保证 FIFO 稳定性

    def put(self, answer: str | None, priority: int = 10) -> None:
        if answer is None:
            self._q.put((self._SENTINEL_PRIORITY, self._counter, None))
        else:
            self._q.put((priority, self._counter, answer))
        self._counter += 1

    def get(self, timeout: float | None = None, **kwargs) -> str | None:
        _, _, answer = self._q.get(timeout=timeout)
        return answer

    def empty(self) -> bool:
        return self._q.empty()


# ---------------------------------------------------------------------------
# Deferred Image Paths — 延迟图片传递（散弹/模板不等，OCR/AI 等待图片就绪）
# ---------------------------------------------------------------------------

class DeferredImagePaths:
    """延迟图片路径容器。

    散弹/模板匹配不需要图片，立即执行。
    OCR/AI 需要图片，调用 wait_and_get() 阻塞等待图片就绪。

    Usage::

        deferred = DeferredImagePaths()
        # 启动 callback（散弹/TemplateMatch 立即执行）
        callback(content, deferred)
        # 图片提取完成后
        deferred.set(['/path/to/0.png', '/path/to/1.png'])
    """

    def __init__(self):
        self._paths: list[str] = []
        self._event = threading.Event()

    def set(self, paths: list[str]) -> None:
        """设置图片路径并通知等待中的 source。"""
        self._paths = list(paths) if paths else []
        self._event.set()

    def wait_and_get(self, timeout: float = 15.0) -> list[str]:
        """阻塞等待图片就绪，返回路径列表。"""
        self._event.wait(timeout=timeout)
        return self._paths

    @property
    def is_ready(self) -> bool:
        return self._event.is_set()

    # 兼容 list 接口（散弹/TemplateMatch 不会调用这些）
    def __iter__(self):
        return iter(self.wait_and_get())

    def __len__(self):
        if self._event.is_set():
            return len(self._paths)
        return 0  # 未就绪时返回 0

    def __bool__(self):
        return True  # 总是 truthy，表示"可能有图片"


class TemplateMatchCommentSource:
    """极速文本模板匹配评论（不依赖图片，~0ms）

    优先级最高（priority=-1），在 OCR/AI 之前完成。
    支持三种匹配策略：
      1. 已知答案映射（角色名 → 固定答案）
      2. 纯文本数学题求解
      3. 非 COUNT 类模板匹配（复用 parse_answer_from_templates）
    """

    priority = -1  # 比 OCR(0) 更高优先级

    def __init__(
        self,
        templates: list | None = None,
        known_answers: dict[str, str] | None = None,
        known_keywords: list[str] | None = None,
        answer_suffix: str | None = None,
        enable_math: bool = True,
    ):
        """
        Args:
            templates: QuestionTemplate 列表（用于非 COUNT 模板匹配）
            known_answers: 角色名 → 固定答案映射，如 {"楚凭阑": "5楚凭阑"}
            known_keywords: 已知角色名列表，用于在文本中匹配后查 known_answers
            answer_suffix: 拼车模式后缀，如 "男"
            enable_math: 是否启用数学题自动解答
        """
        self.templates = templates or []
        self.known_answers = known_answers or {}
        self.known_keywords = known_keywords or list(self.known_answers.keys())
        self.answer_suffix = answer_suffix
        self.enable_math = enable_math

    def _apply_suffix(self, answer: str) -> str:
        """提取前导数字，拼接 suffix。 '5楚凭阑' + suffix='男' → '5男'"""
        if not self.answer_suffix:
            return answer
        m = re.match(r'^(\d+)', answer)
        if m:
            return f"{m.group(1)}{self.answer_suffix}"
        return answer

    def _try_known_answer(self, content: str) -> str | None:
        """从文本中匹配已知角色名，返回预设答案。"""
        if not self.known_answers:
            return None
        for keyword in self.known_keywords:
            if keyword in content:
                answer = self.known_answers.get(keyword)
                if answer:
                    print(f"[TemplateMatch] known answer hit: {keyword!r} → {answer!r}")
                    return self._apply_suffix(answer)
        return None

    def _try_math(self, content: str) -> str | None:
        """安全正则求解纯文本数学题。"""
        if not self.enable_math:
            return None
        # 匹配常见中文题目格式：【2+5= ？】, 2+5=? , 2+5=
        patterns = [
            r'[【\[]?\s*(\d+)\s*([+\-×÷\*\/xX])\s*(\d+)\s*=\s*[？\?]?\s*[】\]]?',
        ]
        for pattern in patterns:
            m = re.search(pattern, content)
            if m:
                a, op, b = int(m.group(1)), m.group(2), int(m.group(3))
                try:
                    if op in ('+', ):
                        result = a + b
                    elif op in ('-', ):
                        result = a - b
                    elif op in ('×', '*', 'x', 'X'):
                        result = a * b
                    elif op in ('÷', '/'):
                        if b == 0:
                            return None
                        result = a // b if a % b == 0 else round(a / b, 2)
                    else:
                        return None
                    answer = str(result)
                    print(f"[TemplateMatch] math solved from text: {a}{op}{b}={answer}")
                    return self._apply_suffix(answer)
                except Exception:
                    return None
        return None

    def _try_templates(self, content: str) -> str | None:
        """非 COUNT 类模板匹配（复用 rush_engine.parse_answer_from_templates）。"""
        if not self.templates:
            return None
        try:
            from .rush_engine import parse_answer_from_templates
            result = parse_answer_from_templates(
                content, self.templates, skip_count_templates=True
            )
            if result and result.answer:
                answer = result.answer.strip()
                print(f"[TemplateMatch] template hit ({result.source}): {answer!r}")
                return self._apply_suffix(answer)
        except ImportError:
            pass
        return None

    def generate(self, content: str, image_paths: list[str]) -> str | None:
        """依次尝试三种策略，命中即返回。"""
        # 1. 已知答案映射（最快）
        answer = self._try_known_answer(content)
        if answer:
            return answer

        # 2. 数学题求解
        answer = self._try_math(content)
        if answer:
            return answer

        # 3. 非 COUNT 模板匹配
        answer = self._try_templates(content)
        if answer:
            return answer

        return None

    @staticmethod
    def load_known_answers(path: str) -> dict[str, str]:
        """从 JSON 文件加载已知答案映射。"""
        if not path or not os.path.isfile(path):
            return {}
        try:
            with open(path, "r", encoding="utf-8-sig") as f:
                data = json.load(f)
            if isinstance(data, dict):
                return {str(k): str(v) for k, v in data.items()}
        except Exception as exc:
            print(f"[TemplateMatch] failed to load known answers from {path}: {exc}")
        return {}


class NumberGuessCommentSource:
    """数字散弹猜测评论（立即覆盖常见答案范围，~0ms）

    优先级最低（priority=-2 表示最先执行，但队列优先级 loose=20 表示
    AI/OCR 精确答案可以在 UI 模式下插队）。
    """

    priority = -2  # 最先执行（在 TemplateMatch 之前）
    QUEUE_PRIORITY = 20  # 队列中优先级最低（数字越大越靠后）

    def __init__(
        self,
        guess_range: tuple[int, int] = (3, 7),
        suffix: str = "男",
        skip_values: set[str] | None = None,
    ):
        """
        Args:
            guess_range: 猜测数字范围 (min, max)，含两端
            suffix: 拼接后缀，如 "男"
            skip_values: 跳过的值（如其他 source 已知的精确答案）
        """
        self.guess_min, self.guess_max = guess_range
        self.suffix = suffix
        self.skip_values = skip_values or set()

    def generate(self, content: str, image_paths: list[str]) -> list[str]:
        """生成一组猜测答案。"""
        guesses = []
        for n in range(self.guess_min, self.guess_max + 1):
            answer = f"{n}{self.suffix}"
            if answer not in self.skip_values:
                guesses.append(answer)
        if guesses:
            print(f"[NumberGuess] scatter shot: {guesses}")
        return guesses


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
        # 支持 DeferredImagePaths — 等待图片就绪
        if hasattr(image_paths, 'wait_and_get'):
            image_paths = image_paths.wait_and_get()
        if not image_paths:
            return None

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
        # 支持 DeferredImagePaths — 等待图片就绪
        if hasattr(image_paths, 'wait_and_get'):
            image_paths = image_paths.wait_and_get()

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


# ---------------------------------------------------------------------------
# Source Priority -> Queue Priority 映射
# ---------------------------------------------------------------------------
# source.priority 控制执行顺序（越小越先执行）
# queue_priority 控制消费顺序（越小越先被 .get() 取出）
#
# NumberGuess:  source.priority=-2 (最先执行), queue_priority=20 (最后消费)
# TemplateMatch: source.priority=-1, queue_priority=1 (高优消费)
# OCR:          source.priority=0,  queue_priority=2
# AI:           source.priority=1,  queue_priority=0 (最高优消费！)
# Canned:       source.priority=2,  queue_priority=15
# OCRRetry:     source.priority=3,  queue_priority=3

_SOURCE_QUEUE_PRIORITY = {
    "NumberGuess": 20,       # 散弹猜测 — 队列最低优先级
    "TemplateMatch": 1,      # 模板精确匹配 — 高优先级
    "OCR": 2,                # OCR 识别 — 高优先级
    "AI": 0,                 # AI 答案 — 最高优先级（插队！）
    "Canned": 15,            # 预制话术 — 低优先级
    "OCRRetry": 3,           # OCR 重试 — 中等
    "Dynamic": 5,            # 动态生成 — 中等
}


def _get_queue_priority(source: Any) -> int:
    """获取评论源对应的队列消费优先级。"""
    # 优先检查类属性
    if hasattr(source, 'QUEUE_PRIORITY'):
        return source.QUEUE_PRIORITY
    # 按类名映射
    name = source.__class__.__name__.replace("CommentSource", "")
    return _SOURCE_QUEUE_PRIORITY.get(name, 10)


def create_multi_source_streaming_callback(
    sources: list[CommentSource],
    max_comments: int = 5,
    max_guess_comments: int = 5,
    dedup: bool = True,
    verbose: bool = True,
) -> Callable[[str, list[str] | DeferredImagePaths], PriorityAnswerQueue]:
    """创建多源流式回调（支持优先级队列 + 延迟图片）。

    Args:
        sources: 评论来源列表（按 priority 排序）
        max_comments: 精确答案最多几条（AI/OCR/TemplateMatch）
        max_guess_comments: 散弹猜测最多几条
        dedup: 是否去重（默认 True）
        verbose: 是否打印日志（默认 True）

    Returns:
        回调函数，签名为 (content, image_paths) -> PriorityAnswerQueue
        image_paths 可以是 list[str] 或 DeferredImagePaths
        Queue 中的答案按优先级弹出（AI > OCR > 散弹），None 表示结束
    """
    # 散弹阈值（queue_priority >= 此值视为散弹）
    _GUESS_PRIORITY_THRESHOLD = 15

    def callback(content: str, image_paths: list[str] | DeferredImagePaths) -> PriorityAnswerQueue:
        answer_queue = PriorityAnswerQueue()
        total_max = max_comments + max_guess_comments
        if verbose:
            print(
                f"[multi_source] start, {len(sources)} sources, "
                f"max={max_comments}+{max_guess_comments}guess"
            )

        callback_start = time.time()
        seen: set[str] = set()
        precise_count = 0  # AI/OCR/TemplateMatch
        guess_count = 0    # NumberGuess 散弹

        def push(answer: str, source_name: str, elapsed_ms: int,
                 q_priority: int = 10) -> bool:
            nonlocal precise_count, guess_count
            is_guess = q_priority >= _GUESS_PRIORITY_THRESHOLD

            # 分开计数：散弹 vs 精确答案
            if is_guess:
                if guess_count >= max_guess_comments:
                    return False
            else:
                if precise_count >= max_comments:
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
            answer_queue.put(answer, priority=q_priority)
            if is_guess:
                guess_count += 1
            else:
                precise_count += 1
            total = precise_count + guess_count
            if verbose:
                kind = "guess" if is_guess else "precise"
                pri_label = f"p{q_priority}" if q_priority != 10 else ""
                print(
                    f"[multi_source] {source_name} ready: {answer} ({elapsed_ms}ms) "
                    f"-> queue ({total}/{total_max}) {pri_label} [{kind}]"
                )
            return True

        def run_source(source: CommentSource, source_idx: int) -> None:
            """运行单个评论源"""
            start = time.time()
            source_name = source.__class__.__name__.replace("CommentSource", "")
            q_priority = _get_queue_priority(source)

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
                            push(str(answer).strip(), source_name, elapsed,
                                 q_priority)
                else:
                    answer = str(result).strip()
                    if answer:
                        push(answer, source_name, elapsed, q_priority)

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

                    # 如果两个计数都满了，取消剩余任务
                    if precise_count >= max_comments and guess_count >= max_guess_comments:
                        for f in futures:
                            if not f.done():
                                f.cancel()
                        break

            total_ms = int((time.time() - callback_start) * 1000)
            total = precise_count + guess_count
            if verbose:
                print(
                    f"[multi_source] all done ({total_ms}ms), "
                    f"{total} answers ({precise_count} precise + {guess_count} guess)"
                )
            answer_queue.put(None)  # 哨兵

        Thread(target=run_all, daemon=True).start()
        return answer_queue

    return callback
