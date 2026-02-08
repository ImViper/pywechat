"""AI provider protocol for rush answer generation."""

from __future__ import annotations

import base64
import inspect
import json
import mimetypes
import os
from dataclasses import dataclass
from typing import Any, Protocol
from urllib import request

try:
    from .rush_types import AnswerResult, QuestionTemplate
except ImportError:  # pragma: no cover - for direct module import in local tests
    from rush_types import AnswerResult, QuestionTemplate


class AIAnswerProvider(Protocol):
    """Implement this protocol to plug your own model."""

    def answer_from_text_and_images(
        self,
        question_text: str,
        image_paths: list[str],
        templates_hint: list[QuestionTemplate] | None = None,
    ) -> AnswerResult | None:
        ...


class OCRProvider(Protocol):
    """Optional OCR provider protocol."""

    def extract_text(self, image_path: str) -> str:
        ...


@dataclass(slots=True)
class NullAIProvider:
    """Fallback provider that returns no answer."""

    def answer_from_text_and_images(
        self,
        question_text: str,
        image_paths: list[str],
        templates_hint: list[QuestionTemplate] | None = None,
    ) -> AnswerResult | None:
        _ = (question_text, image_paths, templates_hint)
        return None


@dataclass(slots=True)
class NullOCRProvider:
    """Fallback OCR provider."""

    def extract_text(self, image_path: str) -> str:
        _ = image_path
        return ""


@dataclass(slots=True)
class PaddleOCRProvider:
    """
    PaddleOCR provider for local text extraction.

    Completely free, no API key needed, runs locally.
    Install: pip install paddleocr paddlepaddle
    """

    _ocr_cache = {}
    use_angle_cls: bool = True
    lang: str = "ch"  # 'ch' for Chinese, 'en' for English
    show_log: bool = False
    enable_mkldnn: bool = False
    text_detection_model_name: str | None = None
    text_recognition_model_name: str | None = None
    cpu_threads: int | None = None
    text_det_limit_side_len: int | None = 1200
    text_det_limit_type: str | None = "max"

    @staticmethod
    def _looks_like_missing_paddle_core(exc: Exception) -> bool:
        """Detect missing paddle runtime from nested exceptions/messages."""
        text = f"{type(exc).__name__}: {exc}"
        lower_text = text.lower()
        if "no module named 'paddle'" in lower_text:
            return True
        if "import paddle" in lower_text and "no module named" in lower_text:
            return True
        cause = getattr(exc, "__cause__", None)
        if cause is not None and cause is not exc:
            cause_text = f"{type(cause).__name__}: {cause}".lower()
            if "no module named 'paddle'" in cause_text:
                return True
        return False

    def _get_ocr(self):
        """Lazy load PaddleOCR instance."""
        cls = type(self)
        cache_key = (
            self.use_angle_cls,
            self.lang,
            self.show_log,
            self.enable_mkldnn,
            self.text_detection_model_name,
            self.text_recognition_model_name,
            self.cpu_threads,
        )
        if cache_key not in cls._ocr_cache:
            try:
                if not self.enable_mkldnn and "FLAGS_use_mkldnn" not in os.environ:
                    # Paddle 3.x CPU + oneDNN has known runtime regressions on some setups.
                    os.environ["FLAGS_use_mkldnn"] = "0"
                from paddleocr import PaddleOCR
                sig = inspect.signature(PaddleOCR)
                kwargs = {}
                has_custom_models = bool(self.text_detection_model_name or self.text_recognition_model_name)
                if (not has_custom_models) and "lang" in sig.parameters:
                    kwargs["lang"] = self.lang
                if "show_log" in sig.parameters:
                    kwargs["show_log"] = self.show_log
                if "device" in sig.parameters:
                    kwargs["device"] = "cpu"
                if "use_doc_orientation_classify" in sig.parameters:
                    kwargs["use_doc_orientation_classify"] = False
                if "use_doc_unwarping" in sig.parameters:
                    kwargs["use_doc_unwarping"] = False
                if "use_textline_orientation" in sig.parameters:
                    kwargs["use_textline_orientation"] = self.use_angle_cls
                elif "use_angle_cls" in sig.parameters:
                    kwargs["use_angle_cls"] = self.use_angle_cls
                if "use_gpu" in sig.parameters:
                    kwargs["use_gpu"] = False
                if self.text_detection_model_name and "text_detection_model_name" in sig.parameters:
                    kwargs["text_detection_model_name"] = self.text_detection_model_name
                if self.text_recognition_model_name and "text_recognition_model_name" in sig.parameters:
                    kwargs["text_recognition_model_name"] = self.text_recognition_model_name
                if isinstance(self.cpu_threads, int) and self.cpu_threads > 0:
                    if "cpu_threads" in sig.parameters:
                        kwargs["cpu_threads"] = self.cpu_threads
                    else:
                        # Some versions accept this via **kwargs only.
                        kwargs["cpu_threads"] = self.cpu_threads
                speculative_enable_mkldnn = False
                if "enable_mkldnn" in sig.parameters:
                    kwargs["enable_mkldnn"] = self.enable_mkldnn
                elif "use_mkldnn" in sig.parameters:
                    kwargs["use_mkldnn"] = self.enable_mkldnn
                else:
                    # PaddleOCR 3.x may accept this through **kwargs even if not in signature.
                    kwargs["enable_mkldnn"] = self.enable_mkldnn
                    speculative_enable_mkldnn = True
                try:
                    cls._ocr_cache[cache_key] = PaddleOCR(**kwargs)
                except Exception as inner_exc:
                    msg = str(inner_exc)
                    if speculative_enable_mkldnn and "Unknown argument: enable_mkldnn" in msg:
                        kwargs.pop("enable_mkldnn", None)
                        cls._ocr_cache[cache_key] = PaddleOCR(**kwargs)
                    else:
                        raise
            except ImportError as exc:
                if "no module named 'paddle'" in str(exc).lower():
                    raise RuntimeError(
                        "PaddleOCR runtime dependency 'paddle' is missing. "
                        "Install paddlepaddle in a supported Python environment "
                        "(recommended Python 3.10/3.11)."
                    ) from exc
                raise RuntimeError(
                    "PaddleOCR not installed. Run: pip install paddleocr paddlepaddle"
                ) from exc
            except Exception as exc:
                if self._looks_like_missing_paddle_core(exc):
                    raise RuntimeError(
                        "PaddleOCR runtime dependency 'paddle' is missing. "
                        "Install paddlepaddle in a supported Python environment "
                        "(recommended Python 3.10/3.11)."
                    ) from exc
                raise
        return cls._ocr_cache[cache_key]

    def extract_text(self, image_path: str) -> str:
        """Extract text from image using PaddleOCR."""
        if not os.path.isfile(image_path):
            return ""

        try:
            ocr = self._get_ocr()
            # PaddleOCR 3.x prefers predict(); ocr() is retained for backward compatibility.
            if hasattr(ocr, "predict"):
                predict_kwargs = {}
                if isinstance(self.text_det_limit_side_len, int) and self.text_det_limit_side_len > 0:
                    try:
                        predict_sig = inspect.signature(ocr.predict)
                        if "text_det_limit_side_len" in predict_sig.parameters:
                            predict_kwargs["text_det_limit_side_len"] = self.text_det_limit_side_len
                        if (
                            self.text_det_limit_type
                            and isinstance(self.text_det_limit_type, str)
                            and "text_det_limit_type" in predict_sig.parameters
                        ):
                            predict_kwargs["text_det_limit_type"] = self.text_det_limit_type
                    except Exception:
                        pass
                result = ocr.predict(image_path, **predict_kwargs)
            else:
                result = ocr.ocr(image_path, cls=self.use_angle_cls)
            if not result:
                return ""

            # Extract text from OCR result (compatible with multiple PaddleOCR result formats).
            lines = []
            if isinstance(result, list):
                for item in result:
                    if isinstance(item, dict):
                        rec_texts = item.get("rec_texts")
                        if isinstance(rec_texts, (list, tuple)):
                            for text in rec_texts:
                                if isinstance(text, str) and text.strip():
                                    lines.append(text.strip())
                        text = item.get("rec_text") or item.get("text") or ""
                        if isinstance(text, str) and text.strip():
                            lines.append(text.strip())
                    elif isinstance(item, list):
                        for line in item:
                            if line and len(line) >= 2:
                                text_obj = line[1]
                                text = (
                                    text_obj[0]
                                    if isinstance(text_obj, (tuple, list)) and text_obj
                                    else str(text_obj)
                                )
                                if text:
                                    lines.append(text.strip())

            return "\n".join(lines).strip()
        except Exception as exc:
            msg = str(exc)
            if "ConvertPirAttribute2RuntimeAttribute" in msg:
                print(
                    "[OCR] Paddle CPU/oneDNN runtime issue detected. "
                    "Recommend: disable MKLDNN or install paddlepaddle==3.2.2."
                )
            print(f"[OCR] PaddleOCR failed on {os.path.basename(image_path)}: {exc}")
            return ""


@dataclass(slots=True)
class SiliconFlowOpenAIProvider:
    """
    SiliconFlow OpenAI-compatible chat/completions provider.

    Default model is Qwen/Qwen3-VL-32B-Instruct for VLM use.
    """

    api_key: str | None = None
    model: str = "Qwen/Qwen3-VL-32B-Instruct"
    base_url: str = "https://api.siliconflow.cn/v1"
    system_prompt: str = (
        "You are an answer extraction assistant for fast WeChat moments rush. "
        "Return only final answer text, no explanation."
    )
    max_tokens: int = 64
    temperature: float = 0.1
    top_p: float = 0.7
    timeout_sec: float = 8.0
    enable_thinking: bool = False

    def __post_init__(self) -> None:
        if not self.api_key:
            self.api_key = os.getenv("SILICONFLOW_API_KEY")
        self.base_url = self.base_url.rstrip("/")

    @staticmethod
    def _image_to_data_url(image_path: str) -> str:
        mime, _ = mimetypes.guess_type(image_path)
        if not mime:
            mime = "image/png"
        with open(image_path, "rb") as f:
            b64 = base64.b64encode(f.read()).decode("ascii")
        return f"data:{mime};base64,{b64}"

    def _build_user_prompt(self, question_text: str, templates_hint: list[QuestionTemplate] | None) -> str:
        template_names = [t.name for t in (templates_hint or [])][:8]
        hint = ",".join(template_names) if template_names else "none"
        return (
            "Task: read the post text/image and output ONLY the final answer string.\n"
            "No explanation, no markdown, no JSON.\n"
            f"Template hints: {hint}\n"
            f"Question context:\n{question_text}"
        )

    def _build_payload(
        self,
        question_text: str,
        image_paths: list[str],
        templates_hint: list[QuestionTemplate] | None = None,
    ) -> dict:
        content: list[dict] = [{"type": "text", "text": self._build_user_prompt(question_text, templates_hint)}]
        for path in image_paths:
            if os.path.isfile(path):
                content.append({"type": "image_url", "image_url": {"url": self._image_to_data_url(path)}})
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": self.system_prompt},
                {"role": "user", "content": content},
            ],
            "stream": False,
            "max_tokens": self.max_tokens,
            "temperature": self.temperature,
            "top_p": self.top_p,
        }
        # Some OpenAI-compatible endpoints reject unknown params for specific models.
        # Only include enable_thinking when explicitly enabled.
        if self.enable_thinking:
            payload["enable_thinking"] = True
        return payload

    @staticmethod
    def _extract_message_text(content: object) -> str:
        if isinstance(content, str):
            return content.strip()
        if isinstance(content, list):
            chunks: list[str] = []
            for item in content:
                if isinstance(item, dict):
                    if item.get("type") == "text" and isinstance(item.get("text"), str):
                        chunks.append(item["text"].strip())
                    elif isinstance(item.get("content"), str):
                        chunks.append(item["content"].strip())
            return "\n".join([x for x in chunks if x]).strip()
        return ""

    @staticmethod
    def _normalize_answer(text: str) -> str:
        answer = text.strip()
        if not answer:
            return ""
        answer = answer.replace("\r", "\n").split("\n")[0].strip()
        # strip common wrappers
        answer = answer.strip("` ")
        return answer

    def answer_from_text_and_images(
        self,
        question_text: str,
        image_paths: list[str],
        templates_hint: list[QuestionTemplate] | None = None,
    ) -> AnswerResult | None:
        if not self.api_key:
            raise ValueError("Missing API key. Set SILICONFLOW_API_KEY or pass api_key.")
        payload = self._build_payload(question_text, image_paths, templates_hint)
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        req = request.Request(
            url=f"{self.base_url}/chat/completions",
            data=body,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}",
            },
        )
        with request.urlopen(req, timeout=self.timeout_sec) as resp:
            raw = resp.read().decode("utf-8")
        data = json.loads(raw)
        choices = data.get("choices") or []
        if not choices:
            return None
        message = choices[0].get("message", {})
        text = self._extract_message_text(message.get("content"))
        answer = self._normalize_answer(text)
        if not answer:
            return None
        return AnswerResult(
            answer=answer,
            confidence=0.6,
            source=f"ai:siliconflow:{self.model}",
            extra={"model": self.model},
        )


@dataclass(slots=True)
class ArkChatProvider:
    """
    Volcengine Ark Chat API provider (chat/completions endpoint).

    Optimized for speed:
    - Uses reasoning_effort="minimal" to disable thinking
    - Uses detail="low" for fast image processing
    - Minimal prompt for direct answers

    Install:
        pip install --upgrade "volcengine-python-sdk[ark]"
    """

    api_key: str | None = None
    model: str = "doubao-seed-1-8-251228"
    base_url: str = "https://ark.cn-beijing.volces.com/api/v3"
    system_prompt: str = (
        "抢答助手。只输出答案，不解释.\\n"
        "1. 问角色名数量（如楚凭阑、胡不医）→ 数字+角色名，如 4年华\\n"
        "2. 问物品/动作数量（如葫芦、拿剑的人）→ 只要数字，如 3\\n"
        "3. 数学题 → 只要数字答案，如 7\\n"
        "4. 非题目 → SKIP"
    )
    max_tokens: int = 32
    temperature: float = 0.7
    top_p: float = 0.9
    timeout_sec: float = 5.0

    def __post_init__(self) -> None:
        if not self.api_key:
            self.api_key = os.getenv("ARK_API_KEY")
        self.base_url = self.base_url.rstrip("/")

    @staticmethod
    def _image_to_data_url(image_path: str) -> str:
        mime, _ = mimetypes.guess_type(image_path)
        if not mime:
            mime = "image/png"
        with open(image_path, "rb") as f:
            b64 = base64.b64encode(f.read()).decode("ascii")
        return f"data:{mime};base64,{b64}"

    def _build_user_prompt(self, question_text: str) -> str:
        # 强调总数量
        return f"{question_text}\n\n回答总数量（格式：数字+对象名）："

    def _build_messages(
        self,
        question_text: str,
        image_paths: list[str],
    ) -> list[dict[str, Any]]:
        # 构建多模态内容
        content: list[dict[str, Any]] = [
            {"type": "text", "text": self._build_user_prompt(question_text)}
        ]

        # 添加图片
        for path in image_paths:
            if os.path.isfile(path):
                content.append({
                    "type": "image_url",
                    "image_url": {
                        "url": self._image_to_data_url(path),
                        "detail": "low"
                    }
                })

        return [
            {"role": "system", "content": self.system_prompt},
            {"role": "user", "content": content}
        ]

    def _build_payload(
        self,
        question_text: str,
        image_paths: list[str],
    ) -> dict:
        return {
            "model": self.model,
            "messages": self._build_messages(question_text, image_paths),
            "reasoning_effort": "minimal",  # 关闭思考，优先速度
            "max_tokens": self.max_tokens,
            "temperature": self.temperature,
            "top_p": self.top_p,
            "stream": False,
        }

    @staticmethod
    def _normalize_answer(text: str) -> str:
        answer = text.strip()
        if not answer:
            return ""
        # 只取第一行
        answer = answer.replace("\r", "\n").split("\n")[0].strip()
        # 清理常见包装
        answer = answer.strip("` ")
        return answer

    def answer_from_text_and_images(
        self,
        question_text: str,
        image_paths: list[str],
        templates_hint: list[QuestionTemplate] | None = None,
    ) -> AnswerResult | None:
        if not self.api_key:
            raise ValueError("Missing API key. Set ARK_API_KEY or pass api_key.")

        payload = self._build_payload(question_text, image_paths)
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")

        req = request.Request(
            url=f"{self.base_url}/chat/completions",
            data=body,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}",
            },
        )

        try:
            with request.urlopen(req, timeout=self.timeout_sec) as resp:
                raw = resp.read().decode("utf-8")
        except Exception:
            return None

        data = json.loads(raw)
        choices = data.get("choices") or []
        if not choices:
            return None

        message = choices[0].get("message", {})
        content = message.get("content", "")
        answer = self._normalize_answer(content)

        if not answer or answer.upper() == "SKIP":
            return None

        return AnswerResult(
            answer=answer,
            confidence=0.7,
            source=f"ai:ark:chat:{self.model}",
            extra={"model": self.model},
        )


@dataclass(slots=True)
class ArkResponsesProvider:
    """
    Volcengine Ark responses API provider (DEPRECATED - use ArkChatProvider instead).

    Install:
        pip install --upgrade "volcengine-python-sdk[ark]"
    """

    api_key: str | None = None
    model: str = "doubao-seed-1-8-251228"
    base_url: str = "https://ark.cn-beijing.volces.com/api/v3"
    system_prompt: str = (
        "你是朋友圈抢答助手。要求：\n"
        "1. 只输出最终答案（格式：数字+性别，如 3女 或 7男）\n"
        "2. 不要解释，不要思考过程，直接给答案\n"
        "3. 如果不是题目或无法判断，输出 SKIP"
    )

    def __post_init__(self) -> None:
        if not self.api_key:
            self.api_key = os.getenv("ARK_API_KEY")
        self.base_url = self.base_url.rstrip("/")

    @staticmethod
    def _image_to_data_url(image_path: str) -> str:
        mime, _ = mimetypes.guess_type(image_path)
        if not mime:
            mime = "image/png"
        with open(image_path, "rb") as f:
            b64 = base64.b64encode(f.read()).decode("ascii")
        return f"data:{mime};base64,{b64}"

    def _build_user_text(self, question_text: str, templates_hint: list[QuestionTemplate] | None) -> str:
        # 简化提示词，避免冗长导致推理变慢
        return f"{self.system_prompt}\n\n题目:\n{question_text}"

    def _build_input(
        self,
        question_text: str,
        image_paths: list[str],
        templates_hint: list[QuestionTemplate] | None = None,
    ) -> list[dict[str, Any]]:
        content: list[dict[str, Any]] = [
            {"type": "input_text", "text": self._build_user_text(question_text, templates_hint)}
        ]
        for path in image_paths:
            if os.path.isfile(path):
                content.append({"type": "input_image", "image_url": self._image_to_data_url(path)})
        return [{"role": "user", "content": content}]

    @staticmethod
    def _extract_from_mapping(data: Any) -> str:
        if not isinstance(data, dict):
            return ""
        output_text = data.get("output_text")
        if isinstance(output_text, str) and output_text.strip():
            return output_text.strip()

        output = data.get("output")
        if isinstance(output, list):
            chunks: list[str] = []
            for item in output:
                if not isinstance(item, dict):
                    continue
                content = item.get("content")
                if isinstance(content, list):
                    for part in content:
                        if not isinstance(part, dict):
                            continue
                        text = part.get("text")
                        if isinstance(text, str) and text.strip():
                            chunks.append(text.strip())
                        output_text2 = part.get("output_text")
                        if isinstance(output_text2, str) and output_text2.strip():
                            chunks.append(output_text2.strip())
            if chunks:
                return "\n".join(chunks).strip()

        choices = data.get("choices")
        if isinstance(choices, list) and choices:
            first = choices[0] if isinstance(choices[0], dict) else {}
            message = first.get("message") if isinstance(first, dict) else {}
            content = message.get("content") if isinstance(message, dict) else None
            if isinstance(content, str) and content.strip():
                return content.strip()
            if isinstance(content, list):
                chunks = []
                for part in content:
                    if isinstance(part, dict) and isinstance(part.get("text"), str):
                        text = part["text"].strip()
                        if text:
                            chunks.append(text)
                if chunks:
                    return "\n".join(chunks).strip()
        return ""

    @staticmethod
    def _extract_response_text(response: Any) -> str:
        if response is None:
            return ""
        for attr in ("output_text", "text"):
            value = getattr(response, attr, None)
            if isinstance(value, str) and value.strip():
                return value.strip()

        mapping: Any = None
        if hasattr(response, "model_dump"):
            try:
                mapping = response.model_dump()
            except Exception:
                mapping = None
        if mapping is None and hasattr(response, "to_dict"):
            try:
                mapping = response.to_dict()
            except Exception:
                mapping = None
        if mapping is None and isinstance(response, dict):
            mapping = response
        if mapping is None:
            mapping = getattr(response, "__dict__", None)
        return ArkResponsesProvider._extract_from_mapping(mapping)

    @staticmethod
    def _normalize_answer(text: str) -> str:
        answer = text.strip()
        if not answer:
            return ""
        answer = answer.replace("\r", "\n").split("\n")[0].strip()
        answer = answer.strip("` ")
        return answer

    def answer_from_text_and_images(
        self,
        question_text: str,
        image_paths: list[str],
        templates_hint: list[QuestionTemplate] | None = None,
    ) -> AnswerResult | None:
        if not self.api_key:
            raise ValueError("Missing API key. Set ARK_API_KEY or pass api_key.")
        try:
            from volcenginesdkarkruntime import Ark
        except ImportError as exc:
            raise RuntimeError(
                "Ark SDK not installed. Run: pip install --upgrade \"volcengine-python-sdk[ark]\""
            ) from exc

        client = Ark(base_url=self.base_url, api_key=self.api_key)

        # 调用 Ark Responses API
        # 注意：thinking/reasoning 参数在当前 SDK 版本中不支持，仅通过优化提示词提升速度
        response = client.responses.create(
            model=self.model,
            input=self._build_input(question_text, image_paths, templates_hint),
        )

        answer = self._normalize_answer(self._extract_response_text(response))
        if not answer or answer.upper() == "SKIP":
            return None
        return AnswerResult(
            answer=answer,
            confidence=0.65,
            source=f"ai:ark:{self.model}",
            extra={"model": self.model},
        )
