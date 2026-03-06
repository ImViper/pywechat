# 朋友圈抢答运行指南（现行版）

更新时间：2026-02-24

> 历史调试与过期方案已归档到：`docs/archive/moments_rush_guide_history_2026-02-23.md`

## 1. 目标

本指南只保留当前线上可用、已验证的流程与参数，目标是：
- 首条评论由 `AI` 真实识别结果触发（不再使用预制首答）。
- 后续评论稳定补发。
- 在稳定前提下压缩总耗时。

## 2. 启动方式（当前）

在仓库根目录运行：

```powershell
python 启动抢答.py
```

按提示输入：
- 好友名（如：`小蔡`）
- 预计发圈时间（`HH:MM`）
- 抢答模式（标准抢答 / 拼车数数题）
- 其他选填项可直接回车

脚本实际调用：`examples/run_feed_multi_comment_listener.py`。

## 3. 当前默认参数（以 `config/rush_runtime_env.json` 为准）

现在统一从配置文件加载运行参数：
- 配置文件：`config/rush_runtime_env.json`
- `启动抢答.py` 固定加载 profile：`startup`
- `examples/run_feed_multi_comment_listener.py` 默认加载 profile：`listener`

### 3.1 稳定优先参数
- `PYWEIXIN_HOOK_ENABLED=0`（默认不启用 Hook）
- `PYWEIXIN_HOOK_BATCH_MODE=fast_first_batch`
- `PYWEIXIN_FAST_FIRST_PRE_HOOK=0`
- `PYWEIXIN_ANSWER_MODE=standard`
- `PYWEIXIN_FIRST_ANSWER_MODE=ai_ocr_only`（关闭 NumberGuess/TemplateMatch 首答）
- `PYWEIXIN_DISABLE_OCR=1`（默认纯 AI）
- `PYWEIXIN_FAST_FIRST_DEFER_IMAGES=1`
- `PYWEIXIN_FAST_FIRST_EDITOR_PRELOAD=0`（默认不提前点评论框）
- `PYWEIXIN_FAST_FIRST_COLLECT_TIMEOUT_S=6`
- `PYWEIXIN_FAST_FIRST_FLUSH_EARLY=0`
- `PYWEIXIN_FAST_FIRST_QUICK_CAPTURE=0`
- `PYWEIXIN_FAST_FIRST_POST_FIRST_REMAINING_EARLY=0`

### 3.2 Hook/发送相关
- `PYWEIXIN_FAST_FIRST_SCATTER=0`（默认关闭散弹）
- `PYWEIXIN_UI_SEND_RETRY=1`
- `PYWEIXIN_UI_SEND_RETRY_GAP_MS=120`

### 3.3 AI/OCR 参数
- AI（默认生效）：
  - `PYWEIXIN_AI_PROVIDER=ark`（可切到 `aliyun`）
  - `PYWEIXIN_ARK_MODEL=doubao-seed-1-8-251228`
  - `PYWEIXIN_ARK_IMAGE_DETAIL=high`
  - `PYWEIXIN_ARK_MAX_TOKENS=16`
  - `PYWEIXIN_ARK_TEMPERATURE=0.0`
  - `PYWEIXIN_ARK_TOP_P=0.6`
  - `PYWEIXIN_ARK_TIMEOUT_SEC=8.0`
  - `PYWEIXIN_DASHSCOPE_MODEL=qwen3.5-plus`（当前默认，仅 `PYWEIXIN_AI_PROVIDER=aliyun` 时生效）
  - `PYWEIXIN_DASHSCOPE_ENABLE_THINKING=0`
  - `PYWEIXIN_DASHSCOPE_MAX_TOKENS=32`
  - `PYWEIXIN_DASHSCOPE_TEMPERATURE=0.0`
  - `PYWEIXIN_DASHSCOPE_TOP_P=0.6`
  - `PYWEIXIN_DASHSCOPE_TIMEOUT_SEC=8.0`
  - `PYWEIXIN_AI_IMAGE_OPTIMIZE=1`
  - `PYWEIXIN_AI_IMAGE_MAX_SIDE=1280`
  - `PYWEIXIN_AI_IMAGE_JPEG_QUALITY=90`
  - `PYWEIXIN_AI_IMAGE_OPT_MIN_SIDE=1100`
- OCR（仅在 `PYWEIXIN_DISABLE_OCR=0` 时启用）：
  - `PYWEIXIN_OCR_DET_MODEL=PP-OCRv5_mobile_det`
  - `PYWEIXIN_OCR_REC_MODEL=PP-OCRv5_mobile_rec`
  - `PYWEIXIN_OCR_CPU_THREADS=8`
  - `PYWEIXIN_OCR_MAX_SIDE=560`
  - `PYWEIXIN_OCR_COUNT_MAX=20`（异常大值过滤）

## 4. 现行流程（准确版）

1. 进入监听窗口（发圈前 2 分钟到后 5 分钟）。
2. 发现目标帖后先提图，AI 识别并返回首条答案（不再走预制首答）。
3. 默认仅 `AICommentSource`；如手动开启 OCR，再进入 `OCR+AI` 并行模式。
4. 首条评论优先走 UI 发送（更稳）。
5. 默认走纯 UI 发送；仅在你显式启用 Hook 时才走 Hook batch。

## 4.1 当前阿里默认模型

当前默认通过 DashScope / 百炼 OpenAI 兼容接口使用 `qwen3.5-plus`。

模式切换约定：

- 标准抢答：`PYWEIXIN_ANSWER_MODE=standard`
- 拼车数数题：`PYWEIXIN_ANSWER_MODE=count_suffix`，并配合 `--suffix 男` 这类后缀

- API Key：
  - 环境变量：`DASHSCOPE_API_KEY`
  - 或 `config/.local_env.bat`
  - 或 `config/.local_secrets.json`
- Provider 切换：
  - 设置 `PYWEIXIN_AI_PROVIDER=aliyun`
- 模型：
  - 默认：`PYWEIXIN_DASHSCOPE_MODEL=qwen3.5-plus`
  - 如需固定快照，可改成具体日期后缀版本
  - 备选：`qwen3-vl-plus`、`qwen3-vl-flash`

推荐做法：

- 直接运行示例脚本并传 `--runtime-profile aliyun_qwen3_vl_plus`
- 或一键脚本前设置 `PYWEIXIN_RUNTIME_PROFILE=aliyun_qwen3_vl_plus`
- 或手动把 `startup/listener` profile 中的 `PYWEIXIN_AI_PROVIDER` 改成 `aliyun`

## 5. Hook 当前定位

Hook 目前主要用于“后续批次辅助发送”，不是首条主通道。

- 首条：由 OCR/AI 首个结果触发，仍以 UI 为主。
- 后续：通过 piggyback 减少纯 UI 串行压力。
- 当 Hook 超时或 SEH 时，自动回退 UI，不中断流程。

## 6. 速度解读（避免误判）

日志里两个时间含义不同：

- `AI answer=xxxms`：仅模型推理/返回耗时。
- `AI ready=xxxms`：从回调启动到答案入队的总耗时，包含提图与前置流程。

因此会出现“AI answer 很快，但 AI ready 仍偏慢”。

## 7. 实测基准（真实启动脚本）

目标 `小蔡`、真实 `启动抢答.py`、`first_mode=ai_ocr_only`、纯 AI：

- 样本（2026-02-24 14:20）
  - `PYWEIXIN_DISABLE_OCR=1`
  - `Comment sources: ['AICommentSource']`
  - `[AI] answer=5楚凭阑 (1498ms)`
  - `AI ready: 5楚凭阑 (3492ms)`
  - `streaming done: 5790ms`
  - `Posted comments: 5楚凭阑`

结论：默认已切换为“纯 AI 首答 -> 首条 UI -> 后续 Hook batch（失败回退 UI）”。

## 8. 常见问题

### 8.1 只发出首条
优先检查：
- 微信 UI 自动化是否异常（COM 错误）。
- 是否命中提图慢路径/空图路径（`OCR/AI no result`）。
- `UI_SEND_RETRY` 是否被外部环境覆盖为 0。

### 8.4 打开朋友圈后一直重试、无答案
常见原因是首答模式改成 `ai_ocr_only` 后仍强制“首条后再提图”，会导致队列无答案超时。
当前已修复：`ai_ocr_only` 下不再强制 defer image extraction。

### 8.5 为什么第一轮 `no answer`，第二轮才成功？
常见原因：
- AI 请求超时（日志会有 `AI:ark request failed: TimeoutError`）。
- 目标帖首次抓图耗时偏高，导致本轮窗口内未拿到答案。

处理建议：
- 保持 `PYWEIXIN_ARK_TIMEOUT_SEC=8.0`（当前默认）。
- 保持纯 AI（`PYWEIXIN_DISABLE_OCR=1`）减少不一致来源。

### 8.2 `open moments failed`
通常是微信 UI 状态波动，不是业务逻辑回归。处理方式：
- 确认微信主窗口可操作。
- 必要时重开讲述人与微信后重试。

### 8.3 OCR 出现离谱计数（如 30+）
当前已启用 `PYWEIXIN_OCR_COUNT_MAX=20` 自动丢弃异常 OCR 结果，回退 AI。

## 9. 推荐执行策略

如果目标是“先稳再快”，建议保持本文件参数不变直接跑。

仅在专项压测时再单独开启实验开关（一次只改一个）：
- `PYWEIXIN_FAST_FIRST_POST_FIRST_REMAINING_EARLY=1`（第二条更早，但可能拉长尾部）
- `PYWEIXIN_FAST_FIRST_FLUSH_EARLY=1`（高风险，易触发 UI COM 抖动）

## 10. 当前定位进度（2026-02-24 下午）

本次新增与在测项：
- 已实现：首答模式 `PYWEIXIN_FIRST_ANSWER_MODE=ai_ocr_only`，禁用 TemplateMatch/NumberGuess 首发。
- 已实现：`ai_ocr_only` 下关闭首条强制 defer 提图，避免“打开朋友圈后无答案反复重试”。
- 已实现：`PYWEIXIN_DISABLE_OCR` 开关；默认 `startup` 配置启用纯 AI。
- 已实现：默认关闭首条 editor preload（`PYWEIXIN_FAST_FIRST_EDITOR_PRELOAD=0`），降低 UI 竞态。
- 已实现：启动脚本与监听脚本均打印关键生效参数，便于排查“配置未生效”问题。
- 保留 profile：
  - `ai_first_pro`：模型对比（pro）
  - `ai_first_lite`：模型对比（lite）

---

如需回看历史问题定位、失败链路、过期方案，请查看归档文档：
`docs/archive/moments_rush_guide_history_2026-02-23.md`
