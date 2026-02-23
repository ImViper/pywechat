# 朋友圈抢答运行指南（现行版）

更新时间：2026-02-24

> 历史调试与过期方案已归档到：`docs/archive/moments_rush_guide_history_2026-02-23.md`

## 1. 目标

本指南只保留当前线上可用、已验证的流程与参数，目标是：
- 首条评论由 `OCR/AI` 真实识别结果触发（不再使用预制首答）。
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
- 其他选填项可直接回车

脚本实际调用：`examples/run_feed_multi_comment_listener.py`。

## 3. 当前默认参数（以 `config/rush_runtime_env.json` 为准）

现在统一从配置文件加载运行参数：
- 配置文件：`config/rush_runtime_env.json`
- `启动抢答.py` 固定加载 profile：`startup`
- `examples/run_feed_multi_comment_listener.py` 默认加载 profile：`listener`

### 3.1 稳定优先参数
- `PYWEIXIN_HOOK_BATCH_MODE=fast_first_batch`
- `PYWEIXIN_FAST_FIRST_PRE_HOOK=0`
- `PYWEIXIN_FIRST_ANSWER_MODE=ai_ocr_only`（关闭 NumberGuess/TemplateMatch 首答）
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

### 3.3 OCR/AI 参数
- OCR：
  - `PYWEIXIN_OCR_DET_MODEL=PP-OCRv5_mobile_det`
  - `PYWEIXIN_OCR_REC_MODEL=PP-OCRv5_mobile_rec`
  - `PYWEIXIN_OCR_CPU_THREADS=8`
  - `PYWEIXIN_OCR_MAX_SIDE=560`
  - `PYWEIXIN_OCR_COUNT_MAX=20`（异常大值过滤）
- AI 图像优化：
  - `PYWEIXIN_AI_IMAGE_OPTIMIZE=1`
  - `PYWEIXIN_AI_IMAGE_MAX_SIDE=960`
  - `PYWEIXIN_AI_IMAGE_JPEG_QUALITY=84`
  - `PYWEIXIN_AI_IMAGE_OPT_MIN_SIDE=1100`
- Ark：
  - `PYWEIXIN_ARK_MAX_TOKENS=16`
  - `PYWEIXIN_ARK_TEMPERATURE=0.0`
  - `PYWEIXIN_ARK_TOP_P=0.6`
  - `PYWEIXIN_ARK_TIMEOUT_SEC=4.5`

## 4. 现行流程（准确版）

1. 进入监听窗口（发圈前 2 分钟到后 5 分钟）。
2. 发现目标帖后先提图，OCR 与 AI 并行识别（不再走预制首答）。
3. `OCR/AI` 谁先返回，谁作为首条答案。
4. 首条评论优先走 UI 发送（更稳）。
5. 后续答案走 Hook batch（piggyback）；Hook 不可用时自动回退 UI。

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

目标 `小蔡`、真实监听脚本、`first_mode=ai_ocr_only`：

- 样本（2026-02-24 03:33）
  - `Comment sources: ['OCRCommentSource', 'AICommentSource']`
  - `OCR ready: 3红袖 (2539ms)`（首答）
  - `AI ready: 7红袖 (4316ms)`（后续）
  - `streaming done: 7800ms`
  - `Posted comments: ['3红袖', '7红袖']`

结论：已实现“等待 OCR/AI 首答 -> 首条 UI -> 后续 Hook batch（失败回退 UI）”。

## 8. 常见问题

### 8.1 只发出首条
优先检查：
- 微信 UI 自动化是否异常（COM 错误）。
- 是否命中提图慢路径/空图路径（`OCR/AI no result`）。
- `UI_SEND_RETRY` 是否被外部环境覆盖为 0。

### 8.4 打开朋友圈后一直重试、无答案
常见原因是首答模式改成 `ai_ocr_only` 后仍强制“首条后再提图”，会导致队列无答案超时。
当前已修复：`ai_ocr_only` 下不再强制 defer image extraction。

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

## 10. 当前定位进度（2026-02-24 凌晨）

本次新增与在测项：
- 已实现：首答模式 `PYWEIXIN_FIRST_ANSWER_MODE=ai_ocr_only`，禁用 TemplateMatch/NumberGuess 首发。
- 已实现：`ai_ocr_only` 下关闭首条强制 defer 提图，避免“打开朋友圈后无答案反复重试”。
- 已实现：默认关闭首条 editor preload（`PYWEIXIN_FAST_FIRST_EDITOR_PRELOAD=0`），降低 UI 竞态。
- 保留 profile：
  - `ai_first_pro`：模型对比（pro）
  - `ai_first_lite`：模型对比（lite）

---

如需回看历史问题定位、失败链路、过期方案，请查看归档文档：
`docs/archive/moments_rush_guide_history_2026-02-23.md`
