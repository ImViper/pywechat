# 朋友圈抢答运行指南（现行版）

更新时间：2026-02-23

> 历史调试与过期方案已归档到：`docs/archive/moments_rush_guide_history_2026-02-23.md`

## 1. 目标

本指南只保留当前线上可用、已验证的流程与参数，目标是：
- 首条评论尽快发出。
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

## 3. 当前默认参数（以 `启动抢答.py` 为准）

### 3.1 稳定优先参数
- `PYWEIXIN_HOOK_BATCH_MODE=fast_first_batch`
- `PYWEIXIN_FAST_FIRST_PRE_HOOK=0`
- `PYWEIXIN_FAST_FIRST_DEFER_IMAGES=1`
- `PYWEIXIN_FAST_FIRST_EDITOR_PRELOAD=0`
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
2. 发现目标帖后，TemplateMatch 先给首条答案（通常 `4红袖`）。
3. 首条评论走 UI 发送（最快、最稳）。
4. 首条发出后再做图片提取（deferred extraction）。
5. OCR 与 AI 并行识别：
   - OCR 常先返回；
   - AI 作为并行精确补充。
6. 后续答案按 batch 发送（默认 piggyback 路径，非全 UI）。

## 5. Hook 当前定位

Hook 目前主要用于“后续批次辅助发送”，不是首条主通道。

- 首条：仍以 UI 为主（更稳）。
- 后续：通过 piggyback 减少纯 UI 串行压力。
- 直接 Hook 单发（capture_thread/pipe_thread）仍可能超时或 SEH，故默认不依赖散弹。

## 6. 速度解读（避免误判）

日志里两个时间含义不同：

- `AI answer=xxxms`：仅模型推理/返回耗时。
- `AI ready=xxxms`：从回调启动到答案入队的总耗时，包含提图与前置流程。

因此会出现“AI answer 很快，但 AI ready 仍偏慢”。

## 7. 实测基准（真实启动脚本）

目标 `小蔡`、真实 `启动抢答.py`、非 warmup：

- 稳定样本（当前默认）
  - `AI ready ≈ 5996ms`
  - `streaming done ≈ 9447ms`
  - `Posted comments: ['4红袖','3红袖','7红袖']`

- 对照样本（旧参数）
  - `AI ready ≈ 6283ms`
  - `streaming done ≈ 9682ms`

结论：当前默认是“稳定前提下的小幅提速”配置。

## 8. 常见问题

### 8.1 只发出首条
优先检查：
- 微信 UI 自动化是否异常（COM 错误）。
- 是否命中提图慢路径/空图路径。
- `UI_SEND_RETRY` 是否被外部环境覆盖为 0。

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

---

如需回看历史问题定位、失败链路、过期方案，请查看归档文档：
`docs/archive/moments_rush_guide_history_2026-02-23.md`
