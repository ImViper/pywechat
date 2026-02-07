# OCR / AI 测试集与评测指南

## 1. 目标

把你本地抓取过的朋友圈图片整理成可重复评测的数据集，支持：

1. OCR 回归测试（关键词计数是否稳定）
2. AI 回归测试（输出答案是否稳定）
3. OCR 与 AI 耗时对比

---

## 2. 本地测试集目录（自动生成）

默认生成到：

- `local_workspace/testsets/moments_ocr_ai_v1/`

结构：

- `images/`：测试图
- `manifest.jsonl`：样本清单（问题、关键词、期望答案、来源）
- `results/`：评测输出

当前已使用目录 `local_workspace/testsets/moments_ocr_ai_v1/images` 的 4 张图做过实测。

---

## 3. 先构建测试集

```powershell
python examples/build_local_ocr_ai_testset.py
```

脚本会从以下位置收集图片并去重：

1. `rush_moments_cache_feed_*/*/0.png`
2. `rush_moments_cache_test_*/*/0.png`
3. `dataset/test_images/*`
4. `local_workspace/artifacts/*`

其中会自动挑选并标注你当前已验证的“红袖/胡不医”样本。

---

## 4. 跑 OCR 评测

```powershell
python examples/evaluate_local_ocr_ai_testset.py --mode ocr
```

极速配置（推荐，目标秒级）：

```powershell
$env:PADDLE_PDX_DISABLE_MODEL_SOURCE_CHECK='True'
$env:PYWEIXIN_OCR_DET_MODEL='PP-OCRv5_mobile_det'
$env:PYWEIXIN_OCR_REC_MODEL='PP-OCRv5_mobile_rec'
$env:PYWEIXIN_OCR_CPU_THREADS='8'
$env:PYWEIXIN_OCR_MAX_SIDE='560'
$env:PYWEIXIN_OCR_LIMIT_TYPE='max'
python examples/evaluate_local_ocr_ai_testset.py --mode ocr --max-cases 2
```

---

## 5. 跑 AI 评测（需要 ARK_API_KEY）

```powershell
python examples/evaluate_local_ocr_ai_testset.py --mode ai
```

---

## 6. OCR + AI 一起跑

```powershell
python examples/evaluate_local_ocr_ai_testset.py --mode both
```

输出会写到：

- `local_workspace/testsets/moments_ocr_ai_v1/results/benchmark_<timestamp>.json`

---

## 7. 结果怎么看

重点关注：

1. `ocr_correct_rate`：OCR 有标注样本的准确率
2. `ai_correct_rate`：AI 有标注样本的准确率
3. `ocr_avg_ms` / `ai_avg_ms`：平均耗时

本机实测（Intel i9-13900K，2 张已标注样本）：

1. 配置：`PP-OCRv5_mobile_det/rec + max_side=560 + cpu_threads=8`
2. 结果：`ocr_avg_ms ≈ 0.9~1.2s`，`ocr_correct_rate = 1.0`

---

## 8. 注意事项

1. 本测试集位于 `local_workspace`，默认不会被提交到仓库。
2. 如果你新增了新的高价值样本，直接重跑构建脚本即可。
3. 若 OCR 出现版本兼容问题，优先固定 `paddlepaddle==3.2.2` 再测。
