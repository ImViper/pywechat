# 统一测评指南（唯一入口）

本仓库现在只保留一种测评方式：

- 命令：`python examples/evaluate_test_cases.py`
- 数据集：`dataset/test_cases.json`
- 评测链路：`resolve_answer`（与代码实现一致）

> 旧脚本 `examples/evaluate_local_ocr_ai_testset.py` 和 `examples/evaluate_ark_accuracy.py` 已降级为历史入口，不再作为标准评测方案。

## 1. 前置准备

1. 激活虚拟环境并安装依赖。
2. 如需 AI 评测，准备 `ARK_API_KEY` 或 `SILICONFLOW_API_KEY`。
3. 如需 OCR 评测，确保本地可用 PaddleOCR。

推荐 OCR 速度参数：

```powershell
$env:PADDLE_PDX_DISABLE_MODEL_SOURCE_CHECK='True'
$env:PYWEIXIN_OCR_DET_MODEL='PP-OCRv5_mobile_det'
$env:PYWEIXIN_OCR_REC_MODEL='PP-OCRv5_mobile_rec'
$env:PYWEIXIN_OCR_CPU_THREADS='8'
$env:PYWEIXIN_OCR_MAX_SIDE='560'
$env:PYWEIXIN_OCR_LIMIT_TYPE='max'
```

## 2. 数据集维护

统一维护文件：`dataset/test_cases.json`

字段和判定规则详见：`dataset/README_test_cases.md`

你后续新增测评内容时，只需要新增 case；脚本和规则不需要改。

## 3. 运行评测

基础命令：

```powershell
python examples/evaluate_test_cases.py
```

常用命令：

```powershell
# 按标签回归
python examples/evaluate_test_cases.py --tag count

# 只跑指定 case
python examples/evaluate_test_cases.py --case-id count_001 --case-id count_002

# 控制样本量
python examples/evaluate_test_cases.py --max-cases 20

# 禁用 AI（仅 template+OCR+default）
python examples/evaluate_test_cases.py --provider null

# 禁用 OCR（仅 template+AI+default）
python examples/evaluate_test_cases.py --ocr null

# 覆盖 AI 参数并指定输出
python examples/evaluate_test_cases.py --ai-timeout 1500 --output dataset/results/latest_eval.json
```

## 4. 输出与指标

默认输出：`dataset/results/evaluation_<timestamp>.json`

核心指标：

1. `answer_rate`：答题覆盖率
2. `accuracy`：有标注样本准确率
3. `method_counts`：template / ai / default / none / error
4. `latency_ms`：avg / p50 / p95 / max

## 5. 规则冻结

为了保证可比性，统一规则固定如下：

1. 只允许使用 `examples/evaluate_test_cases.py` 作为官方评测入口。
2. 正确性判定默认严格字符串匹配（`strip()` 后比对）。
3. `SKIP` 表示该用例应无答案。
4. 未标注标准答案的 case 不计入准确率分母。
