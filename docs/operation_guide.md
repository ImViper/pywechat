# 朋友圈自动抢答操作指南（当前推荐）

## 1. 环境准备

1. Windows + PC 微信已登录。
2. 项目目录：`H:\Code\pywechat`
3. 激活虚拟环境：

```powershell
cd H:\Code\pywechat
.\.venv\Scripts\Activate.ps1
```

4. 安装依赖：

```powershell
python -m pip install -r requirements.txt
python -m pip install -U paddleocr paddlepaddle
```

5. 建议关闭 Paddle 模型源检查（避免每次联网探测）：

```powershell
$env:PADDLE_PDX_DISABLE_MODEL_SOURCE_CHECK='True'
```

6. 推荐 OCR 极速参数（秒级优先）：

```powershell
$env:PYWEIXIN_OCR_DET_MODEL='PP-OCRv5_mobile_det'
$env:PYWEIXIN_OCR_REC_MODEL='PP-OCRv5_mobile_rec'
$env:PYWEIXIN_OCR_CPU_THREADS='8'
$env:PYWEIXIN_OCR_MAX_SIDE='560'
$env:PYWEIXIN_OCR_LIMIT_TYPE='max'
```

---

## 2. 配置 API Key

文件：`config/.local_secrets.json`

```json
{
  "ARK_API_KEY": "你的ARK_API_KEY"
}
```

---

## 3. 核心架构：并发 OCR+AI 双评论

### 3.1 工作流程

```
收到新动态
    │
    ├── 并发启动 ──┬── OCR 文字计数（约1.5-2秒）
    │              └── AI  视觉识别（约1.2-1.7秒）
    │
    └── 结果处理：
        ├── 两者相同 → 评论1次
        └── 两者不同 → 评论2次（你手动删错的那个）
```

### 3.2 核心模块

| 模块 | 路径 | 说明 |
|------|------|------|
| `rush_callback` | `pyweixin/rush_callback.py` | 并发回调工厂函数 |
| `rush_ai` | `pyweixin/rush_ai.py` | OCR/AI 提供者实现 |
| 监听入口 | `examples/run_feed_refresh_listener.py` | 主运行脚本 |

### 3.3 双评论策略

- **OCR**：快速精准，适合有明确关键词的题目（如"楚凭阑"出现几次）
- **AI**：通用强，适合复杂题目（如数学题、无明确关键词）
- **双评论**：当 OCR 和 AI 答案不一致时，两个都评论，你手动删掉错误的

---

## 4. 运行入口

### 4.1 总朋友圈监听（推荐）

```powershell
python examples/run_feed_refresh_listener.py <发布时间HH:MM> <目标作者> [轮询秒数]
```

示例：

```powershell
python examples/run_feed_refresh_listener.py 19:15 小蔡
python examples/run_feed_refresh_listener.py 19:15 小蔡 0.5
```

### 4.2 抓取某个好友朋友圈并按关键词筛选

```powershell
# 标准模式（输出到 dataset/moments_questions_<好友>_<时间戳>）
python examples/collect_friend_moments_questions.py --friend 小蔡 --number 200 --include 小杜

# 详细日志模式（建议排障时使用）
python examples/collect_friend_moments_questions_verbose.py --friend 小蔡 --number 200 --include 小杜 --exclude 测试

# "全部"模式：用大上限抓取（默认5000，可调）
python examples/collect_friend_moments_questions.py --friend 小蔡 --all --all-number 8000 --include 小杜

# 仅导出结构化结果，不保存详情图片/文本
python examples/collect_friend_moments_questions.py --friend 小蔡 --number 200 --include 小杜 --no-save-detail
```

输出文件：

1. `all_posts.json`：本轮抓取到的全部朋友圈内容。
2. `question_candidates.json`：关键词/正则命中的候选内容。
3. `question_candidates.md`：可读报告。

---

## 5. 发送点击校准（重要）

如出现"内容已输入但未发送"，优先校准本地偏移：

1. 复制模板：

```powershell
Copy-Item config/sns_click_offsets.example.json config/sns_click_offsets.local.json
```

2. 修改：

- `SNS_ELLIPSIS_X_OFFSET`
- `SNS_ELLIPSIS_Y_OFFSET`
- `SNS_SEND_LIST_X_OFFSET`
- `SNS_SEND_LIST_Y_OFFSET`

3. 重跑监听脚本观察。

---

## 6. 运行产物

1. 总朋友圈缓存：`rush_moments_cache_feed_<作者>/...`
2. 状态文件：`rush_state_*.json`

这些属于本地运行产物，不建议提交到仓库。

---

## 7. 常见问题

1. **OCR 显示未识别到文本**：先用 `python examples/evaluate_test_cases.py --provider null` 验证 OCR 链路。
2. **评论没发出去**：先检查发送点击偏移；必要时先开启调试模式保留窗口观察。
3. **刷新频率能否更快**：可以降轮询间隔，但太小会增加 UI 抖动和误点概率。
4. **识别速度慢**：并发模式下，OCR 和 AI 同时运行，总耗时约等于最慢的那个（通常 1.5-2 秒）。

---

## 8. 关联文档

1. 实现说明：`docs/implementation_guide.md`
2. 测试集评测：`docs/testing_dataset_guide.md`
3. Fork 同步：`docs/fork_sync_guide.md`
4. 群关键词转发操作：`docs/group_keyword_forwarder_guide.md`
5. 好友朋友圈保存说明：`docs/moments_dump_guide.md`
