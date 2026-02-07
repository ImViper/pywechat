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

## 3. 运行入口

### 3.1 总朋友圈监听（推荐）

```powershell
python examples/run_feed_refresh_listener.py <发布时间HH:MM> <目标作者> [轮询秒数]
```

示例：

```powershell
python examples/run_feed_refresh_listener.py 19:15 小蔡
python examples/run_feed_refresh_listener.py 19:15 小蔡 0.5
```

### 3.2 好友主页监听（备用）

```powershell
python start_test.py <发布时间HH:MM> [好友备注]
```

示例：

```powershell
python start_test.py 19:15 孙大炮
```

---

## 4. 发送点击校准（重要）

如出现“内容已输入但未发送”，优先校准本地偏移：

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

## 5. 运行产物

1. 总朋友圈缓存：`rush_moments_cache_feed_<作者>/...`
2. 好友模式缓存：`rush_moments_cache_test_<好友>/...`
3. 状态文件：`rush_state_*.json`

这些属于本地运行产物，不建议提交到仓库。

---

## 6. 常见问题

1. OCR 显示未识别到文本：先用 `docs/testing_dataset_guide.md` 的测试集脚本验证 OCR 本身。
2. 评论没发出去：先检查发送点击偏移；必要时先开启调试模式保留窗口观察。
3. 刷新频率能否更快：可以降轮询间隔，但太小会增加 UI 抖动和误点概率。
4. 识别速度慢：启用极速参数后，默认是 OCR 命中即跳过 AI，通常可到约 1 秒级。

---

## 7. 关联文档

1. 实现说明：`docs/implementation_guide.md`
2. 测试集评测：`docs/testing_dataset_guide.md`
3. Fork 同步：`docs/fork_sync_guide.md`
