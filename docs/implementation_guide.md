# 朋友圈自动抢答实现说明（当前主版本）

## 1. 目标与范围

本仓库当前围绕两个入口流程：

1. `start_test.py`：监听某个好友主页。
2. `examples/run_feed_refresh_listener.py`：监听总朋友圈（常驻窗口 + 刷新按钮）。

日常推荐优先使用总朋友圈监听模式（刷新更快、链路更短）。

---

## 2. 核心流程（总朋友圈模式）

核心函数：`pyweixin/WeChatAuto.py` `Moments.fetch_and_comment_from_moments_feed(...)`

### 2.1 读取与筛选

1. 复用已打开的朋友圈窗口（可由外部循环传入 `moments_window`）。
2. 可选点击刷新按钮（`Buttons.RefreshButton`）。
3. 在列表中选中第一条有效内容。
4. 解析作者、正文、发布时间、图片数量。
5. 计算指纹（`content + publish_time + image_count`）。
6. 依次执行：作者筛选、关键词筛选、去重（`last_fingerprint`）。

### 2.2 图像提取

1. 命中后在列表页尝试打开图片查看器。
2. 通过右键“复制”提取高清图到本地缓存目录。
3. 缓存目录示例：`rush_moments_cache_feed_<作者>/<作者>_<timestamp>/0.png`

### 2.3 识别与评论

1. 回调 `ai_callback(content, image_paths)` 产出答案（支持 `str` 或 `list[str]`）。
2. 通过 `_comment_flow(..., anchor_mode='list')` 进入评论流程。
3. 调用 `_open_comment_editor(...)`：先点省略号，再点评论按钮。
4. 调用 `_paste_and_send_comment(...)`：粘贴内容并点击发送区域。

---

## 3. 评论点击实现（重点）

### 3.1 点开评论区

不是直接定位“评论区控件”，而是坐标链路：

1. 以内容项 `rectangle()` 为基准。
2. 点击内容项右下角省略号区域。
3. 点出 `CommentButton` 后进入输入框。

### 3.2 发送评论

发送按钮没有稳定控件，主要依赖：

1. 绿色发送按钮像素识别（优先）。
2. 失败后回退到相对偏移点击。

偏移参数通过以下配置覆盖：

- `config/sns_click_offsets.local.json`
- 或环境变量 `PYWEIXIN_SNS_OFFSET_FILE`

---

## 4. OCR + AI 策略

当前建议策略：

1. 先 OCR（本地 PaddleOCR）计数关键词（例如“红袖”“胡不医”）。
2. OCR 命中可直接作为高优先答案。
3. OCR 未命中再调用 AI 兜底。

当前默认速度档：

1. `PP-OCRv5_mobile_det + PP-OCRv5_mobile_rec`
2. `text_det_limit_side_len=1200`（可通过环境变量下调）
3. 在极速参数 `PYWEIXIN_OCR_MAX_SIDE=560` 下，可接近 1 秒级（见测试文档）。

你当前本机环境（Intel CPU）已验证可用 PaddleOCR 路径，详见：`docs/testing_dataset_guide.md`。

---

## 5. 已知风险

1. UI 坐标与分辨率、缩放比例、微信版本相关。
2. `comment_posted=True` 表示流程执行成功，不等于微信端强校验成功。
3. 列表页图片提取失败时，当前策略是本轮跳过，不做详情页兜底。
4. OCR 在某些 Paddle 版本可能有 CPU oneDNN 兼容问题（建议固定版本）。

---

## 6. 关联文档

1. 操作指南：`docs/operation_guide.md`
2. Fork 同步：`docs/fork_sync_guide.md`
3. 测试集与评测：`docs/testing_dataset_guide.md`
