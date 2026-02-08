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

---

## 7. 群聊关键词监听并转发（pyweixin 4.1+）

本仓库新增示例脚本：`examples/run_group_keyword_forwarder.py`，用于监听一个或多个会话（群聊或好友）并在关键词命中后转发提醒。

### 7.1 复用的现有 API

1. `Navigator.open_seperate_dialog_window(...)`：打开并复用监听窗口。
2. `Messages.send_messages_to_friend(...)`：发送命中后的提醒消息。
3. `Messages.pull_messages(...)` / `Messages.check_new_messages(...)`：窗口监听不可用时的后备轮询。
4. 脚本保持单线程执行，避免 UI 自动化并发冲突。

### 7.2 配置文件

复制模板：

```powershell
Copy-Item config/group_keyword_forwarder.example.json config/group_keyword_forwarder.json
```

核心字段说明：

1. `target_friend`：提醒接收人（例如“文件传输助手”）。
2. `groups`：监控会话白名单（按会话名称匹配）。
3. `keywords`：关键词列表（按顺序匹配，命中即转发）。
4. `exclude_keywords`：排除词列表（命中则跳过）。
5. `poll_interval_sec`：轮询间隔秒数。
6. `dedupe_ttl_sec`：后备轮询模式的去重 TTL 秒数。
7. `case_sensitive`：是否大小写敏感。
8. `use_regex`：是否按正则匹配关键词与排除词。
9. `send_delay_sec`：发送多条提醒时的单条间隔。
10. `max_send_per_cycle`：单轮最多发送条数。
11. `message_template`：提醒模板，支持 `{group}` `{keyword}` `{time}` `{message}` `{sender}` `{send_time}`。
12. `use_window_listener`：是否启用窗口增量监听模式（推荐 `true`）。
13. `window_minimize`：监听窗口是否最小化。
14. `window_tail_scan_count`：每轮扫描窗口尾部 `ListItem` 数量（默认 80，建议 80~200）。
15. `listener_window_offset_x`：监听窗口横向偏移像素，负数向左，正数向右。
16. `use_direct_poll`：窗口监听不可用时是否启用后备轮询。
17. `pull_count`：后备轮询每轮拉取的消息条数。

### 7.3 运行方式

默认命令（使用 `config/group_keyword_forwarder.json`）：

```powershell
python examples/run_group_keyword_forwarder.py
```

指定配置：

```powershell
python examples/run_group_keyword_forwarder.py --config config/group_keyword_forwarder.json
```

调试与验证选项：

```powershell
# 只打印命中，不实际发送
python examples/run_group_keyword_forwarder.py --dry-run

# 只执行一轮，便于验配置
python examples/run_group_keyword_forwarder.py --once

# 打印窗口监听调试信息（建议排障时开启）
python examples/run_group_keyword_forwarder.py --dry-run --debug
```

### 7.4 行为规则

1. 启动时校验 `target_friend/groups/keywords` 必填；若 `target_friend` 出现在 `groups` 中直接报错退出。
2. 启动后先执行 warmup，跳过历史消息，仅处理后续新增消息。
3. `use_window_listener=true` 时，按窗口新增项增量监听；监听窗口失效时会自动重开并恢复监听。
4. 命中流程：先排除词，再关键词匹配；默认“命中即转发”。
5. 当前实现没有额外“按消息时间区间过滤”，只要是新增且命中就会触发。
6. 窗口监听模式下按消息项键去重；后备轮询模式按 `sha1(group + "|" + message)` + TTL 去重。
7. 消息正文会截断到安全长度（500 字符）再拼模板，避免超长消息影响稳定性。
8. `{sender}`/`{send_time}` 为尽力解析：解析不到时回退“未知发送者/未知时间”。
9. 监听异常与发送异常只影响当前轮，不中断主循环；支持 `Ctrl+C` 优雅退出。

### 7.5 限制与排障

1. 发送人识别依赖 UI 文本可见性与结构；在部分聊天样式中可能稳定回退为“未知发送者”。
2. 若出现“转发后不再监听”，请开启 `--debug` 观察是否触发自动重开日志：`reopened listener window for: ...`。
3. 监听窗口遮挡主界面可调 `listener_window_offset_x`，例如 `-500` 表示向左偏移 500 像素。
4. 若短时间高频消息较多，可提高 `max_send_per_cycle` 并结合 `send_delay_sec` 调整发送节奏。
