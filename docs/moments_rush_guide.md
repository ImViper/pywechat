# 朋友圈自动抢答全流程指南

> 更新时间：2026-02-10
> 当前版本说明：评论发送已支持 Hook + UI 混合路径，默认策略为 Hook 优先、失败回退 UI。

## 0. 快速理解（先看这个）

1. 端到端流程图：`docs/hook_flow_overview.md`
2. Hook 架构与接口：`docs/hook_comment_research.md`
3. 当前阶段进度：`docs/hook_progress.md`

当前评论发送通道：

1. `PYWEIXIN_HOOK_ENABLED=1` 时，`moments_ext` 会接入 `CommentDispatcher`（Hook 优先）。
2. Hook 不可用或调用失败时，会自动回退 `comment_flow` UI 自动化。
3. 当前流式路径仍按答案逐条发送；批量并发能力已实现，但主流程尚未默认启用。
4. DLL 侧已支持 `piggyback_comment`（回调期批量执行），最新实测可实现 10/10 成功。

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

5. 关闭 Paddle 模型源检查（避免每次联网探测）：

```powershell
$env:PADDLE_PDX_DISABLE_MODEL_SOURCE_CHECK='True'
```

6. 推荐 OCR 极速参数：

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

唯一推荐入口：`examples/run_feed_refresh_listener.py`

```powershell
python examples/run_feed_refresh_listener.py <发布时间HH:MM> <目标作者> [轮询秒数] [--suffix 性别]
```

示例：

```powershell
python examples/run_feed_refresh_listener.py 19:15 小蔡
python examples/run_feed_refresh_listener.py 19:15 小蔡 0.5
python examples/run_feed_refresh_listener.py 19:15 小蔡 0.5 --suffix 男
```

参数说明：

| 参数 | 说明 |
|------|------|
| `发布时间` | 预计发布时间（HH:MM），脚本会在前2分钟开始监听，后5分钟结束 |
| `目标作者` | 微信好友备注名 |
| `轮询秒数` | 可选，默认 0.5 秒 |
| `--suffix` | 可选，拼车模式后缀。指定后答案自动变为"数字+后缀"（如 `5楚凭阑` → `5男`） |

运行产物：

- 缓存目录：`rush_moments_cache_feed_<作者>/`（含提取的图片）
- 状态文件：`rush_state_feed_<作者>.json`（断点续跑用）

---

## 4. 核心架构：流式 OCR+AI 双评论

### 4.1 全流程时间线

```
帖子出现 (0ms)
    │
    ├─ 轮询命中、解析内容、提取图片
    │
    ├─ 并行启动 ─┬── OCR 关键词计数 (~1.8s)  ─→ 到达即发评论 #1
    │             ├── AI  视觉识别   (~3.1s)  ─→ 到达即发评论 #2
    │             ├── UI 重新定位帖子 (~0.3s, 被覆盖)
    │             └── 预打开评论编辑器 (~0.4s, 被覆盖)
    │
    └─ 第一条评论约 2.7s 内发出（含图片提取）
```

### 4.2 流式消费策略（当前实现）

1. `create_streaming_callback` 启动 OCR 和 AI 两个并发线程。
2. 答案通过 `queue.Queue` 推送，先完成的先入队。
3. 主线程从队列消费，每收到一个答案立即发一条评论。
4. 相同答案自动去重，不同答案各发一条。
5. UI 重新定位（reacquire feed list）与 OCR/AI 并行执行，不额外等待。
6. reacquire 完成后立即预打开评论编辑器，使第一条评论直接粘贴发送。
7. reacquire 时校验作者名，确保评论到正确的帖子。

### 4.3 OCR 关键词提取

OCR 的核心逻辑是从题目中提取关键词，然后在图片 OCR 文本中计数该关键词出现次数。

关键词提取优先级：

1. **引号提取**：题目中用引号括起来的词（支持中文引号 `""` `''` `「」`、英文引号 `""`、方括号 `[]`）
2. **已知关键词匹配**：题目中出现预定义的关键词列表中的词（如角色名）

已知关键词在 `run_feed_refresh_listener.py` 中配置：

```python
known_keywords = [
    "百里辞", "楚凭阑", "晋王", "晏如晦", "从嘉", "方驰",
    "耶律洪", "萧寻", "红袖", "胡不医", "顾知意", "赵岚",
]
```

### 4.4 核心模块

| 模块 | 路径 | 说明 |
|------|------|------|
| 监听入口 | `examples/run_feed_refresh_listener.py` | 主运行脚本 |
| 流式回调 | `pyweixin/rush_callback.py` | `create_streaming_callback` 工厂 |
| OCR/AI 提供者 | `pyweixin/rush_ai.py` | PaddleOCR + ARK Chat 封装 |
| UI 自动化 | `pyweixin/moments_ext.py` | `fetch_and_comment_from_moments_feed` |

---

## 5. 实现细节

### 5.1 总朋友圈监听流程

核心函数：`moments_ext.fetch_and_comment_from_moments_feed(...)`

1. **读取与筛选**：复用已打开的朋友圈窗口，点刷新按钮，选中第一条有效内容，解析作者/正文/时间/图片数，计算指纹去重。
2. **图像提取**：在列表页打开图片查看器，右键复制提取图片到本地缓存。
3. **流式识别**：启动 OCR+AI 并发（`create_streaming_callback`），答案通过队列推送。
4. **并行 UI 定位**：在 OCR/AI 运行的同时，重新获取 feed list 并定位到目标帖子（校验作者名匹配）。
5. **预打开编辑器**：reacquire 完成后立即点开评论编辑器，等待答案到达后直接粘贴。
6. **流式评论**：从队列消费答案，第一条评论跳过编辑器打开步骤直接粘贴发送，后续答案走完整评论流程。

### 5.2 评论点击实现

1. 先将鼠标移到窗口中心（触发帖子悬停，让省略号按钮出现）。
2. 计算省略号坐标：`(item.right - X_OFFSET, item.bottom - Y_OFFSET)`。
3. 点击省略号 → 等待评论按钮出现 → 点击评论按钮。
4. 通过剪贴板粘贴评论内容 → 点击发送区域。

发送偏移参数可通过 `config/sns_click_offsets.local.json` 覆盖：

```powershell
Copy-Item config/sns_click_offsets.example.json config/sns_click_offsets.local.json
```

关键偏移字段：`SNS_ELLIPSIS_X_OFFSET`、`SNS_ELLIPSIS_Y_OFFSET`、`SNS_SEND_LIST_X_OFFSET`、`SNS_SEND_LIST_Y_OFFSET`

---

## 6. 已完成的优化

### 6.1 流式评论（OCR 先行）

- **问题**：之前等 OCR+AI 都完成再发评论，第一条评论要等最慢的 AI (~3s)。
- **方案**：`create_streaming_callback` 通过队列流式推送答案，OCR ~1.8s 出结果后立即发第一条评论，不等 AI。
- **效果**：第一条评论从 ~3.5s 提前到 ~2s。

### 6.2 UI 重定位与识别并行

- **问题**：OCR/AI 回调完成后才开始重新获取 feed list 和定位帖子（~0.5s 串行等待）。
- **方案**：`ai_callback` 启动后，主线程立即开始 reacquire feed list，两者并行执行。
- **效果**：reacquire 时间完全被 OCR/AI 覆盖。

### 6.3 已知关键词直接匹配

- **问题**：OCR 关键词提取只支持引号内的词，题目没用引号时 OCR 不触发。
- **方案**：`try_ocr_count` 新增 `known_keywords` 参数，引号提取失败后在题目中搜索已知角色名。
- **效果**：无论题目格式如何，只要提到已知角色名就能触发 OCR。

### 6.4 修复多余 ESC 关闭窗口

- **问题**：图片查看器在 `finally` 块中已被 ESC 关闭，AI 回调后再按一次 ESC 把朋友圈窗口关了。
- **方案**：去掉多余的 ESC。

### 6.5 修复评论编辑器检测失败

- **问题**：`_paste_and_send_comment` 检测不到评论编辑器元素（`SnsCommentEdit`）就直接 return False。
- **方案**：检测失败时不放弃，继续粘贴和发送（与 `like_posts` 中 `comment()` 行为一致）。

### 6.6 修复省略号点击缺少鼠标预移动

- **问题**：feed refresh 流程调用 `_comment_flow` 没传 `pre_move_coords`，鼠标不在帖子上方，省略号不显示。
- **方案**：传入窗口中心坐标作为 `pre_move_coords`。

### 6.7 评论 UI 交互超时缩减

- **问题**：评论流程各环节等待超时偏保守（打开编辑器 0.6s、粘贴后 0.1s、关闭检测 0.9s），导致单条评论约 2.5s。
- **方案**：全面缩减超时参数：
  - `open_comment_editor`：编辑器等待 0.6s→0.3s，按钮点击后 0.15s→0.05s
  - `paste_and_send_comment`：编辑器检测 0.6s→0.2s，粘贴后 0.1s→0.03s，关闭检测 0.9s→0.4s
  - 图片提取：点击 0.2s→0.08s，菜单等待 0.3s→0.15s，复制等待 0.5s→0.15s
- **效果**：端到端从 ~7.9s 降到 ~4.1s。

### 6.8 评论编辑器预打开

- **问题**：OCR/AI 返回答案后，还要走完整的"点省略号→等评论按钮→点评论→等编辑器"流程才能粘贴。
- **方案**：reacquire 定位完帖子后，在等待 OCR/AI 答案的同时预打开评论编辑器。第一条评论跳过 `open_comment_editor`，直接进入 `paste_and_send_comment`。
- **效果**：端到端从 ~4.1s 降到 ~2.7s。

### 6.9 Reacquire 作者校验

- **问题**：reacquire 遍历 feed list 时只检查 class_name，不验证作者名。如果目标帖子不在第一条，可能误评论到其他人的帖子。
- **方案**：reacquire 循环中增加 `target_author` 匹配检查，跳过不匹配的帖子。
- **效果**：避免评论到错误帖子。

### 6.10 拼车模式（--suffix）

- **问题**：散拼抢车场景要求评论"正确答案+性别"（如 `5男`），而 OCR/AI 返回的是原始答案（如 `5楚凭阑`）。
- **方案**：`create_streaming_callback` 新增 `answer_suffix` 参数。在 `push()` 中提取答案的前导数字，拼接用户指定的后缀。CLI 通过 `--suffix` 参数传入。
- **效果**：`5楚凭阑` 自动变为 `5男`，无需手动改答案。

---

## 7. 后续可优化方向

### 7.1 OCR 模型预热

首次 OCR 调用有模型加载开销。可以在监听启动时做一次空白图片的预热调用。

### 7.2 图片提取提速

当前图片提取通过右键复制 + 剪贴板，每张约 0.2s。可以探索直接从微信缓存目录读取图片文件。

### 7.3 SnsCommentEdit 元素适配

当前评论编辑器检测（`class_name='mmui::XValidatorTextEdit'`）在某些微信版本不匹配。应该抓取当前版本的正确 class_name 更新 `Uielements.py`。

### 7.4 AI 提供者切换

当前使用 ARK（火山引擎），可以按需切换 SiliconFlow 或其他 OpenAI 兼容接口。在 `rush_ai.py` 中已有 `SiliconFlowOpenAIProvider` 实现。

---

## 8. 已知风险

1. UI 坐标与分辨率、缩放比例、微信版本强相关。
2. `comment_posted=True` 表示流程执行完成，不等于微信端强校验成功。
3. 列表页图片提取失败时，当前策略是跳过本轮。
4. OCR 在某些 Paddle 版本可能有 CPU oneDNN 兼容问题。
5. 自动化执行期间不要手动操作微信窗口。

---

## 9. 常见问题

1. **OCR 未识别到文本**：用 `python examples/evaluate_test_cases.py --provider null` 验证 OCR 链路。
2. **评论没发出去**：检查发送偏移（第 5.2 节），用 `--debug` 模式保留窗口观察。
3. **刷新频率能否更快**：可降轮询间隔，但太小会增加 UI 抖动概率。
4. **第一条评论太慢**：检查 OCR 模型是否为 mobile 版本，`PYWEIXIN_OCR_MAX_SIDE` 是否设为 560。

---

## 10. 关联文档

1. 测试集评测：`docs/testing_dataset_guide.md`
2. Fork 同步：`docs/fork_sync_guide.md`
