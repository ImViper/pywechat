# 朋友圈自动抢答全流程指南

> 更新时间：2026-02-23
> 当前版本说明：评论发送已支持 Hook + UI 混合路径，默认策略为 Hook 优先、失败回退 UI。支持 DeferredImagePaths 延迟图片提取。

## 0. 快速理解（先看这个）

1. 端到端流程图：`docs/overall_flowchart.md`
2. 多评论队列监听器：`docs/multi_comment_listener_guide.md`

当前评论发送通道：

1. `PYWEIXIN_HOOK_ENABLED=1` 时，`moments_ext` 会接入 `CommentDispatcher`（Hook 优先）。
2. Hook 不可用或调用失败时，会自动回退 `comment_flow` UI 自动化。
3. 支持 **DeferredImagePaths** 机制：回调函数先启动，图片提取完成后 set() 生效，OCR/AI 立即处理。
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

推荐入口（基础单评论）：`examples/run_feed_refresh_listener.py`

多评论监听（fast_first_batch）：`examples/run_feed_multi_comment_listener.py`（详见 `docs/multi_comment_listener_guide.md`）

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

### 6.11 延迟图片提取（DeferredImagePaths）

- **问题**：TemplateMatch 在 0ms 内命中答案，但图片提取需要 ~1s，导致第一条评论被图片提取阻塞。
- **方案**：当 TemplateMatch 有即时答案且 Hook 不可用时，跳过图片提取，先通过 UI 发出第一条评论，发完后再提取图片给 OCR/AI。
- **实现**：`_defer_image_extraction` 标志位控制。第一条评论发出后在 streaming loop 内执行图片提取，`_deferred_images.set(paths)` 唤醒 OCR/AI 线程。
- **效果**：第一条评论从 ~2s（含图片提取）提前到 ~0.4s（仅 reacquire + UI 发送）。

### 6.12 Hook Capture 过期自动降级 + capture_thread 重试

- **问题 1**：Hook DLL 的 capture context 只在 UI 评论时刷新。长时间无 UI 操作后 context 过期，`capture_thread` 模式超时（400ms），`pipe_thread` 模式 SEH crash。
- **问题 2**：即使 capture 刚刷新（245ms），`capture_thread` 模式仍然不可靠 — 微信 UI 线程不一定能在 400ms 内处理排队任务。
- **方案**：
  1. `send_comment()` 检测 `capture_age_ms > 10s` 时直接用 `pipe_thread`（跳过 400ms 超时等待）
  2. `capture_thread` 失败时自动重试 `pipe_thread`（fresh capture 下 `pipe_thread` 大概率成功）
  3. streaming loop 入口检测 capture 是否 fresh，stale 时走 UI 路径避免误入 `fast_first_batch`
- **关键**：第一条 UI 评论会触发 hook callback 刷新 capture，之后重新检查并启用 Hook。

### 6.13 Hook Pipe 连接复用

- **问题**：DLL pipe server 是单线程阻塞的（`pipe_server.cpp:run()`），一次只能处理一个客户端。pre-image 阶段的 dispatcher 占着连接，streaming loop 重建 dispatcher 连不上。
- **方案**：streaming loop 复用 pre-image 阶段的 `_hook_dispatcher`，不重新创建 `CommentDispatcher`。

### 6.14 OCR 转义引号修复

- **问题**：Windows UI Automation 返回的文本含转义引号 `\"红袖\"`，OCR 关键词提取正则匹配到 `红袖\`（多了反斜杠），导致图片文本匹配失败。
- **方案**：`try_ocr_count()` 入口处预处理 `content.replace('\\"', '"')`。

---

## 6.A Hook DLL 工作原理与故障排查

### 工作原理

```
注入 DLL → hook 微信评论函数 → 等待 UI 评论触发 capture
                                        ↓
                              捕获 vtable/arg1/arg2/arg3/线程ID
                                        ↓
                              后续 Hook 调用复用 captured state
```

1. **注入**：`hook_injector.inject_dll(pid, dll_path)` 将 DLL 注入微信进程
2. **Hook 安装**：DLL 启动后 hook 微信的 `SnsCommentSubmit` 函数
3. **Capture**：当用户通过 UI 发评论时，hook callback 捕获函数参数（vtable、arg1/2/3、TLS 等）
4. **复用**：后续 Hook 调用用 captured state 构造参数，直接调用原始函数

### 两种执行模式

| 模式 | 说明 | 优点 | 缺点 |
|------|------|------|------|
| `capture_thread` | 把任务排队到微信 UI 线程执行 | 线程安全，TLS 正确 | 需要 UI 线程活跃，idle 时超时 |
| `pipe_thread` | 在 pipe server 线程直接调用 | 不依赖 UI 线程 | 跨线程调用，stale context 可能 SEH crash |

Python 默认 `capture_thread`（`PYWEIXIN_HOOK_EXECUTION_MODE`），DLL 默认 `pipe_thread`。

### Capture 过期问题

Capture context 只在 UI 评论时刷新。状态检查：

```python
from pyweixin.hook_bridge import HookBridge
b = HookBridge(); b.connect()
st = b.status()
print(f"capture_age_ms={st.data['capture_age_ms']}, fresh={st.data['context_fresh']}")
```

- `capture_age_ms < 2000`：fresh，两种模式都能用
- `capture_age_ms < 10000`：较新，`pipe_thread` 大概率成功
- `capture_age_ms > 10000`：stale，两种模式都可能失败

**解决方案**：第一条评论走 UI 刷新 capture，后续评论走 Hook。代码已自动处理。

### 常见故障

| 日志 | 原因 | 解决 |
|------|------|------|
| `hook enabled but DLL not connected` | pipe 连接失败（被占用或 DLL 未注入） | 检查 DLL 是否注入，确保不重复创建 dispatcher |
| `capture context stale (Xms)` | 长时间无 UI 评论，context 过期 | 自动降级到 `pipe_thread`，第一条 UI 评论后 Hook 恢复 |
| `SEH exception in sns_do_comment` | captured state 内存指针失效 | context 过期导致，需 UI 评论刷新 capture |
| `capture-thread execution timeout` | UI 线程未在 400ms 内处理任务 | 自动重试 `pipe_thread`，fresh capture 下大概率成功 |
| `capture_thread_id is 0` | DLL 注入后从未有 UI 评论 | 需要至少一次 UI 评论触发 capture |

### 实测时间线（2026-02-23，capture 过期场景）

```
T+0ms     TemplateMatch 命中 "4红袖"
T+0ms     Hook capture_thread stale → pipe_thread SEH → 走 defer 路径
T+356ms   Reacquire 完成，UI 路径就绪
T+~500ms  第一条评论 "4红袖" 通过 UI 发出
T+~500ms  Hook capture 刷新 (capture_age=245ms)，Hook 重新启用
T+~500ms  延迟图片提取开始
T+~1800ms 图片提取完成，OCR/AI 被唤醒
T+5139ms  OCR 出结果 "3红袖"
T+5139ms  Hook capture_thread 超时 → pipe_thread 重试（预期成功）
T+6150ms  AI 出结果 "7红袖"
T+10741ms 全部 3 条评论发出
```

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

---

## 11. 2026-02-23 实测更新（代码改动总结）

### 结论

- `capture_thread` 仍可能在 fresh capture 下超时。
- 超时后已能稳定触发 `pipe_thread` 重试日志：`capture_thread failed, retrying pipe_thread`。
- 但 `pipe_thread` direct-call 目前仍失败：`SEH exception in sns_do_comment`。
- 稳定可用路径是：`UI 首条 + piggyback 后续`（批量 3/3 可通过）。

### 已落地修复

1. `pyweixin/comment_dispatcher.py`
- `capture_thread` 失败后自动重试 `pipe_thread`。
- `piggyback -> parallel` 自动升级改为显式开关：
  - 仅当 `PYWEIXIN_HOOK_AUTO_UPGRADE_PARALLEL=1` 时启用。
  - 默认关闭，优先稳定性。

2. `pyweixin/moments_ext.py`
- reacquire 后重新绑定 dispatcher 的 UI sender。
- `fast_first_batch` 下即使 capture stale 也保留 Hook 入口（保证“首条 UI + 后续 piggyback”可走通）。

3. `hook/src/sns_comment.cpp` + `hook/src/sns_comment.h` + `hook/src/pipe_server.cpp`
- direct-call 新增诊断字段与响应透出：
  - `arg1_ctx_written`
  - `direct_ctx_available`
  - `direct_tls_override_enabled`
- 实测上述字段可为 `true`，但 direct-call 仍在 `0x3c5c70` 崩溃链路失败。

### 最新验收

- 通过（稳定链路）：
  - `local_workspace/acceptance_reports/hook_e2e_20260223_041317.json`
  - 结果：`3/3`，方法为 `ui + piggyback`
- 未通过（direct-call）：
  - `local_workspace/acceptance_reports/hook_e2e_20260223_041345.json`
  - 结果：`capture_thread timeout -> pipe_thread fail`

### 当前建议

- 生产执行优先使用 `fast_first_batch`（本质 UI 首条 + piggyback 后续）。
- direct-call 继续作为实验路径，不作为稳定主路径。

---

## 12. 2026-02-23 当前流程与修复记录（真实启动脚本）

### 12.1 当前实际流程（`启动抢答.py` -> `run_feed_multi_comment_listener.py`）

当前默认使用 `PYWEIXIN_HOOK_BATCH_MODE=fast_first_batch`，实际链路为：

1. 先等待首条答案（通常 TemplateMatch 命中）。
2. 首条评论优先发出（Hook stale 时会退 UI）。
3. 首条发出后再做 deferred 图片提取。
4. OCR/AI 基于提取图片继续产出后续答案。
5. 后续答案走 batch（`post_batch_comments`，默认 piggyback serial）。

当“后续答案=2条”时，实际会是：
- 第2条作为 piggyback bootstrap 走 UI；
- 第3条走 Hook（piggyback 结果）。

这也是观测到 `4红袖(ui) + 3红袖(ui) + 7红袖(hook)` 的原因。

### 12.2 本轮已修复问题

1. `capture_thread` 超时自动重试 `pipe_thread`（已生效）。
- 关键日志：`capture_thread failed (...), retrying pipe_thread`

2. 禁止默认自动升级 `piggyback -> parallel`（避免并行不稳定导致整批失败）。
- 仅当 `PYWEIXIN_HOOK_AUTO_UPGRADE_PARALLEL=1` 时升级。

3. 修复 `fast_first_batch` 分支漏掉 deferred 图片提取的问题。
- 之前会导致 OCR/AI 可能长期拿不到图片，只发首条。
- 修复后：首条发出后立即提图，OCR/AI可继续产出后续答案。

4. 默认关闭多源 dedup，避免 OCR/AI 与模板答案被去重吞掉。
- 新行为：`PYWEIXIN_MULTI_SOURCE_DEDUP` 默认 `0`。

5. 修复 UI 发送锚点失效（`anchor rect = 0,0,0,0`）导致“没点到发送”。
- 新行为：锚点无效时不再坐标点击，直接 fallback `Enter` 发送。
- 同时在 batch 前刷新 UI sender 锚点，降低失效概率。

### 12.3 最新真实脚本验证（非 acceptance）

使用根目录 `启动抢答.py` 实跑（目标 `小蔡`，默认配置）：
- 结果：`Posted comments: ['4红袖', '3红袖', '7红袖']`
- 总耗时：约 `10255ms`

说明：
- 10s 主要耗时来自“首条后提图 + OCR/AI产出等待”；
- 之前 30s+ 的慢路径与锚点失效/ piggyback 超时有关，本轮已修复锚点失效问题。

---

## 13. 2026-02-23 性能收敛与稳定性补充（真实启动脚本）

### 13.1 当前默认策略（稳定优先）

`启动抢答.py` 默认参数：

- `PYWEIXIN_FAST_FIRST_PRE_HOOK=0`（关闭 fast_first 首条前 Hook 探测，减少首条抖动）
- `PYWEIXIN_FAST_FIRST_DEFER_IMAGES=1`（首条后再提图）
- `PYWEIXIN_FAST_FIRST_EDITOR_PRELOAD=0`（关闭异步预开编辑器，避免“框没起就继续”）
- `PYWEIXIN_FAST_FIRST_COLLECT_TIMEOUT_S=8`（后续答案收集窗口）
- `PYWEIXIN_AI_IMAGE_OPTIMIZE=1`（仅 AI 图像优化，OCR 仍用原图）

### 13.2 本轮新增修复

1. 首条评论改为 fast_first 默认 UI 直发，Hook 仅做一次失败兜底（不再“先 Hook 试错再 UI”）。
2. 首条失败不会丢失：失败答案会回灌到 batch 队列重发。
3. deferred 提图失败时新增 fallback 截图，避免 OCR/AI因空图直接失效。
4. 日志预览长度由 60 提升到 120，便于排查“只看到半条内容”。
5. AI 图像优化路径改为模块级预加载 Pillow，避免首次调用导入抖动。

### 13.3 真实脚本连续实测（`启动抢答.py`, 目标 `小蔡`）

稳定样本：

- `local_workspace/startup_perf_batch_20260223_112607_r1.log`：`10223ms`，`['4红袖','3红袖','7红袖']`
- `local_workspace/startup_perf_batch_20260223_112626_r2.log`：`9520ms`，`['4红袖','3红袖','7红袖']`
- `local_workspace/startup_perf_batch_20260223_112646_r3.log`：`9999ms`，`['4红袖','3红袖','7红袖']`
- `local_workspace/startup_perf_final_20260223_113605.log`：`9343ms`，`['4红袖','3红袖','7红袖']`
- `local_workspace/startup_perf_fallbackfix_20260223_113903.log`：`9501ms`，`['4红袖','3红袖','7红袖']`

说明：

- 体感“两条几乎同时发”是 piggyback 正常行为（第2条 UI bootstrap + 第3条 Hook drain）。
- 少数轮次仍可能受 UIA COMError 影响，现已加提图 fallback 降低“只发一条”的概率。

### 13.4 关于“不开首发只等 AI”耗时

按最近真实数据，`AI ready` 常见在 `~6s-8s`；再加发送动作约 `0.4s-0.8s`。
因此如果不首发，首条评论通常会晚到 `~6.5s-8.8s`。

## 14. 2026-02-23 新一轮性能/稳定性复盘（实时回归）
### 14.1 本轮落地改动
1. `pyweixin/moments_ext.py`
- 初始帖子选择改为“扫描前 15 条并按 author/keyword/fingerprint 过滤后再选中”，不再只看第一条。
- `fast_first_batch` 增加增量发送能力（`PYWEIXIN_FAST_FIRST_FLUSH_EARLY`），但默认关闭，避免 UI COM 抖动。
- deferred 提图在“提图成功但 0 张”时新增 fallback 截图，避免 OCR/AI 因空图直接失效。
- `quick capture` 保留开关，但默认关闭（`PYWEIXIN_FAST_FIRST_QUICK_CAPTURE=0`）。
2. `启动抢答.py`
- 默认改为稳定优先：
  - `PYWEIXIN_FAST_FIRST_FLUSH_EARLY=0`
  - `PYWEIXIN_FAST_FIRST_QUICK_CAPTURE=0`

### 14.2 关键实测结论
1. 增量发送（`flush_early=1`）在当前微信 UI 状态下会触发 COM 级异常，出现只发首条：
- `local_workspace/startup_perf_opt_oneshot_20260223_121400_fastfirst.log`
- 现已改为默认关闭。
2. `quick capture` 在部分轮次可显著提速，但波动大：
- 有成功样本，也有 OCR 空文本/误判样本（例如 `14红袖`）。
- 因稳定性风险，默认关闭，仅保留为实验开关。
3. 稳定成功样本（3 条评论）
- `local_workspace/startup_perf_opt_oneshot_20260223_121618_fastfirst_scan.log`
- 结果：`['4红袖','3红袖','7红袖']`，`streaming done: 11105ms`。
4. 检测慢问题已定位并修复一部分
- 以前“只检查第一条”，现在“首屏多条扫描 + 过滤”后再选中目标，能跳过第一条无关内容。

### 14.3 当前建议配置（稳定优先）
- `PYWEIXIN_HOOK_BATCH_MODE=fast_first_batch`
- `PYWEIXIN_FAST_FIRST_PRE_HOOK=0`
- `PYWEIXIN_FAST_FIRST_DEFER_IMAGES=1`
- `PYWEIXIN_FAST_FIRST_EDITOR_PRELOAD=0`
- `PYWEIXIN_FAST_FIRST_COLLECT_TIMEOUT_S=8`
- `PYWEIXIN_FAST_FIRST_FLUSH_EARLY=0`
- `PYWEIXIN_FAST_FIRST_QUICK_CAPTURE=0`

说明：如要继续冲极限耗时，可单独开启 `flush_early` 或 `quick_capture` 做小样本验证，但不建议直接作为默认生产策略。

### 14.4 新增：首条后 Hook 散弹（1/2/3）
- 新增能力：`fast_first_batch` 在首条 UI 成功后可尝试 Hook 散弹（从首条答案提取关键词，按 `PYWEIXIN_FAST_FIRST_SCATTER_VALUES` 生成如 `1红袖,2红袖,3红袖`）。
- 默认启动脚本已开启：
  - `PYWEIXIN_FAST_FIRST_SCATTER=1`
  - `PYWEIXIN_FAST_FIRST_SCATTER_VALUES=1,2,3`
  - `PYWEIXIN_FAST_FIRST_SCATTER_MAX=3`
  - `PYWEIXIN_FAST_FIRST_SCATTER_STOP_ON_FAIL=1`
- 实测日志：`local_workspace/startup_perf_opt_oneshot_20260223_152211_scatter_try1.log`
  - 可见 `early hook scatter candidates: ['1红袖', '2红袖', '3红袖']`
  - 首条散弹 `1红袖` 触发 `capture_thread failed -> pipe_thread -> SEH`，按 stop-on-fail 停止后续散弹。
  - 主流程仍稳定完成 `['4红袖','3红袖','7红袖']`，`streaming done: 9440ms`。

### 14.5 最新真实启动脚本回归（17:00+）
本节均为根目录 `启动抢答.py` 实跑（目标 `小蔡`），非 warmup。

1. 稳定性修复（已落地）
- `pyweixin/comment_dispatcher.py`：
  - `UICommentSender.send_comment()` 增加 UI 异常重试（默认 `PYWEIXIN_UI_SEND_RETRY=1`，间隔 `120ms`）。
  - 避免 `(-2147220991, 事件无法调用任何订户)` 直接抛出打断批量链路。
- `pyweixin/moments_ext.py`：
  - `fast_first scatter` 新增 `PYWEIXIN_FAST_FIRST_SCATTER_UI_FALLBACK`（默认 `0`）。
  - 默认散弹仅走 Hook，不再在散弹阶段回退 UI，降低 UI 线程干扰。
  - 修复“批量失败也被记入已发评论”的统计错误：现在只记录 `batch_result.results[i].success=True` 的答案。
- `启动抢答.py`：
  - 新增默认：
    - `PYWEIXIN_FAST_FIRST_SCATTER_UI_FALLBACK=0`
    - `PYWEIXIN_FAST_FIRST_SCATTER_HOOK_WAIT_MS=650`（原 900，下调以减少散弹失败等待）
    - `PYWEIXIN_UI_SEND_RETRY=1`
    - `PYWEIXIN_UI_SEND_RETRY_GAP_MS=120`

2. 实测结果
- 失败样本（修复前特征）：
  - 首条 `4红袖` 成功，后续在 scatter/final batch 阶段出现 UI COM 异常，只发 1 条。
- 成功样本 A：
  - `Posted comments: ['4红袖', '3红袖', '6红袖']`
  - `streaming done: 10715ms`
- 成功样本 B（修复后默认回归）：
  - `Posted comments: ['4红袖', '3红袖', '7红袖']`
  - `final batch posted: 2/2 (accepted=['3红袖', '7红袖'])`
  - `streaming done: 9408ms`

3. 性能与策略结论
- 当前稳定路径仍是：`首条 UI + 后续 piggyback`。
- `flush_early=1` 在当前环境仍不稳定（会放大 UI COM 异常），默认继续保持 `0`。
- Hook 散弹在本环境仍常见 `SEH exception in sns_do_comment`，已改为“失败快停，不拖慢主链路”。

### 14.6 继续优化（后续批次稳定性 + OCR误发防护）
1. 新增修复
- `pyweixin/moments_ext.py`
  - 批次发送前 `_refresh_ui_sender_anchor_before_batch()` 增强为“强制重取 feed list + 焦点 ListItem + anchor + center_point”后再绑定 UI sender。
  - 降低等待期后 `content_item`/anchor 变陈旧导致的 UIA COM 异常概率。
  - 修复“后续批次失败仍记为已发”问题，`all_answers` 仅纳入 `batch_result.results[i].success=True` 的答案。
- `pyweixin/rush_callback.py`
  - 增加 OCR 异常大值过滤：`PYWEIXIN_OCR_COUNT_MAX`（默认 `20`）。
  - 当 OCR 计数超过阈值时直接丢弃 OCR 结果并继续依赖 AI。
- `启动抢答.py`
  - 增加默认：`PYWEIXIN_OCR_COUNT_MAX=20`。

2. 真实启动脚本回归
- 成功样本（默认配置，修复后）：
  - `streaming done: 9680ms`
  - `Posted comments: ['4红袖', '3红袖', '7红袖']`
  - 日志可见：`final batch posted: 2/2 (accepted=['3红袖', '7红袖'])`
- 防误发样本（OCR 高噪）：
  - 日志：`[OCR] suspicious high count=37 (> 20), drop OCR answer and fallback to AI`
  - 本轮最终仅保留真实已发：`Posted comments: 4红袖`（不再虚报 `7红袖/34红袖` 已发）。

3. 时延拆分（默认稳定配置，成功样本）
- `first answer ready`: `0ms`（TemplateMatch）
- `reacquire ready`: `~488ms`
- `OCR ready`: `~5547ms`
- `AI ready`: `~6343ms`
- `streaming done`: `~9680ms`

说明：当前第 2/3 条主要受“最终 piggyback 批次 UI bootstrap”耗时影响，通常会在 `~9s` 左右落地。

4. 额外观测（环境侧）
- 17:13+ 两轮回归出现连续 `open moments failed`（朋友圈 Tab 控件不可用），属微信 UI 环境波动，不是评论链路逻辑回归。

### 14.7 2026-02-23 晚间速度收敛（AI 优化专项）
1. 目标与现象
- 目标：不引入“截图主路径”，在稳定前提下压 `AI ready` 与总耗时。
- 关键区分：
  - `AI answer=xxxms`：仅模型推理耗时。
  - `AI ready=xxxms`：从回调启动到答案入队，包含提图/队列/流程等待。

2. 本轮调整
- `启动抢答.py` 当前默认（速度优先）：
  - `PYWEIXIN_FAST_FIRST_SCATTER=0`（关闭首条后 Hook 散弹，减少无效等待）
  - `PYWEIXIN_FAST_FIRST_COLLECT_TIMEOUT_S=6`（收窄后续收集窗口）
  - `PYWEIXIN_FAST_FIRST_POST_FIRST_REMAINING_EARLY=0`（保总耗时，避免 early-one-shot 拉长尾部）
  - `PYWEIXIN_ARK_MAX_TOKENS=16`
  - `PYWEIXIN_ARK_TEMPERATURE=0.0`
  - `PYWEIXIN_ARK_TOP_P=0.6`
  - `PYWEIXIN_ARK_TIMEOUT_SEC=4.5`
- `pyweixin/rush_ai.py`：Ark 参数支持环境变量覆盖（无需改代码可继续调参）。

3. 实测对比（真实 `启动抢答.py`，目标 `小蔡`）
- 对照样本（early-one-shot 关闭、旧 Ark 参数）：
  - `AI ready: 6283ms`
  - `streaming done: 9682ms`
  - `Posted comments: ['4红袖', '3红袖', '7红袖']`
- 本轮默认（上面配置）：
  - `AI ready: 5996ms`
  - `streaming done: 9447ms`
  - `Posted comments: ['4红袖', '3红袖', '7红袖']`

4. 结论
- 本轮是“稳态小幅提速”：`AI ready` 与总耗时均有下降。
- 当前主要瓶颈仍在“首条后提图与流程串联”，不是模型推理本体。
- 若后续继续提速，优先做“提图稳定性”而不是继续压模型 token。
