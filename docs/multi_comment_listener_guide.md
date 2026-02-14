# 多评论队列监听器使用指南

## 概述

多评论队列监听器是一个增强版的朋友圈监听脚本，支持**快速首评 + 队列后续评论**机制。相比原有的单评论模式，它能在保持快速首评（~300ms）的同时，自动发送多条后续评论，显著提升互动性。

## 核心特性

- **快速首评**：使用 OCR 快速识别（~300ms），立即发送第 1 条评论
- **多源评论**：支持 OCR、AI、预制话术、OCR 重试、动态生成等多种评论来源
- **自动去重**：智能去除重复评论（归一化比较）
- **Serial Mode**：使用已验证可靠的 Hook Serial Mode 发送
- **灵活配置**：通过命令行参数轻松控制评论源和数量

## 典型使用场景

### 场景 1：基础模式（OCR + AI）

```bash
python examples/run_feed_multi_comment_listener.py 19:15 小蔡
```

**效果**：
- T+300ms：OCR 快速答案（如"5百里辞"）→ 立即发送
- T+800ms：AI 改进答案（如"5个百里辞"）→ 如果与 OCR 不同，加入队列

**适用场景**：需要快速抢答，同时保证答案准确性

### 场景 2：增加互动性（预制话术）

```bash
python examples/run_feed_multi_comment_listener.py 19:15 小蔡 --canned "666,厉害,沙发"
```

**效果**：
- T+300ms：OCR 快速答案 → 立即发送
- T+350ms：预制话术"666" → 加入队列
- T+400ms：预制话术"厉害" → 加入队列
- T+800ms：AI 改进答案 → 加入队列

**适用场景**：希望在抢答的同时增加互动评论，活跃气氛

### 场景 3：提高识别率（OCR 重试）

```bash
python examples/run_feed_multi_comment_listener.py 19:15 小蔡 --ocr-retry --max-comments 3
```

**效果**：
- T+300ms：OCR 快速答案（标准参数）→ 立即发送
- T+800ms：AI 改进答案 → 加入队列
- T+1200ms：OCR 重试（更高分辨率）→ 如果不同，加入队列

**适用场景**：题目图片质量较差，需要多次识别提高准确率

### 场景 4：完整配置（所有功能启用）

```bash
python examples/run_feed_multi_comment_listener.py 19:15 小蔡 ^
    --canned "666,厉害,沙发,第一" ^
    --ocr-retry ^
    --max-comments 5 ^
    --poll-interval 0.5 ^
    --suffix 男
```

**效果**：最多发送 5 条评论，包含所有来源的答案

### 场景 5：已知答案即时首评

```bash
python examples/run_feed_multi_comment_listener.py 19:15 小蔡 ^
    --known-answers config/known_answers.json
```

**效果**：使用已知答案 JSON 文件，第一条评论可在 OCR/AI 完成前发出（毫秒级）

### 场景 6：禁用数学题和散弹猜测

```bash
python examples/run_feed_multi_comment_listener.py 19:15 小蔡 ^
    --no-math ^
    --no-guess
```

**效果**：只使用 OCR/AI/模板匹配，不自动解题和猜测数字

### 场景 7：自定义散弹范围 + 模板匹配

```bash
python examples/run_feed_multi_comment_listener.py 19:15 小蔡 ^
    --guess-range "1,10" ^
    --rush-config config/rush_event.json
```

**效果**：发送 1男~10男，更大范围覆盖；使用自定义模板配置文件

## 命令行参数

| 参数 | 类型 | 默认值 | 说明 |
|-----|------|--------|------|
| `publish_time` | 必需 | - | 预期发布时间（HH:MM 格式） |
| `target_author` | 必需 | - | 目标作者名称 |
| `--poll-interval` | float | 0.5 | 轮询间隔（秒） |
| `--suffix` | string | None | 答案后缀（如"男"） |
| `--canned` | string | None | 预制话术（逗号分隔） |
| `--ocr-retry` | flag | False | 启用 OCR 重试 |
| `--max-comments` | int | 5 | 每帖最多评论数 |
| `--known-answers` | string | None | 已知答案 JSON 路径，实现即时首评 |
| `--no-math` | flag | False | 禁用数学题自动求解 |
| `--rush-config` | string | None | 模板匹配配置文件路径 (`rush_event.json`) |
| `--guess-range` | string | "3,7" | 散弹射击范围（如 "3,7" = 发送 3男,4男,...,7男） |
| `--no-guess` | flag | False | 禁用数字散弹猜测 |

## 环境变量配置

脚本会自动设置以下环境变量，通常不需要手动配置：

```bash
# Hook 配置（脚本自动设置）
PYWEIXIN_HOOK_ENABLED=1
PYWEIXIN_HOOK_BATCH_MODE=fast_first_batch
PYWEIXIN_HOOK_MAX_CONCURRENCY=1  # Serial Mode

# OCR 配置（可选，优化识别效果）
PYWEIXIN_OCR_DET_MODEL=PP-OCRv5_mobile_det
PYWEIXIN_OCR_REC_MODEL=PP-OCRv5_mobile_rec
PYWEIXIN_OCR_CPU_THREADS=8
PYWEIXIN_OCR_MAX_SIDE=1200

# API 配置（必需）
ARK_API_KEY=your_api_key
```

## 输出文件

脚本运行时会生成以下文件：

- `rush_state_feed_{author}_multi.json` — 运行状态（避免重复评论）
- `rush_moments_cache_feed_{author}_multi/` — 抓取的图片和日志

**注意**：这些文件已在 `.gitignore` 中忽略，不会被提交到 Git 仓库。

## 性能对比

| 方案 | 首评延迟 | 总延迟 | 评论数 |
|------|---------|--------|--------|
| 旧脚本（AI only） | 800ms | 800ms | 1 条 |
| 旧脚本（OCR + AI streaming） | 300ms | 800ms | 2 条 |
| **新脚本（fast_first_batch）** | **300ms** | **1300ms** | **4-5 条** |

**优势**：
- ✅ 首评速度不变（300ms）
- ✅ 评论数增加 2-3 倍
- ✅ 总延迟增加有限（+500ms）
- ✅ 互动性显著提升

## 常见问题

### Q1: 为什么有时候评论数少于 max-comments？

**A**: 多源回调会自动去重，如果多个来源生成了相同的答案（归一化比较），只会保留第一个。

### Q2: 可以调整首评等待时间吗？

**A**: 目前首评等待时间固定为 2 秒。如果 OCR 在 2 秒内未完成，会直接进入批量收集模式。

### Q3: 预制话术会按顺序发送吗？

**A**: 预制话术会轮流选择，每次运行选择不同的话术（通过内部索引实现）。

### Q4: 如何禁用某个评论源？

**A**: 不传递对应的参数即可。例如不传递 `--canned` 就禁用预制话术，不传递 `--ocr-retry` 就禁用 OCR 重试。

### Q5: Hook DLL 未注入怎么办？

**A**: 参考主文档中的 Hook DLL 开发流程：
1. Kill 微信进程
2. 启动微信并等待 5 秒
3. 注入 DLL：`python -c "from pyweixin.hook_injector import ...; inject_dll(pid, dll_path)"`
4. 运行脚本

## 技术架构

### 核心组件

1. **rush_callback_multi.py** — 多源评论生成框架
   - `CommentSource` 协议：定义评论源接口
   - 5 种内置评论源：OCR、AI、预制、OCR重试、动态生成
   - `create_multi_source_streaming_callback()` 工厂函数

2. **moments_ext.py** — 添加 fast_first_batch 模式
   - 等待第 1 个答案（最多 2 秒）
   - 立即发送第 1 条评论
   - 继续收集剩余答案（最多 8 秒）
   - 批量发送剩余评论（Serial Mode）

3. **run_feed_multi_comment_listener.py** — 新监听脚本
   - 基于 `run_feed_refresh_listener.py` 结构
   - 使用多源回调替代单源回调
   - 友好的命令行参数

### 工作流程

```
T=0ms     检测到新帖子（题目："图中有几个百里辞？"）
T=50ms    启动多源回调：OCR、AI、预制、OCR重试
T=300ms   OCR 完成："5百里辞" → 立即发送第 1 条评论 ✓
T=350ms   预制话术就绪："666" → 加入队列
T=400ms   预制话术就绪："厉害" → 加入队列
T=800ms   AI 完成："5个百里辞" → 加入队列（与 OCR 不同，保留）
T=1200ms  OCR 重试完成："5百里辞" → 去重，不加入队列
T=1300ms  收集完成，批量发送剩余 3 条评论
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
最终效果：
- 第 1 条评论：T+300ms（极快）
- 共 4 条评论：["5百里辞", "666", "厉害", "5个百里辞"]
- 总耗时：1.3 秒
```

### DeferredImagePaths 机制

实现上 `ai_callback` 会先启动，并传入 `DeferredImagePaths`；图片提取完成后再调用 `DeferredImagePaths.set(image_paths)`，OCR/AI 才开始处理。TemplateMatch/散弹等不依赖图片的 source 可在图片就绪前直接产出。

优势：
- **更短的首评延迟**：不依赖图片提取完成，回调立即启动
- **并行处理**：图片提取与 OCR/AI 初始化并行执行
- **资源优化**：OCR/AI 只在图片就绪后才开始处理，避免空转

## 后续优化方向

1. **动态评论生成器**：基于题目类型生成个性化评论
2. **评论时序优化**：预制话术延迟发送，模拟人工打字
3. **多帖子队列**：持续监听多个帖子（需要帖子队列机制）
4. **状态持久化增强**：记录每个帖子的评论历史

## 与现有脚本的关系

- **新脚本**：`run_feed_multi_comment_listener.py`（多评论队列）
- **旧脚本**：`run_feed_refresh_listener.py`（单评论或双评论）

**兼容性**：
- 两个脚本可以共存，互不影响
- 旧脚本继续使用原有的 batch mode（piggyback/parallel/serial）
- 新脚本使用新的 fast_first_batch mode
- moments_ext.py 的修改不影响旧脚本的功能

## 开发规范遵守情况

按照 CLAUDE.md 规范：

✅ **不侵入 upstream 代码**：新功能全部在独立文件中实现
✅ **最小化修改**：moments_ext.py 仅添加新的 batch mode 分支（~100 行）
✅ **独立扩展文件**：rush_callback_multi.py 是完全独立的新文件
✅ **文档完善**：提供详细的使用指南和技术架构说明

## 更多信息

- 朋友圈功能总览：`docs/moments_rush_guide.md`
- Hook DLL 开发流程：`CLAUDE.md`（Hook DLL 开发流程部分）
- 原始计划文档：查看实施计划获取更多技术细节
