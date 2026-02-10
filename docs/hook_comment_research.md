# 朋友圈评论 Hook 架构设计与实现（代码对齐版）

> 更新时间：2026-02-10（按最新代码扫描）
> 适用范围：当前工作区 `viper/hook-comment`
> 流程图入口：`docs/hook_flow_overview.md`

## 1. 目标与边界

- 目标：将评论发送从 UI 自动化迁移到进程内调用，降低抖动并冲刺 `10 条 < 1s`。
- 底线：Hook 不可用时必须自动回退 UI。
- 边界：朋友圈监听、OCR/AI 识别仍在 Python 层，Hook 只负责发送通道。

## 2. 分层结构

```text
Python 业务层
  moments_ext.py
    -> CommentDispatcher
       -> HookBridge (Named Pipe)
       -> UI comment_flow (fallback)

WeChat 进程内 DLL
  dllmain.cpp -> HookManager(MinHook)
              -> PipeServer
              -> sns_comment.cpp

WeChat 内部函数
  cgi_A_caller_2 (4.1.7.30: RVA 0x049e9240)
```

## 3. DLL 端实现现状（`hook/src/sns_comment.cpp`）

### 3.1 初始化与 hook

1. 版本识别后定位目标函数（4.1.7.30 走硬编码 RVA）。
2. 安装 `cgi_A_caller_2` hook。
3. Pipe 命令进入 `PipeServer` 分发。

### 3.2 Hook 回调职责

每次合法评论回调时，会做这些事：

1. 捕获运行时上下文：`arg1/arg2/arg3/vtable/author_info`。
2. 缓存模板：request 前缀与 arg1 模板。
3. 更新 `latest_sns_id`。
4. 执行 capture-thread job 队列。
5. 执行 `hook_comment` 注入队列。
6. 调一次原始函数后，缓存 `request->+0x368`。
7. 若有 `piggyback` batch，在同一次回调中 drain（串行或并行）。

### 3.3 发送路径（代码真实状态）

1. `comment(execution_mode=pipe_thread)`：仍可能触发 `0xC0000005`。
2. `comment(execution_mode=capture_thread)`：任务入队，等下一次回调执行。
3. `parallel_comment`：worker 线程并发调 `sns_do_comment`，实验态。
4. `piggyback_comment`：先入队，回调期执行，已包含并行分支。

### 3.4 piggyback 关键点

- 并行启用条件：`max_concurrency > 1 && g_cached_req_0x368_valid`。
- 每个 worker 使用独立 request buffer。
- worker 共享同一组 `arg1/arg2/arg3`（来自当前 hook 回调）。
- 已有 10/10 成功样本，但已验证耗时仍是 `5591ms / 10 条` 量级。

### 3.5 TLS 相关现状

- 标准 TLS/FLS 诊断与复制逻辑存在。
- `implicit TLS` 整块复制在当前代码中未作为默认稳定方案。
- `TLS_ACCESSOR_RVA = 0x00b91e90` 已纳入分析，但当前代码没有安装该函数的 hook。
- 详细根因分析见：`docs/tls_crash_analysis.md`。

## 4. Pipe 命令面

- 基础：`ping` / `version` / `status`
- 发送：`comment` / `hook_comment` / `batch_comment` / `parallel_comment` / `piggyback_comment`
- 缓存：`query_sns_id` / `get_latest_sns_id`
- 诊断：`diagnose_thread` / `read_memory` / `tls_diag` / `test_hook_trigger`

## 5. Python 端实现现状

### 5.1 Bridge 与协议

- `hook_types.py`：命令与返回结构（含 `PiggybackCommentCommand`）。
- `hook_bridge.py`：包含 `send_parallel_comments()` 与 `send_piggyback_comments()`。

### 5.2 调度器（`comment_dispatcher.py`）

- 默认优先 Hook，失败自动 UI fallback。
- `post_batch_comments()` 已实现并发优先、串行回退、UI 兜底。
- 当前并发可用判定是 `succeeded > 0`，对“10/10”目标不够严格。

### 5.3 业务主路径（`moments_ext.py`）

- 仍以逐条 `post_comment()` 为主。
- 尚未默认切到批量接口，因此端到端仍偏串行。

## 6. 对 `<1s/10条` 的结论（代码视角）

1. 发送能力已打通，核心难点已从“能不能发”变成“并发是否稳定”。
2. 目前最近已验证样本是 `5591ms / 10 条`，距离目标仍显著。
3. 距离达标的关键闭环是：
   - 共享 `arg1` 并行安全验证完成；
   - 验收口径收紧到 `10/10`；
   - 连续多轮 `<1s` 报表稳定。
