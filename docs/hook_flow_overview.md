# Hook 评论链路流程图（代码对齐版）

> 更新时间：2026-02-10（按最新代码扫描）
> 对应代码：`pyweixin/moments_ext.py`、`pyweixin/comment_dispatcher.py`、`pyweixin/hook_bridge.py`、`hook/src/pipe_server.cpp`、`hook/src/sns_comment.cpp`

## 1. 端到端主链路

```mermaid
flowchart TD
    A[run_feed_refresh_listener.py] --> B[moments_ext.py]
    B --> C[CommentDispatcher]
    C --> D{Hook 可用?}
    D -- 否 --> U[UI comment_flow]
    D -- 是 --> E[HookBridge Named Pipe]
    E --> F[DLL PipeServer]
    F --> G{cmd}
    G -- comment --> H[sns_do_comment / capture_thread]
    G -- parallel_comment --> I[sns_do_comment_parallel]
    G -- piggyback_comment --> J[sns_queue_piggyback]
    H --> K[cgi_A_caller_2]
    I --> K
    J --> K
    K --> R[CommentResult / BatchResult]
    U --> R
```

## 2. `piggyback_comment` 执行分支（当前关键）

```mermaid
flowchart TD
    A[Python send_piggyback_comments] --> B[pipe: piggyback_comment]
    B --> C[DLL: 缓存 batch 并等待下一次 hook 回调]
    C --> D[hooked_cgi_A_caller_2 被触发]
    D --> E[先调用一次 g_original_fn]
    E --> F[缓存 request+0x368]
    F --> G{max_concurrency>1 且 req+0x368 已缓存?}
    G -- 否 --> H[串行逐条调用 g_original_fn]
    G -- 是 --> I[并行 worker 调用 g_original_fn]
    H --> J[汇总 total/succeeded/failed/latency]
    I --> J
    J --> K[返回 BatchCommentResult]
```

## 3. 现状速记

1. `pipe_thread` 仍有 `0xC0000005` 风险。
2. `capture_thread` 可用，但依赖回调触发时机。
3. piggyback 已有 10/10 成功样本，已验证耗时为 `5591ms / 10 条`。
4. 代码内已有 piggyback 并行分支，但稳定收益仍待验收。
5. 目标差距：还需把总耗时从 `5591ms` 压到 `<1000ms`（还差 `4591ms`）。
