# Hook 评论加速 — 进度追踪（代码对齐版）

> 更新时间：2026-02-10（按最新代码扫描）
> 当前状态：注入与通信链路稳定；`piggyback_comment` 已出现 10/10 成功样本；hook 回调内并行分支已写入代码，但 `<1s / 10条` 仍未验收通过。
> 流程图入口：`docs/hook_flow_overview.md`

## 1. 目标

- 监听命中后自动发送 10 条评论。
- 性能目标：10 条总耗时 `< 1s`。
- 验收口径：`10/10` 成功 + P95 `< 1s`。

## 2. 阶段状态

| 阶段 | 状态 | 说明 |
|---|---|---|
| Phase 1 逆向定位与调用链确认 | ✅ 完成 | 锚定 `cgi_A_caller_2`、请求结构、关键 RVA |
| Phase 2 DLL 基建 | ✅ 完成 | MinHook 生命周期、注入、Pipe 服务、状态捕获 |
| Phase 3 Python 接入 | ✅ 完成 | `hook_types/hook_bridge/comment_dispatcher` 接线 |
| Phase 4 诊断能力 | ✅ 完成 | `diagnose_thread/read_memory/tls_diag` 与脚本体系 |
| Phase 5 并发加速 | 🟡 进行中 | `parallel_comment` 与 `piggyback_comment` 已有实现，稳定收益待收敛 |
| Phase 6 主流程接线 | 🟡 进行中 | `moments_ext` 仍以逐条 `post_comment` 为主 |
| Phase 7 达标验收 | ⛔ 未完成 | 缺少连续多轮 `10/10 + <1s` 证据 |

## 3. 当前代码事实（最新）

1. `pipe_thread` 直调仍可触发 `0xC0000005`，不可视作稳定并发基础。
2. `capture_thread` 可用，但本质是“任务入队 -> 等下一次 hook 回调执行”。
3. `piggyback_comment` 已实现批量入队 + 回调期 drain，且包含串行/并行两条执行分支。
4. 并行分支启用条件：`max_concurrency > 1 && g_cached_req_0x368_valid`。
5. `REQUEST_CALL_BUFFER_SIZE` 已扩到 `0x400`，并缓存 `request->+0x368` 供 worker 预填充。
6. 代码中还没有真正安装 `0xb91e90` 的函数 hook（仅有 `TLS_ACCESSOR_RVA` 常量与分析文档）。
7. `CommentDispatcher.post_batch_comments()` 仍以 `succeeded > 0` 作为并发路径可用判定，标准偏宽。
8. `moments_ext` 主路径尚未默认切到 `post_batch_comments()`。

## 4. 距离目标还有多远（量化）

| 指标 | 当前已验证 | 目标 | 差距 |
|---|---:|---:|---:|
| 10 条总耗时 | 5591ms | <1000ms | 还差 4591ms |
| 平均单条耗时（串行样本） | 559ms/条 | 理论串行需 <100ms/条 | 约 5.59x 提升需求 |
| 成功率口径 | 有 10/10 单次样本 | 连续多轮 10/10 | 缺稳定性样本集 |

结论：以当前“已验证结果”计算，还需约 `82.1%` 的总时延下降（`1 - 1000/5591`）。

## 5. P0 待办（达标前必做）

- [ ] 固化“硬冲刺”压测入口：10 条一次下发，关闭 UI fallback 干扰。
- [ ] 并发成功判定改为 `succeeded == total`，不再使用 `succeeded > 0`。
- [ ] 对 piggyback 并发做分级压测：`2 -> 4 -> 8 -> 10`，记录成功率与崩溃分布。
- [ ] 输出统一验收报表：总耗时、P50/P95、10/10 比例、失败分类（SEH/timeout/null return/限流）。

## 6. 风险

1. 共享 `arg1` 的并行调用可能存在内部写竞争。
2. 线程局部依赖尚未彻底剥离，`parallel_comment` 仍属于实验态。
3. 即使本地达标，服务端限流也可能拉低稳定性。

## 7. 现阶段判断

- 方向是对的：已从“能否发送”进入“并行收敛与验收”阶段。
- 目标还差一个关键技术里程碑：把 piggyback 并发从“有代码路径”变成“稳定 10/10 + <1s”。
