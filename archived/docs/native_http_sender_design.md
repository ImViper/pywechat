# 非 Hook 执行后端设计（HTTP Native 攻坚）
更新时间：2026-02-11  
适用范围：`pywechat` 当前工作区

## 1. 背景与问题
当前 `backend=http` 仍会在真实链路中复用 Hook 执行器（`real_hook` 模式），因此并发异常不会消失，只是把入口从 pipe 换成了 HTTP。

已验证事实（来自最近验收与日志）：
1. `HTTP + real_hook + concurrency=1` 可达成功，但延迟约 5~8s/10 条。
2. `HTTP + real_hook + concurrency>1` 仍会触发 `piggyback_parallel` 不稳定，出现 `pipe 109`/崩溃。
3. `mock_http` 可轻松达标（P95 < 1000ms），说明瓶颈不在 Python/HTTP 框架，而在当前 Hook 并发执行路径。

结论：要“治本”，必须让并发主路径不再依赖 `piggyback_parallel`。

## 2. 目标与非目标
### 2.1 目标
1. 引入真正的 `native_http` 执行后端（不调用 Hook 并发发送函数）。
2. 保留 `hook/ui` 作为兜底，而不是主路径。
3. 先达成“真实链路可持续成功（5 轮上限）”，再冲刺 `<1s`。

### 2.2 非目标
1. 不在本阶段删除 Hook 体系。
2. 不在本阶段大规模重写朋友圈检测/OCR/AI 流程。
3. 不承诺一次性完成全协议逆向；先做可验证 PoC，再扩展。

## 3. 总体架构
新增“执行引擎”分层，拆分“入口协议”和“执行实现”：

1. `CommentDispatcher`：只做路由与回退（HTTP -> Hook -> UI）。
2. `HTTP Sidecar`：统一 API 层，新增 provider 插件机制。
3. `Provider`：
   - `mock`：性能基线。
   - `real_hook`：兼容旧路径（保留）。
   - `native_http`：新主攻后端。

目标是让 `backend=http` 默认对接 `native_http`，`real_hook` 仅作为回退/对照。

## 4. native_http 设计
### 4.1 接口约束
Sidecar 维持现有接口不变：
1. `POST /api/comment`
2. `POST /api/comment/batch`

响应结构继续兼容当前 `HttpCommentSender`：
1. 顶层 `ok/error_code/error_message/latency_ms`
2. `data.total/succeeded/failed/results[]`

### 4.2 Provider 抽象
在 `examples/run_http_comment_sidecar.py` 内先做本地抽象（后续可提取到 `pyweixin/`）：
1. `BaseProvider.send_one(req) -> dict`
2. `BaseProvider.send_batch(req) -> dict`
3. `MockProvider` / `RealHookProvider` / `NativeHttpProvider`

### 4.3 NativeHttpProvider（分阶段）
阶段 A（PoC）：
1. 实现 `native_http` provider 框架与参数面。
2. 接入“真实发送适配器”占位（先支持 dry-run 与回放）。
3. 验证批量并发控制、超时、重试、幂等、报告字段完整性。

阶段 B（真实发送）：
1. 对接真实评论发送通道（独立于 Hook 并发调用）。
2. 增加 `trace_id`、错误码映射、请求签名/鉴权。
3. 完成 `rounds=1` 与 `rounds=5` 的真实链路回归。

## 5. 协议与观测增强
### 5.1 请求字段（新增建议）
1. `trace_id`：调用链全局追踪。
2. `idempotency_key`：幂等去重，避免重试重复评论。
3. `deadline_ms`：服务端强约束超时。

### 5.2 响应字段（新增建议）
1. `provider`: `mock|real_hook|native_http`
2. `raw_provider_latency_ms`
3. `retry_count`

### 5.3 报告对齐
继续使用：
1. `raw_batch_*`
2. `fallback_count`
3. `failed_items[]`

新增建议：
1. `provider`
2. `provider_error_code`
3. `provider_error_message`

## 6. 代码改造清单
### 6.1 第一批（本轮开发）
1. `examples/run_http_comment_sidecar.py`
   - 引入 provider 抽象。
   - 增加 `--mode native_http`（先 PoC 框架）。
2. `examples/run_hook_e2e_acceptance.py`
   - 增加 `--http-provider` 透传（可选）。
3. `docs/*`
   - 更新执行路线与验收口径。

### 6.2 第二批（真实通道接入）
1. `pyweixin/comment_dispatcher.py`
   - 增加 provider 能力探测和分级回退策略。
2. sidecar provider 实现
   - 接入真实发送实现，打通并发主链路。

## 7. 验收标准（固定 5 轮上限）
快测：
1. `rounds=1`
2. 并发参数优先验证 `concurrency=10`

稳定性：
1. `rounds=5`
2. 必看三项：
   - `summary.strict_success_rounds`
   - `summary.latency_p95_ms`
   - `summary.goal_passed`

达标定义：
1. `strict_success_rounds == rounds`
2. `latency_p95_ms < 1000`
3. `goal_passed == true`

## 8. 风险与回退
风险：
1. 真实发送协议复杂度高，PoC 到稳定需要多轮迭代。
2. 发送链路可能存在服务端节流，导致并发收益低于预期。

回退策略：
1. `native_http` 不稳定时自动降级 `real_hook`。
2. `real_hook` 异常时自动降级 UI。
3. 任一路径失败都不阻断主流程，确保“先可用再优化”。

## 9. 本设计的执行顺序
1. 先完成 sidecar provider 抽象（不改业务入口）。
2. 再接入 `native_http` provider（PoC）。
3. 再切换验收脚本默认走 `native_http` 做真实链路冲刺。
4. 最后根据报告决定是否继续保留 `real_hook` 作为中间态。
