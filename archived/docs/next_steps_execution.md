# 后续执行总文档（唯一入口）
更新时间：2026-02-12  
适用范围：`pywechat` 当前工作区

## 1. 当前状态结论（先看这个）
1. 主攻方向已切换为纯 HTTP 路线：`backend=http` + `provider=native_http`。
2. 轮次规则已固定：先跑 `--rounds 1`，稳定性最多 `--rounds 5`。
3. 目前纯 HTTP 真上游仍未打通，核心阻塞是：
   - 还未拿到 `mmsnscomment` 的“加密前明文请求样本（req id + protobuf）”。
4. 已确认 `send/WSASend` 层只能看到 `/mmtls/<id>` 加密封装，不能直接还原业务请求。

## 2. 唯一执行路线（当前）
### 2.1 快速验证（1 轮）
```powershell
python examples/run_hook_e2e_acceptance.py 小蔡 --backend http --http-provider native_http --http-base-url http://127.0.0.1:19080 --pure-http --use-latest-context --rounds 1 --concurrency 10
```

### 2.2 稳定性验证（最多 5 轮）
```powershell
python examples/run_hook_e2e_acceptance.py 小蔡 --backend http --http-provider native_http --http-base-url http://127.0.0.1:19080 --pure-http --use-latest-context --rounds 5 --concurrency 10
```

### 2.3 当纯 HTTP 上游未知/不可用时
进入协议取证线：`docs/native_http_protocol_recon.md`

## 3. 判定口径（报告三项必看）
报告目录：`local_workspace/acceptance_reports/*.json`

1. `summary.strict_success_rounds`
2. `summary.latency_p95_ms`
3. `summary.goal_passed`

辅助排障字段：
1. `rounds[].raw_batch_succeeded/raw_batch_total/raw_batch_failed`
2. `rounds[].fallback_count`
3. `rounds[].failed_items[]`

## 4. 截至今天（2026-02-12）进度快照
1. 新增统一取证跑法：`examples/run_frida_probe_with_action.py`（探针挂载 + 触发动作 + 单报告落盘）。
2. 已完成候选偏移时序分层：
   - `0x435900b`、`0x5622d7b`：发包后 1-5ms，属于 `/mmtls` 发送链。
   - `0x1df300e`、`0x1df38d2`：多为发包后延迟路径，不是首选构包点。
   - `0x74e2b8`：抓到过发包前 `acc-rXX-cYY`，是当前优先攻坚点。
3. 当前结论：纯 HTTP 未完工，但取证已从“盲找”收敛到“围绕 `0x74e2b8` 上下游函数链”。

## 5. 后续 TODO（严格按顺序）
1. 继续从 `0x74e2b8` 做 caller/callee 链前移，定位稳定函数边界。
2. 在该链路中抓取请求对象字段：
   - `request_type/cmd`
   - `payload_ptr + payload_len`
   - URI 映射证据（指向 `mmsnscomment`）
3. 拿到第一份“加密前明文 protobuf 样本”后，再进入 HTTP 重放 PoC。
4. PoC 成功后再接 sidecar `native_http` 真上游，并重跑 1 轮 + 5 轮验收。

## 6. 执行边界（防跑偏）
1. 不再把 Hook 并发稳定性当作当前主目标。
2. 不把 UI 自动评论成功当作纯 HTTP 成功。
3. 仅在纯 HTTP 链路定位需要时，才引用 Hook 历史文档做对照。

