# Direct-Call 攻坚进展（2026-02-23）

## 目标

在 `capture_thread` 超时后，`pipe_thread` 直接调用也能稳定成功，避免第 2/3 条评论频繁回退 UI。

## 当前结论

截至 2026-02-23 03:33（本地实测）：

- `capture_thread -> retry pipe_thread` 路径已稳定触发；
- 但 `pipe_thread` direct-call 仍失败，表现为：
  - `SEH exception in sns_do_comment`
  - 典型崩溃点仍是 `crash_rip_rva = 0x3c5c70`
- 因此 direct-call 仍未打通。

对应验收报告：

- `local_workspace/acceptance_reports/hook_e2e_20260223_033244.json`

## 已落地修复（本轮前后累计）

### A. 业务链路修复（已验证有效）

1. `piggyback` 升级 `parallel` 的条件收紧，只在 `parallel_ready=True` 时升级：
   - 文件：`pyweixin/comment_dispatcher.py`
   - 影响：避免 `fast_first_batch` 提前走不稳定并发路径。

2. `moments_ext` 在 reacquire 后给复用 dispatcher 重新绑定 UI sender：
   - 文件：`pyweixin/moments_ext.py`
   - 影响：Hook 失败时可在同一 dispatcher 内回退 UI，避免“no sender available”。

3. `fast_first_batch` 场景下，capture stale 时保留 Hook 入口：
   - 文件：`pyweixin/moments_ext.py`
   - 影响：首条可 UI fallback，后续继续走 piggyback。

4. 端到端验证通过（目标作者“小蔡”）：
   - 结果：`3/3` 成功，`method_counts={"ui":1,"piggyback":2}`
   - 报告：`local_workspace/acceptance_reports/hook_e2e_20260223_032921.json`

### B. DLL 诊断增强（用于 direct-call 攻坚）

1. 状态增加 `arg1_ctx_patch_hits`：
   - `hook/src/sns_comment.h`
   - `hook/src/sns_comment.cpp`
   - `hook/src/pipe_server.cpp`

2. `hooked_arg1_ctx_helper` 增加 worker 直接返回 `ctx` 的路径（避免原 helper 在 worker 上读空）：
   - `hook/src/sns_comment.cpp`

3. `sns_do_comment` 调用阶段临时开启 worker ctx patch 标记：
   - `hook/src/sns_comment.cpp`

4. 新增 TOP 入口 fallback 尝试（caller2 崩溃后再试 `cgi_A_caller_3_TOP`）：
   - `hook/src/sns_comment.cpp`
   - 当前实测：仍未解决 `0x3c5c70` 崩溃。

## 本轮关键现象

1. `arg1_ctx_patch_hits` 持续为 0，说明当前崩溃链路很可能没有经过预期的 arg1 helper hook 入口。
2. 不同 `arg1_mode`（template/captured_ptr/zeroed）在 pipe_thread 下均收敛到同一崩溃点 `0x3c5c70`。
3. `capture_thread` 仍可能超时（UI 线程调度不稳定），因此 direct-call 仍有必要继续攻坚。

## 下一步分析计划（继续执行）

1. 暴露更多 DLL status 诊断字段：
   - `g_arg1_ctx_helper_hook_installed`
   - `g_tls_accessor_hook_installed`
   - `g_hook_hit_count / g_hook_top_hit_count`
   - `g_arg1_ctx_helper_addr / g_tls_accessor_addr`
   目标：先确认 helper/tls 辅助 hook 是否真的安装并命中。

2. 对 `0x3c5c70` 附近做在线字节采样与对照：
   - 结合 `read_memory` 输出，确认实际执行路径是否绕过了当前 hook 入口 `0x3c5970`。

3. 若确认绕过，尝试“双入口 hook”策略：
   - 保留 `0x3c5970`，并在 `0x3c5c70` 或其上游可控点增加兜底 hook（仅在 worker 触发）。

4. 若仍不可行，退回“稳定优先”策略：
   - 业务层默认 `fast_first_batch + piggyback(serial)`，把 direct-call 作为可选实验开关。


---

## 2026-02-23 04:10 补充进展

### 已确认稳定

- `capture_thread` 超时后会触发日志：
  - `capture_thread failed (...), retrying pipe_thread`
- `pipe_thread` direct-call 仍失败（见下节），但批量稳定链路可用：
  - `batch_mode=piggyback`（不自动升级 parallel）在 `小蔡` 目标复测通过 `3/3`
  - 报告：`local_workspace/acceptance_reports/hook_e2e_20260223_040210.json`

### direct-call 仍未打通（最新证据）

- `serial`（单条）复测仍失败：
  - 报告：`local_workspace/acceptance_reports/hook_e2e_20260223_040230.json`
- 新增诊断字段后确认：
  - `arg1_ctx_written=true`
  - `direct_ctx_available=true`
  - `direct_tls_override_enabled=true`
  - 仍抛 `SEH exception in sns_do_comment`
- `arg1_ctx_helper_hook_last_status=8`（MinHook unsupported function）持续存在，helper hook 无法安装。

### 本轮代码更新（新增）

1. `hook/src/sns_comment.h`
- `CommentResult` 增加 direct-call 诊断字段：
  - `arg1_ctx_written`
  - `direct_ctx_available`
  - `direct_tls_override_enabled`

2. `hook/src/sns_comment.cpp`
- direct-call 增加“主动写入 arg1+0x368”路径；
- 增加“本次调用级别”的 TLS accessor 覆盖开关（仅 direct-call worker 线程）；
- 保留原 fallback 逻辑（TOP 优先实验已回滚）。

3. `hook/src/pipe_server.cpp`
- 将上述诊断字段透出到 `comment` 响应 `data`，便于在线判断 direct-call 是否命中修复分支。

4. `pyweixin/comment_dispatcher.py`
- `piggyback -> parallel` 自动升级改为显式开关：
  - 仅在 `PYWEIXIN_HOOK_AUTO_UPGRADE_PARALLEL=1` 时启用；
  - 默认关闭，避免在 parallel 不稳定时拖垮批量成功率。

---

## 2026-02-23 追加：fast_first_batch 真实行为说明

- 在 `fast_first_batch` 下，当后续答案数量为 2 时，最终经常呈现：
  - 首条 UI（尽快出首评）
  - 第二条 UI（作为 piggyback bootstrap）
  - 第三条 Hook（piggyback 真正注入）
- 因此 `4红袖(ui) + 3红袖(ui) + 7红袖(hook)` 属于当前策略行为，不是偶发。

### 本轮新增修复（已落地）

1. 修复 fast_first_batch 分支“首条后未触发 deferred 提图”问题。
2. 修复 UI 锚点 `0,0,0,0` 时误点发送的问题（改为 fallback Enter）。
3. 默认关闭 `piggyback -> parallel` 自动升级，避免并行不稳定拖垮成功率。
4. 默认关闭多源 dedup，避免 OCR/AI 结果被模板答案去重吞掉。
