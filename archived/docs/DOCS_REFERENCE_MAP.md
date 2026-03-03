# 文档参考地图（全量分类）
更新时间：2026-02-12

## A. 执行入口（P0，日常必看）
1. `docs/ecosystem_research_and_route_a_plan.md`
   - 用途：生态调研结论 + 路线 A（Hook 并行）5 阶段实施计划。**当前主线。**
2. `docs/wxhook_dll_research_2026-02-12.md`
   - 用途：lyx102/WeChatHook + miloira/wxhook 深度调研报告。**结论：不值得逆向。**
3. `docs/wxhelper_analysis_2026-02-12.md`
   - 用途：ttttupup/wxhelper 深度分析报告。**结论：无评论功能，当前项目已更优。**
4. `docs/wxhelper_methodology_comparison_2026-02-12.md`
   - 用途：wxhelper 方法论对比（数据库解密 vs Hook CGI）。**结论：Hook CGI 是唯一正确路径。**
5. `docs/hook/hook_e2e_acceptance_guide.md`
   - 用途：命令参数与报告字段说明；对齐 `strict_success_rounds / latency_p95_ms / goal_passed`。
6. `docs/target_goal_gap.md`
   - 用途：目标差距定义（10 条评论 < 1s 的基线与拆解）。

## B. Hook 技术参考（P1，实施路线 A 时必看）
1. `docs/hook/hook_comment_research.md`
   - 用途：Hook 架构与评论函数逆向分析，DLL 实现细节。
2. `docs/hook/tls_crash_analysis.md`
   - 用途：TLS 崩溃根因分析，`0xb91e90` 方案设计。路线 A 阶段 1 的核心参考。
3. `docs/hook/hook_flow_overview.md`
   - 用途：端到端评论流程图（Python → DLL → CGI）。
4. `docs/hook/hook_progress.md`
   - 用途：Hook 各阶段进度跟踪。

## C. 纯 HTTP 路线（P3，长期储备，暂不主攻）
1. `docs/native_http_protocol_recon.md`
   - 用途：协议取证进度、偏移分层、Frida 探针工具链。
2. `docs/native_http_sender_design.md`
   - 用途：HTTP 发送端架构设计。
3. `docs/next_steps_execution.md`
   - 用途：原纯 HTTP 执行路线（已被路线 A 取代，保留做历史参考）。

## D. 业务/流程辅助（P2，按需）
1. `docs/testing_dataset_guide.md`
   - 用途：测试样本/数据集使用规范。
2. `docs/moments_rush_guide.md`
   - 用途：朋友圈自动抢答流程。
3. `docs/fork_sync_guide.md`
   - 用途：分叉同步流程说明。

## E. 归档区（Archive，仅追溯）
入口：`docs/archive/README.md`

归档文件：
1. `docs/archive/2026-02-10_1s10comments_plan.md`
2. `docs/archive/external_repo_research_2026-02-09.md`
3. `docs/archive/hook_thread_diag_log_2026-02-10.md`

## 推荐阅读顺序
1. 日常推进：`docs/ecosystem_research_and_route_a_plan.md` → `docs/hook/hook_e2e_acceptance_guide.md`
2. 实施 TLS 覆盖：`docs/hook/tls_crash_analysis.md` → 代码 `hook/src/sns_comment.cpp:937-956`
3. 需要追溯历史纯 HTTP 尝试：`docs/native_http_protocol_recon.md` → `docs/native_http_sender_design.md`
4. 需要追溯更早的旧方案：Archive

