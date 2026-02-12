# Docs 导航（当前执行版）
更新时间：2026-02-12

## 先看这 2 份（日常固定入口）
1. `docs/ecosystem_research_and_route_a_plan.md`
   - 生态调研结论 + 路线 A（Hook 并行）实施计划。**当前主线。**
2. `docs/hook/hook_e2e_acceptance_guide.md`
   - 跑数命令参数、报告字段解释（含 `raw_batch_*`、`fallback_count`）。

## 当前阶段主线（强约束）
1. **主线回归 Hook 并行优化**：piggyback + TLS accessor 覆盖 → 并行 <1s。
2. 纯 HTTP 路线降为 P3 长期储备，不再作为冲刺目标。
3. 实施计划分 5 阶段，详见 `docs/ecosystem_research_and_route_a_plan.md` 第四节。

## 全量文档分类索引（完整）
查看：`docs/DOCS_REFERENCE_MAP.md`

## 快速选读（按问题）
1. 我只想知道下一步做什么：`docs/ecosystem_research_and_route_a_plan.md`
2. 我只想看这次是否达标：`docs/hook/hook_e2e_acceptance_guide.md`
3. 生态调研（其他项目怎么做的）：`docs/ecosystem_research_and_route_a_plan.md` 第一节
4. 想看 Hook 技术细节：`docs/hook/hook_comment_research.md`、`docs/hook/tls_crash_analysis.md`
5. 想看历史纯 HTTP 尝试：`docs/native_http_protocol_recon.md`、`docs/native_http_sender_design.md`
6. 想追溯旧方案与旧排障：`docs/archive/README.md`

