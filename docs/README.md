# Docs Index

本目录按“核心文档 / 归档文档”维护，避免多份进度文档互相冲突。

## 核心文档（持续维护）

1. `docs/moments_rush_guide.md`：朋友圈监听、识别、评论主流程与运行手册。
2. `docs/hook_comment_research.md`：Hook 评论链路的架构与实现现状（代码对齐）。
3. `docs/hook_progress.md`：当前阶段进度、已完成项、待办与风险。
4. `docs/target_goal_gap.md`：最终目标（10 条 < 1 秒）与现实差距、验收口径。
5. `docs/hook_flow_overview.md`：当前链路流程图（端到端、发送分支、批量并发）。
6. `docs/tls_crash_analysis.md`：并行评论场景下的 TLS 崩溃根因分析与方案状态。
7. `docs/testing_dataset_guide.md`：统一测评入口与指标说明。
8. `docs/fork_sync_guide.md`：Fork 与上游同步规范。

## 归档文档（历史记录，不作为当前默认方案）

1. `docs/archive/hook_thread_diag_log_2026-02-10.md`：pipe_thread 崩溃诊断全过程日志。
2. `docs/archive/2026-02-10_1s10comments_plan.md`：2026-02-10 当日的 1 秒 10 条方案草案。
3. `docs/archive/external_repo_research_2026-02-09.md`：外部仓库调研记录。

## 维护约定

1. 架构设计与接口说明优先更新 `hook_comment_research.md`。
2. 阶段性状态与待办只在 `hook_progress.md` 维护，避免多份“进度文档”。
3. 目标差距与验收标准只在 `target_goal_gap.md` 维护。
4. 临时排障日志统一进入 `docs/archive/`。
