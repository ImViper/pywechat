# Route B Phase 0 验证总结报告

**日期**: 2026-02-12
**分支**: `viper/hook-comment`
**结论**: ❌ Route B 在 WeChat 4.1.7.30 上不可行

---

## 执行摘要

**目标**: 验证通过 Hook WeChat 的 `OnSnsTimeLineSceneFinish` 回调能否比 UI 刷新更早获取朋友圈数据（预期提速 2-3 秒）

**结果**: Hook 安装成功，但在 WeChat 4.1.7.30 中从未被触发，无法验证时间差。

**结论**: Route B 的核心前提（Hook 回调触发）未能实现，方案不可行。

---

## Phase 0 完整流程

### ✅ 成功的部分

1. **Hook DLL 开发**
   - 文件: `hook/src/sns_moments_poc.h`, `hook/src/sns_moments_poc.cpp`
   - 实现了 7 种签名模式的多签名扫描
   - 成功适配 MinHook
   - 编译通过，生成 DLL

2. **DLL 注入**
   - 成功注入到 WeChat 进程 (PID 44008)
   - Named Pipe 通信正常
   - Hook 状态查询正常

3. **签名匹配**
   - 签名 #1 匹配成功: `48 89 5C 24 ?? 57 48 83 EC 30 48 8B F9`
   - 函数地址: `0x7ff9271fd1fc`
   - 来源: wxhelper 3.9.5.81

4. **Hook 安装**
   - MinHook 报告: 成功
   - 日志确认: `[SNS_POC] Hook installed successfully!`

5. **测试工具开发**
   - `phase0_proper_refresh_test.py` - 单次刷新测试
   - `phase0_continuous_refresh.py` - 持续刷新测试 (2分钟)
   - `phase0_monitor_live.py` - 实时日志监控
   - `hook_log_utils.py` - 日志解析工具

### ❌ 失败的部分

**Hook 回调从未触发**

测试场景 | 刷新方法 | 新内容 | Hook 触发
---------|----------|--------|----------
单次测试 | 点击 RefreshButton | 未知 | ❌
持续测试 | 12 次刷新 (2分钟) | ✅ 有 | ❌
手动测试 | 多次下拉刷新 | ✅ 有 | ❌

---

## 根本原因分析

### 最可能的原因: WeChat 4.1.7.30 不再使用此函数

**证据**:
1. wxhelper 的签名来自 WeChat 3.9.5.81
2. 当前版本是 4.1.7.30 (大版本跨越)
3. 签名匹配成功 → 函数存在
4. 但函数从未被调用 → 可能已废弃

**推测**:
- 微信团队在 4.x 重构了朋友圈架构
- `OnSnsTimeLineSceneFinish` 可能被新的函数替代
- 或者刷新逻辑改为异步/后台执行

### 其他可能性（概率较低）

1. **签名匹配了错误的函数**
   - 概率低，wxhelper 经过验证
   - 但不能完全排除

2. **需要特殊条件才触发**
   - 可能需要特定类型的朋友圈内容
   - 或者首次打开、后台刷新等特殊场景

---

## 投入产出分析

### 已投入

- **时间**: ~2 小时（符合 Phase 0 预算）
- **代码**:
  - C++ Hook 实现: ~400 行
  - Python 测试工具: ~800 行
  - 文档: ~1000 行

### 潜在收益（如果成功）

- **时间提升**: 2-3 秒（13s → 10s）
- **提升比例**: ~15-23%

### 继续投入成本

如果选择深入逆向 WeChat 4.1.7.30:
- **时间**: 2-5 天
- **工具**: IDA Pro / Ghidra
- **技能**: 逆向工程、x64 汇编
- **成功率**: 不确定

---

## 与 Route A 对比

维度 | Route A (并发评论) | Route B (后台抓取)
-----|-------------------|-------------------
当前状态 | ✅ 已验证可行 | ❌ Phase 0 失败
实现难度 | ⭐⭐ 中等 | ⭐⭐⭐⭐ 很高
收益确定性 | ✅ 明确 (7.8s → 2-3s) | ❓ 不确定
风险 | 稳定性问题 | Hook 失效、反作弊
维护成本 | 低 | 高（每次微信更新）

---

## 决策建议

### ✅ 推荐: 放弃 Route B

**理由**:
1. **Phase 0 的目的就是快速验证** → 已验证不可行
2. **机会成本高** → 时间用于 Route A 更有价值
3. **风险收益不成正比** → 即使成功也只提速 2-3 秒

### 🎯 替代方案

1. **优化 Route A (Parallel Mode)**
   - 当前: Serial Mode 7.8 秒
   - 目标: Parallel Mode 2-3 秒
   - 重点: 稳定性优化

2. **优化其他瓶颈**
   - OCR 预热和模型选择
   - AI 推理优化（流式输出）
   - UI 自动化可靠性

3. **接受现状**
   - Serial Mode 7.8 秒已经不错
   - 专注于功能完善和稳定性

---

## 学习与收获

### 技术学习

1. **MinHook 使用**
   - 函数签名扫描
   - Hook 安装和回调
   - Named Pipe IPC

2. **逆向工程基础**
   - wxhelper 源码分析
   - 函数签名提取
   - 内存结构理解

3. **测试方法论**
   - Phase 0 快速验证的价值
   - 自动化测试工具开发
   - 失败也是有价值的数据

### 项目管理

1. **合理的 Phase 0 投入**
   - 2 小时快速验证
   - 避免了 2-5 天的深度投入

2. **及时止损的重要性**
   - 不陷入 sunk cost fallacy
   - 重新评估优先级

---

## 文件清单

### 文档

- `docs/route_b_phase0_summary.md` - 本文档
- `docs/phase0_conclusion.md` - 详细结论
- `docs/phase0_hook_trigger_analysis.md` - 触发机制分析
- `docs/phase0_final_verification.md` - 验证步骤

### Hook 代码

- `hook/src/sns_moments_poc.h`
- `hook/src/sns_moments_poc.cpp`
- `hook/CMakeLists.txt` (已修改)
- `hook/src/dllmain.cpp` (已修改)

### Python 测试工具

- `scripts/phase0_proper_refresh_test.py` - 正确的刷新测试
- `scripts/phase0_continuous_refresh.py` - 持续刷新测试
- `scripts/phase0_close_reopen_test.py` - 关闭重开测试
- `scripts/phase0_verify_hook_timing.py` - 时间验证
- `scripts/hook_log_utils.py` - 日志解析工具

### 其他

- `examples/phase0_timing_test.py` (已修改)
- `scripts/phase0_monitor_live.py` (已修改)
- `scripts/phase0_auto_test.py` (已修改)

---

## 下一步行动

### 立即行动 (今天)

1. ✅ 更新文档和任务状态
2. ✅ 提交所有改动到 git
3. ⏸️ 暂停 Route B 研究

### 短期 (本周)

1. 评估是否继续优化 Route A
2. 或专注于其他功能开发

### 长期 (可选)

如果未来有强烈需求：
1. 使用 IDA Pro 逆向 WeChat 4.1.7.30
2. 找到新的朋友圈刷新函数
3. 重新实施 Route B

但当前**不推荐**继续投入。

---

**结论**: Phase 0 达成了验证目的，虽然结果是否定的，但避免了更大的投入。这是一次成功的快速验证。
