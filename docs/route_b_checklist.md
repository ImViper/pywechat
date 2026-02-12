# Route B 实施进度 Checklist

## Phase 0: 去风险实验 ⏳ In Progress

**目标**: 验证 Hook 回调是否比 UI 刷新更早（2-4 小时）

### ✅ 已完成

- [x] 创建 `hook/src/sns_moments_poc.h` - PoC 头文件
- [x] 创建 `hook/src/sns_moments_poc.cpp` - PoC 实现（Hook 回调 + 日志）
- [x] 修改 `hook/CMakeLists.txt` - 添加新源文件
- [x] 修改 `hook/src/dllmain.cpp` - 调用 PoC 初始化
- [x] 创建 `examples/phase0_timing_test.py` - Python 时间对比测试脚本
- [x] 创建 `docs/phase0_execution_guide.md` - 执行指南

### ⚠️ 待完成（关键！）

- [ ] **提取函数签名** - 使用 IDA Pro 分析 WeChat 4.1.7.30 的 Weixin.dll
  - [ ] 搜索字符串锚点（`SnsTimeLineScene`, `OnSnsFinish`, `TimelineObject`）
  - [ ] 定位 `OnSnsTimeLineSceneFinish` 函数
  - [ ] 提取 16-24 字节签名（地址替换为 `??`）
  - [ ] 更新 `hook/src/sns_moments_poc.cpp` line 155
- [ ] **编译 Hook DLL**
  ```bash
  cd hook/build && cmake --build . --config Release
  ```
- [ ] **注入 + 验证**
  - [ ] Kill 微信并重启
  - [ ] 注入 DLL
  - [ ] 检查 `pywechat_hook.log` 是否有 `[SNS_POC]` 日志
  - [ ] 手动刷新朋友圈，验证回调被触发
- [ ] **运行 Python 测试**
  ```bash
  python examples/phase0_timing_test.py
  ```
- [ ] **分析结果 + 决策**
  - [ ] 如果平均提前 ≥2s → 继续 Phase 1
  - [ ] 如果平均提前 <1s → 重新评估 ROI
  - [ ] 如果更晚或同时 → 放弃 Route B

### 🚧 风险点

1. **函数签名提取困难** - WeChat 4.1.7.30 可能没有明显的字符串锚点
   - 缓解：使用 Frida 动态探测，或降级到 3.9.5.81
2. **偏移地址不正确** - wxhelper 的偏移是针对 3.9.5.81
   - 缓解：用 Frida hexdump param2 结构，试错调整
3. **Hook 回调不比 UI 更早** - Route B 核心假设失败
   - 缓解：如果失败，停止 Route B，改为其他方案

---

## Phase 1: Hook 回调实现 ⏸️ Not Started

**前置条件**: Phase 0 成功（平均提前 ≥2s）

**目标**: 实现完整的 Hook OnSnsTimeLineSceneFinish + 内存快照缓存（6-8 小时）

### 待完成

- [ ] **Step 1.1**: 确认 Phase 0 的函数地址和偏移正确
- [ ] **Step 1.2**: 创建 `hook/src/sns_moments.h` - 公开接口
- [ ] **Step 1.3**: 创建 `hook/src/sns_moments.cpp` - 完整实现（~300 行）
  - [ ] Hook 回调函数（解析 param2 结构）
  - [ ] 内存快照缓存（std::deque, max 10 条）
  - [ ] 去重逻辑（避免重复缓存）
  - [ ] SEH 异常处理
- [ ] **Step 1.4**: 修改 `hook/CMakeLists.txt` - 添加 `sns_moments.cpp`
- [ ] **Step 1.5**: 修改 `hook/src/dllmain.cpp` - 调用 `init_sns_moments_hook()`
- [ ] **验证**:
  - [ ] 编译 DLL
  - [ ] 注入微信
  - [ ] 检查 log 是否有 `[SNS_HOOK] OnSnsFinish called`
  - [ ] 确认能读取 post 的 sns_id 和 content

---

## Phase 2: Named Pipe 命令集成 ⏸️ Not Started

**目标**: 通过 Named Pipe 暴露内存快照给 Python（4-6 小时）

### 待完成

- [ ] **Step 2.1**: 修改 `hook/src/pipe_server.cpp` - 添加 `get_sns_snapshot` 命令
- [ ] **Step 2.2**: 修改 `pyweixin/hook_types.py` - 添加 `GetSNSSnapshotCommand`
- [ ] **Step 2.3**: 修改 `pyweixin/hook_bridge.py` - 添加 `get_sns_snapshot()` 方法
- [ ] **Step 2.4**: 创建 `examples/test_sns_snapshot.py` - 测试脚本
- [ ] **验证**:
  - [ ] Python 能调用 `bridge.get_sns_snapshot()`
  - [ ] 返回至少 1 条 post
  - [ ] content 字段包含中文文本
  - [ ] 无崩溃或超时

---

## Phase 3: Python 轮询监控器 ⏸️ Not Started

**目标**: 后台线程轮询快照，检测新帖子（4-6 小时）

### 待完成

- [ ] **Step 3.1**: 创建 `pyweixin/moments_monitor.py` - 轮询监控器（~150 行）
- [ ] **Step 3.2**: 创建 `pyweixin/wxid_mapping.py` - 备注名→wxid 映射
- [ ] **Step 3.3**: 创建 `examples/test_moments_monitor.py` - 测试脚本
- [ ] **验证**:
  - [ ] 监控器能检测到新帖子
  - [ ] 延迟 <2 秒
  - [ ] 能正确过滤 sender_id

---

## Phase 4: 性能验证 ⏸️ Not Started

**目标**: 验证 Route B 真实提速效果（2-4 小时）

### 待完成

- [ ] **Step 4.1**: 创建 `examples/benchmark_route_b.py` - 端到端性能测试
- [ ] **Step 4.2**: 运行 10 次测试，记录延迟
- [ ] **Step 4.3**: 分析结果
  - [ ] 平均延迟
  - [ ] P95 延迟
  - [ ] 最大/最小延迟
- [ ] **验证成功标准**:
  - [ ] ✅ 最低目标: 平均 <2s, P95 <2.5s（提速 ~1s）
  - [ ] ✅ 理想目标: 平均 <1s, P95 <1.5s（提速 ~2s）
  - [ ] ✅ 极限目标: 平均 <0.5s, P95 <1s（提速 ~3s）

---

## 关键文件清单

### C++ 侧（Hook DLL）

- [x] `hook/src/sns_moments_poc.h` - Phase 0 PoC 头文件
- [x] `hook/src/sns_moments_poc.cpp` - Phase 0 PoC 实现
- [ ] `hook/src/sns_moments.h` - Phase 1 完整头文件
- [ ] `hook/src/sns_moments.cpp` - Phase 1 完整实现
- [x] `hook/src/dllmain.cpp` - 已修改（PoC 初始化）
- [x] `hook/CMakeLists.txt` - 已修改（添加 PoC）
- [ ] `hook/src/pipe_server.cpp` - Phase 2 待修改

### Python 侧

- [ ] `pyweixin/hook_types.py` - Phase 2 待修改
- [ ] `pyweixin/hook_bridge.py` - Phase 2 待修改
- [ ] `pyweixin/moments_monitor.py` - Phase 3 待创建
- [ ] `pyweixin/wxid_mapping.py` - Phase 3 待创建

### 测试脚本

- [x] `examples/phase0_timing_test.py` - Phase 0 时间对比测试
- [ ] `examples/test_sns_snapshot.py` - Phase 2 测试
- [ ] `examples/test_moments_monitor.py` - Phase 3 测试
- [ ] `examples/benchmark_route_b.py` - Phase 4 性能测试

### 文档

- [x] `docs/phase0_execution_guide.md` - Phase 0 执行指南
- [ ] `docs/route_b_implementation_log.md` - 实施日志（待创建）

---

## 时间线（预计）

| Phase | 预计时长 | 状态 | 截止日期 |
|-------|---------|------|---------|
| Phase 0 | 2-4 小时 | ⏳ In Progress | Day 1 上午 |
| Phase 1 | 6-8 小时 | ⏸️ Pending | Day 1 下午 |
| Phase 2 | 4-6 小时 | ⏸️ Pending | Day 2 上午 |
| Phase 3 | 4-6 小时 | ⏸️ Pending | Day 2 下午 |
| Phase 4 | 2-4 小时 | ⏸️ Pending | Day 3 上午 |
| **总计** | **18-28 小时** | - | **2-3 天** |

---

## 决策点

### ✅ Phase 0 成功 → 继续

- 平均提前 ≥2s
- 开始 Phase 1-4

### ⚠️ Phase 0 部分成功 → 评估

- 平均提前 1-2s
- 评估 ROI，决定是否继续

### ❌ Phase 0 失败 → 停止

- 平均提前 <1s 或更晚
- 放弃 Route B，考虑其他方案

---

**当前状态**: Phase 0 代码已完成，等待用户提取函数签名并执行测试
**下一步**: 阅读 `docs/phase0_execution_guide.md`，开始 Phase 0 测试
