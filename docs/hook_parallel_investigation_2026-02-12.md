# Hook并发优化调查报告

**日期**：2026-02-12
**目标**：实现10条评论<1秒发送（通过并发执行）
**结果**：并发执行导致崩溃，当前使用Serial Mode稳定运行

---

## 执行摘要

**结论**：微信`cgi_A_caller_2`函数**不是线程安全**的，并发调用会导致DLL崩溃。当前推荐使用**Serial Mode (concurrency=1)**，性能为~750ms/条评论，10条评论约8秒。

**性能对比**：

| 模式 | 并发数 | 10条评论耗时 | 稳定性 | 成功率 |
|------|--------|--------------|--------|--------|
| **Serial** | 1 | ~7.8秒 | ✅ 稳定 | 100% (3/3轮) |
| Parallel | 2 | 崩溃 | ❌ 不稳定 | 0% |
| Parallel | 10 | 崩溃 | ❌ 不稳定 | 0% |

**原计划性能目标**：10条评论 < 1秒（理论：串行时间/并发数 + 开销 ≈ 5.6s/10 + 0.3s ≈ 0.9s）
**实际性能**：10条评论 ~7.8秒（Serial Mode）

---

## 实施过程

### 1. 初始假设

根据之前的研究（`docs/tls_crash_analysis.md`），Worker线程调用`hooked_tls_accessor`时返回NULL导致崩溃。假设通过**TLS override**可以解决。

### 2. 实现方案

**计划**：在`hooked_tls_accessor`中，Worker线程返回Capture线程缓存的TLS值。

**代码修改**：
- `hook/src/sns_comment.cpp`: 实现TLS override逻辑
- `hook/src/pipe_server.cpp`: 添加`set_config`命令（kill switch）
- `hook/src/sns_comment.h`: 导出TLS相关变量

### 3. 测试矩阵

| 测试 | TLS Override | Concurrency | 结果 | 说明 |
|------|--------------|-------------|------|------|
| Baseline | 禁用 | 1 | ✅ 3/3成功 | P95=7745ms，稳定 |
| Test 1 | 启用 | 1 | ✅ 3/3成功 | P95=7824ms，证明TLS override本身稳定 |
| Test 2 | 禁用 | 2 | ❌ 崩溃 | 管道已结束，DLL崩溃 |
| Test 3 | 启用 | 2 | ❌ 崩溃 | 超时33秒，DLL崩溃 |
| Test 4 | 启用+mutex | 2 | ❌ 崩溃 | 快速失败3秒，序列化访问仍崩溃 |
| Test 5 | 仅arg1 patch | 2 | ❌ 崩溃 | 不override TLS仍崩溃 |

### 4. 根本原因分析

#### 初步假设（错误）
- Worker线程TLS accessor返回NULL → 崩溃
- **反证**：Test 1证明concurrency=1时TLS override完全稳定

#### 深入分析
**加锁实验**（Test 4）：添加`std::mutex`序列化所有TLS accessor调用
- **结果**：仍然崩溃
- **说明**：问题不在TLS accessor并发访问，而在后续函数调用

#### 最终结论
**`cgi_A_caller_2`函数或其依赖项不是线程安全的**

可能原因：
1. 函数内部有未保护的全局状态（计数器、缓存等）
2. 依赖的网络层/序列化层有内部锁导致死锁
3. 内部引用计数或COM对象不支持多线程
4. TLS容器本身设计为单线程使用，跨线程共享导致内部状态混乱

---

## 当前解决方案：Serial Mode

### 工作流程

```
1. UI自动化发送第1条评论（触发hook）
   ↓
2. hook回调捕获运行时状态
   ↓
3. hook在同一回调中**串行**发送剩余9条评论
   ↓
4. 返回，总耗时~7.8秒
```

### 性能分析

**时间分解**（10条评论）：
- UI触发：~2.5-3秒（打开编辑器、粘贴、点击发送）
- Hook串行：~5秒（9条评论 × ~550ms/条）
- **总计**：~7.8秒

**与纯UI自动化对比**：
- 纯UI：~3秒/条 × 10 = 30秒
- Serial Mode：~7.8秒
- **加速比**：3.8×

### 稳定性

**验证结果**（3轮 × 10条评论）：
- Round 1: 10/10, 7772ms
- Round 2: 10/10, 7499ms
- Round 3: 10/10, 7387ms
- **P95**: 7745ms
- **成功率**: 100%

---

## 未来优化方向

### 方向1：Hook底层网络函数（中等难度）

**思路**：绕过业务层，直接Hook WSASend或protobuf序列化层

```
当前：Hook cgi_A_caller_2（业务层，不支持并发）
      ↓
替代：Hook WSASend/序列化层（网络层，可能支持并发）
```

**优点**：
- 网络层通常是线程安全的
- 可能支持真正并发
- 性能提升潜力大

**缺点**：
- 需要重新逆向分析网络协议
- 需要手动构造protobuf消息
- 更容易被微信检测（修改底层协议）

**预估工作量**：2-3周

### 方向2：复用微信内部线程池（高难度）

**思路**：找到微信内部的异步任务队列，将评论发送任务提交到微信自己的worker线程

**优点**：
- 使用微信自己的线程，理论上线程安全
- 不会引入新的线程安全问题

**缺点**：
- 需要深度逆向分析微信线程池实现
- 微信版本升级可能失效
- 难度极高

**预估工作量**：4-6周

### 方向3：多轮UI触发（低难度，低收益）

**思路**：UI快速连续触发多次，每次hook串行发送少量评论

```python
# 伪代码
for batch in chunks(comments, 3):  # 每批3条
    ui_send_comment(batch[0])  # UI触发
    # hook串行发送batch[1:2]
    sleep(1.5)

# 10条 = 4批 × 2.5秒 = 10秒
```

**优点**：
- 风险低，易实现
- 分散单次hook负担

**缺点**：
- 总耗时不变甚至更长
- UI触发次数增多，UI自动化失败风险增加

**预估工作量**：1-2天

---

## 技术细节

### TLS Override实现

**文件**：`hook/src/sns_comment.cpp`

```cpp
static void* __fastcall hooked_tls_accessor(int slot) {
    void* value = g_original_tls_accessor(slot);
    DWORD tid = GetCurrentThreadId();

    // Capture线程：缓存TLS值
    if (tid == g_capture_thread_id) {
        if (value && looks_like_user_pointer(value)) {
            g_capture_tls_accessor_value = value;
            g_capture_tls_accessor_ready = true;
        }
        return value;
    }

    // Worker线程：不override，返回原始值（通常为NULL）
    // arg1_ctx_helper会patch arg1->+0x368来提供context
    return value;
}
```

**关键发现**：
- TLS override本身在单线程下完全稳定
- 问题不在TLS，而在后续的并发函数调用
- 即使不override TLS，并发仍会崩溃

### Arg1 Context Patch

**文件**：`hook/src/sns_comment.cpp:985-1007`

```cpp
static void* __fastcall hooked_arg1_ctx_helper(void* arg1, ...) {
    if (t_piggyback_parallel_worker && arg1) {
        void* ctx = nullptr;
        // 优先级链：cached > tls_accessor > tls_slot
        if (g_cached_req_0x368_valid) {
            ctx = g_cached_req_0x368;
        } else if (g_capture_tls_accessor_ready) {
            ctx = g_capture_tls_accessor_value;
        } else if (g_capture_tls_slot_0x358_ready) {
            ctx = reinterpret_cast<void*>(g_capture_tls_slot_0x358_ptr);
        }

        if (ctx && looks_like_user_pointer(ctx)) {
            // Patch arg1->+0x368
            safe_copy_bytes((uint8_t*)arg1 + 0x368, &ctx, sizeof(ctx));
        }
    }
    return g_original_arg1_ctx_helper(arg1, ...);
}
```

**说明**：
- 在Serial Mode下，这个patch足够支持worker线程
- 但并发调用`cgi_A_caller_2`时，函数内部其他部分崩溃

---

## 配置说明

### 推荐配置

```python
# Python端
dispatcher = CommentDispatcher(
    hook_bridge=bridge,
    max_concurrency=1,  # 必须为1（Serial Mode）
    piggyback_timeout_ms=30000
)

results = dispatcher.dispatch_batch(
    sns_id=sns_id,
    comments=comments,
    reply_to="",
    backend="real",
    batch_mode="piggyback",
    concurrency=1  # 必须为1
)
```

### DLL配置

```cpp
// hook/src/sns_comment.cpp
bool g_tls_override_enabled = false;  // 建议保持禁用
```

**通过pipe动态配置**（仅用于调试）：
```python
bridge.send_command({
    "cmd": "set_config",
    "key": "tls_override_enabled",
    "value": False
})
```

---

## 附录：测试数据

### Serial Mode详细数据（3轮测试）

**测试环境**：
- 微信版本：4.1.7.30
- DLL版本：2026-02-12 14:52
- 并发数：1
- 评论数/轮：10

**Round 1**：
- 总耗时：7772ms
- Piggyback耗时：4872ms
- UI耗时：~2900ms
- 成功率：10/10

**Round 2**：
- 总耗时：7499ms
- Piggyback耗时：4773ms
- UI耗时：~2726ms
- 成功率：10/10

**Round 3**：
- 总耗时：7387ms
- Piggyback耗时：4641ms
- UI耗时：~2746ms
- 成功率：10/10

**统计**：
- 平均耗时：7552ms
- P95：7745ms
- P50：7499ms
- 平均每条评论：755ms
- Piggyback平均每条：~540ms

---

## 参考文档

- `docs/tls_crash_analysis.md` - TLS崩溃初步分析
- `docs/hook_progress.md` - Hook实现进度
- `docs/moments_rush_guide.md` - 朋友圈抢答指南
- `examples/run_hook_e2e_acceptance.py` - 端到端测试脚本
