# pipe_thread 崩溃诊断 — 排查日志

## 背景

`sns_do_comment()` 在 pipe_thread 上调用 `cgi_A_caller_2` 时 100% 触发 `0xC0000005`。
本次实现了分层诊断基础设施（VEH 崩溃地址捕获、TLS 对比、arg1 模式实验），并尝试端到端验证。

---

## 2026-02-10 实施记录

### 1. 代码修改（已完成，编译通过）

**修改文件：**
- `hook/src/dllmain.cpp` — pipe thread 启动前加 `CoInitializeEx(NULL, COINIT_APARTMENTTHREADED)`
- `hook/src/sns_comment.h` — `CommentResult` 新增 9 个 VEH 崩溃诊断字段 + `arg1_mode`；新增 `ThreadDiagResult` 结构体
- `hook/src/sns_comment.cpp` — VEH handler (`diag_veh`)、TLS 收集（hook 回调中）、arg1_mode 四种模式、`diagnose_thread_context()`
- `hook/src/pipe_server.cpp` — `comment` 命令新增 `arg1_mode` 参数 + 崩溃诊断字段；新增 `diagnose_thread` 命令
- `hook/CMakeLists.txt` — 链接 `ole32` + `user32`
- `hook/tools/thread_diag_probe.py` — 新建诊断脚本

**编译结果：** `cmake --build hook/build_opt10 --config Release` 成功，仅 C4819 中文编码警告。
**单元测试：** 26/26 全部通过（test_hook_types 12, test_comment_dispatcher 12, test_hook_injector 2）。

### 2. DLL 注入

- WeChat PID: 55156，版本 4.1.7.30
- 注入路径: `H:\Code\pywechat\hook\build_opt10\bin\Release\pywechat_hook.dll`
- 注入成功，`is_dll_loaded()` = True
- Pipe 通信正常: `ping=True`, `version=4.1.7.30`
- DLL 日志位置: `C:\Program Files\Tencent\Weixin\4.1.7.30\pywechat_hook.log`

### 3. DLL 初始化日志

```
[11:24:01.447] pywechat_hook loaded, init starting
[11:24:01.448] WeChat version: 4.1.7.30
[11:24:01.448] version 4.1.7.30 matched, using hardcoded RVA: 0x7ffcd1739240
[11:24:01.448] vtable @ 0x7ffcd52ee6d8 (hardcoded RVA)
[11:24:01.488] comment hook installed @ 0x7ffcd1739240
[11:24:01.488] COM init on pipe thread: ok (hr=0x0)
[11:24:01.488] pipe server starting on \\.\pipe\pywechat_hook
```

- Weixin.dll base = `0x7ffcccd50000`（从 vtable 地址反推: `0x7ffcd52ee6d8 - 0x0859e6d8`）
- 目标函数地址 = `0x7ffcccd50000 + 0x049e9240 = 0x7ffcd1739240` ✅
- COM 初始化成功 (hr=0x0, STA 模式) ✅
- Hook 安装成功 ✅

### 4. 状态查询

```json
{
  "hook_installed": true,
  "state_captured": false,
  "context_fresh": false,
  "capture_age_ms": 0,
  "capture_thread_id": 0,
  "request_template_ready": false,
  "arg1_template_ready": false
}
```

**关键问题：`state_captured` 始终为 false，hook 回调从未触发。**

### 5. UI 自动化评论测试

通过 `moments_ext.comment_flow()` 发送了 **3 条** 评论（"ok", "test2", "hi3"），全部成功：
- 编辑器打开成功（`comment_button.exists=True`）
- 文本粘贴成功
- 回车发送，编辑器关闭（`editor closed after send=True`）

**但所有 3 条评论均未触发 hook 回调。** 10 秒持续轮询 `state_captured` 仍为 false。

### 6. Hook Detour 内存验证

用 `ReadProcessMemory` 读取目标函数地址 `0x7ffcd1739240` 的前 16 字节：

```
e9 8e 7d 60 fb 41 55 41 54 56 57 53 48 81 ec 38
```

- 字节 0: `E9` = JMP near (相对跳转) ✅
- JMP 目标: `0x7ffcd1739240 + 5 + 0xfb607d8e = 0x7ffcccd40fd3` (MinHook relay buffer)
- 字节 5-11: `41 55 41 54 56 57 53` = 原始函数字节（push r13/r12/rsi/rdi/rbx）
- **结论: MinHook detour 已正确安装在函数入口**

### 7. Eject 尝试

- `eject_dll(pid)` 调用后 `is_dll_loaded` 仍返回 True
- 原因: DLL 引用计数 > 1（可能多次注入或内部引用）
- 重新注入后 hook 仍活跃，但 state_captured 仍为 false

---

## 当前阻塞问题

**Hook detour 已安装但 `cgi_A_caller_2` 函数从未被 WeChat 调用。**

### 可能原因（按概率排序）

1. **WeChat 评论走了不同的代码路径**
   - 朋友圈列表模式评论可能不经过 `cgi_A_caller_2`
   - 可能走了更上层的 `cgi_A_caller_3_TOP`（RVA `0x049bdc10`）或更底层的 CGI 路径
   - 原始 Frida PoC 可能在不同的 UI 状态下测试的

2. **评论提交是异步的**
   - UI 编辑器关闭 ≠ 立即调用评论函数
   - 评论可能被放入内部队列，由另一个线程/机制延迟处理
   - 但 10 秒轮询仍未触发，排除短期延迟

3. **MinHook relay 地址无效**
   - JMP 目标 `0x7ffcccd40fd3` 在 Weixin.dll base 之前 `0xF02D` 字节
   - 需验证这个地址是否是有效的 MinHook trampoline
   - 如果 relay 内存被释放/覆盖，调用会崩溃但不会到达我们的 hook

4. **函数在此版本已被内联/优化掉**
   - 编译器可能将 `cgi_A_caller_2` 内联到其调用者中
   - 虽然函数体仍存在（signature 匹配），但实际调用走了内联版本

5. **评论实际未发送成功**
   - UI 编辑器关闭可能不代表评论真的提交了
   - 需要在朋友圈页面确认评论是否显示

### 下一步排查方向

1. **验证 MinHook relay 有效性**
   - 读取 JMP 目标 `0x7ffcccd40fd3` 处的字节
   - 确认是 `FF 25` 间接跳转到我们的 DLL 地址空间

2. **验证评论是否真的提交成功**
   - 刷新朋友圈页面，检查 "ok"/"test2"/"hi3" 是否显示

3. **尝试 hook 上层函数 `cgi_A_caller_3_TOP`**
   - RVA `0x049bdc10`
   - 这是调用链最顶层入口，可能是实际被调用的函数

4. **用 Frida 动态确认当前评论代码路径**
   - 在 `cgi_A_caller_2` 和 `cgi_A_caller_3_TOP` 同时设断点
   - 发送评论，观察哪个被触发

5. **检查 MinHook 内部状态**
   - 添加日志到 `MH_EnableHook` 之后，确认 hook 状态
   - 或直接在 hook 函数入口加一个 `OutputDebugStringA` 避免依赖 spdlog

---

## 2026-02-10 第二轮排查（hook 触发 + VEH 崩溃诊断）

### 8. 修正：之前 hook 未触发是因为评论未正确发送

之前的 UI 评论使用了 Enter 键发送，但 WeChat 朋友圈评论不响应 Enter，需要通过点击发送按钮（使用 `anchor_source` 定位）。

修正后，通过 `comment_flow()` + `anchor_source=TimelineCommentCell` 正确发送评论后：
- `state_captured: True`
- `arg1_template_ready: True` ← 真实运行时数据
- `capture_thread_id: 48144`
- `latest_sns_id: q756627124`
- `capture_age_ms` 从 541962ms 骤降到 2147ms → **hook 确认被触发**

### 9. pipe_thread VEH 崩溃诊断结果

**Weixin.dll base = `0x7ffcccd50000`**

#### arg1_mode=template (使用捕获的 arg1 模板)
| 字段 | 值 |
|------|-----|
| seh_code | `0xc0000005` |
| crash_rip_rva | **`0x3c5c70`** |
| fault_addr | **`0x0`** (NULL READ) |
| rcx | `0x0` |
| rdx | `0x5000f` |
| r8 | `0xfffffffffffe5001` |
| rsp | `0x28ec4fc2f0` |

#### arg1_mode=null (arg1=nullptr)
| 字段 | 值 |
|------|-----|
| seh_code | `0xc0000005` |
| crash_rip_rva | **`0x49e9273`** (函数入口 +0x33) |
| fault_addr | **`0x10`** (WRITE) |
| rcx | `0x28ec4fd860` (request struct 地址) |
| rdx | `0x0` |

#### arg1_mode=zeroed (arg1=全零 buffer)
| 字段 | 值 |
|------|-----|
| seh_code | `0xc0000005` |
| crash_rip_rva | **`0x3c5c70`** (同 template) |
| fault_addr | **`0x0`** (NULL READ) |
| rcx | `0x0` |

#### arg1_mode=captured_ptr (使用原始捕获的指针)
| 字段 | 值 |
|------|-----|
| seh_code | `0xc0000005` |
| crash_rip_rva | **`0x3c5c70`** (同 template) |
| fault_addr | **`0x0`** (NULL READ) |
| rcx | `0x0` |

### 10. Thread diagnostics (TLS/COM/GUI 对比)

| 指标 | Capture Thread (48144) | Pipe Thread (43348) |
|------|----------------------|-------------------|
| TLS 非空槽位数 | **10** | **1** |
| 独有 TLS 槽位 | [1, 3, 9, 27, 28, 37, 38, 40, 51] | — |
| COM 初始化 | — | True |
| IsGUIThread | **True** | **False** |

### 11. 崩溃根因分析

1. **template / zeroed / captured_ptr 三种模式崩溃点相同** (`0x3c5c70`)，而 **null 模式崩在函数入口** (`0x49e9273`)：
   - null 模式: 函数一入口就要写 `arg1+0x10`，arg1=NULL 所以崩 → arg1 结构必须有效
   - 其他模式: arg1 有效但函数执行到 `0x3c5c70` 时 rcx=0 → 通过 TLS 获取某个上下文返回了 NULL

2. **RVA `0x3c5c70` 不在 `cgi_A_caller_2` 内部** (caller2 在 `0x49e9240`)，而是在 Weixin.dll 更底层的辅助函数中。这是评论提交链路中的一个被调用函数，它尝试通过 TLS 查找线程上下文。

3. **TLS 差异巨大**: capture thread 有 10 个非空 TLS 槽，pipe thread 只有 1 个。9 个缺失的 TLS 槽中，某个（或某些）包含了 WeChat 的线程上下文对象，被 `0x3c5c70` 处的代码所依赖。

4. **IsGUIThread 差异**: capture thread 是 GUI 线程，pipe thread 不是。这也可能影响消息循环和 COM 调度。

### 下一步：TLS 复制实验

需要将 capture thread 的 TLS 值复制到 pipe thread，验证是否能解决崩溃：
1. 逐个复制 9 个缺失 TLS 槽的值到 pipe thread
2. 调用 cgi_A_caller_2
3. 调用后恢复原始 TLS 值

如果成功，可通过二分法定位关键 TLS 槽位，实现固定修复。

---

## 2026-02-10 第三轮：TLS copy 实验 + capture_thread 验证

### 12. TLS copy 实验结果

在 `sns_do_comment()` 中实现了 `tls_copy` 参数：
- 在调用前将 capture thread 的 9 个 TLS 槽位值复制到 pipe thread
- 调用后恢复原始值

| 模式 | 结果 | crash_rip_rva | fault_addr |
|------|------|---------------|------------|
| template, **no** TLS copy | CRASH | `0x3c5c70` | `0x0` (NULL READ) |
| template, **TLS copy** | CRASH | `0x3c5c70` | `0x0` (NULL READ) |

**结论：标准 TLS 槽位（TlsGetValue/TlsSetValue）的复制无法解决问题。**

崩溃位置 (`0x3c5c70`) 完全相同，说明关键的线程上下文不在标准 TLS (slots 0-63) 中。可能的原因：
1. `__declspec(thread)` 隐式 TLS — 存储在 TEB 的不同位置（TEB+0x2C TLS expansion slots）
2. Fiber Local Storage (FLS)
3. 某些 WeChat/Qt 内部的线程局部单例（通过其他机制而非 TLS API）

### 13. capture_thread 模式验证

| 模式 | 结果 | Latency |
|------|------|---------|
| **capture_thread** | **SUCCESS** | **618ms** |

capture_thread 模式工作流程：
1. Python 发送 `execution_mode=capture_thread` 请求
2. DLL 将 job 入队到 `g_capture_thread_jobs`
3. 需要一次 UI 评论来触发 hook 回调
4. hook 回调在 WeChat 工作线程上消费 job，调用 `sns_do_comment()`
5. 因为在正确的线程上，函数正常执行并返回

### 14. 最终结论

**pipe_thread 直接调用不可修复**（至少在不做更深层的逆向分析的情况下）。

**采用 capture_thread 作为正式方案**：
- 每次评论需要一次 UI 触发（click send button）来激活 hook 回调
- hook 回调在正确线程上执行待发评论队列中的所有 job
- 单次触发可执行多条评论（批量模式）
- latency ~618ms（函数执行时间），加上 UI 触发的等待时间

