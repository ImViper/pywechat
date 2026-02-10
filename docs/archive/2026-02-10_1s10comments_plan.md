 1 秒内 10 条评论 — 可行性分析与实现方案                                                                                                                                                                                                                                                         
  
 目标

 看到朋友圈后 1 秒内 发出 10 条评论。

 当前瓶颈

 - cgi_A_caller_2 是同步函数，单次调用阻塞 ~618ms（服务端往返）
 - 串行 10 次 = ~6.2s，不可能 <1s
 - 只能在 capture_thread 上调用（pipe_thread 崩溃）

 三条可行路径

 路径 A：并行调用 — 修复 pipe_thread 崩溃（最优）

 核心思路：如果能在任意线程调用 cgi_A_caller_2，就可以 10 线程并行，总耗时 ≈ 618ms。

 崩溃根因：RVA 0x3c5c70 处的辅助函数通过某种 thread-local 机制获取上下文对象，在非 WeChat 线程上返回 NULL → rcx=0x0 → NULL READ。

 之前的 TLS 复制实验只复制了标准 TLS (slots 0-63)，但崩溃未修复。这说明关键上下文在：
 1. 隐式 TLS (__declspec(thread)) — 存储在 TEB+0x58 (ThreadLocalStoragePointer) 指向的数组中
 2. FLS (Fiber Local Storage) — 通过 FlsGetValue/FlsSetValue 访问
 3. Qt 框架的 thread-local 单例 — 可能通过 QThreadStorage 或 thread_local 关键字

 新的诊断方案：

 1. 反汇编 RVA 0x3c5c70 — 用 Frida 读取该地址附近的指令，确定它是通过什么机制获取 thread-local 值的：
   - 如果是 gs:[0x58] → 隐式 TLS（__declspec(thread)）
   - 如果是 call FlsGetValue → FLS
   - 如果是 call TlsGetValue → 标准 TLS（但之前实验排除了）
   - 如果是 call 到某个 Qt 函数 → Qt thread-local
 2. 根据机制选择修复：
   - 隐式 TLS：读取 Weixin.dll 的 PE TLS Directory，获取 TLS index，然后从 capture thread 的 TEB 复制 TLS 数据块到新线程
   - FLS：枚举 FLS slots，从 capture thread 复制到新线程
   - Qt thread-local：在新线程上初始化 Qt 的 thread-local 对象
 3. 如果修复成功：创建 10 个工作线程，每个线程复制必要的 thread-local 上下文，并行调用 g_original_fn()

 预期性能：10 条并行 ≈ 618ms（单次网络往返时间）

 风险：
 - 反汇编分析可能复杂
 - 即使修复了 0x3c5c70 的崩溃，更深层可能还有其他 thread-local 依赖
 - 并行调用可能触发 WeChat 服务端限流

 ---
 路径 B：HTTP 直发 — 绕过客户端（最快但最复杂）

 核心思路：截获 WeChat 发送评论时的 HTTP 请求（protobuf + MMTLS），提取 session 信息，然后直接向微信服务端发请求。

 已知信息：
 - 端点：/cgi-bin/micromsg-bin/mmsnscomment
 - 协议：Protobuf 序列化 + MMTLS 加密
 - 消息类型：micromsg.SnsCommentRequest

 实现步骤：

 1. Hook 网络层 — 在 WSASend 或 MMTLS 加密前 hook，截获明文 protobuf 请求
 2. 解析 protobuf — 反序列化 SnsCommentRequest，理解字段含义
 3. 提取 session — 从请求中提取认证信息（session key、cookie、uin 等）
 4. 构造请求 — 用 Python 直接构造 protobuf 请求
 5. 发送 — 通过 MMTLS 或直接 HTTPS 发送到微信服务端

 预期性能：10 条并发 HTTP 请求 ≈ 200-500ms

 风险：
 - MMTLS 是微信自研加密协议，不是标准 TLS，可能无法绕过
 - Session 信息可能包含设备绑定、时间戳签名等防重放机制
 - 微信服务端可能检测异常请求模式
 - 工作量巨大（需要完整逆向 MMTLS + protobuf schema）

 ---
 路径 C：混合方案 — 批量入队 + 隐藏窗口触发（保底）

 核心思路：在 capture_thread 上串行调用，但通过 PostMessage 自触发消除 UI 依赖。

 预期性能：10 条串行 ≈ 6.2s（无法 <1s）

 这条路径无法满足 1s 目标，但作为保底方案仍有价值。

 ---
 推荐执行顺序

 路径 A（并行调用）
   ├── Step 1: 反汇编 RVA 0x3c5c70，确定 thread-local 机制
   │     ├── 隐式 TLS → Step 2a: PE TLS Directory + TEB 复制
   │     ├── FLS → Step 2b: FLS slot 复制
   │     └── Qt thread-local → Step 2c: Qt 初始化
   ├── Step 2: 在新线程上修复 thread-local 上下文
   ├── Step 3: 验证单线程调用成功
   ├── Step 4: 10 线程并行调用
   └── 成功 → 完成 ✅ (预期 ~618ms)

 如果路径 A 失败 →

 路径 B（HTTP 直发）
   ├── Step 1: Hook WSASend/MMTLS，截获明文请求
   ├── Step 2: 解析 protobuf schema
   ├── Step 3: 提取 session 信息
   ├── Step 4: Python 直发 HTTP 请求
   └── 成功 → 完成 ✅ (预期 ~200-500ms)

 路径 A 详细实现计划

 Step 1: 反汇编 RVA 0x3c5c70

 方法：用 Frida 或 DLL 内读取 Weixin.dll base + 0x3c5c70 处的指令字节，反汇编分析。

 DLL 侧新增 disasm_crash_site pipe 命令：
 - 读取 crash_rip 前后 64 字节
 - 返回原始字节（hex dump）
 - Python 侧用 capstone 反汇编

 或者更简单：在 pipe_server.cpp 新增 read_memory 命令，读取指定 RVA 处的 N 字节。

 Step 2: 根据反汇编结果修复

 2a. 如果是隐式 TLS (__declspec(thread))

 1. 读取 Weixin.dll PE 头的 IMAGE_TLS_DIRECTORY
 2. 获取 TLS index (AddressOfIndex)
 3. 在 hook 回调中：
    - 读取 capture thread 的 TEB+0x58 (ThreadLocalStoragePointer)
    - 用 TLS index 索引到 Weixin.dll 的 TLS 数据块
    - 保存数据块的地址和大小
 4. 在新线程调用前：
    - 分配同样大小的内存
    - 复制 capture thread 的 TLS 数据块
    - 修改新线程的 TEB+0x58 指向的数组中对应 index 的指针
 5. 调用 g_original_fn()
 6. 恢复原始 TEB 状态

 2b. 如果是 FLS

 1. 在 hook 回调中枚举 FLS slots (0-127)
 2. 记录非空 slot 的 index 和值
 3. 在新线程调用前：
    - 对每个非空 slot 调用 FlsSetValue(index, value)
 4. 调用 g_original_fn()
 5. 恢复原始 FLS 值

 Step 3: 并行调用架构

 // DLL 新增 sns_do_comment_parallel()
 BatchCommentResult sns_do_comment_parallel(
     const std::string& sns_id,
     const std::vector<std::string>& comments,
     const std::string& reply_to,
     int max_concurrency = 10);

 // 实现：
 // 1. 创建 N 个 std::thread
 // 2. 每个线程：复制 thread-local 上下文 → 调用 sns_do_comment() → 恢复
 // 3. 等待所有线程完成
 // 4. 收集结果

 Step 4: Python 侧

 pipe_server.cpp 新增 parallel_comment 命令：
 - 参数：sns_id, comments[], reply_to, max_concurrency
 - 调用 sns_do_comment_parallel()
 - 返回 BatchCommentResult

 hook_bridge.py 新增 send_parallel_comments() 方法。

 comment_dispatcher.py 的 post_batch_comments() 优先走 parallel_comment。

 ---
 修改文件清单
 ┌─────────────────────────────────┬────────────────────────────────────────────────────────┐
 │              文件               │                          改动                          │
 ├─────────────────────────────────┼────────────────────────────────────────────────────────┤
 │ hook/src/pipe_server.cpp        │ 新增 read_memory 命令（诊断用）+ parallel_comment 命令 │
 ├─────────────────────────────────┼────────────────────────────────────────────────────────┤
 │ hook/src/sns_comment.h          │ 新增 sns_do_comment_parallel 声明                      │
 ├─────────────────────────────────┼────────────────────────────────────────────────────────┤
 │ hook/src/sns_comment.cpp        │ 反汇编诊断 + thread-local 修复 + 并行调用实现          │
 ├─────────────────────────────────┼────────────────────────────────────────────────────────┤
 │ pyweixin/hook_types.py          │ 新增 ReadMemoryCommand, ParallelCommentCommand         │
 ├─────────────────────────────────┼────────────────────────────────────────────────────────┤
 │ pyweixin/hook_bridge.py         │ 新增 read_memory(), send_parallel_comments()           │
 ├─────────────────────────────────┼────────────────────────────────────────────────────────┤
 │ pyweixin/comment_dispatcher.py  │ post_batch_comments() 接入并行路径                     │
 ├─────────────────────────────────┼────────────────────────────────────────────────────────┤
 │ hook/tools/disasm_crash_site.py │ 新建：读取崩溃点字节 + capstone 反汇编                 │
 └─────────────────────────────────┴────────────────────────────────────────────────────────┘
 验证步骤

 1. 构建 DLL → 注入 → 手动评论触发 state_captured
 2. read_memory(rva=0x3c5c70, size=64) → 获取崩溃点字节
 3. capstone 反汇编 → 确定 thread-local 机制
 4. 实现修复 → 单线程验证 → 多线程验证
 5. 10 线程并行 → 记录总耗时