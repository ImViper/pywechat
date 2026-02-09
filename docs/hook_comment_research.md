# 朋友圈评论加速方案调研：UI 自动化 + Hook 混合架构

## 1. 背景与目标

### 1.1 当前状态

当前朋友圈自动评论全链路依赖 UI 自动化（pyautogui + pywinauto），经过多轮优化后单条评论端到端约 2.7s（含图片提取、OCR/AI 识别、评论发送），其中纯评论发送约 850ms：

```
评论发送耗时拆解（~850ms）：
├─ open_comment_editor:   ~430ms  (省略号菜单 300ms + 点击评论 50ms + 等待 80ms)
├─ paste_and_send_comment: ~420ms  (粘贴 30ms + 绿色按钮检测 200ms + 发送验证 190ms)
```

### 1.2 目标

评论发送从 ~850ms 降到 <100ms。监控/识别流程保持不变。

### 1.3 核心思路

**监控/识别保持 Python（已有流程不变），评论发送走 Hook DLL（毫秒级）**。Hook 不可用时自动回退到 UI 自动化。

---

## 2. 开源项目调研

### 2.1 调研范围

调研了以下 7 个主流微信自动化开源项目，重点关注是否支持朋友圈评论：

| 项目 | 技术方案 | 朋友圈评论 | 朋友圈读取 | 支持版本 | 状态 |
|------|---------|-----------|-----------|---------|------|
| **wxhelper** | MinHook + HTTP API | 无 | 有（首页/翻页） | 3.8~3.9 | 社区维护 |
| **WeChatFerry** | C++ + 多语言 SDK | 无 | 无 | 3.9+ | 活跃 |
| **ComWeChatRobot** | COM 接口 + DLL 注入 | 无 | 无 | 3.x | 停更 |
| **wxbot** | DLL 注入 + HTTP API | 无 | 无 | 3.9.8.25 | 低活跃 |
| **WeChatHook** | DLL 注入 | 未明确 | 有 | 3.9~4.1 | 社区维护 |
| **dify-on-wechat** | 协议库（gewechat 等） | 无 | 无 | 多版本 | 活跃(聊天) |
| **Gewechat** | iPad 协议 | 付费功能 | 付费功能 | iPad 协议 | 已归档 |

### 2.2 各项目详细分析

#### wxhelper（ttttupup/wxhelper）

最接近需求的项目。已实现 SNS 数据获取（`GetSNSFirstPage`、`GetSNSNextPage`），但**没有评论接口**。

核心代码参考价值：
```cpp
// manager.cc - SNS 数据获取的实现模式
INT64 Manager::GetSNSFirstPage() {
    UINT64 sns_data_mgr_addr = base_addr_ + offset::kSNSDataMgr;
    UINT64 sns_first_page_addr = base_addr_ + offset::kSNSGetFirstPage;
    func::__GetSNSDataMgr sns_data_mgr = (func::__GetSNSDataMgr)sns_data_mgr_addr;
    func::__GetSNSFirstPage sns_first_page = (func::__GetSNSFirstPage)sns_first_page_addr;
    UINT64 mgr = sns_data_mgr();
    INT64 buff[16] = {0};
    success = sns_first_page(mgr, reinterpret_cast<UINT64>(&buff), 1);
    return success;
}
```

**可参考点**：
- 基址 + 偏移量定位函数的模式（`base_addr_ + offset::kXxx`）
- SNS 数据管理器的获取方式（`kSNSDataMgr` 返回全局实例）
- 评论函数大概率在 `kSNSGetFirstPage` 附近的代码区域
- MinHook 框架的使用方式
- HTTP API 服务器的架构

#### wxbot（jwping/wxbot）

DLL 注入 + HTTP REST API + WebSocket 回调。不支持朋友圈任何功能（Issue #18 有人提需求未解决）。

**可参考点**：
- DLL 注入器实现
- HTTP API 服务器 + WebSocket 回调架构
- 消息拦截 Hook 的模式

#### Gewechat（Devo919/Gewechat）

iPad 协议方案，Java 实现。朋友圈功能是**付费模块**，开源版不包含。项目已因法律原因归档（2025.5.3）。

**不可参考**：已归档、付费闭源、iPad 协议非 PC Hook。

#### dify-on-wechat（hanfangyuan4396/dify-on-wechat）

chatgpt-on-wechat 的 fork，集成 Dify LLM 平台。面向聊天机器人，通道库（gewechat/ntchat/wechaty）均不支持朋友圈操作。

**不可参考**：定位完全不同。

#### WeChatHook（lyx102/WeChatHook）

支持最新版本（3.9~4.1.0.X），声称支持朋友圈功能，但具体评论能力未明确文档化。

**可参考点**：
- 4.0+ 版本的 Hook 兼容性方案
- offset 表的组织方式

### 2.3 调研结论

**朋友圈评论 Hook 在整个开源社区是空白。没有任何项目公开了可用的朋友圈评论接口。**

需要自行逆向微信评论函数。但 wxhelper 的 SNS 获取代码提供了有价值的参考：函数定位模式、Manager 实例获取方式、偏移量组织方式。

---

## 3. 混合架构设计

### 3.1 整体架构

```
Python 层 (不变)                          C++ DLL (新增)
┌─────────────────────────┐              ┌───────────────────────┐
│ run_feed_refresh_       │              │  sns_comment_hook.dll  │
│ listener.py             │              │                        │
│   ↓                     │              │  ┌──────────────────┐  │
│ moments_ext.py          │              │  │ PipeServer       │  │
│   监控/识别/图片提取    │              │  │  监听 JSON 命令  │  │
│   ↓                     │   Named      │  └────────┬─────────┘  │
│ comment_dispatcher.py   │───Pipe──────→│  ┌────────▼─────────┐  │
│   prefer Hook           │   JSON       │  │ SnsComment       │  │
│   fallback UI           │              │  │  调用微信内部函数 │  │
│   ↓ (回退时)            │              │  └────────┬─────────┘  │
│ comment_flow()          │              │           ↓             │
│   UI 自动化             │              │  WeChatWin.dll 原生    │
└─────────────────────────┘              └───────────────────────┘
```

### 3.2 数据流

```
帖子出现
  ↓
[Python] 轮询检测 → 解析作者/内容 → 图片提取 → OCR+AI 识别
  ↓
[Python] CommentDispatcher.post_comment(answer, author, content_hash)
  ↓
┌─ [尝试 Hook] ──→ HookBridge 管道发送 ──→ DLL 调用微信函数 ──→ 评论发出 (~10ms)
│
└─ [Hook 失败] ──→ comment_flow() UI 自动化 ──→ 评论发出 (~850ms)
```

### 3.3 新增文件

#### Python 端 (pyweixin/)

| 文件 | 职责 |
|------|------|
| `comment_dispatcher.py` | 统一评论入口：Hook 优先 + UI 回退 |
| `hook_bridge.py` | Named Pipe 客户端，与 DLL 通信 |
| `hook_types.py` | 通信协议类型（命令、响应、错误码） |

#### C++ DLL (hook/)

| 文件 | 职责 |
|------|------|
| `hook/CMakeLists.txt` | CMake 构建（VS2022 x86） |
| `hook/src/dllmain.cpp` | DLL 入口，启动初始化线程 |
| `hook/src/pipe_server.cpp` | Named Pipe 服务端，解析 JSON 命令 |
| `hook/src/hook_manager.cpp` | MinHook 封装，Hook SNS feed 加载以捕获 SNS ID |
| `hook/src/sns_comment.cpp` | 特征码扫描 + 调用微信评论函数 |
| `hook/src/sig_scanner.cpp` | 运行时特征码搜索 |
| `hook/injector/inject.py` | Python 注入器（CreateRemoteThread + LoadLibrary） |

### 3.4 通信协议

Named Pipe 路径：`\\.\pipe\pywechat_hook`

```json
// Python -> DLL: 发评论
{"cmd": "comment", "sns_id": "12345678901234", "content": "5男"}

// Python -> DLL: 查询帖子 SNS ID
{"cmd": "query_sns_id", "author": "小蔡", "content_hash": "abc123def"}

// Python -> DLL: 健康检查
{"cmd": "ping"}

// DLL -> Python: 响应
{"status": "ok", "error_code": 0, "message": "", "data": {}}
```

### 3.5 集成点

`moments_ext.py` 第 ~1614 行的评论发送分支：

```python
# 当前：直接 UI 自动化
posted = paste_and_send_comment(moments_window, answer, ...)

# 集成后：统一调度
dispatcher = CommentDispatcher(prefer_hook=True)
posted = dispatcher.post_comment(
    answer,
    author=target_author, content_hash=result['fingerprint'],  # Hook 路径
    moments_window=moments_window, content_item=selected_item, # UI 回退
)
```

---

## 4. 逆向工程方案（Phase 0 门控）

**这是整个方案的 go/no-go 决策点。** 如果评论函数无法定位或无法调用，方案终止。

### 4.1 工具链

| 工具 | 用途 |
|------|------|
| IDA Pro 8.x / Ghidra | 静态分析 WeChatWin.dll |
| x64dbg | 动态调试，断点追踪 |
| API Monitor | API 调用追踪 |
| Wireshark | 观察网络请求模式 |
| Process Monitor | 文件/注册表活动 |
| CheatEngine | 内存搜索辅助 |

目标文件：**WeChatWin.dll**（微信安装目录，通常 200-300MB，核心逻辑所在）

### 4.2 定位 SNS 评论函数

#### 策略 A：字符串交叉引用法（推荐首选）

1. IDA 加载 WeChatWin.dll，等待分析完成
2. Strings 窗口搜索以下关键字符串：
   - `"/cgi-bin/micromsg-bin/mmsns"` — SNS 相关 CGI 路径
   - `"SnsComment"` 或 `"sns_comment"` — 函数名日志
   - `"snsId"` 或 `"sns_id"` — 帖子 ID 字段
   - `"comment"` + `"content"` 组合
   - `"MMSnsComment"` — Obj-C 风格类名残留
   - `"OpLog"` / `"oplog"` — 微信操作日志
   - `"addcomment"` — 可能的函数名
3. 对每个命中字符串做交叉引用（Xref），追踪到引用它的函数
4. 从 caller 链往上追溯，找到发送评论的高层业务函数

#### 策略 B：网络断点回溯法

1. x64dbg 附加微信进程
2. 在 `send` / `WSASend` 等网络发送函数设断点
3. 手动在朋友圈发一条评论
4. 断点命中时回溯调用栈：
   ```
   send / WSASend
     ← 网络封包层
       ← protobuf 序列化层
         ← SnsComment 业务逻辑层  ← 目标
           ← UI 事件处理层
   ```

#### 策略 C：参考 wxhelper 锚点法

wxhelper 已定位了以下 SNS 相关函数偏移：
- `offset::kSNSDataMgr` — SNS 数据管理器
- `offset::kSNSGetFirstPage` — 获取首页
- `offset::kSNSTimeLineMgr` — 时间线管理器
- `offset::kSNSGetNextPageScene` — 获取下一页

评论函数大概率在这些函数附近的代码区域。可以：
1. 在 wxhelper 支持的版本（3.9.5.81）上先找到评论函数
2. 提取特征码
3. 用特征码在目标版本上重新定位

#### 策略 D：虚函数表遍历

微信 SNS 模块通常有一个 Manager 类（如 `CSNSDataMgr` 或 `MMSnsService`），通过 `kSNSDataMgr` 获取实例。该类的虚函数表中通常包含 `Comment`、`Like`、`Delete` 等操作。

### 4.3 需要确认的关键信息

| 信息 | 说明 | 重要性 |
|------|------|--------|
| 评论函数地址 | WeChatWin.dll 中的偏移量 | 必须 |
| 调用约定 | `__fastcall`（x64 默认）或 `__thiscall` | 必须 |
| 参数列表 | 通常 3-4 个：this 指针、SNS ID、评论内容、回复目标 | 必须 |
| SNS ID 类型 | uint64 还是结构体 | 必须 |
| 评论数据格式 | protobuf buffer 还是 C++ struct | 必须 |
| Manager 实例获取 | 全局函数还是单例模式 | 必须 |
| 特征码 | 函数前 20-30 字节机器码 | 用于跨版本定位 |

### 4.4 SNS ID 获取方案

评论函数需要帖子的 SNS ID 作为参数。推荐方案：

**方案 A（推荐）：Hook SNS feed 加载函数**

Hook 微信加载朋友圈 feed 的函数（参考 wxhelper 的 `kSNSGetFirstPage`），当新帖子出现时记录其 SNS ID。DLL 内部维护映射表：

```
(author + content_hash) → sns_id
```

Python 端通过管道发送 `query_sns_id` 命令查询。

**方案 B：从内存中直接读取**

找到 SNS 数据管理器的全局实例（通过 `kSNSDataMgr`），遍历其内部数据结构获取当前可见帖子的 SNS ID。

### 4.5 验证流程

1. 在 x64dbg 中定位到候选函数
2. 设断点，手动发评论，观察参数值
3. 确认参数布局后，手动构造参数调用函数
4. 验证评论是否成功出现在朋友圈中
5. 提取特征码，在不同版本上验证可复用性

### 4.6 特征码格式

```
示例特征码（x64）：
"48 89 5C 24 ?? 48 89 74 24 ?? 57 48 83 EC 30 48 8B F9 48 8B DA"

?? = 通配符，跳过可能变化的字节（相对偏移等）
```

---

## 5. 分阶段实施计划

### Phase 0: 逆向研究 [门控点]

| 步骤 | 工作 | 产出 |
|------|------|------|
| 0.1 | IDA 加载 WeChatWin.dll，字符串搜索定位 SNS 函数群 | 候选函数列表 |
| 0.2 | x64dbg 动态调试，手动发评论触发断点，确认函数和参数 | 函数签名 |
| 0.3 | 确认评论数据结构（protobuf / struct） | 数据格式文档 |
| 0.4 | 定位 SNS feed 加载函数，确认 SNS ID 获取路径 | SNS ID 方案 |
| 0.5 | 提取特征码，跨版本验证 | 特征码表 |
| 0.6 | 手动调用评论函数，验证评论发出 | 验证日志 |
| **决策** | **如果函数无法定位/调用 → 方案终止，继续优化 UI 路径** | |

### Phase 1: 最小可行 DLL

| 步骤 | 工作 | 产出 |
|------|------|------|
| 1.1 | CMake 项目 + MinHook + DLL 骨架 | 可编译 DLL |
| 1.2 | 特征码扫描器 | sig_scanner.cpp |
| 1.3 | SNS 评论调用 | sns_comment.cpp |
| 1.4 | Named Pipe 服务器（ping + comment） | pipe_server.cpp |
| 1.5 | Python 注入器 | inject.py |
| 1.6 | 端到端测试 | 测试日志 |

### Phase 2: Python 桥接层

| 步骤 | 工作 | 产出 |
|------|------|------|
| 2.1 | `hook_types.py` 类型定义 | 协议文件 |
| 2.2 | `hook_bridge.py` Pipe 客户端 | 桥接层 |
| 2.3 | `comment_dispatcher.py` 统一调度 | 调度器 |
| 2.4 | 集成到 `moments_ext.py` | 修改后代码 |

### Phase 3: SNS ID 自动获取

| 步骤 | 工作 | 产出 |
|------|------|------|
| 3.1 | DLL 中 Hook SNS feed 加载 | hook_manager 更新 |
| 3.2 | SNS ID 缓存 + query 命令 | pipe_server 更新 |
| 3.3 | Python 端集成 | hook_bridge 更新 |
| 3.4 | 端到端测试 | 完整流程日志 |

### Phase 4: 健壮性

| 步骤 | 工作 | 产出 |
|------|------|------|
| 4.1 | DLL 内评论频率限制（最小 200ms） | 风控逻辑 |
| 4.2 | 异常处理（`__try/__except` 防崩溃） | 错误处理 |
| 4.3 | Hook 失效自动检测和回退 | 降级逻辑 |
| 4.4 | 微信更新适配流程文档 | 维护文档 |

---

## 6. 风险评估

### 6.1 技术风险

| 风险 | 概率 | 影响 | 应对 |
|------|------|------|------|
| 评论函数逆向不出来 | 中 | 方案不可行 | Phase 0 门控，失败则继续 UI 路径 |
| 微信更新导致偏移变化 | 高 | Hook 失效 | 特征码扫描；失效自动回退 UI |
| DLL 崩溃致微信闪退 | 中 | 体验差 | `__try/__except` 保护；崩溃时卸载 hook |
| 微信 4.0+ 反注入 | 中 | DLL 加载失败 | 延迟注入；manual map；绕不过则放弃 |
| 评论数据格式变化 | 低 | 评论失败 | 参数校验；版本检测 |

### 6.2 风控风险

| 风险 | 概率 | 影响 | 应对 |
|------|------|------|------|
| 评论频率过高 | 中 | 被限制/封号 | DLL 内置最小间隔 200ms |
| DLL 注入被检测 | 低~中 | 封号 | 延迟注入；DLL 名伪装 |
| 评论行为异常 | 低 | 被标记 | Hook 走原生通道，行为与正常评论一致 |

### 6.3 工程风险

| 风险 | 概率 | 影响 | 应对 |
|------|------|------|------|
| C++ 开发周期超预期 | 中 | 延期 | Phase 0 为门控点 |
| 维护成本高 | 高 | 长期负担 | UI 路径始终保留兜底 |

---

## 7. 预期性能

| 路径 | 单条评论延迟 | 说明 |
|------|------------|------|
| Hook 路径（目标） | ~10ms | 管道通信 2ms + 微信内部调用 5ms + 开销 3ms |
| Hook + SNS ID 查询 | ~15ms | 额外管道往返 5ms |
| UI 自动化（当前） | ~850ms | 菜单 300ms + 检测 200ms + 验证 350ms |
| UI 自动化（含预打开） | ~420ms | 编辑器预打开省去菜单步骤 |

---

## 8. 技术选型总结

### 8.1 Hook 框架选择：MinHook

| 方案 | 优点 | 缺点 | 选择 |
|------|------|------|------|
| **MinHook** | 开源免费、轻量、x86/x64、wxhelper 已验证 | 仅用户态 | **选用** |
| Detours | 微软官方、稳定 | 商业许可 | 备选 |
| Frida | 脚本化、跨平台、调试方便 | 运行时环境大、性能略低 | 仅用于调研阶段 |

### 8.2 通信方式选择：Named Pipe

| 方案 | 延迟 | 可靠性 | 复杂度 | 选择 |
|------|------|--------|--------|------|
| **Named Pipe** | ~2ms | 高 | 中 | **选用** |
| 共享内存 | <1ms | 中（需同步） | 高 | 不选 |
| HTTP API | ~10ms | 高 | 中 | 不选（wxhelper 方案，延迟偏高） |
| WM_COPYDATA | ~3ms | 中 | 低 | 备选 |

### 8.3 注入方式选择：CreateRemoteThread

| 方案 | 隐蔽性 | 实现难度 | 兼容性 | 选择 |
|------|--------|---------|--------|------|
| **CreateRemoteThread** | 中 | 低 | 高 | **选用** |
| SetWindowsHookEx | 较好 | 中 | 中 | 备选 |
| Manual Map | 高 | 高 | 中 | 仅反注入时考虑 |

---

## 9. 附录：参考项目链接

| 项目 | 链接 | 参考价值 |
|------|------|---------|
| wxhelper | https://github.com/ttttupup/wxhelper | SNS 函数定位模式、MinHook 使用、偏移量组织 |
| WeChatHook | https://github.com/lyx102/WeChatHook | 4.0+ 版本兼容、offset 表 |
| wxbot | https://github.com/jwping/wxbot | DLL 注入器、HTTP API 架构 |
| WeChatFerry | https://github.com/lich0821/WeChatFerry | C++ + Python SDK 混合架构 |
| ComWeChatRobot | https://github.com/ljc545w/ComWeChatRobot | COM 接口封装方案 |
| dify-on-wechat | https://github.com/hanfangyuan4396/dify-on-wechat | 通道抽象层设计（无 SNS） |
| Gewechat | https://github.com/Devo919/Gewechat | 已归档，iPad 协议方案（朋友圈付费） |
| MinHook | https://github.com/TsudaKageworthy/minhook | Hook 框架 |

---

## 10. 关键结论

1. **朋友圈评论 Hook 在开源社区是空白**，没有任何项目提供可用接口，需要自行逆向。
2. **Phase 0（逆向研究）是整个方案的 go/no-go 门控点**，建议优先投入。
3. wxhelper 的 SNS 获取代码是最有价值的参考，评论函数大概率在其附近代码区域。
4. UI 自动化路径始终保留作为兜底，确保 Hook 方案失败时不影响现有功能。
5. 当前的 UI 自动化方案已经是开源社区中对朋友圈评论支持最完整的实现。
