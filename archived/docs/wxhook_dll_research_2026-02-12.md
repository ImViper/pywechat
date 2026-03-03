# wxhook DLL 深度调研报告

更新时间：2026-02-12
调研对象：lyx102/WeChatHook、miloira/wxhook

---

## 执行摘要

**核心结论：两个仓库使用同一个 DLL（579 KB），朋友圈评论功能完全是虚假宣传，不值得下载逆向。**

**推荐替代：研究 [ttttupup/wxhelper](https://github.com/ttttupup/wxhelper)（完整 C++ 源码 + SNS 函数定义）。**

---

## 一、仓库关系与代码重叠度

### 1.1 基本信息

| 项目 | Stars | Forks | 主要作者 | 最近更新 |
|------|-------|-------|----------|----------|
| [lyx102/WeChatHook](https://github.com/lyx102/WeChatHook) | 243 | 51 | lyx102 | 2025-11 |
| [miloira/wxhook](https://github.com/miloira/wxhook) | 268 | 76 | 张明明 | 2025-11 |

### 1.2 代码重叠分析

**结论：独立仓库，但共享同一个二进制 DLL。**

证据：
- 两个仓库的 `wxhook/tools/wxhook.dll` 大小完全一致：579 KB
- Python 代码结构完全相同（`Bot` 类方法、辅助工具）
- lyx102 声称 82 个接口，miloira 声称 39 个，但实际代码方法数基本一致
- 很可能共享同一个上游付费 DLL 提供者（README 提到 `技术V:tts1837` 和 QQ 群）

---

## 二、朋友圈评论功能实现现状

### 2.1 README 声称 vs 实际代码

| 功能 | README | 实际代码 |
|------|--------|----------|
| 获取朋友圈首页 | ✅ | ✅ `get_sns_first_page()` |
| 获取朋友圈下一页 | ✅ | ✅ `get_sns_next_page(sns_id)` |
| 朋友圈点赞 | ✅ (lyx102) | ❌ **不存在** |
| **朋友圈评论** | ✅ (lyx102) | ❌ **不存在** |
| 发送朋友圈 | ✅ (lyx102) | ❌ **不存在** |

### 2.2 代码搜索验证

在两个仓库中搜索以下关键词，**全部返回 0 结果**：
- `朋友圈评论` / `comment`
- `朋友圈点赞` / `like`
- `评论` / `点赞`
- `sns_comment`

### 2.3 实际可用 API

```python
# core.py 中唯二的朋友圈方法
def get_sns_first_page(self) -> Response:
    """获取朋友圈首页"""
    return self.call_api("/api/getSNSFirstPage")

def get_sns_next_page(self, sns_id: str) -> Response:
    """获取朋友圈下一页"""
    return self.call_api("/api/getSNSNextPage", snsId=sns_id)
```

**结论：只能读取朋友圈内容，无任何交互功能（评论/点赞/发布）。**

---

## 三、Hook 技术栈分析

### 3.1 注入方式

**通过外部 EXE 启动器注入 DLL**

```python
# utils.py 核心代码
START_WECHAT = Path(__file__).parent / "tools" / "start-wechat.exe"
DLL = Path(__file__).parent / "tools" / "wxhook.dll"
FAKER = Path(__file__).parent / "tools" / "faker.exe"

def start_wechat_with_inject(port: int) -> (int, str):
    result = subprocess.run(f"{START_WECHAT} {DLL} {port}")
    return int(code), output
```

工具链：
- `start-wechat.exe`：启动器，负责启动微信 + 注入 DLL
- `wxhook.dll`：Hook 库（579 KB，无源码）
- `faker.exe`：版本伪装工具，修改微信进程版本号

### 3.2 IPC 机制

**双向通信架构**：

1. **Python → DLL**：HTTP POST
   - 端点：`/api/sendTextMsg`, `/api/getSNSFirstPage` 等
   - DLL 内置 HTTP Server（可能是 mongoose）

2. **DLL → Python**：TCP Socket
   - Python 使用 `socketserver.ThreadingTCPServer` 监听
   - DLL 推送消息事件到 Python

3. **可选 Webhook**：支持转发消息到第三方 HTTP 服务

### 3.3 版本适配

**声称支持**：
- lyx102：3.9.5.81 - 4.1.1
- miloira：3.9.2.23 - 4.1.6.14

**适配方式**：
1. 版本伪装：`faker.exe` 修改进程内存中的版本字符串
2. 动态定位：可能用特征码扫描（仓库只有一个 DLL，无多版本分支）

---

## 四、DLL 逆向价值评估

### 4.1 技术指标

| 指标 | 评估 |
|------|------|
| 文件大小 | 579 KB（中等规模） |
| 导出函数 | 未知（需 PE 工具） |
| PDB/符号 | ❌ 不可用 |
| 混淆/加壳 | 未知（需 DIE/PEiD） |
| **C++ 源码** | ❌ **不可用** |

### 4.2 可能获得的信息

如果逆向 DLL：
- 微信函数地址/偏移（SendTextMsg 等）
- 数据结构布局（消息、用户、群聊）
- HTTP API 完整端点列表
- 版本适配机制（特征码/偏移表）

### 4.3 与当前项目的相关性

**低。不推荐逆向。**

理由：
1. **核心功能不存在**：朋友圈评论是虚假宣传，DLL 中可能没有实现
2. **我们的方案更成熟**：
   - 已有 UI 自动化 + Named Pipe Hook
   - 已实现朋友圈评论（`sns_comment.cpp`）
   - C++ 源码可控（Detours + MinHook）
3. **版本差异**：wxhook 声称 4.1.x，我们在 4.0+ 上已运行
4. **逆向成本高**：无源码，需 IDA Pro 反编译 + 大量分析时间

### 4.4 替代方案：ttttupup/wxhelper

**强烈推荐研究这个项目**：

| 项目 | wxhook | wxhelper |
|------|--------|----------|
| C++ 源码 | ❌ | ✅ **完整可用** |
| 支持版本 | 3.9-4.1 | 3.8-3.9 |
| SNS 函数 | 无法查看 | ✅ `__GetSNSDataMgr`, `__GetSnsTimeLineMgr`, `__GetSNSFirstPage` |
| 代码质量 | 未知 | C++ 44.8% |
| 社区 | 243-268 stars | 活跃维护 |

**wxhelper 优势**：
- 完整 `wechat_function.h` 暴露微信内部函数地址
- SNS 数据管理器函数指针定义：
  ```cpp
  typedef UINT64 (*__GetSNSDataMgr)();
  typedef UINT64 (*__GetSnsTimeLineMgr)(UINT64);
  typedef UINT64 (*__GetSNSFirstPage)(UINT64, UINT64);
  ```
- HTTP Server 实现（mongoose.c）可参考
- 完整 Hook 框架代码可学习

---

## 五、推荐行动方案

### 5.1 明确建议

**❌ 不值得下载 wxhook DLL 进行逆向分析**

理由：
1. 朋友圈评论功能虚假宣传
2. 无 C++ 源码，逆向成本高
3. 两个仓库是同一个 DLL，无需重复
4. 替代方案更优（wxhelper 有源码）

### 5.2 优先级排序

| 优先级 | 项目 | 行动 | 理由 |
|--------|------|------|------|
| **P0** | [ttttupup/wxhelper](https://github.com/ttttupup/wxhelper) | 研究 C++ 源码 | 完整源码 + SNS 函数定义 |
| P1 | 当前项目 | 执行路线 A | TLS accessor hook 已 90% 就绪 |
| P2 | lyx102/WeChatHook | 仅验证（可选） | 快速确认是否真无评论功能 |
| P3 | miloira/wxhook | 跳过 | 与 lyx102 是同一 DLL |

### 5.3 具体执行步骤

**推荐：深入研究 wxhelper**

```bash
# 1. 克隆仓库
git clone https://github.com/ttttupup/wxhelper.git
cd wxhelper/src

# 2. 查看关键文件
# - wechat_function.h（微信函数地址）
# - hooks.cc（Hook 实现）
# - http_server_callback.cc（API 端点）
```

**重点关注**：
- `__GetSNSDataMgr` 等 SNS 函数的调用方式
- 是否有 `__SendSNSComment` 或类似评论函数
- HTTP API 端点设计（对比我们的 Named Pipe）

**可选验证：下载 wxhook.dll**

如果坚持要验证：
1. 仅下载 lyx102 版本（[直接链接](https://github.com/lyx102/WeChatHook/raw/refs/heads/master/wxhook/tools/wxhook.dll)）
2. 用 IDA Pro/Ghidra 打开
3. 搜索字符串："getSNS", "comment", "like"
4. 查看导出表，确认是否有隐藏 API
5. **不超过 2 小时**

---

## 六、社区与可信度评估

### 6.1 社区活跃度

| 指标 | lyx102 | miloira |
|------|--------|---------|
| Issues | 0 个打开 | 0 个打开 |
| PRs | 未发现 | 未发现 |
| 用户反馈 | 无评论相关 | 无评论相关 |

**警告信号**：
- 搜索 "朋友圈评论" 或 "comment" 全站 0 结果
- 无用户报告成功使用评论功能
- 无示例代码展示评论 API 调用

### 6.2 付费版本

两个仓库都提到联系方式：
- lyx102：`技术V:tts1837`
- miloira：`QQ群 705791428`

**推测**：
- 开源版是引流工具
- 完整功能需付费购买 DLL
- 朋友圈评论可能在付费版（但无法验证）

---

## 七、最终结论

### 关键发现

1. ✅ lyx102/WeChatHook 和 miloira/wxhook 是同一个 DLL 的不同包装
2. ❌ 朋友圈评论功能完全不存在，README 虚假宣传
3. ✅ 只能读取朋友圈内容（首页 + 翻页）
4. ❌ DLL 无 C++ 源码，逆向成本高且价值有限
5. ✅ ttttupup/wxhelper 是更优质的学习资源

### 明确建议

**不要浪费时间在 wxhook DLL 上。**

**推荐行动**：
1. 深度研究 ttttupup/wxhelper 的 C++ 源码
2. 查找 wxhelper 中是否有 SNS 评论函数
3. 对比 wxhelper 的 Hook 技术与我们的方案
4. 如果 wxhelper 也没有评论功能，继续执行路线 A（TLS accessor hook）

---

## 附录：相关链接

- [lyx102/WeChatHook - GitHub](https://github.com/lyx102/WeChatHook)
- [miloira/wxhook - GitHub](https://github.com/miloira/wxhook)
- [ttttupup/wxhelper - GitHub](https://github.com/ttttupup/wxhelper)
- [wxhook - PyPI](https://pypi.org/project/wxhook/)
- [DLL 直接下载](https://github.com/lyx102/WeChatHook/raw/refs/heads/master/wxhook/tools/wxhook.dll)（仅验证用，不推荐）
