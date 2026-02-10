# CLAUDE.md — 开发规范

## 项目概况

本仓库 fork 自 [Hello-Mr-Crab/pywechat](https://github.com/Hello-Mr-Crab/pywechat)，是微信 4.0 的 Windows UI 自动化库。我们在此基础上扩展朋友圈自动抢答、rush 引擎等能力。

## 核心原则：不侵入 upstream 代码

upstream 文件（原作者代码）只做最小化 bug fix，**不做功能增强、不做重构、不改风格**。

### upstream 文件清单（不可随意修改）

- `pyweixin/WeChatAuto.py`
- `pyweixin/WeChatTools.py`
- `pyweixin/Uielements.py`
- `pyweixin/Errors.py`
- `pyweixin/Config.py`
- `pyweixin/WinSettings.py`
- `pyweixin/utils.py`
- `pyweixin/Warnings.py`

### 允许对 upstream 文件做的事

1. **一行级 bug fix**（如 null check），必须在 commit message 中注明。
2. **`pyweixin/__init__.py`** 末尾追加 viper 扩展导入。
3. **`pyweixin/Uielements.py`** 新增 UI 元素定义（不删改原有定义）。
4. **`.gitignore`、`requirements.txt`** 追加条目。

### 不允许的操作

- 给 upstream 函数加参数、改签名、改默认行为。
- 在 upstream 文件中新增 class/function。
- 改 upstream 代码风格（缩进、空行、注释、import 顺序）。
- 添加 `_find_sidebar_item` 之类的兼容层到 upstream 代码中。

## 新增功能的标准做法

### 1. 新建独立扩展文件

在 `pyweixin/` 下新建文件，文件头声明不修改 upstream：

```python
"""
Viper XXX Extension — 功能简述。
不修改 upstream 代码，只导入其公共 API。
"""
from .WeChatTools import Tools, Navigator, ...
from .WeChatAuto import Moments, ...
```

### 2. 只通过公共 API 调用 upstream

- 使用 `Tools.*`、`Navigator.*`、`Moments.*` 等已有静态方法。
- 使用 `Uielements.py` 中定义的 UI 元素 dict。
- 如果 upstream 缺少你需要的底层能力，在自己的扩展文件中实现，不要改 upstream。

### 3. 在 `__init__.py` 中注册导出

在 `# viper 扩展` 注释块下追加导入：

```python
# viper 扩展
from pyweixin.your_ext import your_function
```

### 4. 辅助函数放在自己的文件里

即使与 upstream 中已有函数功能类似（如 `_listitem_signature`），也放在扩展文件中独立维护，不往 upstream 里塞。

## 项目结构

```
pyweixin/
  WeChatAuto.py          # upstream（不动）
  WeChatTools.py         # upstream（仅 bug fix）
  Uielements.py          # upstream（可追加新 UI 元素）
  __init__.py            # 导出入口（追加 viper 扩展导入）
  moments_ext.py         # viper: 朋友圈扩展
  rush_engine.py         # viper: 抢答引擎
  rush_ai.py             # viper: AI/OCR provider
  rush_callback.py       # viper: 流式回调
  rush_types.py          # viper: 类型定义
  rush_state.py          # viper: 状态持久化
  moments_question_miner.py  # viper: 题目挖掘
config/                  # 配置文件（.local_secrets.json 已 gitignore）
examples/                # 运行入口脚本
tests/                   # 测试
docs/                    # 文档
deprecated/              # 废弃脚本
local_workspace/         # 本地工作区（已 gitignore，不入库）
```

## Git 分支策略

- **`main`**：始终与 `upstream/main` 同步，不直接提交功能代码。
- **`viper/moments-custom-v2`**：当前开发分支。
- 功能分支统一以 `viper/` 为前缀。
- 需要上游新代码时：`main` pull upstream → 开发分支 rebase main。
- 详见 `docs/fork_sync_guide.md`。

## 运行时产物

以下文件由运行时生成，已在 `.gitignore` 中忽略，**不要提交**：

- `rush_state*.json` — 运行状态
- `rush_moments_cache*/` — 抓取的图片/日志缓存
- `config/.local_secrets.json` — API 密钥
- `local_workspace/` — 本地调试工作区
- `dataset/` — 测试数据集

## 提交规范

- 一个 commit 做一件事，commit message 用中文或英文均可。
- 对 upstream 文件的 bug fix 必须在 message 中标注，例如：`fix: WeChatTools.is_sns_at_bottom null check`。
- 推送前将开发分支 squash 为尽量少的 commit。

## Hook DLL 开发流程

### 构建 → 注入 → 测试的标准流程

**每次测试前必须按以下顺序操作，不可跳步：**

1. **Kill 微信** — `cmd.exe /c "taskkill /F /IM Weixin.exe"`，等待 2-3 秒
2. **确认进程已清除** — `tasklist | grep Weixin`，如果还有残留（僵尸进程，内存 <100KB，status=stopped）可以忽略
3. **启动微信** — `cmd.exe /c start "" "C:\Program Files\Tencent\Weixin\Weixin.exe"`，等待 5 秒让主进程完全初始化
4. **确认主进程就绪** — 检查 Weixin.exe 进程内存 >100MB 的那个才是主进程
5. **注入 DLL** — `python -c "from pyweixin.hook_injector import ...; inject_dll(pid, dll_path)"`
6. **等待 pipe server 启动** — sleep 2 秒后再连接 pipe
7. **验证连接** — `HookBridge.connect()` + `status()`

### Eject 失败的处理

`eject_dll()` 经常失败（DLL 文件被锁定），**不要反复重试 eject**。正确做法：
- 直接关闭微信（kill 进程）
- 重新构建 DLL（此时文件不再被锁定）
- 重新启动微信 → 注入

### 构建 DLL

```bash
cd H:/Code/pywechat/hook/build && cmake --build . --config Release
```

DLL 输出路径：`hook/build/bin/Release/pywechat_hook.dll`

## 文档维护

- 功能架构、运行方式、优化记录写在 `docs/moments_rush_guide.md`。
- 新增独立功能模块时，在 `docs/README.md` 索引中补充条目。
- 文档中引用函数路径时，确保与代码实际位置一致（如 `moments_ext.fetch_and_comment_from_moments_feed`，不是 `Moments.xxx`）。
