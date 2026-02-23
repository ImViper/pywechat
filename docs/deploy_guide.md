# 新电脑部署指南（运行包版）

更新时间：2026-02-23

## 1. 适用包

本指南对应运行包：

- `local_workspace/release/pywechat_runtime_20260223_230032.zip`
- SHA256：`7A71B235E9CCD7BC0D3F1810C3879A5EE525149FE6EE29D2C3A18E0696DEF10E`

## 2. 前置条件

- Windows 10/11
- Python 3.9 - 3.12（安装时勾选 `Add Python to PATH`）
- 微信 PC 已安装并可登录

## 3. 部署步骤

### 3.1 解压

将 zip 解压到目标目录，例如：

```powershell
D:\pywechat_runtime
```

### 3.2 安装依赖

在解压目录执行：

```powershell
cd D:\pywechat_runtime
python install.py
```

该脚本会自动：

1. 检查 Python 版本
2. 创建 `.venv`
3. 安装 `requirements.txt`
4. 尝试安装 PaddleOCR（可选）
5. 引导配置 `ARK_API_KEY`

### 3.3 配置 ARK_API_KEY

推荐二选一：

1. `config/.local_env.bat`

```bat
@echo off
set ARK_API_KEY=你的Key
```

2. `config/.local_secrets.json`

```json
{"ARK_API_KEY": "你的Key"}
```

### 3.4 环境校验

```powershell
python install.py --check
```

看到关键项 `[OK]` 后再运行。

### 3.5 启动

```powershell
python 启动抢答.py
```

按提示输入目标好友和预计发圈时间（`HH:MM`）。

## 4. 微信 4.1+ 注意事项

首次部署在新机通常需要做一次：

1. 打开讲述人：`Win + Ctrl + Enter`
2. 登录微信后保持 5 分钟
3. 关闭讲述人

这一步用于让微信控件树稳定生成，后续一般不需要重复做。

## 5. 运行包内容说明

运行包已包含：

- 抢答入口：`启动抢答.py`
- 安装脚本：`install.py`
- 核心代码：`pyweixin/*`
- Hook 运行 DLL：`hook/build/bin/Release/pywechat_hook.dll`
- 默认配置样例与规则：`config/rush_event.json`、`config/known_answers.json`

运行包未包含（需要在新机自行配置）：

- `config/.local_env.bat`
- `config/.local_secrets.json`

## 6. 常见问题

1. `ARK_API_KEY` 缺失  
- 重新检查 `config/.local_env.bat` 或 `config/.local_secrets.json`。

2. 打开朋友圈失败（`open moments failed`）  
- 确认微信主窗口正常可交互。  
- 必要时重开微信并重新执行“讲述人一次性初始化”。

3. Hook 不生效  
- 确认 `hook/build/bin/Release/pywechat_hook.dll` 文件存在。  
- 确认微信进程未被安全软件拦截注入行为。
