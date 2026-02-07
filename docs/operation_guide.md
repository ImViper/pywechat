# 朋友圈自动抢答系统 - 操作手册（最新版）

## 1. 目标

这份文档只回答两件事：

1. 你现在怎么启动系统跑一遍完整流程
2. 跑完后你后续怎么重复操作、怎么快速排查

---

## 2. 首次准备

### 2.1 环境

1. Windows 已安装并登录 PC 微信
2. Python 虚拟环境可用（建议项目内 `.venv`）
3. 项目依赖已安装：

```powershell
pip install -r requirements.txt
```

4. 可选 OCR（未安装也能跑，只是少一路 OCR 辅助）：

```powershell
pip install easyocr
```

### 2.2 配置 API Key

创建或修改 `config/.local_secrets.json`：

```json
{
  "ARK_API_KEY": "你的ARK密钥"
}
```

---

## 3. 如何启动（你现在就能用）

在项目根目录执行：

```powershell
python start_test.py <发布时间> [好友备注]
```

示例：

```powershell
python start_test.py 13:45
python start_test.py 13:45 孙大炮
```

参数说明：

1. `发布时间`：朋友圈预计发布时间（`HH:MM`）
2. `好友备注`：可选，不传默认 `小蔡`

监控窗口固定为：

1. 开始：发布时间前 2 分钟
2. 结束：发布时间后 5 分钟

---

## 4. 一次标准实操流程

1. 打开终端并进入项目目录：

```powershell
cd H:\Code\pywechat
.\.venv\Scripts\activate
```

2. 设定一个“马上要发”的时间（建议当前时间后 1-2 分钟）并启动：

```powershell
python start_test.py 13:45 孙大炮
```

3. 在监控窗口内，用该好友发一条带题目的朋友圈（最好带图）。
4. 观察终端输出：抓取 -> 识别 -> 评论发送。
5. 结束后检查：
   - 微信朋友圈里是否出现评论
   - 输出目录：`rush_moments_cache_test_<好友备注>/`
   - 状态文件：`rush_state_test_<好友备注>.json`

---

## 5. 后续日常操作

### 5.1 换好友测试

直接换第二个参数：

```powershell
python start_test.py 14:20 小王
```

### 5.2 重跑同一好友

可直接重跑。若你希望“完全当成首次运行”，可删除该好友状态文件后再跑：

```powershell
Remove-Item rush_state_test_孙大炮.json
```

---

## 6. 快速排障

### Q1: `未找到 ARK_API_KEY`

检查 `config/.local_secrets.json` 是否存在且字段名是 `ARK_API_KEY`。

### Q2: 提示 `easyocr 未安装`

这是可选能力，不会阻塞主流程；需要 OCR 时再安装 `easyocr`。

### Q3: 评论没发出去

当前发送成功判定是“流程已执行”，不是强校验。建议先手工确认评论区是否真的落地；必要时可手动点一次发送按钮。

### Q4: 找不到微信窗口或控件

确保 PC 微信在正常可交互状态（已登录、窗口未异常最小化/遮挡），然后重试。
