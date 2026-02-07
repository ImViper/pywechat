# 朋友圈自动抢答操作手册（当前版）

## 1. 你要保留的两个入口

1. 好友主页监听：`start_test.py`
2. 总朋友圈刷新监听：`examples/run_feed_refresh_listener.py`

建议日常优先用第 2 个（总朋友圈常驻刷新）。

---

## 2. 环境准备

## 2.1 基础

1. Windows + PC微信已登录。
2. 项目目录：`H:\Code\pywechat`
3. 虚拟环境：`.venv`

## 2.2 依赖安装

```powershell
cd H:\Code\pywechat
.\.venv\Scripts\activate
python -m pip install -r requirements.txt
python -m pip install -U paddleocr
```

说明：

1. 当前 `.venv` 是 Python `3.14`。
2. `paddleocr` 已可安装，但 `paddlepaddle` 在该环境下不可用，导致 OCR 运行时会自动禁用。
3. 这不影响 AI-only 主流程。

如果你要启用 OCR：

1. 单独用 Python `3.10/3.11` 新建 venv。
2. 再执行 `pip install paddleocr paddlepaddle`。

## 2.3 API Key

文件：`config/.local_secrets.json`

```json
{
  "ARK_API_KEY": "你的ARK密钥"
}
```

## 2.4 坐标偏移本地配置（建议）

不要改源码，改本地配置文件即可：

```powershell
Copy-Item config/sns_click_offsets.example.json config/sns_click_offsets.local.json
```

然后编辑 `config/sns_click_offsets.local.json`，逐步调以下字段：

1. `SNS_ELLIPSIS_X_OFFSET`
2. `SNS_ELLIPSIS_Y_OFFSET`
3. `SNS_SEND_LIST_X_OFFSET`
4. `SNS_SEND_LIST_Y_OFFSET`

---

## 3. 启动命令

## 3.1 好友主页模式（旧流程）

```powershell
python start_test.py <发布时间HH:MM> [好友备注]
```

例子：

```powershell
python start_test.py 19:15 孙大炮
```

特征：

1. 轮询间隔固定 `1.0s`。
2. 会打开好友朋友圈页后处理。

## 3.2 总朋友圈常驻刷新模式（推荐）

```powershell
python examples/run_feed_refresh_listener.py <发布时间HH:MM> <目标作者> [轮询秒数]
```

例子：

```powershell
python examples/run_feed_refresh_listener.py 19:15 孙大炮
python examples/run_feed_refresh_listener.py 19:15 孙大炮 0.5
```

参数说明：

1. 轮询秒数默认 `0.5`。
2. 最小值限制为 `0.3`（再小会明显增加 UI 不稳定）。
3. 朋友圈窗口默认按最大化运行（稳定性优先）。

---

## 4. 运行中你应该看到什么

总朋友圈模式典型日志：

1. `已打开总朋友圈窗口（常驻）`
2. `[流程] 点击刷新按钮...`
3. `[流程] 定位总朋友圈列表...`
4. 若首条作者不匹配：`首条作者不匹配目标作者，跳过`
5. 命中后：图片提取 -> OCR/AI -> 开始评论

说明：

1. 当前实现命中后直接在列表页评论，不依赖进入详情页。
2. 评论后窗口默认保持不关闭，方便你手工确认发送按钮位置。

---

## 5. 输出文件位置

好友主页模式：

1. 缓存目录：`rush_moments_cache_test_<好友>`
2. 状态文件：`rush_state_test_<好友>.json`

总朋友圈模式：

1. 缓存目录：`rush_moments_cache_feed_<目标作者>`
2. 状态文件：`rush_state_feed_<目标作者>.json`

---

## 6. 常见问题

## Q1：为什么日志里显示 OCR 跳过？

当前 Python 3.14 环境缺 `paddlepaddle` 运行时，脚本会自动禁用 OCR，只走 AI。

## Q2：评论流程执行了但微信里没发出去？

当前成功标记是“发送动作执行过”，不是微信端强确认。请观察微信输入框和发送按钮落点，必要时手工补点一次发送。

## Q3：轮询可以更短吗？

可以传第三个参数，但建议不低于 `0.3`，否则容易出现控件定位抖动和误点。

## Q4：如何重跑同一个对象？

直接重跑命令即可。要清空历史状态可删除对应 `rush_state_*.json`。
