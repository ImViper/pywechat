# 群关键词监听转发操作指南

## 1. 功能目标

脚本 `examples/run_group_keyword_forwarder.py` 用于监听指定会话（群聊或好友），命中关键词后将消息转发给目标联系人。

---

## 2. 快速开始

1. 复制配置模板：

```powershell
Copy-Item config/group_keyword_forwarder.example.json config/group_keyword_forwarder.json
```

2. 修改 `config/group_keyword_forwarder.json` 关键字段：

1. `target_friend`：接收提醒的人。
2. `groups`：监听会话列表。
3. `keywords`：触发关键词。
4. `message_template`：转发模板（建议保留 `{group}` 方便区分来源会话）。

3. 启动脚本：

```powershell
python examples/run_group_keyword_forwarder.py
```

---

## 3. 常用命令

```powershell
# 默认配置启动（config/group_keyword_forwarder.json）
python examples/run_group_keyword_forwarder.py

# 干跑，不发送，只看命中日志
python examples/run_group_keyword_forwarder.py --dry-run

# 只跑一轮，验证配置
python examples/run_group_keyword_forwarder.py --once

# 开启排障日志
python examples/run_group_keyword_forwarder.py --debug

# 指定其他配置文件
python examples/run_group_keyword_forwarder.py --config config/xxx.json
```

---

## 4. 关键配置说明

1. `use_window_listener`：推荐 `true`，使用窗口增量监听。
2. `window_tail_scan_count`：每轮扫描窗口尾部消息项数量，消息密集时可适当调大。
3. `listener_window_offset_x`：监听窗口横向偏移像素（负数向左，正数向右）。
4. `max_send_per_cycle`：单轮最多发送条数。
5. `send_delay_sec`：每条提醒发送间隔。
6. `use_direct_poll` + `pull_count`：窗口监听不可用时的后备轮询参数。

---

## 5. 当前行为说明

1. 启动时会 warmup，跳过历史消息，只处理后续新增。
2. 命中流程是“排除词 -> 关键词”，命中即转发。
3. 当前没有额外时间区间过滤，只要是新增且命中就会触发。
4. 发送人和消息时间是尽力解析，可能出现“未知发送者/未知时间”。

---

## 6. 常见问题

1. 发送后后续不再监听：
现已加入自动自愈，会在监听窗口失效时自动重开。
建议开启 `--debug`，观察是否出现 `reopened listener window for: ...`。

2. 监听窗口遮挡主界面：
调整 `listener_window_offset_x`，例如 `-500`。

3. 同样内容是否重复转发：
窗口监听模式按新增消息项处理；后备轮询模式受 `dedupe_ttl_sec` 去重影响。
