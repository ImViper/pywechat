# Route A 探索脚本归档

**日期**：2026-02-12
**状态**：已废弃

## 背景

这些脚本是探索 Route A（Hook WSASend实现并发评论发送）的产物。

**结论**：Route A 方向调研后发现：
1. Hook DLL调用 `cgi_A_caller_2` 不是线程安全，并发会崩溃
2. 尝试Hook WSASend来绕过业务层，但此方向投入产出比不高
3. **更重要的发现**：瓶颈不在评论发送速度（7.8秒），而在获取题目速度（UI刷新慢2-3秒）

## 新方向

**Route B：后台朋友圈抓取**
- 使用wxhelper的 `getSNSFirstPage()` 方法
- 后台轮询或Hook回调获取新帖子
- 直接提取题目文本，无需OCR，无需等UI刷新
- 预期提速2-3秒

详见：`docs/route_b_background_moments_fetch.md`（待创建）

## 归档内容

### Frida Hook 脚本
- `frida_wsasend_probe.js` - WSASend Hook
- `frida_*_probe.js` - 各种探索性Hook

### HTTP 捕获脚本
- `*capture*.py` - HTTP请求捕获工具
- `monitor_*.py` - 网络监听工具

### 协议探索脚本
- `discover_*.py` - 协议发现工具
- `extract_*.py` - 数据提取工具
- `profile_*.py` - 流量分析工具

### HTTP Sidecar（未完成）
- `run_http_*.py` - HTTP代理方案（已放弃）

## 参考价值

虽然Route A已废弃，但以下经验仍有价值：
1. Frida在微信上可正常工作
2. WSASend可以被Hook
3. 微信网络层设计的了解

如需重新启动Route A，这些脚本可作为参考。
