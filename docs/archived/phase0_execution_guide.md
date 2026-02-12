# Phase 0: Route B 去风险实验 - 执行指南

## 目标

验证"Hook OnSnsTimeLineSceneFinish 回调能否比 UI 刷新更早拿到朋友圈数据"，这是判断 Route B 方案是否可行的关键。

**时间限制**: 2-4 小时，如果无法验证提速，停止 Route B。

## 前置条件

### 1. 工具准备

- **IDA Pro** 或 **Ghidra** - 用于分析 WeChat 4.1.7.30 的 Weixin.dll
- **CMake** - 编译 Hook DLL
- **Visual Studio 2019+** - C++ 编译器

### 2. 环境检查

```bash
# 检查微信版本
python -c "from pyweixin.hook_injector import get_wechat_version; print(get_wechat_version())"
# 预期输出: 4.1.7.30

# 检查微信进程
tasklist | findstr Weixin.exe
# 预期：应该有一个主进程（内存 >100MB）
```

## ⚠️ 关键步骤：提取函数签名

**当前代码中的签名是占位符，必须替换为实际签名！**

### 方法 1：使用 IDA Pro（推荐）

1. **打开 Weixin.dll**:
   ```
   C:\Program Files\Tencent\Weixin\Weixin.dll
   ```

2. **搜索字符串**:
   - 按 `Shift+F12` 打开 Strings 窗口
   - 搜索以下字符串（可能的锚点）：
     - `SnsTimeLineScene`
     - `OnSnsFinish`
     - `TimelineObject`
     - `OnSnsTimeLineSceneFinish`

3. **跟踪交叉引用**:
   - 双击字符串，查看引用位置
   - 按 `X` 查看 Cross-references
   - 找到回调函数

4. **提取签名**:
   - 定位到函数入口
   - 复制前 16-24 字节的机器码
   - 使用 IDA 的 "Copy to assembly" 功能
   - 将地址部分替换为 `??`

   示例（来自 wxhelper 3.9.5.81）：
   ```
   原始机器码: 48 89 5C 24 10 57 48 83 EC 30 48 8B F9 ...
   签名（地址替换为 ??）: 48 89 5C 24 ?? 57 48 83 EC 30
   ```

5. **更新代码**:
   编辑 `hook/src/sns_moments_poc.cpp` line 155:
   ```cpp
   const char* signature = "YOUR_EXTRACTED_SIGNATURE_HERE";
   ```

### 方法 2：使用 Frida 动态探测（备选）

如果 IDA 找不到函数，可以用 Frida 拦截所有导出函数，记录调用时机：

```javascript
// frida_probe_callbacks.js
var module = Process.getModuleByName("Weixin.dll");
var exports = module.enumerateExports();

exports.forEach(function(exp) {
    if (exp.name.indexOf("Sns") !== -1 || exp.name.indexOf("Timeline") !== -1) {
        Interceptor.attach(exp.address, {
            onEnter: function(args) {
                console.log("[" + Date.now() + "] " + exp.name + " called");
            }
        });
    }
});
```

运行：
```bash
frida -p <WeChat_PID> -l frida_probe_callbacks.js
# 手动刷新朋友圈，观察哪个函数被触发
```

### 方法 3：参考 wxhelper（如果降级到 3.9.5.81）

如果 4.1.7.30 太难分析，可以临时降级到 WeChat 3.9.5.81，使用 wxhelper 已验证的签名：

```cpp
// wxhelper 3.9.5.81 的签名（仅供参考）
const char* signature = "48 89 5C 24 ?? 57 48 83 EC 30 48 8B F9";
```

**注意**: 降级微信需要卸载当前版本，可能丢失聊天记录，慎重！

## 执行流程

### Step 1: 提取并更新函数签名

按照上述方法提取签名，更新 `hook/src/sns_moments_poc.cpp` line 155。

### Step 2: 编译 Hook DLL

```bash
cd hook/build
cmake --build . --config Release
```

输出：`hook/build/bin/Release/pywechat_hook.dll`

### Step 3: Kill 微信并重新启动

```bash
# Kill 微信
cmd.exe /c "taskkill /F /IM Weixin.exe"

# 等待 2-3 秒
ping 127.0.0.1 -n 3 > nul

# 启动微信
cmd.exe /c start "" "C:\Program Files\Tencent\Weixin\Weixin.exe"

# 等待 5 秒让主进程完全初始化
ping 127.0.0.1 -n 6 > nul
```

### Step 4: 注入 DLL

```bash
# 获取微信主进程 PID
tasklist | findstr Weixin.exe
# 找到内存 >100MB 的那个进程

# 注入 DLL（替换 <PID>）
python -c "from pyweixin.hook_injector import inject_dll; inject_dll(<PID>, 'hook/build/bin/Release/pywechat_hook.dll')"
```

### Step 5: 验证 Hook 安装

检查 `pywechat_hook.log`:

```bash
tail -f pywechat_hook.log
```

预期输出：
```
[info] pywechat_hook loaded, init starting
[info] WeChat version: 4.1.7.30
[info] comment hook installed
[info] [SNS_POC] Initializing Phase 0 PoC hook...
[info] [SNS_POC] OnSnsTimeLineSceneFinish found at 0x...
[info] [SNS_POC] Hook installed successfully!
```

如果看到 `[SNS_POC] Failed to locate`，说明签名不正确，返回 Step 1。

### Step 6: 准备测试数据

在朋友圈手动发布 5-10 条测试帖子（或让朋友发布），确保有足够的数据。

### Step 7: 运行 Python 测试脚本

```bash
python examples/phase0_timing_test.py
```

按照提示操作：
1. 脚本会打开朋友圈窗口
2. 每次测试时，手动下拉刷新朋友圈
3. 脚本会自动检测 UI 可见时间
4. 对比 DLL log 中的 Hook 回调时间
5. 重复 5 次

## 成功标准

### ✅ 成功（继续 Phase 1）

```
测试汇总
======================================================================
成功测试数: 5/5
平均提前: 2.50s
最大提前: 3.20s
最小提前: 1.80s

最终判断
======================================================================
✅ Phase 0 成功！
   Hook 回调平均提前 2.50s，Route B 值得推进
   预期提速：13s → 10.5s

下一步：开始 Phase 1 - 实现完整 Hook + 内存快照
```

**行动**: 继续实施 Phase 1-4。

### ⚠️ 部分成功（需评估 ROI）

```
平均提前: 1.20s
预期提速：13s → 11.8s

建议：评估 ROI，考虑是否值得继续
```

**行动**: 权衡收益和开发成本，决定是否继续。

### ❌ 失败（放弃 Route B）

```
平均提前: 0.30s
预期提速：13s → 12.7s

建议：放弃 Route B，考虑其他方案
```

**行动**: 停止 Route B，考虑：
1. Hook UI 渲染函数
2. 监听 Windows 消息队列
3. 接受当前性能，优化其他环节

## 常见问题

### Q1: `[SNS_POC] Failed to locate OnSnsTimeLineSceneFinish`

**原因**: 函数签名不正确。

**解决**:
1. 检查 IDA Pro 中提取的签名是否正确
2. 尝试增加签名长度（24-32 字节）
3. 检查是否有通配符 `??` 替换地址
4. 考虑降级到 WeChat 3.9.5.81

### Q2: `[SNS_POC] Exception while parsing param2 structure`

**原因**: 数据结构偏移不正确（wxhelper 的偏移是针对 3.9.5.81）。

**解决**:
1. 用 Frida 动态探测 param2 结构：
   ```javascript
   Interceptor.attach(Module.findBaseAddress("Weixin.dll").add(0x...回调地址), {
       onEnter: function(args) {
           console.log(hexdump(ptr(args[1]), { length: 0x100 }));
       }
   });
   ```
2. 试错调整偏移（+0x30, +0x38, +0x48 等）
3. 对比 wxhelper 源码

### Q3: Hook 安装成功，但 log 里没有 `[SNS_POC] TRIGGERED`

**原因**: 回调函数没有被触发。

**可能性**:
1. 函数地址定位错误（Hook 了错误的函数）
2. WeChat 4.1.7.30 的回调机制变了
3. 需要特定操作才能触发（如点赞、评论）

**解决**:
1. 在 IDA 中验证函数逻辑是否匹配
2. 尝试不同的操作（点赞、评论、发布）
3. 使用 Frida 验证函数是否被调用

### Q4: DLL 注入失败

**常见原因**:
- 微信还没完全启动（等待 5 秒）
- 僵尸进程残留（彻底 kill）
- DLL 路径错误（使用绝对路径）

**解决**:
```bash
# 彻底清理
taskkill /F /IM Weixin.exe /T
ping 127.0.0.1 -n 3 > nul

# 重新启动 + 注入
cmd.exe /c start "" "C:\Program Files\Tencent\Weixin\Weixin.exe"
ping 127.0.0.1 -n 6 > nul
python -c "from pyweixin.hook_injector import inject_dll; inject_dll(<PID>, r'C:\path\to\pywechat_hook.dll')"
```

## 时间预算

| 步骤 | 预计时间 |
|-----|---------|
| 安装 IDA Pro / 学习使用 | 30 分钟 |
| 提取函数签名 | 30-60 分钟 |
| 编译 + 注入 + 验证 | 30 分钟 |
| 运行测试（5 次） | 15 分钟 |
| 分析结果 + 决策 | 15 分钟 |
| **总计** | **2-2.5 小时** |

**如果 4 小时内无法完成签名提取，停止 Phase 0，重新评估方案。**

## 下一步

- **Phase 0 成功** → 阅读 `docs/route_b_background_moments_fetch.md` Phase 1
- **Phase 0 失败** → 更新 `docs/route_b_background_moments_fetch.md` 状态为"已废弃"

---

**方案维护者**: Claude Sonnet 4.5
**最后更新**: 2026-02-12
**状态**: 待执行（需提取函数签名）
