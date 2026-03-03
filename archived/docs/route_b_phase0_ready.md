# Route B - 后台朋友圈抓取实施方案

## 📋 快速开始

### Phase 0 已就绪！

Phase 0 的所有代码已经创建完成，现在需要你做以下关键步骤：

### ⚠️ 关键步骤：提取函数签名（必须！）

**当前代码中的签名是占位符，必须使用 IDA Pro 提取实际签名！**

1. **打开 IDA Pro**，加载:
   ```
   C:\Program Files\Tencent\Weixin\Weixin.dll
   ```

2. **搜索字符串锚点**（Shift+F12）:
   - `SnsTimeLineScene`
   - `OnSnsFinish`
   - `TimelineObject`

3. **提取 16-24 字节签名**，更新:
   ```
   hook/src/sns_moments_poc.cpp, line 155
   ```

4. **编译 + 注入 + 测试**:
   ```bash
   cd hook/build && cmake --build . --config Release
   python examples/phase0_timing_test.py
   ```

详细步骤见：**`docs/phase0_execution_guide.md`**

---

## 📁 已创建的文件

### C++ Hook 代码

- ✅ `hook/src/sns_moments_poc.h` - PoC 头文件
- ✅ `hook/src/sns_moments_poc.cpp` - Hook 回调实现（需要更新签名！）
- ✅ `hook/CMakeLists.txt` - 已添加新源文件
- ✅ `hook/src/dllmain.cpp` - 已集成 PoC 初始化

### Python 测试脚本

- ✅ `examples/phase0_timing_test.py` - 时间对比测试（打开朋友圈 + 轮询 UI + 对比 DLL log）

### 文档

- ✅ `docs/phase0_execution_guide.md` - **详细执行指南（必读！）**
- ✅ `docs/route_b_checklist.md` - 实施进度 checklist

---

## 🎯 Phase 0 目标

**验证"Hook 回调能否比 UI 刷新更早拿到数据"**

### 成功标准

- ✅ **继续 Phase 1**: 平均提前 ≥2s → 预期提速 13s → 10s
- ⚠️ **重新评估**: 平均提前 1-2s → 预期提速 13s → 11-12s
- ❌ **放弃 Route B**: 平均提前 <1s → 几乎无收益

### 时间限制

**2-4 小时**，如果无法提取签名或验证失败，停止 Route B。

---

## 📖 执行流程（简化版）

```bash
# 1. 提取函数签名（IDA Pro）
#    → 更新 hook/src/sns_moments_poc.cpp line 155

# 2. 编译 DLL
cd hook/build
cmake --build . --config Release

# 3. Kill 微信 + 重启 + 注入
taskkill /F /IM Weixin.exe
timeout /t 3
start "" "C:\Program Files\Tencent\Weixin\Weixin.exe"
timeout /t 5
python -c "from pyweixin.hook_injector import inject_dll; inject_dll(<PID>, 'hook/build/bin/Release/pywechat_hook.dll')"

# 4. 验证 Hook 安装
tail -f pywechat_hook.log
# 预期看到: [SNS_POC] Hook installed successfully!

# 5. 运行测试
python examples/phase0_timing_test.py
# 手动刷新朋友圈 5 次，观察结果
```

---

## 🚨 常见问题

### Q: 看到 `[SNS_POC] Failed to locate OnSnsTimeLineSceneFinish`

**A**: 函数签名不正确，需要重新从 IDA Pro 提取。参考 `docs/phase0_execution_guide.md` 的详细步骤。

### Q: Hook 安装成功，但刷新朋友圈没有 `[SNS_POC] TRIGGERED` 日志

**A**: 可能原因：
1. 函数地址定位错误
2. 偏移不正确（wxhelper 的偏移是 3.9.5.81）
3. 需要用 Frida 动态探测

### Q: `[SNS_POC] Exception while parsing param2 structure`

**A**: 数据结构偏移不正确，需要用 Frida hexdump param2，试错调整。

---

## 📊 方案架构（Route B 全貌）

```
Phase 0 (2-4h):  验证可行性 ← 当前阶段
   ↓
Phase 1 (6-8h):  Hook 回调 + 内存快照
   ↓
Phase 2 (4-6h):  Named Pipe 命令集成
   ↓
Phase 3 (4-6h):  Python 轮询监控器
   ↓
Phase 4 (2-4h):  性能验证
```

**总计**: 18-28 小时（2-3 天）

---

## 🔗 相关文档

- **必读**: `docs/phase0_execution_guide.md` - 详细执行指南
- **进度**: `docs/route_b_checklist.md` - 实施进度 checklist
- **方案**: `docs/route_b_background_moments_fetch.md` - 完整技术方案
- **分析**: `docs/wxhelper_analysis_2026-02-12.md` - wxhelper 源码分析

---

## ✅ 下一步

1. **阅读**: `docs/phase0_execution_guide.md`
2. **提取签名**: 使用 IDA Pro 分析 Weixin.dll
3. **更新代码**: `hook/src/sns_moments_poc.cpp` line 155
4. **编译 + 测试**: 按照执行指南操作
5. **决策**: 根据测试结果决定是否继续 Phase 1-4

**预计时间**: 2-4 小时
**成败关键**: 函数签名提取 + 时间对比测试

---

**方案维护者**: Claude Sonnet 4.5
**最后更新**: 2026-02-12
**当前状态**: Phase 0 代码已完成，等待用户执行测试
