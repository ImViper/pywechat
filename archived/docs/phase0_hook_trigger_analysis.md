# Phase 0 - Hook 触发机制分析

## 当前状态

✅ Hook 安装成功
- 地址: `0x7ff9271fd1fc`
- 签名匹配: #1 (wxhelper 3.9.5.81 兼容 4.1.7.30)

❌ Hook 回调未触发
- 尝试方法: 鼠标滚动朋友圈列表
- 结果: UI 在 0.5 秒内可见，但 Hook 未触发

## 问题分析

### OnSnsTimeLineSceneFinish 的触发条件

根据 wxhelper 代码分析，此函数**只在网络请求完成时调用**，而不是 UI 滚动时。

**触发场景**:
1. 首次打开朋友圈 → 调用 `GetSNSFirstPage()` → 网络请求 → 回调触发
2. 滚动到底部加载更多 → 调用 `GetSNSNextPageScene(snsId)` → 网络请求 → 回调触发
3. **下拉刷新**（Pull to Refresh）→ 重新调用 `GetSNSFirstPage()` → 网络请求 → 回调触发

**不触发场景**:
- ❌ 仅滚动已缓存的朋友圈内容（无网络请求）
- ❌ 重新打开已缓存的朋友圈窗口（无网络请求）
- ❌ 鼠标移动、点击、焦点切换（无网络请求）

### 测试失败原因

我的测试脚本执行了：
```python
# 这只是滚动 UI，没有触发网络请求
mouse.scroll(coords=feed_list.rectangle().mid_point(), wheel_dist=5)
```

这个操作：
- ✅ 让 UI 在 0.5 秒内显示已缓存的帖子
- ❌ **没有**触发网络请求到微信服务器
- ❌ **没有**调用 `OnSnsTimeLineSceneFinish`

## 正确的触发方法

### 方法 1: 手动下拉刷新（最可靠）

1. 打开朋友圈窗口
2. 在朋友圈列表顶部**用鼠标按住并向下拖动**（Pull to Refresh）
3. 释放鼠标，触发刷新动画
4. 等待网络请求完成 → Hook 触发

**UI 自动化实现**（pyautogui/pywinauto）:
```python
# 获取朋友圈列表顶部坐标
rect = feed_list.rectangle()
start_x = rect.mid_point().x
start_y = rect.top + 50  # 顶部往下 50 像素

# 按住鼠标并向下拖动（模拟下拉刷新）
pyautogui.moveTo(start_x, start_y)
pyautogui.drag(0, 200, duration=0.5, button='left')  # 向下拖 200 像素
```

### 方法 2: 通过 WeChat API 调用（最精确，但需要逆向）

直接调用 WeChat 的内部函数（类似 wxhelper）:
```cpp
// 需要定位以下函数地址（4.1.7.30 版本）
UINT64 kSNSDataMgr = ???;
UINT64 kSNSGetFirstPage = ???;

// 调用刷新
func::__GetSNSDataMgr sns_data_mgr = (func::__GetSNSDataMgr)(base + kSNSDataMgr);
func::__GetSNSFirstPage sns_first_page = (func::__GetSNSFirstPage)(base + kSNSGetFirstPage);

UINT64 mgr = sns_data_mgr();
INT64 buff[16] = {0};
sns_first_page(mgr, reinterpret_cast<UINT64>(&buff), 1);
```

**缺点**: 需要额外逆向工程定位这些函数地址

### 方法 3: 关闭并重新打开朋友圈（强制刷新）

```python
# 关闭朋友圈窗口
moments_window.close()
time.sleep(2)

# 重新打开（首次打开会触发 GetSNSFirstPage）
moments_window = Navigator.open_moments()
# → 触发网络请求 → Hook 回调
```

**注意**: 只有**首次打开**才会触发，如果微信缓存了数据可能不触发

## 建议的 Phase 0 验证流程

### 选项 A: 手动触发（推荐，最简单）

1. 运行监控脚本（实时查看日志）:
   ```bash
   python scripts/phase0_monitor_live.py
   ```

2. **手动操作**:
   - 打开微信朋友圈
   - 用鼠标在顶部**下拉刷新**
   - 观察脚本输出

3. 验证:
   - 如果看到 `[SNS_POC] TRIGGERED` → 成功
   - 对比时间戳

### 选项 B: 自动化下拉刷新（需要调试）

修改 `phase0_verify_hook_timing.py`，改用**拖拽下拉**代替滚动:

```python
import pyautogui

rect = feed_list.rectangle()
start_x = rect.mid_point().x
start_y = rect.top + 50

# 拖拽下拉（模拟 Pull to Refresh）
pyautogui.click(start_x, start_y)
pyautogui.drag(0, 200, duration=0.5, button='left')
time.sleep(1)  # 等待刷新动画
pyautogui.click(start_x, start_y)  # 释放
```

**风险**: 可能需要多次尝试找到正确的拖拽参数

### 选项 C: 关闭重开朋友圈（最可靠）

```python
# 完全关闭朋友圈
moments_window.close()
time.sleep(3)

# 记录时间
refresh_start_time = time.time()

# 重新打开（触发首次加载）
moments_window = Navigator.open_moments(is_maximize=False, close_weixin=False)

# 监控 Hook 回调和 UI 可见时间
# ...
```

## 下一步行动

**短期**（今天）:
1. 使用**选项 A**（手动触发）验证 Hook 是否能触发
2. 如果成功触发，记录时间对比数据
3. 如果失败，尝试**选项 C**（关闭重开）

**中期**（如果 Phase 0 成功）:
1. 改进自动化脚本，实现可靠的下拉刷新
2. 或者接受手动触发，只在 production 场景下使用 Hook

**长期**（可选）:
1. 逆向定位 `GetSNSFirstPage` 函数地址
2. 直接通过 API 调用触发刷新（类似 wxhelper）

## 关键结论

❌ **当前测试方法有误**: 鼠标滚动不触发网络请求
✅ **Hook 安装正确**: 地址、签名都匹配
⚠️ **需要真实的网络刷新**: 下拉刷新或首次打开

**Phase 0 核心假设仍未验证**:
- Hook 回调是否比 UI 更早？
- 需要先成功触发 Hook，才能对比时间
