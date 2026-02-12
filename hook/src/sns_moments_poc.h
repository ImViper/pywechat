#pragma once

/**
 * Phase 0: Route B 去风险实验 PoC
 *
 * 验证 Hook OnSnsTimeLineSceneFinish 回调是否比 UI 刷新更早拿到数据。
 *
 * 实现策略：
 *   1. Hook OnSnsTimeLineSceneFinish 回调（参考 wxhelper 3.9.5.81）
 *   2. 在回调里打日志记录时间戳和 content 前 50 字符
 *   3. 不回传数据到 Python（减少复杂度）
 *   4. Python 侧轮询 UI，检测帖子可见时间
 *   5. 对比时间差，判断 Hook 是否比 UI 更早
 *
 * 关键不确定性：
 *   - WeChat 4.1.7.30 的偏移地址与 wxhelper 3.9.5.81 不同，需要试错调整
 *   - Hook 回调可能和 UI 刷新几乎同时触发（收益 <1s）
 *   - 如果 Hook 更晚，Route B 完全无效
 */

namespace pywechat {

/// 初始化 SNS moments PoC hook（在 dllmain.cpp 调用）
/// 返回 true 表示 hook 安装成功，false 表示失败（不影响 DLL 加载）
bool init_sns_moments_poc();

/// 清理 hook（在 DLL 卸载时调用）
void cleanup_sns_moments_poc();

}  // namespace pywechat
