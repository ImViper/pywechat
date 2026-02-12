#pragma once

/**
 * Phase 1: Route B - 后台朋友圈抓取（完整实现）
 *
 * ⚠️ 前置条件：Phase 0 验证成功（Hook 回调平均提前 ≥2s）
 *
 * 功能：
 *   1. Hook OnSnsTimeLineSceneFinish 回调
 *   2. 解析 param2 结构，提取朋友圈 post 数据
 *   3. 缓存到内存快照（最多 10 条，循环队列）
 *   4. 去重，避免重复缓存
 *   5. 通过 Named Pipe 暴露给 Python
 *
 * 与 Phase 0 PoC 的区别：
 *   - Phase 0: 只打日志，不缓存数据
 *   - Phase 1: 完整解析 + 内存缓存 + Pipe 接口
 */

#include <cstdint>
#include <string>
#include <vector>

namespace pywechat {

// 朋友圈 post 结构
struct MomentsPost {
    uint64_t sns_id;        // 唯一 ID
    uint32_t create_time;   // Unix 时间戳
    std::string sender_id;  // wxid_xxx 格式
    std::string content;    // 文本内容
    // xml 字段可选（通常很大，默认不缓存）
};

/// 初始化 SNS moments hook（在 dllmain.cpp 调用）
/// 返回 true 表示 hook 安装成功
bool init_sns_moments_hook();

/// 清理 hook（在 DLL 卸载时调用）
void cleanup_sns_moments_hook();

/// 获取内存快照（从 pipe 命令调用）
/// max_count: 最多返回几条（避免超过 64KB Named Pipe 限制）
std::vector<MomentsPost> get_sns_snapshot(int max_count = 3);

}  // namespace pywechat
