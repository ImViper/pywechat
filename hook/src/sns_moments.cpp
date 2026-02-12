#include "sns_moments.h"

#include <Windows.h>
#include <chrono>
#include <deque>
#include <mutex>
#include <algorithm>
#include <spdlog/spdlog.h>
#include <MinHook.h>

#include "sig_scanner.h"

/**
 * Phase 1: Route B - 后台朋友圈抓取（完整实现）
 *
 * ⚠️ 前置条件：Phase 0 验证成功（Hook 回调平均提前 ≥2s）
 *
 * 与 Phase 0 PoC 的区别：
 *   - Phase 0: 只打日志，验证可行性
 *   - Phase 1: 完整解析 + 内存缓存 + Pipe 接口
 */

namespace pywechat {

// ========== 全局状态 ==========

// 内存快照（最多缓存 10 条，循环队列）
static std::deque<MomentsPost> g_snapshot;
static std::mutex g_snapshot_mutex;
static constexpr size_t MAX_SNAPSHOT_SIZE = 10;

// Hook 函数指针
using OnSnsFinish_t = uint64_t (*)(uint64_t, uint64_t, uint64_t);
static OnSnsFinish_t original_OnSnsFinish = nullptr;
static void* hook_target_addr = nullptr;

// 统计信息
struct Stats {
    uint64_t total_callbacks = 0;
    uint64_t total_posts = 0;
    uint64_t parse_errors = 0;
};
static Stats g_stats;

// ========== 辅助函数 ==========

/// 读取 std::wstring（WeChat 内部字符串结构）
/// 假设结构：struct { wchar_t* ptr; size_t len; size_t cap; }
static std::string read_wstring_safe(uintptr_t addr) {
    if (!addr) return "";

    __try {
        // 尝试读取字符串指针（假设是第一个字段）
        wchar_t** ptr_ptr = reinterpret_cast<wchar_t**>(addr);
        if (!ptr_ptr || !*ptr_ptr) return "";

        wchar_t* wstr = *ptr_ptr;

        // 读取最多 2048 个字符（防止越界）
        std::wstring ws;
        ws.reserve(512);

        for (size_t i = 0; i < 2048; ++i) {
            if (wstr[i] == L'\0') break;
            ws += wstr[i];
        }

        // 转换为 UTF-8
        if (ws.empty()) return "";

        int len = WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), -1, nullptr, 0, nullptr, nullptr);
        if (len <= 0) return "";

        std::string result(len - 1, '\0');
        WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), -1, &result[0], len, nullptr, nullptr);
        return result;

    } __except (EXCEPTION_EXECUTE_HANDLER) {
        spdlog::error("[SNS_HOOK] Exception while reading wstring at {:#x}", addr);
        return "";
    }
}

/// 读取 UINT64（带异常保护）
static uint64_t read_uint64_safe(uintptr_t addr) {
    __try {
        return *reinterpret_cast<uint64_t*>(addr);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
}

/// 读取 UINT32（带异常保护）
static uint32_t read_uint32_safe(uintptr_t addr) {
    __try {
        return *reinterpret_cast<uint32_t*>(addr);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
}

// ========== Hook 回调 ==========

uint64_t hooked_OnSnsFinish(uint64_t param1, uint64_t param2, uint64_t param3) {
    auto start_time = std::chrono::high_resolution_clock::now();
    g_stats.total_callbacks++;

    __try {
        // 读取 post 数组（偏移根据 Phase 0 验证结果调整）
        // wxhelper 3.9.5.81 偏移：param2 + 0x30 = begin, +0x38 = end
        // TODO: 如果 Phase 0 发现偏移不同，需要在这里调整
        uintptr_t begin_addr = read_uint64_safe(param2 + 0x30);
        uintptr_t end_addr = read_uint64_safe(param2 + 0x38);

        if (begin_addr == 0 || end_addr == 0 || begin_addr >= end_addr) {
            // 无效的数组范围，跳过
            goto call_original;
        }

        // 计算元素数量
        constexpr size_t stride = 0x11E0;  // wxhelper: 4576 bytes per post
        size_t count = (end_addr - begin_addr) / stride;

        if (count == 0 || count > 100) {
            // 异常数量，跳过
            spdlog::warn("[SNS_HOOK] Unusual post count: {}", count);
            goto call_original;
        }

        spdlog::debug("[SNS_HOOK] Processing {} posts", count);

        // 遍历 post 数组
        std::vector<MomentsPost> new_posts;
        new_posts.reserve(count);

        uintptr_t post_addr = begin_addr;
        while (post_addr < end_addr) {
            MomentsPost post;

            // wxhelper 3.9.5.81 偏移：
            // +0x00: sns_id (uint64_t)
            // +0x18: sender_id (wstring)
            // +0x38: create_time (uint32_t)
            // +0x48: content (wstring)
            //
            // TODO: 如果 Phase 0 发现偏移不同，需要调整

            post.sns_id = read_uint64_safe(post_addr + 0x00);
            post.create_time = read_uint32_safe(post_addr + 0x38);

            // 读取字符串字段（需要解引用指针）
            post.sender_id = read_wstring_safe(post_addr + 0x18);
            post.content = read_wstring_safe(post_addr + 0x48);

            // 只缓存有效的 post（sns_id != 0）
            if (post.sns_id != 0) {
                new_posts.push_back(std::move(post));
                g_stats.total_posts++;
            }

            post_addr += stride;
        }

        // 更新内存快照（只保留最新 10 条）
        if (!new_posts.empty()) {
            std::lock_guard<std::mutex> lock(g_snapshot_mutex);

            for (auto& post : new_posts) {
                // 去重（避免重复缓存）
                auto it = std::find_if(g_snapshot.begin(), g_snapshot.end(),
                    [&](const MomentsPost& p) { return p.sns_id == post.sns_id; });

                if (it == g_snapshot.end()) {
                    // 新帖子，插入到队首
                    g_snapshot.push_front(std::move(post));

                    // 限制队列大小
                    if (g_snapshot.size() > MAX_SNAPSHOT_SIZE) {
                        g_snapshot.pop_back();
                    }
                }
            }

            spdlog::debug("[SNS_HOOK] Snapshot updated, total cached: {}", g_snapshot.size());
        }

    } __except (EXCEPTION_EXECUTE_HANDLER) {
        spdlog::error("[SNS_HOOK] Exception in hook callback");
        g_stats.parse_errors++;
    }

call_original:
    // 调用原函数
    uint64_t result = 0;
    if (original_OnSnsFinish) {
        result = original_OnSnsFinish(param1, param2, param3);
    }

    // 记录耗时
    auto end_time = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end_time - start_time);

    if (duration.count() > 1000) {
        spdlog::warn("[SNS_HOOK] Callback took {}µs (slow!)", duration.count());
    }

    return result;
}

// ========== 公开接口 ==========

bool init_sns_moments_hook() {
    spdlog::info("[SNS_HOOK] Initializing Phase 1 hook...");

    // 确定主模块
    const char* module = "Weixin.dll";
    if (!GetModuleHandleA(module)) {
        module = "WeChatWin.dll";
        if (!GetModuleHandleA(module)) {
            spdlog::error("[SNS_HOOK] Neither Weixin.dll nor WeChatWin.dll found");
            return false;
        }
    }

    spdlog::info("[SNS_HOOK] Target module: {}", module);

    // 签名扫描
    // TODO: 使用 Phase 0 验证成功的签名
    // 如果 Phase 0 发现签名需要调整，在这里更新
    const char* signature = "48 89 5C 24 ?? 57 48 83 EC 30";  // 占位，需要替换

    spdlog::info("[SNS_HOOK] Scanning for OnSnsTimeLineSceneFinish...");

    uintptr_t func_addr = SigScanner::find(module, signature);

    if (!func_addr) {
        spdlog::error("[SNS_HOOK] Failed to locate OnSnsTimeLineSceneFinish");
        spdlog::error("[SNS_HOOK] Make sure Phase 0 signature is correct");
        return false;
    }

    spdlog::info("[SNS_HOOK] OnSnsTimeLineSceneFinish found at {:#x}", func_addr);

    // 安装 Hook
    hook_target_addr = reinterpret_cast<void*>(func_addr);

    if (MH_CreateHook(hook_target_addr,
                      reinterpret_cast<void*>(&hooked_OnSnsFinish),
                      reinterpret_cast<void**>(&original_OnSnsFinish)) != MH_OK) {
        spdlog::error("[SNS_HOOK] MH_CreateHook failed");
        return false;
    }

    if (MH_EnableHook(hook_target_addr) != MH_OK) {
        spdlog::error("[SNS_HOOK] MH_EnableHook failed");
        return false;
    }

    spdlog::info("[SNS_HOOK] Hook installed successfully!");
    return true;
}

void cleanup_sns_moments_hook() {
    if (hook_target_addr) {
        MH_DisableHook(hook_target_addr);
        spdlog::info("[SNS_HOOK] Hook disabled");
        hook_target_addr = nullptr;
    }

    // 打印统计信息
    spdlog::info("[SNS_HOOK] Stats: callbacks={}, posts={}, errors={}",
                 g_stats.total_callbacks, g_stats.total_posts, g_stats.parse_errors);
}

std::vector<MomentsPost> get_sns_snapshot(int max_count) {
    std::lock_guard<std::mutex> lock(g_snapshot_mutex);

    // 返回最新 N 条（避免超过 64KB Named Pipe 限制）
    int count = std::min(static_cast<int>(g_snapshot.size()), max_count);

    if (count == 0) {
        return {};
    }

    return std::vector<MomentsPost>(g_snapshot.begin(), g_snapshot.begin() + count);
}

}  // namespace pywechat
