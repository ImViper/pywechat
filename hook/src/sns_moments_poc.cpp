#include "sns_moments_poc.h"

#include <Windows.h>
#include <chrono>
#include <string>
#include <spdlog/spdlog.h>
#include <MinHook.h>

#include "sig_scanner.h"

namespace pywechat {

// ========== Hook 函数指针 ==========

using OnSnsFinish_t = uint64_t (*)(uint64_t, uint64_t, uint64_t);
static OnSnsFinish_t original_OnSnsFinish = nullptr;
static void* hook_target_addr = nullptr;

// ========== 辅助函数（简化版，移除复杂的异常处理）==========

/// 安全读取 wstring（简化版）
static std::string read_wstring_safe(uintptr_t addr) {
    if (!addr) return "";

    // 直接尝试读取，如果失败就返回空
    wchar_t* wstr_ptr = nullptr;

    // 第一步：读取指针
    if (IsBadReadPtr(reinterpret_cast<void*>(addr), sizeof(wchar_t*))) {
        return "";
    }

    wstr_ptr = *reinterpret_cast<wchar_t**>(addr);
    if (!wstr_ptr) return "";

    // 第二步：读取字符串内容
    std::wstring ws;
    ws.reserve(256);

    for (size_t i = 0; i < 1024; ++i) {
        if (IsBadReadPtr(wstr_ptr + i, sizeof(wchar_t))) {
            break;
        }

        wchar_t ch = wstr_ptr[i];
        if (ch == L'\0') break;
        ws += ch;
    }

    if (ws.empty()) return "";

    // 转换为 UTF-8
    int len = WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (len <= 0) return "";

    std::string result(len - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, ws.c_str(), -1, &result[0], len, nullptr, nullptr);
    return result;
}

/// 安全读取 uint64_t
static uint64_t read_uint64_safe(uintptr_t addr) {
    if (IsBadReadPtr(reinterpret_cast<void*>(addr), sizeof(uint64_t))) {
        return 0;
    }
    return *reinterpret_cast<uint64_t*>(addr);
}

/// 安全读取 uint32_t
static uint32_t read_uint32_safe(uintptr_t addr) {
    if (IsBadReadPtr(reinterpret_cast<void*>(addr), sizeof(uint32_t))) {
        return 0;
    }
    return *reinterpret_cast<uint32_t*>(addr);
}

// ========== Hook 回调 ==========

uint64_t hooked_OnSnsFinish(uint64_t param1, uint64_t param2, uint64_t param3) {
    // 记录时间戳（毫秒）
    auto now = std::chrono::system_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()).count();

    spdlog::info("[SNS_POC] ========== OnSnsFinish TRIGGERED ==========");
    spdlog::info("[SNS_POC] Timestamp: {} ms", ms);
    spdlog::info("[SNS_POC] param1={:#x}, param2={:#x}, param3={:#x}",
                 param1, param2, param3);

    // 尝试解析 param2 结构（基于 wxhelper 3.9.5.81 偏移）
    uintptr_t begin_addr = read_uint64_safe(param2 + 0x30);
    uintptr_t end_addr = read_uint64_safe(param2 + 0x38);

    spdlog::info("[SNS_POC] Array range: {:#x} - {:#x}", begin_addr, end_addr);

    if (begin_addr == 0 || end_addr == 0 || begin_addr >= end_addr) {
        spdlog::warn("[SNS_POC] Invalid array range, skipping parse");
    } else {
        // 计算元素数量
        size_t stride = 0x11E0;  // wxhelper: 4576 bytes per post
        size_t count = (end_addr - begin_addr) / stride;

        spdlog::info("[SNS_POC] Detected {} posts (stride={:#x})", count, stride);

        // 只读取第一个 post（最新的）
        if (count > 0 && count < 100) {
            uintptr_t post_addr = begin_addr;

            // wxhelper 偏移：
            // +0x00: sns_id (uint64_t)
            // +0x18: sender_id (wstring)
            // +0x38: create_time (uint32_t)
            // +0x48: content (wstring)

            uint64_t sns_id = read_uint64_safe(post_addr + 0x00);
            uint32_t create_time = read_uint32_safe(post_addr + 0x38);
            std::string content = read_wstring_safe(post_addr + 0x48);

            spdlog::info("[SNS_POC] First post:");
            spdlog::info("[SNS_POC]   sns_id: {}", sns_id);
            spdlog::info("[SNS_POC]   create_time: {}", create_time);
            spdlog::info("[SNS_POC]   content: {}",
                         content.empty() ? "<empty>" : content.substr(0, 100));

            if (content.empty()) {
                spdlog::warn("[SNS_POC] Content is empty - offset might be wrong!");
                spdlog::warn("[SNS_POC] Try adjusting +0x48 offset in code");
            }
        }
    }

    spdlog::info("[SNS_POC] ========================================");

    // 调用原函数
    if (original_OnSnsFinish) {
        return original_OnSnsFinish(param1, param2, param3);
    }

    // 不应该到这里
    spdlog::error("[SNS_POC] original_OnSnsFinish is null!");
    return 0;
}

// ========== 公开接口 ==========

bool init_sns_moments_poc() {
    spdlog::info("[SNS_POC] Initializing Phase 0 PoC hook...");

    // 确定主模块
    const char* module = "Weixin.dll";
    if (!GetModuleHandleA(module)) {
        module = "WeChatWin.dll";
        if (!GetModuleHandleA(module)) {
            spdlog::error("[SNS_POC] Neither Weixin.dll nor WeChatWin.dll found");
            return false;
        }
    }

    spdlog::info("[SNS_POC] Target module: {}", module);

    // 签名扫描 - 尝试多个可能的签名
    const char* signatures[] = {
        // wxhelper 3.9.5.81 完整签名
        "48 89 5C 24 ?? 57 48 83 EC 30 48 8B F9",

        // 简化版本（更宽松匹配）
        "48 89 5C 24 ?? 57 48 83 EC 30",

        // 常见的 x64 函数序言模式
        "48 89 5C 24 ?? 48 89 74 24 ?? 57 48 83 EC",
        "40 53 48 83 EC ?? 48 8B D9",
        "48 89 5C 24 ?? 48 89 6C 24 ?? 48 89 74 24 ?? 57 48 83 EC",

        // 更短的模式（作为最后手段）
        "48 89 5C 24 ?? 57",
        "40 53 48 83 EC",
    };

    spdlog::info("[SNS_POC] Scanning for OnSnsTimeLineSceneFinish...");
    spdlog::info("[SNS_POC] Trying {} signature patterns", sizeof(signatures) / sizeof(signatures[0]));

    uintptr_t func_addr = 0;
    int matched_index = -1;

    for (size_t i = 0; i < sizeof(signatures) / sizeof(signatures[0]); ++i) {
        spdlog::debug("[SNS_POC] Trying signature #{}: {}", i + 1, signatures[i]);
        func_addr = SigScanner::find(module, signatures[i]);

        if (func_addr) {
            matched_index = static_cast<int>(i);
            spdlog::info("[SNS_POC] Signature #{} matched!", i + 1);
            break;
        }
    }

    if (!func_addr) {
        spdlog::error("[SNS_POC] Failed to locate OnSnsTimeLineSceneFinish");
        spdlog::error("[SNS_POC] All {} signature patterns failed", sizeof(signatures) / sizeof(signatures[0]));
        spdlog::error("[SNS_POC] WeChat version might be too different from wxhelper 3.9.5.81");
        return false;
    }

    spdlog::info("[SNS_POC] OnSnsTimeLineSceneFinish found at {:#x}", func_addr);
    spdlog::info("[SNS_POC] Matched signature #{}: {}", matched_index + 1, signatures[matched_index]);

    // 安装 Hook
    hook_target_addr = reinterpret_cast<void*>(func_addr);

    if (MH_CreateHook(hook_target_addr,
                      reinterpret_cast<void*>(&hooked_OnSnsFinish),
                      reinterpret_cast<void**>(&original_OnSnsFinish)) != MH_OK) {
        spdlog::error("[SNS_POC] MH_CreateHook failed");
        return false;
    }

    if (MH_EnableHook(hook_target_addr) != MH_OK) {
        spdlog::error("[SNS_POC] MH_EnableHook failed");
        return false;
    }

    spdlog::info("[SNS_POC] Hook installed successfully!");
    spdlog::info("[SNS_POC] Waiting for朋友圈 refresh to trigger callback...");

    return true;
}

void cleanup_sns_moments_poc() {
    if (hook_target_addr) {
        MH_DisableHook(hook_target_addr);
        spdlog::info("[SNS_POC] Hook disabled");
        hook_target_addr = nullptr;
    }
}

}  // namespace pywechat
