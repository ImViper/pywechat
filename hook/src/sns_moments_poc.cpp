#include "sns_moments_poc.h"

#include <Windows.h>
#include <chrono>
#include <string>
#include <spdlog/spdlog.h>
#include <MinHook.h>

#include "sig_scanner.h"

namespace pywechat {

// ========== Hook 函数指针 ==========

// wxhelper 中的签名：uint64_t (*)(uint64_t, uint64_t, uint64_t)
// 我们采用相同的签名
using OnSnsFinish_t = uint64_t (*)(uint64_t, uint64_t, uint64_t);
static OnSnsFinish_t original_OnSnsFinish = nullptr;
static void* hook_target_addr = nullptr;

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

        // 读取最多 1024 个字符（防止越界）
        std::wstring ws;
        for (size_t i = 0; i < 1024; ++i) {
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
        spdlog::error("[SNS_POC] Exception while reading wstring at {:#x}", addr);
        return "";
    }
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
    __try {
        // wxhelper 偏移：param2 + 0x30 = 数组起始地址, +0x38 = 数组结束地址
        uintptr_t begin_addr = *reinterpret_cast<uintptr_t*>(param2 + 0x30);
        uintptr_t end_addr = *reinterpret_cast<uintptr_t*>(param2 + 0x38);

        spdlog::info("[SNS_POC] Array range: {:#x} - {:#x}", begin_addr, end_addr);

        if (begin_addr == 0 || end_addr == 0 || begin_addr >= end_addr) {
            spdlog::warn("[SNS_POC] Invalid array range, skipping parse");
        } else {
            // 计算元素数量
            size_t stride = 0x11E0;  // wxhelper: 4576 bytes per post
            size_t count = (end_addr - begin_addr) / stride;

            spdlog::info("[SNS_POC] Detected {} posts (stride={:#x})", count, stride);

            // 只读取第一个 post（最新的）
            if (count > 0) {
                uintptr_t post_addr = begin_addr;

                // wxhelper 偏移：
                // +0x00: sns_id (uint64_t)
                // +0x18: sender_id (wstring)
                // +0x38: create_time (uint32_t)
                // +0x48: content (wstring)

                uint64_t sns_id = *reinterpret_cast<uint64_t*>(post_addr + 0x00);
                uint32_t create_time = *reinterpret_cast<uint32_t*>(post_addr + 0x38);

                // 尝试读取 content（最关键的字段）
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

    } __except (EXCEPTION_EXECUTE_HANDLER) {
        spdlog::error("[SNS_POC] Exception while parsing param2 structure");
        spdlog::error("[SNS_POC] This likely means offsets are wrong for WeChat 4.1.7.30");
        spdlog::error("[SNS_POC] Need to use Frida/IDA to find correct offsets");
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

    // 签名扫描
    // 注意：这是从 wxhelper 3.9.5.81 提取的签名，可能需要调整
    //
    // wxhelper 中 OnSnsTimeLineSceneFinish 的签名（示例，需要从 IDA 提取实际签名）：
    // "48 89 5C 24 ?? 57 48 83 EC 30 48 8B F9"
    //
    // TODO: 需要在 IDA Pro 中分析 WeChat 4.1.7.30 的 Weixin.dll，
    //       搜索 "SnsTimeLineScene", "OnSnsFinish", "TimelineObject" 等字符串，
    //       提取正确的函数签名
    //
    // 暂时使用占位签名（会失败，需要替换）
    const char* signature = "48 89 5C 24 ?? 57 48 83 EC 30";

    spdlog::info("[SNS_POC] Scanning for OnSnsTimeLineSceneFinish...");
    spdlog::info("[SNS_POC] Signature: {}", signature);

    uintptr_t func_addr = SigScanner::find(module, signature);

    if (!func_addr) {
        spdlog::error("[SNS_POC] Failed to locate OnSnsTimeLineSceneFinish");
        spdlog::error("[SNS_POC] Signature might be wrong for WeChat 4.1.7.30");
        spdlog::error("[SNS_POC] Phase 0 cannot proceed - need to extract signature from IDA");
        return false;
    }

    spdlog::info("[SNS_POC] OnSnsTimeLineSceneFinish found at {:#x}", func_addr);

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
