#include "version_check.h"

#include <Windows.h>
#include <sstream>

#include <spdlog/spdlog.h>

#pragma comment(lib, "Version.lib")

namespace pywechat {

std::string get_wechat_version() {
    // WeChat 4.0+ renamed WeChatWin.dll to Weixin.dll
    const char* module_names[] = {"Weixin.dll", "WeChatWin.dll"};
    HMODULE hMod = nullptr;
    for (auto name : module_names) {
        hMod = GetModuleHandleA(name);
        if (hMod) {
            spdlog::info("Found module: {}", name);
            break;
        }
    }
    if (!hMod) {
        spdlog::warn("Neither Weixin.dll nor WeChatWin.dll found");
        return "unknown";
    }

    // Get the module file path
    char path[MAX_PATH] = {};
    if (!GetModuleFileNameA(hMod, path, MAX_PATH)) {
        return "unknown";
    }

    // Query version info size
    DWORD dummy = 0;
    DWORD size = GetFileVersionInfoSizeA(path, &dummy);
    if (size == 0) {
        return "unknown";
    }

    std::vector<uint8_t> data(size);
    if (!GetFileVersionInfoA(path, 0, size, data.data())) {
        return "unknown";
    }

    // Extract fixed file info
    VS_FIXEDFILEINFO* info = nullptr;
    UINT len = 0;
    if (!VerQueryValueA(data.data(), "\\", reinterpret_cast<LPVOID*>(&info), &len) || !info) {
        return "unknown";
    }

    std::ostringstream oss;
    oss << HIWORD(info->dwFileVersionMS) << "."
        << LOWORD(info->dwFileVersionMS) << "."
        << HIWORD(info->dwFileVersionLS) << "."
        << LOWORD(info->dwFileVersionLS);

    return oss.str();
}

}  // namespace pywechat
