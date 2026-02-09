#include "sig_scanner.h"

#include <Windows.h>
#include <sstream>

#include <spdlog/spdlog.h>

namespace pywechat {

std::vector<SigScanner::PatternByte> SigScanner::parse_pattern(const std::string& pattern) {
    std::vector<PatternByte> bytes;
    std::istringstream ss(pattern);
    std::string token;
    while (ss >> token) {
        if (token == "??" || token == "?") {
            bytes.push_back({0, true});
        } else {
            uint8_t val = static_cast<uint8_t>(std::stoul(token, nullptr, 16));
            bytes.push_back({val, false});
        }
    }
    return bytes;
}

uintptr_t SigScanner::find(const std::string& module_name, const std::string& pattern) {
    HMODULE hMod = GetModuleHandleA(module_name.c_str());
    if (!hMod) {
        spdlog::warn("SigScanner: module '{}' not found", module_name);
        return 0;
    }

    // Get module size from PE header
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(hMod);
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS*>(
        reinterpret_cast<uintptr_t>(hMod) + dos->e_lfanew
    );
    size_t module_size = nt->OptionalHeader.SizeOfImage;
    uintptr_t base = reinterpret_cast<uintptr_t>(hMod);

    spdlog::debug("SigScanner: scanning {} [{:#x} + {:#x}]", module_name, base, module_size);
    return find_in_range(base, module_size, pattern);
}

uintptr_t SigScanner::find_in_range(uintptr_t start, size_t size, const std::string& pattern) {
    auto pat = parse_pattern(pattern);
    if (pat.empty()) return 0;

    const uint8_t* data = reinterpret_cast<const uint8_t*>(start);
    size_t pat_len = pat.size();

    for (size_t i = 0; i + pat_len <= size; ++i) {
        bool match = true;
        for (size_t j = 0; j < pat_len; ++j) {
            if (!pat[j].wildcard && data[i + j] != pat[j].value) {
                match = false;
                break;
            }
        }
        if (match) {
            return start + i;
        }
    }
    return 0;
}

}  // namespace pywechat
