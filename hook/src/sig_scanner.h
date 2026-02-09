#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace pywechat {

/**
 * Byte pattern scanner for finding function signatures in loaded modules.
 *
 * Pattern format: "48 8B C1 ?? 89 5C 24"
 *   - "??" matches any byte
 *   - Hex bytes are space-separated
 */
class SigScanner {
public:
    /// Scan a loaded module for the given byte pattern.
    /// Returns the address of the first match, or 0 if not found.
    static uintptr_t find(const std::string& module_name,
                          const std::string& pattern);

    /// Scan a memory range [start, start+size) for the pattern.
    static uintptr_t find_in_range(uintptr_t start, size_t size,
                                   const std::string& pattern);

private:
    struct PatternByte {
        uint8_t value;
        bool wildcard;
    };

    static std::vector<PatternByte> parse_pattern(const std::string& pattern);
};

}  // namespace pywechat
