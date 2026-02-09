#pragma once

#include <mutex>
#include <string>
#include <unordered_map>

namespace pywechat {

/**
 * Manages MinHook lifecycle and the SNS ID cache.
 *
 * Singleton -- use HookManager::instance().
 */
class HookManager {
public:
    static HookManager& instance();

    /// Initialize MinHook and install hooks.
    void init();

    /// Remove all hooks and uninitialize MinHook.
    void cleanup();

    /// Cache a mapping: (author, content_hash) -> sns_id
    void cache_sns_id(const std::string& author,
                      const std::string& content_hash,
                      const std::string& sns_id);

    /// Look up a cached sns_id. Returns empty string if not found.
    std::string lookup_sns_id(const std::string& author,
                              const std::string& content_hash) const;

private:
    HookManager() = default;
    ~HookManager() = default;
    HookManager(const HookManager&) = delete;
    HookManager& operator=(const HookManager&) = delete;

    bool initialized_ = false;
    mutable std::mutex cache_mutex_;
    // key = "author\0content_hash"
    std::unordered_map<std::string, std::string> sns_id_cache_;

    static std::string make_cache_key(const std::string& author,
                                       const std::string& content_hash);
};

}  // namespace pywechat
