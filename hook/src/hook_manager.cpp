#include "hook_manager.h"

#include <spdlog/spdlog.h>

// MinHook
#include <MinHook.h>

namespace pywechat {

HookManager& HookManager::instance() {
    static HookManager inst;
    return inst;
}

void HookManager::init() {
    if (initialized_) return;

    MH_STATUS status = MH_Initialize();
    if (status != MH_OK) {
        spdlog::error("MH_Initialize failed: {}", MH_StatusToString(status));
        return;
    }

    spdlog::info("MinHook initialized");
    initialized_ = true;

    /*
     * TODO(reverse): Install hooks here.
     *
     * Example: hook the SNS timeline refresh function to capture sns_id
     * mappings as posts are loaded.
     *
     * auto addr = SigScanner::find("WeChatWin.dll", SNS_TIMELINE_SIG);
     * if (addr) {
     *     MH_CreateHook(reinterpret_cast<LPVOID>(addr),
     *                   &hooked_sns_timeline,
     *                   reinterpret_cast<LPVOID*>(&orig_sns_timeline));
     *     MH_EnableHook(reinterpret_cast<LPVOID>(addr));
     * }
     */
}

void HookManager::cleanup() {
    if (!initialized_) return;

    MH_DisableHook(MH_ALL_HOOKS);
    MH_Uninitialize();
    initialized_ = false;

    spdlog::info("MinHook cleaned up");
}

void HookManager::cache_sns_id(const std::string& author,
                                 const std::string& content_hash,
                                 const std::string& sns_id) {
    std::lock_guard<std::mutex> lock(cache_mutex_);
    auto key = make_cache_key(author, content_hash);
    sns_id_cache_[key] = sns_id;
    spdlog::debug("cached sns_id: {} + {} -> {}", author, content_hash, sns_id);
}

std::string HookManager::lookup_sns_id(const std::string& author,
                                         const std::string& content_hash) const {
    std::lock_guard<std::mutex> lock(cache_mutex_);
    auto key = make_cache_key(author, content_hash);
    auto it = sns_id_cache_.find(key);
    if (it != sns_id_cache_.end()) {
        return it->second;
    }
    return "";
}

std::string HookManager::make_cache_key(const std::string& author,
                                          const std::string& content_hash) {
    return author + '\0' + content_hash;
}

}  // namespace pywechat
