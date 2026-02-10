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

    // Hook installation is handled by dllmain.cpp (init_sns_comment + install_comment_hook)
    // after HookManager::init() completes. This ensures MH_Initialize() runs first.
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

void HookManager::cache_latest_sns_id(const std::string& sns_id) {
    std::lock_guard<std::mutex> lock(cache_mutex_);
    latest_sns_id_ = sns_id;
    spdlog::debug("cached latest sns_id: {}", sns_id);
}

std::string HookManager::get_latest_sns_id() const {
    std::lock_guard<std::mutex> lock(cache_mutex_);
    return latest_sns_id_;
}

std::string HookManager::make_cache_key(const std::string& author,
                                          const std::string& content_hash) {
    return author + '\0' + content_hash;
}

}  // namespace pywechat
