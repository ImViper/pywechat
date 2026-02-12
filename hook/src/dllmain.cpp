/**
 * pywechat_hook DLL entry point.
 *
 * On DLL_PROCESS_ATTACH we spin up an init thread that:
 *   1. Checks the WeChat version
 *   2. Starts the Named Pipe server
 *   3. Installs any hooks
 *
 * On DLL_PROCESS_DETACH we clean up.
 */

#include <Windows.h>
#include <objbase.h>
#include <atomic>
#include <thread>

#include <spdlog/spdlog.h>
#include <spdlog/sinks/basic_file_sink.h>

#include "pipe_server.h"
#include "hook_manager.h"
#include "version_check.h"
#include "sns_comment.h"
#include "sns_moments_poc.h"  // Phase 0: Route B PoC

static std::thread g_init_thread;
static std::atomic<bool> g_running{false};

static void init_routine() {
    try {
        // Set up file logging
        auto logger = spdlog::basic_logger_mt("hook", "pywechat_hook.log", true);
        spdlog::set_default_logger(logger);
        spdlog::set_level(spdlog::level::debug);
        spdlog::flush_on(spdlog::level::debug);

        spdlog::info("pywechat_hook loaded, init starting");

        // Version check
        auto ver = pywechat::get_wechat_version();
        spdlog::info("WeChat version: {}", ver);

        // Initialize hook manager (MinHook lifecycle)
        pywechat::HookManager::instance().init();

        // Locate comment function via signature scan + install hook
        if (pywechat::init_sns_comment()) {
            if (pywechat::install_comment_hook()) {
                spdlog::info("comment hook installed");
            } else {
                spdlog::warn("comment hook install failed, direct-call only");
            }
        } else {
            spdlog::warn("sns_comment init failed, comment feature unavailable");
        }

        // Phase 0: Initialize SNS moments PoC hook
        if (pywechat::init_sns_moments_poc()) {
            spdlog::info("SNS moments PoC hook installed");
        } else {
            spdlog::warn("SNS moments PoC hook failed - Phase 0 cannot proceed");
            spdlog::warn("Need to extract correct signature from IDA Pro");
        }

        // Start pipe server (blocks until g_running == false)
        g_running.store(true);
        pywechat::PipeServer server;

        // COM init for pipe server thread — WeChat internal functions may
        // depend on COM being initialised on the calling thread (STA).
        HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
        bool com_ok = SUCCEEDED(hr);
        spdlog::info("COM init on pipe thread: {} (hr={:#x})", com_ok ? "ok" : "failed", (unsigned)hr);

        server.run(g_running);

        if (com_ok) CoUninitialize();

        spdlog::info("pipe server stopped, cleaning up");
    } catch (const std::exception& ex) {
        spdlog::error("init_routine exception: {}", ex.what());
    }
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved) {
    switch (reason) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        g_init_thread = std::thread(init_routine);
        g_init_thread.detach();
        break;

    case DLL_PROCESS_DETACH:
        g_running.store(false);
        pywechat::uninstall_comment_hook();
        pywechat::cleanup_sns_moments_poc();  // Phase 0: cleanup
        pywechat::HookManager::instance().cleanup();
        spdlog::info("pywechat_hook unloaded");
        spdlog::shutdown();
        break;
    }
    return TRUE;
}
