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
#include <thread>

#include <spdlog/spdlog.h>
#include <spdlog/sinks/basic_file_sink.h>

#include "pipe_server.h"
#include "hook_manager.h"
#include "version_check.h"

static std::thread g_init_thread;
static bool g_running = false;

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

        // Initialize hook manager
        pywechat::HookManager::instance().init();

        // Start pipe server (blocks until g_running == false)
        g_running = true;
        pywechat::PipeServer server;
        server.run(g_running);

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
        g_running = false;
        pywechat::HookManager::instance().cleanup();
        spdlog::info("pywechat_hook unloaded");
        spdlog::shutdown();
        break;
    }
    return TRUE;
}
