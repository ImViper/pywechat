#include "pipe_server.h"

#include <Windows.h>
#include <cstdint>
#include <chrono>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include "sns_comment.h"
#include "hook_manager.h"
#include "version_check.h"

using json = nlohmann::json;

namespace pywechat {

static constexpr DWORD PIPE_BUFFER_SIZE = 65536;
static constexpr DWORD CONNECT_TIMEOUT_MS = 1000;

PipeServer::PipeServer(const std::string& pipe_name)
    : pipe_name_(pipe_name) {}

PipeServer::~PipeServer() = default;

void PipeServer::run(std::atomic<bool>& running) {
    spdlog::info("pipe server starting on {}", pipe_name_);

    while (running.load()) {
        HANDLE pipe = CreateNamedPipeA(
            pipe_name_.c_str(),
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            PIPE_BUFFER_SIZE,
            PIPE_BUFFER_SIZE,
            CONNECT_TIMEOUT_MS,
            nullptr
        );

        if (pipe == INVALID_HANDLE_VALUE) {
            spdlog::error("CreateNamedPipe failed: {}", GetLastError());
            Sleep(500);
            continue;
        }

        // Wait for client connection (with timeout via overlapped could be
        // better, but keeping it simple for now)
        BOOL connected = ConnectNamedPipe(pipe, nullptr)
            ? TRUE
            : (GetLastError() == ERROR_PIPE_CONNECTED);

        if (!connected || !running.load()) {
            CloseHandle(pipe);
            continue;
        }

        spdlog::debug("client connected");
        handle_client(pipe, running);

        DisconnectNamedPipe(pipe);
        CloseHandle(pipe);
        spdlog::debug("client disconnected");
    }

    spdlog::info("pipe server stopped");
}

void PipeServer::handle_client(void* pipe_handle, std::atomic<bool>& running) {
    HANDLE pipe = static_cast<HANDLE>(pipe_handle);
    while (running.load()) {
        std::string request;
        if (!read_message(pipe, request)) {
            break;  // client disconnected or error
        }

        spdlog::debug("recv: {}", request);
        std::string response = dispatch(request);
        spdlog::debug("send: {}", response);

        if (!write_message(pipe, response)) {
            break;
        }
    }
}

std::string PipeServer::dispatch(const std::string& request_json) {
    auto start = std::chrono::steady_clock::now();
    json resp;
    resp["v"] = 1;

    try {
        auto req = json::parse(request_json);
        std::string cmd = req.value("cmd", "");
        std::string task_id = req.value("task_id", "");
        resp["task_id"] = task_id;

        if (cmd == "ping") {
            resp["ok"] = true;
            resp["error_code"] = 0;
            resp["error_message"] = "";
            resp["data"] = json::object();

        } else if (cmd == "version") {
            resp["ok"] = true;
            resp["error_code"] = 0;
            resp["error_message"] = "";
            resp["data"] = {{"wechat_version", get_wechat_version()}};

        } else if (cmd == "comment") {
            std::string sns_id = req.value("sns_id", "");
            std::string content = req.value("content", "");
            std::string reply_to = req.value("reply_to", "");
            bool allow_queue_fallback = req.value("allow_queue_fallback", false);
            bool prefer_arg1_template = req.value("prefer_arg1_template", true);
            std::string execution_mode = req.value("execution_mode", "pipe_thread");
            std::string arg1_mode = req.value("arg1_mode", "template");
            bool tls_copy = req.value("tls_copy", false);
            uint32_t wait_timeout_ms = req.value("wait_timeout_ms", 1500u);
            if (wait_timeout_ms < 100) wait_timeout_ms = 100;
            if (wait_timeout_ms > 30000) wait_timeout_ms = 30000;

            // Compute Weixin.dll base for RVA calculation
            uintptr_t weixin_base = 0;
            HMODULE hWeixin = GetModuleHandleA("Weixin.dll");
            if (!hWeixin) hWeixin = GetModuleHandleA("WeChatWin.dll");
            if (hWeixin) weixin_base = reinterpret_cast<uintptr_t>(hWeixin);

            CommentResult result;
            if (execution_mode == "capture_thread") {
                result = sns_do_comment_on_capture_thread(
                    sns_id, content, reply_to, prefer_arg1_template, wait_timeout_ms);
            } else {
                // Default: execute direct call on pipe server thread.
                result = sns_do_comment(sns_id, content, reply_to, prefer_arg1_template, arg1_mode, tls_copy);
            }
            if (allow_queue_fallback && !result.success && result.error_code == 30) {
                // SEH exception or null return - try hook+inject fallback
                spdlog::info("direct call failed, falling back to hook_comment queue");
                bool queued = sns_queue_comment(sns_id, content, reply_to);
                resp["ok"] = queued;
                resp["error_code"] = queued ? 0 : 50;
                resp["error_message"] = queued
                    ? "queued for hook injection (trigger a comment in UI)"
                    : "hook not installed, cannot queue";
                resp["data"] = {
                    {"method", "hook_inject"},
                    {"call_method", result.call_method},
                    {"state_captured", has_captured_state()},
                    {"context_fresh", is_captured_state_fresh()},
                    {"capture_age_ms", get_capture_age_ms()},
                    {"arg1_template_ready", has_arg1_template()},
                    {"arg1_template_used", result.arg1_template_used},
                    {"arg1_mode", result.arg1_mode},
                    {"prefer_arg1_template", prefer_arg1_template},
                    {"queue_fallback_enabled", allow_queue_fallback},
                    {"execution_mode", execution_mode},
                    {"wait_timeout_ms", wait_timeout_ms},
                    {"direct_error", result.error_message},
                    {"seh_code", result.seh_code},
                    {"call_latency_ms", result.latency_ms},
                    {"crash_rip", result.crash_rip},
                    {"crash_rip_rva", (weixin_base && result.crash_rip) ? result.crash_rip - weixin_base : 0},
                    {"crash_fault_addr", result.crash_fault_addr},
                    {"crash_fault_type", result.crash_fault_type},
                    {"crash_rcx", result.crash_rcx},
                    {"crash_rdx", result.crash_rdx},
                    {"crash_r8", result.crash_r8},
                    {"crash_r9", result.crash_r9},
                    {"crash_rsp", result.crash_rsp},
                    {"crash_rbp", result.crash_rbp},
                    {"weixin_base", weixin_base},
                };
            } else {
                resp["ok"] = result.success;
                resp["error_code"] = result.error_code;
                resp["error_message"] = result.error_message;
                resp["data"] = {
                    {"method", result.success ? "direct_call" : "direct_failed"},
                    {"call_method", result.call_method},
                    {"state_captured", has_captured_state()},
                    {"context_fresh", is_captured_state_fresh()},
                    {"capture_age_ms", get_capture_age_ms()},
                    {"arg1_template_ready", has_arg1_template()},
                    {"arg1_template_used", result.arg1_template_used},
                    {"arg1_mode", result.arg1_mode},
                    {"prefer_arg1_template", prefer_arg1_template},
                    {"queue_fallback_enabled", allow_queue_fallback},
                    {"execution_mode", execution_mode},
                    {"wait_timeout_ms", wait_timeout_ms},
                    {"direct_error", result.error_message},
                    {"seh_code", result.seh_code},
                    {"call_latency_ms", result.latency_ms},
                    {"crash_rip", result.crash_rip},
                    {"crash_rip_rva", (weixin_base && result.crash_rip) ? result.crash_rip - weixin_base : 0},
                    {"crash_fault_addr", result.crash_fault_addr},
                    {"crash_fault_type", result.crash_fault_type},
                    {"crash_rcx", result.crash_rcx},
                    {"crash_rdx", result.crash_rdx},
                    {"crash_r8", result.crash_r8},
                    {"crash_r9", result.crash_r9},
                    {"crash_rsp", result.crash_rsp},
                    {"crash_rbp", result.crash_rbp},
                    {"weixin_base", weixin_base},
                };
            }

        } else if (cmd == "hook_comment") {
            // 显式使用 hook+inject 模式 (队列等待下一次合法调用)
            std::string sns_id = req.value("sns_id", "");
            std::string content = req.value("content", "");
            std::string reply_to = req.value("reply_to", "");

            bool queued = sns_queue_comment(sns_id, content, reply_to);
            resp["ok"] = queued;
            resp["error_code"] = queued ? 0 : 50;
            resp["error_message"] = queued
                ? "queued for hook injection"
                : "hook not installed";
            resp["data"] = json::object();

        } else if (cmd == "status") {
            resp["ok"] = true;
            resp["error_code"] = 0;
            resp["error_message"] = "";
            resp["data"] = {
                {"hook_installed", is_comment_hook_installed()},
                {"state_captured", has_captured_state()},
                {"context_fresh", is_captured_state_fresh()},
                {"capture_age_ms", get_capture_age_ms()},
                {"capture_thread_id", get_capture_thread_id()},
                {"request_template_ready", has_request_template()},
                {"arg1_template_ready", has_arg1_template()},
                {"parallel_ready", g_cached_req_0x368_valid},
                {"tls_override_enabled", g_tls_override_enabled},
                {"tls_accessor_override_hits", g_tls_accessor_override_hits.load()},
                {"tls_accessor_worker_miss", g_tls_accessor_worker_miss.load()},
            };

        } else if (cmd == "diagnose_thread") {
            auto diag = diagnose_thread_context();

            json capture_tls = json::array();
            json pipe_tls = json::array();
            for (size_t i = 0; i < diag.capture_tls_values.size(); i++) {
                capture_tls.push_back(diag.capture_tls_values[i]);
            }
            for (size_t i = 0; i < diag.pipe_tls_values.size(); i++) {
                pipe_tls.push_back(diag.pipe_tls_values[i]);
            }
            json capture_only = json::array();
            for (int slot : diag.capture_only_slots) {
                capture_only.push_back(slot);
            }

            resp["ok"] = true;
            resp["error_code"] = 0;
            resp["error_message"] = "";
            resp["data"] = {
                {"capture_thread_id", diag.capture_thread_id},
                {"pipe_thread_id", diag.pipe_thread_id},
                {"capture_tls_nonzero", diag.capture_tls_nonzero},
                {"pipe_tls_nonzero", diag.pipe_tls_nonzero},
                {"capture_only_slots", capture_only},
                {"pipe_com_initialized", diag.pipe_com_initialized},
                {"capture_is_gui_thread", diag.capture_is_gui_thread},
                {"pipe_is_gui_thread", diag.pipe_is_gui_thread},
                {"capture_tls_values", capture_tls},
                {"pipe_tls_values", pipe_tls},
            };

        } else if (cmd == "query_sns_id") {
            std::string author = req.value("author", "");
            std::string content_hash = req.value("content_hash", "");
            auto& mgr = HookManager::instance();
            std::string sns_id = mgr.lookup_sns_id(author, content_hash);
            if (!sns_id.empty()) {
                resp["ok"] = true;
                resp["error_code"] = 0;
                resp["error_message"] = "";
                resp["data"] = {{"sns_id", sns_id}};
            } else {
                resp["ok"] = false;
                resp["error_code"] = 20;  // SNS_ID_NOT_FOUND
                resp["error_message"] = "sns_id not found in cache";
                resp["data"] = json::object();
            }

        } else if (cmd == "get_latest_sns_id") {
            auto& mgr = HookManager::instance();
            std::string latest = mgr.get_latest_sns_id();
            if (!latest.empty()) {
                resp["ok"] = true;
                resp["error_code"] = 0;
                resp["error_message"] = "";
                resp["data"] = {{"sns_id", latest}};
            } else {
                resp["ok"] = false;
                resp["error_code"] = 20;  // SNS_ID_NOT_FOUND
                resp["error_message"] = "no sns_id captured yet (trigger a comment in UI first)";
                resp["data"] = json::object();
            }

        } else if (cmd == "batch_comment") {
            std::string sns_id = req.value("sns_id", "");
            std::string reply_to = req.value("reply_to", "");
            int concurrency = req.value("concurrency", 10);

            // 解析 comments 数组
            std::vector<std::string> comments;
            if (req.contains("comments") && req["comments"].is_array()) {
                for (const auto& c : req["comments"]) {
                    comments.push_back(c.get<std::string>());
                }
            }

            if (comments.empty()) {
                resp["ok"] = false;
                resp["error_code"] = 10;
                resp["error_message"] = "comments array is empty";
                resp["data"] = json::object();
            } else if (sns_id.empty()) {
                resp["ok"] = false;
                resp["error_code"] = 20;
                resp["error_message"] = "sns_id is required for batch_comment";
                resp["data"] = json::object();
            } else {
                auto batch = sns_do_comment_batch(sns_id, comments, reply_to, concurrency);
                json results_arr = json::array();
                for (const auto& r : batch.results) {
                    results_arr.push_back({
                        {"success", r.success},
                        {"error_code", r.error_code},
                        {"error_message", r.error_message},
                        {"call_method", r.call_method},
                        {"latency_ms", r.latency_ms},
                    });
                }
                const bool all_ok = (batch.total > 0 && batch.succeeded == batch.total);
                resp["ok"] = all_ok;
                resp["error_code"] = all_ok ? 0 : 30;
                resp["error_message"] = (batch.failed > 0)
                    ? std::to_string(batch.failed) + "/" + std::to_string(batch.total) + " failed"
                    : "";
                resp["data"] = {
                    {"total", batch.total},
                    {"succeeded", batch.succeeded},
                    {"failed", batch.failed},
                    {"total_latency_ms", batch.total_latency_ms},
                    {"results", results_arr},
                };
            }

        } else if (cmd == "test_hook_trigger") {
            std::string result = test_hook_trigger();
            resp["ok"] = true;
            resp["error_code"] = 0;
            resp["error_message"] = "";
            resp["data"] = {{"result", result}};

        } else if (cmd == "read_memory") {
            uintptr_t rva = req.value("rva", (uintptr_t)0);
            size_t size = req.value("size", (size_t)64);
            auto mem = read_memory_at_rva(rva, size);
            if (mem.success) {
                // Convert bytes to hex string
                std::string hex;
                hex.reserve(mem.bytes.size() * 2);
                for (uint8_t b : mem.bytes) {
                    char buf[4];
                    sprintf_s(buf, "%02x", b);
                    hex += buf;
                }
                resp["ok"] = true;
                resp["error_code"] = 0;
                resp["error_message"] = "";
                resp["data"] = {
                    {"address", mem.address},
                    {"rva", mem.rva},
                    {"size", mem.bytes.size()},
                    {"hex", hex},
                };
            } else {
                resp["ok"] = false;
                resp["error_code"] = 30;
                resp["error_message"] = mem.error_message;
                resp["data"] = {{"rva", mem.rva}};
            }

        } else if (cmd == "tls_diag") {
            auto info = get_tls_diag_info();
            json fls_only = json::array();
            for (int slot : info.capture_only_fls_slots) {
                fls_only.push_back(slot);
            }
            resp["ok"] = true;
            resp["error_code"] = 0;
            resp["error_message"] = "";
            resp["data"] = {
                {"has_tls_directory", info.has_tls_directory},
                {"tls_start_rva", info.tls_start_rva},
                {"tls_end_rva", info.tls_end_rva},
                {"tls_index_addr", info.tls_index_addr},
                {"tls_index_value", info.tls_index_value},
                {"tls_data_size", info.tls_data_size},
                {"capture_implicit_tls_valid", info.capture_implicit_tls_valid},
                {"capture_tls_block_addr", info.capture_tls_block_addr},
                {"current_tls_block_addr", info.current_tls_block_addr},
                {"capture_fls_nonzero", info.capture_fls_nonzero},
                {"current_fls_nonzero", info.current_fls_nonzero},
                {"capture_only_fls_slots", fls_only},
            };

        } else if (cmd == "parallel_comment") {
            std::string sns_id = req.value("sns_id", "");
            std::string reply_to = req.value("reply_to", "");
            int max_concurrency = req.value("max_concurrency", 10);
            std::string tls_mode = req.value("tls_mode", "implicit");

            std::vector<std::string> comments;
            if (req.contains("comments") && req["comments"].is_array()) {
                for (const auto& c : req["comments"]) {
                    comments.push_back(c.get<std::string>());
                }
            }

            if (comments.empty()) {
                resp["ok"] = false;
                resp["error_code"] = 10;
                resp["error_message"] = "comments array is empty";
                resp["data"] = json::object();
            } else if (sns_id.empty()) {
                resp["ok"] = false;
                resp["error_code"] = 20;
                resp["error_message"] = "sns_id is required";
                resp["data"] = json::object();
            } else {
                auto batch = sns_do_comment_parallel(
                    sns_id, comments, reply_to, max_concurrency, tls_mode);
                json results_arr = json::array();
                for (const auto& r : batch.results) {
                    results_arr.push_back({
                        {"success", r.success},
                        {"error_code", r.error_code},
                        {"error_message", r.error_message},
                        {"call_method", r.call_method},
                        {"latency_ms", r.latency_ms},
                        {"seh_code", r.seh_code},
                        {"crash_rip", r.crash_rip},
                        {"crash_fault_addr", r.crash_fault_addr},
                    });
                }
                const bool all_ok = (batch.total > 0 && batch.succeeded == batch.total);
                resp["ok"] = all_ok;
                resp["error_code"] = all_ok ? 0 : 30;
                resp["error_message"] = (batch.failed > 0)
                    ? std::to_string(batch.failed) + "/" + std::to_string(batch.total) + " failed"
                    : "";
                resp["data"] = {
                    {"total", batch.total},
                    {"succeeded", batch.succeeded},
                    {"failed", batch.failed},
                    {"total_latency_ms", batch.total_latency_ms},
                    {"tls_mode", tls_mode},
                    {"results", results_arr},
                };
            }

        } else if (cmd == "piggyback_comment") {
            std::string sns_id = req.value("sns_id", "");
            std::string reply_to = req.value("reply_to", "");
            int max_concurrency = req.value("max_concurrency", 10);
            int timeout_ms = req.value("timeout_ms", 30000);

            std::vector<std::string> comments;
            if (req.contains("comments") && req["comments"].is_array()) {
                for (const auto& c : req["comments"]) {
                    comments.push_back(c.get<std::string>());
                }
            }

            if (comments.empty()) {
                resp["ok"] = false;
                resp["error_code"] = 10;
                resp["error_message"] = "comments array is empty";
                resp["data"] = json::object();
            } else {
                auto batch = sns_queue_piggyback(
                    sns_id, comments, reply_to,
                    max_concurrency, timeout_ms);
                json results_arr = json::array();
                for (const auto& r : batch.results) {
                    results_arr.push_back({
                        {"success", r.error_code == 0},
                        {"error_code", r.error_code},
                        {"error_message", r.error_message},
                        {"call_method", r.call_method},
                        {"latency_ms", r.latency_ms},
                    });
                }
                const bool all_ok = (batch.total > 0 && batch.succeeded == batch.total);
                resp["ok"] = all_ok;
                resp["error_code"] = all_ok ? 0 : 30;
                resp["error_message"] = (batch.failed > 0)
                    ? std::to_string(batch.failed) + "/"
                      + std::to_string(batch.total) + " failed"
                    : "";
                resp["data"] = {
                    {"total", batch.total},
                    {"succeeded", batch.succeeded},
                    {"failed", batch.failed},
                    {"total_latency_ms", batch.total_latency_ms},
                    {"results", results_arr},
                };
            }

        } else if (cmd == "set_config") {
            std::string key = req.value("key", "");
            if (key == "tls_override_enabled") {
                g_tls_override_enabled = req.value("value", true);
                spdlog::info("config set: tls_override_enabled = {}", g_tls_override_enabled);
                resp["ok"] = true;
                resp["error_code"] = 0;
                resp["data"] = {{"key", key}, {"value", g_tls_override_enabled}};
            } else {
                resp["ok"] = false;
                resp["error_code"] = 10;
                resp["error_message"] = "unknown config key: " + key;
                resp["data"] = json::object();
            }

        } else {
            resp["ok"] = false;
            resp["error_code"] = 10;  // INVALID_COMMAND
            resp["error_message"] = "unknown command: " + cmd;
            resp["data"] = json::object();
        }

    } catch (const std::exception& ex) {
        resp["ok"] = false;
        resp["error_code"] = 1;  // UNKNOWN
        resp["error_message"] = std::string("dispatch error: ") + ex.what();
        resp["data"] = json::object();
    }

    auto end = std::chrono::steady_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    resp["latency_ms"] = static_cast<int>(ms);

    // Use error_handler_t::replace to avoid crash on non-UTF-8 strings
    return resp.dump(-1, ' ', false, json::error_handler_t::replace);
}

bool PipeServer::read_message(void* pipe, std::string& out) {
    HANDLE h = static_cast<HANDLE>(pipe);
    // Read 4-byte length header
    uint32_t length = 0;
    DWORD bytes_read = 0;
    if (!ReadFile(h, &length, 4, &bytes_read, nullptr) || bytes_read != 4) {
        return false;
    }
    if (length == 0 || length > PIPE_BUFFER_SIZE) {
        return false;
    }
    // Read payload
    out.resize(length);
    if (!ReadFile(h, out.data(), length, &bytes_read, nullptr) || bytes_read != length) {
        return false;
    }
    return true;
}

bool PipeServer::write_message(void* pipe, const std::string& msg) {
    HANDLE h = static_cast<HANDLE>(pipe);
    uint32_t length = static_cast<uint32_t>(msg.size());
    DWORD written = 0;
    if (!WriteFile(h, &length, 4, &written, nullptr) || written != 4) {
        return false;
    }
    if (!WriteFile(h, msg.data(), length, &written, nullptr) || written != length) {
        return false;
    }
    FlushFileBuffers(h);
    return true;
}

}  // namespace pywechat
