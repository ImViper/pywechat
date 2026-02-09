#include "pipe_server.h"

#include <Windows.h>
#include <cstdint>
#include <chrono>

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
            auto result = sns_do_comment(sns_id, content, reply_to);
            resp["ok"] = result.success;
            resp["error_code"] = result.error_code;
            resp["error_message"] = result.error_message;
            resp["data"] = json::object();

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

    return resp.dump();
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
