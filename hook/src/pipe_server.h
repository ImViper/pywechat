#pragma once

#include <atomic>
#include <string>

namespace pywechat {

/**
 * Named Pipe server that listens for JSON commands from the Python bridge.
 *
 * Wire format: [4-byte LE uint32 length][UTF-8 JSON payload]
 * Pipe name:   \\.\pipe\pywechat_hook
 */
class PipeServer {
public:
    explicit PipeServer(const std::string& pipe_name = R"(\\.\pipe\pywechat_hook)");
    ~PipeServer();

    /// Run the server loop; blocks until running becomes false.
    void run(std::atomic<bool>& running);

private:
    std::string pipe_name_;

    /// Handle a single client connection.
    void handle_client(void* pipe_handle, std::atomic<bool>& running);

    /// Dispatch a JSON command string and return a JSON response string.
    std::string dispatch(const std::string& request_json);

    /// Low-level read/write with length prefix.
    bool read_message(void* pipe, std::string& out);
    bool write_message(void* pipe, const std::string& msg);
};

}  // namespace pywechat
