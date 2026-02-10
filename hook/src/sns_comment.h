#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace pywechat {

/**
 * Result of a comment attempt via direct function call.
 */
struct CommentResult {
    bool success = false;
    int error_code = 0;
    std::string error_message;
    std::string call_method;  // "trampoline" | "direct"
    int latency_ms = 0;
    uint32_t seh_code = 0;
    bool arg1_template_used = false;
    // VEH crash diagnostics (populated on access violation)
    uintptr_t crash_rip = 0;
    uintptr_t crash_fault_addr = 0;
    uint64_t  crash_fault_type = 0;  // 0=read, 1=write, 8=DEP
    uintptr_t crash_rcx = 0;
    uintptr_t crash_rdx = 0;
    uintptr_t crash_r8 = 0;
    uintptr_t crash_r9 = 0;
    uintptr_t crash_rsp = 0;
    uintptr_t crash_rbp = 0;
    // arg1 mode used
    std::string arg1_mode;
};

/**
 * Result of a batch comment attempt.
 */
struct BatchCommentResult {
    int total = 0;
    int succeeded = 0;
    int failed = 0;
    int total_latency_ms = 0;  // wall-clock time for entire batch
    std::vector<CommentResult> results;
};

/**
 * WeChat 内部评论请求结构体 (逆向自 cgi_A_caller_2 arg0)。
 *
 * 基于 deep_struct_probe.js 动态验证 (WeChat 4.1.7.30):
 *   +0x00: void**      vtable       (RVA 0x0859e6d8, 4 个虚函数 + COL)
 *   +0x08: std::string sns_id       (SSO, e.g. "q756627124")
 *   +0x28: void*       author_info  (指向含昵称的结构, e.g. "小蔡")
 *   +0x30: void*       author_info2 (同上, 偏移 -0x10)
 *   +0x38: std::string content      (SSO, UTF-8 评论文本)
 *   +0x58: std::string reply_to     (空=顶层评论, 非空=回复某人)
 *   +0x78: uint8_t[16] reserved1
 *   +0x88: uint32_t    comment_type (2=文本评论)
 *   +0x8C: uint32_t    create_time  (Unix timestamp)
 *   +0x90: uint8_t[16] reserved2
 *   +0xA0: std::string comment_key  ("sns_comment:{obj_id}_{ts}_{seq}")
 *
 * 注意: 不要用 C++ std::string 赋值操作修改 WeChat 的结构体字段,
 * 因为可能存在 CRT 分配器不匹配。用 raw memory 操作 (write_msvc_string).
 */
struct SnsCommentRequestData {
    void**       vtable;        // +0x00 (RVA 0x0859e6d8)
    std::string  sns_id;        // +0x08
    void*        author_info;   // +0x28 (指向含昵称的结构)
    void*        author_info2;  // +0x30
    std::string  content;       // +0x38
    std::string  reply_to;      // +0x58
    uint8_t      reserved1[16]; // +0x78
    uint32_t     comment_type;  // +0x88
    uint32_t     create_time;   // +0x8C
    uint8_t      reserved2[16]; // +0x90
    std::string  comment_key;   // +0xA0
    // +0xC0: 后续字段 (文件路径等, 暂不需要)
};

// ===== 初始化 + 特征码扫描 =====

/// Initialize: locate cgi_A_caller_2 via signature scan.
/// Must be called once after DLL injection, before other sns_* functions.
bool init_sns_comment();

// ===== MinHook Hook (PoC-verified approach) =====

/// Install MinHook on cgi_A_caller_2 to enable interception + state capture.
/// Must be called after init_sns_comment() and MH_Initialize().
bool install_comment_hook();

/// Remove the MinHook hook.
void uninstall_comment_hook();

/// Queue a comment for injection via the next legitimate cgi_A_caller_2 call.
/// The hook will modify the request struct fields on the next intercepted call.
/// Returns true if queued successfully.
bool sns_queue_comment(const std::string& sns_id,
                       const std::string& content,
                       const std::string& reply_to);

/// Check if runtime state has been captured from a legitimate call.
bool has_captured_state();

/// Check if runtime state capture is still fresh enough for direct-call reuse.
bool is_captured_state_fresh(uint64_t max_age_ms = 2000);

/// Runtime diagnostics for status API.
bool is_comment_hook_installed();
uint64_t get_capture_age_ms();
uint32_t get_capture_thread_id();
bool has_request_template();
bool has_arg1_template();

// ===== 直接调用 (experimental, may crash) =====

/// Send a comment by directly calling cgi_A_caller_2 with a constructed struct.
/// Protected by SEH. Uses captured runtime state if available.
/// arg1_mode: "template" (default), "null", "zeroed", "captured_ptr"
/// tls_copy: if true, copy capture thread's TLS slots to current thread before call
CommentResult sns_do_comment(const std::string& sns_id,
                              const std::string& content,
                              const std::string& reply_to,
                              bool prefer_arg1_template = true,
                              const std::string& arg1_mode = "template",
                              bool tls_copy = false);

/// Schedule direct-call execution on the hook capture thread.
/// The call is performed when the next hook callback arrives on that thread.
/// Returns timeout error if no callback arrives within wait_timeout_ms.
CommentResult sns_do_comment_on_capture_thread(
    const std::string& sns_id,
    const std::string& content,
    const std::string& reply_to,
    bool prefer_arg1_template = true,
    uint32_t wait_timeout_ms = 1500);

/// Send multiple comments concurrently using N threads.
/// Each thread calls sns_do_comment independently.
BatchCommentResult sns_do_comment_batch(
    const std::string& sns_id,
    const std::vector<std::string>& comments,
    const std::string& reply_to,
    int concurrency = 10);

// ===== Hook trigger test =====

/// Call target function directly to verify MinHook detour fires.
/// Returns diagnostic string with results.
std::string test_hook_trigger();

// ===== Memory read (for crash-site disassembly) =====

struct ReadMemoryResult {
    bool success = false;
    std::string error_message;
    uintptr_t address = 0;       // absolute address read from
    uintptr_t rva = 0;           // requested RVA
    std::vector<uint8_t> bytes;  // raw bytes
};

/// Read N bytes from Weixin.dll base + rva.
ReadMemoryResult read_memory_at_rva(uintptr_t rva, size_t size);

// ===== TLS diagnostics (implicit TLS / FLS) =====

struct TlsDiagInfo {
    // PE TLS Directory
    bool has_tls_directory = false;
    uintptr_t tls_start_rva = 0;
    uintptr_t tls_end_rva = 0;
    uintptr_t tls_index_addr = 0;
    uint32_t tls_index_value = 0;
    size_t tls_data_size = 0;
    // Implicit TLS comparison (capture thread vs current thread)
    bool capture_implicit_tls_valid = false;
    uintptr_t capture_tls_block_addr = 0;
    uintptr_t current_tls_block_addr = 0;
    // FLS slots
    int capture_fls_nonzero = 0;
    int current_fls_nonzero = 0;
    std::vector<int> capture_only_fls_slots;
};

/// Collect implicit TLS and FLS diagnostics.
TlsDiagInfo get_tls_diag_info();

// ===== Cached request->+0x368 (enables parallel calling) =====

/// Exposed state for status API
extern bool g_cached_req_0x368_valid;

// ===== Parallel comment =====

/// Send multiple comments in parallel, copying thread-local context
/// from the capture thread to each worker thread.
/// tls_mode: "implicit" (copy PE TLS block), "fls" (copy FLS slots),
///           "both" (copy both), "none" (no TLS copy)
BatchCommentResult sns_do_comment_parallel(
    const std::string& sns_id,
    const std::vector<std::string>& comments,
    const std::string& reply_to,
    int max_concurrency = 10,
    const std::string& tls_mode = "implicit");

/// Queue comments for piggyback execution inside the next hook callback.
/// Blocks until the hook fires and drains the batch, or timeout.
/// This is the safest parallel path — arg1 is guaranteed valid.
BatchCommentResult sns_queue_piggyback(
    const std::string& sns_id,
    const std::vector<std::string>& comments,
    const std::string& reply_to,
    int max_concurrency = 10,
    int timeout_ms = 30000);

// ===== Thread diagnostics =====

struct ThreadDiagResult {
    // TLS comparison
    int capture_tls_nonzero = 0;     // # of non-null TLS slots on capture thread
    int pipe_tls_nonzero = 0;        // # of non-null TLS slots on pipe thread
    std::vector<int> capture_only_slots;  // slots with value only on capture thread
    // COM state
    bool pipe_com_initialized = false;
    // IsGUIThread
    bool capture_is_gui_thread = false;
    bool pipe_is_gui_thread = false;
    // Thread IDs
    uint32_t capture_thread_id = 0;
    uint32_t pipe_thread_id = 0;
    // capture TLS slot values (first 64)
    std::vector<uint64_t> capture_tls_values;
    std::vector<uint64_t> pipe_tls_values;
};

/// Collect thread diagnostics comparing capture thread vs pipe thread.
ThreadDiagResult diagnose_thread_context();

}  // namespace pywechat
