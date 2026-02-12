#include "sns_comment.h"

#include <Windows.h>
#include <objbase.h>
#include <array>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstring>
#include <deque>
#include <memory>
#include <ctime>
#include <mutex>
#include <queue>
#include <thread>
#include <vector>
#include <spdlog/spdlog.h>
#include <MinHook.h>

#include "sig_scanner.h"
#include "hook_manager.h"
#include "version_check.h"

// For NtQueryInformationThread (TLS copy experiment)
typedef LONG NTSTATUS;
typedef NTSTATUS (NTAPI *fn_NtQueryInformationThread)(
    HANDLE ThreadHandle,
    int ThreadInformationClass,
    PVOID ThreadInformation,
    ULONG ThreadInformationLength,
    PULONG ReturnLength
);

namespace pywechat {

/*
 * =====================================================================
 * 评论函数调用 — 逆向分析记录 (WeChat 4.1.7.30 / Weixin.dll 166.7 MB x64)
 * =====================================================================
 *
 * ===== Phase 1: 字符串锚点 (memory_scanner.py) =====
 *
 * Protobuf 消息类型:
 *   micromsg.SnsCommentRequest         @ RVA 0x0857ed68
 *   micromsg.SnsCommentResponse        @ RVA 0x0857edf8
 *   micromsg.SnsCommentContentRequest  @ RVA 0x0857d318
 *   micromsg.SnsCommentContentResult   @ RVA 0x0857d3a8
 *   micromsg.SnsCommentContent         @ RVA 0x084fc9d8
 *   micromsg.SnsCommentInfo            @ RVA 0x0857d298
 *   micromsg.SnsObjectOpRequest        @ RVA 0x0857f368
 *
 * CGI 路径:
 *   /cgi-bin/micromsg-bin/mmsnscomment  @ RVA 0x081ea28c
 *   /cgi-bin/micromsg-bin/mmsnsobjectop @ RVA 0x0859a19c
 *
 * 内核/UI 类名:
 *   kernel::SNSCommentContentInfo       @ RVA 0x09a540be
 *   kernel::foundation::CoCgiSendRequest (mmsnscomment_cgi_A 引用)
 *   mmui::TimelineCommentCollect        @ RVA 0x07ca301d
 *   mmui::CommentReplyTextEdit          @ RVA 0x09a53ee0
 *
 * ===== Phase 2-4: 静态/动态分析 =====
 *
 *   详见 docs/hook/hook_progress.md
 *
 *   最佳 Hook 点: cgi_A_caller_2 (RVA 0x049e9240)
 *   结构体布局: 见 sns_comment.h SnsCommentRequestData
 *   vtable: RVA 0x0859e6d8, 4 个虚函数 + COL
 *
 * ===== Phase 5: PoC 验证结果 =====
 *
 *   内容注入 PoC (poc_inject_comment.js) — 成功!
 *     - Hook cgi_A_caller_2, 拦截合法评论调用
 *     - 将 content (+0x38) 从 "测试" 替换为 "123"
 *     - 朋友圈成功显示 "123", 结构体偏移完全正确
 *     - 函数正常返回, 耗时 915ms
 *
 *   直接调用 PoC (poc_call_comment.js) — Frida 中 crash
 *     - 原因: Frida 线程 vs WeChat 工作线程上下文不匹配
 *     - C++ DLL 在进程内运行, 直接调用可能可行 (需验证)
 *
 *   实现策略:
 *     1. Hook+Inject (首选, PoC 已验证):
 *        - MinHook hook cgi_A_caller_2
 *        - 捕获运行时状态 (vtable, author_info, arg1-3)
 *        - 检查待发评论队列, 修改请求结构体字段
 *     2. 直接调用 (实验性):
 *        - 使用捕获的运行时状态构造结构体
 *        - SEH 保护, 失败时回退到 Hook+Inject
 *
 * =====================================================================
 */

// 主模块名 (4.0+ 为 Weixin.dll, 3.9.x 为 WeChatWin.dll)
static const char* resolve_module_name() {
    if (GetModuleHandleA("Weixin.dll")) return "Weixin.dll";
    if (GetModuleHandleA("WeChatWin.dll")) return "WeChatWin.dll";
    return nullptr;
}

// =====================================================================
// 特征码 — 从 WeChat 4.1.7.30 Weixin.dll 提取 (extract_signatures.py)
// =====================================================================

// 目标函数: cgi_A_caller_2 (RVA 0x049e9240)
// 功能: 构造评论请求对象, arg0 = 请求结构体指针 (含 sns_id + content)
static const char* SIG_CGI_A_CALLER_2 =
    "55 41 57 41 56 41 55 41 54 56 57 53 "  // push rbp/r15/r14/r13/r12/rsi/rdi/rbx
    "48 81 EC 38 03 00 00 "                  // sub rsp, 0x338
    "48 8D AC 24 80 00 00 00 "              // lea rbp, [rsp+0x80]
    "0F 29 B5 A0 02 00 00 "                 // movaps [rbp+0x2A0], xmm6
    "48 C7 85 98 02 00 00 FE FF FF FF "     // mov qword [rbp+0x298], -2
    "48 89 CE";                              // mov rsi, rcx

// 备选: cgi_A_caller_3_TOP (RVA 0x049bdc10) — 调用链最顶层入口
static const char* SIG_CGI_A_TOP =
    "55 41 56 56 57 53 "                     // push rbp/r14/rsi/rdi/rbx
    "48 81 EC 30 03 00 00 "                  // sub rsp, 0x330
    "48 8D AC 24 80 00 00 00 "              // lea rbp, [rsp+0x80]
    "0F 29 B5 A0 02 00 00 "                 // movaps [rbp+0x2A0], xmm6
    "48 C7 85 98 02 00 00 FE FF FF FF";     // mov qword [rbp+0x298], -2

// 已知 RVA (WeChat 4.1.7.30, 通过 Frida 动态验证确认)
static const uintptr_t COMMENT_FN_RVA = 0x049e9240;  // cgi_A_caller_2
static const uintptr_t TOP_FN_RVA     = 0x049bdc10;  // cgi_A_caller_3_TOP
static const uintptr_t VTABLE_RVA     = 0x0859e6d8;
static const uintptr_t TLS_ACCESSOR_RVA = 0x00b91e90; // TLS accessor (crash root cause)
static const uintptr_t ARG1_CTX_HELPER_RVA = 0x003c5970; // checks arg1->+0x368 before crash path

// =====================================================================
// MSVC std::string 内存布局辅助函数 (匹配 Frida PoC)
// =====================================================================

// MSVC x64 std::string: 32 bytes
//   +0x00: union { char buf[16]; char* ptr; }  (SSO when cap <= 15)
//   +0x10: uint64_t size
//   +0x18: uint64_t capacity

// 结构体字段偏移
static constexpr size_t OFF_VTABLE      = 0x00;
static constexpr size_t OFF_SNS_ID      = 0x08;
static constexpr size_t OFF_AUTHOR_INFO = 0x28;
static constexpr size_t OFF_CONTENT     = 0x38;
static constexpr size_t OFF_REPLY_TO    = 0x58;
static constexpr size_t OFF_COMMENT_TYPE = 0x88;
static constexpr size_t OFF_CREATE_TIME  = 0x8C;
static constexpr size_t OFF_COMMENT_KEY  = 0xA0;

// We replay a prefix of the original request object.
// Must be >= 0x370 to cover the +0x368 field (thread-local context pointer
// that the internal function reads but never writes).
static constexpr size_t REQUEST_CALL_BUFFER_SIZE = 0x400;
static constexpr uint64_t CONTEXT_FRESHNESS_MS = 2000;
// Must cover +0x368 which is read in the internal call chain.
static constexpr size_t ARG1_TEMPLATE_SIZE = 0x400;

/// Read a MSVC std::string from raw memory (safe, no CRT dependency)
static std::string read_msvc_string(const uint8_t* base) {
    auto size = *reinterpret_cast<const uint64_t*>(base + 0x10);
    auto cap  = *reinterpret_cast<const uint64_t*>(base + 0x18);
    if (size > 10000 || cap > 10000000) return "";
    const char* data = (cap <= 15)
        ? reinterpret_cast<const char*>(base)
        : *reinterpret_cast<const char* const*>(base);
    if (size == 0) return "";
    return std::string(data, static_cast<size_t>(size));
}

/// Write to a MSVC std::string in SSO mode (max 15 bytes, no heap alloc needed)
/// Returns false if text is too long for SSO
static bool write_msvc_string_sso(uint8_t* base, const std::string& text) {
    if (text.size() > 15) {
        spdlog::warn("write_msvc_string_sso: text too long ({} bytes), max 15", text.size());
        return false;
    }
    // Overwrite SSO buffer
    memcpy(base, text.c_str(), text.size());
    memset(base + text.size(), 0, 16 - text.size());
    // Set size and capacity
    *reinterpret_cast<uint64_t*>(base + 0x10) = text.size();
    *reinterpret_cast<uint64_t*>(base + 0x18) = 15;  // SSO capacity
    return true;
}

/// Write to a MSVC std::string — SSO for <=15 bytes, heap alloc for longer.
/// Returns heap pointer that caller must free with HeapFree, or nullptr if SSO.
static char* write_msvc_string_heap(uint8_t* base, const std::string& text) {
    if (text.size() <= 15) {
        // SSO path
        memcpy(base, text.c_str(), text.size());
        memset(base + text.size(), 0, 16 - text.size());
        *reinterpret_cast<uint64_t*>(base + 0x10) = text.size();
        *reinterpret_cast<uint64_t*>(base + 0x18) = 15;
        return nullptr;
    }
    // Heap path — use process heap (same as MSVC operator new)
    size_t capacity = text.size() + 1;
    if (capacity < 32) capacity = 32;
    char* buf = static_cast<char*>(
        HeapAlloc(GetProcessHeap(), 0, capacity));
    if (!buf) return nullptr;
    memcpy(buf, text.c_str(), text.size());
    buf[text.size()] = 0;
    // MSVC layout: +0x00 = ptr, +0x10 = size, +0x18 = capacity (excl null)
    *reinterpret_cast<char**>(base) = buf;
    memset(base + sizeof(char*), 0, 16 - sizeof(char*));
    *reinterpret_cast<uint64_t*>(base + 0x10) = text.size();
    *reinterpret_cast<uint64_t*>(base + 0x18) = capacity - 1;
    return buf;
}

// =====================================================================
// 函数指针 + Hook 状态
// =====================================================================

// 函数原型 — 基于动态验证 + 结构体解析:
//   cgi_A_caller_2: rcx = SnsCommentRequestData*, 返回指针
typedef void* (__fastcall *fn_SnsCommentSubmit)(
    void* request,    // SnsCommentRequestData* (用 void* 避免 CRT 问题)
    void* arg1,       // 观测值: 栈上地址 (上下文对象)
    int64_t arg2,     // 观测值: 1
    void* arg3        // 观测值: Weixin.dll 内地址 (回调函数?)
);

// Internal TLS accessor around RVA 0x00b91e90 (returns context pointer).
typedef void* (__fastcall *fn_TlsAccessor)(int slot);
typedef void* (__fastcall *fn_Arg1CtxHelper)(void* arg1, void* a2, void* a3, void* a4);

// 原始函数地址 (通过 SigScanner 找到)
static uintptr_t g_target_fn_addr = 0;
static uintptr_t g_top_fn_addr = 0;  // cgi_A_caller_3_TOP
static uintptr_t g_tls_accessor_addr = 0;
static uintptr_t g_arg1_ctx_helper_addr = 0;

// MinHook trampoline: 调用原始函数
static fn_SnsCommentSubmit g_original_fn = nullptr;
static fn_SnsCommentSubmit g_original_top_fn = nullptr;
static fn_TlsAccessor g_original_tls_accessor = nullptr;
static fn_Arg1CtxHelper g_original_arg1_ctx_helper = nullptr;

// =====================================================================
// 运行时状态捕获 (首次合法调用时自动捕获)
// =====================================================================

static std::mutex g_capture_mutex;
static bool g_state_captured = false;
static void** g_captured_vtable = nullptr;
static void* g_captured_arg1 = nullptr;
static int64_t g_captured_arg2 = 0;
static void* g_captured_arg3 = nullptr;
static void* g_captured_author_info = nullptr;
static void* g_captured_author_info2 = nullptr;
static uint64_t g_capture_tick_ms = 0;
static DWORD g_capture_thread_id = 0;
static bool g_request_template_ready = false;
static std::array<uint8_t, REQUEST_CALL_BUFFER_SIZE> g_request_template{};
static bool g_arg1_template_ready = false;
static std::array<uint8_t, ARG1_TEMPLATE_SIZE> g_arg1_template{};

// =====================================================================
// VEH crash diagnostics
// =====================================================================

static struct CrashDiag {
    uintptr_t rip = 0;           // 崩溃指令地址
    uintptr_t fault_addr = 0;    // 被访问的内存地址
    uint64_t  fault_type = 0;    // 0=read, 1=write, 8=DEP
    uintptr_t rcx = 0, rdx = 0, r8 = 0, r9 = 0;
    uintptr_t rsp = 0, rbp = 0;
} g_crash_diag;
static volatile bool g_veh_armed = false;

static LONG CALLBACK diag_veh(PEXCEPTION_POINTERS info) {
    if (g_veh_armed && info->ExceptionRecord->ExceptionCode == 0xC0000005) {
        g_crash_diag.rip = info->ContextRecord->Rip;
        g_crash_diag.fault_addr = info->ExceptionRecord->ExceptionInformation[1];
        g_crash_diag.fault_type = info->ExceptionRecord->ExceptionInformation[0];
        g_crash_diag.rcx = info->ContextRecord->Rcx;
        g_crash_diag.rdx = info->ContextRecord->Rdx;
        g_crash_diag.r8  = info->ContextRecord->R8;
        g_crash_diag.r9  = info->ContextRecord->R9;
        g_crash_diag.rsp = info->ContextRecord->Rsp;
        g_crash_diag.rbp = info->ContextRecord->Rbp;
        g_veh_armed = false;
        spdlog::error("VEH captured: rip={:#x} fault_addr={:#x} type={} rcx={:#x} rdx={:#x}",
                      g_crash_diag.rip, g_crash_diag.fault_addr, g_crash_diag.fault_type,
                      g_crash_diag.rcx, g_crash_diag.rdx);
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

// =====================================================================
// Capture-thread TLS snapshot (collected during hook callback)
// =====================================================================

static constexpr int TLS_SLOT_COUNT = 64;
static uint64_t g_capture_tls_slots[TLS_SLOT_COUNT] = {};
static int g_capture_tls_nonzero = 0;
static bool g_capture_is_gui_thread = false;

// =====================================================================
// 待发评论队列 (hook+inject 模式)
// =====================================================================

struct PendingComment {
    std::string sns_id;
    std::string content;
    std::string reply_to;
};

static std::mutex g_queue_mutex;
static std::queue<PendingComment> g_pending_queue;

// =====================================================================
// Piggyback parallel queue — drained inside hook callback while arg1 valid
// =====================================================================

struct PiggybackBatch {
    std::vector<std::string> comments;
    std::string sns_id;
    std::string reply_to;
    int max_concurrency = 10;
    // Results written by hook callback
    std::vector<CommentResult> results;
    bool done = false;
    int64_t total_latency_ms = 0;
    std::mutex mutex;
    std::condition_variable cv;
};

static std::mutex g_piggyback_mutex;
static std::shared_ptr<PiggybackBatch> g_piggyback_batch;

// =====================================================================
// Capture-thread direct-call queue
// =====================================================================

struct CaptureThreadDirectJob {
    std::mutex mutex;
    std::condition_variable cv;
    bool done = false;
    bool cancelled = false;
    std::string sns_id;
    std::string content;
    std::string reply_to;
    bool prefer_arg1_template = true;
    CommentResult result;
};

static std::mutex g_capture_thread_jobs_mutex;
static std::deque<std::shared_ptr<CaptureThreadDirectJob>> g_capture_thread_jobs;

static std::shared_ptr<CaptureThreadDirectJob> pop_next_capture_thread_job() {
    std::lock_guard<std::mutex> lock(g_capture_thread_jobs_mutex);
    if (g_capture_thread_jobs.empty()) {
        return nullptr;
    }
    auto job = g_capture_thread_jobs.front();
    g_capture_thread_jobs.pop_front();
    return job;
}

// Capture-thread message hook: allows actively waking capture thread
// to process queued direct-call jobs without waiting for next comment callback.
static std::mutex g_capture_msg_hook_mutex;
static HHOOK g_capture_msg_hook = nullptr;
static DWORD g_capture_msg_hook_tid = 0;
static constexpr UINT WM_PYWECHAT_CAPTURE_TICK = WM_APP + 0x337;

// =====================================================================
// Hook 安装状态
// =====================================================================

static bool g_hook_installed = false;
static bool g_hook_top_installed = false;
static bool g_tls_accessor_hook_installed = false;
static bool g_arg1_ctx_helper_hook_installed = false;
static volatile int g_hook_hit_count = 0;       // total hook callbacks
static volatile int g_hook_top_hit_count = 0;    // total TOP hook callbacks

// Captured TLS accessor return from capture thread.
static void* g_capture_tls_accessor_value = nullptr;
static bool g_capture_tls_accessor_ready = false;
static std::atomic<int> g_tls_accessor_capture_hits{0};
std::atomic<int> g_tls_accessor_override_hits{0};  // Exposed to pipe_server for status
std::atomic<int> g_tls_accessor_worker_miss{0};    // Exposed to pipe_server for status
static std::atomic<int> g_arg1_ctx_patch_hits{0};
// Kill switch for TLS override (can be disabled via pipe config).
// NOTE: TLS override is disabled by default because cgi_A_caller_2 is not thread-safe.
// Concurrent execution (concurrency >= 2) causes crashes regardless of TLS override setting.
// Use concurrency=1 (serial mode) for stable operation.
bool g_tls_override_enabled = false;
// Capture-thread implicit TLS block +0x358 fallback context (for parallel workers).
static uint64_t g_capture_tls_slot_0x358_raw = 0;
static uintptr_t g_capture_tls_slot_0x358_ptr = 0;
static bool g_capture_tls_slot_0x358_ready = false;

// Worker-scope switch: only override TLS accessor on piggyback parallel workers.
static thread_local bool t_piggyback_parallel_worker = false;

// =====================================================================
// Cached request->+0x368 value (set by g_original_fn on capture thread)
// This is the thread-local context pointer that causes crashes on
// non-capture threads. We cache it after the first successful call
// and pre-fill it in parallel piggyback request buffers.
// =====================================================================
static void* g_cached_req_0x368 = nullptr;
bool g_cached_req_0x368_valid = false;

static uint64_t monotonic_ms() {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
}

static bool safe_copy_bytes(void* dst, const void* src, size_t n) {
    __try {
        memcpy(dst, src, n);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

static bool looks_like_user_pointer(void* ptr) {
    const uintptr_t v = reinterpret_cast<uintptr_t>(ptr);
    if (v < 0x10000 || v > 0x00007FFFFFFFFFFFULL) {
        return false;
    }
    uint8_t probe[8] = {};
    return safe_copy_bytes(probe, ptr, sizeof(probe));
}

// Decode possible tagged pointers (raw / clear low 1/2/4 bits).
// Weixin frequently stores pointer-like values with low-bit flags.
static bool decode_tagged_pointer(uint64_t raw, uintptr_t* out_ptr, int* out_tag_bits) {
    static constexpr uint64_t kMasks[] = {
        0xFFFFFFFFFFFFFFFFULL,
        ~0x1ULL,
        ~0x3ULL,
        ~0xFULL
    };
    static constexpr int kTagBits[] = {0, 1, 2, 4};

    for (size_t i = 0; i < (sizeof(kMasks) / sizeof(kMasks[0])); ++i) {
        uintptr_t candidate = static_cast<uintptr_t>(raw & kMasks[i]);
        if (!candidate) {
            continue;
        }
        if (looks_like_user_pointer(reinterpret_cast<void*>(candidate))) {
            if (out_ptr) {
                *out_ptr = candidate;
            }
            if (out_tag_bits) {
                *out_tag_bits = kTagBits[i];
            }
            return true;
        }
    }
    return false;
}

static bool is_in_weixin_module(uintptr_t ptr) {
    HMODULE hmod = GetModuleHandleA("Weixin.dll");
    if (!hmod) {
        hmod = GetModuleHandleA("WeChatWin.dll");
    }
    if (!hmod) {
        return false;
    }
    auto base = reinterpret_cast<uintptr_t>(hmod);
    auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(hmod);
    auto nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
    auto end = base + nt->OptionalHeader.SizeOfImage;
    return ptr >= base && ptr < end;
}

static bool is_executable_address(uintptr_t ptr) {
    MEMORY_BASIC_INFORMATION mbi = {};
    if (VirtualQuery(reinterpret_cast<LPCVOID>(ptr), &mbi, sizeof(mbi)) == 0) {
        return false;
    }
    const DWORD prot = (mbi.Protect & 0xFF);
    switch (prot) {
    case PAGE_EXECUTE:
    case PAGE_EXECUTE_READ:
    case PAGE_EXECUTE_READWRITE:
    case PAGE_EXECUTE_WRITECOPY:
        return true;
    default:
        return false;
    }
}

static std::atomic<int> g_ctx_container_probe_hits{0};
static std::atomic<int> g_ctx_object_fingerprint_hits{0};

static void log_ctx_object_fingerprint(void* obj_ptr, const char* tag) {
    if (!obj_ptr) {
        return;
    }
    int hit = ++g_ctx_object_fingerprint_hits;
    if (hit > 24) {
        return;
    }
    uintptr_t obj = reinterpret_cast<uintptr_t>(obj_ptr);
    uintptr_t vtbl = 0;
    uintptr_t fn0 = 0, fn1 = 0, fn2 = 0, fn3 = 0;
    safe_copy_bytes(&vtbl, reinterpret_cast<void*>(obj), sizeof(vtbl));
    if (vtbl) {
        safe_copy_bytes(&fn0, reinterpret_cast<void*>(vtbl + 0x00), sizeof(fn0));
        safe_copy_bytes(&fn1, reinterpret_cast<void*>(vtbl + 0x08), sizeof(fn1));
        safe_copy_bytes(&fn2, reinterpret_cast<void*>(vtbl + 0x10), sizeof(fn2));
        safe_copy_bytes(&fn3, reinterpret_cast<void*>(vtbl + 0x18), sizeof(fn3));
    }
    spdlog::info(
        "ctx fp#{} ({}) obj={:#x} vtbl={:#x} fns=[{:#x},{:#x},{:#x},{:#x}]",
        hit,
        tag ? tag : "unknown",
        obj,
        vtbl,
        fn0,
        fn1,
        fn2,
        fn3);
}

static bool looks_like_vtable_object(void* obj_ptr) {
    if (!obj_ptr || !looks_like_user_pointer(obj_ptr)) {
        return false;
    }
    uintptr_t vtbl = 0;
    if (!safe_copy_bytes(&vtbl, obj_ptr, sizeof(vtbl))) {
        return false;
    }
    if (!looks_like_user_pointer(reinterpret_cast<void*>(vtbl)) ||
        !is_in_weixin_module(vtbl)) {
        return false;
    }
    int exec_hits = 0;
    for (size_t i = 0; i < 4; ++i) {
        uintptr_t fn = 0;
        if (!safe_copy_bytes(&fn, reinterpret_cast<void*>(vtbl + i * sizeof(uintptr_t)), sizeof(fn))) {
            continue;
        }
        if (looks_like_user_pointer(reinterpret_cast<void*>(fn)) &&
            is_in_weixin_module(fn) &&
            is_executable_address(fn)) {
            exec_hits++;
        }
    }
    return exec_hits >= 2;
}

static void log_ctx_container_probe(uintptr_t container_ptr, const char* source) {
    int hit = ++g_ctx_container_probe_hits;
    if (hit > 8) {
        return;
    }
    spdlog::info("ctx probe #{} ({}) container={:#x}",
                 hit, source ? source : "unknown", container_ptr);
    for (size_t off = 0; off <= 0x80; off += 8) {
        uint64_t raw = 0;
        if (!safe_copy_bytes(&raw, reinterpret_cast<void*>(container_ptr + off), sizeof(raw))) {
            continue;
        }
        uintptr_t ptr = 0;
        int tag_bits = 0;
        bool decoded = decode_tagged_pointer(raw, &ptr, &tag_bits);
        bool in_weixin = decoded && is_in_weixin_module(ptr);
        bool vtbl_obj = decoded && looks_like_vtable_object(reinterpret_cast<void*>(ptr));
        if (!decoded && raw == 0) {
            continue;
        }
        spdlog::info("  +{:#x}: raw={:#x} decoded={} ptr={:#x} tag_bits={} in_weixin={} vtbl_obj={}",
                     off, raw, decoded, ptr, tag_bits, in_weixin, vtbl_obj);

        if (decoded && looks_like_user_pointer(reinterpret_cast<void*>(ptr)) && off <= 0x80) {
            for (size_t off2 = 0; off2 <= 0x28; off2 += 8) {
                uint64_t raw2 = 0;
                if (!safe_copy_bytes(&raw2, reinterpret_cast<void*>(ptr + off2), sizeof(raw2))) {
                    continue;
                }
                uintptr_t ptr2 = 0;
                int tag_bits2 = 0;
                bool decoded2 = decode_tagged_pointer(raw2, &ptr2, &tag_bits2);
                bool vtbl2 = decoded2 && looks_like_vtable_object(reinterpret_cast<void*>(ptr2));
                if (!decoded2 && raw2 == 0) {
                    continue;
                }
                spdlog::info("    -> +{:#x}: raw={:#x} decoded={} ptr={:#x} tag_bits={} vtbl_obj={}",
                             off2, raw2, decoded2, ptr2, tag_bits2, vtbl2);
            }
        }
    }
}

static bool read_pointer_like_value(uintptr_t addr, uintptr_t* out_ptr, int* out_tag_bits) {
    uint64_t raw = 0;
    if (!safe_copy_bytes(&raw, reinterpret_cast<void*>(addr), sizeof(raw))) {
        return false;
    }
    uintptr_t ptr = 0;
    int tag_bits = 0;
    if (!decode_tagged_pointer(raw, &ptr, &tag_bits)) {
        return false;
    }
    if (out_ptr) {
        *out_ptr = ptr;
    }
    if (out_tag_bits) {
        *out_tag_bits = tag_bits;
    }
    return true;
}

// Extract vtable-like object pointer from a context container.
// Many Weixin internals return a container whose fields hold real object ptrs.
static void* extract_ctx_object_from_container(uintptr_t container_ptr,
                                               const char* source,
                                               uintptr_t* out_field_addr = nullptr,
                                               int* out_tag_bits = nullptr) {
    if (!container_ptr || !looks_like_user_pointer(reinterpret_cast<void*>(container_ptr))) {
        return nullptr;
    }

    if (looks_like_vtable_object(reinterpret_cast<void*>(container_ptr))) {
        if (out_field_addr) {
            *out_field_addr = container_ptr;
        }
        if (out_tag_bits) {
            *out_tag_bits = 0;
        }
        return reinterpret_cast<void*>(container_ptr);
    }

    for (size_t off = 0; off <= 0x120; off += 8) {
        uintptr_t candidate = 0;
        int tag_bits = 0;
        if (!read_pointer_like_value(container_ptr + off, &candidate, &tag_bits)) {
            continue;
        }
        if (looks_like_vtable_object(reinterpret_cast<void*>(candidate))) {
            if (out_field_addr) {
                *out_field_addr = container_ptr + off;
            }
            if (out_tag_bits) {
                *out_tag_bits = tag_bits;
            }
            spdlog::info(
                "ctx extract ({}) container={:#x} field=+{:#x} raw_ptr={:#x} tag_bits={}",
                source ? source : "unknown",
                container_ptr,
                off,
                candidate,
                tag_bits);
            log_ctx_object_fingerprint(reinterpret_cast<void*>(candidate), "extract-direct");
            return reinterpret_cast<void*>(candidate);
        }

        // One-level indirection: field may point to a helper struct that
        // contains the real vtable object pointer.
        for (size_t off2 = 0; off2 <= 0x80; off2 += 8) {
            uintptr_t nested = 0;
            int nested_tag_bits = 0;
            if (!read_pointer_like_value(candidate + off2, &nested, &nested_tag_bits)) {
                continue;
            }
            if (!looks_like_vtable_object(reinterpret_cast<void*>(nested))) {
                continue;
            }
            if (out_field_addr) {
                *out_field_addr = candidate + off2;
            }
            if (out_tag_bits) {
                *out_tag_bits = nested_tag_bits;
            }
            spdlog::info(
                "ctx extract ({}) container={:#x} field=+{:#x} -> nested=+{:#x} obj={:#x} tag_bits={}",
                source ? source : "unknown",
                container_ptr,
                off,
                off2,
                nested,
                nested_tag_bits);
            log_ctx_object_fingerprint(reinterpret_cast<void*>(nested), "extract-nested");
            return reinterpret_cast<void*>(nested);
        }

    }
    return nullptr;
}

static void* normalize_ctx_object_ptr(void* raw_ptr, const char* source) {
    if (!raw_ptr || !looks_like_user_pointer(raw_ptr)) {
        return nullptr;
    }
    auto container = reinterpret_cast<uintptr_t>(raw_ptr);

    uintptr_t field_addr = 0;
    int tag_bits = 0;
    if (void* obj = extract_ctx_object_from_container(
            container,
            source,
            &field_addr,
            &tag_bits)) {
        return obj;
    }
    for (size_t off = 8; off <= 0x80; off += 8) {
        uintptr_t shifted = container + off;
        if (void* obj = extract_ctx_object_from_container(
                shifted,
                source,
                &field_addr,
                &tag_bits)) {
            spdlog::info(
                "normalize ctx object ({}): shifted container raw={:#x} -> +{:#x} field={:#x} tag_bits={}",
                source ? source : "unknown",
                container,
                off,
                field_addr,
                tag_bits);
            return obj;
        }
    }
    spdlog::warn("normalize ctx object ({}): no vtable-like object near {:#x}",
                 source ? source : "unknown", container);
    log_ctx_container_probe(container, source);
    return nullptr;
}

static bool read_tagged_context_ptr(const uint8_t* base,
                                    size_t offset,
                                    void** out_ctx,
                                    uint64_t* out_raw,
                                    int* out_tag_bits) {
    if (!base) {
        return false;
    }
    uint64_t raw = 0;
    if (!safe_copy_bytes(&raw, base + offset, sizeof(raw))) {
        return false;
    }
    if (out_raw) {
        *out_raw = raw;
    }
    uintptr_t ptr = 0;
    int tag_bits = 0;
    if (!decode_tagged_pointer(raw, &ptr, &tag_bits)) {
        return false;
    }
    void* normalized = normalize_ctx_object_ptr(reinterpret_cast<void*>(ptr), "tagged_context");
    if (!normalized) {
        return false;
    }
    if (out_ctx) {
        *out_ctx = normalized;
    }
    if (out_tag_bits) {
        *out_tag_bits = tag_bits;
    }
    return true;
}

// Forward declarations (defined later, called from hook callbacks)
static void collect_capture_fls();
static void collect_capture_implicit_tls();
static bool copy_implicit_tls_to_current(uint32_t tls_index, size_t tls_data_size,
                                         uintptr_t src_block);
static int copy_tls_slots_to_current();
static int copy_fls_to_current();
static int process_capture_thread_jobs(const char* source_tag);
static bool ensure_capture_thread_msg_hook();
static void remove_capture_thread_msg_hook();

static std::string make_short_comment_key() {
    // Keep comment_key in SSO to avoid external heap/CRT coupling.
    // Example: hk02af1c9d50 (12 chars)
    char key[16] = {0};
    auto now_ms = static_cast<unsigned long long>(monotonic_ms() & 0xFFFFFFFFFFULL);
    sprintf_s(key, sizeof(key), "hk%010llx", now_ms);
    return std::string(key);
}

// =====================================================================
// SEH-safe wrapper for calling g_original_fn (no C++ objects allowed)
// Returns 0 on success, non-zero on SEH exception
// =====================================================================

static DWORD g_last_seh_code = 0;
static uintptr_t g_last_seh_address = 0;

static int seh_filter(EXCEPTION_POINTERS* ep) {
    if (ep && ep->ExceptionRecord) {
        g_last_seh_code = ep->ExceptionRecord->ExceptionCode;
        g_last_seh_address = (uintptr_t)ep->ExceptionRecord->ExceptionAddress;
        HMODULE hmod = GetModuleHandleA("Weixin.dll");
        uintptr_t base = hmod ? (uintptr_t)hmod : 0;
        uintptr_t rva = g_last_seh_address - base;

        spdlog::error("SEH exception: code={:#x} addr={:#x} rva={:#x}",
                      g_last_seh_code, g_last_seh_address, rva);
        if (ep->ContextRecord) {
            auto ctx = ep->ContextRecord;
            spdlog::error("  rax={:#x} rcx={:#x} rdx={:#x} rdi={:#x} rsi={:#x}",
                          ctx->Rax, ctx->Rcx, ctx->Rdx, ctx->Rdi, ctx->Rsi);
        }
    }
    return EXCEPTION_EXECUTE_HANDLER;
}

static int safe_call_original(void* request, void* arg1,
                              int64_t arg2, void* arg3) {
    __try {
        g_original_fn(request, arg1, arg2, arg3);
        return 0;
    } __except (seh_filter(GetExceptionInformation())) {
        return GetExceptionCode();
    }
}

static void* safe_call_tls_accessor(int slot = 5) {
    if (!g_original_tls_accessor) {
        return nullptr;
    }
    __try {
        return g_original_tls_accessor(slot);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return nullptr;
    }
}

static int process_capture_thread_jobs(const char* source_tag) {
    int processed = 0;
    while (true) {
        auto job = pop_next_capture_thread_job();
        if (!job) {
            break;
        }

        bool cancelled = false;
        {
            std::lock_guard<std::mutex> job_lock(job->mutex);
            cancelled = job->cancelled;
        }

        if (cancelled) {
            std::lock_guard<std::mutex> job_lock(job->mutex);
            if (!job->done) {
                job->done = true;
                job->result.error_code = 30;
                job->result.error_message = "capture-thread job cancelled";
                job->result.call_method = "capture_thread";
            }
            job->cv.notify_all();
            processed++;
            continue;
        }

        spdlog::info("{}: executing capture-thread direct job, content_len={}",
                     source_tag ? source_tag : "capture_thread",
                     job->content.size());

        auto job_result = sns_do_comment(
            job->sns_id,
            job->content,
            job->reply_to,
            job->prefer_arg1_template);
        job_result.call_method = "capture_thread";

        {
            std::lock_guard<std::mutex> job_lock(job->mutex);
            job->result = std::move(job_result);
            job->done = true;
        }
        job->cv.notify_all();
        processed++;
    }
    return processed;
}

static LRESULT CALLBACK capture_thread_getmsg_hook(int code, WPARAM wParam, LPARAM lParam) {
    if (code >= 0) {
        MSG* msg = reinterpret_cast<MSG*>(lParam);
        if (msg && (msg->message == WM_NULL || msg->message == WM_PYWECHAT_CAPTURE_TICK)) {
            int n = process_capture_thread_jobs("capture_msg_hook");
            if (n > 0) {
                spdlog::info("capture_msg_hook: processed {} queued jobs", n);
            }
        }
    }
    return CallNextHookEx(g_capture_msg_hook, code, wParam, lParam);
}

static bool ensure_capture_thread_msg_hook() {
    DWORD tid = 0;
    {
        std::lock_guard<std::mutex> lock(g_capture_mutex);
        tid = g_capture_thread_id;
    }
    if (tid == 0) {
        return false;
    }

    std::lock_guard<std::mutex> lock(g_capture_msg_hook_mutex);
    if (g_capture_msg_hook && g_capture_msg_hook_tid == tid) {
        return true;
    }

    if (g_capture_msg_hook) {
        UnhookWindowsHookEx(g_capture_msg_hook);
        g_capture_msg_hook = nullptr;
        g_capture_msg_hook_tid = 0;
    }

    g_capture_msg_hook = SetWindowsHookExA(
        WH_GETMESSAGE,
        capture_thread_getmsg_hook,
        nullptr,
        tid);
    if (!g_capture_msg_hook) {
        spdlog::warn("ensure_capture_thread_msg_hook: SetWindowsHookEx failed, err={}",
                     GetLastError());
        return false;
    }
    g_capture_msg_hook_tid = tid;
    spdlog::info("capture message hook installed on tid={}", tid);
    return true;
}

static void remove_capture_thread_msg_hook() {
    std::lock_guard<std::mutex> lock(g_capture_msg_hook_mutex);
    if (g_capture_msg_hook) {
        UnhookWindowsHookEx(g_capture_msg_hook);
        g_capture_msg_hook = nullptr;
        g_capture_msg_hook_tid = 0;
        spdlog::info("capture message hook removed");
    }
}

static void* __fastcall hooked_tls_accessor(int slot) {
    if (!g_original_tls_accessor) {
        return nullptr;
    }
    void* value = g_original_tls_accessor(slot);
    DWORD tid = GetCurrentThreadId();

    // Capture thread: cache TLS value for arg1_ctx_helper to use
    if (tid == g_capture_thread_id) {
        if (value && looks_like_user_pointer(value)) {
            g_capture_tls_accessor_value = value;
            g_capture_tls_accessor_ready = true;
            int cap = ++g_tls_accessor_capture_hits;
            if (cap <= 8) {
                spdlog::info("tls_accessor capture hit#{} -> {:#x}",
                             cap, (uintptr_t)value);
            }
        }
        return value;
    }

    // Worker thread: DO NOT override TLS accessor
    // Let it return NULL - arg1_ctx_helper will patch arg1->+0x368 instead
    // Overriding causes crashes because TLS container is not thread-safe
    if (t_piggyback_parallel_worker && (!value || !looks_like_user_pointer(value))) {
        ++g_tls_accessor_worker_miss;
    }

    return value;  // Return original value (likely NULL for worker threads)
}

static void* __fastcall hooked_arg1_ctx_helper(void* arg1, void* a2, void* a3, void* a4) {
    if (t_piggyback_parallel_worker && arg1) {
        void* ctx = nullptr;
        if (g_cached_req_0x368_valid) {
            ctx = g_cached_req_0x368;
        } else if (g_capture_tls_accessor_ready &&
                   looks_like_user_pointer(g_capture_tls_accessor_value)) {
            ctx = g_capture_tls_accessor_value;
        } else if (g_capture_tls_slot_0x358_ready) {
            ctx = reinterpret_cast<void*>(g_capture_tls_slot_0x358_ptr);
        }
        if (ctx && looks_like_user_pointer(ctx)) {
            bool patched = safe_copy_bytes(
                reinterpret_cast<uint8_t*>(arg1) + 0x368, &ctx, sizeof(ctx));
            if (patched) {
                int hit = ++g_arg1_ctx_patch_hits;
                if (hit <= 12) {
                    spdlog::info("arg1_ctx_helper patch hit#{} arg1={:#x} ctx={:#x}",
                                 hit, (uintptr_t)arg1, (uintptr_t)ctx);
                }
            }
        }
    }
    if (!g_original_arg1_ctx_helper) {
        return nullptr;
    }
    return g_original_arg1_ctx_helper(arg1, a2, a3, a4);
}

// =====================================================================
// Hooked 函数 — MinHook trampoline
// =====================================================================

static void* __fastcall hooked_cgi_A_caller_2(
    void* request,
    void* arg1,
    int64_t arg2,
    void* arg3)
{
    auto req_bytes = reinterpret_cast<uint8_t*>(request);

    // --- 1. 捕获运行时状态 ---
    {
        std::lock_guard<std::mutex> lock(g_capture_mutex);
        g_captured_vtable = *reinterpret_cast<void***>(req_bytes + OFF_VTABLE);
        g_captured_arg1 = arg1;
        g_captured_arg2 = arg2;
        g_captured_arg3 = arg3;
        g_captured_author_info = *reinterpret_cast<void**>(req_bytes + OFF_AUTHOR_INFO);
        g_captured_author_info2 = *reinterpret_cast<void**>(req_bytes + OFF_AUTHOR_INFO + 8);
        g_capture_tick_ms = monotonic_ms();
        g_capture_thread_id = GetCurrentThreadId();
        g_request_template_ready = safe_copy_bytes(
            g_request_template.data(), req_bytes, REQUEST_CALL_BUFFER_SIZE);
        g_arg1_template_ready = false;
        if (arg1) {
            g_arg1_template_ready = safe_copy_bytes(
                g_arg1_template.data(), arg1, ARG1_TEMPLATE_SIZE);
        }
        if (!g_state_captured) {
            g_state_captured = true;
            spdlog::info("captured runtime state: vtable={:#x}, arg1={:#x}, arg2={}, arg3={:#x}",
                         (uintptr_t)g_captured_vtable, (uintptr_t)arg1,
                         arg2, (uintptr_t)arg3);
        }

        // Collect TLS slots from capture thread for diagnostics
        g_capture_tls_nonzero = 0;
        for (int i = 0; i < TLS_SLOT_COUNT; i++) {
            void* val = TlsGetValue(i);
            g_capture_tls_slots[i] = (uint64_t)(uintptr_t)val;
            if (val) g_capture_tls_nonzero++;
        }
        g_capture_is_gui_thread = (IsGUIThread(FALSE) != FALSE);
    }

    // --- 1b. Collect FLS + implicit TLS for parallel comment support ---
    collect_capture_fls();
    collect_capture_implicit_tls();
    ensure_capture_thread_msg_hook();

    // --- 2. 缓存 SNS ID ---
    auto sns_id = read_msvc_string(req_bytes + OFF_SNS_ID);
    auto content = read_msvc_string(req_bytes + OFF_CONTENT);
    if (!sns_id.empty()) {
        auto& mgr = HookManager::instance();
        // 缓存 content → sns_id 映射
        mgr.cache_sns_id("", content, sns_id);
        // 缓存最新 SNS ID (供 get_latest_sns_id 使用)
        mgr.cache_latest_sns_id(sns_id);
        spdlog::debug("hook: sns_id={}, content={}", sns_id, content);
    }

    // --- 3. 执行 capture-thread direct-call 任务 ---
    process_capture_thread_jobs("hook_callback");

    // --- 4. 检查待发评论队列, 注入 ---
    {
        std::lock_guard<std::mutex> lock(g_queue_mutex);
        if (!g_pending_queue.empty()) {
            auto pending = g_pending_queue.front();
            g_pending_queue.pop();

            spdlog::info("hook: injecting queued comment: content={}", pending.content);

            // 修改 content 字段 (SSO 模式, max 15 bytes)
            if (!pending.content.empty()) {
                if (!write_msvc_string_sso(req_bytes + OFF_CONTENT, pending.content)) {
                    spdlog::warn("hook: content too long for SSO ({}), passing through",
                                 pending.content.size());
                }
            }

            // 修改 sns_id (如果指定了不同的 SNS ID)
            if (!pending.sns_id.empty()) {
                if (!write_msvc_string_sso(req_bytes + OFF_SNS_ID, pending.sns_id)) {
                    spdlog::warn("hook: sns_id too long for SSO ({})", pending.sns_id.size());
                }
            }

            // 修改 reply_to (如果需要回复某人)
            if (!pending.reply_to.empty()) {
                if (!write_msvc_string_sso(req_bytes + OFF_REPLY_TO, pending.reply_to)) {
                    spdlog::warn("hook: reply_to too long for SSO ({})", pending.reply_to.size());
                }
            }
        }
    }

    // --- 5. 调用原始函数 ---
    // Pre-call sampling: some builds clear/mutate +0x368 after return.
    void* pre_arg1_ctx = nullptr;
    bool pre_arg1_ctx_valid = false;
    uint64_t pre_arg1_raw = 0;
    int pre_arg1_tag_bits = 0;
    if (arg1) {
        pre_arg1_ctx_valid = read_tagged_context_ptr(
            reinterpret_cast<const uint8_t*>(arg1),
            0x368,
            &pre_arg1_ctx,
            &pre_arg1_raw,
            &pre_arg1_tag_bits);
    }
    void* pre_req_ctx = nullptr;
    bool pre_req_ctx_valid = false;
    uint64_t pre_req_raw = 0;
    int pre_req_tag_bits = 0;
    if (REQUEST_CALL_BUFFER_SIZE > 0x370) {
        pre_req_ctx_valid = read_tagged_context_ptr(
            req_bytes,
            0x368,
            &pre_req_ctx,
            &pre_req_raw,
            &pre_req_tag_bits);
    }

    auto* original_result = g_original_fn(request, arg1, arg2, arg3);

    // Capture TLS accessor return on capture thread as a fallback source for
    // parallel worker override.
    if (g_original_tls_accessor) {
        void* accessor_val = safe_call_tls_accessor();
        if (accessor_val && looks_like_user_pointer(accessor_val)) {
            g_capture_tls_accessor_value = accessor_val;
            g_capture_tls_accessor_ready = true;
            int cap = ++g_tls_accessor_capture_hits;
            if (cap <= 8) {
                spdlog::info("tls_accessor explicit capture hit#{} -> {:#x}",
                             cap, (uintptr_t)accessor_val);
            }
        }
    }

    // --- 5b. Cache a sane +0x368 context pointer for parallel piggyback ---
    // Prefer arg1->+0x368 (closer to internal check chain), fallback to request->+0x368.
    void* ctx_0x368 = nullptr;
    bool ctx_0x368_valid = false;
    if (arg1) {
        void* arg1_ctx = nullptr;
        uint64_t arg1_raw = 0;
        int arg1_tag_bits = 0;
        if (read_tagged_context_ptr(reinterpret_cast<const uint8_t*>(arg1),
                                    0x368,
                                    &arg1_ctx,
                                    &arg1_raw,
                                    &arg1_tag_bits)) {
            ctx_0x368 = arg1_ctx;
            ctx_0x368_valid = true;
            spdlog::info("cached arg1->+0x368: raw={:#x} ptr={:#x} tag_bits={}",
                         arg1_raw, (uintptr_t)arg1_ctx, arg1_tag_bits);
        }
    }
    if (!ctx_0x368_valid && REQUEST_CALL_BUFFER_SIZE > 0x370) {
        void* req_ctx = nullptr;
        uint64_t req_raw = 0;
        int req_tag_bits = 0;
        if (read_tagged_context_ptr(req_bytes, 0x368, &req_ctx, &req_raw, &req_tag_bits)) {
            ctx_0x368 = req_ctx;
            ctx_0x368_valid = true;
            spdlog::info("cached request->+0x368: raw={:#x} ptr={:#x} tag_bits={}",
                         req_raw, (uintptr_t)req_ctx, req_tag_bits);
        }
    }
    if (!ctx_0x368_valid && pre_arg1_ctx_valid) {
        ctx_0x368 = pre_arg1_ctx;
        ctx_0x368_valid = true;
        spdlog::info("fallback context from pre-call arg1->+0x368: raw={:#x} ptr={:#x} tag_bits={}",
                     pre_arg1_raw, (uintptr_t)pre_arg1_ctx, pre_arg1_tag_bits);
    }
    if (!ctx_0x368_valid && pre_req_ctx_valid) {
        ctx_0x368 = pre_req_ctx;
        ctx_0x368_valid = true;
        spdlog::info("fallback context from pre-call request->+0x368: raw={:#x} ptr={:#x} tag_bits={}",
                     pre_req_raw, (uintptr_t)pre_req_ctx, pre_req_tag_bits);
    }
    if (!ctx_0x368_valid && !g_capture_tls_accessor_ready && g_original_tls_accessor) {
        void* pre_accessor = safe_call_tls_accessor();
        if (pre_accessor && looks_like_user_pointer(pre_accessor)) {
            g_capture_tls_accessor_value = pre_accessor;
            g_capture_tls_accessor_ready = true;
            int cap = ++g_tls_accessor_capture_hits;
            if (cap <= 8) {
                spdlog::info("tls_accessor fallback capture hit#{} -> {:#x}",
                             cap, (uintptr_t)pre_accessor);
            }
        }
    }
    if (!ctx_0x368_valid &&
        g_capture_tls_accessor_ready &&
        looks_like_user_pointer(g_capture_tls_accessor_value)) {
        void* normalized = normalize_ctx_object_ptr(
            g_capture_tls_accessor_value,
            "tls_accessor");
        if (normalized) {
            ctx_0x368 = normalized;
            ctx_0x368_valid = true;
            spdlog::info("fallback context from tls accessor: raw={:#x} normalized={:#x}",
                         (uintptr_t)g_capture_tls_accessor_value,
                         (uintptr_t)normalized);
        }
    }
    if (!ctx_0x368_valid && g_capture_tls_slot_0x358_ready) {
        void* normalized = normalize_ctx_object_ptr(
            reinterpret_cast<void*>(g_capture_tls_slot_0x358_ptr),
            "capture_tls_slot_0x358");
        if (normalized) {
            ctx_0x368 = normalized;
            ctx_0x368_valid = true;
            spdlog::info(
                "fallback context from capture_tls_block+0x358: raw={:#x} ptr={:#x} normalized={:#x}",
                g_capture_tls_slot_0x358_raw,
                g_capture_tls_slot_0x358_ptr,
                (uintptr_t)normalized);
        }
    }
    g_cached_req_0x368_valid = ctx_0x368_valid;
    if (ctx_0x368_valid) {
        g_cached_req_0x368 = ctx_0x368;
    } else {
        spdlog::warn(
            "parallel context not ready: arg1_raw={:#x} req_raw={:#x} tls_accessor_ready={} tls_358_ready={} tls_358_raw={:#x}",
            pre_arg1_raw,
            pre_req_raw,
            g_capture_tls_accessor_ready,
            g_capture_tls_slot_0x358_ready,
            g_capture_tls_slot_0x358_raw);
    }

    // --- 6. Piggyback: drain parallel queue while arg1 is still valid ---
    {
        std::shared_ptr<PiggybackBatch> batch;
        {
            std::lock_guard<std::mutex> lock(g_piggyback_mutex);
            batch = g_piggyback_batch;
            g_piggyback_batch.reset();
        }
        if (batch && !batch->comments.empty()) {
            bool use_parallel = (batch->max_concurrency > 1);

            spdlog::info("hook piggyback: firing {} comments {} (req_0x368={:#x})",
                         batch->comments.size(),
                         use_parallel ? "PARALLEL" : "SERIAL",
                         (uintptr_t)g_cached_req_0x368);
            auto pb_start = std::chrono::steady_clock::now();

            batch->results.resize(batch->comments.size());
            std::string pb_sns = batch->sns_id;
            if (pb_sns.empty()) {
                pb_sns = read_msvc_string(req_bytes + OFF_SNS_ID);
            }

            if (use_parallel) {
                // ===== PARALLEL MODE: spawn worker threads =====
                auto tls_diag = get_tls_diag_info();
                const bool implicit_tls_ready =
                    tls_diag.has_tls_directory &&
                    tls_diag.capture_implicit_tls_valid &&
                    tls_diag.tls_index_value != 0xFFFFFFFF &&
                    tls_diag.tls_data_size > 0 &&
                    tls_diag.capture_tls_block_addr != 0;
                const bool fls_ready = tls_diag.capture_fls_nonzero > 0;

                spdlog::info(
                    "piggyback_parallel context: implicit_ready={} (idx={}, size={}, block={:#x}) "
                    "fls_ready={} (capture_fls_nonzero={})",
                    implicit_tls_ready,
                    tls_diag.tls_index_value,
                    tls_diag.tls_data_size,
                    tls_diag.capture_tls_block_addr,
                    fls_ready,
                    tls_diag.capture_fls_nonzero);

                void* parallel_ctx = nullptr;
                if (g_cached_req_0x368_valid &&
                    looks_like_vtable_object(g_cached_req_0x368)) {
                    parallel_ctx = g_cached_req_0x368;
                } else if (g_capture_tls_accessor_ready &&
                           looks_like_user_pointer(g_capture_tls_accessor_value)) {
                    parallel_ctx = normalize_ctx_object_ptr(
                        g_capture_tls_accessor_value,
                        "parallel_gate_tls_accessor");
                } else if (g_capture_tls_slot_0x358_ready) {
                    parallel_ctx = normalize_ctx_object_ptr(
                        reinterpret_cast<void*>(g_capture_tls_slot_0x358_ptr),
                        "parallel_gate_tls_slot_0x358");
                }
                if (parallel_ctx) {
                    g_cached_req_0x368 = parallel_ctx;
                    g_cached_req_0x368_valid = true;
                }

                if (!parallel_ctx) {
                    spdlog::error(
                        "piggyback_parallel blocked: context object unavailable "
                        "(cached_valid={} tls_accessor_ready={} tls_358_ready={})",
                        g_cached_req_0x368_valid,
                        g_capture_tls_accessor_ready,
                        g_capture_tls_slot_0x358_ready);
                    for (size_t i = 0; i < batch->comments.size(); ++i) {
                        CommentResult cr;
                        cr.error_code = 31;
                        cr.error_message = "parallel context object unavailable";
                        cr.call_method = "piggyback_parallel";
                        batch->results[i] = std::move(cr);
                    }
                } else {
                    std::vector<std::thread> workers;
                    int conc = (std::min)((int)batch->comments.size(),
                                          batch->max_concurrency);
                    workers.reserve(conc);

                    for (size_t i = 0; i < batch->comments.size(); ++i) {
                        workers.emplace_back([&, i, pb_sns, arg1, arg2, arg3,
                                              implicit_tls_ready, fls_ready, parallel_ctx]() {
                            void* context_368 = nullptr;

                            bool implicit_copied = false;
                            int tls_slots_copied = 0;
                            int fls_copied = 0;
                            tls_slots_copied = copy_tls_slots_to_current();
                            if (implicit_tls_ready) {
                                implicit_copied = copy_implicit_tls_to_current(
                                    tls_diag.tls_index_value,
                                    tls_diag.tls_data_size,
                                    tls_diag.capture_tls_block_addr);
                            }
                            if (fls_ready) {
                                fls_copied = copy_fls_to_current();
                            }

                            // Prefer worker-local context extracted from the current
                            // thread's TLS accessor after TLS/FLS copy.
                            if (g_original_tls_accessor) {
                                void* worker_tls_raw = safe_call_tls_accessor();
                                if (worker_tls_raw && looks_like_user_pointer(worker_tls_raw)) {
                                    context_368 = normalize_ctx_object_ptr(
                                        worker_tls_raw,
                                        "worker_local_tls_accessor");
                                }
                            }
                            if (!context_368) {
                                // Keep a conservative fallback for diagnostics only.
                                context_368 = parallel_ctx;
                            }

                            alignas(16) uint8_t pb_req[REQUEST_CALL_BUFFER_SIZE];
                            memcpy(pb_req, g_request_template.data(),
                                   REQUEST_CALL_BUFFER_SIZE);

                        // Keep request->+0x368 exactly as captured template bytes.
                        // Forcing a synthetic pointer here can bypass internal
                        // fixup and crash at downstream virtual calls.

                        // Use per-worker arg1 template to avoid cross-thread races
                        // on shared arg1->+0x368 state.
                            alignas(16) uint8_t pb_arg1[ARG1_TEMPLATE_SIZE];
                            void* worker_arg1 = arg1;
                            bool arg1_copied = false;
                            if (g_arg1_template_ready) {
                                memcpy(pb_arg1, g_arg1_template.data(), ARG1_TEMPLATE_SIZE);
                                worker_arg1 = pb_arg1;
                                arg1_copied = true;
                            }
                            bool arg1_ctx_written = false;
                            if (!context_368 || !looks_like_vtable_object(context_368)) {
                                CommentResult cr;
                                cr.error_code = 31;
                                cr.error_message = "parallel worker context unavailable";
                                cr.call_method = "piggyback_parallel";
                                batch->results[i] = std::move(cr);
                                spdlog::warn(
                                    "piggyback_parallel[{}]: skip invalid context ctx={:#x}",
                                    i, (uintptr_t)context_368);
                                return;
                            }
                            log_ctx_object_fingerprint(context_368, "worker-before-call");
                            if (worker_arg1 && ARG1_TEMPLATE_SIZE > 0x370) {
                                arg1_ctx_written = safe_copy_bytes(
                                    reinterpret_cast<uint8_t*>(worker_arg1) + 0x368,
                                    &context_368,
                                    sizeof(context_368));
                            }

                            *reinterpret_cast<void***>(pb_req + OFF_VTABLE) =
                                g_captured_vtable;
                            *reinterpret_cast<void**>(pb_req + OFF_AUTHOR_INFO) =
                                g_captured_author_info;
                            *reinterpret_cast<void**>(pb_req + OFF_AUTHOR_INFO + 8) =
                                g_captured_author_info2;

                            char* h1 = write_msvc_string_heap(
                                pb_req + OFF_SNS_ID, pb_sns);
                            char* h2 = write_msvc_string_heap(
                                pb_req + OFF_CONTENT, batch->comments[i]);
                            char* h3 = write_msvc_string_heap(
                                pb_req + OFF_REPLY_TO, batch->reply_to);
                            char* h4 = write_msvc_string_heap(
                                pb_req + OFF_COMMENT_KEY, make_short_comment_key());

                            auto t0 = std::chrono::steady_clock::now();
                            CommentResult cr;
                            t_piggyback_parallel_worker = true;
                            int seh_rc = safe_call_original(
                                pb_req, worker_arg1, arg2, arg3);
                            t_piggyback_parallel_worker = false;
                            auto t1 = std::chrono::steady_clock::now();
                            cr.latency_ms = static_cast<int>(
                                std::chrono::duration_cast<
                                    std::chrono::milliseconds>(t1 - t0).count());
                            if (seh_rc == 0) {
                                cr.error_code = 0;
                                cr.call_method = "piggyback_parallel";
                            } else {
                                cr.error_code = 30;
                                cr.error_message = "SEH in piggyback_parallel";
                                cr.call_method = "piggyback_parallel";
                                spdlog::error("piggyback_parallel[{}]: SEH exc", i);
                            }

                            auto heap = GetProcessHeap();
                            if (h1) HeapFree(heap, 0, h1);
                            if (h2) HeapFree(heap, 0, h2);
                            if (h3) HeapFree(heap, 0, h3);
                            if (h4) HeapFree(heap, 0, h4);

                            batch->results[i] = std::move(cr);
                            spdlog::info(
                                "piggyback_parallel[{}]: code={} lat={}ms implicit_tls={} tls_slots_copied={} fls_copied={} arg1_copied={} arg1_ctx_written={} ctx={:#x}",
                                i, cr.error_code, cr.latency_ms, implicit_copied, tls_slots_copied, fls_copied, arg1_copied, arg1_ctx_written, (uintptr_t)context_368);
                        });

                        // Throttle: wait when we hit max_concurrency
                        if (workers.size() >= static_cast<size_t>(conc)) {
                            for (auto& w : workers) {
                                if (w.joinable()) w.join();
                            }
                            workers.clear();
                        }
                    }
                    for (auto& w : workers) {
                        if (w.joinable()) w.join();
                    }
                }
            } else {
                // ===== SERIAL MODE (original) =====
                for (size_t i = 0; i < batch->comments.size(); ++i) {
                alignas(16) uint8_t pb_req[REQUEST_CALL_BUFFER_SIZE];
                memcpy(pb_req, g_request_template.data(),
                       REQUEST_CALL_BUFFER_SIZE);

                *reinterpret_cast<void***>(pb_req + OFF_VTABLE) =
                    g_captured_vtable;
                *reinterpret_cast<void**>(pb_req + OFF_AUTHOR_INFO) =
                    g_captured_author_info;
                *reinterpret_cast<void**>(pb_req + OFF_AUTHOR_INFO + 8) =
                    g_captured_author_info2;

                char* h1 = write_msvc_string_heap(
                    pb_req + OFF_SNS_ID, pb_sns);
                char* h2 = write_msvc_string_heap(
                    pb_req + OFF_CONTENT, batch->comments[i]);
                char* h3 = write_msvc_string_heap(
                    pb_req + OFF_REPLY_TO, batch->reply_to);
                char* h4 = write_msvc_string_heap(
                    pb_req + OFF_COMMENT_KEY, make_short_comment_key());

                auto t0 = std::chrono::steady_clock::now();
                CommentResult cr;
                int seh_rc = safe_call_original(
                    pb_req, arg1, arg2, arg3);
                auto t1 = std::chrono::steady_clock::now();
                cr.latency_ms = static_cast<int>(
                    std::chrono::duration_cast<
                        std::chrono::milliseconds>(t1 - t0).count());
                if (seh_rc == 0) {
                    cr.error_code = 0;
                    cr.call_method = "piggyback";
                } else {
                    cr.error_code = 30;
                    cr.error_message = "SEH in piggyback";
                    cr.call_method = "piggyback";
                    spdlog::error("piggyback[{}]: SEH exc", i);
                }

                auto heap = GetProcessHeap();
                if (h1) HeapFree(heap, 0, h1);
                if (h2) HeapFree(heap, 0, h2);
                if (h3) HeapFree(heap, 0, h3);
                if (h4) HeapFree(heap, 0, h4);

                batch->results[i] = std::move(cr);
                spdlog::info("piggyback[{}]: code={} lat={}ms",
                             i, cr.error_code, cr.latency_ms);
            }
            } // end serial mode

            auto pb_end = std::chrono::steady_clock::now();
            auto total_ms = std::chrono::duration_cast<
                std::chrono::milliseconds>(pb_end - pb_start).count();

            {
                std::lock_guard<std::mutex> lk(batch->mutex);
                batch->total_latency_ms = total_ms;
                batch->done = true;
            }
            batch->cv.notify_all();
            spdlog::info("hook piggyback: done, total={}ms", total_ms);
        }
    }

    return original_result;
}

// =====================================================================
// cgi_A_caller_3_TOP hook — lightweight probe to detect if this path is used
// =====================================================================

// SEH-safe field reader (pure C, no C++ objects in __try scope)
static bool seh_read_fields(const uint8_t* req_bytes,
                             char* sns_id_buf, size_t sns_id_max,
                             char* content_buf, size_t content_max) {
    sns_id_buf[0] = 0;
    content_buf[0] = 0;
    __try {
        // Read sns_id at OFF_SNS_ID (MSVC std::string layout)
        auto sns_size = *reinterpret_cast<const uint64_t*>(req_bytes + OFF_SNS_ID + 0x10);
        auto sns_cap  = *reinterpret_cast<const uint64_t*>(req_bytes + OFF_SNS_ID + 0x18);
        if (sns_size > 0 && sns_size < sns_id_max && sns_cap < 10000000) {
            const char* sns_data = (sns_cap <= 15)
                ? reinterpret_cast<const char*>(req_bytes + OFF_SNS_ID)
                : *reinterpret_cast<const char* const*>(req_bytes + OFF_SNS_ID);
            memcpy(sns_id_buf, sns_data, (size_t)sns_size);
            sns_id_buf[sns_size] = 0;
        }
        // Read content at OFF_CONTENT
        auto cnt_size = *reinterpret_cast<const uint64_t*>(req_bytes + OFF_CONTENT + 0x10);
        auto cnt_cap  = *reinterpret_cast<const uint64_t*>(req_bytes + OFF_CONTENT + 0x18);
        if (cnt_size > 0 && cnt_size < content_max && cnt_cap < 10000000) {
            const char* cnt_data = (cnt_cap <= 15)
                ? reinterpret_cast<const char*>(req_bytes + OFF_CONTENT)
                : *reinterpret_cast<const char* const*>(req_bytes + OFF_CONTENT);
            memcpy(content_buf, cnt_data, (size_t)cnt_size);
            content_buf[cnt_size] = 0;
        }
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        sns_id_buf[0] = 0;
        content_buf[0] = 0;
        return false;
    }
}

// SEH-safe state capture (no C++ objects)
static bool seh_capture_state(const uint8_t* req_bytes,
                               void*** out_vtable, void** out_author1, void** out_author2,
                               uint8_t* template_buf, size_t template_size,
                               void* arg1, uint8_t* arg1_buf, size_t arg1_size,
                               bool* out_arg1_ready) {
    __try {
        *out_vtable = *reinterpret_cast<void** const*>(req_bytes + OFF_VTABLE);
        *out_author1 = *reinterpret_cast<void* const*>(req_bytes + OFF_AUTHOR_INFO);
        *out_author2 = *reinterpret_cast<void* const*>(req_bytes + OFF_AUTHOR_INFO + 8);
        memcpy(template_buf, req_bytes, template_size);
        *out_arg1_ready = false;
        if (arg1) {
            memcpy(arg1_buf, arg1, arg1_size);
            *out_arg1_ready = true;
        }
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// Pure C version of write_msvc_string_sso for use in __try blocks (no std::string)
static bool write_msvc_string_sso_raw(uint8_t* base, const char* text, size_t len) {
    if (len > 15) return false;
    memcpy(base, text, len);
    memset(base + len, 0, 16 - len);
    *reinterpret_cast<uint64_t*>(base + 0x10) = len;
    *reinterpret_cast<uint64_t*>(base + 0x18) = 15;
    return true;
}

// SEH-safe inject fields
static void seh_inject_fields(uint8_t* req_bytes, const char* content, const char* sns_id, const char* reply_to) {
    __try {
        if (content[0]) write_msvc_string_sso_raw(req_bytes + OFF_CONTENT, content, strlen(content));
        if (sns_id[0]) write_msvc_string_sso_raw(req_bytes + OFF_SNS_ID, sns_id, strlen(sns_id));
        if (reply_to[0]) write_msvc_string_sso_raw(req_bytes + OFF_REPLY_TO, reply_to, strlen(reply_to));
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        // ignore
    }
}

static void* __fastcall hooked_cgi_A_top(
    void* request,
    void* arg1,
    int64_t arg2,
    void* arg3)
{
    g_hook_top_hit_count++;

    auto req_bytes = reinterpret_cast<uint8_t*>(request);

    // Log the call with arg details
    spdlog::info("TOP_HOOK HIT #{}: request={:#x} arg1={:#x} arg2={} arg3={:#x} tid={}",
                 g_hook_top_hit_count,
                 (uintptr_t)request, (uintptr_t)arg1, arg2, (uintptr_t)arg3,
                 GetCurrentThreadId());

    // Try to read sns_id and content from the request struct
    char sns_id_buf[256] = {}, content_buf[256] = {};
    bool read_ok = seh_read_fields(req_bytes, sns_id_buf, sizeof(sns_id_buf),
                                    content_buf, sizeof(content_buf));
    if (!read_ok) {
        spdlog::warn("TOP_HOOK: failed to read request fields (access violation)");
    }

    std::string sns_id(sns_id_buf), content(content_buf);
    if (!sns_id.empty() || !content.empty()) {
        spdlog::info("TOP_HOOK: sns_id={}, content={}", sns_id, content);
    }

    // Also do full state capture (same as cgi_A_caller_2 hook)
    {
        std::lock_guard<std::mutex> lock(g_capture_mutex);
        g_captured_arg1 = arg1;
        g_captured_arg2 = arg2;
        g_captured_arg3 = arg3;
        g_capture_tick_ms = monotonic_ms();
        g_capture_thread_id = GetCurrentThreadId();

        // Try to capture vtable and author info (SEH-safe)
        bool arg1_rdy = false;
        bool cap_ok = seh_capture_state(req_bytes,
            &g_captured_vtable, &g_captured_author_info, &g_captured_author_info2,
            g_request_template.data(), REQUEST_CALL_BUFFER_SIZE,
            arg1, g_arg1_template.data(), ARG1_TEMPLATE_SIZE, &arg1_rdy);
        g_request_template_ready = cap_ok;
        g_arg1_template_ready = arg1_rdy;

        if (!cap_ok) {
            spdlog::warn("TOP_HOOK: failed to capture state (access violation)");
        }

        if (!g_state_captured) {
            g_state_captured = true;
            spdlog::info("TOP_HOOK: first state capture! vtable={:#x} arg1={:#x}",
                         (uintptr_t)g_captured_vtable, (uintptr_t)arg1);
        }

        // Collect TLS
        g_capture_tls_nonzero = 0;
        for (int i = 0; i < TLS_SLOT_COUNT; i++) {
            void* val = TlsGetValue(i);
            g_capture_tls_slots[i] = (uint64_t)(uintptr_t)val;
            if (val) g_capture_tls_nonzero++;
        }
        g_capture_is_gui_thread = (IsGUIThread(FALSE) != FALSE);
    }

    // Collect FLS + implicit TLS for parallel comment support
    collect_capture_fls();
    collect_capture_implicit_tls();
    ensure_capture_thread_msg_hook();

    // Cache SNS ID
    if (!sns_id.empty()) {
        auto& mgr = HookManager::instance();
        mgr.cache_sns_id("", content, sns_id);
        mgr.cache_latest_sns_id(sns_id);
    }

    // Process capture-thread direct-call jobs
    process_capture_thread_jobs("hook_top_callback");

    // Process pending comment queue
    {
        std::lock_guard<std::mutex> lock(g_queue_mutex);
        if (!g_pending_queue.empty()) {
            auto pending = g_pending_queue.front();
            g_pending_queue.pop();
            spdlog::info("TOP_HOOK: injecting queued comment: content={}", pending.content);
            seh_inject_fields(req_bytes,
                              pending.content.c_str(),
                              pending.sns_id.c_str(),
                              pending.reply_to.c_str());
        }
    }

    return g_original_top_fn(request, arg1, arg2, arg3);
}

// =====================================================================
// 公共 API 实现
// =====================================================================

bool init_sns_comment() {
    const char* mod = resolve_module_name();
    if (!mod) {
        spdlog::error("init_sns_comment: no WeChat module found");
        return false;
    }
    spdlog::info("init_sns_comment: using module {}", mod);

    auto hmod = GetModuleHandleA(mod);
    if (!hmod) {
        spdlog::error("init_sns_comment: GetModuleHandle failed");
        return false;
    }
    auto base = reinterpret_cast<uintptr_t>(hmod);

    // 1. 已知版本: 直接用硬编码 RVA (Frida PoC 已验证)
    auto ver = get_wechat_version();
    if (ver == "4.1.7.30") {
        auto comment_addr = base + COMMENT_FN_RVA;
        auto top_addr = base + TOP_FN_RVA;
        auto tls_accessor_addr = base + TLS_ACCESSOR_RVA;
        auto arg1_ctx_helper_addr = base + ARG1_CTX_HELPER_RVA;
        spdlog::info("version {} matched, using hardcoded RVA: {:#x} (caller2), {:#x} (top)",
                     ver, comment_addr, top_addr);
        g_target_fn_addr = comment_addr;
        g_top_fn_addr = top_addr;
        g_tls_accessor_addr = tls_accessor_addr;
        g_arg1_ctx_helper_addr = arg1_ctx_helper_addr;
    } else {
        // 2. 未知版本: 特征码扫描
        spdlog::info("version {} not hardcoded, using signature scan", ver);
        auto comment_addr = SigScanner::find(mod, SIG_CGI_A_CALLER_2);
        if (!comment_addr) {
            spdlog::warn("cgi_A_caller_2 not found via primary sig, trying cgi_A_top...");
            comment_addr = SigScanner::find(mod, SIG_CGI_A_TOP);
        }
        if (!comment_addr) {
            spdlog::error("SnsComment function not found via any signature");
            return false;
        }
        g_target_fn_addr = comment_addr;
        spdlog::info("SnsComment function @ {:#x} (RVA {:#x})",
                     comment_addr, comment_addr - base);
        g_tls_accessor_addr = 0;
        g_arg1_ctx_helper_addr = 0;
    }

    // vtable
    g_captured_vtable = reinterpret_cast<void**>(base + VTABLE_RVA);
    spdlog::info("vtable @ {:#x} (hardcoded RVA)", (uintptr_t)g_captured_vtable);

    return true;
}

bool install_comment_hook() {
    if (g_hook_installed) return true;
    if (g_target_fn_addr == 0) {
        spdlog::error("install_comment_hook: target function not located");
        return false;
    }

    auto target = reinterpret_cast<LPVOID>(g_target_fn_addr);
    MH_STATUS status = MH_CreateHook(
        target,
        reinterpret_cast<LPVOID>(&hooked_cgi_A_caller_2),
        reinterpret_cast<LPVOID*>(&g_original_fn)
    );
    if (status != MH_OK) {
        spdlog::error("MH_CreateHook failed: {}", MH_StatusToString(status));
        return false;
    }

    status = MH_EnableHook(target);
    if (status != MH_OK) {
        spdlog::error("MH_EnableHook failed: {}", MH_StatusToString(status));
        MH_RemoveHook(target);
        return false;
    }

    g_hook_installed = true;
    spdlog::info("comment hook installed @ {:#x}", g_target_fn_addr);

    if (g_tls_accessor_addr != 0) {
        auto tls_target = reinterpret_cast<LPVOID>(g_tls_accessor_addr);
        status = MH_CreateHook(
            tls_target,
            reinterpret_cast<LPVOID>(&hooked_tls_accessor),
            reinterpret_cast<LPVOID*>(&g_original_tls_accessor)
        );
        if (status != MH_OK) {
            spdlog::warn("MH_CreateHook tls accessor failed: {}", MH_StatusToString(status));
        } else {
            status = MH_EnableHook(tls_target);
            if (status != MH_OK) {
                spdlog::warn("MH_EnableHook tls accessor failed: {}", MH_StatusToString(status));
                MH_RemoveHook(tls_target);
                g_original_tls_accessor = nullptr;
            } else {
                g_tls_accessor_hook_installed = true;
                spdlog::info("tls accessor hook installed @ {:#x}", g_tls_accessor_addr);
            }
        }
    }

    if (g_arg1_ctx_helper_addr != 0) {
        auto helper_target = reinterpret_cast<LPVOID>(g_arg1_ctx_helper_addr);
        status = MH_CreateHook(
            helper_target,
            reinterpret_cast<LPVOID>(&hooked_arg1_ctx_helper),
            reinterpret_cast<LPVOID*>(&g_original_arg1_ctx_helper)
        );
        if (status != MH_OK) {
            spdlog::warn("MH_CreateHook arg1 ctx helper failed: {}", MH_StatusToString(status));
        } else {
            status = MH_EnableHook(helper_target);
            if (status != MH_OK) {
                spdlog::warn("MH_EnableHook arg1 ctx helper failed: {}", MH_StatusToString(status));
                MH_RemoveHook(helper_target);
                g_original_arg1_ctx_helper = nullptr;
            } else {
                g_arg1_ctx_helper_hook_installed = true;
                spdlog::info("arg1 ctx helper hook installed @ {:#x}", g_arg1_ctx_helper_addr);
            }
        }
    }
    return true;
}

void uninstall_comment_hook() {
    if (!g_hook_installed || g_target_fn_addr == 0) return;

    remove_capture_thread_msg_hook();

    if (g_arg1_ctx_helper_hook_installed && g_arg1_ctx_helper_addr != 0) {
        auto helper_target = reinterpret_cast<LPVOID>(g_arg1_ctx_helper_addr);
        MH_DisableHook(helper_target);
        MH_RemoveHook(helper_target);
        g_arg1_ctx_helper_hook_installed = false;
        g_original_arg1_ctx_helper = nullptr;
    }

    if (g_tls_accessor_hook_installed && g_tls_accessor_addr != 0) {
        auto tls_target = reinterpret_cast<LPVOID>(g_tls_accessor_addr);
        MH_DisableHook(tls_target);
        MH_RemoveHook(tls_target);
        g_tls_accessor_hook_installed = false;
        g_original_tls_accessor = nullptr;
    }

    auto target = reinterpret_cast<LPVOID>(g_target_fn_addr);
    MH_DisableHook(target);
    MH_RemoveHook(target);
    g_hook_installed = false;
    g_original_fn = nullptr;
    spdlog::info("comment hook uninstalled");
}

bool sns_queue_comment(const std::string& sns_id,
                       const std::string& content,
                       const std::string& reply_to) {
    if (!g_hook_installed) {
        spdlog::error("sns_queue_comment: hook not installed");
        return false;
    }

    std::lock_guard<std::mutex> lock(g_queue_mutex);
    g_pending_queue.push({sns_id, content, reply_to});
    spdlog::info("queued comment: sns_id={}, content={}, reply_to={}",
                 sns_id, content, reply_to);
    return true;
}

// =====================================================================
// Piggyback queue — load comments, wait for hook to fire and drain them
// =====================================================================

BatchCommentResult sns_queue_piggyback(
    const std::string& sns_id,
    const std::vector<std::string>& comments,
    const std::string& reply_to,
    int max_concurrency,
    int timeout_ms)
{
    BatchCommentResult result;
    result.total = static_cast<int>(comments.size());
    result.results.resize(comments.size());

    if (!g_hook_installed) {
        for (auto& r : result.results) {
            r.error_code = 20;
            r.error_message = "hook not installed";
        }
        result.failed = result.total;
        return result;
    }

    // Create batch and install it
    auto batch = std::make_shared<PiggybackBatch>();
    batch->comments = comments;
    batch->sns_id = sns_id;
    batch->reply_to = reply_to;
    batch->max_concurrency = max_concurrency;

    {
        std::lock_guard<std::mutex> lock(g_piggyback_mutex);
        g_piggyback_batch = batch;
    }

    spdlog::info("piggyback: queued {} comments, waiting for hook trigger "
                 "(timeout={}ms)", comments.size(), timeout_ms);

    // Wait for hook callback to drain the batch
    {
        std::unique_lock<std::mutex> lk(batch->mutex);
        bool ok = batch->cv.wait_for(
            lk, std::chrono::milliseconds(timeout_ms),
            [&] { return batch->done; });

        if (!ok) {
            // Timeout — remove batch
            {
                std::lock_guard<std::mutex> lock(g_piggyback_mutex);
                if (g_piggyback_batch == batch) {
                    g_piggyback_batch.reset();
                }
            }
            for (auto& r : result.results) {
                r.error_code = 40;
                r.error_message = "piggyback timeout -- no hook trigger";
            }
            result.failed = result.total;
            result.total_latency_ms = timeout_ms;
            return result;
        }
    }

    // Collect results
    result.results = batch->results;
    result.total_latency_ms = static_cast<int>(batch->total_latency_ms);
    for (auto& r : result.results) {
        if (r.error_code == 0) result.succeeded++;
        else result.failed++;
    }
    return result;
}

bool has_captured_state() {
    std::lock_guard<std::mutex> lock(g_capture_mutex);
    return g_state_captured;
}

bool is_captured_state_fresh(uint64_t max_age_ms) {
    std::lock_guard<std::mutex> lock(g_capture_mutex);
    if (!g_state_captured || g_capture_tick_ms == 0) return false;
    auto age = monotonic_ms() - g_capture_tick_ms;
    return age <= max_age_ms;
}

bool is_comment_hook_installed() {
    return g_hook_installed;
}

uint64_t get_capture_age_ms() {
    std::lock_guard<std::mutex> lock(g_capture_mutex);
    if (!g_state_captured || g_capture_tick_ms == 0) return 0;
    return monotonic_ms() - g_capture_tick_ms;
}

uint32_t get_capture_thread_id() {
    std::lock_guard<std::mutex> lock(g_capture_mutex);
    return static_cast<uint32_t>(g_capture_thread_id);
}

bool has_request_template() {
    std::lock_guard<std::mutex> lock(g_capture_mutex);
    return g_request_template_ready;
}

bool has_arg1_template() {
    std::lock_guard<std::mutex> lock(g_capture_mutex);
    return g_arg1_template_ready;
}

// =====================================================================
// Hook trigger test — call target function with NULL args to verify
// the MinHook detour fires and our hook function is reachable.
// =====================================================================

static int seh_test_call(fn_SnsCommentSubmit fn, void* arg0) {
    __try {
        fn(arg0, nullptr, 0, nullptr);
        return 0;  // no crash
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return GetExceptionCode();
    }
}

std::string test_hook_trigger() {
    // We call the ORIGINAL target address (not the trampoline).
    // If MinHook is active, this should go through our detour -> hook function.
    if (!g_target_fn_addr) {
        return "error: target function not resolved";
    }

    auto direct_fn = reinterpret_cast<fn_SnsCommentSubmit>(g_target_fn_addr);
    auto trampoline_fn = g_original_fn;

    // Prepare a dummy buffer (will crash, but hook should fire first)
    alignas(16) uint8_t dummy[0x200] = {};

    spdlog::info("test_hook_trigger: calling direct_fn={:#x} with dummy buffer", g_target_fn_addr);

    // Reset state_captured to detect if hook fires
    bool was_captured = false;
    {
        std::lock_guard<std::mutex> lock(g_capture_mutex);
        was_captured = g_state_captured;
    }

    int seh_code = seh_test_call(direct_fn, dummy);

    bool now_captured = false;
    {
        std::lock_guard<std::mutex> lock(g_capture_mutex);
        now_captured = g_state_captured;
    }

    bool hook_fired = (!was_captured && now_captured) || (was_captured);

    std::string result;
    result += "target_fn=" + std::to_string(g_target_fn_addr);
    result += " trampoline=" + std::to_string((uintptr_t)trampoline_fn);
    result += " seh_code=" + std::to_string(seh_code);
    result += " hook_fired=" + std::string(hook_fired ? "unknown(was_captured)" : (now_captured ? "YES" : "NO"));
    result += " state_before=" + std::string(was_captured ? "true" : "false");
    result += " state_after=" + std::string(now_captured ? "true" : "false");

    spdlog::info("test_hook_trigger: {}", result);
    return result;
}

// SEH 调用包装 — 独立函数，不含 C++ 对象，避免 C2712
static void* seh_call_comment_fn(fn_SnsCommentSubmit call_fn,
                                  void* request, void* arg1,
                                  int64_t arg2, void* arg3,
                                  int* out_error_code) {
    *out_error_code = 0;
    __try {
        return call_fn(request, arg1, arg2, arg3);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        *out_error_code = GetExceptionCode();
        return nullptr;
    }
}

CommentResult sns_do_comment(const std::string& sns_id,
                              const std::string& content,
                              const std::string& reply_to,
                              bool prefer_arg1_template,
                              const std::string& arg1_mode,
                              bool tls_copy) {
    spdlog::info("sns_do_comment called: sns_id={}, content_len={}, reply_to={}, prefer_arg1_template={}, arg1_mode={}",
                 sns_id, content.size(), reply_to, prefer_arg1_template, arg1_mode);

    CommentResult result;

    // 检查: 原始函数可用 (通过 hook 或直接定位)
    fn_SnsCommentSubmit call_fn = g_original_fn;  // 优先用 hook trampoline
    const char* call_method = "trampoline";
    if (!call_fn) {
        // 没有 hook, 用直接地址 (fallback)
        if (g_target_fn_addr) {
            call_fn = reinterpret_cast<fn_SnsCommentSubmit>(g_target_fn_addr);
            call_method = "direct";
        } else {
            result.error_code = 50;  // HOOK_NOT_INSTALLED
            result.error_message = "comment function not resolved (call init_sns_comment first)";
            spdlog::error("sns_do_comment: no function available");
            return result;
        }
    }

    if (!g_captured_vtable) {
        result.error_code = 50;
        result.error_message = "vtable not available";
        spdlog::error("sns_do_comment: vtable not available");
        return result;
    }

    // 持有锁快照捕获的运行时状态 (避免与 hook 线程 data race)
    void** snapshot_vtable;
    void* snapshot_arg1;
    int64_t snapshot_arg2;
    void* snapshot_arg3;
    void* snapshot_author_info;
    void* snapshot_author_info2;
    bool snapshot_captured;
    uint64_t snapshot_capture_tick_ms;
    DWORD snapshot_capture_thread_id;
    bool snapshot_template_ready;
    std::array<uint8_t, REQUEST_CALL_BUFFER_SIZE> snapshot_template{};
    bool snapshot_arg1_template_ready;
    std::array<uint8_t, ARG1_TEMPLATE_SIZE> snapshot_arg1_template{};
    uint64_t snapshot_tls_slots[TLS_SLOT_COUNT] = {};
    {
        std::lock_guard<std::mutex> lock(g_capture_mutex);
        snapshot_vtable = g_captured_vtable;
        snapshot_arg1 = g_captured_arg1;
        snapshot_arg2 = g_captured_arg2;
        snapshot_arg3 = g_captured_arg3;
        snapshot_author_info = g_captured_author_info;
        snapshot_author_info2 = g_captured_author_info2;
        snapshot_captured = g_state_captured;
        snapshot_capture_tick_ms = g_capture_tick_ms;
        snapshot_capture_thread_id = g_capture_thread_id;
        snapshot_template_ready = g_request_template_ready;
        if (snapshot_template_ready) {
            snapshot_template = g_request_template;
        }
        snapshot_arg1_template_ready = g_arg1_template_ready;
        if (snapshot_arg1_template_ready) {
            snapshot_arg1_template = g_arg1_template;
        }
        // Copy TLS slots for TLS copy experiment
        memcpy(snapshot_tls_slots, g_capture_tls_slots, sizeof(snapshot_tls_slots));
    }

    if (!snapshot_captured) {
        result.error_code = 30;
        result.error_message = "runtime context not captured yet";
        result.call_method = call_method;
        spdlog::warn("sns_do_comment: no captured runtime context");
        return result;
    }

    uint64_t age_ms = 0;
    if (snapshot_capture_tick_ms > 0) {
        age_ms = monotonic_ms() - snapshot_capture_tick_ms;
    }
    const bool stale_context = age_ms > CONTEXT_FRESHNESS_MS;
    if (stale_context) {
        // Observed in practice: stale context can still succeed on some runs.
        // Keep trying direct-call, but expose freshness through status API.
        spdlog::warn("sns_do_comment: stale context age={}ms > {}ms, still attempting direct-call",
                     age_ms, CONTEXT_FRESHNESS_MS);
    }

    if (!snapshot_template_ready) {
        result.error_code = 30;
        result.error_message = "request template not ready";
        result.call_method = call_method;
        spdlog::warn("sns_do_comment: request template not ready");
        return result;
    }

    spdlog::info("sns_do_comment: method={}, state_captured={}, vtable={:#x}, "
                 "arg1={:#x}, arg2={}, arg3={:#x}, author_info={:#x}, "
                 "age_ms={}, capture_tid={}",
                 call_method, snapshot_captured,
                 (uintptr_t)snapshot_vtable,
                 (uintptr_t)snapshot_arg1,
                 snapshot_arg2,
                 (uintptr_t)snapshot_arg3,
                 (uintptr_t)snapshot_author_info,
                 age_ms, snapshot_capture_thread_id);

    // Build request from captured template prefix, then patch known fields.
    alignas(16) std::array<uint8_t, REQUEST_CALL_BUFFER_SIZE> req_buf{};
    auto* req_bytes = req_buf.data();
    memcpy(req_bytes, snapshot_template.data(), REQUEST_CALL_BUFFER_SIZE);

    *reinterpret_cast<void***>(req_bytes + OFF_VTABLE) = snapshot_vtable;
    *reinterpret_cast<void**>(req_bytes + OFF_AUTHOR_INFO) = snapshot_author_info;
    *reinterpret_cast<void**>(req_bytes + OFF_AUTHOR_INFO + 8) = snapshot_author_info2;

    // Track heap allocations for cleanup after call
    char* heap_sns = nullptr;
    char* heap_content = nullptr;
    char* heap_reply = nullptr;
    char* heap_key = nullptr;

    heap_sns = write_msvc_string_heap(req_bytes + OFF_SNS_ID, sns_id);
    heap_content = write_msvc_string_heap(req_bytes + OFF_CONTENT, content);
    heap_reply = write_msvc_string_heap(req_bytes + OFF_REPLY_TO, reply_to);
    heap_key = write_msvc_string_heap(req_bytes + OFF_COMMENT_KEY, make_short_comment_key());
    *reinterpret_cast<uint32_t*>(req_bytes + OFF_COMMENT_TYPE) = 2;  // 文本评论
    *reinterpret_cast<uint32_t*>(req_bytes + OFF_CREATE_TIME) = static_cast<uint32_t>(time(nullptr));

    // 准备参数 — arg1_mode controls how arg1 is provided
    alignas(16) std::array<uint8_t, ARG1_TEMPLATE_SIZE> arg1_buf{};
    void* arg1 = nullptr;
    std::string effective_arg1_mode = arg1_mode;

    if (arg1_mode == "null") {
        arg1 = nullptr;
    } else if (arg1_mode == "zeroed") {
        memset(arg1_buf.data(), 0, ARG1_TEMPLATE_SIZE);
        arg1 = arg1_buf.data();
    } else if (arg1_mode == "captured_ptr") {
        arg1 = snapshot_arg1;  // original pointer, may be stale
    } else {
        // "template" (default) — use captured template bytes
        if (prefer_arg1_template && snapshot_arg1_template_ready) {
            arg1_buf = snapshot_arg1_template;
            arg1 = arg1_buf.data();
            result.arg1_template_used = true;
        } else {
            arg1 = snapshot_arg1;
            effective_arg1_mode = "captured_ptr_fallback";
        }
    }
    result.arg1_mode = effective_arg1_mode;

    int64_t arg2 = snapshot_arg2;
    void* arg3 = snapshot_arg3;

    // Arm VEH to capture crash details before SEH swallows the exception
    memset(&g_crash_diag, 0, sizeof(g_crash_diag));
    PVOID veh_handle = AddVectoredExceptionHandler(1 /*first handler*/, diag_veh);
    g_veh_armed = true;

    // TLS copy: temporarily copy capture thread's TLS slots to current thread
    uint64_t saved_tls[TLS_SLOT_COUNT] = {};
    int tls_copied_count = 0;
    if (tls_copy) {
        spdlog::info("sns_do_comment: TLS copy mode — copying capture thread TLS slots");
        for (int i = 0; i < TLS_SLOT_COUNT; i++) {
            saved_tls[i] = (uint64_t)(uintptr_t)TlsGetValue(i);
            if (snapshot_tls_slots[i] != 0 && saved_tls[i] == 0) {
                TlsSetValue(i, (LPVOID)snapshot_tls_slots[i]);
                tls_copied_count++;
            }
        }
        spdlog::info("sns_do_comment: copied {} TLS slots", tls_copied_count);
    }

    // SEH 保护调用 (通过独立函数避免 C2712)
    auto call_start = std::chrono::steady_clock::now();
    int seh_error = 0;
    void* ret = seh_call_comment_fn(call_fn, req_bytes, arg1, arg2, arg3, &seh_error);
    auto call_end = std::chrono::steady_clock::now();
    auto call_ms = std::chrono::duration_cast<std::chrono::milliseconds>(call_end - call_start).count();

    // Restore TLS slots
    if (tls_copy) {
        for (int i = 0; i < TLS_SLOT_COUNT; i++) {
            if (snapshot_tls_slots[i] != 0 && saved_tls[i] == 0) {
                TlsSetValue(i, (LPVOID)saved_tls[i]);
            }
        }
        spdlog::info("sns_do_comment: TLS slots restored");
    }

    // Disarm VEH
    g_veh_armed = false;
    if (veh_handle) RemoveVectoredExceptionHandler(veh_handle);

    // Free heap-allocated string buffers
    auto heap = GetProcessHeap();
    if (heap_sns) HeapFree(heap, 0, heap_sns);
    if (heap_content) HeapFree(heap, 0, heap_content);
    if (heap_reply) HeapFree(heap, 0, heap_reply);
    if (heap_key) HeapFree(heap, 0, heap_key);

    result.call_method = call_method;
    result.latency_ms = static_cast<int>(call_ms);

    if (seh_error != 0) {
        result.error_code = 30;
        result.error_message = "SEH exception in sns_do_comment";
        result.seh_code = static_cast<uint32_t>(seh_error);
        // Copy VEH crash diagnostics
        result.crash_rip = g_crash_diag.rip;
        result.crash_fault_addr = g_crash_diag.fault_addr;
        result.crash_fault_type = g_crash_diag.fault_type;
        result.crash_rcx = g_crash_diag.rcx;
        result.crash_rdx = g_crash_diag.rdx;
        result.crash_r8 = g_crash_diag.r8;
        result.crash_r9 = g_crash_diag.r9;
        result.crash_rsp = g_crash_diag.rsp;
        result.crash_rbp = g_crash_diag.rbp;
        spdlog::error("sns_do_comment: SEH exception code={:#x}, latency={}ms, "
                      "crash_rip={:#x}, fault_addr={:#x}, fault_type={}",
                      seh_error, call_ms,
                      g_crash_diag.rip, g_crash_diag.fault_addr, g_crash_diag.fault_type);
    } else {
        result.success = (ret != nullptr);
        if (!result.success) {
            result.error_code = 30;
            result.error_message = "WeChat returned null";
        }
        spdlog::info("sns_do_comment: ret={:#x}, success={}, latency={}ms",
                     (uintptr_t)ret, result.success, call_ms);
    }

    return result;
}

CommentResult sns_do_comment_on_capture_thread(
    const std::string& sns_id,
    const std::string& content,
    const std::string& reply_to,
    bool prefer_arg1_template,
    uint32_t wait_timeout_ms) {
    CommentResult timeout_result;
    timeout_result.error_code = 30;
    timeout_result.error_message = "capture-thread execution timeout";
    timeout_result.call_method = "capture_thread";

    if (!g_hook_installed) {
        timeout_result.error_code = 50;
        timeout_result.error_message = "hook not installed";
        return timeout_result;
    }

    auto job = std::make_shared<CaptureThreadDirectJob>();
    job->sns_id = sns_id;
    job->content = content;
    job->reply_to = reply_to;
    job->prefer_arg1_template = prefer_arg1_template;

    {
        std::lock_guard<std::mutex> lock(g_capture_thread_jobs_mutex);
        g_capture_thread_jobs.push_back(job);
    }

    // Try actively waking capture thread via message hook so this call does not
    // rely on the next UI comment callback.
    bool wake_sent = false;
    if (ensure_capture_thread_msg_hook()) {
        DWORD capture_tid = 0;
        {
            std::lock_guard<std::mutex> lock(g_capture_mutex);
            capture_tid = g_capture_thread_id;
        }
        if (capture_tid != 0) {
            if (PostThreadMessage(capture_tid, WM_PYWECHAT_CAPTURE_TICK, 0, 0) ||
                PostThreadMessage(capture_tid, WM_NULL, 0, 0)) {
                wake_sent = true;
            } else {
                spdlog::warn("capture-thread wake PostThreadMessage failed, err={}",
                             GetLastError());
            }
        }
    }
    if (!wake_sent) {
        spdlog::debug("capture-thread wake not sent, waiting for callback trigger");
    }

    // Wait until the next hook callback executes this job.
    std::unique_lock<std::mutex> lk(job->mutex);
    const bool done = job->cv.wait_for(
        lk,
        std::chrono::milliseconds(wait_timeout_ms),
        [&]() { return job->done; });

    if (done) {
        return job->result;
    }

    // Timeout: mark cancelled and best-effort remove from pending queue.
    job->cancelled = true;
    lk.unlock();

    bool removed_from_queue = false;
    {
        std::lock_guard<std::mutex> lock(g_capture_thread_jobs_mutex);
        for (auto it = g_capture_thread_jobs.begin(); it != g_capture_thread_jobs.end(); ++it) {
            if (it->get() == job.get()) {
                g_capture_thread_jobs.erase(it);
                removed_from_queue = true;
                break;
            }
        }
    }

    if (!removed_from_queue) {
        timeout_result.error_message = "capture-thread execution timeout (job may still be running)";
    }

    return timeout_result;
}

BatchCommentResult sns_do_comment_batch(
    const std::string& sns_id,
    const std::vector<std::string>& comments,
    const std::string& reply_to,
    int concurrency) {

    BatchCommentResult batch;
    batch.total = static_cast<int>(comments.size());

    if (comments.empty()) {
        spdlog::info("sns_do_comment_batch: empty comments list");
        return batch;
    }

    // 限制并发数
    if (concurrency < 1) concurrency = 1;
    if (concurrency > 20) concurrency = 20;

    spdlog::info("sns_do_comment_batch: total={}, concurrency={}, sns_id={}",
                 batch.total, concurrency, sns_id);

    batch.results.resize(comments.size());

    auto batch_start = std::chrono::steady_clock::now();

    // 创建线程池并发发送
    std::vector<std::thread> threads;
    threads.reserve(comments.size());

    for (size_t i = 0; i < comments.size(); ++i) {
        threads.emplace_back([&, i]() {
            batch.results[i] = sns_do_comment(sns_id, comments[i], reply_to);
        });

        // 控制并发数: 当已启动线程数达到 concurrency 时等待
        if (threads.size() >= static_cast<size_t>(concurrency)) {
            for (auto& t : threads) {
                if (t.joinable()) t.join();
            }
            threads.clear();
        }
    }

    // 等待剩余线程完成
    for (auto& t : threads) {
        if (t.joinable()) t.join();
    }

    auto batch_end = std::chrono::steady_clock::now();
    batch.total_latency_ms = static_cast<int>(
        std::chrono::duration_cast<std::chrono::milliseconds>(batch_end - batch_start).count());

    // 统计结果
    for (const auto& r : batch.results) {
        if (r.success) batch.succeeded++;
        else batch.failed++;
    }

    spdlog::info("sns_do_comment_batch done: {}/{} succeeded, total_latency={}ms",
                 batch.succeeded, batch.total, batch.total_latency_ms);

    return batch;
}

// =====================================================================
// Thread diagnostics — compare capture thread vs pipe thread context
// =====================================================================

ThreadDiagResult diagnose_thread_context() {
    ThreadDiagResult diag;
    diag.pipe_thread_id = GetCurrentThreadId();

    // Capture thread info (from last hook callback)
    {
        std::lock_guard<std::mutex> lock(g_capture_mutex);
        diag.capture_thread_id = static_cast<uint32_t>(g_capture_thread_id);
        diag.capture_tls_nonzero = g_capture_tls_nonzero;
        diag.capture_is_gui_thread = g_capture_is_gui_thread;
        diag.capture_tls_values.resize(TLS_SLOT_COUNT);
        for (int i = 0; i < TLS_SLOT_COUNT; i++) {
            diag.capture_tls_values[i] = g_capture_tls_slots[i];
        }
    }

    // Pipe thread TLS
    diag.pipe_tls_nonzero = 0;
    diag.pipe_tls_values.resize(TLS_SLOT_COUNT);
    for (int i = 0; i < TLS_SLOT_COUNT; i++) {
        void* val = TlsGetValue(i);
        diag.pipe_tls_values[i] = (uint64_t)(uintptr_t)val;
        if (val) diag.pipe_tls_nonzero++;
    }

    // Identify slots that are set only on capture thread
    for (int i = 0; i < TLS_SLOT_COUNT; i++) {
        if (diag.capture_tls_values[i] != 0 && diag.pipe_tls_values[i] == 0) {
            diag.capture_only_slots.push_back(i);
        }
    }

    // COM state test on pipe thread
    // Try CoInitializeEx — if it returns S_OK we weren't initialized, undo it.
    // If RPC_E_CHANGED_MODE or S_FALSE, COM was already initialized.
    HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (hr == S_OK) {
        // Was NOT initialized, undo
        CoUninitialize();
        diag.pipe_com_initialized = false;
    } else {
        // S_FALSE (already STA) or RPC_E_CHANGED_MODE (already MTA) = initialized
        diag.pipe_com_initialized = true;
        if (hr == S_FALSE) CoUninitialize();  // balance ref count
    }

    diag.pipe_is_gui_thread = (IsGUIThread(FALSE) != FALSE);

    spdlog::info("diagnose_thread: capture_tid={}, pipe_tid={}, "
                 "capture_tls_nonzero={}, pipe_tls_nonzero={}, "
                 "capture_only_slots={}, pipe_com={}, "
                 "capture_gui={}, pipe_gui={}",
                 diag.capture_thread_id, diag.pipe_thread_id,
                 diag.capture_tls_nonzero, diag.pipe_tls_nonzero,
                 diag.capture_only_slots.size(),
                 diag.pipe_com_initialized,
                 diag.capture_is_gui_thread, diag.pipe_is_gui_thread);

    return diag;
}

// =====================================================================
// read_memory_at_rva — read N bytes from Weixin.dll base + rva
// =====================================================================

ReadMemoryResult read_memory_at_rva(uintptr_t rva, size_t size) {
    ReadMemoryResult result;
    result.rva = rva;

    if (size == 0 || size > 4096) {
        result.error_message = "size must be 1-4096";
        return result;
    }

    HMODULE hmod = GetModuleHandleA("Weixin.dll");
    if (!hmod) hmod = GetModuleHandleA("WeChatWin.dll");
    if (!hmod) {
        result.error_message = "WeChat module not found";
        return result;
    }

    auto base = reinterpret_cast<uintptr_t>(hmod);
    result.address = base + rva;

    result.bytes.resize(size);
    if (!safe_copy_bytes(result.bytes.data(),
                         reinterpret_cast<const void*>(result.address),
                         size)) {
        result.error_message = "access violation reading memory";
        result.bytes.clear();
        return result;
    }

    result.success = true;
    spdlog::info("read_memory_at_rva: rva={:#x} addr={:#x} size={}",
                 rva, result.address, size);
    return result;
}

// =====================================================================
// get_tls_diag_info — implicit TLS + FLS diagnostics
// =====================================================================

// Capture-thread FLS snapshot (collected during hook callback)
static constexpr int FLS_SLOT_MAX = 128;
static uint64_t g_capture_fls_slots[FLS_SLOT_MAX] = {};
static int g_capture_fls_nonzero = 0;
static bool g_capture_fls_collected = false;

// Called from hook callback to collect FLS slots
static void collect_capture_fls() {
    g_capture_fls_nonzero = 0;
    for (int i = 0; i < FLS_SLOT_MAX; i++) {
        void* val = FlsGetValue(i);
        g_capture_fls_slots[i] = (uint64_t)(uintptr_t)val;
        if (val) g_capture_fls_nonzero++;
    }
    g_capture_fls_collected = true;
}

// Capture-thread implicit TLS block address
static uintptr_t g_capture_implicit_tls_block = 0;
static bool g_capture_implicit_tls_collected = false;
static std::atomic<int> g_tls_slot_0x358_log_hits{0};

static void collect_capture_implicit_tls() {
    // Read TEB->ThreadLocalStoragePointer (offset 0x58 on x64)
    auto teb = reinterpret_cast<uintptr_t>(NtCurrentTeb());
    if (!teb) return;
    auto tls_array = *reinterpret_cast<uintptr_t**>(teb + 0x58);
    if (!tls_array) return;

    // Get Weixin.dll TLS index from PE header
    HMODULE hmod = GetModuleHandleA("Weixin.dll");
    if (!hmod) hmod = GetModuleHandleA("WeChatWin.dll");
    if (!hmod) return;

    auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(hmod);
    auto nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(
        reinterpret_cast<uintptr_t>(hmod) + dos->e_lfanew);
    auto& tls_dir_entry = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    if (tls_dir_entry.VirtualAddress == 0 || tls_dir_entry.Size == 0) return;

    auto tls_dir = reinterpret_cast<IMAGE_TLS_DIRECTORY64*>(
        reinterpret_cast<uintptr_t>(hmod) + tls_dir_entry.VirtualAddress);
    auto tls_index_ptr = reinterpret_cast<uint32_t*>(tls_dir->AddressOfIndex);
    uint32_t tls_index = *tls_index_ptr;

    g_capture_implicit_tls_block = tls_array[tls_index];
    g_capture_implicit_tls_collected = true;

    g_capture_tls_slot_0x358_raw = 0;
    g_capture_tls_slot_0x358_ptr = 0;
    g_capture_tls_slot_0x358_ready = false;
    if (g_capture_implicit_tls_block) {
        uint64_t raw = 0;
        if (safe_copy_bytes(&raw,
                            reinterpret_cast<void*>(g_capture_implicit_tls_block + 0x358),
                            sizeof(raw))) {
            g_capture_tls_slot_0x358_raw = raw;
            uintptr_t ptr = 0;
            int tag_bits = 0;
            if (decode_tagged_pointer(raw, &ptr, &tag_bits)) {
                g_capture_tls_slot_0x358_ptr = ptr;
                g_capture_tls_slot_0x358_ready = true;
            }
            int hit = ++g_tls_slot_0x358_log_hits;
            if (hit <= 12) {
                spdlog::info(
                    "capture_tls_block+0x358: raw={:#x} ptr={:#x} ready={} tag_bits={} block={:#x}",
                    g_capture_tls_slot_0x358_raw,
                    g_capture_tls_slot_0x358_ptr,
                    g_capture_tls_slot_0x358_ready,
                    tag_bits,
                    g_capture_implicit_tls_block);
            }
        }
    }
}

// SEH helper: read uint32 safely (cannot use __try in functions with unwindable objects)
static uint32_t safe_read_uint32(const uint32_t* ptr, uint32_t fallback) {
    __try {
        return *ptr;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return fallback;
    }
}

TlsDiagInfo get_tls_diag_info() {
    TlsDiagInfo info;

    HMODULE hmod = GetModuleHandleA("Weixin.dll");
    if (!hmod) hmod = GetModuleHandleA("WeChatWin.dll");
    if (!hmod) {
        return info;
    }
    auto base = reinterpret_cast<uintptr_t>(hmod);

    // Parse PE TLS Directory
    auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(hmod);
    auto nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
    auto& tls_entry = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];

    if (tls_entry.VirtualAddress != 0 && tls_entry.Size != 0) {
        info.has_tls_directory = true;
        auto tls_dir = reinterpret_cast<IMAGE_TLS_DIRECTORY64*>(
            base + tls_entry.VirtualAddress);

        info.tls_start_rva = tls_dir->StartAddressOfRawData - base;
        info.tls_end_rva = tls_dir->EndAddressOfRawData - base;
        info.tls_index_addr = tls_dir->AddressOfIndex;
        info.tls_data_size = static_cast<size_t>(
            tls_dir->EndAddressOfRawData - tls_dir->StartAddressOfRawData);

        auto tls_index_ptr = reinterpret_cast<uint32_t*>(tls_dir->AddressOfIndex);
        info.tls_index_value = safe_read_uint32(tls_index_ptr, 0xFFFFFFFF);
    }

    // Implicit TLS block comparison
    if (g_capture_implicit_tls_collected) {
        info.capture_implicit_tls_valid = true;
        info.capture_tls_block_addr = g_capture_implicit_tls_block;

        // Current thread's implicit TLS block
        auto teb = reinterpret_cast<uintptr_t>(NtCurrentTeb());
        if (teb && info.has_tls_directory) {
            auto tls_array = *reinterpret_cast<uintptr_t**>(teb + 0x58);
            if (tls_array) {
                info.current_tls_block_addr = tls_array[info.tls_index_value];
            }
        }
    }

    // FLS comparison
    if (g_capture_fls_collected) {
        info.capture_fls_nonzero = g_capture_fls_nonzero;
    }
    info.current_fls_nonzero = 0;
    for (int i = 0; i < FLS_SLOT_MAX; i++) {
        void* val = FlsGetValue(i);
        if (val) info.current_fls_nonzero++;
        if (g_capture_fls_collected && g_capture_fls_slots[i] != 0 &&
            (uintptr_t)val == 0) {
            info.capture_only_fls_slots.push_back(i);
        }
    }

    spdlog::info("tls_diag: has_tls_dir={} tls_data_size={} tls_index={} "
                 "capture_block={:#x} current_block={:#x} "
                 "capture_fls={} current_fls={} fls_only_slots={}",
                 info.has_tls_directory, info.tls_data_size,
                 info.tls_index_value,
                 info.capture_tls_block_addr, info.current_tls_block_addr,
                 info.capture_fls_nonzero, info.current_fls_nonzero,
                 info.capture_only_fls_slots.size());
    return info;
}

// =====================================================================
// sns_do_comment_parallel — parallel comment with TLS context copy
// =====================================================================

// Helper: copy implicit TLS block from capture thread to current thread
static bool copy_implicit_tls_to_current(uint32_t tls_index, size_t tls_data_size,
                                          uintptr_t src_block) {
    if (!src_block || tls_data_size == 0) return false;

    auto teb = reinterpret_cast<uintptr_t>(NtCurrentTeb());
    if (!teb) return false;
    auto tls_array = *reinterpret_cast<uintptr_t**>(teb + 0x58);
    if (!tls_array) return false;

    auto dst_block = tls_array[tls_index];
    if (!dst_block) return false;

    return safe_copy_bytes(reinterpret_cast<void*>(dst_block),
                           reinterpret_cast<const void*>(src_block),
                           tls_data_size);
}

// Helper: copy capture-thread TLS slots to current thread (force overwrite).
static int copy_tls_slots_to_current() {
    int copied = 0;
    for (int i = 0; i < TLS_SLOT_COUNT; i++) {
        if (g_capture_tls_slots[i] != 0) {
            void* current = TlsGetValue(i);
            if ((uintptr_t)current != g_capture_tls_slots[i]) {
                if (TlsSetValue(i, (LPVOID)g_capture_tls_slots[i])) {
                    copied++;
                }
            }
        }
    }
    return copied;
}

// Helper: copy FLS slots from capture snapshot to current thread (force overwrite).
static int copy_fls_to_current() {
    int copied = 0;
    for (int i = 0; i < FLS_SLOT_MAX; i++) {
        if (g_capture_fls_slots[i] != 0) {
            void* current = FlsGetValue(i);
            if ((uintptr_t)current != g_capture_fls_slots[i]) {
                if (FlsSetValue(i, (LPVOID)g_capture_fls_slots[i])) {
                    copied++;
                }
            }
        }
    }
    return copied;
}

// Helper: restore FLS slots to original values
static void restore_fls(const uint64_t saved_fls[FLS_SLOT_MAX]) {
    for (int i = 0; i < FLS_SLOT_MAX; i++) {
        if (g_capture_fls_slots[i] != 0) {
            void* current = FlsGetValue(i);
            if (current == (LPVOID)g_capture_fls_slots[i]) {
                FlsSetValue(i, (LPVOID)saved_fls[i]);
            }
        }
    }
}

BatchCommentResult sns_do_comment_parallel(
    const std::string& sns_id,
    const std::vector<std::string>& comments,
    const std::string& reply_to,
    int max_concurrency,
    const std::string& tls_mode) {

    BatchCommentResult batch;
    batch.total = static_cast<int>(comments.size());

    if (comments.empty()) return batch;
    if (max_concurrency < 1) max_concurrency = 1;
    if (max_concurrency > 20) max_concurrency = 20;

    spdlog::info("sns_do_comment_parallel: total={} concurrency={} tls_mode={} "
                 "req_0x368_cached={} sns_id={}",
                 batch.total, max_concurrency, tls_mode,
                 g_cached_req_0x368_valid, sns_id);

    if (!g_cached_req_0x368_valid) {
        spdlog::warn("sns_do_comment_parallel: request->+0x368 not cached, "
                      "need at least one hook trigger first");
    }

    batch.results.resize(comments.size());
    auto batch_start = std::chrono::steady_clock::now();

    // Launch worker threads with TLS accessor hook bypass
    std::vector<std::thread> threads;
    threads.reserve((std::min)((size_t)max_concurrency, comments.size()));

    for (size_t i = 0; i < comments.size(); ++i) {
        threads.emplace_back([&, i]() {
            batch.results[i] = sns_do_comment(
                sns_id, comments[i], reply_to,
                false,           // prefer_arg1_template = false
                "captured_ptr",  // use original arg1 pointer
                false);          // tls_copy = false
        });

        // Throttle: wait when we hit max_concurrency
        if (threads.size() >= static_cast<size_t>(max_concurrency)) {
            for (auto& t : threads) {
                if (t.joinable()) t.join();
            }
            threads.clear();
        }
    }

    for (auto& t : threads) {
        if (t.joinable()) t.join();
    }

    auto batch_end = std::chrono::steady_clock::now();
    batch.total_latency_ms = static_cast<int>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            batch_end - batch_start).count());

    for (const auto& r : batch.results) {
        if (r.success) batch.succeeded++;
        else batch.failed++;
    }

    spdlog::info("sns_do_comment_parallel done: {}/{} succeeded, "
                 "total_latency={}ms",
                 batch.succeeded, batch.total, batch.total_latency_ms);
    return batch;
}

}  // namespace pywechat
