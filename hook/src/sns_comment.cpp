#include "sns_comment.h"

#include <Windows.h>
#include <spdlog/spdlog.h>

#include "sig_scanner.h"

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
 * ===== Phase 2: 交叉引用分析 (xref_finder.py) =====
 *
 * 以下函数通过 RIP-relative 引用了上述字符串:
 *
 *   RVA 0x04924ff0  "SnsCommentRequest_proto"
 *     - 79 字节, 2 参数 (rcx, rdx)
 *     - 功能: 分配缓冲区, 复制 "micromsg.SnsCommentRequest" 字符串
 *     - 本质: protobuf 类型名初始化器 (NOT 评论入口)
 *     - 位于 vtable @ .rdata RVA 0x0857ed10
 *
 *   RVA 0x04925540  "SnsCommentResponse_proto"
 *     - 同上模式, 初始化 SnsCommentResponse 类型名
 *     - vtable @ .rdata RVA 0x0857eda0
 *
 *   RVA 0x048fb690  "SnsCommentContentRequest_proto"
 *     - 同上模式, 81 字节
 *     - vtable @ .rdata RVA 0x0857d2c0
 *
 *   RVA 0x029de330  "mmsnscomment_cgi_A"  ★★ CGI 请求发送
 *     - 840 字节栈帧, 4 参数 (rcx, r8, r9, [rbp+0x330])
 *     - 引用: "kernel::foundation::CoCgiSendRequest", "mm_cgi.h"
 *     - 直接调用 0x049244f0 (protobuf 区域函数)
 *     - 这是 CGI 层: 构造 HTTP 请求并发送
 *
 *   RVA 0x02a10a70  "mmsnscomment_cgi_B"  ★★★ 评论请求构造
 *     - 112 字节栈帧, 4 参数 (rcx=this, rdx=proto_data, r8=string, r9=string)
 *     - 直接加载 "/cgi-bin/micromsg-bin/mmsnscomment" 字符串
 *     - 调用 0x04924f40 (near SnsCommentRequest_proto, protobuf 序列化)
 *     - 这是评论请求构造的核心函数
 *
 *   RVA 0x05af06b0  "SnsComment_logic"
 *     - 856 字节栈帧, 0 显式参数 (可能通过全局/TLS 获取上下文)
 *     - vtable @ .rdata RVA 0x088f0fe0
 *     - 调用 0x000ad440, 0x000aca20, 0x000ac900 (数据管理器获取?)
 *     - 大量字符串处理和内存分配, 可能是业务主逻辑
 *
 * ===== Phase 3: 调用链分析 (caller_scanner.py) =====
 *
 *   路径 A (通过 mmsnscomment_cgi_A):
 *     0x049bdc10 (cgi_A_top, 1 arg, 816B 栈帧, 遍历请求队列)
 *       → 0x049e9240 (cgi_A_mid, 1 arg, 824B 栈帧, 构造请求对象)
 *         → 0x029de330 (mmsnscomment_cgi_A, 发送 CGI 请求)
 *
 *   路径 B (通过 mmsnscomment_cgi_B):   ★ 更直接的路径
 *     0x02a105a0 (cgi_B_top, 2 args, vtable 虚函数 @ .rdata 0x081e9ef8)
 *       → 0x02a10630 (cgi_B_mid)
 *         → 0x02a10a70 (mmsnscomment_cgi_B, 构造并发送评论请求)
 *
 * ===== Phase 4: 关键发现 =====
 *
 *   1. RTTI 类名被加密/混淆, 无法通过 type_info 获取类名
 *   2. 路径 B 更紧凑 (3 层调用, 入口仅 100 字节)
 *   3. mmsnscomment_cgi_B 直接连接 CGI 路径和 protobuf 序列化
 *   4. 0x04924f40 是 protobuf 序列化桥接函数:
 *      调用 vtable[3] (offset +0x18) 然后 JMP 到 0x04924560
 *
 * ===== 下一步: 动态验证 =====
 *
 *   使用 hook/tools/hook_candidates.js 挂钩所有候选函数:
 *     frida -p <PID> -l hook/tools/hook_candidates.js
 *   然后在微信中手动发一条评论, 观察:
 *     1. 哪些函数被触发 (排除未使用的)
 *     2. 调用顺序 (确认路径 A/B 哪个是实际路径)
 *     3. 各函数的参数值 (确定 sns_id, content, reply_to 的传递方式)
 *
 *   确认后即可填入下方代码。
 * =====================================================================
 */

// 主模块名 (4.0+ 为 Weixin.dll, 3.9.x 为 WeChatWin.dll)
static const char* resolve_module_name() {
    if (GetModuleHandleA("Weixin.dll")) return "Weixin.dll";
    if (GetModuleHandleA("WeChatWin.dll")) return "WeChatWin.dll";
    return nullptr;
}

// TODO(reverse): 特征码 — 在 IDA xref 分析完成后填入
// static const char* SNS_COMMENT_SIG = "48 89 5C 24 ?? ...";

// TODO(reverse): 函数原型
// typedef int64_t (__fastcall *fn_SnsComment)(
//     uint64_t mgr_ptr,          // SNS 管理器实例
//     uint64_t sns_obj_id,       // 帖子 SNS ID
//     const wchar_t* content,    // 评论内容 (UTF-16)
//     const wchar_t* reply_wxid  // 回复目标 wxid (空 = 顶层评论)
// );
// static fn_SnsComment g_sns_comment_fn = nullptr;

// TODO(reverse): SNS 管理器获取
// typedef uint64_t (__fastcall *fn_GetSnsDataMgr)();
// static fn_GetSnsDataMgr g_get_sns_mgr = nullptr;

bool init_sns_comment() {
    const char* mod = resolve_module_name();
    if (!mod) {
        spdlog::error("init_sns_comment: no WeChat module found");
        return false;
    }
    spdlog::info("init_sns_comment: using module {}", mod);

    // TODO(reverse): 通过特征码定位函数
    // auto comment_addr = SigScanner::find(mod, SNS_COMMENT_SIG);
    // if (!comment_addr) {
    //     spdlog::error("SnsComment function not found via signature");
    //     return false;
    // }
    // g_sns_comment_fn = reinterpret_cast<fn_SnsComment>(comment_addr);
    // spdlog::info("SnsComment function @ {:#x}", comment_addr);

    return false;  // 尚未实现
}

CommentResult sns_do_comment(const std::string& sns_id,
                              const std::string& content,
                              const std::string& reply_to) {
    spdlog::info("sns_do_comment called: sns_id={}, content={}, reply_to={}",
                 sns_id, content, reply_to);

    CommentResult result;

    // --- 逆向完成前: 返回 NOT_IMPLEMENTED ---
    result.success = false;
    result.error_code = 31;  // COMMENT_NOT_IMPLEMENTED
    result.error_message = "comment function not yet implemented (pending reverse engineering)";
    return result;

    // --- 逆向完成后: 取消下方注释并填入实际调用 ---
    /*
    if (!g_sns_comment_fn) {
        result.error_code = 50;  // HOOK_NOT_INSTALLED
        result.error_message = "comment function not resolved";
        return result;
    }

    // 转换参数
    std::wstring w_content(content.begin(), content.end());  // TODO: 正确的 UTF-8 -> UTF-16
    std::wstring w_reply(reply_to.begin(), reply_to.end());
    uint64_t obj_id = std::stoull(sns_id);

    // 获取管理器实例
    uint64_t mgr = g_get_sns_mgr ? g_get_sns_mgr() : 0;
    if (!mgr) {
        result.error_code = 50;
        result.error_message = "SNS manager instance is null";
        return result;
    }

    // SEH 保护调用
    __try {
        int64_t ret = g_sns_comment_fn(mgr, obj_id, w_content.c_str(), w_reply.c_str());
        result.success = (ret == 0);
        if (!result.success) {
            result.error_code = 30;
            result.error_message = "WeChat returned " + std::to_string(ret);
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        result.error_code = 30;
        result.error_message = "SEH exception in sns_do_comment";
        spdlog::error("SEH exception in sns_do_comment, code={:#x}",
                       GetExceptionCode());
    }

    return result;
    */
}

}  // namespace pywechat
