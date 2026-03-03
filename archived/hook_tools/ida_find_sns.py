"""
IDA Pro 脚本 —— 在 WeChatWin.dll 中定位 SNS 评论相关函数。

使用方法:
    1. IDA Pro 加载 WeChatWin.dll, 等待自动分析完成
    2. File -> Script file... -> 选择本文件
    3. 查看 Output 窗口的分析结果

脚本工作:
    1. 搜索 SNS/评论相关字符串
    2. 对每个字符串做交叉引用, 找到引用它的函数
    3. 从引用函数向上追溯调用链
    4. 输出候选函数列表及其特征信息
"""

import idaapi
import idautils
import idc
import ida_bytes
import ida_funcs
import ida_name
import ida_xref

# =========================================================================
# 配置: SNS 相关关键字符串
# =========================================================================

# 高优先级 (直接与评论相关)
HIGH_PRIORITY_STRINGS = [
    "SnsComment",
    "sns_comment",
    "AddComment",
    "DoComment",
    "PublishComment",
    "CreateComment",
    "addcomment",
    "/cgi-bin/micromsg-bin/mmsnscomment",
    "MMSnsComment",
    "SnsCommentRequest",
    "SnsCommentResponse",
]

# 中优先级 (SNS 操作相关)
MED_PRIORITY_STRINGS = [
    "/cgi-bin/micromsg-bin/mmsns",
    "SnsPost",
    "SnsObject",
    "SnsUpload",
    "snsId",
    "sns_id",
    "objId",
    "SnsTimeLine",
    "TimeLineData",
    "WCBizSns",
    "SnsDataMgr",
    "SnsService",
    "mmsnsweb",
]

# 低优先级 (辅助定位)
LOW_PRIORITY_STRINGS = [
    "comment",
    "replyTo",
    "reply_to",
    "OpLog",
    "oplog",
    "SnsObjectOp",
]

ALL_STRINGS = (
    [(s, "HIGH") for s in HIGH_PRIORITY_STRINGS] +
    [(s, "MED") for s in MED_PRIORITY_STRINGS] +
    [(s, "LOW") for s in LOW_PRIORITY_STRINGS]
)


def find_string_addresses(target_str):
    """在 IDB 的字符串表中搜索包含 target_str 的字符串地址。"""
    results = []
    # 搜索 ASCII
    addr = ida_bytes.bin_search(
        0, idaapi.BADADDR,
        target_str.encode("ascii"), None,
        ida_bytes.BIN_SEARCH_FORWARD | ida_bytes.BIN_SEARCH_NOCASE,
        0
    )
    while addr != idaapi.BADADDR:
        results.append(addr)
        addr = ida_bytes.bin_search(
            addr + 1, idaapi.BADADDR,
            target_str.encode("ascii"), None,
            ida_bytes.BIN_SEARCH_FORWARD | ida_bytes.BIN_SEARCH_NOCASE,
            0
        )

    # 搜索 UTF-16LE
    encoded = target_str.encode("utf-16-le")
    addr = ida_bytes.bin_search(
        0, idaapi.BADADDR,
        encoded, None,
        ida_bytes.BIN_SEARCH_FORWARD,
        0
    )
    while addr != idaapi.BADADDR:
        results.append(addr)
        addr = ida_bytes.bin_search(
            addr + 1, idaapi.BADADDR,
            encoded, None,
            ida_bytes.BIN_SEARCH_FORWARD,
            0
        )

    return results


def get_xrefs_to(addr):
    """获取地址的所有交叉引用。"""
    refs = []
    for xref in idautils.XrefsTo(addr, 0):
        refs.append(xref.frm)
    return refs


def get_function_at(addr):
    """获取包含给定地址的函数信息。"""
    func = ida_funcs.get_func(addr)
    if func:
        name = ida_name.get_name(func.start_ea)
        return {
            "start": func.start_ea,
            "end": func.end_ea,
            "name": name,
            "size": func.end_ea - func.start_ea,
        }
    return None


def get_callers(func_addr, depth=3):
    """递归获取函数的调用者, 最多 depth 层。"""
    if depth <= 0:
        return []
    callers = []
    for xref in idautils.XrefsTo(func_addr, 0):
        if xref.type in (ida_xref.fl_CN, ida_xref.fl_CF):  # call near/far
            func = get_function_at(xref.frm)
            if func:
                callers.append({
                    "call_site": xref.frm,
                    "function": func,
                    "depth": depth,
                    "parent_callers": get_callers(func["start"], depth - 1),
                })
    return callers


def extract_signature(func_addr, sig_len=30):
    """提取函数前 sig_len 字节作为特征码。"""
    bytes_data = ida_bytes.get_bytes(func_addr, sig_len)
    if not bytes_data:
        return ""
    hex_str = " ".join(f"{b:02X}" for b in bytes_data)
    return hex_str


def format_caller_tree(callers, indent=4):
    """格式化调用树输出。"""
    lines = []
    for c in callers:
        prefix = " " * indent
        func = c["function"]
        lines.append(
            f"{prefix}← {func['name']} @ {func['start']:#x} "
            f"(call site: {c['call_site']:#x}, size: {func['size']})"
        )
        if c["parent_callers"]:
            lines.extend(format_caller_tree(c["parent_callers"], indent + 4))
    return lines


# =========================================================================
# 主逻辑
# =========================================================================

def main():
    print("=" * 70)
    print("  pywechat SNS Function Finder for IDA Pro")
    print("=" * 70)
    print()

    image_base = idaapi.get_imagebase()
    print(f"Image base: {image_base:#x}")
    print()

    # 收集所有候选函数
    candidates = {}  # func_addr -> info

    for target_str, priority in ALL_STRINGS:
        addrs = find_string_addresses(target_str)
        if not addrs:
            continue

        print(f"[{priority}] String '{target_str}': {len(addrs)} matches")

        for str_addr in addrs[:5]:  # 每个字符串最多处理 5 个
            offset = str_addr - image_base
            print(f"  @ {str_addr:#x} (offset +{offset:#x})")

            xrefs = get_xrefs_to(str_addr)
            if not xrefs:
                # 数据引用: 搜索引用此数据的指令
                # (字符串地址可能被 LEA 指令引用)
                continue

            for xref_addr in xrefs[:10]:
                func = get_function_at(xref_addr)
                if not func:
                    continue

                func_key = func["start"]
                if func_key not in candidates:
                    candidates[func_key] = {
                        "function": func,
                        "strings": [],
                        "priority": priority,
                        "callers": get_callers(func["start"], depth=2),
                    }
                candidates[func_key]["strings"].append(target_str)

                # 升级优先级
                if priority == "HIGH":
                    candidates[func_key]["priority"] = "HIGH"
                elif priority == "MED" and candidates[func_key]["priority"] == "LOW":
                    candidates[func_key]["priority"] = "MED"

    # 输出候选函数
    print()
    print("=" * 70)
    print(f"  CANDIDATE FUNCTIONS ({len(candidates)} total)")
    print("=" * 70)
    print()

    # 按优先级排序
    priority_order = {"HIGH": 0, "MED": 1, "LOW": 2}
    sorted_candidates = sorted(
        candidates.values(),
        key=lambda c: (priority_order.get(c["priority"], 99), -len(c["strings"]))
    )

    for i, cand in enumerate(sorted_candidates[:30]):  # 最多输出 30 个
        func = cand["function"]
        offset = func["start"] - image_base
        sig = extract_signature(func["start"])

        print(f"[{i+1}] [{cand['priority']}] {func['name']}")
        print(f"    Address: {func['start']:#x} (offset +{offset:#x})")
        print(f"    Size:    {func['size']} bytes")
        print(f"    Strings: {', '.join(cand['strings'])}")
        print(f"    Sig:     {sig}")

        if cand["callers"]:
            print("    Call chain:")
            for line in format_caller_tree(cand["callers"]):
                print(line)
        print()

    # 特别标记: 最可能的评论函数
    high_candidates = [c for c in sorted_candidates if c["priority"] == "HIGH"]
    if high_candidates:
        print("=" * 70)
        print("  TOP CANDIDATES (HIGH priority - likely comment-related)")
        print("=" * 70)
        for cand in high_candidates:
            func = cand["function"]
            offset = func["start"] - image_base
            print(f"  >>> {func['name']} @ +{offset:#x}  strings: {cand['strings']}")
        print()
        print("  Next step: 在 x64dbg 中对这些函数设断点,")
        print("  手动发评论观察是否命中, 分析参数。")
    else:
        print("  No HIGH priority candidates found.")
        print("  Try the MED priority candidates, or use Frida dynamic tracing.")

    print()
    print("Done.")


if __name__ == "__main__":
    main()
