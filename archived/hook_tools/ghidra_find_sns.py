"""
Ghidra 脚本 —— 在 WeChatWin.dll 中定位 SNS 评论相关函数。

使用方法:
    1. Ghidra 加载 WeChatWin.dll, 完成自动分析
    2. Script Manager -> Run Script -> 选择本文件
    3. 查看 Console 输出

等效于 ida_find_sns.py, 但使用 Ghidra 的 API。
需要通过 Ghidra 的 Script Manager 运行 (Jython 环境)。
"""

# Ghidra imports (在 Ghidra Script Manager 中自动可用)
# @category pywechat
# @description Find SNS comment functions in WeChatWin.dll

from ghidra.program.model.mem import MemoryAccessException
from ghidra.program.util import DefinedDataIterator
from ghidra.app.util.bin.format.pe import PortableExecutable

import re


# =========================================================================
# 关键字配置
# =========================================================================

HIGH_PRIORITY = [
    "SnsComment", "sns_comment", "AddComment", "DoComment",
    "PublishComment", "CreateComment", "addcomment",
    "/cgi-bin/micromsg-bin/mmsnscomment",
    "MMSnsComment", "SnsCommentRequest",
]

MED_PRIORITY = [
    "/cgi-bin/micromsg-bin/mmsns",
    "SnsPost", "SnsObject", "snsId", "sns_id",
    "SnsTimeLine", "SnsDataMgr", "SnsService",
]


def search_strings(memory, addr_set, keyword):
    """在程序内存中搜索字符串。"""
    results = []
    pattern = keyword.encode("ascii")
    addr = memory.findBytes(addr_set.getMinAddress(), pattern, None, True, monitor)
    while addr is not None and addr_set.contains(addr):
        results.append(addr)
        next_addr = addr.add(1)
        if not addr_set.contains(next_addr):
            break
        addr = memory.findBytes(next_addr, pattern, None, True, monitor)
    return results


def get_references_to(addr):
    """获取对给定地址的所有引用。"""
    refs = []
    ref_mgr = currentProgram.getReferenceManager()
    ref_iter = ref_mgr.getReferencesTo(addr)
    while ref_iter.hasNext():
        ref = ref_iter.next()
        refs.append(ref.getFromAddress())
    return refs


def get_function_containing(addr):
    """获取包含给定地址的函数。"""
    func_mgr = currentProgram.getFunctionManager()
    return func_mgr.getFunctionContaining(addr)


def get_callers(func, depth=2):
    """获取函数的调用者链。"""
    if depth <= 0 or func is None:
        return []
    callers = []
    entry = func.getEntryPoint()
    for ref_addr in get_references_to(entry):
        caller_func = get_function_containing(ref_addr)
        if caller_func and caller_func != func:
            callers.append({
                "call_site": ref_addr,
                "function": caller_func,
                "parent_callers": get_callers(caller_func, depth - 1),
            })
    return callers


def get_signature_bytes(addr, length=30):
    """读取地址处的字节作为特征码。"""
    try:
        mem = currentProgram.getMemory()
        buf = bytearray(length)
        mem.getBytes(addr, buf)
        return " ".join("%02X" % (b & 0xFF) for b in buf)
    except MemoryAccessException:
        return "<read error>"


# =========================================================================
# 主逻辑
# =========================================================================

def main():
    println("=" * 60)
    println("  pywechat SNS Function Finder for Ghidra")
    println("=" * 60)

    memory = currentProgram.getMemory()
    addr_set = memory.getLoadedAndInitializedAddressSet()
    image_base = currentProgram.getImageBase()

    println("Image base: %s" % image_base)
    println("")

    candidates = {}  # entry_addr_str -> info

    all_keywords = (
        [(kw, "HIGH") for kw in HIGH_PRIORITY] +
        [(kw, "MED") for kw in MED_PRIORITY]
    )

    for keyword, priority in all_keywords:
        addrs = search_strings(memory, addr_set, keyword)
        if not addrs:
            continue

        println("[%s] '%s': %d matches" % (priority, keyword, len(addrs)))

        for str_addr in addrs[:5]:
            offset = str_addr.subtract(image_base)
            println("  @ %s (+0x%X)" % (str_addr, offset))

            refs = get_references_to(str_addr)
            for ref_addr in refs[:10]:
                func = get_function_containing(ref_addr)
                if not func:
                    continue

                key = func.getEntryPoint().toString()
                if key not in candidates:
                    candidates[key] = {
                        "function": func,
                        "strings": [],
                        "priority": priority,
                        "callers": get_callers(func, depth=2),
                    }
                candidates[key]["strings"].append(keyword)
                if priority == "HIGH":
                    candidates[key]["priority"] = "HIGH"

    # 输出结果
    println("")
    println("=" * 60)
    println("  CANDIDATES (%d functions)" % len(candidates))
    println("=" * 60)
    println("")

    priority_order = {"HIGH": 0, "MED": 1, "LOW": 2}
    sorted_cands = sorted(
        candidates.values(),
        key=lambda c: (priority_order.get(c["priority"], 99), -len(c["strings"]))
    )

    for i, cand in enumerate(sorted_cands[:20]):
        func = cand["function"]
        entry = func.getEntryPoint()
        offset = entry.subtract(image_base)
        sig = get_signature_bytes(entry)

        println("[%d] [%s] %s" % (i + 1, cand["priority"], func.getName()))
        println("    Address: %s (+0x%X)" % (entry, offset))
        println("    Size:    %d bytes" % func.getBody().getNumAddresses())
        println("    Strings: %s" % ", ".join(cand["strings"]))
        println("    Sig:     %s" % sig)

        for caller in cand["callers"][:3]:
            cf = caller["function"]
            println("    <- %s @ %s" % (cf.getName(), caller["call_site"]))
        println("")

    # 高优先级总结
    high = [c for c in sorted_cands if c["priority"] == "HIGH"]
    if high:
        println(">>> TOP CANDIDATES:")
        for c in high:
            func = c["function"]
            offset = func.getEntryPoint().subtract(image_base)
            println("    %s @ +0x%X  [%s]" % (
                func.getName(), offset, ", ".join(c["strings"])))

    println("\nDone.")


main()
