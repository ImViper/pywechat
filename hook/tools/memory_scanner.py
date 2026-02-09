"""
Viper Memory Scanner (Enhanced) -- 扫描 WeChatWin.dll 定位 SNS 评论函数。

增强功能:
    - ASCII + UTF-16LE 字符串搜索
    - 函数序言 (prologue) 检测: 在字符串引用附近搜索代码模式
    - Protobuf .proto 字段名检测
    - PE section 解析, 区分代码段/数据段
    - 导出的地址引用分析 (简易 xref)
    - CGI 路径提取 (微信网络请求路径)

使用方法:
    python memory_scanner.py [--dll-path PATH] [--keyword KW] [--find-prologues] [--find-protos]

如果 --dll-path 未指定，自动从运行中的微信进程定位。
"""

from __future__ import annotations

import argparse
import os
import re
import struct
import sys
from collections import defaultdict


def find_wechatwin_dll() -> str | None:
    """Auto-locate WeChatWin.dll from the running WeChat process."""
    try:
        import psutil
    except ImportError:
        print("psutil not installed, please specify --dll-path manually")
        return None

    for proc in psutil.process_iter(["pid", "name", "cmdline"]):
        if proc.info["name"] != "Weixin.exe":
            continue
        cmdline = proc.info.get("cmdline") or []
        if any("--type" in arg for arg in cmdline):
            continue
        try:
            for m in proc.memory_maps():
                if "WeChatWin.dll" in m.path:
                    return m.path
        except Exception:
            pass
    return None


# =========================================================================
# PE 解析
# =========================================================================

def parse_pe(data: bytes) -> dict:
    """解析 PE 文件基础信息和 section 表。"""
    if data[:2] != b"MZ":
        raise ValueError("Not a PE file")
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if data[e_lfanew:e_lfanew+4] != b"PE\x00\x00":
        raise ValueError("Invalid PE signature")

    coff_offset = e_lfanew + 4
    machine = struct.unpack_from("<H", data, coff_offset)[0]
    num_sections = struct.unpack_from("<H", data, coff_offset + 2)[0]
    size_of_opt = struct.unpack_from("<H", data, coff_offset + 16)[0]

    opt_offset = coff_offset + 20
    magic = struct.unpack_from("<H", data, opt_offset)[0]
    is_64 = (magic == 0x20b)

    if is_64:
        image_base = struct.unpack_from("<Q", data, opt_offset + 24)[0]
    else:
        image_base = struct.unpack_from("<I", data, opt_offset + 28)[0]

    section_offset = opt_offset + size_of_opt
    sections = []
    for i in range(num_sections):
        off = section_offset + i * 40
        name = data[off:off+8].rstrip(b"\x00").decode("ascii", errors="replace")
        virtual_size = struct.unpack_from("<I", data, off + 8)[0]
        virtual_addr = struct.unpack_from("<I", data, off + 12)[0]
        raw_size = struct.unpack_from("<I", data, off + 16)[0]
        raw_offset = struct.unpack_from("<I", data, off + 20)[0]
        chars = struct.unpack_from("<I", data, off + 36)[0]
        sections.append({
            "name": name, "virtual_size": virtual_size,
            "virtual_addr": virtual_addr, "raw_size": raw_size,
            "raw_offset": raw_offset, "characteristics": chars,
            "is_code": bool(chars & 0x20),
            "is_data": bool(chars & 0x40),
        })

    return {
        "is_64": is_64, "machine": machine, "image_base": image_base,
        "sections": sections,
    }


def file_offset_to_rva(sections: list[dict], fo: int) -> int | None:
    for s in sections:
        if s["raw_offset"] <= fo < s["raw_offset"] + s["raw_size"]:
            return s["virtual_addr"] + (fo - s["raw_offset"])
    return None


def rva_to_file_offset(sections: list[dict], rva: int) -> int | None:
    for s in sections:
        if s["virtual_addr"] <= rva < s["virtual_addr"] + s["raw_size"]:
            return s["raw_offset"] + (rva - s["virtual_addr"])
    return None


# =========================================================================
# 字符串扫描
# =========================================================================

SNS_KEYWORDS = [
    "SnsComment", "sns_comment", "SnsPost", "SnsObject", "SnsUpload",
    "MMSnsComment", "MMSnsPost", "AddComment", "DoComment",
    "CreateComment", "PublishComment", "comment",
    "snsId", "sns_id", "objId", "replyTo", "reply_to",
    "SnsTimeLine", "TimeLineData", "WCBizSns",
    "/cgi-bin/micromsg-bin/mmsns",
    "SnsDataMgr", "SnsService", "SnsCommentRequest",
]


def scan_ascii_strings(data: bytes, min_length: int = 6) -> list[tuple[int, str]]:
    """提取 ASCII 字符串。"""
    results = []
    pattern = re.compile(rb"[\x20-\x7e]{%d,}" % min_length)
    for m in pattern.finditer(data):
        results.append((m.start(), m.group().decode("ascii", errors="replace")))
    return results


def scan_utf16_strings(data: bytes, min_chars: int = 4) -> list[tuple[int, str]]:
    """提取 UTF-16LE 字符串。"""
    results = []
    # 匹配至少 min_chars 个 UTF-16 字符 (2 bytes each)
    pattern = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % min_chars)
    for m in pattern.finditer(data):
        try:
            decoded = m.group().decode("utf-16-le", errors="ignore")
            if decoded.strip():
                results.append((m.start(), decoded))
        except Exception:
            pass
    return results


def filter_by_keywords(strings: list[tuple[int, str]], keywords: list[str]
                       ) -> list[tuple[int, str, str]]:
    """按关键字过滤字符串。"""
    kw_lower = [k.lower() for k in keywords]
    results = []
    for offset, s in strings:
        s_lower = s.lower()
        for kw in kw_lower:
            if kw in s_lower:
                results.append((offset, s, kw))
                break
    return results


# =========================================================================
# 函数序言检测
# =========================================================================

# 常见 x64 MSVC 函数序言模式
X64_PROLOGUES = [
    # sub rsp, imm8
    (b"\x48\x83\xEC", "sub rsp, imm8"),
    # push rbx; sub rsp
    (b"\x40\x53\x48\x83\xEC", "push rbx; sub rsp"),
    # mov [rsp+XX], rbx  (常见的 home 参数保存)
    (b"\x48\x89\x5C\x24", "mov [rsp+XX], rbx"),
    # push rbp; mov rbp, rsp
    (b"\x55\x48\x8B\xEC", "push rbp; mov rbp, rsp"),
    # push rdi
    (b"\x57\x48\x83\xEC", "push rdi; sub rsp"),
    # mov rax, rsp (保存 rsp)
    (b"\x48\x8B\xC4", "mov rax, rsp"),
]


def find_nearby_prologues(data: bytes, target_offset: int,
                          search_range: int = 4096) -> list[dict]:
    """在目标地址附近搜索函数序言。"""
    results = []
    start = max(0, target_offset - search_range)
    end = min(len(data), target_offset + search_range)
    region = data[start:end]

    for pattern, desc in X64_PROLOGUES:
        pos = 0
        while True:
            idx = region.find(pattern, pos)
            if idx == -1:
                break
            abs_offset = start + idx
            distance = abs_offset - target_offset
            # 读取完整的序言字节
            prologue_bytes = data[abs_offset:abs_offset + 16]
            hex_str = " ".join(f"{b:02X}" for b in prologue_bytes)
            results.append({
                "file_offset": abs_offset,
                "distance": distance,
                "pattern": desc,
                "bytes": hex_str,
            })
            pos = idx + 1

    # 按距离排序
    results.sort(key=lambda r: abs(r["distance"]))
    return results


# =========================================================================
# Protobuf 字段名检测
# =========================================================================

PROTO_FIELD_PATTERNS = [
    # protobuf 序列化中的字段名 (通常在 .proto reflection 信息中)
    re.compile(rb"(sns[_.](?:comment|post|object|id|like|data|timeline)[\w.]*)", re.IGNORECASE),
    re.compile(rb"(comment[_.](?:content|text|reply|author|id)[\w.]*)", re.IGNORECASE),
    re.compile(rb"(MM(?:Sns|SNS)\w+)", re.IGNORECASE),
]


def find_proto_fields(data: bytes) -> list[tuple[int, str]]:
    """在二进制中搜索 protobuf 字段名模式。"""
    results = []
    for pat in PROTO_FIELD_PATTERNS:
        for m in pat.finditer(data):
            try:
                text = m.group(1).decode("ascii", errors="ignore")
                results.append((m.start(), text))
            except Exception:
                pass
    return results


# =========================================================================
# CGI 路径提取
# =========================================================================

def find_cgi_paths(data: bytes) -> list[tuple[int, str]]:
    """提取微信 CGI 请求路径。"""
    results = []
    pattern = re.compile(rb"/cgi-bin/[\w/-]+")
    for m in pattern.finditer(data):
        path = m.group().decode("ascii", errors="ignore")
        results.append((m.start(), path))
    return results


# =========================================================================
# 简易地址引用搜索
# =========================================================================

def find_address_references(data: bytes, target_rva: int, pe_info: dict,
                            search_sections: list[dict] | None = None
                            ) -> list[int]:
    """在代码段中搜索引用目标 RVA 的 LEA/MOV 指令。

    x64 中字符串通常通过 RIP-relative LEA 引用:
        LEA reg, [rip + disp32]
    我们搜索 disp32 值等于 (target_rva - (current_rva + 7)) 的位置。
    """
    results = []
    sections = search_sections or [s for s in pe_info["sections"] if s["is_code"]]

    for sec in sections:
        sec_data = data[sec["raw_offset"]:sec["raw_offset"] + sec["raw_size"]]
        for i in range(len(sec_data) - 7):
            # LEA 指令 (48 8D xx): opcode varies, check displacement
            # 简化: 搜索任何 4 字节值，看是否指向 target
            if i + 7 > len(sec_data):
                break
            # 读取当前位置 +3 处的 4 字节 (LEA reg, [rip + disp32] 的 disp)
            for instr_len in (3, 4, 7):  # 不同指令长度
                if i + instr_len + 4 > len(sec_data):
                    continue
                disp = struct.unpack_from("<i", sec_data, i + instr_len)[0]
                current_rva = sec["virtual_addr"] + i
                # RIP-relative: target = rip + disp, where rip = current + total_instr_len
                total_len = instr_len + 4
                effective = current_rva + total_len + disp
                if effective == target_rva:
                    results.append(sec["virtual_addr"] + i)
                    break

    return results


# =========================================================================
# 主逻辑
# =========================================================================

def scan_dll(dll_path: str, keywords: list[str] | None = None,
             find_prologues: bool = False, find_protos: bool = False,
             find_cgis: bool = False) -> None:
    keywords = keywords or SNS_KEYWORDS

    if not os.path.isfile(dll_path):
        print(f"File not found: {dll_path}")
        sys.exit(1)

    file_size = os.path.getsize(dll_path)
    print(f"Scanning: {dll_path}")
    print(f"File size: {file_size:,} bytes ({file_size / 1024 / 1024:.1f} MB)")

    with open(dll_path, "rb") as f:
        data = f.read()

    pe = parse_pe(data)
    print(f"Architecture: {'x64' if pe['is_64'] else 'x86'}")
    print(f"Image base: {pe['image_base']:#x}")
    print(f"Sections: {len(pe['sections'])}")
    for sec in pe["sections"]:
        flags = []
        if sec["is_code"]: flags.append("CODE")
        if sec["is_data"]: flags.append("DATA")
        print(f"  {sec['name']:8s}  VA={sec['virtual_addr']:#010x}  "
              f"size={sec['raw_size']:#010x}  {','.join(flags)}")
    print()

    # --- ASCII strings ---
    print("=" * 70)
    print("  ASCII String Search")
    print("=" * 70)
    ascii_strings = scan_ascii_strings(data)
    print(f"Total ASCII strings: {len(ascii_strings):,}")

    matches = filter_by_keywords(ascii_strings, keywords)
    if matches:
        print(f"SNS/Comment matches: {len(matches)}")
        print("-" * 70)
        for offset, s, kw in matches:
            rva = file_offset_to_rva(pe["sections"], offset)
            rva_str = f"RVA={rva:#010x}" if rva else "RVA=?"
            display = s if len(s) <= 80 else s[:80] + "..."
            print(f"  0x{offset:08X}  {rva_str}  [{kw}]  {display}")

            # 如果启用了 prologue 搜索, 在字符串附近查找函数入口
            if find_prologues and rva:
                prologues = find_nearby_prologues(data, offset, search_range=8192)
                if prologues:
                    print(f"    Nearby function prologues ({len(prologues)} found):")
                    for p in prologues[:5]:
                        p_rva = file_offset_to_rva(pe["sections"], p["file_offset"])
                        p_rva_str = f"RVA={p_rva:#010x}" if p_rva else ""
                        print(f"      {p['distance']:+6d} bytes  "
                              f"0x{p['file_offset']:08X}  {p_rva_str}  "
                              f"{p['pattern']}  [{p['bytes']}]")
    else:
        print("No SNS/Comment ASCII strings found.")

    # --- UTF-16 strings ---
    print()
    print("=" * 70)
    print("  UTF-16LE String Search")
    print("=" * 70)
    utf16_strings = scan_utf16_strings(data)
    print(f"Total UTF-16 strings: {len(utf16_strings):,}")

    # 中文评论相关关键字
    cn_keywords = ["评论", "朋友圈", "发送评论", "回复", "SNS"]
    cn_matches = []
    for offset, s in utf16_strings:
        for kw in cn_keywords:
            if kw in s:
                cn_matches.append((offset, s, kw))
                break
    # 也检查英文关键字
    en_utf16_matches = filter_by_keywords(utf16_strings, keywords)

    all_utf16 = cn_matches + en_utf16_matches
    if all_utf16:
        print(f"Matches: {len(all_utf16)}")
        for offset, s, kw in all_utf16[:30]:
            rva = file_offset_to_rva(pe["sections"], offset)
            rva_str = f"RVA={rva:#010x}" if rva else "RVA=?"
            display = s if len(s) <= 60 else s[:60] + "..."
            print(f"  0x{offset:08X}  {rva_str}  [{kw}]  {display!r}")

    # --- CGI paths ---
    if find_cgis:
        print()
        print("=" * 70)
        print("  CGI Path Extraction")
        print("=" * 70)
        cgis = find_cgi_paths(data)
        # SNS 相关的 CGI
        sns_cgis = [(o, p) for o, p in cgis if "sns" in p.lower()]
        print(f"Total CGI paths: {len(cgis)},  SNS-related: {len(sns_cgis)}")
        for offset, path in sns_cgis:
            rva = file_offset_to_rva(pe["sections"], offset)
            rva_str = f"RVA={rva:#010x}" if rva else ""
            print(f"  0x{offset:08X}  {rva_str}  {path}")

    # --- Protobuf field detection ---
    if find_protos:
        print()
        print("=" * 70)
        print("  Protobuf Field Detection")
        print("=" * 70)
        proto_fields = find_proto_fields(data)
        if proto_fields:
            # 去重
            seen = set()
            unique = []
            for offset, field_name in proto_fields:
                if field_name not in seen:
                    seen.add(field_name)
                    unique.append((offset, field_name))

            print(f"Unique proto-like field names: {len(unique)}")
            for offset, field_name in unique[:50]:
                rva = file_offset_to_rva(pe["sections"], offset)
                rva_str = f"RVA={rva:#010x}" if rva else ""
                print(f"  0x{offset:08X}  {rva_str}  {field_name}")
        else:
            print("No protobuf field names detected.")

    print()
    print("Done.")


def main():
    parser = argparse.ArgumentParser(
        description="Enhanced WeChatWin.dll scanner for SNS comment function discovery"
    )
    parser.add_argument("--dll-path", help="Path to WeChatWin.dll")
    parser.add_argument("--keyword", action="append", help="Additional keyword")
    parser.add_argument("--find-prologues", action="store_true",
                        help="Search for function prologues near matched strings")
    parser.add_argument("--find-protos", action="store_true",
                        help="Detect protobuf field names")
    parser.add_argument("--find-cgis", action="store_true",
                        help="Extract CGI request paths")
    parser.add_argument("--all", action="store_true",
                        help="Enable all analysis features")
    args = parser.parse_args()

    dll_path = args.dll_path
    if not dll_path:
        dll_path = find_wechatwin_dll()
        if not dll_path:
            print("Cannot auto-locate WeChatWin.dll. Specify --dll-path.")
            sys.exit(1)

    keywords = list(SNS_KEYWORDS)
    if args.keyword:
        keywords.extend(args.keyword)

    scan_dll(
        dll_path, keywords,
        find_prologues=args.find_prologues or args.all,
        find_protos=args.find_protos or args.all,
        find_cgis=args.find_cgis or args.all,
    )


if __name__ == "__main__":
    main()
