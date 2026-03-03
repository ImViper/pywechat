"""
特征码迁移工具 —— 从 wxhelper 3.9.x 已知偏移提取特征码，在 4.0 DLL 中搜索。

原理:
    wxhelper 已知 3.9.x 版本中 SNS 函数的偏移量。虽然 4.0 偏移会变化，
    但函数的机器码 (function prologue) 往往有一定的相似性。
    本工具从旧版 DLL 提取函数入口的字节特征，在新版 DLL 中搜索匹配。

使用方法:
    python sig_migrate.py --old <3.9.x WeChatWin.dll> --new <4.0.x WeChatWin.dll>
    python sig_migrate.py --new <4.0.x WeChatWin.dll>  # 只扫描新 DLL (用内置特征)

提示:
    - 旧版 WeChatWin.dll 可从微信安装包历史版本获取
    - 新版 DLL 从当前微信安装目录获取
    - 特征码匹配是概率性的，需要手动验证候选结果
"""

from __future__ import annotations

import argparse
import os
import re
import struct
import sys
from dataclasses import dataclass, field
from typing import Optional


# =========================================================================
# wxhelper 已知偏移 (3.9.x 版本)
# =========================================================================

@dataclass
class KnownOffset:
    name: str
    version: str
    offset: int
    description: str = ""


WXHELPER_OFFSETS = [
    # 3.9.5.81 (64-bit)
    KnownOffset("kSNSDataMgr",          "3.9.5.81", 0xeebda0,  "SNS 数据管理器全局函数"),
    KnownOffset("kSNSGetFirstPage",     "3.9.5.81", 0x1a51dd0, "获取朋友圈首页"),
    KnownOffset("kSNSGetNextPageScene", "3.9.5.81", 0x1a77240, "获取朋友圈下一页"),
    KnownOffset("kSNSTimeLineMgr",      "3.9.5.81", 0x19e83a0, "时间线管理器"),
    KnownOffset("kGetMgrByPrefixLocalId","3.9.5.81", 0xe4add0, "按 LocalId 获取管理器"),
    KnownOffset("kOnSnsTimeLineSceneFinish", "3.9.5.81", 0x1a73150, "时间线场景完成回调"),

    # 3.9.11.25 (64-bit, 大偏移)
    KnownOffset("kSNSDataMgr",          "3.9.11.25", 0x21dd6b0, "SNS 数据管理器"),
    KnownOffset("kSNSGetFirstPage",     "3.9.11.25", 0x2e1bec0, "获取朋友圈首页"),
    KnownOffset("kSNSGetNextPageScene", "3.9.11.25", 0x2e41a70, "获取朋友圈下一页"),
    KnownOffset("kSNSTimeLineMgr",      "3.9.11.25", 0x2dadf20, "时间线管理器"),
    KnownOffset("kGetMgrByPrefixLocalId","3.9.11.25", 0x213afb0, "按 LocalId 获取管理器"),
]


# =========================================================================
# PE 文件解析 (最小化, 不依赖第三方库)
# =========================================================================

def parse_pe_sections(data: bytes) -> list[dict]:
    """解析 PE 文件的 section 表。"""
    if data[:2] != b"MZ":
        raise ValueError("Not a PE file")
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if data[e_lfanew:e_lfanew+4] != b"PE\x00\x00":
        raise ValueError("Invalid PE signature")

    # COFF header
    coff_offset = e_lfanew + 4
    machine = struct.unpack_from("<H", data, coff_offset)[0]
    num_sections = struct.unpack_from("<H", data, coff_offset + 2)[0]
    size_of_opt = struct.unpack_from("<H", data, coff_offset + 16)[0]

    # Optional header
    opt_offset = coff_offset + 20
    magic = struct.unpack_from("<H", data, opt_offset)[0]
    is_64 = (magic == 0x20b)

    if is_64:
        image_base = struct.unpack_from("<Q", data, opt_offset + 24)[0]
    else:
        image_base = struct.unpack_from("<I", data, opt_offset + 28)[0]

    # Section table
    section_offset = opt_offset + size_of_opt
    sections = []
    for i in range(num_sections):
        off = section_offset + i * 40
        name = data[off:off+8].rstrip(b"\x00").decode("ascii", errors="replace")
        virtual_size = struct.unpack_from("<I", data, off + 8)[0]
        virtual_addr = struct.unpack_from("<I", data, off + 12)[0]
        raw_size = struct.unpack_from("<I", data, off + 16)[0]
        raw_offset = struct.unpack_from("<I", data, off + 20)[0]
        characteristics = struct.unpack_from("<I", data, off + 36)[0]
        sections.append({
            "name": name,
            "virtual_size": virtual_size,
            "virtual_addr": virtual_addr,
            "raw_size": raw_size,
            "raw_offset": raw_offset,
            "characteristics": characteristics,
            "is_code": bool(characteristics & 0x20),  # IMAGE_SCN_CNT_CODE
        })

    return sections


def rva_to_file_offset(sections: list[dict], rva: int) -> int | None:
    """将 RVA 转为文件偏移。"""
    for sec in sections:
        if sec["virtual_addr"] <= rva < sec["virtual_addr"] + sec["raw_size"]:
            return sec["raw_offset"] + (rva - sec["virtual_addr"])
    return None


# =========================================================================
# 特征码提取和搜索
# =========================================================================

def extract_signature(data: bytes, file_offset: int, length: int = 32,
                      wildcard_relative: bool = True) -> str:
    """从文件偏移处提取特征码。

    Args:
        data: PE 文件全部字节
        file_offset: 文件偏移
        length: 提取长度
        wildcard_relative: 是否将可能的相对偏移替换为通配符
    """
    if file_offset + length > len(data):
        return ""
    raw = data[file_offset:file_offset + length]
    # 基础特征: 全部字节
    parts = [f"{b:02X}" for b in raw]

    if wildcard_relative:
        # x64 常见: CALL rel32 / JMP rel32 在 E8/E9 后有 4 字节相对偏移
        # LEA 等在 48 8D xx 后有 4 字节 rip-relative offset
        # 将这些替换为通配符以提高跨版本匹配率
        i = 0
        while i < length:
            b = raw[i]
            if b in (0xE8, 0xE9) and i + 5 <= length:
                # CALL/JMP rel32: 操作码保留, 4字节偏移通配
                parts[i+1] = "??"
                parts[i+2] = "??"
                parts[i+3] = "??"
                parts[i+4] = "??"
                i += 5
                continue
            i += 1

    return " ".join(parts)


def search_pattern(data: bytes, pattern: str, code_sections: list[dict] | None = None) -> list[int]:
    """在数据中搜索特征码, 返回文件偏移列表。"""
    parts = pattern.split()
    pat_bytes = []
    pat_mask = []
    for p in parts:
        if p == "??":
            pat_bytes.append(0)
            pat_mask.append(False)
        else:
            pat_bytes.append(int(p, 16))
            pat_mask.append(True)

    pat_len = len(pat_bytes)
    results = []

    # 搜索范围
    if code_sections:
        ranges = [(s["raw_offset"], s["raw_offset"] + s["raw_size"]) for s in code_sections]
    else:
        ranges = [(0, len(data))]

    for start, end in ranges:
        for i in range(start, min(end, len(data)) - pat_len):
            match = True
            for j in range(pat_len):
                if pat_mask[j] and data[i + j] != pat_bytes[j]:
                    match = False
                    break
            if match:
                results.append(i)

    return results


def file_offset_to_rva(sections: list[dict], file_offset: int) -> int | None:
    """将文件偏移转为 RVA。"""
    for sec in sections:
        if sec["raw_offset"] <= file_offset < sec["raw_offset"] + sec["raw_size"]:
            return sec["virtual_addr"] + (file_offset - sec["raw_offset"])
    return None


# =========================================================================
# 主逻辑
# =========================================================================

def migrate_signatures(old_path: str | None, new_path: str, sig_length: int = 32):
    """从旧版 DLL 提取特征, 在新版 DLL 中搜索。"""
    print(f"Loading new DLL: {new_path}")
    with open(new_path, "rb") as f:
        new_data = f.read()
    new_sections = parse_pe_sections(new_data)
    new_code_sections = [s for s in new_sections if s["is_code"]]

    print(f"  Size: {len(new_data):,} bytes")
    print(f"  Code sections: {[s['name'] for s in new_code_sections]}")
    print()

    signatures: list[tuple[str, str, str]] = []  # (name, version, pattern)

    if old_path:
        print(f"Loading old DLL: {old_path}")
        with open(old_path, "rb") as f:
            old_data = f.read()
        old_sections = parse_pe_sections(old_data)
        print(f"  Size: {len(old_data):,} bytes")
        print()

        # 从旧版 DLL 提取特征码
        for known in WXHELPER_OFFSETS:
            fo = rva_to_file_offset(old_sections, known.offset)
            if fo is None:
                print(f"  [{known.name} ({known.version})] RVA {known.offset:#x} -> file offset not found")
                continue

            sig = extract_signature(old_data, fo, sig_length, wildcard_relative=True)
            if not sig:
                continue

            print(f"  [{known.name} ({known.version})] RVA {known.offset:#x} -> file {fo:#x}")
            print(f"    Sig: {sig}")
            signatures.append((known.name, known.version, sig))
    else:
        print("No old DLL specified, using built-in prologue patterns")
        print()

    # 内置的常见 x64 函数序言模式 (通用搜索)
    # 这些是 MSVC 编译的 x64 函数常见开头
    builtin_patterns = [
        # 典型的 x64 函数序言 + SNS 相关操作模式
        ("prologue_push_rbx_sub_rsp", "generic",
         "48 89 5C 24 ?? 48 89 74 24 ?? 57 48 83 EC"),
        ("prologue_push_rbx_push_rsi", "generic",
         "40 53 56 57 48 83 EC"),
        ("prologue_mov_rsp_sub", "generic",
         "48 8B C4 48 89 58 ?? 48 89 68 ?? 48 89 70"),
    ]

    # 在新 DLL 中搜索
    print()
    print("=" * 70)
    print("  Searching in new DLL")
    print("=" * 70)
    print()

    all_sigs = signatures + builtin_patterns
    total_matches = 0

    for name, version, pattern in all_sigs:
        matches = search_pattern(new_data, pattern, new_code_sections)
        total_matches += len(matches)

        if not matches:
            print(f"  [{name} ({version})] No matches")
            continue

        print(f"  [{name} ({version})] {len(matches)} matches:")
        for fo in matches[:10]:
            rva = file_offset_to_rva(new_sections, fo)
            if rva is not None:
                # 读取匹配处前后的字节用于人工确认
                context = new_data[fo:fo+48]
                hex_context = " ".join(f"{b:02X}" for b in context[:48])
                print(f"    RVA {rva:#010x}  file {fo:#010x}  {hex_context}")

        if len(matches) > 10:
            print(f"    ... and {len(matches) - 10} more")
        print()

    print(f"Total matches across all patterns: {total_matches}")
    print()

    if signatures:
        print("=" * 70)
        print("  NEXT STEPS")
        print("=" * 70)
        print()
        print("  1. 如果某个已知函数只有 1-3 个匹配，很可能就是目标")
        print("  2. 对匹配地址用 IDA/Ghidra 打开新 DLL 进行确认")
        print("  3. 或用 Frida --hook 0x<RVA> 动态验证")
        print("  4. 特征码匹配不到时，尝试缩短 sig_length 或去掉更多通配符")
    else:
        print("  提示: 提供 --old 参数指定旧版 WeChatWin.dll 可获得更精确的搜索")


def main():
    parser = argparse.ArgumentParser(
        description="wxhelper 特征码迁移工具 - 从 3.9.x 定位 4.0 函数"
    )
    parser.add_argument("--old", help="旧版 WeChatWin.dll 路径 (3.9.x)")
    parser.add_argument("--new", required=True, help="新版 WeChatWin.dll 路径 (4.0.x)")
    parser.add_argument("--sig-length", type=int, default=32,
                        help="特征码提取长度 (默认 32 字节)")
    args = parser.parse_args()

    if args.old and not os.path.isfile(args.old):
        print(f"Old DLL not found: {args.old}")
        sys.exit(1)
    if not os.path.isfile(args.new):
        print(f"New DLL not found: {args.new}")
        sys.exit(1)

    migrate_signatures(args.old, args.new, args.sig_length)


if __name__ == "__main__":
    main()
