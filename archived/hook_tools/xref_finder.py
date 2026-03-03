"""
x64 PE Cross-Reference Finder — 定位引用已知字符串的函数

工作原理:
  1. 解析 PE 头, 获取所有 section 信息
  2. 对于目标字符串 (如 "SnsCommentRequest"), 先扫描整个 DLL 找到字符串 RVA
  3. 在可执行 section (.text) 中扫描 RIP-relative 引用 (LEA, MOV, CMP 等)
  4. 对每个命中点, 向前搜索函数开头 (常见 prologue)
  5. 输出候选函数列表

用法:
  python xref_finder.py "C:\\...\\Weixin.dll"
  python xref_finder.py "C:\\...\\Weixin.dll" --target "SnsCommentRequest"
  python xref_finder.py "C:\\...\\Weixin.dll" --rva 0x0857ed68
"""

import argparse
import mmap
import os
import struct
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path


# ---- PE 解析 ----

@dataclass
class PESection:
    name: str
    virtual_address: int  # RVA
    virtual_size: int
    raw_offset: int       # file offset
    raw_size: int
    characteristics: int

    @property
    def is_executable(self) -> bool:
        return bool(self.characteristics & 0x20000000)  # IMAGE_SCN_MEM_EXECUTE

    @property
    def is_writable(self) -> bool:
        return bool(self.characteristics & 0x80000000)  # IMAGE_SCN_MEM_WRITE


@dataclass
class PEInfo:
    image_base: int
    sections: list
    size_of_image: int


def parse_pe(data: bytes) -> PEInfo:
    """Minimal PE64 parser."""
    if data[:2] != b'MZ':
        raise ValueError("Not a valid PE file")

    pe_offset = struct.unpack_from('<I', data, 0x3C)[0]
    if data[pe_offset:pe_offset+4] != b'PE\x00\x00':
        raise ValueError("Invalid PE signature")

    # COFF header
    machine = struct.unpack_from('<H', data, pe_offset + 4)[0]
    num_sections = struct.unpack_from('<H', data, pe_offset + 6)[0]
    optional_hdr_size = struct.unpack_from('<H', data, pe_offset + 20)[0]

    opt_offset = pe_offset + 24
    magic = struct.unpack_from('<H', data, opt_offset)[0]

    if magic == 0x20B:  # PE32+
        image_base = struct.unpack_from('<Q', data, opt_offset + 24)[0]
        size_of_image = struct.unpack_from('<I', data, opt_offset + 56)[0]
    elif magic == 0x10B:  # PE32
        image_base = struct.unpack_from('<I', data, opt_offset + 28)[0]
        size_of_image = struct.unpack_from('<I', data, opt_offset + 56)[0]
    else:
        raise ValueError(f"Unknown PE optional header magic: {magic:#x}")

    # Section headers
    sec_offset = opt_offset + optional_hdr_size
    sections = []
    for i in range(num_sections):
        off = sec_offset + i * 40
        name_bytes = data[off:off+8]
        name = name_bytes.split(b'\x00')[0].decode('ascii', errors='replace')
        vsize, va, raw_size, raw_off = struct.unpack_from('<IIII', data, off + 8)
        chars = struct.unpack_from('<I', data, off + 36)[0]
        sections.append(PESection(name, va, vsize, raw_off, raw_size, chars))

    return PEInfo(image_base, sections, size_of_image)


# ---- 字符串搜索 ----

def find_string_rvas(data: bytes, pe: PEInfo, target: str) -> list:
    """Find all occurrences of target string (ASCII) and return their RVAs."""
    target_bytes = target.encode('ascii')
    results = []
    offset = 0
    while True:
        idx = data.find(target_bytes, offset)
        if idx == -1:
            break
        # Convert file offset to RVA
        rva = file_offset_to_rva(pe, idx)
        if rva is not None:
            results.append((rva, idx))
        offset = idx + 1
    return results


def file_offset_to_rva(pe: PEInfo, file_offset: int) -> int | None:
    for sec in pe.sections:
        if sec.raw_offset <= file_offset < sec.raw_offset + sec.raw_size:
            return sec.virtual_address + (file_offset - sec.raw_offset)
    return None


def rva_to_file_offset(pe: PEInfo, rva: int) -> int | None:
    for sec in pe.sections:
        if sec.virtual_address <= rva < sec.virtual_address + sec.virtual_size:
            return sec.raw_offset + (rva - sec.virtual_address)
    return None


# ---- x64 RIP-Relative Cross-Reference Scanner ----

@dataclass
class XRef:
    code_rva: int        # RVA of the referencing instruction's displacement field
    target_rva: int      # RVA of the referenced string
    target_string: str
    instruction_rva: int  # estimated start of instruction
    function_rva: int | None  # estimated function start


def scan_rip_relative_xrefs(data: bytes, pe: PEInfo, target_rva: int,
                             target_string: str, text_sec: PESection) -> list:
    """
    Scan .text section for x64 RIP-relative references to target_rva.

    On x64, RIP-relative addressing uses a 32-bit signed displacement
    relative to the END of the current instruction. For a 4-byte displacement
    field at file position P (RVA = R):
        referenced_rva = R + 4 + int32_at(P)
    We need: int32_at(P) = target_rva - R - 4
    """
    results = []
    text_start = text_sec.raw_offset
    text_end = text_start + text_sec.raw_size
    text_rva_start = text_sec.virtual_address

    # Process in 4MB chunks to control memory
    chunk_size = 4 * 1024 * 1024
    pos = text_start

    while pos < text_end:
        end = min(pos + chunk_size + 3, text_end)  # +3 for overlap
        chunk = data[pos:end]
        chunk_len = len(chunk) - 3  # need 4 bytes per position

        for i in range(chunk_len):
            # Read 4 bytes as signed int32
            disp = struct.unpack_from('<i', chunk, i)[0]
            # RVA of this displacement field
            disp_rva = text_rva_start + (pos - text_start) + i
            # The referenced RVA
            ref_rva = disp_rva + 4 + disp

            if ref_rva == target_rva:
                # Potential hit — verify it's plausibly part of an instruction
                # Look backwards up to 3 bytes for common instruction prefixes
                instr_rva = estimate_instruction_start(data, pe, disp_rva, text_sec)
                results.append(XRef(
                    code_rva=disp_rva,
                    target_rva=target_rva,
                    target_string=target_string,
                    instruction_rva=instr_rva,
                    function_rva=None  # filled later
                ))

        pos += chunk_size  # no overlap needed since we just check displacement value

    return results


def estimate_instruction_start(data: bytes, pe: PEInfo, disp_rva: int,
                                text_sec: PESection) -> int:
    """
    Given the RVA of a displacement field, try to estimate the instruction start.
    Common x64 patterns with RIP-relative addressing:
      48 8D xx dd dd dd dd  — LEA r64, [rip+disp32]     (7 bytes, disp at +3)
      48 8B xx dd dd dd dd  — MOV r64, [rip+disp32]     (7 bytes, disp at +3)
      4C 8D xx dd dd dd dd  — LEA r8-r15, [rip+disp32]  (7 bytes, disp at +3)
      48 89 xx dd dd dd dd  — MOV [rip+disp32], r64     (7 bytes, disp at +3)
      8D xx dd dd dd dd     — LEA r32, [rip+disp32]     (6 bytes, disp at +2)
      E8 dd dd dd dd        — CALL rel32                (5 bytes, disp at +1)
      E9 dd dd dd dd        — JMP rel32                 (5 bytes, disp at +1)
      FF 15 dd dd dd dd     — CALL [rip+disp32]         (6 bytes, disp at +2)
      FF 25 dd dd dd dd     — JMP [rip+disp32]          (6 bytes, disp at +2)
    """
    file_off = rva_to_file_offset(pe, disp_rva)
    if file_off is None or file_off < 4:
        return disp_rva

    # Check 3 bytes before disp for REX.W + opcode + modrm
    b_m3 = data[file_off - 3] if file_off >= 3 else 0
    b_m2 = data[file_off - 2] if file_off >= 2 else 0
    b_m1 = data[file_off - 1] if file_off >= 1 else 0

    # REX.W prefix (0x48-0x4F) + opcode + ModRM with RIP-relative (mod=00, rm=101)
    if b_m3 in range(0x48, 0x50) and (b_m1 & 0xC7) == 0x05:
        return disp_rva - 3  # 7-byte instruction

    # No REX prefix, opcode + ModRM
    if (b_m1 & 0xC7) == 0x05 and b_m2 in (0x8B, 0x8D, 0x89, 0x3B, 0x39):
        return disp_rva - 2  # 6-byte instruction

    # FF 15/25 (indirect CALL/JMP through [rip+disp32])
    if b_m2 == 0xFF and b_m1 in (0x15, 0x25):
        return disp_rva - 2

    # E8/E9 (direct CALL/JMP)
    if b_m1 in (0xE8, 0xE9):
        return disp_rva - 1

    # Fallback: just go back 3
    return disp_rva - 3


# ---- Function Start Detection ----

# Common x64 function prologues
PROLOGUES = [
    b'\x40\x53',           # push rbx
    b'\x40\x55',           # push rbp
    b'\x40\x56',           # push rsi
    b'\x40\x57',           # push rdi
    b'\x48\x83\xEC',       # sub rsp, imm8
    b'\x48\x89\x5C\x24',   # mov [rsp+xx], rbx
    b'\x48\x89\x6C\x24',   # mov [rsp+xx], rbp
    b'\x48\x89\x74\x24',   # mov [rsp+xx], rsi
    b'\x48\x89\x4C\x24',   # mov [rsp+xx], rcx
    b'\x4C\x89\x44\x24',   # mov [rsp+xx], r8
    b'\x55',               # push rbp
    b'\x56',               # push rsi
    b'\x57',               # push rdi
    b'\x53',               # push rbx
    b'\xCC\x48',           # int3; followed by sub rsp... (alignment pad)
]


def find_function_start(data: bytes, pe: PEInfo, instr_rva: int,
                         text_sec: PESection, max_search: int = 4096) -> int | None:
    """
    Walk backwards from instr_rva to find the most likely function start.
    Looks for common function prologues.
    """
    file_off = rva_to_file_offset(pe, instr_rva)
    if file_off is None:
        return None

    text_file_start = text_sec.raw_offset

    # Search backwards up to max_search bytes
    search_start = max(file_off - max_search, text_file_start)

    for off in range(file_off, search_start, -1):
        for prologue in PROLOGUES:
            if data[off:off + len(prologue)] == prologue:
                rva = file_offset_to_rva(pe, off)
                # Sanity check: prologue should be preceded by int3 (0xCC),
                # nop (0x90), or ret (0xC3) — function boundary markers
                if off > text_file_start:
                    prev_byte = data[off - 1]
                    if prev_byte in (0xCC, 0x90, 0xC3, 0xC2):
                        return rva
                    # Also allow if it's at the very start of .text
                    if off == text_file_start:
                        return rva
                else:
                    return rva

    # Fallback: no clean prologue found, look for any prologue without boundary check
    for off in range(file_off, search_start, -1):
        for prologue in PROLOGUES:
            if data[off:off + len(prologue)] == prologue:
                # At least check it's aligned to some degree (2-byte boundary)
                if (off - text_file_start) % 16 == 0:
                    return file_offset_to_rva(pe, off)

    return None


# ---- Main Analysis ----

# Default targets: known strings from memory_scanner results
DEFAULT_TARGETS = [
    "micromsg.SnsCommentRequest",
    "micromsg.SnsCommentResponse",
    "micromsg.SnsCommentContentRequest",
    "/cgi-bin/micromsg-bin/mmsnscomment",
    "SnsCommentRequest",
    "SnsComment",
    "DoSnsComment",
    "AddComment",
]


def analyze(dll_path: str, targets: list[str] = None,
            target_rvas: list[int] = None, verbose: bool = False):
    """Main analysis entry point."""
    dll_path = Path(dll_path)
    if not dll_path.exists():
        print(f"[ERROR] File not found: {dll_path}")
        return

    file_size = dll_path.stat().st_size
    print(f"[*] Analyzing: {dll_path}")
    print(f"[*] File size: {file_size / 1024 / 1024:.1f} MB")

    with open(dll_path, 'rb') as f:
        data = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)

    pe = parse_pe(data)
    print(f"[*] ImageBase: {pe.image_base:#x}")
    print(f"[*] Sections: {len(pe.sections)}")
    for sec in pe.sections:
        flags = []
        if sec.is_executable:
            flags.append("EXEC")
        if sec.is_writable:
            flags.append("WRITE")
        print(f"    {sec.name:8s}  RVA {sec.virtual_address:#010x}  "
              f"VSize {sec.virtual_size:#010x}  "
              f"Raw {sec.raw_offset:#010x}  RawSize {sec.raw_size:#010x}  "
              f"{'|'.join(flags)}")

    # Find executable section(s)
    text_sections = [s for s in pe.sections if s.is_executable]
    if not text_sections:
        print("[ERROR] No executable sections found")
        return

    print(f"\n[*] Executable sections: {', '.join(s.name for s in text_sections)}")

    # Collect all target RVAs
    target_info = []  # (rva, string_name)

    if target_rvas:
        for rva in target_rvas:
            target_info.append((rva, f"RVA_{rva:#x}"))

    if targets is None:
        targets = DEFAULT_TARGETS

    print(f"\n[*] Searching for {len(targets)} target strings...")
    for target_str in targets:
        matches = find_string_rvas(data, pe, target_str)
        if matches:
            print(f"  '{target_str}': {len(matches)} match(es)")
            for rva, foff in matches:
                print(f"    RVA {rva:#010x} (file offset {foff:#x})")
                target_info.append((rva, target_str))
        elif verbose:
            print(f"  '{target_str}': not found")

    if not target_info:
        print("[!] No target strings found in the binary")
        return

    # Deduplicate by RVA
    seen_rvas = set()
    unique_targets = []
    for rva, name in target_info:
        if rva not in seen_rvas:
            seen_rvas.add(rva)
            unique_targets.append((rva, name))

    print(f"\n[*] Scanning for cross-references to {len(unique_targets)} unique addresses...")
    print(f"[*] Text section(s) total size: "
          f"{sum(s.raw_size for s in text_sections) / 1024 / 1024:.1f} MB")

    all_xrefs = []
    for text_sec in text_sections:
        for target_rva, target_str in unique_targets:
            t0 = time.time()
            xrefs = scan_rip_relative_xrefs(data, pe, target_rva, target_str, text_sec)
            elapsed = time.time() - t0

            if xrefs:
                print(f"  [{text_sec.name}] '{target_str}' @ RVA {target_rva:#010x}: "
                      f"{len(xrefs)} xref(s) ({elapsed:.1f}s)")

                for xref in xrefs:
                    # Find function start
                    xref.function_rva = find_function_start(
                        data, pe, xref.instruction_rva, text_sec)
                    all_xrefs.append(xref)
            elif verbose:
                print(f"  [{text_sec.name}] '{target_str}' @ {target_rva:#010x}: "
                      f"0 xrefs ({elapsed:.1f}s)")

    # ---- Report ----
    print(f"\n{'='*80}")
    print(f" CROSS-REFERENCE REPORT")
    print(f"{'='*80}")
    print(f" Total xrefs found: {len(all_xrefs)}")

    if not all_xrefs:
        print(" [!] No cross-references found. Try running with --verbose")
        print(" [!] The strings might be referenced via absolute pointers (not RIP-relative)")
        return

    # Group by function
    func_map = {}  # function_rva -> list of xrefs
    for xref in all_xrefs:
        key = xref.function_rva or xref.instruction_rva
        func_map.setdefault(key, []).append(xref)

    print(f" Unique referencing functions: {len(func_map)}")
    print()

    # Sort by number of references (most references = most interesting)
    for func_rva, xrefs in sorted(func_map.items(),
                                    key=lambda x: len(x[1]), reverse=True):
        ref_strings = set(x.target_string for x in xrefs)
        print(f"  Function @ RVA {func_rva:#010x}  ({len(xrefs)} ref(s))")
        for xref in xrefs:
            instr_file = rva_to_file_offset(pe, xref.instruction_rva)
            # Show a few bytes around the instruction
            ctx = ""
            if instr_file and instr_file + 10 <= len(data):
                instr_bytes = data[instr_file:instr_file + 10]
                ctx = " ".join(f"{b:02x}" for b in instr_bytes)
            print(f"    instr @ {xref.instruction_rva:#010x}  "
                  f"-> '{xref.target_string}'  [{ctx}]")
        print()

    # ---- Summary for sns_comment.cpp ----
    print(f"{'='*80}")
    print(f" CANDIDATE FUNCTIONS FOR sns_comment.cpp")
    print(f"{'='*80}")
    print()

    # Prioritize functions that reference both SnsCommentRequest AND mmsnscomment
    priority_keywords = {"SnsCommentRequest", "mmsnscomment", "SnsComment"}
    scored = []
    for func_rva, xrefs in func_map.items():
        ref_strings = set(x.target_string for x in xrefs)
        score = 0
        for kw in priority_keywords:
            for rs in ref_strings:
                if kw.lower() in rs.lower():
                    score += 1
                    break
        scored.append((score, func_rva, xrefs))

    scored.sort(key=lambda x: (-x[0], x[1]))

    for rank, (score, func_rva, xrefs) in enumerate(scored[:20], 1):
        ref_strs = ", ".join(sorted(set(x.target_string for x in xrefs)))
        print(f"  #{rank:2d}  RVA {func_rva:#010x}  "
              f"score={score}  refs=[{ref_strs}]")

    print()
    print("[*] Next steps:")
    print("    1. Use these RVAs in IDA/Ghidra to examine function signatures")
    print("    2. Or hook with Frida: script.post({type:'hook_address', offset:'0x...'})")
    print("    3. Top-scored functions are most likely the comment submission path")

    data.close()


def main():
    parser = argparse.ArgumentParser(description="x64 PE Cross-Reference Finder")
    parser.add_argument("dll", help="Path to Weixin.dll / WeChatWin.dll")
    parser.add_argument("--target", "-t", action="append",
                        help="Target string to find xrefs for (can repeat)")
    parser.add_argument("--rva", action="append", type=lambda x: int(x, 0),
                        help="Target RVA to find xrefs for (hex, can repeat)")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Show all scan progress")
    args = parser.parse_args()

    analyze(args.dll, targets=args.target, target_rvas=args.rva, verbose=args.verbose)


if __name__ == "__main__":
    main()
