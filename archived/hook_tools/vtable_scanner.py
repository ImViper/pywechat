"""
扫描 .rdata 段中的虚函数表指针 — 找到间接调用候选函数的 vtable 条目。

PE 文件中的指针基于 preferred ImageBase (0x180000000)。
"""

import mmap
import struct
import sys
from pathlib import Path
from xref_finder import parse_pe, rva_to_file_offset, file_offset_to_rva


def scan_vtable_refs(dll_path: str, target_rvas: list):
    path = Path(dll_path)
    with open(path, 'rb') as f:
        data = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)

    pe = parse_pe(data)
    image_base = pe.image_base
    print(f"[*] ImageBase: {image_base:#x}")

    # Find data sections (.rdata, .data)
    data_sections = [s for s in pe.sections
                     if not s.is_executable and s.raw_size > 0]

    for target_rva in target_rvas:
        target_va = image_base + target_rva
        target_bytes = struct.pack('<Q', target_va)
        print(f"\n[*] Scanning for VA {target_va:#018x} (RVA {target_rva:#010x})")

        for sec in data_sections:
            offset = sec.raw_offset
            end = sec.raw_offset + sec.raw_size - 7
            count = 0
            while offset < end:
                idx = data.find(target_bytes, offset, end + 7)
                if idx == -1:
                    break
                ref_rva = file_offset_to_rva(pe, idx)
                # Check surrounding entries (vtable = array of function pointers)
                # Read 3 entries before and after
                context = []
                for delta in range(-3, 4):
                    ptr_off = idx + delta * 8
                    if 0 <= ptr_off <= len(data) - 8:
                        val = struct.unpack_from('<Q', data, ptr_off)[0]
                        entry_rva = val - image_base if val >= image_base else 0
                        marker = " <--" if delta == 0 else ""
                        # Check if this pointer is in .text range
                        in_text = any(s.virtual_address <= entry_rva <
                                      s.virtual_address + s.virtual_size
                                      for s in pe.sections if s.is_executable)
                        flag = " [CODE]" if in_text else ""
                        context.append(f"    [{delta:+d}] {val:#018x}  "
                                       f"(RVA {entry_rva:#010x}){flag}{marker}")

                print(f"  Found in {sec.name} @ file_off {idx:#x} "
                      f"(RVA {ref_rva:#010x})")
                for line in context:
                    print(line)
                count += 1
                offset = idx + 1

            if count == 0 and sec.name in ('.rdata', '.data'):
                pass  # only print if verbose

    data.close()


if __name__ == "__main__":
    dll = sys.argv[1] if len(sys.argv) > 1 else \
        r"C:\Program Files\Tencent\Weixin\4.1.7.30\Weixin.dll"

    # All 6 candidate functions + 3 callers
    targets = [
        0x04924ff0,  # SnsCommentRequest_ctor
        0x04925540,  # SnsCommentResponse_ctor
        0x048fb690,  # SnsCommentContentRequest_ctor
        0x029de330,  # mmsnscomment_cgi_A
        0x02a10a70,  # mmsnscomment_cgi_B
        0x05af06b0,  # SnsComment_logic
        0x029dc871,  # caller of cgi_A
        0x049e9240,  # caller of cgi_A
        0x049bdc10,  # caller of 0x49e9240
        0x02a10630,  # caller of cgi_B
        0x02a105a0,  # caller of 0x2a10630
    ]

    scan_vtable_refs(dll, targets)
