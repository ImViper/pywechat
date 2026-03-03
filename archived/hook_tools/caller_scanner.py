"""
调用者扫描器 — 查找谁调用了候选评论函数

对于每个候选函数 RVA，在 .text 段扫描 CALL rel32 (E8) 和 JMP rel32 (E9)
指令来找到调用者，逐级向上追溯调用链。
"""

import argparse
import mmap
import struct
import sys
import time
from pathlib import Path

# Reuse PE parsing from xref_finder
from xref_finder import parse_pe, rva_to_file_offset, file_offset_to_rva, find_function_start


def scan_callers(data: bytes, pe, text_sec, target_rva: int) -> list:
    """
    Scan .text for E8 (CALL rel32) and E9 (JMP rel32) targeting target_rva.
    Returns list of (caller_instr_rva, caller_func_rva, call_type).
    """
    results = []
    text_start = text_sec.raw_offset
    text_end = text_start + text_sec.raw_size
    text_rva_start = text_sec.virtual_address

    chunk_size = 4 * 1024 * 1024
    pos = text_start

    while pos < text_end:
        end = min(pos + chunk_size + 4, text_end)
        chunk = data[pos:end]
        chunk_len = len(chunk) - 4

        for i in range(chunk_len):
            opcode = chunk[i]
            if opcode not in (0xE8, 0xE9):
                continue

            # Read rel32 displacement
            disp = struct.unpack_from('<i', chunk, i + 1)[0]
            instr_rva = text_rva_start + (pos - text_start) + i
            # CALL/JMP target = instr_rva + 5 + disp
            call_target = instr_rva + 5 + disp

            if call_target == target_rva:
                call_type = "CALL" if opcode == 0xE8 else "JMP"
                func_rva = find_function_start(data, pe, instr_rva, text_sec)
                results.append((instr_rva, func_rva, call_type))

        pos += chunk_size

    return results


def main():
    parser = argparse.ArgumentParser(description="Caller Scanner")
    parser.add_argument("dll", help="Path to Weixin.dll")
    parser.add_argument("--targets", "-t", nargs="+",
                        help="Target RVAs (hex) to find callers for")
    parser.add_argument("--depth", "-d", type=int, default=2,
                        help="How many levels up to trace (default: 2)")
    args = parser.parse_args()

    # Default: our 6 candidate functions from xref_finder results
    if args.targets:
        target_rvas = [int(x, 16) for x in args.targets]
    else:
        target_rvas = [
            0x04924ff0,  # -> micromsg.SnsCommentRequest
            0x04925540,  # -> micromsg.SnsCommentResponse
            0x048fb690,  # -> micromsg.SnsCommentContentRequest
            0x029de330,  # -> /cgi-bin/.../mmsnscomment
            0x02a10a70,  # -> /cgi-bin/.../mmsnscomment
            0x05af06b0,  # -> SnsComment
        ]

    target_names = {
        0x04924ff0: "SnsCommentRequest_ctor",
        0x04925540: "SnsCommentResponse_ctor",
        0x048fb690: "SnsCommentContentRequest_ctor",
        0x029de330: "mmsnscomment_cgi_A",
        0x02a10a70: "mmsnscomment_cgi_B",
        0x05af06b0: "SnsComment_logic",
    }

    dll_path = Path(args.dll)
    print(f"[*] Opening {dll_path} ({dll_path.stat().st_size / 1024 / 1024:.1f} MB)")

    with open(dll_path, 'rb') as f:
        data = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)

    pe = parse_pe(data)
    text_sections = [s for s in pe.sections if s.is_executable]

    # Build call graph level by level
    all_edges = {}  # (caller_func, callee_func) -> call_type
    current_targets = list(target_rvas)

    for depth in range(args.depth):
        print(f"\n[*] === Level {depth + 1} caller scan ({len(current_targets)} targets) ===")
        next_targets = []

        for target in current_targets:
            name = target_names.get(target, f"func_{target:#x}")
            print(f"  Scanning callers of {name} ({target:#010x})...", end=" ", flush=True)

            t0 = time.time()
            callers = []
            for text_sec in text_sections:
                callers.extend(scan_callers(data, pe, text_sec, target))
            elapsed = time.time() - t0

            print(f"{len(callers)} caller(s) ({elapsed:.1f}s)")

            for instr_rva, func_rva, call_type in callers:
                caller = func_rva or instr_rva
                edge_key = (caller, target)
                all_edges[edge_key] = call_type

                # Name new functions
                if caller not in target_names:
                    target_names[caller] = f"caller_{caller:#x}"
                    next_targets.append(caller)

                print(f"    {call_type} @ {instr_rva:#010x}  "
                      f"in func {caller:#010x} ({target_names[caller]})")

        current_targets = next_targets

    # Print call graph
    print(f"\n{'='*80}")
    print(f" CALL GRAPH (arrows = calls)")
    print(f"{'='*80}")

    # Group by callee
    callees = {}
    for (caller, callee), ctype in all_edges.items():
        callees.setdefault(callee, []).append((caller, ctype))

    printed = set()

    def print_tree(node, indent=0):
        if node in printed:
            print("  " * indent + f"[{target_names.get(node, f'{node:#x}')}] (see above)")
            return
        printed.add(node)

        marker = " *" if node in target_rvas else ""
        print("  " * indent + f"[{target_names.get(node, f'{node:#x}')}] "
              f"RVA {node:#010x}{marker}")

        callers_list = callees.get(node, [])
        for caller, ctype in callers_list:
            print("  " * (indent + 1) + f"<-- {ctype} from:")
            print_tree(caller, indent + 2)

    for target in target_rvas:
        print_tree(target)
        print()

    # Summary
    print(f"{'='*80}")
    print(f" ENTRY POINT CANDIDATES (functions with no known callers)")
    print(f"{'='*80}")

    all_callees_set = set(c for (_, c) in all_edges.keys())
    all_callers_set = set(c for (c, _) in all_edges.keys())
    # Functions that are callers but not called by anyone we found
    top_level = all_callers_set - all_callees_set
    for func in sorted(top_level):
        print(f"  {target_names.get(func, f'{func:#x}')}  RVA {func:#010x}")

    data.close()


if __name__ == "__main__":
    main()
