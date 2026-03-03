"""
反汇编候选函数 — 分析函数签名和调用关系

对每个候选函数反汇编前 N 条指令，识别:
  1. 参数寄存器使用 (rcx, rdx, r8, r9 → 最多 4 个参数)
  2. 字符串引用 (LEA + RIP-relative → .rdata 中的字符串)
  3. CALL 目标 (直接调用了哪些函数)
  4. 函数大小估算
"""

import mmap
import struct
import sys
from pathlib import Path

from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_OPT_DETAIL, CsInsn
from xref_finder import parse_pe, rva_to_file_offset, file_offset_to_rva


# 候选函数
CANDIDATES = {
    0x04924ff0: "SnsCommentRequest_proto",
    0x04925540: "SnsCommentResponse_proto",
    0x048fb690: "SnsCommentContentRequest_proto",
    0x029de330: "mmsnscomment_cgi_A",
    0x02a10a70: "mmsnscomment_cgi_B",
    0x05af06b0: "SnsComment_logic",
    0x029dc871: "cgi_A_caller_1",
    0x049e9240: "cgi_A_caller_2",
    0x049bdc10: "cgi_A_caller_3_TOP",
    0x02a10630: "cgi_B_caller_1",
    0x02a105a0: "cgi_B_caller_2_TOP",
}


def read_string_at_rva(data: bytes, pe, rva: int, max_len=128) -> str | None:
    """Try to read an ASCII string at the given RVA."""
    off = rva_to_file_offset(pe, rva)
    if off is None or off + 4 >= len(data):
        return None
    end = min(off + max_len, len(data))
    result = []
    for i in range(off, end):
        b = data[i]
        if b == 0:
            break
        if 32 <= b < 127:
            result.append(chr(b))
        else:
            return None  # not a clean ASCII string
    s = "".join(result)
    return s if len(s) >= 3 else None


def disassemble_function(data: bytes, pe, rva: int, name: str,
                          max_bytes=512, max_insns=150):
    """Disassemble a function and analyze its structure."""
    off = rva_to_file_offset(pe, rva)
    if off is None:
        print(f"  [ERROR] Cannot map RVA {rva:#x} to file offset")
        return

    # Read up to max_bytes
    end = min(off + max_bytes, len(data))
    func_bytes = bytes(data[off:end])

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True

    print(f"\n{'='*80}")
    print(f" {name}  @ RVA {rva:#010x}  (file offset {off:#x})")
    print(f"{'='*80}")

    # Track analysis
    arg_regs_used = set()   # rcx, rdx, r8, r9 before first write
    arg_reg_written = set()
    string_refs = []
    call_targets = []
    stack_alloc = 0
    insn_count = 0
    func_end_rva = rva + max_bytes

    # Windows x64 calling convention: rcx=arg1, rdx=arg2, r8=arg3, r9=arg4
    ARG_REGS = {'rcx': 1, 'rdx': 2, 'r8': 3, 'r9': 4,
                'ecx': 1, 'edx': 2, 'r8d': 3, 'r9d': 4}

    for insn in md.disasm(func_bytes, rva):
        insn_count += 1
        if insn_count > max_insns:
            break

        # Detect function end (ret / int3 padding)
        if insn.mnemonic == 'ret' and insn_count > 3:
            func_end_rva = insn.address + insn.size
            # Print this insn then stop
            offset_str = f"+{insn.address - rva:#06x}"
            print(f"  {offset_str}  {insn.address:#012x}  {insn.mnemonic:8s} {insn.op_str}")
            break

        if insn.mnemonic == 'int3':
            func_end_rva = insn.address
            break

        # Print instruction
        offset_str = f"+{insn.address - rva:#06x}"
        annotation = ""

        # Detect stack allocation: sub rsp, imm
        if insn.mnemonic == 'sub' and 'rsp' in insn.op_str:
            try:
                imm = int(insn.op_str.split(',')[1].strip(), 0)
                stack_alloc = imm
                annotation = f"  ; stack frame = {imm:#x} ({imm} bytes)"
            except (ValueError, IndexError):
                pass

        # Detect LEA with RIP-relative (string references)
        if insn.mnemonic == 'lea' and 'rip' in insn.op_str:
            # The target address is the instruction address + instruction size + displacement
            # capstone provides this via operands
            try:
                for op in insn.operands:
                    if op.type == 3:  # MEM
                        if op.mem.base == 0:  # RIP-relative in capstone terms
                            pass
                # Simpler: parse from the encoded displacement
                # For LEA reg, [rip + disp32]: disp is last 4 bytes before end
                disp_off = insn.size - 4
                disp = struct.unpack_from('<i', insn.bytes, disp_off)[0]
                target_rva = insn.address + insn.size + disp
                s = read_string_at_rva(data, pe, target_rva)
                if s:
                    string_refs.append((insn.address, target_rva, s))
                    annotation = f'  ; -> "{s[:60]}"'
                else:
                    annotation = f"  ; -> RVA {target_rva:#010x}"
            except Exception:
                pass

        # Detect MOVUPS/MOVAPS with RIP-relative (also loads string pointers)
        if insn.mnemonic in ('movups', 'movaps') and 'rip' in insn.op_str:
            try:
                disp_off = insn.size - 4
                disp = struct.unpack_from('<i', insn.bytes, disp_off)[0]
                target_rva = insn.address + insn.size + disp
                s = read_string_at_rva(data, pe, target_rva)
                if s:
                    string_refs.append((insn.address, target_rva, s))
                    annotation = f'  ; -> "{s[:60]}"'
                else:
                    annotation = f"  ; -> RVA {target_rva:#010x}"
            except Exception:
                pass

        # Detect CALL rel32
        if insn.mnemonic == 'call' and insn.op_str.startswith('0x'):
            try:
                target = int(insn.op_str, 16)
                call_name = CANDIDATES.get(target, "")
                if call_name:
                    annotation = f"  ; -> {call_name}"
                call_targets.append((insn.address, target, call_name))
            except ValueError:
                pass

        # Track argument register usage
        if insn_count <= 30:  # Only in the first ~30 instructions (prologue + early body)
            op_str = insn.op_str
            mnem = insn.mnemonic
            for reg, argn in ARG_REGS.items():
                if reg in op_str:
                    parts = op_str.split(',')
                    # If the reg is the source (2nd operand or single operand in mov)
                    if len(parts) >= 2 and reg in parts[1] and argn not in arg_reg_written:
                        arg_regs_used.add(argn)
                    # If reg is destination (written to)
                    if len(parts) >= 1 and reg in parts[0] and mnem in ('mov', 'lea', 'xor', 'sub', 'add'):
                        if mnem == 'xor' and parts[0].strip() == parts[1].strip():
                            pass  # xor rcx, rcx = zero, but doesn't count as "read"
                        arg_reg_written.add(argn)
                    # Simple read in other contexts
                    if mnem in ('cmp', 'test', 'push') and reg in op_str:
                        if argn not in arg_reg_written:
                            arg_regs_used.add(argn)

        print(f"  {offset_str}  {insn.address:#012x}  {insn.mnemonic:8s} {insn.op_str}{annotation}")

    # Summary
    func_size = func_end_rva - rva
    print(f"\n  --- Summary ---")
    print(f"  Function size (est): {func_size:#x} ({func_size} bytes)")
    print(f"  Stack frame: {stack_alloc:#x} ({stack_alloc} bytes)")

    # Argument count estimate
    if arg_regs_used:
        max_arg = max(arg_regs_used)
        print(f"  Arguments (est): {max_arg} (used: {sorted(arg_regs_used)})")
    else:
        print(f"  Arguments (est): unknown (no arg register reads detected)")

    if string_refs:
        print(f"  String references ({len(string_refs)}):")
        for addr, trva, s in string_refs[:15]:
            print(f"    @ {addr:#x} -> \"{s[:70]}\"")

    if call_targets:
        print(f"  Direct calls ({len(call_targets)}):")
        for addr, target, cname in call_targets[:20]:
            label = f" ({cname})" if cname else ""
            known = CANDIDATES.get(target, "")
            if not known:
                # Check if close to any candidate
                for crva, cnam in CANDIDATES.items():
                    if abs(target - crva) < 0x100:
                        label = f" (near {cnam})"
                        break
            print(f"    @ {addr:#x} -> {target:#010x}{label}")


def main():
    dll_path = sys.argv[1] if len(sys.argv) > 1 else \
        r"C:\Program Files\Tencent\Weixin\4.1.7.30\Weixin.dll"

    path = Path(dll_path)
    print(f"[*] Opening {path} ({path.stat().st_size / 1024 / 1024:.1f} MB)")

    with open(path, 'rb') as f:
        data = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)

    pe = parse_pe(data)

    # Focus on the most interesting candidates first
    priority_order = [
        0x049bdc10,  # cgi_A_caller_3_TOP (highest in call chain)
        0x02a105a0,  # cgi_B_caller_2_TOP
        0x049e9240,  # cgi_A_caller_2
        0x029de330,  # mmsnscomment_cgi_A
        0x02a10a70,  # mmsnscomment_cgi_B
        0x04924ff0,  # SnsCommentRequest_proto
        0x048fb690,  # SnsCommentContentRequest_proto
        0x05af06b0,  # SnsComment_logic
    ]

    for rva in priority_order:
        name = CANDIDATES[rva]
        disassemble_function(data, pe, rva, name, max_bytes=600, max_insns=120)

    data.close()


if __name__ == "__main__":
    main()
