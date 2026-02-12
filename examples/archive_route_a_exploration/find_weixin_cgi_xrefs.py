"""Find code xrefs to target CGI strings in Weixin.dll (static scan).

The scanner looks for RIP-relative instructions like:
  - lea reg, [rip+disp32]
  - mov reg, [rip+disp32]
whose computed target points to target CGI string RVAs.
"""

from __future__ import annotations

import argparse
import json
import struct
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any


DEFAULT_DLL = r"C:\Program Files\Tencent\Weixin\4.1.7.30\Weixin.dll"
DEFAULT_NEEDLES = [
    "/cgi-bin/micromsg-bin/mmsnscomment",
    "/cgi-bin/micromsg-bin/mmsnstimeline",
    "/cgi-bin/micromsg-bin/mmsnspost",
]


def _log(msg: str) -> None:
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}", flush=True)


@dataclass
class Section:
    name: str
    vaddr: int
    vsize: int
    raw_ptr: int
    raw_size: int
    chars: int

    def contains_file(self, off: int) -> bool:
        return self.raw_ptr <= off < (self.raw_ptr + self.raw_size)

    def contains_rva(self, rva: int) -> bool:
        size = max(self.vsize, self.raw_size)
        return self.vaddr <= rva < (self.vaddr + size)

    def is_executable(self) -> bool:
        return bool(self.chars & 0x20000000)


@dataclass
class PEInfo:
    image_base: int
    sections: list[Section]

    def file_to_rva(self, off: int) -> int:
        for s in self.sections:
            if s.contains_file(off):
                return s.vaddr + (off - s.raw_ptr)
        return off

    def rva_to_file(self, rva: int) -> int:
        for s in self.sections:
            if s.contains_rva(rva):
                return s.raw_ptr + (rva - s.vaddr)
        return rva

    def rva_section_name(self, rva: int) -> str:
        for s in self.sections:
            if s.contains_rva(rva):
                return s.name
        return ""


def _parse_pe(raw: bytes) -> PEInfo:
    if len(raw) < 0x100:
        raise ValueError("file too small for PE")
    if raw[:2] != b"MZ":
        raise ValueError("not a PE file (MZ header missing)")

    e_lfanew = struct.unpack_from("<I", raw, 0x3C)[0]
    if e_lfanew <= 0 or e_lfanew + 0x100 >= len(raw):
        raise ValueError("invalid e_lfanew")
    if raw[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
        raise ValueError("PE signature missing")

    coff_off = e_lfanew + 4
    num_sections = struct.unpack_from("<H", raw, coff_off + 2)[0]
    size_opt = struct.unpack_from("<H", raw, coff_off + 16)[0]
    opt_off = coff_off + 20
    magic = struct.unpack_from("<H", raw, opt_off)[0]
    if magic == 0x20B:  # PE32+
        image_base = struct.unpack_from("<Q", raw, opt_off + 24)[0]
    elif magic == 0x10B:  # PE32
        image_base = struct.unpack_from("<I", raw, opt_off + 28)[0]
    else:
        raise ValueError(f"unsupported optional header magic: 0x{magic:x}")

    sec_off = opt_off + size_opt
    sections: list[Section] = []
    for i in range(num_sections):
        off = sec_off + i * 40
        if off + 40 > len(raw):
            break
        name_raw = raw[off : off + 8]
        name = name_raw.split(b"\x00", 1)[0].decode("ascii", errors="ignore")
        vsize, vaddr, raw_size, raw_ptr = struct.unpack_from("<IIII", raw, off + 8)
        chars = struct.unpack_from("<I", raw, off + 36)[0]
        sections.append(
            Section(
                name=name,
                vaddr=vaddr,
                vsize=vsize,
                raw_ptr=raw_ptr,
                raw_size=raw_size,
                chars=chars,
            )
        )
    if not sections:
        raise ValueError("PE sections not found")
    return PEInfo(image_base=image_base, sections=sections)


def _find_all(raw: bytes, needle: bytes) -> list[int]:
    out: list[int] = []
    pos = 0
    while True:
        idx = raw.find(needle, pos)
        if idx < 0:
            break
        out.append(idx)
        pos = idx + 1
    return out


def _scan_rip_rel_xrefs(raw: bytes, pe: PEInfo, targets: list[dict[str, Any]]) -> list[dict[str, Any]]:
    try:
        from capstone import CS_ARCH_X86, CS_MODE_64, Cs
        from capstone.x86_const import X86_OP_IMM, X86_OP_MEM, X86_REG_RIP
    except Exception as exc:  # pragma: no cover
        raise RuntimeError(f"capstone is required for xref scan: {exc}") from exc

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True

    xrefs: list[dict[str, Any]] = []
    target_ranges = []
    for t in targets:
        target_ranges.append(
            (
                int(t["rva"]),
                int(t["rva"]) + int(t["length"]) + 1,
                str(t["needle"]),
                int(t["file_offset"]),
            )
        )

    def _match_target_rva(rva: int) -> tuple[str, int] | None:
        for lo, hi, needle, s_off in target_ranges:
            if lo <= rva < hi:
                return needle, s_off
        return None

    for s in pe.sections:
        if not s.is_executable():
            continue
        start = s.raw_ptr
        end = min(s.raw_ptr + s.raw_size, len(raw))
        if end <= start:
            continue
        code = raw[start:end]
        base_va = pe.image_base + s.vaddr
        for ins in md.disasm(code, base_va):
            target_va: int | None = None
            target_kind = ""
            try:
                for op in ins.operands:
                    if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
                        target_va = ins.address + ins.size + op.mem.disp
                        target_kind = "rip_mem"
                        break
                    if op.type == X86_OP_IMM:
                        imm = int(op.imm)
                        # Some code uses absolute VA immediates for string pointers.
                        if pe.image_base <= imm < (pe.image_base + 0x20000000):
                            target_va = imm
                            target_kind = "imm"
                            break
            except Exception:
                continue
            if target_va is None:
                continue
            target_rva = int(target_va - pe.image_base)
            matched = _match_target_rva(target_rva)
            if matched is None:
                continue
            needle, s_off = matched
            inst_rva = int(ins.address - pe.image_base)
            xrefs.append(
                {
                    "inst_file_offset": pe.rva_to_file(inst_rva),
                    "inst_rva": inst_rva,
                    "inst_va": int(ins.address),
                    "inst_section": s.name,
                    "mnemonic": ins.mnemonic,
                    "op_str": ins.op_str,
                    "target_kind": target_kind,
                    "target_rva": target_rva,
                    "target_va": int(target_va),
                    "needle": needle,
                    "needle_file_offset": s_off,
                }
            )
    return xrefs


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Find Weixin CGI string xrefs.")
    p.add_argument("--dll", default=DEFAULT_DLL)
    p.add_argument(
        "--needles",
        default=",".join(DEFAULT_NEEDLES),
        help="Comma-separated ASCII needles.",
    )
    p.add_argument(
        "--output",
        default="local_workspace/http_context/weixin_cgi_xrefs.json",
    )
    return p.parse_args()


def main() -> int:
    args = _parse_args()
    dll_path = Path(args.dll).expanduser().resolve()
    if not dll_path.is_file():
        raise FileNotFoundError(f"dll not found: {dll_path}")

    needles = [x.strip() for x in str(args.needles).split(",") if x.strip()]
    if not needles:
        raise ValueError("needles is empty")

    raw = dll_path.read_bytes()
    pe = _parse_pe(raw)

    targets: list[dict[str, Any]] = []
    for n in needles:
        hits = _find_all(raw, n.encode("ascii", errors="ignore"))
        for off in hits:
            rva = pe.file_to_rva(off)
            targets.append(
                {
                    "needle": n,
                    "file_offset": off,
                    "rva": rva,
                    "va": pe.image_base + rva,
                    "length": len(n),
                    "section": pe.rva_section_name(rva),
                }
            )

    xrefs = _scan_rip_rel_xrefs(raw, pe, targets)
    # Deduplicate by instruction RVA + needle.
    dedup: dict[tuple[int, str], dict[str, Any]] = {}
    for x in xrefs:
        key = (int(x["inst_rva"]), str(x["needle"]))
        dedup[key] = x
    xrefs = sorted(dedup.values(), key=lambda x: (x["needle"], int(x["inst_rva"])))

    summary = {
        "target_needle_count": len(needles),
        "target_hit_count": len(targets),
        "xref_count": len(xrefs),
    }
    report = {
        "generated_at": datetime.now().isoformat(),
        "dll": str(dll_path),
        "image_base": hex(pe.image_base),
        "summary": summary,
        "targets": targets,
        "xrefs": xrefs,
    }

    out = Path(args.output).expanduser().resolve()
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)

    _log(f"report saved: {out}")
    _log(
        "summary: "
        f"needles={summary['target_needle_count']}, "
        f"target_hits={summary['target_hit_count']}, "
        f"xrefs={summary['xref_count']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
