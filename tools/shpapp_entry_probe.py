#!/usr/bin/env python3
"""Probe the ShpApp embedded ELF entry region.

This writes metadata and short disassembly windows only. Temporary binary slices
are written under the selected ignored out/ directory.
"""

from __future__ import annotations

import argparse
import json
import shutil
import struct
import subprocess
from pathlib import Path


ELF_MAGIC = b"\x7fELF"


def u16le(data: bytes, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def u32le(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def parse_elf(data: bytes, elf_offset: int) -> dict:
    if data[elf_offset:elf_offset + 4] != ELF_MAGIC:
        raise ValueError(f"No ELF header at 0x{elf_offset:x}")
    if data[elf_offset + 4] != 1 or data[elf_offset + 5] != 1:
        raise ValueError("Only ELF32 little-endian is supported")

    header = struct.unpack_from("<HHIIIIIHHHHHH", data, elf_offset + 16)
    (
        e_type,
        e_machine,
        e_version,
        e_entry,
        e_phoff,
        e_shoff,
        e_flags,
        e_ehsize,
        e_phentsize,
        e_phnum,
        e_shentsize,
        e_shnum,
        e_shstrndx,
    ) = header

    phdrs = []
    for index in range(e_phnum):
        pos = elf_offset + e_phoff + index * e_phentsize
        phdr = struct.unpack_from("<IIIIIIII", data, pos)
        p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align = phdr
        phdrs.append(
            {
                "type": p_type,
                "offset": p_offset,
                "vaddr": p_vaddr,
                "paddr": p_paddr,
                "filesz": p_filesz,
                "memsz": p_memsz,
                "flags": p_flags,
                "align": p_align,
            }
        )

    return {
        "entry": e_entry,
        "flags": e_flags,
        "program_headers": phdrs,
        "section_header_offset": e_shoff,
        "section_header_count": e_shnum,
        "section_header_entry_size": e_shentsize,
    }


def vaddr_to_file_offset(elf: dict, vaddr: int) -> int:
    for ph in elf["program_headers"]:
        if ph["type"] != 1:
            continue
        start = ph["vaddr"]
        end = start + ph["filesz"]
        if start <= vaddr < end:
            return ph["offset"] + (vaddr - start)
    raise ValueError(f"VMA 0x{vaddr:x} is not covered by a loadable file range")


def read_vaddr_u32(data: bytes, elf_offset: int, elf: dict, vaddr: int) -> int | None:
    try:
        rel = vaddr_to_file_offset(elf, vaddr)
    except ValueError:
        return None
    pos = elf_offset + rel
    if pos + 4 > len(data):
        return None
    return u32le(data, pos)


def thumb_literal_loads(data: bytes, elf_offset: int, elf: dict, start_vaddr: int, size: int) -> list[dict]:
    rel = vaddr_to_file_offset(elf, start_vaddr)
    pos = elf_offset + rel
    end = min(pos + size, len(data))
    hits = []
    current = pos
    while current + 2 <= end:
        hw = u16le(data, current)
        addr = start_vaddr + (current - pos)
        # Thumb-1 LDR literal: 01001 Rt:3 Imm8. PC is aligned (addr + 4), imm scaled by 4.
        if (hw & 0xF800) == 0x4800:
            rt = (hw >> 8) & 0x7
            imm = hw & 0xFF
            literal_vaddr = ((addr + 4) & ~3) + imm * 4
            literal_value = read_vaddr_u32(data, elf_offset, elf, literal_vaddr)
            hits.append(
                {
                    "address": addr,
                    "halfword": hw,
                    "rt": rt,
                    "imm8": imm,
                    "literal_vaddr": literal_vaddr,
                    "literal_value": literal_value,
                }
            )
        current += 2
    return hits


def run_objdump(blob: Path, vma: int, mode: str) -> list[str]:
    objdump = shutil.which("arm-none-eabi-objdump")
    if not objdump:
        return []
    machine_args = ["-marm"]
    disasm_opts = []
    if mode == "thumb":
        disasm_opts = ["-M", "force-thumb"]
    cmd = [
        objdump,
        "-D",
        "-b",
        "binary",
        *machine_args,
        *disasm_opts,
        f"--adjust-vma=0x{vma:x}",
        str(blob),
    ]
    proc = subprocess.run(cmd, check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    lines = []
    for line in proc.stdout.splitlines():
        stripped = line.rstrip()
        if stripped:
            lines.append(stripped)
    return lines


def hex_or_none(value: int | None) -> str | None:
    return None if value is None else f"0x{value:x}"


def analyze(path: Path, out: Path, window_before: int, window_size: int) -> dict:
    data = path.read_bytes()
    elf_offset = data.find(ELF_MAGIC)
    if elf_offset < 0:
        raise SystemExit("No embedded ELF found")
    elf = parse_elf(data, elf_offset)
    entry = elf["entry"]
    entry_rel = vaddr_to_file_offset(elf, entry)
    entry_container_offset = elf_offset + entry_rel

    window_vaddr = max(elf["program_headers"][0]["vaddr"], entry - window_before)
    window_rel = vaddr_to_file_offset(elf, window_vaddr)
    window_container_offset = elf_offset + window_rel
    window_data = data[window_container_offset:window_container_offset + window_size]

    out.mkdir(parents=True, exist_ok=True)
    blob = out / "shpapp_entry_window.bin"
    blob.write_bytes(window_data)

    literal_loads = thumb_literal_loads(data, elf_offset, elf, entry, min(window_size, 0x100))
    return {
        "input": str(path),
        "elf_offset": elf_offset,
        "entry_vaddr": entry,
        "entry_elf_offset": entry_rel,
        "entry_container_offset": entry_container_offset,
        "window_vaddr": window_vaddr,
        "window_container_offset": window_container_offset,
        "window_size": len(window_data),
        "elf_flags": elf["flags"],
        "load_segments": elf["program_headers"],
        "thumb_literal_loads": literal_loads,
        "thumb_disassembly": run_objdump(blob, window_vaddr, "thumb")[:80],
        "arm_disassembly": run_objdump(blob, window_vaddr, "arm")[:40],
    }


def write_markdown(report: dict, out_path: Path) -> None:
    lines = ["# ShpApp entry probe", ""]
    lines.append(f"Input: `{Path(report['input']).name}`")
    lines.append(f"ELF offset: `0x{report['elf_offset']:x}`")
    lines.append(f"Entry VMA: `0x{report['entry_vaddr']:x}`")
    lines.append(f"Entry ELF offset: `0x{report['entry_elf_offset']:x}`")
    lines.append(f"Entry container offset: `0x{report['entry_container_offset']:x}`")
    lines.append(f"Window VMA: `0x{report['window_vaddr']:x}`")
    lines.append(f"Window container offset: `0x{report['window_container_offset']:x}`")
    lines.append(f"Window size: `0x{report['window_size']:x}`")
    lines.append("")
    lines.append("## Thumb Literal Loads Near Entry")
    lines.append("")
    lines.append("| Address | Halfword | Register | Literal address | Literal value |")
    lines.append("| ---: | ---: | ---: | ---: | ---: |")
    for hit in report["thumb_literal_loads"]:
        lines.append(
            f"| `0x{hit['address']:x}` | `0x{hit['halfword']:04x}` | `r{hit['rt']}` | "
            f"`0x{hit['literal_vaddr']:x}` | `{hex_or_none(hit['literal_value'])}` |"
        )
    lines.append("")
    lines.append("## Thumb Disassembly Window")
    lines.append("")
    lines.append("```text")
    lines.extend(report["thumb_disassembly"])
    lines.append("```")
    lines.append("")
    lines.append("## ARM Disassembly Window")
    lines.append("")
    lines.append("```text")
    lines.extend(report["arm_disassembly"])
    lines.append("```")
    lines.append("")
    out_path.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("--out", type=Path, default=Path("out/shpapp_entry_probe"))
    parser.add_argument("--window-before", type=lambda x: int(x, 0), default=0x20)
    parser.add_argument("--window-size", type=lambda x: int(x, 0), default=0x180)
    args = parser.parse_args()

    report = analyze(args.input, args.out, args.window_before, args.window_size)
    args.out.mkdir(parents=True, exist_ok=True)
    json_path = args.out / "shpapp_entry_probe.json"
    md_path = args.out / "shpapp_entry_probe.md"
    json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    write_markdown(report, md_path)
    print(f"Wrote {json_path}")
    print(f"Wrote {md_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
