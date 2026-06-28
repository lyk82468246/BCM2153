#!/usr/bin/env python3
"""Summarize the embedded ARM ELF inside a Samsung ShpApp/FimBIN image.

The script parses headers in-place and writes only metadata. It does not extract
or copy executable bytes into the repository.
"""

from __future__ import annotations

import argparse
import json
import struct
from pathlib import Path


def read_c_utf16le(data: bytes, offset: int, max_bytes: int = 128) -> str:
    raw = bytearray()
    for pos in range(offset, min(len(data), offset + max_bytes), 2):
        pair = data[pos : pos + 2]
        if pair == b"\x00\x00" or len(pair) < 2:
            break
        raw.extend(pair)
    if not raw:
        return ""
    return raw.decode("utf-16le", "replace")


def parse_elf(data: bytes, offset: int) -> dict:
    if data[offset : offset + 4] != b"\x7fELF":
        raise ValueError(f"No ELF header at 0x{offset:x}")
    if data[offset + 4] != 1 or data[offset + 5] != 1:
        raise ValueError("Only ELF32 little-endian is supported")

    header = struct.unpack_from("<HHIIIIIHHHHHH", data, offset + 16)
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

    program_headers = []
    for index in range(e_phnum):
        pos = offset + e_phoff + index * e_phentsize
        if pos + 32 > len(data):
            break
        p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align = struct.unpack_from(
            "<IIIIIIII", data, pos
        )
        program_headers.append(
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

    section_headers_raw = []
    for index in range(e_shnum):
        pos = offset + e_shoff + index * e_shentsize
        if pos + 40 > len(data):
            break
        section_headers_raw.append(struct.unpack_from("<IIIIIIIIII", data, pos))

    shstr = b""
    if 0 <= e_shstrndx < len(section_headers_raw):
        sh = section_headers_raw[e_shstrndx]
        sh_offset, sh_size = sh[4], sh[5]
        shstr = data[offset + sh_offset : offset + sh_offset + sh_size]

    def section_name(name_off: int) -> str:
        if name_off >= len(shstr):
            return ""
        end = shstr.find(b"\x00", name_off)
        if end < 0:
            end = len(shstr)
        return shstr[name_off:end].decode("ascii", "replace")

    section_headers = []
    for sh in section_headers_raw:
        sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info, sh_addralign, sh_entsize = sh
        section_headers.append(
            {
                "name": section_name(sh_name),
                "type": sh_type,
                "flags": sh_flags,
                "addr": sh_addr,
                "offset": sh_offset,
                "size": sh_size,
                "align": sh_addralign,
            }
        )

    return {
        "elf_offset": offset,
        "type": e_type,
        "machine": e_machine,
        "version": e_version,
        "entry": e_entry,
        "program_header_offset": e_phoff,
        "section_header_offset": e_shoff,
        "flags": e_flags,
        "program_header_count": e_phnum,
        "section_header_count": e_shnum,
        "section_header_string_index": e_shstrndx,
        "program_headers": program_headers,
        "section_headers": section_headers,
    }


def hexify(value: int) -> str:
    return f"0x{value:x}"


def write_markdown(report: dict, out_path: Path) -> None:
    elf = report["elf"]
    lines = ["# ShpApp embedded ELF survey", ""]
    lines.append(f"Input: `{report['input']}`")
    lines.append(f"File size: `{hexify(report['file_size'])}` ({report['file_size']} bytes)")
    lines.append(f"FimBIN magic: `{report['fimbin_magic']}`")
    lines.append(f"Header size-like word at `0x78`: `{hexify(report['header_word_0x78'])}`")
    lines.append(f"Header path-like UTF-16 string at `0x8c`: `{report['header_path_0x8c']}`")
    lines.append("")
    lines.append("## ELF")
    lines.append("")
    lines.append(f"- Offset: `{hexify(elf['elf_offset'])}`")
    lines.append(f"- Machine: `{hexify(elf['machine'])}`")
    lines.append(f"- Entry: `{hexify(elf['entry'])}`")
    lines.append(f"- Flags: `{hexify(elf['flags'])}`")
    lines.append(f"- Program headers: {elf['program_header_count']}")
    lines.append(f"- Section headers: {elf['section_header_count']}")
    lines.append("")
    lines.append("## Program Headers")
    lines.append("")
    lines.append("| Type | Offset | VMA | File size | Mem size | Flags | Align |")
    lines.append("| ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
    for ph in elf["program_headers"]:
        lines.append(
            "| `{}` | `{}` | `{}` | `{}` | `{}` | `{}` | `{}` |".format(
                hexify(ph["type"]),
                hexify(ph["offset"]),
                hexify(ph["vaddr"]),
                hexify(ph["filesz"]),
                hexify(ph["memsz"]),
                hexify(ph["flags"]),
                hexify(ph["align"]),
            )
        )
    lines.append("")
    lines.append("## Section Headers")
    lines.append("")
    lines.append("| Name | Address | Offset | Size | Flags |")
    lines.append("| --- | ---: | ---: | ---: | ---: |")
    for sh in elf["section_headers"]:
        lines.append(
            f"| `{sh['name']}` | `{hexify(sh['addr'])}` | `{hexify(sh['offset'])}` | "
            f"`{hexify(sh['size'])}` | `{hexify(sh['flags'])}` |"
        )
    lines.append("")
    out_path.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("--out", type=Path, default=Path("out/shpapp_elf_survey"))
    args = parser.parse_args()

    data = args.input.read_bytes()
    elf_offset = data.find(b"\x7fELF")
    if elf_offset < 0:
        raise SystemExit("No embedded ELF found")

    report = {
        "input": str(args.input),
        "file_size": len(data),
        "fimbin_magic": read_c_utf16le(data, 0, 32),
        "header_word_0x78": struct.unpack_from("<I", data, 0x78)[0],
        "header_path_0x8c": read_c_utf16le(data, 0x8c, 64),
        "elf": parse_elf(data, elf_offset),
    }

    args.out.mkdir(parents=True, exist_ok=True)
    json_path = args.out / "shpapp_elf_survey.json"
    md_path = args.out / "shpapp_elf_survey.md"
    json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    write_markdown(report, md_path)
    print(f"Wrote {json_path}")
    print(f"Wrote {md_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
