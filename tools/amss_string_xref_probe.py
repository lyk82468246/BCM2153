#!/usr/bin/env python3
"""Find raw AMSS references to selected service/debug strings.

This is a lightweight pre-Ghidra helper. It searches for little-endian runtime
addresses of important strings and writes only offsets, addresses, and small
local disassembly windows into ignored out/ storage.
"""

from __future__ import annotations

import argparse
import json
import shutil
import struct
import subprocess
from pathlib import Path


DEFAULT_BASE = 0x80300000
DEFAULT_REF_BASES = [0x00000000, 0x80000000, 0x80300000, 0x80400000]
DEFAULT_TARGETS = [
    (0x18840, "memory_debug_i32"),
    (0x18868, "memory_debug_char"),
    (0x18890, "memory_debug_i16"),
    (0x188B8, "memory_debug_read_help"),
    (0x18928, "memory_debug_write_help"),
    (0x2370, "ATCmd_MUSBTEST_default"),
    (0x260C, "ATCmd_MUSBTST_case_1"),
    (0x2684, "ATCmd_MUSBTST_case_21_cal"),
    (0x2768, "ATCmd_MUSBTST_case_40_uart"),
    (0x27A4, "ATCmd_MUSBTST_get_vid"),
    (0x291C, "ATCmd_MUSBTST_set_pid"),
    (0x597C, "CAPI2AT_Q"),
    (0x5A54, "CP2ATC_Q"),
    (0xBDE0, "CAPI2_atc_entry"),
    (0x11CA4, "CAPI2_FFS_Control_enter"),
    (0x11CE0, "CAPI2_FFS_Control_fail"),
    (0x11D00, "CAPI2_FFS_Control_exit"),
    (0x17534, "download_script_prompt"),
    (0x72764, "normal_cal_download_mode"),
]


def u32le(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def read_ascii_at(data: bytes, offset: int, limit: int = 96) -> str:
    end = offset
    while end < len(data) and 32 <= data[end] <= 126 and end - offset < limit:
        end += 1
    return data[offset:end].decode("ascii", "replace")


def find_u32_refs(data: bytes, value: int) -> list[int]:
    needle = struct.pack("<I", value)
    refs = []
    pos = 0
    while True:
        pos = data.find(needle, pos)
        if pos < 0:
            break
        if pos % 4 == 0:
            refs.append(pos)
        pos += 1
    return refs


def nearest_ascii_before(data: bytes, offset: int, limit: int = 128) -> str:
    start = max(0, offset - limit)
    window = data[start:offset]
    runs = []
    i = 0
    while i < len(window):
        if 32 <= window[i] <= 126:
            j = i
            while j < len(window) and 32 <= window[j] <= 126:
                j += 1
            if j - i >= 4:
                runs.append(window[i:j].decode("ascii", "replace"))
            i = j
        else:
            i += 1
    return runs[-1] if runs else ""


def run_objdump(blob: Path, vma: int, mode: str, max_lines: int) -> list[str]:
    objdump = shutil.which("arm-none-eabi-objdump")
    if not objdump:
        return []
    cmd = [objdump, "-D", "-b", "binary", "-marm", f"--adjust-vma=0x{vma:x}"]
    if mode == "thumb":
        cmd.extend(["-M", "force-thumb"])
    cmd.append(str(blob))
    proc = subprocess.run(cmd, check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    lines = []
    for line in proc.stdout.splitlines():
        line = line.rstrip()
        if line:
            lines.append(line)
    return lines[:max_lines]


def write_disasm_windows(data: bytes, out: Path, base: int, ref_offset: int, label: str, index: int) -> dict:
    start = max(0, ref_offset - 0x60)
    end = min(len(data), ref_offset + 0x40)
    blob = out / f"xref_{label}_{index:02d}_0x{ref_offset:x}.bin"
    blob.write_bytes(data[start:end])
    vma = base + start
    return {
        "window_offset": start,
        "window_vma": vma,
        "window_size": end - start,
        "thumb": run_objdump(blob, vma, "thumb", 28),
        "arm": run_objdump(blob, vma, "arm", 20),
    }


def parse_target(text: str) -> tuple[int, str]:
    if ":" in text:
        off, label = text.split(":", 1)
    else:
        off, label = text, text
    return int(off, 0), label


def analyze(path: Path, out: Path, base: int, ref_bases: list[int], targets: list[tuple[int, str]], max_refs: int) -> dict:
    data = path.read_bytes()
    out.mkdir(parents=True, exist_ok=True)
    rows = []
    for target_offset, label in targets:
        target_vma = base + target_offset
        all_refs = []
        seen = set()
        for ref_base in ref_bases:
            encoded_value = ref_base + target_offset
            refs = find_u32_refs(data, encoded_value)
            for ref in refs:
                key = (ref, encoded_value)
                if key in seen:
                    continue
                seen.add(key)
                all_refs.append((ref, ref_base, encoded_value))
        ref_rows = []
        for index, (ref, ref_base, encoded_value) in enumerate(all_refs[:max_refs]):
            ref_rows.append(
                {
                    "offset": ref,
                    "vma": base + ref,
                    "ref_base": ref_base,
                    "encoded_value": encoded_value,
                    "nearby_ascii_before": nearest_ascii_before(data, ref),
                    "disassembly": write_disasm_windows(data, out, base, ref, label, index),
                }
            )
        rows.append(
            {
                "label": label,
                "target_offset": target_offset,
                "target_vma": target_vma,
                "target_text": read_ascii_at(data, target_offset),
                "ref_count": len(all_refs),
                "refs": ref_rows,
            }
        )
    return {"input": str(path), "base": base, "ref_bases": ref_bases, "targets": rows}


def write_markdown(report: dict, out_path: Path) -> None:
    lines = ["# AMSS string xref probe", ""]
    lines.append(f"Input: `{Path(report['input']).name}`")
    lines.append(f"Assumed display base: `0x{report['base']:x}`")
    lines.append("Reference bases searched: " + ", ".join(f"`0x{x:x}`" for x in report["ref_bases"]))
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append("| Label | Target offset | Target VMA | Ref count | Text |")
    lines.append("| --- | ---: | ---: | ---: | --- |")
    for item in report["targets"]:
        text = item["target_text"].replace("|", " ")
        lines.append(
            f"| `{item['label']}` | `0x{item['target_offset']:x}` | `0x{item['target_vma']:x}` | "
            f"{item['ref_count']} | `{text}` |"
        )
    lines.append("")
    lines.append("## References")
    lines.append("")
    for item in report["targets"]:
        if not item["refs"]:
            continue
        lines.append(f"### {item['label']}")
        lines.append("")
        lines.append("| Ref offset | Ref VMA | Encoded value | Ref base | Nearby ASCII before ref |")
        lines.append("| ---: | ---: | ---: | ---: | --- |")
        for ref in item["refs"]:
            near = ref["nearby_ascii_before"].replace("|", " ")
            lines.append(f"| `0x{ref['offset']:x}` | `0x{ref['vma']:x}` | `0x{ref['encoded_value']:x}` | `0x{ref['ref_base']:x}` | `{near}` |")
        lines.append("")
    out_path.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("--base", type=lambda x: int(x, 0), default=DEFAULT_BASE)
    parser.add_argument("--target", action="append", default=[])
    parser.add_argument("--ref-base", action="append", type=lambda x: int(x, 0), default=[])
    parser.add_argument("--max-refs", type=int, default=8)
    parser.add_argument("--out", type=Path, default=Path("out/amss_string_xref_probe"))
    args = parser.parse_args()

    targets = [parse_target(item) for item in args.target] if args.target else DEFAULT_TARGETS
    ref_bases = args.ref_base if args.ref_base else DEFAULT_REF_BASES
    report = analyze(args.input, args.out, args.base, ref_bases, targets, args.max_refs)
    args.out.mkdir(parents=True, exist_ok=True)
    json_path = args.out / "amss_string_xref_probe.json"
    md_path = args.out / "amss_string_xref_probe.md"
    json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    write_markdown(report, md_path)
    print(f"Wrote {json_path}")
    print(f"Wrote {md_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
