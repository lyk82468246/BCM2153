#!/usr/bin/env python3
"""Probe AMSS AT command dispatch tables.

This script searches for fixed-size records whose command-name field points to
ASCII AT command names such as +CGDCONT or *MUSBTST. It writes metadata only:
record offsets, command strings, syntax strings, flags, and handler addresses.
"""

from __future__ import annotations

import argparse
import json
import re
import struct
from collections import Counter
from pathlib import Path


DEFAULT_BASE = 0x80300000
DEFAULT_STRIDE = 0x18
AT_NAME_RE = re.compile(rb"[+*][A-Z0-9?/_-]{2,31}")
ASCII_RE = re.compile(rb"[ -~]{1,160}")
INTERESTING_NAMES = {
    "+CGDCONT",
    "+CGDSCONT",
    "+CGATT",
    "+TEMPTEST",
    "*MTEST",
    "*APMTEST",
    "*MUSBTST",
    "*MTESTUSB",
    "*MADCTST",
    "*MDSPTST",
    "*MAUDLOG",
}
INTERESTING_HANDLER_WINDOWS = [
    (0x2000, 0x2c00, "usb_at_test_handlers"),
    (0x18700, 0x18a40, "memory_debug_strings_nearby"),
    (0x3cd000, 0x3e0000, "main_at_handlers"),
]


def u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def ptr_to_offset(value: int, base: int, size: int, clear_thumb: bool = False) -> int | None:
    if clear_thumb:
        value &= ~1
    if base <= value < base + size:
        return value - base
    return None


def c_string(data: bytes, offset: int, limit: int = 160) -> str:
    if offset < 0 or offset >= len(data):
        return ""
    end = offset
    while end < len(data) and data[end] != 0 and 32 <= data[end] <= 126 and end - offset < limit:
        end += 1
    return data[offset:end].decode("ascii", "replace")


def looks_like_at_name(text: str) -> bool:
    return bool(AT_NAME_RE.fullmatch(text.encode("ascii", "replace")))


def handler_bucket(handler_offset: int | None) -> str:
    if handler_offset is None:
        return "external_or_null"
    for start, end, name in INTERESTING_HANDLER_WINDOWS:
        if start <= handler_offset < end:
            return name
    return "other_image_code"


def parse_record(data: bytes, offset: int, base: int) -> dict | None:
    if offset + DEFAULT_STRIDE > len(data):
        return None
    words = [u32(data, offset + i * 4) for i in range(6)]
    name_off = ptr_to_offset(words[2], base, len(data))
    if name_off is None:
        return None
    name = c_string(data, name_off, 64)
    if not looks_like_at_name(name):
        return None

    syntax = ""
    syntax_off = ptr_to_offset(words[3], base, len(data))
    if syntax_off is not None:
        syntax = c_string(data, syntax_off, 160)
        if syntax and not ASCII_RE.fullmatch(syntax.encode("ascii", "replace")):
            syntax = ""

    handler_raw = words[5]
    handler_off = ptr_to_offset(handler_raw, base, len(data), clear_thumb=True)
    return {
        "record_offset": offset,
        "record_vma": base + offset,
        "pre_id": words[0],
        "flags": words[1],
        "name_ptr": words[2],
        "name_offset": name_off,
        "name": name,
        "syntax_ptr": words[3],
        "syntax_offset": syntax_off,
        "syntax": syntax,
        "kind": words[4],
        "handler_ptr": handler_raw,
        "handler_vma": handler_raw & ~1,
        "handler_offset": handler_off,
        "handler_mode": "thumb" if handler_raw & 1 else "arm_or_data",
        "handler_bucket": handler_bucket(handler_off),
    }


def scan_records(data: bytes, base: int) -> list[dict]:
    rows = []
    for offset in range(0, len(data) - DEFAULT_STRIDE, 4):
        row = parse_record(data, offset, base)
        if row is not None:
            rows.append(row)
    rows.sort(key=lambda x: x["record_offset"])
    return rows


def cluster_records(rows: list[dict], stride: int) -> list[dict]:
    if not rows:
        return []
    clusters = []
    current = [rows[0]]
    for row in rows[1:]:
        if row["record_offset"] - current[-1]["record_offset"] == stride:
            current.append(row)
        else:
            clusters.append(current)
            current = [row]
    clusters.append(current)
    out = []
    for items in clusters:
        out.append(
            {
                "start_offset": items[0]["record_offset"],
                "end_offset": items[-1]["record_offset"],
                "count": len(items),
                "first_names": [item["name"] for item in items[:12]],
                "handler_buckets": Counter(item["handler_bucket"] for item in items).most_common(),
            }
        )
    out.sort(key=lambda x: x["count"], reverse=True)
    return out


def analyze(path: Path, base: int) -> dict:
    data = path.read_bytes()
    records = scan_records(data, base)
    interesting = [row for row in records if row["name"] in INTERESTING_NAMES]
    return {
        "input": str(path),
        "base": base,
        "record_count": len(records),
        "clusters": cluster_records(records, DEFAULT_STRIDE),
        "interesting": interesting,
        "records": records,
    }


def fmt_hex(value: int | None) -> str:
    if value is None:
        return ""
    return f"0x{value:x}"


def write_markdown(report: dict, out_path: Path, max_records: int) -> None:
    lines = ["# AMSS AT command table probe", ""]
    lines.append(f"Input: `{Path(report['input']).name}`")
    lines.append(f"Assumed base: `0x{report['base']:x}`")
    lines.append(f"Candidate records: {report['record_count']}")
    lines.append("")
    lines.append("## Largest Contiguous Tables")
    lines.append("")
    lines.append("| Record range | Count | Handler buckets | First names |")
    lines.append("| ---: | ---: | --- | --- |")
    for cluster in report["clusters"][:12]:
        buckets = ", ".join(f"`{name}`:{count}" for name, count in cluster["handler_buckets"])
        names = ", ".join(f"`{name}`" for name in cluster["first_names"])
        lines.append(
            f"| `0x{cluster['start_offset']:x}`-`0x{cluster['end_offset']:x}` | "
            f"{cluster['count']} | {buckets} | {names} |"
        )
    lines.append("")
    lines.append("## Interesting Commands")
    lines.append("")
    lines.append("| Name | Record | Flags | Syntax | Handler | Mode | Bucket |")
    lines.append("| --- | ---: | ---: | --- | ---: | --- | --- |")
    for row in report["interesting"]:
        syntax = row["syntax"].replace("|", " ") if row["syntax"] else ""
        lines.append(
            f"| `{row['name']}` | `0x{row['record_offset']:x}` | `0x{row['flags']:x}` | "
            f"`{syntax}` | `0x{row['handler_vma']:x}` | `{row['handler_mode']}` | `{row['handler_bucket']}` |"
        )
    lines.append("")
    lines.append("## First Records")
    lines.append("")
    lines.append("| Name | Record | Name offset | Syntax | Handler | Mode | Bucket |")
    lines.append("| --- | ---: | ---: | --- | ---: | --- | --- |")
    for row in report["records"][:max_records]:
        syntax = row["syntax"].replace("|", " ") if row["syntax"] else ""
        lines.append(
            f"| `{row['name']}` | `0x{row['record_offset']:x}` | `0x{row['name_offset']:x}` | "
            f"`{syntax}` | `0x{row['handler_vma']:x}` | `{row['handler_mode']}` | `{row['handler_bucket']}` |"
        )
    out_path.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("--base", type=lambda x: int(x, 0), default=DEFAULT_BASE)
    parser.add_argument("--max-records", type=int, default=80)
    parser.add_argument("--out", type=Path, default=Path("out/amss_at_table_probe"))
    args = parser.parse_args()

    report = analyze(args.input, args.base)
    args.out.mkdir(parents=True, exist_ok=True)
    json_path = args.out / "amss_at_table_probe.json"
    md_path = args.out / "amss_at_table_probe.md"
    json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    write_markdown(report, md_path, args.max_records)
    print(f"Wrote {json_path}")
    print(f"Wrote {md_path}")
    print(f"Candidate AT records: {report['record_count']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
