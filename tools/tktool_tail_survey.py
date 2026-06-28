#!/usr/bin/env python3
"""Summarize Samsung/TkTool-style trailer records in local firmware images.

The script is intentionally read-only. It records short offsets and selected
fields only; it does not copy firmware bytes into the repository.
"""

from __future__ import annotations

import argparse
import json
import re
import struct
from pathlib import Path


DEFAULT_NAMES = [
    "bcmboot.img",
    "boot2.img",
    "amss.bin",
    "apps_compressed.bin",
]

NEEDLES = {
    "cd_ab_cd_ab": bytes.fromhex("cd ab cd ab"),
    "f7_94_cd_ab": bytes.fromhex("f7 94 cd ab"),
    "TkToolVer": b"TkToolVer:",
    "B5310": b"B5310",
    "B5310U": b"B5310U",
    "img": b"img\0",
    "bin": b"bin\0",
}


def all_offsets(data: bytes, needle: bytes, limit: int = 16) -> list[int]:
    offsets: list[int] = []
    pos = 0
    while len(offsets) < limit:
        found = data.find(needle, pos)
        if found < 0:
            break
        offsets.append(found)
        pos = found + 1
    return offsets


def ascii_at(data: bytes, offset: int, max_len: int = 64) -> str:
    if offset < 0:
        return ""
    end = offset
    while end < len(data) and data[end] not in (0, 10, 13) and end - offset < max_len:
        end += 1
    raw = data[offset:end]
    if not raw:
        return ""
    if not re.fullmatch(rb"[ -~]+", raw):
        return ""
    return raw.decode("ascii", "replace")


def le32_words(data: bytes, offset: int, count: int = 12) -> list[str]:
    words: list[str] = []
    for index in range(count):
        pos = offset + index * 4
        if pos + 4 > len(data):
            break
        words.append(f"0x{struct.unpack_from('<I', data, pos)[0]:08x}")
    return words


def analyze(path: Path) -> dict:
    data = path.read_bytes()
    hits = {name: all_offsets(data, needle) for name, needle in NEEDLES.items()}
    marker_offsets = hits["cd_ab_cd_ab"]
    marker = marker_offsets[-1] if marker_offsets else -1
    context_start = max(0, marker - 16) if marker >= 0 else -1

    strings: dict[str, str] = {}
    for key in ("B5310", "B5310U", "TkToolVer"):
        offsets = hits[key]
        if offsets:
            strings[key] = ascii_at(data, offsets[-1])

    return {
        "name": path.name,
        "size": len(data),
        "size_hex": f"0x{len(data):x}",
        "marker_offsets": {key: [f"0x{x:x}" for x in value] for key, value in hits.items() if value},
        "last_cd_ab_cd_ab": f"0x{marker:x}" if marker >= 0 else None,
        "last_marker_from_end": len(data) - marker if marker >= 0 else None,
        "context_words_from_marker_minus_16": le32_words(data, context_start) if context_start >= 0 else [],
        "selected_strings": strings,
    }


def write_markdown(report: list[dict], out_path: Path) -> None:
    lines = ["# TkTool tail survey", ""]
    lines.append("| File | Size | Last `cd ab cd ab` | From end | Selected strings |")
    lines.append("| --- | ---: | ---: | ---: | --- |")
    for item in report:
        strings = ", ".join(f"`{v}`" for v in item["selected_strings"].values())
        lines.append(
            f"| `{item['name']}` | {item['size']} | `{item['last_cd_ab_cd_ab']}` | "
            f"{item['last_marker_from_end']} | {strings} |"
        )
    lines.append("")
    lines.append("## Context words")
    lines.append("")
    for item in report:
        lines.append(f"### {item['name']}")
        lines.append("")
        lines.append("Words from 16 bytes before the last `cd ab cd ab` marker:")
        lines.append("")
        lines.append("```text")
        lines.append(" ".join(item["context_words_from_marker_minus_16"]))
        lines.append("```")
        lines.append("")
    out_path.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input_dir", type=Path)
    parser.add_argument("--out", type=Path, default=Path("out/tktool_tail_survey"))
    parser.add_argument("--names", nargs="*", default=DEFAULT_NAMES)
    args = parser.parse_args()

    input_dir = args.input_dir.expanduser().resolve()
    args.out.mkdir(parents=True, exist_ok=True)

    report = []
    for name in args.names:
        path = input_dir / name
        if path.exists():
            report.append(analyze(path))

    json_path = args.out / "tktool_tail_survey.json"
    md_path = args.out / "tktool_tail_survey.md"
    json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    write_markdown(report, md_path)
    print(f"Wrote {json_path}")
    print(f"Wrote {md_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
