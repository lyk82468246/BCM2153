#!/usr/bin/env python3
"""Scan firmware containers for common resource magic values.

This is a lightweight indexer for architecture work. It reports counts and a few
offsets only; it does not extract embedded resources.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path


MAGICS = {
    "IMRC": b"IMRC",
    "FimBIN_utf16le": "FimBIN".encode("utf-16le"),
    "PFSBIN_utf16le": "PFSBIN".encode("utf-16le"),
    "ELF": b"\x7fELF",
    "PNG": b"\x89PNG\r\n\x1a\n",
    "GIF87a": b"GIF87a",
    "GIF89a": b"GIF89a",
    "JFIF": b"JFIF",
    "XML": b"<?xml",
    "BWFXML": b"<BWFXML",
    "ZIP_local": b"PK\x03\x04",
    "SWF_FWS": b"FWS",
    "SWF_CWS": b"CWS",
    "zlib_78_01": b"\x78\x01",
    "zlib_78_9c": b"\x78\x9c",
    "zlib_78_da": b"\x78\xda",
}


def find_offsets(data: bytes, needle: bytes, sample_limit: int = 16) -> tuple[int, list[int]]:
    count = 0
    offsets: list[int] = []
    pos = 0
    while True:
        found = data.find(needle, pos)
        if found < 0:
            break
        count += 1
        if len(offsets) < sample_limit:
            offsets.append(found)
        pos = found + 1
    return count, offsets


def analyze(path: Path) -> dict:
    data = path.read_bytes()
    hits = {}
    for name, magic in MAGICS.items():
        count, offsets = find_offsets(data, magic)
        if count:
            hits[name] = {"count": count, "sample_offsets": [f"0x{x:x}" for x in offsets]}
    return {"name": path.name, "size": len(data), "size_hex": f"0x{len(data):x}", "hits": hits}


def write_markdown(report: list[dict], out_path: Path) -> None:
    lines = ["# Resource magic survey", ""]
    for item in report:
        lines.append(f"## {item['name']}")
        lines.append("")
        lines.append(f"Size: `{item['size_hex']}` ({item['size']} bytes)")
        lines.append("")
        lines.append("| Magic | Count | Sample offsets |")
        lines.append("| --- | ---: | --- |")
        for name, hit in item["hits"].items():
            offsets = ", ".join(f"`{x}`" for x in hit["sample_offsets"][:8])
            lines.append(f"| `{name}` | {hit['count']} | {offsets} |")
        lines.append("")
    out_path.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inputs", nargs="+", type=Path)
    parser.add_argument("--out", type=Path, default=Path("out/resource_magic_survey"))
    args = parser.parse_args()

    report = [analyze(path) for path in args.inputs]
    args.out.mkdir(parents=True, exist_ok=True)
    json_path = args.out / "resource_magic_survey.json"
    md_path = args.out / "resource_magic_survey.md"
    json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    write_markdown(report, md_path)
    print(f"Wrote {json_path}")
    print(f"Wrote {md_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
