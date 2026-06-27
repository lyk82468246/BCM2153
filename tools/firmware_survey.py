#!/usr/bin/env python3
"""Read-only firmware survey helper for BCM2153 sample sets.

The script intentionally avoids copying input binaries into the output
directory. It records hashes, short evidence snippets, entropy summaries,
possible ARM vector tables, BABEFACE header candidates, and plausible address
constants that help bootstrap manual reverse engineering.
"""

from __future__ import annotations

import argparse
import collections
import hashlib
import json
import math
import os
import re
import struct
from pathlib import Path
from typing import Iterable


INTERESTING_EXTS = {
    ".bin",
    ".img",
    ".ffs",
    ".pfs",
    ".rc1",
    ".rc2",
    ".app",
}

CORE_IMAGE_NAMES = {
    "amss.bin",
    "apps_compressed.bin",
    "bcmboot.img",
    "boot2.img",
    "drom_dsp.img",
    "patch_dsp.img",
    "sysparm_dep.img",
    "sysparm_ind.img",
}

DEFAULT_DEEP_SIZE_LIMIT = 8 * 1024 * 1024

INTERESTING_PATTERNS = [
    re.compile(rb"BCM2153", re.IGNORECASE),
    re.compile(rb"Hedge Platform", re.IGNORECASE),
    re.compile(rb"Nucleus PLUS", re.IGNORECASE),
    re.compile(rb"Nand Boot", re.IGNORECASE),
    re.compile(rb"Boot2", re.IGNORECASE),
    re.compile(rb"Download mode", re.IGNORECASE),
    re.compile(rb"ARM memory", re.IGNORECASE),
    re.compile(rb"Chip ID", re.IGNORECASE),
    re.compile(rb"SW Version", re.IGNORECASE),
    re.compile(rb"Patch Version", re.IGNORECASE),
    re.compile(rb"TkToolVer", re.IGNORECASE),
    re.compile(rb"GT-B5310", re.IGNORECASE),
]


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = collections.Counter(data)
    total = len(data)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def entropy_windows(data: bytes, window: int = 65536) -> list[dict[str, float | int]]:
    rows = []
    for off in range(0, len(data), window):
        chunk = data[off : off + window]
        rows.append({"offset": off, "size": len(chunk), "entropy": round(entropy(chunk), 4)})
    return rows


def printable_strings(data: bytes, min_len: int = 6) -> Iterable[tuple[int, str]]:
    pattern = rb"[ -~]{%d,}" % min_len
    for match in re.finditer(pattern, data):
        raw = match.group(0)
        try:
            yield match.start(), raw.decode("ascii", "replace")
        except UnicodeDecodeError:
            continue


def interesting_strings(data: bytes) -> list[dict[str, int | str]]:
    found: list[dict[str, int | str]] = []
    seen: set[tuple[int, str]] = set()
    for off, text in printable_strings(data, 6):
        raw = text.encode("ascii", "replace")
        if any(p.search(raw) for p in INTERESTING_PATTERNS):
            item = (off, text[:160])
            if item not in seen:
                seen.add(item)
                found.append({"offset": off, "text": text[:160]})
    return found[:80]


def interesting_strings_fast(data: bytes) -> list[dict[str, int | str]]:
    found: list[dict[str, int | str]] = []
    seen: set[tuple[int, str]] = set()
    for pattern in INTERESTING_PATTERNS:
        pos = 0
        while len(found) < 80:
            match = pattern.search(data, pos)
            if not match:
                break
            start = match.start()
            lo = start
            while lo > 0 and 32 <= data[lo - 1] <= 126:
                lo -= 1
            hi = match.end()
            while hi < len(data) and 32 <= data[hi] <= 126 and hi - lo < 160:
                hi += 1
            text = data[lo:hi].decode("ascii", "replace")
            item = (lo, text)
            if item not in seen:
                seen.add(item)
                found.append({"offset": lo, "text": text})
            pos = match.end()
    return sorted(found, key=lambda item: int(item["offset"]))[:80]


def count_source_paths(data: bytes) -> dict[str, int]:
    # Windows-style source paths are common in this firmware. Count only path
    # families, not every string, to keep reports compact.
    counts: dict[str, int] = collections.Counter()
    for _off, text in printable_strings(data, 8):
        lowered = text.lower()
        if "\\" not in lowered:
            continue
        if "nucleus\\src" in lowered:
            counts["nucleus/src"] += 1
        elif "bcm2153\\src" in lowered:
            counts["bcm2153/src"] += 1
        elif "capi2" in lowered:
            counts["capi2"] += 1
        elif "src\\" in lowered:
            counts["generic src"] += 1
    return dict(sorted(counts.items()))


def is_arm_ldr_pc(word: int) -> bool:
    # LDR pc, [pc, #imm] in ARM mode, commonly used in vector tables:
    # cond 0101 1001 1111 0000 1111 imm12 => 0xe59ff000 mask.
    return (word & 0xFFFFF000) == 0xE59FF000


def is_arm_branch(word: int) -> bool:
    return (word & 0xFF000000) == 0xEA000000


def vector_score(words: list[int]) -> int:
    score = 0
    ldr_count = 0
    for word in words[:8]:
        if is_arm_ldr_pc(word):
            score += 1
            ldr_count += 1
        elif is_arm_branch(word):
            score += 1
        elif word in (0xE1A00000, 0x00000000):
            score += 0
        else:
            score -= 1
    if ldr_count >= 4:
        score += 1
    return score


def scan_arm_vectors(data: bytes) -> list[dict[str, int | str]]:
    hits = []
    limit = max(0, len(data) - 64)
    for off in range(0, limit, 4):
        words = list(struct.unpack_from("<8I", data, off))
        score = vector_score(words)
        if score >= 5:
            hits.append(
                {
                    "offset": off,
                    "score": score,
                    "words": " ".join(f"{w:08x}" for w in words),
                }
            )
            if len(hits) >= 64:
                break
    return hits


def scan_babeface(data: bytes) -> list[dict[str, int | str]]:
    hits = []
    needle = struct.pack("<I", 0xBABEFACE)
    start = 0
    while True:
        off = data.find(needle, start)
        if off < 0:
            break
        context = data[off : off + 64]
        words = []
        for i in range(0, len(context) - 3, 4):
            words.append(struct.unpack_from("<I", context, i)[0])
        hits.append({"offset": off, "words": " ".join(f"{w:08x}" for w in words[:12])})
        start = off + 4
        if len(hits) >= 32:
            break
    return hits


def plausible_addr(word: int) -> bool:
    ranges = [
        (0x00000000, 0x10000000),
        (0x20000000, 0x30000000),
        (0x80000000, 0x90000000),
    ]
    if word % 4 != 0:
        return False
    return any(lo <= word < hi for lo, hi in ranges)


def address_constants(data: bytes) -> list[dict[str, int]]:
    counts: collections.Counter[int] = collections.Counter()
    for off in range(0, len(data) - 3, 4):
        word = struct.unpack_from("<I", data, off)[0]
        if plausible_addr(word):
            counts[word] += 1
    return [{"address": addr, "count": count} for addr, count in counts.most_common(40)]


def analyze_file(path: Path, deep_all: bool = False) -> dict:
    data = path.read_bytes()
    ent = entropy_windows(data)
    first_entropy = ent[0]["entropy"] if ent else 0.0
    deep = deep_all or path.name in CORE_IMAGE_NAMES or len(data) <= DEFAULT_DEEP_SIZE_LIMIT
    return {
        "name": path.name,
        "path": str(path),
        "size": len(data),
        "scan_mode": "deep" if deep else "shallow",
        "sha256": sha256_file(path),
        "first_16": data[:16].hex(" "),
        "first_64": data[:64].hex(" "),
        "entropy": {
            "whole_file": round(entropy(data), 4),
            "first_window": first_entropy,
            "windows": ent[:64],
        },
        "arm_vector_candidates": scan_arm_vectors(data) if deep else [],
        "babeface_candidates": scan_babeface(data),
        "address_constants": address_constants(data) if deep else [],
        "interesting_strings": interesting_strings(data) if deep else interesting_strings_fast(data),
        "source_path_counts": count_source_paths(data) if deep else {},
    }


def discover_files(root: Path) -> list[Path]:
    files = []
    for path in sorted(root.iterdir()):
        if path.is_file() and path.suffix.lower() in INTERESTING_EXTS:
            files.append(path)
    return files


def fmt_hex(value: int) -> str:
    return f"0x{value:08x}"


def write_markdown(report: dict, out_path: Path) -> None:
    lines: list[str] = []
    lines.append("# BCM2153 firmware survey")
    lines.append("")
    lines.append(f"Input directory: `{report['input_dir']}`")
    lines.append("")
    lines.append("## Files")
    lines.append("")
    lines.append("| File | Scan | Size | SHA-256 | Entropy | First 16 bytes |")
    lines.append("| --- | --- | ---: | --- | ---: | --- |")
    for item in report["files"]:
        lines.append(
            "| `{name}` | {scan} | {size} | `{sha}` | {ent:.4f} | `{first}` |".format(
                name=item["name"],
                scan=item.get("scan_mode", "deep"),
                size=item["size"],
                sha=item["sha256"],
                ent=item["entropy"]["whole_file"],
                first=item["first_16"],
            )
        )
    lines.append("")
    lines.append("## Evidence snippets")
    lines.append("")
    for item in report["files"]:
        lines.append(f"### {item['name']}")
        lines.append("")
        if item["babeface_candidates"]:
            lines.append("BABEFACE candidates:")
            for hit in item["babeface_candidates"][:8]:
                lines.append(f"- `{fmt_hex(hit['offset'])}` words `{hit['words']}`")
            lines.append("")
        if item["arm_vector_candidates"]:
            lines.append("ARM vector candidates:")
            for hit in item["arm_vector_candidates"][:8]:
                lines.append(
                    f"- `{fmt_hex(hit['offset'])}` score {hit['score']} words `{hit['words']}`"
                )
            lines.append("")
        if item["address_constants"]:
            lines.append("Common plausible address constants:")
            for row in item["address_constants"][:12]:
                lines.append(f"- `{fmt_hex(row['address'])}` count {row['count']}")
            lines.append("")
        if item["interesting_strings"]:
            lines.append("Selected strings:")
            for row in item["interesting_strings"][:16]:
                escaped = row["text"].replace("`", "'")
                lines.append(f"- `{fmt_hex(row['offset'])}` `{escaped}`")
            lines.append("")
        if item["source_path_counts"]:
            lines.append("Source path family counts:")
            for key, count in item["source_path_counts"].items():
                lines.append(f"- `{key}`: {count}")
            lines.append("")
    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input_dir", type=Path, help="Directory containing local firmware samples")
    parser.add_argument("--out", type=Path, default=Path("out/firmware_survey"))
    parser.add_argument("--deep-all", action="store_true", help="run expensive scans over every image")
    args = parser.parse_args()

    input_dir = args.input_dir.expanduser().resolve()
    if not input_dir.is_dir():
        raise SystemExit(f"Input directory does not exist: {input_dir}")

    out_dir = args.out
    out_dir.mkdir(parents=True, exist_ok=True)

    files = discover_files(input_dir)
    report = {
        "input_dir": str(input_dir),
        "files": [analyze_file(path, deep_all=args.deep_all) for path in files],
    }

    json_path = out_dir / "firmware_survey.json"
    md_path = out_dir / "firmware_survey.md"
    json_path.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    write_markdown(report, md_path)

    print(f"Wrote {json_path}")
    print(f"Wrote {md_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
