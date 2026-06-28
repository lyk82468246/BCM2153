#!/usr/bin/env python3
"""Survey AMSS service/debug interface string clues.

The script records short strings, offsets, and coarse categories only. It does
not disassemble, decompile, or extract proprietary code/data.
"""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter, defaultdict
from pathlib import Path


DEFAULT_BASE = 0x80300000
STRING_RE = re.compile(rb"[ -~]{4,}")

CATEGORIES = {
    "memory_debug": [
        rb"ARM memory",
        rb"First parameter should be 1, 2 or 3, then address",
    ],
    "usb_at_test": [
        rb"ATCmd_MUSB",
        rb"USB Test",
        rb"USB VID",
        rb"USB PID",
        rb"Switch ATC to UART",
        rb"LOGFORMAT_",
    ],
    "capi2_at_ipc": [
        rb"CAPI2AT_Q",
        rb"CP2ATC_Q",
        rb"CAPI2_atc_entry",
        rb"Capi2AtRespCallbackFunc",
        rb"CAPI2_SYS_ClientInit",
        rb"CAPI2_SYS_ClientRun",
    ],
    "capi2_ffs": [
        rb"CAPI2_FFS_Control",
    ],
    "usb_acm": [
        rb"JusbAdapter_acm",
        rb"jusbAdapter_acm",
        rb"brcm_usb_pid",
        rb"SetDTR",
        rb"SetDCD",
    ],
    "calibration_nv": [
        rb":CAL ACK",
        rb"NVRAM",
        rb"sysparm",
        rb"Calibration",
        rb"CHECKSUM_WRITE",
        rb"BT_DEVICE_ADDR",
        rb"BATTVOL",
        rb"CDAC",
    ],
    "download_diag": [
        rb"Download",
        rb"DL Mode",
        rb"diag",
        rb"DIAG",
        rb"mode :0=normal,1=cal,2=download",
    ],
    "trace_logging": [
        rb"trace",
        rb"TRACE",
    ],
}


def printable_strings(data: bytes, min_len: int) -> list[dict]:
    rows = []
    for match in STRING_RE.finditer(data):
        raw = match.group(0)
        if len(raw) < min_len:
            continue
        text = raw.decode("ascii", "replace")
        rows.append({"offset": match.start(), "text": text})
    return rows


def classify(text: str) -> list[str]:
    raw = text.encode("ascii", "replace")
    hits = []
    for category, needles in CATEGORIES.items():
        if any(needle.lower() in raw.lower() for needle in needles):
            hits.append(category)
    return hits


def snippet(text: str, limit: int) -> str:
    text = " ".join(text.split())
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


def source_hint(text: str) -> str:
    lowered = text.lower()
    if "\\" not in text:
        return ""
    if "capi2" in lowered:
        return "capi2"
    if "usb" in lowered or "jusb" in lowered:
        return "usb"
    if "at" in lowered:
        return "at"
    if "cal" in lowered or "nv" in lowered or "sysparm" in lowered:
        return "cal_nv"
    return "path"


def cluster_hits(hits: list[dict], window: int) -> list[dict]:
    if not hits:
        return []
    sorted_hits = sorted(hits, key=lambda x: x["offset"])
    clusters = []
    current = [sorted_hits[0]]
    start = sorted_hits[0]["offset"]
    for item in sorted_hits[1:]:
        if item["offset"] - start <= window:
            current.append(item)
            continue
        clusters.append(current)
        current = [item]
        start = item["offset"]
    clusters.append(current)

    out = []
    for items in clusters:
        cats = Counter(cat for item in items for cat in item["categories"])
        out.append(
            {
                "start_offset": items[0]["offset"],
                "end_offset": items[-1]["offset"],
                "count": len(items),
                "categories": cats.most_common(),
                "samples": items[:8],
            }
        )
    out.sort(key=lambda x: (x["count"], len(x["categories"])), reverse=True)
    return out


def analyze(path: Path, base: int, min_len: int, snippet_limit: int) -> dict:
    data = path.read_bytes()
    strings = printable_strings(data, min_len)
    category_hits: dict[str, list[dict]] = defaultdict(list)
    source_hints = Counter()
    all_hits = []
    for item in strings:
        cats = classify(item["text"])
        hint = source_hint(item["text"])
        if hint:
            source_hints[hint] += 1
        if not cats:
            continue
        row = {
            "offset": item["offset"],
            "vaddr": base + item["offset"],
            "text": snippet(item["text"], snippet_limit),
            "categories": cats,
        }
        all_hits.append(row)
        for cat in cats:
            category_hits[cat].append(row)

    by_category = {}
    for category, hits in category_hits.items():
        by_category[category] = {
            "count": len(hits),
            "samples": sorted(hits, key=lambda x: x["offset"])[:32],
        }

    return {
        "input": str(path),
        "base": base,
        "string_count": len(strings),
        "hit_count": len(all_hits),
        "source_hint_counts": source_hints.most_common(),
        "categories": dict(sorted(by_category.items())),
        "clusters": cluster_hits(all_hits, 0x400),
    }


def write_markdown(report: dict, out_path: Path) -> None:
    lines = ["# AMSS service/debug string survey", ""]
    lines.append(f"Input: `{Path(report['input']).name}`")
    lines.append(f"Assumed base: `0x{report['base']:x}`")
    lines.append(f"Printable strings scanned: {report['string_count']}")
    lines.append(f"Categorized hits: {report['hit_count']}")
    lines.append("")
    lines.append("## Categories")
    lines.append("")
    lines.append("| Category | Hits | First samples |")
    lines.append("| --- | ---: | --- |")
    for category, item in report["categories"].items():
        samples = "; ".join(f"`0x{s['offset']:x}` {s['text']}" for s in item["samples"][:4])
        lines.append(f"| `{category}` | {item['count']} | {samples} |")
    lines.append("")
    lines.append("## Dense Clusters")
    lines.append("")
    lines.append("| Offset range | Hits | Categories | Samples |")
    lines.append("| ---: | ---: | --- | --- |")
    for cluster in report["clusters"][:12]:
        cats = ", ".join(f"`{cat}`:{count}" for cat, count in cluster["categories"])
        samples = "; ".join(f"`0x{s['offset']:x}` {s['text']}" for s in cluster["samples"][:4])
        lines.append(
            f"| `0x{cluster['start_offset']:x}`-`0x{cluster['end_offset']:x}` | "
            f"{cluster['count']} | {cats} | {samples} |"
        )
    lines.append("")
    for category, item in report["categories"].items():
        lines.append(f"## {category}")
        lines.append("")
        lines.append("| Offset | VMA | Text |")
        lines.append("| ---: | ---: | --- |")
        for hit in item["samples"][:16]:
            lines.append(f"| `0x{hit['offset']:x}` | `0x{hit['vaddr']:x}` | `{hit['text']}` |")
        lines.append("")
    out_path.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("--base", type=lambda x: int(x, 0), default=DEFAULT_BASE)
    parser.add_argument("--min-len", type=int, default=4)
    parser.add_argument("--snippet-limit", type=int, default=96)
    parser.add_argument("--out", type=Path, default=Path("out/amss_service_survey"))
    args = parser.parse_args()

    report = analyze(args.input, args.base, args.min_len, args.snippet_limit)
    args.out.mkdir(parents=True, exist_ok=True)
    json_path = args.out / "amss_service_survey.json"
    md_path = args.out / "amss_service_survey.md"
    json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    write_markdown(report, md_path)
    print(f"Wrote {json_path}")
    print(f"Wrote {md_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
