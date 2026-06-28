#!/usr/bin/env python3
"""Probe Samsung/Broadcom IMRC resource containers without extracting assets.

The goal is to test layout hypotheses safely: header words, small tables, magic
offsets, and parseable embedded resource spans. Output is metadata only.
"""

from __future__ import annotations

import argparse
import json
import struct
from pathlib import Path


MAGICS = {
    "PNG": b"\x89PNG\r\n\x1a\n",
    "GIF87a": b"GIF87a",
    "GIF89a": b"GIF89a",
    "JFIF": b"JFIF",
    "XML": b"<?xml",
    "BWFXML": b"<BWFXML",
    "ZIP_local": b"PK\x03\x04",
    "SWF_FWS": b"FWS",
    "SWF_CWS": b"CWS",
}


def u32le(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def u32be(data: bytes, offset: int) -> int:
    return struct.unpack_from(">I", data, offset)[0]


def find_all(data: bytes, needle: bytes) -> list[int]:
    out: list[int] = []
    pos = 0
    while True:
        pos = data.find(needle, pos)
        if pos < 0:
            return out
        out.append(pos)
        pos += 1


def parse_png_span(data: bytes, offset: int) -> dict | None:
    if not data.startswith(MAGICS["PNG"], offset):
        return None
    pos = offset + 8
    chunks: list[str] = []
    while pos + 12 <= len(data):
        length = u32be(data, pos)
        ctype = data[pos + 4 : pos + 8]
        if any(c < 32 or c > 126 for c in ctype):
            return None
        name = ctype.decode("ascii", errors="replace")
        chunks.append(name)
        pos += 12 + length
        if name == "IEND":
            return {"end": pos, "size": pos - offset, "chunks": chunks[:12]}
        if len(chunks) > 128:
            return None
    return None


def parse_gif_span(data: bytes, offset: int) -> dict | None:
    if not (data.startswith(MAGICS["GIF87a"], offset) or data.startswith(MAGICS["GIF89a"], offset)):
        return None
    pos = offset + 6
    if pos + 7 > len(data):
        return None
    packed = data[pos + 4]
    pos += 7
    if packed & 0x80:
        pos += 3 * (2 ** ((packed & 0x07) + 1))
    while pos < len(data):
        marker = data[pos]
        pos += 1
        if marker == 0x3B:
            return {"end": pos, "size": pos - offset}
        if marker == 0x21:
            pos += 1
            while pos < len(data):
                size = data[pos]
                pos += 1
                if size == 0:
                    break
                pos += size
        elif marker == 0x2C:
            pos += 9
            if pos > len(data):
                return None
            packed = data[pos - 1]
            if packed & 0x80:
                pos += 3 * (2 ** ((packed & 0x07) + 1))
            if pos >= len(data):
                return None
            pos += 1
            while pos < len(data):
                size = data[pos]
                pos += 1
                if size == 0:
                    break
                pos += size
        else:
            return None
    return None


def parse_zip_local(data: bytes, offset: int) -> dict | None:
    if not data.startswith(MAGICS["ZIP_local"], offset) or offset + 30 > len(data):
        return None
    comp_size = u32le(data, offset + 18)
    uncomp_size = u32le(data, offset + 22)
    name_len = struct.unpack_from("<H", data, offset + 26)[0]
    extra_len = struct.unpack_from("<H", data, offset + 28)[0]
    name_start = offset + 30
    data_start = name_start + name_len + extra_len
    name = data[name_start : name_start + min(name_len, 80)].decode("utf-8", errors="replace")
    end = data_start + comp_size
    if end > len(data):
        return None
    return {"end": end, "size": end - offset, "name": name, "compressed": comp_size, "uncompressed": uncomp_size}


def parse_swf_span(data: bytes, offset: int) -> dict | None:
    if not (data.startswith(MAGICS["SWF_FWS"], offset) or data.startswith(MAGICS["SWF_CWS"], offset)):
        return None
    if offset + 8 > len(data):
        return None
    size = u32le(data, offset + 4)
    if size < 8 or offset + size > len(data):
        return None
    return {"end": offset + size, "size": size}


def parse_magic_span(data: bytes, name: str, offset: int) -> dict | None:
    if name == "PNG":
        return parse_png_span(data, offset)
    if name in {"GIF87a", "GIF89a"}:
        return parse_gif_span(data, offset)
    if name == "ZIP_local":
        return parse_zip_local(data, offset)
    if name in {"SWF_FWS", "SWF_CWS"}:
        return parse_swf_span(data, offset)
    return None


def summarize_header(data: bytes, words: int) -> list[dict]:
    result = []
    for index in range(min(words, len(data) // 4)):
        off = index * 4
        val = u32le(data, off)
        result.append({"offset": f"0x{off:04x}", "u32le": f"0x{val:08x}", "decimal": val})
    return result


def score_u32_pairs(data: bytes, start: int, end: int, file_size: int) -> dict:
    best: list[dict] = []
    for base in range(start, min(end, len(data) - 8) + 1, 4):
        pairs = []
        total = 0
        plausible = 0
        monotonic = 0
        previous = -1
        for off in range(base, min(end, len(data) - 8) + 1, 8):
            a = u32le(data, off)
            b = u32le(data, off + 4)
            total += 1
            if 0 < a < file_size and 0 < b < file_size and a + b <= file_size:
                plausible += 1
                if a >= previous:
                    monotonic += 1
                previous = a
                if len(pairs) < 8:
                    pairs.append({"table_offset": f"0x{off:x}", "a": f"0x{a:x}", "b": f"0x{b:x}", "a_plus_b": f"0x{a + b:x}"})
        if plausible:
            best.append({"base": f"0x{base:x}", "total_pairs": total, "plausible_pairs": plausible, "monotonic_plausible": monotonic, "samples": pairs})
    best.sort(key=lambda x: (x["plausible_pairs"], x["monotonic_plausible"]), reverse=True)
    return {"best_candidates": best[:12]}


def analyze(path: Path, header_words: int, sample_limit: int) -> dict:
    data = path.read_bytes()
    header = {
        "magic": data[:4].decode("ascii", errors="replace"),
        "file_size": len(data),
        "file_size_hex": f"0x{len(data):x}",
        "first_words": summarize_header(data, header_words),
    }
    if data[:4] == b"IMRC" and len(data) >= 0x18:
        header["version_word"] = f"0x{u32le(data, 4):08x}"
        header["table_or_header_size"] = f"0x{u32le(data, 8):x}"
        header["word_0x0c"] = f"0x{u32le(data, 0x0c):x}"
        header["word_0x10"] = f"0x{u32le(data, 0x10):x}"
        header["word_0x14"] = f"0x{u32le(data, 0x14):x}"

    magic_hits = {}
    for name, magic in MAGICS.items():
        offsets = find_all(data, magic)
        parseable_count = 0
        first_parseable: str | None = None
        for off in offsets:
            if parse_magic_span(data, name, off):
                parseable_count += 1
                if first_parseable is None:
                    first_parseable = f"0x{off:x}"
        samples = []
        for off in offsets[:sample_limit]:
            span = parse_magic_span(data, name, off)
            samples.append(
                {
                    "offset": f"0x{off:x}",
                    "mod4": off % 4,
                    "preceding_u32le": f"0x{u32le(data, off - 4):08x}" if off >= 4 else None,
                    "span": span,
                }
            )
        if offsets:
            magic_hits[name] = {
                "count": len(offsets),
                "parseable_count": parseable_count,
                "first_parseable": first_parseable,
                "samples": samples,
            }

    table_size = u32le(data, 8) if len(data) >= 12 else min(len(data), 0x1000)
    pair_score = score_u32_pairs(data, 0x18, min(table_size, 0x4000), len(data))

    return {"path": str(path), "header": header, "magic_hits": magic_hits, "pair_score": pair_score}


def write_markdown(report: dict, out_path: Path) -> None:
    lines = [
        "# IMRC probe",
        "",
        f"Input: `{Path(report['path']).name}`",
        "",
        "## Header",
        "",
        f"- File size: `{report['header']['file_size_hex']}` ({report['header']['file_size']} bytes)",
        f"- Magic: `{report['header']['magic']}`",
    ]
    for key in ("version_word", "table_or_header_size", "word_0x0c", "word_0x10", "word_0x14"):
        if key in report["header"]:
            lines.append(f"- {key}: `{report['header'][key]}`")
    lines.extend(["", "First words:", "", "| Offset | u32le | Decimal |", "| ---: | ---: | ---: |"])
    for item in report["header"]["first_words"]:
        lines.append(f"| `{item['offset']}` | `{item['u32le']}` | {item['decimal']} |")

    lines.extend(["", "## Magic Samples", ""])
    for name, hit in report["magic_hits"].items():
        lines.append(f"### {name}")
        lines.append("")
        lines.append(f"Parseable spans: {hit['parseable_count']}")
        if hit["first_parseable"]:
            lines.append(f"First parseable span: `{hit['first_parseable']}`")
        lines.append(f"Count: {hit['count']}")
        lines.append("")
        lines.append("| Offset | mod4 | Preceding u32le | Parsed span |")
        lines.append("| ---: | ---: | ---: | --- |")
        for sample in hit["samples"]:
            span = sample["span"]
            if span:
                span_text = ", ".join(f"{k}={v}" for k, v in span.items() if k != "chunks")
                if "chunks" in span:
                    span_text += f", chunks={','.join(span['chunks'])}"
            else:
                span_text = ""
            lines.append(f"| `{sample['offset']}` | {sample['mod4']} | `{sample['preceding_u32le']}` | {span_text} |")
        lines.append("")

    lines.extend(["## U32 Pair Hypothesis", ""])
    lines.append("Best offset/length-style candidates inside the declared table/header area:")
    lines.append("")
    lines.append("| Base | Plausible pairs | Monotonic plausible | First samples |")
    lines.append("| ---: | ---: | ---: | --- |")
    for cand in report["pair_score"]["best_candidates"]:
        samples = "; ".join(f"{s['a']}+{s['b']}={s['a_plus_b']}" for s in cand["samples"][:4])
        lines.append(f"| `{cand['base']}` | {cand['plausible_pairs']}/{cand['total_pairs']} | {cand['monotonic_plausible']} | {samples} |")
    lines.append("")
    out_path.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("--out", type=Path, default=Path("out/imrc_probe"))
    parser.add_argument("--header-words", type=int, default=64)
    parser.add_argument("--sample-limit", type=int, default=12)
    args = parser.parse_args()

    report = analyze(args.input, args.header_words, args.sample_limit)
    args.out.mkdir(parents=True, exist_ok=True)
    json_path = args.out / "imrc_probe.json"
    md_path = args.out / "imrc_probe.md"
    json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    write_markdown(report, md_path)
    print(f"Wrote {json_path}")
    print(f"Wrote {md_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
