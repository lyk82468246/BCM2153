#!/usr/bin/env python3
"""Summarize the FactoryFs FAT16 image without extracting files."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from collections import Counter
from pathlib import Path


FLS_RE = re.compile(r"^(?P<meta>\S+)\s+(?P<inode>\d+):\t(?P<path>.*)$")
INTERESTING_PREFIXES = [
    "Exe/Java",
    "Exe/Java/Games",
    "Exe/Java/Locked Games",
    "Exe/Mocha",
    "Media",
    "Security",
    "Settings",
    "SystemFS/Country",
    "SystemFS/DB",
    "SystemFS/Driver",
    "SystemFS/MediaSet",
    "SystemFS/MediaSet/Widget",
    "SystemFS/Settings",
    "SystemFS/User",
]


def run_text(cmd: list[str]) -> str:
    proc = subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, errors="replace")
    return proc.stdout


def parse_fls(text: str) -> list[dict]:
    entries = []
    for line in text.splitlines():
        match = FLS_RE.match(line)
        if not match:
            continue
        meta = match.group("meta")
        path = match.group("path")
        kind = "dir" if meta.startswith("d/") else "file"
        parts = path.split("/") if path else []
        suffix = ""
        if kind == "file":
            name = parts[-1] if parts else path
            if "." in name:
                suffix = "." + name.rsplit(".", 1)[1].lower()
            else:
                suffix = "[none]"
        entries.append(
            {
                "meta": meta,
                "inode": int(match.group("inode")),
                "kind": kind,
                "path": path,
                "root": parts[0] if parts else "",
                "depth": len(parts),
                "suffix": suffix,
            }
        )
    return entries


def parse_fsstat(text: str) -> dict:
    wanted = {
        "File System Type": "filesystem_type",
        "OEM Name": "oem_name",
        "Volume ID": "volume_id",
        "File System Type Label": "type_label",
        "Sector Size": "sector_size",
        "Cluster Size": "cluster_size",
        "Total Cluster Range": "total_cluster_range",
    }
    out = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip()
        if key in wanted:
            out[wanted[key]] = value.strip().replace("\x00", "")
    return out


def top_level_summary(entries: list[dict]) -> list[dict]:
    roots = sorted({entry["root"] for entry in entries if entry["root"] and not entry["root"].startswith("$")})
    out = []
    for root in roots:
        subset = [entry for entry in entries if entry["root"] == root]
        out.append(
            {
                "root": root,
                "dirs": sum(1 for entry in subset if entry["kind"] == "dir"),
                "files": sum(1 for entry in subset if entry["kind"] == "file"),
            }
        )
    return out


def prefix_summary(entries: list[dict]) -> list[dict]:
    rows = []
    for prefix in INTERESTING_PREFIXES:
        subset = [entry for entry in entries if entry["path"] == prefix or entry["path"].startswith(prefix + "/")]
        if not subset:
            continue
        suffixes = Counter(entry["suffix"] for entry in subset if entry["kind"] == "file")
        samples = [entry["path"] for entry in subset if entry["kind"] == "file"][:16]
        rows.append(
            {
                "prefix": prefix,
                "dirs": sum(1 for entry in subset if entry["kind"] == "dir"),
                "files": sum(1 for entry in subset if entry["kind"] == "file"),
                "top_suffixes": suffixes.most_common(8),
                "sample_files": samples,
            }
        )
    return rows


def java_app_summary(entries: list[dict]) -> dict:
    groups = {}
    for prefix in ("Exe/Java/Games", "Exe/Java/Locked Games", "Exe/Java/Hidden Games", "Exe/Java/Links"):
        apps = sorted(
            entry["path"].split("/")[-1]
            for entry in entries
            if entry["kind"] == "dir" and entry["path"].startswith(prefix + "/") and entry["depth"] == prefix.count("/") + 2
        )
        groups[prefix] = {"count": len(apps), "samples": apps[:12]}
    jad = sum(1 for entry in entries if entry["kind"] == "file" and entry["suffix"] == ".jad")
    jar = sum(1 for entry in entries if entry["kind"] == "file" and entry["suffix"] == ".jar")
    return {"groups": groups, "jad_files": jad, "jar_files": jar}


def analyze(image: Path) -> dict:
    fls_text = run_text(["fls", "-r", "-p", str(image)])
    fsstat_text = run_text(["fsstat", str(image)])
    entries = parse_fls(fls_text)
    pseudo_entries = [entry for entry in entries if entry["root"].startswith("$")]
    visible_entries = [entry for entry in entries if not entry["root"].startswith("$")]
    files = [entry for entry in visible_entries if entry["kind"] == "file"]
    dirs = [entry for entry in visible_entries if entry["kind"] == "dir"]
    suffixes = Counter(entry["suffix"] for entry in files)
    return {
        "input": str(image),
        "fsstat": parse_fsstat(fsstat_text),
        "entry_count": len(visible_entries),
        "file_count": len(files),
        "dir_count": len(dirs),
        "pseudo_entry_count": len(pseudo_entries),
        "top_level": top_level_summary(visible_entries),
        "suffix_counts": suffixes.most_common(32),
        "prefixes": prefix_summary(visible_entries),
        "java": java_app_summary(visible_entries),
    }


def fmt_suffixes(items: list) -> str:
    if not items:
        return ""
    return ", ".join(f"`{suffix}`:{count}" for suffix, count in items)


def write_markdown(report: dict, out_path: Path) -> None:
    fs = report["fsstat"]
    lines = ["# FactoryFs survey", ""]
    lines.append(f"Input: `{Path(report['input']).name}`")
    lines.append("")
    lines.append("## Filesystem")
    lines.append("")
    for key in ("filesystem_type", "oem_name", "volume_id", "type_label", "sector_size", "cluster_size", "total_cluster_range"):
        if key in fs:
            lines.append(f"- {key}: `{fs[key]}`")
    lines.append("")
    lines.append("## Totals")
    lines.append("")
    lines.append(f"- Visible entries: {report['entry_count']}")
    lines.append(f"- Sleuth Kit pseudo entries: {report['pseudo_entry_count']}")
    lines.append(f"- Directories: {report['dir_count']}")
    lines.append(f"- Files: {report['file_count']}")
    lines.append("")
    lines.append("## Top Level")
    lines.append("")
    lines.append("| Root | Directories | Files |")
    lines.append("| --- | ---: | ---: |")
    for row in report["top_level"]:
        lines.append(f"| `{row['root']}` | {row['dirs']} | {row['files']} |")
    lines.append("")
    lines.append("## Extension Counts")
    lines.append("")
    lines.append("| Suffix | Count |")
    lines.append("| --- | ---: |")
    for suffix, count in report["suffix_counts"]:
        lines.append(f"| `{suffix}` | {count} |")
    lines.append("")
    lines.append("## Prefix Summary")
    lines.append("")
    lines.append("| Prefix | Directories | Files | Top suffixes |")
    lines.append("| --- | ---: | ---: | --- |")
    for row in report["prefixes"]:
        lines.append(f"| `{row['prefix']}` | {row['dirs']} | {row['files']} | {fmt_suffixes(row['top_suffixes'])} |")
    lines.append("")
    lines.append("## Java Summary")
    lines.append("")
    lines.append(f"- `.jad` files: {report['java']['jad_files']}")
    lines.append(f"- `.jar` files: {report['java']['jar_files']}")
    for prefix, item in report["java"]["groups"].items():
        lines.append(f"- `{prefix}` app directories: {item['count']}")
    lines.append("")
    out_path.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("--out", type=Path, default=Path("out/factoryfs_survey"))
    args = parser.parse_args()

    report = analyze(args.input)
    args.out.mkdir(parents=True, exist_ok=True)
    json_path = args.out / "factoryfs_survey.json"
    md_path = args.out / "factoryfs_survey.md"
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    write_markdown(report, md_path)
    print(f"Wrote {json_path}")
    print(f"Wrote {md_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
