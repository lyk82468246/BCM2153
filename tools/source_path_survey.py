#!/usr/bin/env python3
"""Summarize leaked/embedded source-path names from a firmware image survey.

The input is a local text file containing one source path per line. The output is
only aggregate counts and short representative examples.
"""

from __future__ import annotations

import argparse
import collections
import json
from pathlib import Path


CATEGORIES = {
    "rtos_nucleus": ["nucleus/", "nu_os", "nu_sdl"],
    "platform_bcm2153": ["bcm2153/", "irqctrl", "fiqctrl", "gpio", "i2c", "sleep", "mmu"],
    "capi2_ipc": ["capi2", "ipc/", "commsipc"],
    "at_v24_usb": ["at_", "atc", "v24", "usb", "serial"],
    "gsm_gprs_edge": ["gprs", "edge", "grr", "gmm", "llc", "rlc", "mac_", "rr_", "bcch"],
    "umts_rrc_l1": ["umts", "rrc", "l1u", "umac", "urlc", "ubmc", "uas_", "ugdci"],
    "sim_sms_stk": ["sim", "sms", "stk", "isim"],
    "call_ss_phonebook": ["call", "mncc", "mnss", "phonebk", "ss_"],
    "audio_dsp": ["audio", "audvoc", "dsp", "speaker"],
    "cal_nv_sysparm": ["cal", "nvram", "sysparm", "rfcal"],
    "data_socket_ip": ["socket", "iprelay", "data", "pch", "snp_"],
}


def normalize(path: str) -> str:
    return path.strip().replace("\\", "/")


def categorize(path: str) -> set[str]:
    low = path.lower()
    hits = set()
    for category, needles in CATEGORIES.items():
        if any(needle in low for needle in needles):
            hits.add(category)
    if not hits:
        hits.add("uncategorized")
    return hits


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("--out", type=Path, default=Path("out/source_path_survey"))
    args = parser.parse_args()

    paths = [normalize(line) for line in args.input.read_text(errors="replace").splitlines()]
    paths = [path for path in paths if path]

    roots = collections.Counter(path.split("/")[0] if "/" in path else "(root)" for path in paths)
    category_counts: collections.Counter[str] = collections.Counter()
    examples: dict[str, list[str]] = collections.defaultdict(list)

    for path in paths:
        for category in categorize(path):
            category_counts[category] += 1
            if len(examples[category]) < 12:
                examples[category].append(path)

    report = {
        "input": str(args.input),
        "path_count": len(paths),
        "root_counts": dict(roots.most_common()),
        "category_counts": dict(category_counts.most_common()),
        "examples": dict(sorted(examples.items())),
    }

    args.out.mkdir(parents=True, exist_ok=True)
    json_path = args.out / "source_path_survey.json"
    md_path = args.out / "source_path_survey.md"
    json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    lines = ["# Source path survey", ""]
    lines.append(f"Input: `{args.input}`")
    lines.append(f"Path count: {len(paths)}")
    lines.append("")
    lines.append("## Categories")
    lines.append("")
    lines.append("| Category | Count | Examples |")
    lines.append("| --- | ---: | --- |")
    for category, count in category_counts.most_common():
        sample = ", ".join(f"`{x}`" for x in examples[category][:4])
        lines.append(f"| `{category}` | {count} | {sample} |")
    lines.append("")
    lines.append("## Roots")
    lines.append("")
    for root, count in roots.most_common():
        lines.append(f"- `{root}`: {count}")
    lines.append("")
    md_path.write_text("\n".join(lines), encoding="utf-8")

    print(f"Wrote {json_path}")
    print(f"Wrote {md_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
