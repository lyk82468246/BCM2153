#!/usr/bin/env python3
"""Compare an IMRC file header/block table with the public ImrcUnpacker model.

Metadata only: this script never decompresses or extracts vendor resources.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path

PUBLIC_REPO = "https://github.com/raulmrio28-git/ImrcUnpacker"
PUBLIC_COMMIT = "de8a85c342b431b7d18778c8c31e28fb8d21169e"


def u32(data: bytes, off: int) -> int:
    if off < 0 or off + 4 > len(data):
        raise ValueError(f"u32 outside file at 0x{off:x}")
    return struct.unpack_from("<I", data, off)[0]


def inspect(path: Path) -> dict:
    data = path.read_bytes()
    result: dict = {
        "path": str(path),
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "public_reference": {"repo": PUBLIC_REPO, "commit": PUBLIC_COMMIT},
        "parser": "Quram IMRC header model; metadata only",
    }
    if data[:4] != b"IMRC":
        result.update({"format_candidate": False, "reason": "first four bytes are not IMRC"})
        return result
    version, block_size, ext_bits, std_bits, decomp_size, blocks = struct.unpack_from(
        "<6I", data, 4
    )
    table_offset = 0x20
    table_end = table_offset + blocks * 8
    result.update(
        {
            "format_candidate": True,
            "header": {
                "magic_ascii": "IMRC",
                "magic_le": hex(u32(data, 0)),
                "version": hex(version),
                "block_size": block_size,
                "distance_extended_bits": ext_bits,
                "distance_standard_bits": std_bits,
                "decompressed_size": decomp_size,
                "block_count": blocks,
            },
            "block_table": {"offset": hex(table_offset), "end": hex(table_end)},
        }
    )
    if table_end > len(data):
        result["block_table"]["complete"] = False
        result["block_table"]["reason"] = "declared table exceeds file"
        return result
    records = [struct.unpack_from("<2I", data, table_offset + i * 8) for i in range(blocks)]
    # The public implementation treats each pair as command/data sizes. Keep
    # malformed tail records visible instead of silently treating them as data.
    usable = []
    packed_sum = 0
    for index, (command_size, data_size) in enumerate(records):
        if command_size > len(data) or data_size > len(data) or command_size + data_size > len(data):
            break
        usable.append({"index": index, "command_size": command_size, "data_size": data_size})
        packed_sum += command_size + data_size
    data_offset = table_end
    computed_end = data_offset + packed_sum
    tail = data[computed_end:]
    result["block_table"].update(
        {
            "complete": len(usable) == blocks,
            "records_examined": len(usable),
            "data_offset": hex(data_offset),
            "usable_packed_sum": packed_sum,
            "computed_end": hex(computed_end),
            "computed_end_in_file": computed_end <= len(data),
            "tail_bytes_after_usable_records": len(tail),
            "tail_sha256": hashlib.sha256(tail).hexdigest(),
            "first_records": usable[:5],
            "last_usable_records": usable[-5:],
            "last_declared_record": {
                "index": blocks - 1,
                "command_size": records[-1][0],
                "data_size": records[-1][1],
            },
        }
    )
    marker = b"\xcd\xab\xcd\xab"
    marker_positions = [i for i in range(max(0, len(data) - 4096), len(data) - 3) if data[i:i+4] == marker]
    result["packaging_marker"] = {"marker": marker.hex(), "last_4k_offsets": [hex(x) for x in marker_positions]}
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("paths", nargs="+", type=Path)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    report = {"files": [inspect(path) for path in args.paths]}
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(rendered)
    else:
        print(rendered, end="")


if __name__ == "__main__":
    main()
