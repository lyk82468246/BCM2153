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
PUBLIC_REPO = 'https://github.com/raulmrio28-git/ImrcUnpacker'
PUBLIC_COMMIT = 'de8a85c342b431b7d18778c8c31e28fb8d21169e'

def inspect(path: Path) -> dict:
    if path.stat().st_size > 512 * 1024 * 1024:
        return {'path': str(path), 'format_candidate': False, 'reason': 'input exceeds 512 MiB safety limit'}
    data = path.read_bytes()
    result: dict = {'path': str(path), 'size': len(data), 'sha256': hashlib.sha256(data).hexdigest(), 'public_reference': {'repo': PUBLIC_REPO, 'commit': PUBLIC_COMMIT}, 'parser': 'Quram IMRC header model; metadata only'}
    if data[:4] != b'IMRC':
        result.update({'format_candidate': False, 'reason': 'first four bytes are not IMRC'})
        return result
    if len(data) < 0x1c:
        result.update({'format_candidate': False, 'reason': 'truncated IMRC header'})
        return result
    version, block_size, ext_bits, std_bits, decomp_size, blocks = struct.unpack_from('<6I', data, 4)
    if version != 0x02000400:
        result.update({'format_candidate': False, 'reason': 'unsupported version', 'version': hex(version)})
        return result
    result.update({'format_candidate': True, 'header': {'magic_ascii': 'IMRC', 'version': f'0x{version:08x}', 'block_size': block_size, 'distance_extended_bits': ext_bits, 'distance_standard_bits': std_bits, 'decompressed_size': decomp_size, 'block_count': blocks}})
    marker = data.rfind(b'\xcd\xab\xcd\xab', max(0, len(data) - 4096))
    result['packaging_marker'] = {'marker': 'cdabcdab', 'offset': hex(marker) if marker >= 0 else None}
    result['block_table'] = table_model(data, blocks, 0x1c, len(data))
    result['boundary_models'] = {'eof': table_model(data, blocks, 0x1c, len(data))}
    if marker >= 0:
        result['boundary_models']['tktool'] = table_model(data, blocks, 0x1c, marker)
    result['previous_misaligned_model'] = table_model(data, blocks, 0x20, len(data))
    return result

def table_model(data: bytes, blocks: int, base: int, boundary: int) -> dict:
    """Summarize a table hypothesis without reading records past the file."""
    table_end = base + blocks * 8
    result = {'offset': hex(base), 'end': hex(table_end), 'boundary': hex(boundary)}
    if not 0 < blocks <= 131072 or base < 0 or not table_end <= boundary <= len(data):
        return result | {'complete': False, 'reason': 'declared table exceeds boundary or count limit'}
    pos = table_end
    first = []
    last = []
    for i in range(blocks):
        cmd, dat = struct.unpack_from('<II', data, base + i * 8)
        record = {'index': i, 'table_offset': hex(base + i * 8), 'command_size': cmd, 'data_size': dat, 'packed_offset': hex(pos), 'packed_end': hex(pos + cmd + dat)}
        if pos + cmd + dat > boundary:
            return result | {'complete': False, 'records_examined': i, 'computed_end': hex(pos), 'first_records': first, 'last_usable_records': last, 'invalid_record': record}
        if i < 3:
            first.append(record)
        last = (last + [record])[-3:]
        pos += cmd + dat
    return result | {'complete': True, 'records_examined': blocks, 'computed_end': hex(pos), 'first_records': first, 'last_usable_records': last, 'bytes_after_records_to_boundary': boundary - pos, 'tail_sha256': hashlib.sha256(data[pos:boundary]).hexdigest()}

def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('paths', nargs='+', type=Path)
    parser.add_argument('--out', type=Path)
    args = parser.parse_args()
    if args.out and any(args.out.resolve() == p.resolve() for p in args.paths):
        parser.error('--out must differ from all input files')
    report = {'files': [inspect(path) for path in args.paths]}
    rendered = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(rendered)
    else:
        print(rendered, end='')
if __name__ == '__main__':
    main()
