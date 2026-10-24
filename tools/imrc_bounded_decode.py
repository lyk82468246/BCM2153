#!/usr/bin/env python3
"""Bounded, read-only decoder for Quram IMRC resource banks.

The decoder follows the public ImrcUnpacker Quram model but never writes the
complete decompressed bank. --extract-dir writes selected blocks and validated
PNG spans only; selections are limited to 8 MiB. Only version 0x02000400 is
currently supported. The numeric XOR dictionary is format data, not vendor bytes.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import mmap
import zlib
import struct
from dataclasses import dataclass
from pathlib import Path
from itertools import islice
MAGICS = {'PNG': b'\x89PNG\r\n\x1a\n', 'JFIF': b'JFIF', 'SWF_FWS': b'FWS', 'SWF_CWS': b'CWS', 'XML': b'<?xml', 'BWFXML': b'<BWFXML'}
# Fixed 256-entry XOR dictionary defined by the Quram format model.
DIFF_TABLE = [
    0x0001, 0x0003, 0x0100, 0x0002, 0x0008, 0x0007, 0x0006, 0x0300,
    0x0010, 0x0004, 0x0200, 0x0009, 0x0040, 0x0018, 0x0005, 0x0020,
    0x000c, 0x000e, 0x000f, 0x000a, 0x00c0, 0x0800, 0x0700, 0x0101,
    0x0400, 0x000b, 0x0030, 0x0011, 0x0080, 0x0600, 0x000d, 0x0012,
    0x001c, 0x0500, 0x001b, 0x001e, 0x0014, 0x001a, 0x0028, 0x0038,
    0x1000, 0x001f, 0x0019, 0x0016, 0x0060, 0x2000, 0x0013, 0x001d,
    0x0103, 0x0024, 0x0017, 0x0015, 0x0102, 0x01c0, 0x0f00, 0x003c,
    0x0301, 0x0c00, 0x1800, 0x0048, 0x0021, 0x0034, 0x0e00, 0x0202,
    0x002c, 0x0070, 0x0a00, 0x0303, 0x0036, 0x0201, 0x003f, 0x0d00,
    0x0180, 0x003e, 0x3000, 0x0900, 0x0078, 0x0022, 0x0050, 0x003a,
    0x0041, 0x0107, 0x0033, 0x0106, 0x0026, 0x002a, 0x00a0, 0x0023,
    0x0029, 0x0088, 0x0044, 0x003d, 0x00e0, 0x0032, 0x002e, 0x0039,
    0x0031, 0x002d, 0x00f0, 0x0140, 0x0b00, 0x003b, 0x0058, 0x4000,
    0x0037, 0x0035, 0x0068, 0x0302, 0x007c, 0x002f, 0x0027, 0x0064,
    0x0090, 0x0074, 0x0203, 0x0104, 0x006c, 0x1100, 0x03c0, 0x00ff,
    0x0025, 0xf000, 0x1f00, 0x0701, 0x0042, 0x007f, 0x002b, 0x0105,
    0x0054, 0x1c00, 0x004c, 0x0801, 0x0043, 0x6000, 0x005c, 0x007e,
    0x00e8, 0x0108, 0x00f8, 0xe000, 0x0206, 0x1e00, 0x0380, 0x0061,
    0x007a, 0x004e, 0x0601, 0x1001, 0x00c8, 0x8000, 0x1d00, 0x00d0,
    0x0072, 0x0049, 0x1600, 0x1a00, 0x0046, 0x7000, 0x010f, 0x0110,
    0x0076, 0x1200, 0x1400, 0x0404, 0x0606, 0x010e, 0x00fc, 0x1700,
    0x006e, 0x00fe, 0x1300, 0x0062, 0x0066, 0xc000, 0x0204, 0x0306,
    0x0063, 0x0707, 0x0280, 0x0602, 0x0055, 0x0047, 0x006a, 0x010c,
    0x0052, 0x0501, 0x00d8, 0x0307, 0x0073, 0x0109, 0x0808, 0x0401,
    0x004a, 0x2020, 0x005a, 0x0702, 0x00b0, 0x0045, 0x0207, 0x0304,
    0x0402, 0x005e, 0x010a, 0x0079, 0x3800, 0x00f4, 0x1500, 0x01e0,
    0x1b00, 0x0071, 0x1010, 0x00c1, 0x00e4, 0x0502, 0x0056, 0x007d,
    0x0081, 0x0077, 0x00cc, 0x0703, 0x010d, 0x0205, 0x0340, 0x5000,
    0x0082, 0x0067, 0xff00, 0x0120, 0x0069, 0x0098, 0x00c3, 0x1900,
    0x0065, 0x007b, 0x0240, 0x0603, 0x00ec, 0x0059, 0x00fa, 0x0403,
    0x0075, 0x006f, 0x3100, 0x3300, 0x004f, 0x00b8, 0x006d, 0x0208,
    0x004d, 0x0111, 0x0051, 0x020e, 0x00dc, 0x00c4, 0x2100, 0x00a8,
]
MAX_OUTPUT = 512 * 1024 * 1024
MAX_BLOCKS = 131072
MAX_SELECTED = 8 * 1024 * 1024
MAX_INPUT = 512 * 1024 * 1024

class DecodeError(Exception):

    def __init__(self, message: str, **details):
        super().__init__(message)
        self.details = details

@dataclass
class Header:
    version: int
    block_size: int
    ext_bits: int
    std_bits: int
    decompressed_size: int
    blocks: int
    table_offset: int = 0x1c

@dataclass
class Record:
    index: int
    command_size: int
    data_size: int
    packed_offset: int
    packed_end: int

class BitReader:

    def __init__(self, buf: bytes):
        self.buf = buf
        self.pos = 0
        self.bits = 0
        self.value = 0

    def get(self, n: int) -> int:
        if n < 0 or n > 24:
            raise DecodeError('invalid bit width', bits=n)
        while self.bits < n:
            if self.pos >= len(self.buf):
                raise DecodeError('command stream exhausted', command_offset=self.pos, needed_bits=n, buffered_bits=self.bits)
            self.value = self.value << 8 | self.buf[self.pos]
            self.pos += 1
            self.bits += 8
        self.bits -= n
        result = (self.value >> self.bits) & ((1 << n) - 1)
        self.value &= (1 << self.bits) - 1
        return result

class Decoder:

    def __init__(self, data: bytes):
        if len(data) > MAX_INPUT:
            raise DecodeError('input exceeds safety limit', limit=MAX_INPUT)
        self.data = data
        self.header = self.parse_header(data)
        self.records = self.parse_records(data)

    @staticmethod
    def parse_header(data: bytes) -> Header:
        if len(data) < 0x1c:
            raise DecodeError('truncated IMRC header', file_size=len(data))
        if data[:4] != b'IMRC':
            raise DecodeError('not an IMRC file', magic=data[:4].hex())
        h = Header(*struct.unpack_from('<6I', data, 4))
        if h.version != 0x02000400:
            raise DecodeError('unsupported IMRC version', version=hex(h.version))
        if h.block_size < 16 or h.block_size > 65536 or h.block_size % 16:
            raise DecodeError('invalid block size', block_size=h.block_size)
        if h.ext_bits == 0 or h.ext_bits > 16 or h.std_bits == 0 or (h.std_bits > h.ext_bits):
            raise DecodeError('invalid distance bits', ext_bits=h.ext_bits, std_bits=h.std_bits)
        if h.decompressed_size == 0 or h.decompressed_size > MAX_OUTPUT:
            raise DecodeError('declared output exceeds safety limit', decompressed_size=h.decompressed_size, limit=MAX_OUTPUT)
        if h.blocks == 0 or h.blocks > MAX_BLOCKS:
            raise DecodeError('invalid block count', blocks=h.blocks)
        if h.blocks != (h.decompressed_size + h.block_size - 1) // h.block_size:
            raise DecodeError('block count disagrees with output length', blocks=h.blocks)
        if h.decompressed_size % h.block_size and h.decompressed_size % h.block_size < 16:
            raise DecodeError('unsupported compressed final block shorter than 16 bytes')
        table_end = 0x1c + h.blocks * 8
        if table_end > len(data):
            raise DecodeError('block table exceeds file', table_end=table_end, file_size=len(data))
        return h

    def parse_records(self, data: bytes) -> list[Record]:
        pos = self.header.table_offset + self.header.blocks * 8
        out = []
        for i in range(self.header.blocks):
            cmd, dat = struct.unpack_from('<II', data, self.header.table_offset + i * 8)
            if cmd + dat > len(data) - pos:
                raise DecodeError('record exceeds file', index=i, packed_offset=pos, command_size=cmd, data_size=dat, file_size=len(data))
            if cmd + dat > 8 * self.header.block_size + 32:
                raise DecodeError('packed block exceeds safety limit', index=i, command_size=cmd, data_size=dat)
            out.append(Record(i, cmd, dat, pos, pos + cmd + dat))
            pos += cmd + dat
        return out

    def _word(self, out: bytearray, pos: int) -> int:
        if pos < 0 or pos + 2 > len(out):
            raise DecodeError('distance outside output', output_offset=pos)
        return out[pos] | (out[pos + 1] << 8)

    def decode_block(self, index: int, out: bytearray) -> dict:
        if not 0 <= index < self.header.blocks:
            raise DecodeError('block index outside table', index=index)
        if out:
            raise DecodeError('block output must start empty')
        rec = self.records[index]
        expected = min(self.header.block_size, self.header.decompressed_size - index * self.header.block_size)
        if rec.command_size == 0:
            if rec.data_size != expected:
                raise DecodeError('literal block length mismatch', index=index, expected=expected, data_size=rec.data_size)
            out.extend(self.data[rec.packed_offset:rec.packed_end])
            return {'data_bytes_consumed': expected, 'maximum_distance': 0}
        cmd = self.data[rec.packed_offset:rec.packed_offset + rec.command_size]
        inp = self.data[rec.packed_offset + rec.command_size:rec.packed_end]
        br = BitReader(cmd)
        data_pos = 0
        block_start = len(out)
        total_mblks = (expected // 16) * 4
        unpacked = 0
        offs = 4
        max_distance = 0

        def need_data(n):
            nonlocal data_pos
            if data_pos + n > len(inp):
                raise DecodeError('data stream exhausted', index=index, data_offset=data_pos, needed=n, data_size=len(inp))
            p = data_pos
            data_pos += n
            return inp[p:data_pos]

        def distance_word(distance):
            nonlocal max_distance
            if distance < 2 or distance > min(len(out), (1 << self.header.ext_bits) - 1):
                raise DecodeError('illegal word distance', index=index, distance=distance, output_offset=len(out))
            max_distance = max(max_distance, distance)
            return self._word(out, len(out) - distance)

        def copy_distance(distance, n):
            nonlocal max_distance
            max_distance = max(max_distance, distance)
            if distance <= 0 or distance > min(len(out), (1 << self.header.ext_bits) - 1):
                raise DecodeError('illegal distance', index=index, distance=distance, output_size=len(out))
            if len(out) + n > expected:
                raise DecodeError('output length exceeded', index=index)
            for _ in range(n):
                src = len(out) - distance
                if src < 0:
                    raise DecodeError('distance before output', index=index, distance=distance)
                out.append(out[src])

        def write_word(v):
            if len(out) + 2 > expected:
                raise DecodeError('output length exceeded', index=index)
            out.extend(struct.pack('<H', v & 0xffff))
        # Blocks restart at distance four; the first four bytes are literals.
        # Command bits are MSB first; word copies read both bytes before writing.
        for mb in range(4):
            if mb:
                same = br.get(1)
                if not same:
                    stdoffs = br.get(1)
                    offs = br.get(self.header.std_bits if stdoffs else self.header.ext_bits)
                for _ in range(2):
                    stdlz = br.get(1)
                    if stdlz:
                        write_word(distance_word(offs))
                    else:
                        literal = br.get(1)
                        raw = need_data(2 if literal else 1)
                        val = (raw[0] | (raw[1] << 8)) if literal else (DIFF_TABLE[raw[0]] ^ distance_word(offs))
                        write_word(val)
            else:
                out.extend(need_data(4))
            unpacked += 1
        while unpacked < total_mblks:
            mixed = br.get(1)
            if mixed:
                stdlz_bits = need_data(1)[0]
                for mb in range(4):
                    same = br.get(1)
                    if not same:
                        extdoffs = br.get(1)
                        offs = br.get(self.header.std_bits if extdoffs else self.header.ext_bits)
                    for word in range(2):
                        if stdlz_bits & (1 << (7 - (mb * 2 + word))):
                            write_word(distance_word(offs))
                        else:
                            literal = br.get(1)
                            raw = need_data(2 if literal else 1)
                            val = (raw[0] | (raw[1] << 8)) if literal else (DIFF_TABLE[raw[0]] ^ distance_word(offs))
                            write_word(val)
            else:
                lz = br.get(1)
                for _ in range(16):
                    if lz:
                        copy_distance(offs, 1)
                    else:
                        out.extend(need_data(1))
            unpacked += 4
        tail = expected - total_mblks * 4
        if tail:
            out.extend(need_data(tail))
        if len(out) - block_start != expected:
            raise DecodeError('decoded block length mismatch', index=index, expected=expected, actual=len(out) - block_start)
        if data_pos != len(inp):
            raise DecodeError('unused data bytes', index=index, consumed=data_pos, data_size=len(inp))
        return {'command_bits_consumed': br.pos * 8 - br.bits, 'command_bytes_unused': len(cmd) - br.pos, 'data_bytes_consumed': data_pos, 'maximum_distance': max_distance}

    def decode(self, targets: list[int], scan: bool=False, extract_dir: Path | None=None) -> dict:
        targets = sorted(set(targets))
        if not targets or targets[0] < 0 or targets[-1] >= self.header.blocks:
            raise DecodeError('block selection outside table', targets=targets[:16])
        if len(targets) * self.header.block_size > MAX_SELECTED:
            raise DecodeError('selection exceeds safety limit', limit=MAX_SELECTED)
        reports = []
        groups = []
        group = bytearray()
        group_start = 0
        previous = -2
        try:
            for i in targets:
                block = bytearray()
                stats = self.decode_block(i, block)
                reports.append({
                    'index': i,
                    'packed_offset': hex(self.records[i].packed_offset),
                    'command_size': self.records[i].command_size,
                    'data_size': self.records[i].data_size,
                    'decompressed_offset': hex(i * self.header.block_size),
                    'decompressed_length': len(block),
                    'sha256': hashlib.sha256(block).hexdigest(),
                    'magic_hits': magic_hits(block),
                    **stats,
                })
                if extract_dir:
                    extract_dir.mkdir(parents=True, exist_ok=True)
                    (extract_dir / f'block_{i:05d}.bin').write_bytes(block)
                if scan:
                    if i != previous + 1 and group:
                        groups.append((group_start, bytes(group)))
                        group.clear()
                    if not group:
                        group_start = i * self.header.block_size
                    group.extend(block)
                    previous = i
            if group:
                groups.append((group_start, bytes(group)))
        except DecodeError as e:
            return {
                'status': 'failed', 'error': str(e), 'diagnostics': e.details,
                'failed_block': i, 'partial_output_length': len(block),
                'blocks': reports,
            }
        result = {
            'status': 'ok', 'decoded_block_count': len(reports),
            'decoded_length': sum(r['decompressed_length'] for r in reports),
            'blocks': reports,
        }
        if scan:
            result['resources'] = []
            result['scan_limit_per_group'] = 256
            for base, buf in groups:
                for off, span in islice(png_spans(buf), 256):
                    entry = {'type': 'PNG', 'offset': hex(base + off), 'length': len(span), 'sha256': hashlib.sha256(span).hexdigest(), 'validation': 'chunk lengths and CRC through IEND'}
                    if extract_dir:
                        dest = extract_dir / f'png_{base + off:08x}.png'
                        dest.write_bytes(span)
                        entry['extracted_path'] = str(dest)
                    result['resources'].append(entry)
                result.setdefault('magic_hits', []).extend(({'type': name, 'offset': hex(base + off)} for name, magic in MAGICS.items() for off in islice(find_all(buf, magic), 256)))
        return result

def find_all(data, magic):
    pos = 0
    while True:
        pos = data.find(magic, pos)
        if pos < 0:
            return
        yield pos
        pos += 1

def magic_hits(data: bytes):
    return {name: [hex(i) for i in islice(find_all(data, magic), 32)] for name, magic in MAGICS.items() if magic in data}

def png_spans(data):
    """Yield only complete CRC-checked PNGs in the supplied bounded window."""
    for off in find_all(data, MAGICS['PNG']):
        pos = off + 8
        first = True
        idat = False
        while pos + 12 <= len(data):
            length = struct.unpack_from('>I', data, pos)[0]
            typ = data[pos + 4:pos + 8]
            end = pos + 12 + length
            if end > len(data) or any((not (65 <= c <= 90 or 97 <= c <= 122) for c in typ)):
                break
            if first and (typ != b'IHDR' or length != 13):
                break
            if zlib.crc32(data[pos + 4:end - 4]) != struct.unpack_from('>I', data, end - 4)[0]:
                break
            if first:
                width, height = struct.unpack_from('>II', data, pos + 8)
                if not width or not height:
                    break
            first = False
            idat |= typ == b'IDAT'
            pos = end
            if typ == b'IEND':
                if length == 0 and idat:
                    yield (off, data[off:pos])
                break

def parse_selection(value):
    selected = set()
    try:
        for part in value.split(','):
            if ':' in part:
                a, b = part.split(':')
                a, b = (int(a, 0), int(b, 0))
                if a < 0 or b <= a or b - a > MAX_BLOCKS:
                    raise ValueError()
                selected.update(range(a, b))
            else:
                selected.add(int(part, 0))
            if len(selected) > MAX_BLOCKS:
                raise ValueError()
        if not selected:
            raise ValueError()
    except ValueError:
        raise DecodeError('invalid block selection; use 0,100 or half-open 100:110') from None
    return sorted(selected)

def hash_range(data, start, end):
    digest = hashlib.sha256()
    for pos in range(start, end, 1024 * 1024):
        digest.update(data[pos:min(pos + 1024 * 1024, end)])
    return digest.hexdigest()

def inspect(path: Path, targets, scan=False, extract_dir=None, boundary='eof'):
    if boundary not in ('eof', 'tktool'):
        raise DecodeError('unknown boundary model', boundary=boundary)
    if extract_dir and extract_dir.resolve() == path.resolve().parent:
        raise DecodeError('extraction directory must be separate from input directory')
    with path.open('rb') as src:
        size = path.stat().st_size
        if size < 0x1c or size > MAX_INPUT:
            raise DecodeError('input size outside safety limits', file_size=size)
        with mmap.mmap(src.fileno(), 0, access=mmap.ACCESS_READ) as data:
            dec = Decoder(data)
            h = dec.header
            table_end = h.table_offset + h.blocks * 8
            packed_end = dec.records[-1].packed_end
            marker = data.rfind(b'\xcd\xab\xcd\xab', max(0, len(data) - 4096))
            limit = marker if boundary == 'tktool' else len(data)
            if limit < 0:
                raise DecodeError('TkTool boundary marker absent')
            for rec in dec.records:
                if rec.packed_end > limit:
                    raise DecodeError('record exceeds selected boundary', index=rec.index, packed_end=rec.packed_end, boundary=limit)

            def record(r):
                return r.__dict__ | {'table_offset': hex(h.table_offset + r.index * 8), 'packed_offset': hex(r.packed_offset), 'packed_end': hex(r.packed_end)}
            result = {
                'path': str(path),
                'file_size': len(data),
                'sha256': hashlib.sha256(data).hexdigest(),
                'header': {
                    'version': f'0x{h.version:08x}',
                    'block_size': h.block_size,
                    'distance_extended_bits': h.ext_bits,
                    'distance_standard_bits': h.std_bits,
                    'decompressed_size': h.decompressed_size,
                    'block_count': h.blocks,
                    'table_offset': hex(h.table_offset),
                    'table_end': hex(table_end),
                },
                'block_table': {
                    'first_records': [record(r) for r in dec.records[:3]],
                    'last_records': [record(r) for r in dec.records[-2:]],
                    'packed_end': hex(packed_end),
                    'selected_boundary': hex(limit),
                    'boundary_model': boundary,
                    'tail_length': len(data) - packed_end,
                    'tail_sha256': hash_range(data, packed_end, len(data)),
                    'tktool_marker': hex(marker) if marker >= 0 else None,
                },
            }
            result['decode'] = dec.decode(targets, scan, extract_dir)
            return result

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('path', type=Path)
    ap.add_argument('--blocks', default='0,1,2', help='indices or half-open ranges, e.g. 0,100:104; at most 8 MiB selected')
    ap.add_argument('--scan-resources', action='store_true', help='scan contiguous selected windows; validate PNG lengths and CRCs')
    ap.add_argument('--extract-dir', type=Path, help='optional local block and validated PNG output directory')
    ap.add_argument('--boundary', choices=('eof', 'tktool'), default='eof')
    ap.add_argument('--out', type=Path)
    args = ap.parse_args()
    if args.out and args.out.resolve() == args.path.resolve():
        ap.error('--out must differ from the input file')
    try:
        result = inspect(args.path, parse_selection(args.blocks), args.scan_resources, args.extract_dir, args.boundary)
    except (DecodeError, OSError) as e:
        result = {'status': 'failed', 'error': str(e), 'diagnostics': getattr(e, 'details', {}), 'path': str(args.path)}
    rendered = json.dumps(result, indent=2, sort_keys=True) + '\n'
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(rendered)
    else:
        print(rendered, end='')
    raise SystemExit(2 if result.get('decode', result).get('status') == 'failed' else 0)
if __name__ == '__main__':
    main()
