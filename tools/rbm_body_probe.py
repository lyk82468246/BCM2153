#!/usr/bin/env python3
"""Inspect one indexed RBM body; decode observed modes 0/1 to LE u16 samples.

Mode 1 uses a reserved low-six-bit pattern for repeats. RGB565 previews are
explicit candidate interpretations: native color layout and row orientation
have not been established. Modes 2/5 remain opaque; placeholders have no pixels.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass
import hashlib
import json
from pathlib import Path
import struct

MAX_BODY = 2 * 1024 * 1024 + 40
MAX_DIMENSION = 4096
MAX_PIXELS = 1024 * 1024


class BodyError(ValueError):
    pass


@dataclass(frozen=True)
class BodyHeader:
    local_id: int
    word_4: int
    payload_length: int
    mode: int
    width: int
    height: int
    bits_per_sample: int
    key_flag: int
    key_value: int
    word_24: int
    placeholder: bool


def parse_header(data: bytes) -> BodyHeader:
    if not 40 <= len(data) <= MAX_BODY:
        raise BodyError('body size outside safety limits')
    words = struct.unpack_from('<10I', data)
    placeholder = words[1:9] == (0xffffffff,) * 8
    header = BodyHeader(*words, placeholder)
    if header.word_24 != 0x1c:
        raise BodyError('unsupported final header word')
    if placeholder:
        if len(data) != 40:
            raise BodyError('placeholder has trailing bytes')
        return header
    if header.word_4 != 1 or header.payload_length != len(data) - 40:
        raise BodyError('header or payload extent mismatch')
    if (not 0 < header.width <= MAX_DIMENSION or not 0 < header.height <= MAX_DIMENSION
            or header.width * header.height > MAX_PIXELS):
        raise BodyError('dimensions exceed safety limits')
    if header.bits_per_sample not in (16, 32) or header.key_flag not in (0, 1):
        raise BodyError('unsupported sample size or key flag')
    return header


def decode_u16(data: bytes) -> tuple[bytes, dict]:
    """Recover sample words, stopping at the exact dimension-derived count.

    Mode 1 permits only the 0/2 bytes required to align its stream to four
    bytes. Observed alignment bytes are not consistently zero.
    """
    header = parse_header(data)
    if header.placeholder or header.mode not in (0, 1) or header.bits_per_sample != 16:
        raise BodyError('sample decoding supports only ordinary 16-bit modes 0/1')
    expected_bytes = header.width * header.height * 2
    payload = data[40:]
    if header.mode == 0:
        if len(payload) != expected_bytes:
            raise BodyError('raw sample extent disagrees with dimensions')
        return payload, dict(consumed_bytes=len(payload), alignment_bytes=0)
    if len(payload) % 4:
        raise BodyError('mode 1 payload is not four-byte aligned')
    output = bytearray()
    position = 0
    while len(output) < expected_bytes:
        if position + 2 > len(payload):
            raise BodyError('sample stream exhausted before declared pixel count')
        value = struct.unpack_from('<H', payload, position)[0]
        position += 2
        if value & 0x3f == 0x20:
            count = value >> 6
            if not count or position + 2 > len(payload):
                raise BodyError('zero repeat or missing repeat sample')
            if len(output) + count * 2 > expected_bytes:
                raise BodyError('repeat exceeds declared pixel count')
            output.extend(payload[position:position + 2] * count)
            position += 2
        else:
            output.extend(struct.pack('<H', value))
    alignment = (-position) % 4
    if position + alignment != len(payload):
        raise BodyError('unexpected bytes after sample stream')
    return bytes(output), dict(consumed_bytes=position, alignment_bytes=alignment)


def rgb565_candidate_ppm(header: BodyHeader, samples: bytes) -> bytes:
    """Explicit preview assumption; retain key-valued samples as magenta."""
    if len(samples) != header.width * header.height * 2:
        raise BodyError('preview sample extent mismatch')
    rgb = bytearray()
    for (value,) in struct.iter_unpack('<H', samples):
        red, green, blue = value >> 11, (value >> 5) & 63, value & 31
        rgb.extend(((red << 3) | (red >> 2), (green << 2) | (green >> 4),
                    (blue << 3) | (blue >> 2)))
    return f'P6\n{header.width} {header.height}\n255\n'.encode('ascii') + rgb


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('path', type=Path)
    parser.add_argument('--samples-out', type=Path, help='optional decoded LE u16 samples')
    parser.add_argument('--rgb565-preview', type=Path, help='optional candidate RGB565 PPM; key retained')
    parser.add_argument('--out', type=Path, help='JSON report (default stdout)')
    args = parser.parse_args()
    destinations = [p.resolve() for p in (args.samples_out, args.rgb565_preview, args.out) if p]
    if args.path.resolve() in destinations or len(destinations) != len(set(destinations)):
        parser.error('input and all output paths must differ')
    try:
        # A bounded read also handles files whose size changes after stat().
        with args.path.open('rb') as source:
            data = source.read(MAX_BODY + 1)
        header = parse_header(data)
        report = dict(status='ok', path=str(args.path), body_sha256=hashlib.sha256(data).hexdigest(),
                      header=asdict(header), limitations=[
                          'Modes 2/5 and host bitmap constructor remain unresolved',
                          'RGB565 color layout, key use and row orientation are candidate interpretations'])
        if not header.placeholder and header.mode in (0, 1) and header.bits_per_sample == 16:
            samples, decoding = decode_u16(data)
            report['decoding'] = dict(decoding, sample_count=len(samples)//2,
                                      samples_sha256=hashlib.sha256(samples).hexdigest())
            for destination, payload in ((args.samples_out, samples), (args.rgb565_preview,
                    rgb565_candidate_ppm(header, samples) if args.rgb565_preview else None)):
                if destination:
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    destination.write_bytes(payload)
        elif args.samples_out or args.rgb565_preview:
            raise BodyError('requested sample export for unsupported mode or placeholder')
    except (BodyError, OSError) as error:
        report = dict(status='failed', error=str(error))
    rendered = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(rendered)
    else:
        print(rendered, end='')
    raise SystemExit(0 if report['status'] == 'ok' else 2)


if __name__ == '__main__':
    main()
