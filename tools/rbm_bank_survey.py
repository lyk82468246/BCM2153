#!/usr/bin/env python3
"""Boundedly inspect indexed RBM headers and optionally expand known modes.

No raw bytes or previews are exported. Unknown encodings are counted, not
decoded. Failure reports retain completed records and the failing path/ID.
"""
from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import asdict
import hashlib
import json
import mmap
from pathlib import Path

from imrc_bounded_decode import Decoder, DecodeError, MAX_INPUT
from imrc_resource_index import LogicalReader, MAX_ENTRIES, parse_index, parse_rbm_index
from rbm_body_probe import BodyError, decode_u16, parse_header


def survey(reader, decode_modes: set[int], report: dict) -> None:
    if not decode_modes <= {0, 1}:
        raise BodyError('only modes 0/1 support sample expansion')
    index = parse_index(reader)
    counts = Counter()
    report.update(status='running', records=[], mode_counts={}, placeholder_count=0,
                  rbm_file_count=0, sample_decoded_count=0,
                  index_metadata_sha256=index['metadata_sha256'])
    for entry in index['files']:
        if not entry['path'].lower().endswith('.rbm'):
            continue
        report['current'] = dict(path=entry['path'])
        table = parse_rbm_index(reader, entry)
        report['rbm_file_count'] += 1
        if len(report['records']) + len(table['records']) > MAX_ENTRIES:
            raise BodyError('aggregate RBM record count exceeds safety limit')
        for record in table['records']:
            report['current'] = dict(path=entry['path'], local_id=record['local_id'],
                                     logical_offset=record['logical_offset'])
            if record['length'] < 40:
                raise BodyError('indexed body is shorter than header')
            raw_header = reader.read(record['logical_offset'], 40)
            header = parse_header(raw_header, body_size=record['length'])
            if header.local_id != record['local_id']:
                raise BodyError('header ID disagrees with indexed ID')
            row = dict(report['current'], body_length=record['length'], header=asdict(header))
            if header.placeholder:
                report['placeholder_count'] += 1
            else:
                counts[f'{header.mode}/{header.bits_per_sample}'] += 1
                report['mode_counts'] = dict(sorted(counts.items()))
                if header.mode in decode_modes:
                    body = reader.read(record['logical_offset'], record['length'])
                    samples, consumption = decode_u16(body)
                    row['decoding'] = dict(consumption, sample_count=len(samples) // 2,
                                           body_sha256=hashlib.sha256(body).hexdigest(),
                                           samples_sha256=hashlib.sha256(samples).hexdigest())
                    report['sample_decoded_count'] += 1
            report['records'].append(row)
    report.pop('current', None)
    report['status'] = 'ok'


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('path', type=Path)
    parser.add_argument('--decode-modes', choices=('0', '1', '0,1'),
                        help='explicit sample expansion; default only checks headers')
    parser.add_argument('--out', type=Path)
    args = parser.parse_args()
    if args.out and args.out.resolve() == args.path.resolve():
        parser.error('--out must differ from input')
    report = dict(path=str(args.path), limitations=[
        'Observed sample model; unknown modes remain opaque',
        'Sample expansion does not establish native color layout or transparency'])
    reader = None
    try:
        if not 0x1c <= args.path.stat().st_size <= MAX_INPUT:
            raise BodyError('input size outside safety limits')
        with args.path.open('rb') as source, mmap.mmap(source.fileno(), 0, access=mmap.ACCESS_READ) as data:
            if not 0x1c <= len(data) <= MAX_INPUT:
                raise BodyError('mapped input size outside safety limits')
            report['sample_sha256'] = hashlib.sha256(data).hexdigest()
            reader = LogicalReader(Decoder(data))
            modes = {int(n) for n in args.decode_modes.split(',')} if args.decode_modes else set()
            survey(reader, modes, report)
    except (BodyError, DecodeError, OSError, ValueError) as error:
        report.update(status='failed', error=str(error), diagnostics=getattr(error, 'details', {}))
    if reader is not None:
        report.update(read_bytes=reader.read_bytes, decoded_bytes=reader.decoded_bytes,
                      decoded_blocks=sorted(reader.blocks))
    rendered = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(rendered)
    else:
        print(rendered, end='')
    raise SystemExit(0 if report['status'] == 'ok' else 2)


if __name__ == '__main__':
    main()
