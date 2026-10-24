#!/usr/bin/env python3
"""Probe competing RBM mode-2/16-bit interpretations; never export pixels.

Both models are analyst hypotheses. Matching dimensions and legal distances
do not choose the literal-stream origin. Contact-style command flag 0x800
is explicitly unsupported, as are 32-bit bodies. Stable mode-0/1 decoding is
in rbm_body_probe.py.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import struct

from rbm_body_probe import BodyError, MAX_BODY, parse_header


def candidate(payload: bytes, raw_start: int, pixels: int, seeded: bool) -> dict:
    """Return only hashes/consumption, never a selected or exported raster."""
    raw = payload[raw_start:]
    if len(raw) < 2:
        return dict(status='failed', reason='literal stream has no complete word')
    output = bytearray(raw[:2] if seeded else b'')
    initial = len(output)
    position = initial
    command_offset = 4
    try:
        for command_offset in range(4, raw_start, 2):
            word = struct.unpack_from('>H', payload, command_offset)[0]
            count, distance = word >> 12, word & 0xfff
            if count:
                if distance == 0 or distance * 2 > len(output):
                    raise BodyError('candidate distance exceeds produced history')
                if len(output) - initial + count * 2 > pixels * 2:
                    raise BodyError('candidate copy exceeds declared pixel count')
                for _ in range(count):
                    source = len(output) - distance * 2
                    output.extend(output[source:source + 2])
            else:
                if len(output) - initial + 2 > pixels * 2:
                    raise BodyError('candidate literal exceeds declared pixel count')
                if position + 2 > len(raw):
                    raise BodyError('candidate literal stream exhausted')
                output.extend(raw[position:position + 2])
                position += 2
        count = (len(output) - initial) // 2
        if count != pixels:
            raise BodyError('candidate output count disagrees with dimensions')
        # The no-seed model leaves one unexplained word before alignment.
        unexplained = 0 if seeded else 2
        alignment = (-(raw_start + position + unexplained)) % 4
        if alignment not in (0, 2) or position + unexplained + alignment != len(raw):
            raise BodyError('candidate has unexplained extent beyond modeled tail')
        return dict(status='fits_candidate_constraints', sample_count=count,
                    samples_sha256=hashlib.sha256(output[initial:]).hexdigest(),
                    literal_bytes_consumed=position,
                    unexplained_tail_bytes=unexplained, alignment_bytes=alignment)
    except BodyError as error:
        return dict(status='failed', reason=str(error), command_payload_offset=command_offset,
                    produced_samples=(len(output) - initial) // 2,
                    literal_bytes_consumed=position)


def probe(data: bytes) -> dict:
    header = parse_header(data)
    if header.placeholder or header.mode != 2 or header.bits_per_sample != 16:
        raise BodyError('probe supports only ordinary mode-2/16-bit bodies')
    payload = data[40:]
    if len(payload) < 4:
        raise BodyError('mode-2 prefix truncated')
    low = struct.unpack_from('>H', payload)[0]
    high = struct.unpack_from('<H', payload, 2)[0]
    if (high & 1) != (low >> 15):
        raise BodyError('prefix disagrees with observed redundant size bit')
    size_word = low + (high // 2) * 65536
    raw_start = size_word + 3
    if not size_word & 1 or size_word < 3 or raw_start > len(payload):
        raise BodyError('candidate command extent outside body or empty')
    flagged = 0
    first_flag = None
    for offset in range(4, raw_start, 2):
        word = struct.unpack_from('>H', payload, offset)[0]
        if word & 0x800:
            flagged += 1
            if first_flag is None:
                first_flag = offset
    report = dict(status='unresolved', body_sha256=hashlib.sha256(data).hexdigest(),
                  local_id=header.local_id, width=header.width, height=header.height,
                  candidate_command_range=[4, raw_start], raw_payload_offset=raw_start,
                  candidate_command_count=(size_word - 1) // 2, flagged_commands=flagged,
                  limitations=[
                      'Observed framing and command grammar are hypotheses, not native-code proof',
                      'No model is selected and no raster is exported',
                      'Native color packing, row orientation and transparency remain unknown'])
    if flagged:
        report.update(reason='unsupported command bit 0x800; grammar remains unknown',
                      first_flag_payload_offset=first_flag)
        return report
    pixels = header.width * header.height
    models = dict(first_word_is_literal=candidate(payload, raw_start, pixels, False),
                  first_word_is_hidden_seed=candidate(payload, raw_start, pixels, True))
    report['models'] = models
    fits = [m for m in models.values() if m['status'] == 'fits_candidate_constraints']
    report['fitting_models'] = len(fits)
    report['distinct_candidate_hashes'] = len({m['samples_sha256'] for m in fits})
    report['reason'] = 'Constraint fits do not establish which pixels the native decoder produces'
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('path', type=Path)
    parser.add_argument('--out', type=Path)
    args = parser.parse_args()
    if args.out and args.out.resolve() == args.path.resolve():
        parser.error('--out must differ from input')
    try:
        with args.path.open('rb') as source:
            data = source.read(MAX_BODY + 1)
        report = probe(data)
    except (BodyError, OSError) as error:
        report = dict(status='failed', reason=str(error))
    rendered = json.dumps(report, indent=2, sort_keys=True) + '\n'
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(rendered)
    else:
        print(rendered, end='')
    # A successful diagnostic is still explicitly unresolved, not a decoder success.
    raise SystemExit(2 if report['status'] == 'failed' else 0)


if __name__ == '__main__':
    main()
