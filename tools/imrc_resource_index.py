#!/usr/bin/env python3
"""Read the observed IMRC logical directory model and verify selected files.

Paths are directory lookup keys; optional RBM IDs are local to each file, and
their global application encoding is unknown. All offsets refer to decompressed
IMRC bytes. No complete bank or file is exported by default.
"""
from __future__ import annotations

import argparse
from collections import Counter, OrderedDict
from dataclasses import asdict, dataclass
import hashlib
import json
import mmap
from pathlib import Path
import struct
import xml.etree.ElementTree as ET

from imrc_bounded_decode import Decoder, DecodeError, MAX_INPUT, png_spans

MAX_INDEX = 1024 * 1024
MAX_ENTRIES = 16384
MAX_FILES_BYTES = 2 * 1024 * 1024
MAX_READ_BYTES = 8 * 1024 * 1024
MAX_DECODE_BYTES = 32 * 1024 * 1024


class LogicalReader:
    """Decode only addressed blocks, with a bounded LRU and read budget."""
    def __init__(self, decoder: Decoder):
        self.decoder = decoder
        self.size = decoder.header.decompressed_size
        self.block_size = decoder.header.block_size
        self.cache = OrderedDict()
        self.blocks = set()
        self.read_bytes = 0
        self.decoded_bytes = 0

    def read(self, offset: int, size: int) -> bytes:
        if offset < 0 or size < 0 or offset + size > self.size:
            raise DecodeError('logical read outside bank', offset=offset, size=size)
        if self.read_bytes + size > MAX_READ_BYTES:
            raise DecodeError('logical read budget exceeded', limit=MAX_READ_BYTES)
        self.read_bytes += size
        out = bytearray()
        while size:
            index, inner = divmod(offset, self.block_size)
            if index not in self.cache:
                if self.decoded_bytes + self.block_size > MAX_DECODE_BYTES:
                    raise DecodeError('block decode work budget exceeded', limit=MAX_DECODE_BYTES)
                block = bytearray()
                self.decoder.decode_block(index, block)
                self.decoded_bytes += len(block)
                self.cache[index] = bytes(block)
                self.blocks.add(index)
                if len(self.cache) > 32:
                    self.cache.popitem(last=False)
            self.cache.move_to_end(index)
            chunk = self.cache[index]
            count = min(size, len(chunk) - inner)
            out.extend(chunk[inner:inner + count])
            offset += count
            size -= count
        return bytes(out)

    def index_read(self, offset, size):
        if offset < 0 or offset + size > MAX_INDEX:
            raise DecodeError('directory metadata exceeds index budget', offset=offset, size=size)
        return self.read(offset, size)


@dataclass(frozen=True)
class FileEntry:
    path: str
    entry_offset: int
    offset: int
    length: int


def decode_name(raw: bytes) -> str:
    name, separator, padding = raw.partition(b'\0')
    if not separator or any(padding):
        raise DecodeError('name must have zero padding')
    try:
        value = name.decode('ascii')
    except UnicodeDecodeError:
        raise DecodeError('unsupported non-ASCII index name') from None
    if not value or value in ('.', '..') or any(c in value for c in '/\\'):
        raise DecodeError('invalid index name')
    if any(ord(c) < 32 or ord(c) > 126 for c in value):
        raise DecodeError('non-printable index name')
    return value


def parse_index(reader: LogicalReader) -> dict:
    header = reader.index_read(0, 0x40)
    word0, word4 = struct.unpack_from('<II', header)
    root_name = decode_name(header[8:0x34])
    root, size, word3c = struct.unpack_from('<III', header, 0x34)
    if root != 0x40 or size != reader.size:
        raise DecodeError('logical header disagrees with observed directory model', root=root, size=size)
    directories = []
    files = []
    seen = set()
    pending = [(root_name, root, 0)]
    while pending:
        path, offset, expected_parent = pending.pop()
        if offset in seen:
            raise DecodeError('directory cycle or aliased node', offset=offset)
        seen.add(offset)
        if len(seen) > MAX_ENTRIES:
            raise DecodeError('directory count exceeds safety limit')
        parent, directory_count, file_count = struct.unpack('<III', reader.index_read(offset, 12))
        if parent != expected_parent:
            raise DecodeError('directory parent mismatch', offset=offset, parent=parent, expected=expected_parent)
        if directory_count + file_count + len(files) + len(pending) > MAX_ENTRIES:
            raise DecodeError('entry count exceeds safety limit')
        extent = 12 + directory_count * 48 + file_count * 52
        entries = reader.index_read(offset + 12, extent - 12)
        names = set()
        position = 0
        for index in range(directory_count + file_count):
            is_directory = index < directory_count
            width = 48 if is_directory else 52
            entry = entries[position:position + width]
            name = decode_name(entry[:44])
            if name in names:
                raise DecodeError('duplicate name within directory', directory=offset)
            names.add(name)
            child_path = path + '/' + name
            if len(child_path) > 1024 or child_path.count('/') > 64:
                raise DecodeError('directory depth or path length exceeds safety limit')
            target = struct.unpack_from('<I', entry, 44)[0]
            if is_directory:
                if target < 0x40 or target % 4:
                    raise DecodeError('invalid directory target', offset=target)
                pending.append((child_path, target, offset))
            else:
                length = struct.unpack_from('<I', entry, 48)[0]
                if target % 4 or target + length > reader.size:
                    raise DecodeError('file extent outside bank or unaligned', offset=target, length=length)
                files.append(FileEntry(child_path, offset + 12 + position, target, length))
            position += width
        directories.append(dict(path=path, offset=offset, end=offset + extent,
                                parent=parent, directories=directory_count, files=file_count))
    directories.sort(key=lambda item: item['offset'])
    if directories[0]['offset'] != 0x40 or any(a['end'] != b['offset'] for a, b in zip(directories, directories[1:])):
        raise DecodeError('directory nodes overlap or leave gaps in observed index model')
    index_end = directories[-1]['end']
    ordered = sorted((f for f in files if f.length), key=lambda f: f.offset)
    if not ordered or ordered[0].offset != index_end:
        raise DecodeError('first payload does not follow index', index_end=index_end)
    if any(f.offset < index_end for f in files):
        raise DecodeError('file overlaps index')
    gaps = Counter()
    for left, right in zip(ordered, ordered[1:]):
        gap = right.offset - left.offset - left.length
        if gap < 0 or gap > 3:
            raise DecodeError('overlap or unexpected payload gap', offset=right.offset, gap=gap)
        gaps[gap] += 1
    end = max(f.offset + f.length for f in files)
    if end != reader.size:
        raise DecodeError('payload extents do not end at declared output', end=end)
    return dict(
        header=dict(word_0=word0, word_4=word4, word_3c=word3c, root_name=root_name,
                    root_offset=root, logical_size=size),
        directory_count=len(directories), file_count=len(files), index_end=index_end,
        metadata_sha256=hashlib.sha256(reader.index_read(0, index_end)).hexdigest(),
        zero_length_files=sum(f.length == 0 for f in files),
        extension_counts=dict(sorted(Counter(Path(f.path).suffix.lower() for f in files).items())),
        payload_gap_counts=dict(sorted(gaps.items())), payload_end=end,
        directories=directories, files=[asdict(f) for f in sorted(files, key=lambda f: f.path)])


def parse_rbm_index(reader: LogicalReader, file_entry: dict) -> dict:
    """Read RBM table and per-body IDs, without decoding pixel formats."""
    start, size = file_entry['offset'], file_entry['length']
    if size < 12:
        raise DecodeError('RBM header truncated', path=file_entry['path'])
    word0, word4, count = struct.unpack('<III', reader.read(start, 12))
    if (word0, word4) != (0, 0x100) or not 0 < count <= MAX_ENTRIES:
        raise DecodeError('unsupported RBM header', word0=word0, word4=word4, count=count)
    table_end = 12 + 16 * count
    if table_end > size:
        raise DecodeError('RBM table outside indexed file', path=file_entry['path'])
    raw = reader.read(start + 12, count * 16)
    end = table_end
    records = []
    seen = set()
    for index in range(count):
        kind, local_id, offset, length = struct.unpack_from('<4I', raw, index * 16)
        if kind != 0x100 or local_id in seen or offset != end or length < 4 or offset + length > size:
            raise DecodeError('invalid RBM record', path=file_entry['path'], record=index)
        seen.add(local_id)
        body_id = struct.unpack('<I', reader.read(start + offset, 4))[0]
        if body_id != local_id:
            raise DecodeError('RBM table/body ID mismatch', path=file_entry['path'], record=index)
        records.append(dict(local_id=local_id, kind=kind, file_offset=offset,
                            logical_offset=start + offset, length=length, body_id=body_id))
        end = offset + length
    if end != size:
        raise DecodeError('RBM records do not end at indexed file boundary', path=file_entry['path'])
    return dict(path=file_entry['path'], file_offset=start, file_length=size,
                count=count, table_end=table_end, records=records,
                ordinal_ids=[r['local_id'] for r in records] == list(range(count)),
                validation='table bounds; contiguous extents; unique IDs; body IDs; exact indexed end')


def validate_resource(data: bytes) -> dict:
    """Structural checks only; no target code or XML external entity fetching."""
    if data.startswith(b'\x89PNG\r\n\x1a\n'):
        span = next(png_spans(data), None)
        valid = span is not None and span[0] == 0 and len(span[1]) == len(data)
        return dict(type='PNG', valid=valid, checks='chunk lengths and CRCs; IEND at indexed end')
    if data.startswith(b'<?xml'):
        if b'<!ENTITY' in data.upper():
            return dict(type='XML', valid=False, reason='entity declarations unsupported')
        try:
            root = ET.fromstring(data)
        except ET.ParseError as error:
            return dict(type='XML', valid=False, reason=str(error))
        return dict(type='XML', valid=True, root_element=root.tag, checks='complete indexed byte span parsed; external DTD not fetched')
    if data.startswith(b'FWS') and len(data) >= 9:
        declared = struct.unpack_from('<I', data, 4)[0]
        rectangle_bytes = (5 + 4 * (data[8] >> 3) + 7) // 8
        pos = 8 + rectangle_bytes + 4
        tags = 0
        while pos + 2 <= len(data):
            code_length = struct.unpack_from('<H', data, pos)[0]
            pos += 2
            tag, length = code_length >> 6, code_length & 63
            if length == 63:
                if pos + 4 > len(data): break
                length = struct.unpack_from('<I', data, pos)[0]
                pos += 4
            if pos + length > len(data): break
            pos += length
            tags += 1
            if tag == 0:
                valid = length == 0 and pos == len(data) == declared
                return dict(type='SWF_FWS', valid=valid, tag_count=tags, declared_size=declared,
                            checks='RECT/frame header; tag lengths; End at indexed end')
        return dict(type='SWF_FWS', valid=False, reason='incomplete SWF tag stream')
    if data.startswith(b'RIFF') and len(data) >= 12 and data[8:12] == b'WAVE':
        size = struct.unpack_from('<I', data, 4)[0] + 8
        pos = 12
        chunks = []
        while pos + 8 <= len(data):
            length = struct.unpack_from('<I', data, pos + 4)[0]
            end = pos + 8 + length
            if end > len(data): break
            chunk = dict(type=data[pos:pos+4].decode('ascii', errors='replace'),
                         offset=pos + 8, length=length)
            if data[pos:pos+4] == b'iXML':
                xml = data[pos+8:end]
                chunk['validation'] = validate_resource(xml)
                chunk['sha256'] = hashlib.sha256(xml).hexdigest()
            chunks.append(chunk)
            pos = end + (length % 2)
        kinds = {chunk['type'] for chunk in chunks}
        valid = pos == size == len(data) and {'fmt ', 'data'} <= kinds
        return dict(type='RIFF_WAVE', valid=valid, chunks=chunks,
                    checks='RIFF length and chunk extents equal indexed length')
    return dict(type='unknown', valid=False, reason='no supported structural validator')


def inspect(path: Path, verify_paths: list[str], extract_dir: Path | None = None,
            survey_rbm: bool = False, rbm_requests: list[tuple[str, int]] | None = None) -> dict:
    if path.stat().st_size < 0x1c or path.stat().st_size > MAX_INPUT:
        raise DecodeError('input size outside safety limits')
    if extract_dir and extract_dir.resolve() == path.resolve().parent:
        raise DecodeError('extraction directory must be separate from input directory')
    with path.open('rb') as source, mmap.mmap(source.fileno(), 0, access=mmap.ACCESS_READ) as data:
        reader = LogicalReader(Decoder(data))
        index = parse_index(reader)
        paths = {entry['path']: entry for entry in index['files']}
        verified = []
        if len(verify_paths) > 32:
            raise DecodeError('too many selected files; limit is 32')
        for selected in verify_paths:
            if selected not in paths:
                raise DecodeError('selected path absent from index', path=selected)
            entry = paths[selected]
            if entry['length'] > MAX_FILES_BYTES:
                raise DecodeError('selected file exceeds 2 MiB limit', path=selected)
            payload = reader.read(entry['offset'], entry['length'])
            result = dict(entry, sha256=hashlib.sha256(payload).hexdigest(),
                          validation=validate_resource(payload))
            if extract_dir and result['validation']['valid']:
                destination = extract_dir.joinpath(*selected.split('/'))
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(payload)
                result['extracted_path'] = str(destination)
            verified.append(result)
        rbm = []
        if survey_rbm:
            for entry in index['files']:
                if entry['path'].lower().endswith('.rbm'):
                    rbm.append(parse_rbm_index(reader, entry))
        requests = rbm_requests or []
        if len(requests) > 32:
            raise DecodeError('too many selected RBM resources; limit is 32')
        rbm_by_path = {item['path']: item for item in rbm}
        selected_records = []
        for selected, local_id in requests:
            if selected not in paths or not selected.lower().endswith('.rbm'):
                raise DecodeError('selected RBM file absent from index', path=selected)
            if selected not in rbm_by_path:
                rbm_by_path[selected] = parse_rbm_index(reader, paths[selected])
            table = rbm_by_path[selected]
            matches = [item for item in table['records'] if item['local_id'] == local_id]
            if not matches:
                raise DecodeError('local ID absent from selected RBM file', path=selected, local_id=local_id)
            record = matches[0]
            if record['length'] > MAX_FILES_BYTES:
                raise DecodeError('selected RBM body exceeds 2 MiB limit')
            body = reader.read(record['logical_offset'], record['length'])
            result = dict(path=selected, **record, sha256=hashlib.sha256(body).hexdigest(),
                          limitation='indexed RBM body bytes; pixel encoding not decoded')
            if extract_dir:
                destination = extract_dir.joinpath('rbm_records', *selected.split('/'))
                destination = destination.with_name(destination.name + f'.id_{local_id}.bin')
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(body)
                result['extracted_path'] = str(destination)
            selected_records.append(result)
        return dict(path=str(path), sample_sha256=hashlib.sha256(data).hexdigest(),
                    model='observed directory tree and optional RBM local IDs; global application IDs unresolved',
                    index=index, verified_files=verified, decoded_blocks=sorted(reader.blocks),
                    read_bytes=reader.read_bytes, decoded_bytes=reader.decoded_bytes,
                    rbm_indices=rbm, rbm_file_count=len(rbm),
                    rbm_record_count=sum(item['count'] for item in rbm),
                    selected_rbm_records=selected_records)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('path', type=Path)
    parser.add_argument('--verify', action='append', default=[], metavar='LOGICAL_PATH')
    parser.add_argument('--survey-rbm', action='store_true', help='validate all indexed RBM tables and body IDs; no pixel export')
    parser.add_argument('--rbm-id', action='append', nargs=2, default=[], metavar=('LOGICAL_PATH', 'ID'),
                        help='select one RBM body by path and local ID; ID supports decimal and 0x hex')
    parser.add_argument('--extract-dir', type=Path, help='write only structurally verified selected files')
    parser.add_argument('--out', type=Path)
    args = parser.parse_args()
    if args.out and args.out.resolve() == args.path.resolve():
        parser.error('--out must differ from input')
    try:
        try:
            requests = [(path, int(local_id, 0)) for path, local_id in args.rbm_id]
        except ValueError:
            raise DecodeError('invalid RBM local ID; use decimal or 0x hex') from None
        result = inspect(args.path, args.verify, args.extract_dir, args.survey_rbm, requests)
        failed = any(not item['validation']['valid'] for item in result['verified_files'])
        result['status'] = 'failed' if failed else 'ok'
    except (DecodeError, OSError) as error:
        result = dict(status='failed', error=str(error), diagnostics=getattr(error, 'details', {}))
    rendered = json.dumps(result, indent=2, sort_keys=True) + '\n'
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(rendered)
    else:
        print(rendered, end='')
    raise SystemExit(2 if result['status'] == 'failed' else 0)


if __name__ == '__main__':
    main()
