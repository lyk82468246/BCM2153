"""Synthetic independent sample expectations; no vendor payloads."""
from pathlib import Path
import hashlib
import mmap
import os
import struct
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from rbm_body_probe import BodyError, decode_u16, parse_header, rgb565_candidate_ppm


def body(payload, mode=1, width=3, height=1, bits=16):
    return struct.pack('<10I', 7, 1, len(payload), mode, width, height, bits, 1, 0xf81f, 28) + payload


class BodyTests(unittest.TestCase):
    def test_header_only_uses_indexed_extent_without_allocating_payload(self):
        encoded = body(struct.pack('<2H', 0xe0, 1))
        self.assertEqual(parse_header(encoded[:40], body_size=len(encoded)), parse_header(encoded))
        for size in (39, len(encoded) + 1, 0xffffffff):
            with self.subTest(size=size), self.assertRaises(BodyError):
                parse_header(encoded[:40], body_size=size)
        with self.assertRaises(BodyError):
            parse_header(encoded, body_size=len(encoded))

    def test_raw_odd_width_has_no_row_padding(self):
        samples = struct.pack('<3H', 0xf800, 0x7e0, 0x1f)
        encoded = body(samples, mode=0)
        decoded, report = decode_u16(encoded)
        self.assertEqual(decoded, samples)
        self.assertEqual(report, dict(consumed_bytes=6, alignment_bytes=0))
        self.assertEqual(rgb565_candidate_ppm(parse_header(encoded), decoded),
                         b'P6\n3 1\n255\n\xff\0\0\0\xff\0\0\0\xff')

    def test_literals_repeat_and_reserved_sample_escape(self):
        # One literal, three repeats, then the reserved-pattern value 0x20
        # escaped by a repeat of one; nonzero alignment bytes are observed.
        payload = struct.pack('<5H', 0x1234, 0xe0, 0xabcd, 0x60, 0x20) + b'\xaa\xbb'
        decoded, report = decode_u16(body(payload, width=5))
        self.assertEqual(struct.unpack('<5H', decoded), (0x1234, 0xabcd, 0xabcd, 0xabcd, 0x20))
        self.assertEqual(report, dict(consumed_bytes=10, alignment_bytes=2))

    def test_reject_stream_exhaustion_overflow_and_zero_repeat(self):
        for payload in (b'', struct.pack('<2H', 0x120, 1), struct.pack('<2H', 0x20, 1),
                        struct.pack('<2H', 0x1234, 0x60)):
            with self.subTest(payload=payload.hex()), self.assertRaises(BodyError):
                decode_u16(body(payload))

    def test_reject_extra_data_and_misalignment(self):
        for payload in (struct.pack('<4H', 0xe0, 1, 2, 3), struct.pack('<3H', 0xe0, 1, 0)):
            with self.subTest(payload=payload.hex()), self.assertRaises(BodyError):
                decode_u16(body(payload))

    def test_truncation_extent_and_uncontrolled_dimensions(self):
        valid = bytearray(body(struct.pack('<2H', 0xe0, 1)))
        for offset, value in ((4, 0), (8, 0xffffffff), (16, 0xffffffff), (20, 0xffffffff),
                              (24, 0xffffffff), (28, 2), (36, 0)):
            data = bytearray(valid)
            struct.pack_into('<I', data, offset, value)
            with self.subTest(offset=offset), self.assertRaises(BodyError):
                parse_header(data)
        with self.assertRaises(BodyError):
            parse_header(valid[:39])
        with self.assertRaises(BodyError):
            decode_u16(body(b'\0\0', mode=0))
        with self.assertRaises(BodyError):
            parse_header(body(b'', width=4096, height=4096))

    def test_placeholder_and_unsupported_mode_never_decode(self):
        placeholder = struct.pack('<10I', 2, *([0xffffffff]*8), 28)
        self.assertTrue(parse_header(placeholder).placeholder)
        for data in (placeholder, body(b'', mode=2), body(b'', mode=5), body(b'', bits=32)):
            with self.subTest(data=data.hex()), self.assertRaises(BodyError):
                decode_u16(data)
        with self.assertRaises(BodyError):
            parse_header(placeholder+b'\0')

    @unittest.skipUnless(os.environ.get('IMRC_SAMPLE'), 'IMRC_SAMPLE not supplied')
    def test_indexed_real_mode1_resource(self):
        from imrc_bounded_decode import Decoder
        from imrc_resource_index import LogicalReader, parse_index, parse_rbm_index
        with Path(os.environ['IMRC_SAMPLE']).open('rb') as source:
            with mmap.mmap(source.fileno(), 0, access=mmap.ACCESS_READ) as data:
                reader = LogicalReader(Decoder(data))
                index = parse_index(reader)
                entry = next(x for x in index['files'] if
                             x['path'] == 'System/Rsrc/Bmp/Black/MsgTypeIcon.rbm')
                record = parse_rbm_index(reader, entry)['records'][0]
                encoded = reader.read(record['logical_offset'], record['length'])
        header = parse_header(encoded)
        self.assertEqual((header.local_id, header.width, header.height, header.mode), (0, 15, 15, 1))
        self.assertEqual(hashlib.sha256(encoded).hexdigest(),
                         '42660237dfc96f9d8b89b809696c35b9887dbc014fbb1fcdf93d62f95872a91b')
        samples, report = decode_u16(encoded)
        self.assertEqual(len(samples), 450)
        self.assertEqual(report, dict(consumed_bytes=184, alignment_bytes=0))
        self.assertEqual(hashlib.sha256(samples).hexdigest(),
                         '89cba3b5c3c3b21aa986829e29f5dc62bc54c416d1dac848050fe08b3763510d')


if __name__ == '__main__':
    unittest.main()
