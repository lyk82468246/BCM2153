"""Synthetic safety/format regressions; private sample checks are opt-in."""
import hashlib
import os
import json
import subprocess
from pathlib import Path
import struct
import sys
import tempfile
import unittest
import zlib

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
from imrc_bounded_decode import (Decoder, DecodeError, MAX_SELECTED, inspect,
                                 parse_selection, png_spans)
from imrc_public_compare import table_model


def bits(value):
    padded = value + '0' * (-len(value) % 8)
    return int(padded, 2).to_bytes(len(padded) // 8, 'big')


def container(cmd=b'', data=bytes(range(32)), size=32, block_size=32):
    return (b'IMRC' + struct.pack('<6I', 0x02000400, block_size, 12, 6, size, 1)
            + struct.pack('<2I', len(cmd), len(data)) + cmd + data)


def decode(payload):
    dec = Decoder(payload)
    out = bytearray()
    stats = dec.decode_block(0, out)
    return bytes(out), stats


def png():
    def chunk(kind, data):
        return (struct.pack('>I', len(data)) + kind + data
                + struct.pack('>I', zlib.crc32(kind + data)))
    return (b'\x89PNG\r\n\x1a\n'
            + chunk(b'IHDR', struct.pack('>IIBBBBB', 1, 1, 8, 2, 0, 0, 0))
            + chunk(b'IDAT', zlib.compress(b'\x00\xff\x00\x00'))
            + chunk(b'IEND', b''))


class DecoderTests(unittest.TestCase):
    def test_literal_record(self):
        out, _ = decode(container())
        self.assertEqual(out, bytes(range(32)))

    def test_compressed_literals(self):
        out, stats = decode(container(bits('10101' * 3 + '00')))
        self.assertEqual(out, bytes(range(32)))
        self.assertEqual(stats['command_bits_consumed'], 17)

    def test_word_and_overlapping_byte_copy(self):
        out, stats = decode(container(bits('111' * 3 + '01'), b'ABCD'))
        self.assertEqual(out, b'ABCD' * 8)
        self.assertEqual(stats['maximum_distance'], 4)

    def test_xor_difference_dictionary(self):
        out, _ = decode(container(bits('10000' * 3), b'ABCD' + b'\x00' * 6, size=16))
        self.assertEqual(out, b'ABCD@BBD' * 2)

    def test_mixed_group(self):
        # Initial group copies, then a mixed group with eight distance copies.
        out, _ = decode(container(bits('111' * 3 + '1' + '1' * 4), b'ABCD\xff'))
        self.assertEqual(out, b'ABCD' * 8)

    def test_non_imrc(self):
        with self.assertRaisesRegex(DecodeError, 'not an IMRC'):
            Decoder(b'NOPE' + bytes(64))

    def test_truncated_header(self):
        with self.assertRaisesRegex(DecodeError, 'truncated'):
            Decoder(b'IMRC')

    def test_truncated_table(self):
        with self.assertRaisesRegex(DecodeError, 'table exceeds'):
            Decoder(container()[:31])

    def test_truncated_record(self):
        with self.assertRaisesRegex(DecodeError, 'record exceeds'):
            Decoder(container()[:-1])

    def test_uncontrolled_length_fields(self):
        # Every u32 length/bit/count header field is bounded before allocation.
        for offset in (8, 12, 16, 20, 24):
            data = bytearray(container())
            struct.pack_into('<I', data, offset, 0xffffffff)
            with self.subTest(offset=offset), self.assertRaises(DecodeError):
                Decoder(data)

    def test_version(self):
        data = bytearray(container()); struct.pack_into('<I', data, 4, 0x03000000)
        with self.assertRaisesRegex(DecodeError, 'unsupported'):
            Decoder(data)

    def test_command_exhaustion(self):
        report = Decoder(container(b'\xaa')).decode([0])
        self.assertEqual(report['status'], 'failed')
        self.assertIn('command stream exhausted', report['error'])
        self.assertEqual(report['failed_block'], 0)

    def test_data_exhaustion(self):
        with self.assertRaisesRegex(DecodeError, 'data stream exhausted'):
            decode(container(bits('10101' * 3 + '00'), b'ABCD'))

    def test_zero_and_out_of_window_distance(self):
        for distance in (0, 1, 4095):
            cmd = bits('00' + f'{distance:012b}' + '1')
            with self.subTest(distance=distance), self.assertRaisesRegex(DecodeError, 'distance'):
                decode(container(cmd, b'ABCD'))

    def test_literal_length_mismatch(self):
        with self.assertRaisesRegex(DecodeError, 'length mismatch'):
            decode(container(data=b'ABCD'))

    def test_unused_data(self):
        with self.assertRaisesRegex(DecodeError, 'unused data'):
            decode(container(bits('111' * 3 + '01'), b'ABCDextra'))

    def test_selections(self):
        self.assertEqual(parse_selection('0,2:5,0x10'), [0, 2, 3, 4, 16])
        for selection in ('', '1:1', '0:4294967295', '0:2:3', 'hello'):
            with self.subTest(selection=selection), self.assertRaises(DecodeError):
                parse_selection(selection)
        for indices in ([], [-1], [1]):
            with self.assertRaises(DecodeError): Decoder(container()).decode(indices)

    def test_selection_budget_before_decode(self):
        # This valid 8 MiB + one block header/table needs no output allocation.
        count = MAX_SELECTED // 4096 + 1
        payload = (b'IMRC' + struct.pack('<6I', 0x02000400, 4096, 12, 6, count*4096, count)
                   + bytes(count*8))
        with self.assertRaisesRegex(DecodeError, 'selection exceeds'):
            Decoder(payload).decode(list(range(count)))

    def test_png_bounds_crc_and_cross_block_extraction(self):
        image = png()
        self.assertEqual(list(png_spans(image)), [(0, image)])
        bad = bytearray(image); bad[-1] ^= 1
        self.assertFalse(list(png_spans(bad)))
        self.assertFalse(list(png_spans(image[:-1])))
        data = b'prefix' + image
        data += bytes(-len(data) % 32)
        blocks = [data[i:i+32] for i in range(0, len(data), 32)]
        payload = (b'IMRC' + struct.pack('<6I', 0x02000400, 32, 12, 6, len(data), len(blocks))
                   + b''.join(struct.pack('<II', 0, len(b)) for b in blocks) + data)
        report = Decoder(payload).decode(list(range(len(blocks))), scan=True)
        self.assertEqual(report['resources'][0]['offset'], '0x6')
        self.assertEqual(report['resources'][0]['length'], len(image))
        self.assertEqual(report['resources'][0]['sha256'], hashlib.sha256(image).hexdigest())
        # Noncontiguous block selections must never be glued into a resource.
        self.assertFalse(Decoder(payload).decode([0, 2], scan=True)['resources'])

    def test_cli_safe_failure_and_input_preservation(self):
        script = Path(__file__).resolve().parents[1] / 'tools/imrc_bounded_decode.py'
        huge = bytearray(container()); struct.pack_into('<I', huge, 20, 0xffffffff)
        samples = [b'NOPE' + bytes(32), b'IMRC', container()[:31], huge,
                   container(bits('00' + '0'*12 + '1'), b'ABCD')]
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'input.imrc'
            for sample in samples:
                with self.subTest(size=len(sample)):
                    path.write_bytes(sample)
                    completed = subprocess.run([sys.executable, str(script), str(path)],
                                               capture_output=True, text=True, timeout=5)
                    self.assertEqual(completed.returncode, 2)
                    report = json.loads(completed.stdout)
                    self.assertEqual(report.get('decode', report)['status'], 'failed')
                    self.assertEqual(path.read_bytes(), sample)
            path.write_bytes(container())
            completed = subprocess.run([sys.executable, str(script), str(path), '--out', str(path)],
                                       capture_output=True, timeout=5)
            self.assertEqual(completed.returncode, 2)
            self.assertEqual(path.read_bytes(), container())

    def test_boundary_models(self):
        payload = container() + b'\xcd\xab\xcd\xab' + bytes(1020)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'synthetic.imrc'; path.write_bytes(payload)
            eof = inspect(path, [0], boundary='eof')
            tktool = inspect(path, [0], boundary='tktool')
            self.assertEqual(eof['decode']['blocks'], tktool['decode']['blocks'])
            self.assertEqual(eof['block_table']['tail_length'], 1024)
        self.assertTrue(table_model(payload, 1, 0x1c, len(payload))['complete'])
        self.assertFalse(table_model(payload, 1, 0x20, len(payload))['complete'])


@unittest.skipUnless(os.environ.get('IMRC_SAMPLE'), 'set IMRC_SAMPLE for private sample checks')
class SampleTests(unittest.TestCase):
    def test_header_table_and_selected_blocks(self):
        r = inspect(Path(os.environ['IMRC_SAMPLE']), [0, 10000, 17252, 17253], boundary='tktool')
        self.assertEqual(r['sha256'], '425f464bbdaae55fb685bd3e2636b76473cd787dde8a6dadd66f03e8c521e1e3')
        self.assertEqual(r['header']['version'], '0x02000400')
        self.assertEqual(r['header']['block_size'], 0x1000)
        self.assertEqual(r['header']['block_count'], 0x4366)
        self.assertEqual(r['header']['decompressed_size'], 0x4365bbc)
        self.assertEqual(r['block_table']['packed_end'], '0x2e0c9b6')
        self.assertEqual(r['decode']['status'], 'ok')
        self.assertEqual([b['sha256'] for b in r['decode']['blocks']], [
            '1b5b531f0eac403b2bf07664bad0493316723880d1d1865a2f1bf19d5884126f',
            '3043b88a81746f398ac31897eaff5e9a69050305cc2e097e39de141e25cc8656',
            'e2c151e4d52ca7025843acc0c68af898533d2c3924016b29d9b89c7256692638',
            '4278d17e4e6a5ce52f9d2f7cb7dab009bb4fcbfe4408b352b865a2c9b011dca9'])


if __name__ == '__main__':
    unittest.main()
