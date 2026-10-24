"""Directory-model invariants and file-boundary checks, without vendor bytes."""
import hashlib
import os
from pathlib import Path
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from imrc_bounded_decode import Decoder, DecodeError
from imrc_resource_index import LogicalReader, parse_index, parse_rbm_index, inspect, validate_resource
from test_imrc_bounded_decode import png


def name(value):
    return value.encode('ascii').ljust(44, b'\0')


def logical_image(payload=None, child=False):
    payload = png() if payload is None else payload
    root_size = 12 + (48 if child else 0) + (0 if child else 52)
    index_end = 0x40 + root_size + (64 if child else 0)
    size = index_end + len(payload)
    header = struct.pack('<II', 1, 1) + name('System') + struct.pack('<III', 0x40, size, 0)
    file_entry = name('icon.png') + struct.pack('<II', index_end, len(payload))
    if child:
        root = struct.pack('<III', 0, 1, 0) + name('Img') + struct.pack('<I', 0x40+root_size)
        root += struct.pack('<III', 0x40, 0, 1) + file_entry
    else:
        root = struct.pack('<III', 0, 0, 1) + file_entry
    return header + root + payload


def bank(logical):
    blocks = [logical[i:i+4096] for i in range(0, len(logical), 4096)]
    return (b'IMRC' + struct.pack('<6I', 0x02000400, 4096, 12, 6, len(logical), len(blocks))
            + b''.join(struct.pack('<II', 0, len(block)) for block in blocks)
            + logical)


def parse(logical):
    return parse_index(LogicalReader(Decoder(bank(logical))))


class IndexTests(unittest.TestCase):
    def test_name_offset_length_lookup(self):
        logical = logical_image()
        result = parse(logical)
        self.assertEqual(result['file_count'], 1)
        self.assertEqual(result['directory_count'], 1)
        self.assertEqual(result['index_end'], 0x80)
        self.assertEqual(result['files'][0], dict(path='System/icon.png', entry_offset=0x4c,
                                                offset=0x80, length=len(png())))
        self.assertEqual(result['metadata_sha256'], hashlib.sha256(logical[:0x80]).hexdigest())

    def test_nested_directory_parent_and_payload(self):
        result = parse(logical_image(child=True))
        self.assertEqual(result['directory_count'], 2)
        self.assertEqual(result['index_end'], 0xbc)
        self.assertEqual(result['files'][0]['path'], 'System/Img/icon.png')

    def test_bad_header_parent_counts_and_extent(self):
        for offset, value in ((0x34, 0x44), (0x38, 0xffffffff), (0x40, 0x40),
                              (0x48, 0xffffffff), (0x78, 0x40), (0x7c, 0xffffffff)):
            logical = bytearray(logical_image())
            struct.pack_into('<I', logical, offset, value)
            with self.subTest(offset=offset), self.assertRaises(DecodeError):
                parse(logical)

    def test_directory_cycle(self):
        logical = bytearray(logical_image(child=True))
        struct.pack_into('<I', logical, 0x78, 0x40)
        with self.assertRaisesRegex(DecodeError, 'cycle'):
            parse(logical)

    def test_name_safety(self):
        for raw in (b'../icon.png', b'a/b.png', b'a\\b.png', b'\x80.png', b'.'):
            logical = bytearray(logical_image())
            logical[0x4c:0x78] = raw.ljust(44, b'\0')
            with self.subTest(name=raw), self.assertRaises(DecodeError):
                parse(logical)

    def test_structural_png_validation_requires_indexed_end(self):
        self.assertTrue(validate_resource(png())['valid'])
        self.assertFalse(validate_resource(png()+b'junk')['valid'])
        invalid = bytearray(png()); invalid[-1] ^= 1
        self.assertFalse(validate_resource(invalid)['valid'])

    def test_fws_tag_extent(self):
        body = b'\x08\x00' + b'\x00\x0c\x01\x00' + b'\x00\x00'
        swf = b'FWS\x07' + struct.pack('<I', 8+len(body)) + body
        self.assertTrue(validate_resource(swf)['valid'])
        self.assertFalse(validate_resource(swf[:-1])['valid'])
        self.assertFalse(validate_resource(swf+b'junk')['valid'])

    def test_xml_complete_span_and_entities(self):
        self.assertEqual(validate_resource(b'<?xml version="1.0"?><bookmark/>')['root_element'], 'bookmark')
        self.assertFalse(validate_resource(b'<?xml version="1.0"?><bookmark>')['valid'])
        malicious = b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "expansion">]><x>&a;</x>'
        self.assertFalse(validate_resource(malicious)['valid'])

    def test_riff_ixml_subresource_boundary(self):
        xml = b'<?xml version="1.0"?><BWFXML/>'
        def chunk(kind, data):
            return kind + struct.pack('<I', len(data)) + data + bytes(len(data) % 2)
        body = b'WAVE' + chunk(b'fmt ', bytes(16)) + chunk(b'data', b'1234') + chunk(b'iXML', xml)
        riff = b'RIFF' + struct.pack('<I', len(body)) + body
        result = validate_resource(riff)
        self.assertTrue(result['valid'])
        self.assertEqual(result['chunks'][-1]['validation']['root_element'], 'BWFXML')
        self.assertEqual(result['chunks'][-1]['length'], len(xml))
        self.assertFalse(validate_resource(riff[:-1])['valid'])

    def test_rbm_local_ids_and_complete_extents(self):
        rbm = (struct.pack('<III', 0, 0x100, 2)
               + struct.pack('<4I', 0x100, 0, 44, 12)
               + struct.pack('<4I', 0x100, 1, 56, 12)
               + struct.pack('<I', 0) + bytes(8) + struct.pack('<I', 1) + bytes(8))
        entry = dict(path='System/test.rbm', offset=0, length=len(rbm))
        reader = LogicalReader(Decoder(bank(rbm)))
        result = parse_rbm_index(reader, entry)
        self.assertEqual(result['count'], 2)
        self.assertTrue(result['ordinal_ids'])
        self.assertEqual(result['records'][1], dict(local_id=1, kind=0x100, file_offset=56,
                                                  logical_offset=56, length=12, body_id=1))
        for position, value in ((8, 0xffffffff), (24, 13), (36, 1), (40, 0xffffffff), (56, 0)):
            invalid = bytearray(rbm); struct.pack_into('<I', invalid, position, value)
            with self.subTest(position=position), self.assertRaises(DecodeError):
                parse_rbm_index(LogicalReader(Decoder(bank(invalid))), entry)

    def test_rbm_lookup_exports_exact_local_id_body(self):
        body = struct.pack('<I', 7) + bytes(range(8))
        rbm = struct.pack('<III', 0, 0x100, 1) + struct.pack('<4I', 0x100, 7, 28, len(body)) + body
        logical = bytearray(logical_image(rbm))
        logical[0x4c:0x78] = name('icons.rbm')
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / 'fixture.imrc'; source.write_bytes(bank(logical))
            result = inspect(source, [], Path(tmp)/'output', rbm_requests=[('System/icons.rbm', 7)])
            record = result['selected_rbm_records'][0]
            self.assertEqual(record['logical_offset'], 0x80+28)
            self.assertEqual(record['sha256'], hashlib.sha256(body).hexdigest())
            self.assertEqual(Path(record['extracted_path']).read_bytes(), body)
            with self.assertRaisesRegex(DecodeError, 'ID absent'):
                inspect(source, [], rbm_requests=[('System/icons.rbm', 8)])

    def test_verify_and_extract_only_indexed_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / 'fixture.imrc'; source.write_bytes(bank(logical_image(child=True)))
            output = Path(tmp) / 'extracted'
            result = inspect(source, ['System/Img/icon.png'], output)
            self.assertTrue(result['verified_files'][0]['validation']['valid'])
            self.assertEqual((output/'System/Img/icon.png').read_bytes(), png())
            with self.assertRaisesRegex(DecodeError, 'absent'):
                inspect(source, ['System/missing.png'])
            self.assertEqual(source.read_bytes(), bank(logical_image(child=True)))


@unittest.skipUnless(os.environ.get('IMRC_SAMPLE'), 'set IMRC_SAMPLE for private sample checks')
class SampleIndexTests(unittest.TestCase):
    def test_index_and_png_extent(self):
        result = inspect(Path(os.environ['IMRC_SAMPLE']), ['System/Media/Img/Java/checkbox_off.png'])
        index = result['index']
        self.assertEqual((index['directory_count'], index['file_count'], index['index_end']), (101, 736, 0xad3c))
        self.assertEqual(index['metadata_sha256'], 'c30c58587eaf4c0dd6179dd1bc86632708ef247f6f10328ac9fb72d29f8d7c77')
        item = result['verified_files'][0]
        self.assertEqual((item['entry_offset'], item['offset'], item['length']), (0xb50, 0x1068d78, 996))
        self.assertEqual(item['sha256'], '178085e5cc8cc651a51102bd52df565f3f9eba86779b2fae27f729feac03de45')
        self.assertTrue(item['validation']['valid'])
        self.assertLessEqual(len(result['decoded_blocks']), 13)


if __name__ == '__main__':
    unittest.main()
