"""Batch coverage, opaque encodings and retained failure context."""
import hashlib
import mmap
import os
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from imrc_bounded_decode import Decoder
from imrc_resource_index import LogicalReader
from rbm_bank_survey import survey
from rbm_body_probe import BodyError
from test_imrc_resource_index import bank, logical_image


def reader_for(bodies):
    start = 12 + 16 * len(bodies)
    table = bytearray(struct.pack('<III', 0, 0x100, len(bodies)))
    for local_id, encoded in enumerate(bodies):
        table.extend(struct.pack('<4I', 0x100, local_id, start, len(encoded)))
        start += len(encoded)
    image = logical_image(bytes(table) + b''.join(bodies)).replace(b'icon.png', b'icon.rbm')
    return LogicalReader(Decoder(bank(image)))


def ordinary(local_id, mode=1, payload=b'\xe0\0\x34\x12'):
    return struct.pack('<10I', local_id, 1, len(payload), mode, 3, 1, 16, 0, 0, 28) + payload


class SurveyTests(unittest.TestCase):
    def test_headers_skip_opaque_payload_and_placeholder_sentinels(self):
        bodies = [ordinary(0), struct.pack('<10I', 1, *([0xffffffff] * 8), 28),
                  ordinary(2, mode=2, payload=b'opaque!!')]
        report = {}
        survey(reader_for(bodies), set(), report)
        self.assertEqual(report['status'], 'ok')
        self.assertEqual(report['mode_counts'], {'1/16': 1, '2/16': 1})
        self.assertEqual(report['placeholder_count'], 1)
        self.assertEqual(report['sample_decoded_count'], 0)
        self.assertEqual(len(report['records']), 3)
        self.assertNotIn('decoding', report['records'][0])
        decoded_report = {}
        survey(reader_for(bodies), {0, 1}, decoded_report)
        self.assertEqual(decoded_report['sample_decoded_count'], 1)
        self.assertEqual(decoded_report['records'][0]['decoding']['samples_sha256'],
                         hashlib.sha256(b'\x34\x12' * 3).hexdigest())

    def test_failure_retains_completed_record_and_current_id(self):
        broken = bytearray(ordinary(1))
        struct.pack_into('<I', broken, 8, 0xffffffff)
        report = {}
        with self.assertRaises(BodyError):
            survey(reader_for([ordinary(0), broken]), {1}, report)
        self.assertEqual(len(report['records']), 1)
        self.assertEqual(report['current']['local_id'], 1)

    @unittest.skipUnless(os.environ.get('IMRC_SAMPLE'), 'IMRC_SAMPLE not supplied')
    def test_real_bank_modes_and_counts(self):
        with Path(os.environ['IMRC_SAMPLE']).open('rb') as source:
            with mmap.mmap(source.fileno(), 0, access=mmap.ACCESS_READ) as data:
                report = {}
                survey(LogicalReader(Decoder(data)), {0, 1}, report)
        self.assertEqual(report['rbm_file_count'], 139)
        self.assertEqual(len(report['records']), 11539)
        self.assertEqual(report['sample_decoded_count'], 329)
        self.assertEqual(report['placeholder_count'], 2247)
        self.assertEqual(report['mode_counts'], {'0/16': 33, '1/16': 296,
                         '2/16': 4434, '2/32': 4508, '5/16': 1, '5/32': 20})
