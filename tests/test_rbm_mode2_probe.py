"""A fitting sample count cannot establish a unique decoded image."""
import hashlib
import mmap
import os
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from rbm_body_probe import BodyError
from rbm_mode2_probe import probe


def body(commands=(0, 0), samples=(0xf800, 0x07e0, 0x001f), width=2, height=1):
    size = 2 * len(commands) + 1
    prefix = struct.pack('>H', size & 0xffff) + struct.pack('<H', size >> 15)
    payload = prefix + struct.pack('>' + 'H' * len(commands), *commands)
    payload += struct.pack('<' + 'H' * len(samples), *samples)
    payload += bytes((-len(payload)) % 4)
    return struct.pack('<10I', 5, 1, len(payload), 2, width, height, 16, 1, 0xf81f, 28) + payload


class Mode2ProbeTests(unittest.TestCase):
    def test_two_fitting_models_can_produce_different_pixels(self):
        result = probe(body())
        self.assertEqual(result['status'], 'unresolved')
        self.assertEqual(result['fitting_models'], 2)
        self.assertEqual(result['distinct_candidate_hashes'], 2)
        models = result['models']
        self.assertEqual(models['first_word_is_literal']['samples_sha256'],
                         hashlib.sha256(struct.pack('<2H', 0xf800, 0x07e0)).hexdigest())
        self.assertEqual(models['first_word_is_hidden_seed']['samples_sha256'],
                         hashlib.sha256(struct.pack('<2H', 0x07e0, 0x001f)).hexdigest())

    def test_uniform_data_does_not_prove_model_choice(self):
        result = probe(body(samples=(1, 1, 1)))
        self.assertEqual(result['fitting_models'], 2)
        self.assertEqual(result['distinct_candidate_hashes'], 1)
        self.assertEqual(result['status'], 'unresolved')

    def test_command_extent_crosses_16_bit_size_boundary(self):
        result = probe(body(commands=(0,) * 32900, samples=(1,) * 32901, width=100, height=329))
        self.assertEqual(result['candidate_command_range'], [4, 65804])
        self.assertEqual(result['candidate_command_count'], 32900)
        self.assertEqual(result['fitting_models'], 2)

    def test_special_flag_stays_unresolved_without_guessing(self):
        result = probe(body(commands=(0, 0x1801)))
        self.assertEqual(result['flagged_commands'], 1)
        self.assertNotIn('models', result)
        self.assertEqual(result['status'], 'unresolved')

    def test_distance_overflow_and_exhaustion_are_bounded(self):
        for encoded in (body(commands=(0x1002,)), body(width=1),
                        body(commands=(0, 0, 0, 0), samples=(1,)),
                        body(commands=(0x1000,))):
            with self.subTest(encoded=encoded.hex()):
                result = probe(encoded)
                self.assertEqual(result['status'], 'unresolved')
                self.assertEqual(result['fitting_models'], 0)

    def test_truncated_prefix_extent_and_redundant_bit(self):
        valid = bytearray(body())
        for offset, value in ((40, 0xff), (42, 1)):
            encoded = bytearray(valid)
            encoded[offset] = value
            with self.subTest(offset=offset), self.assertRaises(BodyError):
                probe(encoded)
        struct.pack_into('<I', valid, 8, 2)
        with self.assertRaises(BodyError):
            probe(valid[:42])

    @unittest.skipUnless(os.environ.get('IMRC_SAMPLE'), 'IMRC_SAMPLE not supplied')
    def test_real_body_has_two_fitting_distinct_results_and_contact_stays_unknown(self):
        from imrc_bounded_decode import Decoder
        from imrc_resource_index import LogicalReader, parse_index, parse_rbm_index
        with Path(os.environ['IMRC_SAMPLE']).open('rb') as source:
            with mmap.mmap(source.fileno(), 0, access=mmap.ACCESS_READ) as data:
                reader = LogicalReader(Decoder(data))
                index = parse_index(reader)
                paths = {entry['path']: entry for entry in index['files']}
                results = []
                for name, local_id in (('Br_Cd_Etc', 0), ('ContactRsrcBmp', 117)):
                    entry = paths[f'System/Rsrc/Bmp/Black/{name}.rbm']
                    record = parse_rbm_index(reader, entry)['records'][local_id]
                    results.append(probe(reader.read(record['logical_offset'], record['length'])))
        ordinary, special = results
        self.assertEqual(ordinary['body_sha256'],
                         '367a0b0f2acffd799e23893c9836dfbc599a42bb1ae23be2efcc1b075fb171d1')
        self.assertEqual((ordinary['fitting_models'], ordinary['distinct_candidate_hashes']), (2, 2))
        self.assertEqual({m['sample_count'] for m in ordinary['models'].values()}, {49})
        self.assertEqual(special['flagged_commands'], 4)
        self.assertEqual(special['status'], 'unresolved')
        self.assertNotIn('models', special)
