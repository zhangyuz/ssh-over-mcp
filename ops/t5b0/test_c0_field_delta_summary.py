"""Privacy-safe counts of altered semantic fields in C0 machine comparison."""
import copy
import json
import tempfile
import unittest
from pathlib import Path

from test_c0_guidance import VALID, run

FIELD_COUNTS = {'url': 0, 'sha256': 0, 'bytes': 0, 'max_bytes': 0}


def document(objects):
    return json.dumps({'schema': VALID['schema'], 'objects': objects,
                       'approval': None}).encode()


class FieldDeltaSummaryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.old = self.root / 'secret-before.json'
        self.new = self.root / 'secret-after.json'
        self.original = copy.deepcopy(VALID['objects'][0])
        self.old.write_bytes(document([self.original]))
        self.new.write_bytes(document([self.original]))

    def review(self, *flags, input_bytes=b'', expected_code=0):
        code, output, err = run([*flags, '--summary-json', '--fail-on-change'], input_bytes)
        self.assertEqual((code, err), (expected_code, ''))
        for secret in (str(self.root), 'secret-', 'https://',
                       self.original['sha256'], 'C0-W1'):
            self.assertNotIn(secret, output)
        self.assertEqual(json.loads(output)['review_schema'],
                         'som-t5b0-c0-summary-json-v1')
        return json.loads(output)

    def test_all_four_fields_changed_are_counted_without_values(self):
        changed = copy.deepcopy(self.original)
        changed.update(url='https://example.org/new-whl', sha256='b'*64,
                       bytes=17, max_bytes=22)
        self.new.write_bytes(document([changed]))
        cases = [(['--compare-files', self.old, self.new], b''),
                 (['--compare-file-to-stdin', self.old], self.new.read_bytes()),
                 (['--compare-stdin-to-file', self.new], self.old.read_bytes()),
                 (['--compare-stdin-batches'],
                  self.old.read_bytes() + b'\n---\n' + self.new.read_bytes())]
        for args, incoming in cases:
            with self.subTest(route=args[0]):
                result = self.review(*args, input_bytes=incoming, expected_code=3)
                self.assertEqual(result['status'], 'CHANGED')
                self.assertEqual(result['object_change_counts'],
                                 {'added': 0, 'removed': 0, 'changed': 1})
                self.assertEqual(result['object_field_change_counts'],
                                 dict.fromkeys(FIELD_COUNTS, 1))

    def test_two_changed_ids_count_independently_by_field(self):
        second = copy.deepcopy(self.original)
        second.update(id='C0-P1', url='https://example.org/second', sha256='c'*64)
        before = [self.original, second]
        after = copy.deepcopy(before)
        after[0]['sha256'] = 'd'*64
        after[1]['sha256'] = 'e'*64
        after[1]['bytes'] = 19
        self.old.write_bytes(document(before))
        self.new.write_bytes(document(after))
        result = self.review('--compare-files', self.old, self.new, expected_code=3)
        self.assertEqual(result['object_change_counts']['changed'], 2)
        self.assertEqual(result['object_field_change_counts'],
                         {'url': 0, 'sha256': 2, 'bytes': 1, 'max_bytes': 0})

    def test_added_removed_and_unchanged_have_zero_field_counts(self):
        result = self.review('--compare-files', self.old, self.new)
        self.assertEqual(result['object_field_change_counts'], FIELD_COUNTS)
        changed = copy.deepcopy(self.original)
        changed.update(id='C0-P1', sha256='b'*64, url='https://example.org/second')
        self.new.write_bytes(document([changed]))
        result = self.review('--compare-files', self.old, self.new, expected_code=3)
        self.assertEqual(result['object_change_counts'],
                         {'added': 1, 'removed': 1, 'changed': 0})
        self.assertEqual(result['object_field_change_counts'], FIELD_COUNTS)

    def test_either_side_refusal_is_null_not_partial_zero(self):
        for bad_first in (True, False):
            with self.subTest(bad_first=bad_first):
                self.old.write_bytes(b'{' if bad_first else document([self.original]))
                self.new.write_bytes(document([self.original]) if bad_first else b'{')
                result = self.review('--compare-files', self.old, self.new,
                                     expected_code=2)
                self.assertEqual(result['object_changes'], 'UNAVAILABLE')
                self.assertIsNone(result['object_change_counts'])
                self.assertIsNone(result['object_field_change_counts'])

    def test_single_input_and_legacy_output_not_changed(self):
        code, output, err = run(['--stdin', '--summary-json'],
                                document([self.original]))
        self.assertEqual((code, err), (0, ''))
        self.assertNotIn('object_field_change_counts', json.loads(output))
        code, output, err = run(['--compare-files', self.old, self.new, '--json'])
        self.assertEqual((code, err), (0, ''))
        self.assertNotIn('object_field_change_counts', json.loads(output))


if __name__ == '__main__':
    unittest.main()
