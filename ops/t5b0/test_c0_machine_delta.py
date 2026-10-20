"""Privacy-safe semantic delta counts for offline machine review."""
import copy
import json
import tempfile
import unittest
from pathlib import Path

from test_c0_guidance import VALID, run


class MachineDeltaTests(unittest.TestCase):
    def test_four_comparison_modes_show_object_change_counts(self):
        before = json.dumps(VALID).encode()
        newer = copy.deepcopy(VALID)
        newer['objects'][0]['sha256'] = 'b' * 64
        after = json.dumps(newer).encode()
        with tempfile.TemporaryDirectory() as tmp:
            old_dir, new_dir = Path(tmp) / 'old', Path(tmp) / 'new'
            old_dir.mkdir()
            new_dir.mkdir()
            (old_dir / 'secret.json').write_bytes(before)
            (new_dir / 'secret.json').write_bytes(after)
            cases = [(['--compare-directories', old_dir, new_dir], b''),
                     (['--compare-stdin-to-directory', old_dir], after),
                     (['--compare-stdin-before-directory', new_dir], before),
                     (['--compare-stdin-batches'], before + b'\n---\n' + after)]
            for args, input_bytes in cases:
                with self.subTest(args=args):
                    code, output, err = run([*args, '--summary-json', '--fail-on-change'], input_bytes)
                    self.assertEqual((code, err), (3, ''))
                    report = json.loads(output)
                    self.assertEqual(report['status'], 'CHANGED')
                    self.assertEqual(report['object_changes'], 'AVAILABLE')
                    self.assertEqual(report['object_change_counts'],
                                     {'added': 0, 'removed': 0, 'changed': 1})
                    self.assertEqual(report['authorization'], 'NO_AUTHORIZATION')
                    for secret in (tmp, 'secret.json', 'https://', 'b' * 64):
                        self.assertNotIn(secret, output)

    def test_unchanged_yields_zeros_and_single_input_has_no_object_counts(self):
        data = json.dumps(VALID).encode()
        code, output, err = run(['--compare-stdin-batches', '--summary-json'],
                                data + b'\n---\n' + data)
        self.assertEqual((code, err), (0, ''))
        report = json.loads(output)
        self.assertEqual(report['status'], 'UNCHANGED')
        self.assertEqual(report['object_change_counts'],
                         {'added': 0, 'removed': 0, 'changed': 0})
        code, output, err = run(['--stdin', '--summary-json'], data)
        self.assertEqual((code, err), (0, ''))
        self.assertNotIn('object_change_counts', json.loads(output))

    def test_refused_pair_must_not_expose_partial_delta_or_zero_counts(self):
        data = json.dumps(VALID).encode()
        for incoming in (data + b'\n---\n{', b'{\n---\n' + data):
            with self.subTest(incoming=incoming[:8]):
                code, output, err = run(['--compare-stdin-batches', '--summary-json',
                                         '--fail-on-change'], incoming)
                self.assertEqual((code, err), (2, ''))
                report = json.loads(output)
                self.assertEqual(report['object_changes'], 'UNAVAILABLE')
                self.assertIsNone(report['object_change_counts'])
                self.assertNotIn('https://', output)

    def test_added_removed_counts_are_bounded_no_object_ids(self):
        newer = copy.deepcopy(VALID)
        newer['objects'][0]['id'] = 'C0-P1'
        before = json.dumps(VALID).encode()
        after = json.dumps(newer).encode()
        code, output, err = run(['--compare-stdin-batches', '--summary-json'],
                                before + b'\n---\n' + after)
        self.assertEqual((code, err), (0, ''))
        self.assertEqual(json.loads(output)['object_change_counts'],
                         {'added': 1, 'removed': 1, 'changed': 0})
        self.assertNotIn('C0-P1', output)
        self.assertNotIn('C0-W1', output)


if __name__ == '__main__':
    unittest.main()
