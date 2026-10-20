"""Direct pair-of-files C0 offline review contracts; no collection authorization."""
import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from test_c0_guidance import VALID

SCRIPT = Path(__file__).with_name('c0_manifest_preflight.py')


def invoke(args, *, data=b''):
    result = subprocess.run([sys.executable, str(SCRIPT), *map(str, args)],
                            input=data, capture_output=True, check=False, timeout=8)
    parsed = json.loads(result.stdout) if result.stdout.startswith(b'{') else None
    return result, parsed


class CompareFilesTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.before = self.root / 'secret-before.json'
        self.after = self.root / 'secret-after.json'
        self.before.write_bytes(json.dumps(VALID).encode())
        self.after.write_bytes(json.dumps(VALID).encode())

    def check_private(self, output):
        for secret in (self.tmp.name, 'secret-before', 'secret-after',
                       'https://', 'a' * 64, 'b' * 64):
            self.assertNotIn(secret, output)

    def test_identical_manifests_are_unchanged_in_all_presentations(self):
        for flags in ((), ('--fail-on-change',), ('--summary',), ('--summary-json',),
                      ('--summary', '--guidance'), ('--json',)):
            with self.subTest(flags=flags):
                proc, report = invoke(['--compare-files', self.before, self.after, *flags])
                self.assertEqual((proc.returncode, proc.stderr), (0, b''))
                self.check_private(proc.stdout.decode())
                if '--summary' in flags:
                    self.assertIn(b'C0 offline review: UNCHANGED', proc.stdout)
                    self.assertIn(b'Object changes: none', proc.stdout)
                else:
                    self.assertEqual(report['status'], 'UNCHANGED')
                    if '--summary-json' in flags:
                        self.assertEqual(report['review_schema'], 'som-t5b0-c0-summary-json-v1')
                        self.assertEqual(report['review_mode'], 'FILE_COMPARISON')
                        self.assertEqual(report['next_action_codes'], ['VERIFY_INDEPENDENT_EVIDENCE'])
                        self.assertEqual(report['object_change_counts'],
                                         {'added': 0, 'removed': 0, 'changed': 0})
                    else:
                        self.assertEqual(report['object_diff']['status'], 'AVAILABLE')
                        self.assertNotIn('_objects', json.dumps(report))
                    self.assertEqual(report['authorization'], 'NO_AUTHORIZATION')
                    self.assertEqual(report['collection'], 'C0_COLLECT_HOLD')
                    self.assertEqual(report['network'], 'NO_NETWORK')

    def test_each_semantic_field_and_added_removed_change_gate(self):
        for field, value in (('url', 'https://example.org/moved.whl'),
                             ('sha256', 'b'*64), ('bytes', 90), ('max_bytes', 110)):
            with self.subTest(field=field):
                changed = copy.deepcopy(VALID)
                changed['objects'][0][field] = value
                self.after.write_bytes(json.dumps(changed).encode())
                for fmt in (('--summary-json',), ('--json',)):
                    proc, report = invoke(['--compare-files', self.before, self.after,
                                           '--fail-on-change', *fmt])
                    self.assertEqual((proc.returncode, proc.stderr), (3, b''))
                    self.assertEqual(report['status'], 'CHANGED')
                    self.check_private(proc.stdout.decode())
                    if '--summary-json' in fmt:
                        self.assertEqual(report['review_mode'], 'FILE_COMPARISON')
                        self.assertEqual(report['object_change_counts'],
                                         {'added': 0, 'removed': 0, 'changed': 1})
                        self.assertEqual(report['next_action_codes'],
                                         ['REVIEW_OBSERVED_CHANGES',
                                          'VERIFY_INDEPENDENT_EVIDENCE'])
                    else:
                        self.assertEqual(report['object_diff']['changed'],
                                         [{'id': 'C0-W1', 'fields': [field]}])
        renamed = copy.deepcopy(VALID)
        renamed['objects'][0]['id'] = 'C0-P1'
        self.after.write_bytes(json.dumps(renamed).encode())
        proc, report = invoke(['--compare-files', self.before, self.after,
                               '--fail-on-change', '--summary-json'])
        self.assertEqual(proc.returncode, 3)
        self.assertEqual(report['object_change_counts'],
                         {'added': 1, 'removed': 1, 'changed': 0})
        self.assertNotIn('C0-P1', proc.stdout.decode())

    def test_bad_either_or_both_refuse_and_hide_incomplete_diff(self):
        valid = json.dumps(VALID).encode()
        for a, b in ((b'{', valid), (valid, b'{'), (b'{', b'{'),
                     (b'X'*16385, valid), (valid, b'X'*16385)):
            with self.subTest(a=len(a), b=len(b)):
                self.before.write_bytes(a)
                self.after.write_bytes(b)
                for fmt in (('--json',), ('--summary-json',)):
                    proc, report = invoke(['--compare-files', self.before, self.after,
                                           '--fail-on-change', *fmt])
                    self.assertEqual((proc.returncode, proc.stderr), (2, b''))
                    self.assertEqual(report['status'], 'REFUSED')
                    self.check_private(proc.stdout.decode())
                    self.assertEqual(report['object_diff']['status'], 'UNAVAILABLE') if '--json' in fmt else None
                    if '--summary-json' in fmt:
                        self.assertEqual(report['object_changes'], 'UNAVAILABLE')
                        self.assertIsNone(report['object_change_counts'])
                        self.assertIn('RETRY_OFFLINE_REVIEW', report['next_action_codes'])
                        self.assertEqual(report['review_mode'], 'FILE_COMPARISON')

    def test_file_reads_refuse_symlinks_fifos_missing_and_directories(self):
        self.after.unlink()
        for kind in ('symlink', 'fifo', 'directory', 'missing'):
            with self.subTest(kind=kind):
                if kind == 'symlink':
                    self.after.symlink_to(self.before)
                elif kind == 'fifo':
                    os.mkfifo(self.after)
                elif kind == 'directory':
                    self.after.mkdir()
                proc, report = invoke(['--compare-files', self.before, self.after,
                                       '--summary-json'])
                self.assertEqual(proc.returncode, 2, proc.stderr)
                self.assertEqual(report['status'], 'REFUSED')
                self.assertIsNone(report['object_change_counts'])
                self.check_private(proc.stdout.decode())
                if kind == 'symlink' or kind == 'fifo':
                    self.after.unlink()
                elif kind == 'directory':
                    self.after.rmdir()

    def test_strict_option_and_all_other_modes_conflict_pre_read(self):
        other_flags = [('--stdin',), ('--stdin-batch',), ('--compare-stdin-batches',),
                       ('--directory', self.root), ('--compare-directories', self.root, self.root),
                       ('--compare-stdin-to-directory', self.root),
                       ('--compare-stdin-before-directory', self.root),
                       ('--batch', self.before), (self.before,), ('--require-json-only',)]
        for flags in other_flags:
            with self.subTest(flags=flags):
                proc, report = invoke(['--compare-files', self.before, self.after, *flags])
                self.assertEqual(proc.returncode, 2, proc.stderr)
                self.assertIsNone(report)
                self.assertEqual(proc.stdout, b'')
                self.assertIn(b'cannot be combined', proc.stderr)
        proc, _ = invoke(['--compare-files', self.before, self.after,
                          '--summary-json', '--json'])
        self.assertEqual(proc.returncode, 2)
        self.assertIn(b'not allowed', proc.stderr)


if __name__ == '__main__':
    unittest.main()
