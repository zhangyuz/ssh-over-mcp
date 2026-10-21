"""Two bounded local untrusted NDJSON snapshots, no network or admission."""
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


def invoke(before, after, *flags):
    proc = subprocess.run([sys.executable, str(SCRIPT), '--compare-batch-files',
                           str(before), str(after), *flags], capture_output=True,
                          check=False, timeout=8)
    data = json.loads(proc.stdout) if proc.stdout.startswith(b'{') else None
    return proc, data


class TwoLocalBatchTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.before = self.root / 'secret-before.ndjson'
        self.after = self.root / 'secret-after.ndjson'
        self.data = json.dumps(VALID).encode() + b'\n'
        self.before.write_bytes(self.data)
        self.after.write_bytes(self.data)

    def private(self, text):
        for token in (str(self.root), 'secret-', 'https://', 'a'*64, 'b'*64):
            self.assertNotIn(token, text)

    def test_equal_snapshots_all_formats(self):
        for options in (('--summary-json',), ('--json',),
                        ('--summary', '--guidance')):
            with self.subTest(options=options):
                proc, report = invoke(self.before, self.after, *options,
                                      '--fail-on-change')
                self.assertEqual((proc.returncode, proc.stderr), (0, b''))
                self.private(proc.stdout.decode())
                if '--summary' in options:
                    self.assertIn(b'C0 offline review: UNCHANGED', proc.stdout)
                else:
                    self.assertEqual(report['status'], 'UNCHANGED')
                    self.assertEqual(report['authorization'], 'NO_AUTHORIZATION')
                    self.assertEqual(report['network'], 'NO_NETWORK')
                    self.assertEqual(report['collection'], 'C0_COLLECT_HOLD')
                    if '--summary-json' in options:
                        self.assertEqual(report['review_mode'], 'LOCAL_BATCH_COMPARISON')
                        self.assertEqual(report['review_schema'],
                                         'som-t5b0-c0-summary-json-v1')
                        self.assertEqual(report['object_change_counts'],
                                         {'added': 0, 'removed': 0, 'changed': 0})

    def test_valid_changes_and_id_direction(self):
        changed = copy.deepcopy(VALID)
        changed['objects'][0].update(id='C0-P1', sha256='b'*64)
        self.after.write_bytes(json.dumps(changed).encode() + b'\n')
        proc, report = invoke(self.before, self.after, '--json', '--fail-on-change')
        self.assertEqual(proc.returncode, 3)
        self.assertEqual((report['object_diff']['added'], report['object_diff']['removed']),
                         (['C0-P1'], ['C0-W1']))
        proc, report = invoke(self.before, self.after, '--summary-json', '--fail-on-change')
        self.assertEqual(proc.returncode, 3)
        self.assertEqual(report['status'], 'CHANGED')
        self.assertEqual(report['object_change_counts'],
                         {'added': 1, 'removed': 1, 'changed': 0})
        self.private(proc.stdout.decode())

    def test_bad_either_side_refuses_without_partial_diff(self):
        valid = self.data
        for a, b in ((b'{', valid), (valid, b'{'),
                     (b'X'*262161, valid), (valid, b'X'*262161),
                     (valid*17, valid)):
            with self.subTest(a=len(a), b=len(b)):
                self.before.write_bytes(a)
                self.after.write_bytes(b)
                proc, report = invoke(self.before, self.after, '--summary-json', '--fail-on-change')
                self.assertEqual((proc.returncode, proc.stderr), (2, b''))
                self.assertEqual(report['status'], 'REFUSED')
                self.assertEqual(report['object_changes'], 'UNAVAILABLE')
                self.assertIsNone(report['object_change_counts'])
                self.assertIn('RETRY_OFFLINE_REVIEW', report['next_action_codes'])
                self.private(proc.stdout.decode())

    def test_cross_record_conflicts_refuse(self):
        self.before.write_bytes(self.data + self.data)
        proc, report = invoke(self.before, self.after, '--summary-json')
        self.assertEqual(proc.returncode, 2)
        self.assertEqual(report['status'], 'REFUSED')
        self.assertIsNone(report['object_change_counts'])
        self.assertIn('RESOLVE_DUPLICATE_OBJECT_ID', report['next_action_codes'])

    def test_special_files_refuse_nonblocking(self):
        for selected in ('before', 'after'):
            for kind in ('symlink', 'fifo', 'directory', 'missing'):
                with self.subTest(selected=selected, kind=kind):
                    self.before.write_bytes(self.data)
                    self.after.write_bytes(self.data)
                    bad = self.before if selected == 'before' else self.after
                    bad.unlink()
                    if kind == 'symlink':
                        bad.symlink_to(self.before if selected == 'after' else self.after)
                    elif kind == 'fifo':
                        os.mkfifo(bad)
                    elif kind == 'directory':
                        bad.mkdir()
                    proc, report = invoke(self.before, self.after, '--summary-json')
                    self.assertEqual(proc.returncode, 2, proc.stderr)
                    self.assertEqual(report['status'], 'REFUSED')
                    self.assertIsNone(report['object_change_counts'])
                    self.private(proc.stdout.decode())
                    if kind == 'directory':
                        bad.rmdir()
                    elif kind in ('symlink', 'fifo'):
                        bad.unlink()

    def test_conflicting_modes_reject(self):
        for extra in (('--stdin',), ('--stdin-batch',),
                      ('--batch', self.before), ('--compare-stdin-batches',),
                      ('--compare-files', self.before, self.after),
                      ('--compare-file-to-batch', self.before, self.after),
                      ('--compare-directory-to-file', self.root, self.before),
                      ('--compare-directories', self.root, self.root),
                      ('--directory', self.root), ('--capabilities-json',),
                      ('--require-json-only',), (self.before,)):
            with self.subTest(extra=extra):
                proc, _ = invoke(self.before, self.after, *map(str, extra))
                self.assertEqual(proc.returncode, 2)
                self.assertEqual(proc.stdout, b'')
                self.assertIn(b'cannot be combined', proc.stderr)


if __name__ == '__main__':
    unittest.main()
