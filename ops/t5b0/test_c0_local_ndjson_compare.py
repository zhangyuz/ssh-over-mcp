"""Compare a bounded regular manifest with a bounded NDJSON batch file offline."""
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
MODES = (('--compare-file-to-batch', 'FILE_TO_BATCH'),
         ('--compare-batch-to-file', 'BATCH_TO_FILE'))


def run(mode, manifest, batch, *options):
    operands = ((manifest, batch) if mode == MODES[0][0] else (batch, manifest))
    proc = subprocess.run([sys.executable, str(SCRIPT), mode,
                           *map(str, operands), *map(str, options)],
                          capture_output=True, check=False, timeout=8)
    report = json.loads(proc.stdout) if proc.stdout.startswith(b'{') else None
    return proc, report


class LocalNdjsonComparisonTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.manifest = self.root / 'secret-manifest.json'
        self.batch = self.root / 'secret-batch.ndjson'
        self.base = json.dumps(VALID).encode()
        self.manifest.write_bytes(self.base)
        self.batch.write_bytes(self.base + b'\n')

    def private(self, output):
        for token in (self.tmp.name, 'secret-', 'https://', 'a'*64, 'b'*64):
            self.assertNotIn(token, output)

    def test_both_directions_existing_presentations_and_unchanged(self):
        for mode, label in MODES:
            for options in (('--summary-json',), ('--json',), ('--summary', '--guidance')):
                with self.subTest(mode=mode, options=options):
                    proc, report = run(mode, self.manifest, self.batch,
                                       *options, '--fail-on-change')
                    self.assertEqual((proc.returncode, proc.stderr), (0, b''))
                    self.private(proc.stdout.decode())
                    if '--summary' in options:
                        self.assertIn(b'C0 offline review: UNCHANGED', proc.stdout)
                    else:
                        self.assertEqual(report['status'], 'UNCHANGED')
                        self.assertEqual(report['authorization'], 'NO_AUTHORIZATION')
                        self.assertEqual(report['collection'], 'C0_COLLECT_HOLD')
                        self.assertEqual(report['network'], 'NO_NETWORK')
                        if '--summary-json' in options:
                            self.assertEqual(report['review_mode'], label)
                            self.assertEqual(report['review_schema'],
                                             'som-t5b0-c0-summary-json-v1')
                            self.assertEqual(report['object_change_counts'],
                                             {'added': 0, 'removed': 0, 'changed': 0})
                        else:
                            self.assertEqual(report['object_diff']['status'], 'AVAILABLE')

    def test_added_removed_direction_and_change_exit_three(self):
        changed = copy.deepcopy(VALID)
        changed['objects'][0]['id'] = 'C0-P1'
        changed['objects'][0]['sha256'] = 'b'*64
        self.batch.write_bytes(self.base + b'\n' + json.dumps(changed).encode() + b'\n')
        # Same ID across batch must refuse, not produce partial diff.
        for mode, _ in MODES:
            proc, report = run(mode, self.manifest, self.batch, '--summary-json')
            self.assertEqual(proc.returncode, 2, (mode, proc.stderr))
            self.assertEqual(report['status'], 'REFUSED')
            self.assertIsNone(report['object_change_counts'])
        # One valid changed id in the batch; semantic direction matters.
        self.batch.write_bytes(json.dumps(changed).encode() + b'\n')
        for mode, label in MODES:
            proc, report = run(mode, self.manifest, self.batch,
                               '--fail-on-change', '--json')
            self.assertEqual((proc.returncode, proc.stderr), (3, b''))
            self.assertEqual(report['status'], 'CHANGED')
            delta = report['object_diff']
            self.assertEqual((delta['added'], delta['removed']),
                             (['C0-P1'], ['C0-W1']) if mode == MODES[0][0]
                             else (['C0-W1'], ['C0-P1']))
            proc, report = run(mode, self.manifest, self.batch,
                               '--fail-on-change', '--summary-json')
            self.assertEqual(proc.returncode, 3)
            self.assertEqual(report['review_mode'], label)
            self.assertEqual(report['object_change_counts'],
                             {'added': 1, 'removed': 1, 'changed': 0})
            self.private(proc.stdout.decode())

    def test_both_side_refusal_and_ndjson_bounds(self):
        for mode, _ in MODES:
            for manifest_data, batch_data in ((b'{', self.base),
                                              (self.base, b'{'),
                                              (self.base, b'X'*16385),
                                              (self.base, b'X'*262161),
                                              (b'X'*16385, self.base)):
                with self.subTest(mode=mode, left=len(manifest_data), right=len(batch_data)):
                    self.manifest.write_bytes(manifest_data)
                    self.batch.write_bytes(batch_data)
                    proc, report = run(mode, self.manifest, self.batch,
                                       '--summary-json', '--fail-on-change')
                    self.assertEqual((proc.returncode, proc.stderr), (2, b''))
                    self.assertEqual(report['status'], 'REFUSED')
                    self.assertEqual(report['object_changes'], 'UNAVAILABLE')
                    self.assertIsNone(report['object_change_counts'])
                    self.private(proc.stdout.decode())

    def test_ndjson_regular_no_follow_fifo_directory_missing(self):
        for mode, _ in MODES:
            for kind in ('symlink', 'fifo', 'directory', 'missing'):
                with self.subTest(mode=mode, kind=kind):
                    self.batch.unlink(missing_ok=True)
                    if kind == 'symlink':
                        other = self.root / 'target.ndjson'
                        other.write_bytes(self.base)
                        self.batch.symlink_to(other)
                    elif kind == 'fifo':
                        os.mkfifo(self.batch)
                    elif kind == 'directory':
                        self.batch.mkdir()
                    proc, report = run(mode, self.manifest, self.batch,
                                       '--summary-json')
                    self.assertEqual(proc.returncode, 2, proc.stderr)
                    self.assertEqual(report['status'], 'REFUSED')
                    self.assertIsNone(report['object_change_counts'])
                    self.private(proc.stdout.decode())
                    if kind == 'directory':
                        self.batch.rmdir()
                    elif kind in ('symlink', 'fifo'):
                        self.batch.unlink()
                    self.batch.write_bytes(self.base + b'\n')

    def test_distinct_cross_line_manifest_ids_and_16_record_limit(self):
        # Four possible IDs only; repeated across lines is always refused.
        for mode, _ in MODES:
            self.batch.write_bytes((self.base+b'\n')*16)
            proc, report = run(mode, self.manifest, self.batch,
                               '--summary-json', '--fail-on-change')
            self.assertEqual(proc.returncode, 2)
            self.assertEqual(report['status'], 'REFUSED')
            self.assertIsNone(report['object_change_counts'])
            self.batch.write_bytes((self.base+b'\n')*17)
            proc, report = run(mode, self.manifest, self.batch, '--summary-json')
            self.assertEqual(proc.returncode, 2)
            self.assertIsNone(report['object_change_counts'])

    def test_invalid_option_mixes_reject_pre_read(self):
        for mode, _ in MODES:
            for extra in (('--stdin',), ('--stdin-batch',),
                          ('--compare-files', self.manifest, self.manifest),
                          ('--compare-directories', self.root, self.root),
                          ('--directory', self.root), ('--batch', self.manifest),
                          ('--compare-stdin-batches',),
                          ('--compare-stdin-to-file', self.manifest),
                          ('--compare-file-to-directory', self.manifest, self.root),
                          ('--compare-stdin-to-directory', self.root),
                          ('--require-json-only',), ('--capabilities-json',),
                          (self.manifest,),
                          (MODES[1][0] if mode == MODES[0][0] else MODES[0][0],
                           self.batch, self.manifest)):
                with self.subTest(mode=mode, extra=extra):
                    proc, _ = run(mode, self.manifest, self.batch, *extra)
                    self.assertEqual(proc.returncode, 2, proc.stderr)
                    self.assertEqual(proc.stdout, b'')
                    self.assertIn(b'cannot be combined', proc.stderr)


if __name__ == '__main__':
    unittest.main()
