"""Compare bounded local NDJSON batch with stdin NDJSON, both directions."""
import copy
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

import c0_manifest_preflight as cli
from test_c0_guidance import VALID

SCRIPT = Path(__file__).with_name('c0_manifest_preflight.py')
MODES = (('--compare-batch-file-to-stdin-batch', 'LOCAL_BATCH_TO_STDIN_BATCH'),
         ('--compare-stdin-batch-to-batch-file', 'STDIN_BATCH_TO_LOCAL_BATCH'))


def run(mode, disk, stream, *options):
    proc = subprocess.run([sys.executable, str(SCRIPT), mode, str(disk),
                           *map(str, options)], input=stream, capture_output=True,
                          check=False, timeout=8)
    data = json.loads(proc.stdout) if proc.stdout.startswith(b'{') else None
    return proc, data


class LocalBatchStreamComparisonTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.disk = self.root / 'private-local-batch.ndjson'
        self.base = json.dumps(VALID).encode() + b'\n'
        self.disk.write_bytes(self.base)

    def private(self, output):
        for token in (str(self.root), 'private-', 'https://', 'a'*64, 'b'*64):
            self.assertNotIn(token, output)

    def test_symmetric_unchanged_all_output_formats(self):
        for mode, label in MODES:
            for opts in (('--summary-json',), ('--json',),
                         ('--summary', '--guidance')):
                with self.subTest(mode=mode, opts=opts):
                    proc, data = run(mode, self.disk, self.base, *opts, '--fail-on-change')
                    self.assertEqual((proc.returncode, proc.stderr), (0, b''))
                    if '--summary' in opts:
                        self.assertIn(b'C0 offline review: UNCHANGED', proc.stdout)
                        self.private(proc.stdout.decode())
                    else:
                        self.assertEqual(data['status'], 'UNCHANGED')
                        self.assertEqual(data['authorization'], 'NO_AUTHORIZATION')
                        self.assertEqual(data['collection'], 'C0_COLLECT_HOLD')
                        self.assertEqual(data['network'], 'NO_NETWORK')
                        if '--summary-json' in opts:
                            self.assertEqual(data['review_mode'], label)
                            self.assertEqual(data['object_change_counts'],
                                             {'added': 0, 'removed': 0, 'changed': 0})
                            self.private(proc.stdout.decode())
                        else:
                            self.assertEqual(data['object_diff']['status'], 'AVAILABLE')

    def test_semantic_direction_and_exit_three_or_zero(self):
        alt = copy.deepcopy(VALID)
        alt['objects'][0].update(id='C0-P1', url='https://example.org/other.whl',
                                 sha256='b'*64)
        different = json.dumps(alt).encode()+b'\n'
        for mode, label in MODES:
            proc, data = run(mode, self.disk, different, '--json', '--fail-on-change')
            self.assertEqual((proc.returncode, proc.stderr), (3, b''))
            self.assertEqual(data['status'], 'CHANGED')
            self.assertEqual((data['object_diff']['added'], data['object_diff']['removed']),
                             (['C0-P1'], ['C0-W1']) if mode == MODES[0][0]
                             else (['C0-W1'], ['C0-P1']))
            proc, data = run(mode, self.disk, different, '--summary-json')
            self.assertEqual(proc.returncode, 0)
            self.assertEqual(data['status'], 'CHANGED')
            self.assertEqual(data['review_mode'], label)
            self.assertEqual(data['object_change_counts'],
                             {'added': 1, 'removed': 1, 'changed': 0})
            self.private(proc.stdout.decode())

    def test_either_side_bad_and_overlimit_refuses_no_partial_diff(self):
        for mode, _ in MODES:
            for disk, stream in ((b'{', self.base), (self.base, b'{'),
                                 (b'\xff', self.base), (self.base, b'\xff'),
                                 (b'X'*262161, self.base),
                                 (self.base, b'X'*262161),
                                 (self.base, self.base*17)):
                with self.subTest(mode=mode, disk=len(disk), stream=len(stream)):
                    self.disk.write_bytes(disk)
                    proc, data = run(mode, self.disk, stream,
                                     '--summary-json', '--fail-on-change')
                    self.assertEqual((proc.returncode, proc.stderr), (2, b''))
                    self.assertEqual(data['status'], 'REFUSED')
                    self.assertEqual(data['object_changes'], 'UNAVAILABLE')
                    self.assertIsNone(data['object_change_counts'])
                    self.private(proc.stdout.decode())

    def test_duplicate_records_from_either_side_refuse(self):
        for mode, _ in MODES:
            for disk, stream in ((self.base*2, self.base),
                                 (self.base, self.base*2)):
                self.disk.write_bytes(disk)
                proc, data = run(mode, self.disk, stream, '--summary-json')
                self.assertEqual(proc.returncode, 2)
                self.assertEqual(data['status'], 'REFUSED')
                self.assertIsNone(data['object_change_counts'])
                self.assertIn('RESOLVE_DUPLICATE_OBJECT_ID', data['next_action_codes'])

    def test_symlink_fifo_directory_missing_disk_refused(self):
        for mode, _ in MODES:
            for kind in ('symlink', 'fifo', 'directory', 'missing'):
                with self.subTest(mode=mode, kind=kind):
                    self.disk.unlink(missing_ok=True)
                    if kind == 'symlink':
                        target = self.root / 'target.json'
                        target.write_bytes(self.base)
                        self.disk.symlink_to(target)
                    elif kind == 'fifo':
                        os.mkfifo(self.disk)
                    elif kind == 'directory':
                        self.disk.mkdir()
                    proc, data = run(mode, self.disk, self.base, '--summary-json')
                    self.assertEqual(proc.returncode, 2, proc.stderr)
                    self.assertEqual(data['status'], 'REFUSED')
                    self.assertIsNone(data['object_change_counts'])
                    self.private(proc.stdout.decode())
                    if kind == 'directory':
                        self.disk.rmdir()
                    elif kind != 'missing':
                        self.disk.unlink()
                    self.disk.write_bytes(self.base)

    def test_conflicting_flags_reject_before_file_or_stdin_read(self):
        class NoReadStdin:
            @property
            def buffer(self):
                raise AssertionError('stdin accessed')

        for mode, _ in MODES:
            for extra in (('--stdin',), ('--stdin-batch',),
                          ('--compare-batch-files', self.disk, self.disk),
                          ('--compare-batch-file-to-directory', self.disk, self.root),
                          ('--compare-stdin-batches',), ('--require-json-only',),
                          ('--capabilities-json',),
                          (MODES[1][0] if mode == MODES[0][0] else MODES[0][0],
                           self.disk), (self.disk,)):
                with self.subTest(mode=mode, extra=extra):
                    args = [str(SCRIPT), mode, str(self.disk), *map(str, extra)]
                    output, errors = io.StringIO(), io.StringIO()
                    with patch.object(sys, 'argv', args), \
                            patch.object(sys, 'stdin', NoReadStdin()), \
                            patch.object(cli, 'inspect_stdin_batch',
                                         side_effect=AssertionError('read stdin')), \
                            patch.object(cli, 'inspect_local_ndjson_batch',
                                         side_effect=AssertionError('read batch')), \
                            redirect_stdout(output), redirect_stderr(errors), \
                            self.assertRaises(SystemExit) as raised:
                        cli.main()
                    self.assertEqual(raised.exception.code, 2)
                    self.assertEqual(output.getvalue(), '')
                    self.assertIn('cannot be combined', errors.getvalue())


if __name__ == '__main__':
    unittest.main()
