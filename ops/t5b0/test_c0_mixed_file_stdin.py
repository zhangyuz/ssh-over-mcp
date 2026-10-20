"""Offline C0 comparison of a single local manifest with a single piped manifest."""
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
MODES = (('--compare-file-to-stdin', 'FILE_TO_STDIN'),
         ('--compare-stdin-to-file', 'STDIN_TO_FILE'))


def invoke(mode, file, payload, *extra):
    result = subprocess.run([sys.executable, str(SCRIPT), mode, str(file), *map(str, extra)],
                            input=payload, capture_output=True, check=False, timeout=6)
    report = json.loads(result.stdout) if result.stdout.startswith(b'{') else None
    return result, report


class MixedFileStreamTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.file = Path(self.temp.name) / 'secret-local-manifest.json'
        self.file.write_bytes(json.dumps(VALID).encode())
        self.data = json.dumps(VALID).encode()

    def assert_private(self, output):
        for private in (self.temp.name, 'secret-local-manifest',
                        'https://', 'a'*64, 'b'*64):
            self.assertNotIn(private, output)

    def test_both_directions_unchanged_and_non_authorizing(self):
        for mode, label in MODES:
            for fmt in (('--json',), ('--summary-json',), ('--summary', '--guidance')):
                with self.subTest(mode=mode, fmt=fmt):
                    result, report = invoke(mode, self.file, self.data, *fmt,
                                            '--fail-on-change')
                    self.assertEqual((result.returncode, result.stderr), (0, b''))
                    self.assert_private(result.stdout.decode())
                    if '--summary' in fmt:
                        self.assertIn(b'C0 offline review: UNCHANGED', result.stdout)
                        self.assertIn(b'NO_AUTHORIZATION', result.stdout)
                    else:
                        self.assertEqual(report['status'], 'UNCHANGED')
                        self.assertEqual(report['authorization'], 'NO_AUTHORIZATION')
                        self.assertEqual(report['collection'], 'C0_COLLECT_HOLD')
                        self.assertEqual(report['network'], 'NO_NETWORK')
                        if '--summary-json' in fmt:
                            self.assertEqual(report['review_schema'], 'som-t5b0-c0-summary-json-v1')
                            self.assertEqual(report['review_mode'], label)
                            self.assertEqual(report['object_change_counts'],
                                             {'added': 0, 'removed': 0, 'changed': 0})
                            self.assertEqual(report['next_action_codes'],
                                             ['VERIFY_INDEPENDENT_EVIDENCE'])
                        else:
                            self.assertEqual(report['object_diff']['status'], 'AVAILABLE')

    def test_directionality_and_change_gate(self):
        changed = copy.deepcopy(VALID)
        changed['objects'][0].update(sha256='b'*64, max_bytes=105)
        for mode, label in MODES:
            for options, expected_exit in (((), 0), (('--fail-on-change',), 3)):
                with self.subTest(mode=mode, extra=options):
                    self.file.write_bytes(json.dumps(VALID).encode())
                    result, report = invoke(mode, self.file, json.dumps(changed).encode(),
                                            '--summary-json', *options)
                    self.assertEqual((result.returncode, result.stderr),
                                     (expected_exit, b''))
                    self.assertEqual(report['status'], 'CHANGED')
                    self.assertEqual(report['review_mode'], label)
                    self.assertEqual(report['object_change_counts'],
                                     {'added': 0, 'removed': 0, 'changed': 1})
                    self.assert_private(result.stdout.decode())
                    if mode == '--compare-stdin-to-file':
                        # Changed pipe is baseline, so order still changes fields.
                        self.assertEqual(report['before']['status'], 'STRUCTURE_ONLY_PASS')
                        self.assertEqual(report['after']['status'], 'STRUCTURE_ONLY_PASS')

    def test_added_removed_ids_follow_baseline_direction(self):
        changed = copy.deepcopy(VALID)
        changed['objects'][0]['id'] = 'C0-P1'
        for mode, _ in MODES:
            with self.subTest(mode=mode):
                proc, report = invoke(mode, self.file, json.dumps(changed).encode(),
                                      '--fail-on-change')
                self.assertEqual(proc.returncode, 3, proc.stderr)
                delta = report['object_diff']
                self.assertEqual(delta['status'], 'AVAILABLE')
                if mode == '--compare-file-to-stdin':
                    self.assertEqual((delta['added'], delta['removed']),
                                     (['C0-P1'], ['C0-W1']))
                else:
                    self.assertEqual((delta['added'], delta['removed']),
                                     (['C0-W1'], ['C0-P1']))

    def test_exact_byte_limit_per_independent_input(self):
        exact = self.data + b' ' * (16384 - len(self.data))
        for mode, _ in MODES:
            with self.subTest(mode=mode):
                self.file.write_bytes(exact)
                proc, report = invoke(mode, self.file, exact, '--summary-json')
                self.assertEqual(proc.returncode, 0, proc.stderr)
                self.assertEqual(report['status'], 'UNCHANGED')
                self.assertEqual(report['object_change_counts'],
                                 {'added': 0, 'removed': 0, 'changed': 0})
                self.assert_private(proc.stdout.decode())

    def test_refusal_either_side_and_16k_limits(self):
        for mode, label in MODES:
            for file_data, pipe_data in ((b'{', self.data), (self.data, b'{'),
                                         (self.data, b'X'*16385),
                                         (b'X'*16385, self.data)):
                with self.subTest(mode=mode, file_len=len(file_data), pipe_len=len(pipe_data)):
                    self.file.write_bytes(file_data)
                    result, report = invoke(mode, self.file, pipe_data,
                                            '--summary-json', '--fail-on-change')
                    self.assertEqual((result.returncode, result.stderr), (2, b''))
                    self.assertEqual(report['status'], 'REFUSED')
                    self.assertEqual(report['object_changes'], 'UNAVAILABLE')
                    self.assertIsNone(report['object_change_counts'])
                    self.assertEqual(report['review_mode'], label)
                    self.assertIn('RETRY_OFFLINE_REVIEW', report['next_action_codes'])
                    self.assert_private(result.stdout.decode())

    def test_nofollow_fifo_directory_and_nonblocking_refusal(self):
        for mode, label in MODES:
            for kind in ('symlink', 'fifo', 'directory', 'missing'):
                with self.subTest(mode=mode, kind=kind):
                    self.file.unlink(missing_ok=True)
                    if kind == 'symlink':
                        other = Path(self.temp.name) / 'target.json'
                        other.write_bytes(self.data)
                        self.file.symlink_to(other)
                    elif kind == 'fifo':
                        os.mkfifo(self.file)
                    elif kind == 'directory':
                        self.file.mkdir()
                    result, report = invoke(mode, self.file, self.data, '--summary-json')
                    self.assertEqual(result.returncode, 2, result.stderr)
                    self.assertEqual(report['status'], 'REFUSED')
                    self.assertIsNone(report['object_change_counts'])
                    self.assert_private(result.stdout.decode())
                    if kind == 'directory':
                        self.file.rmdir()
                    elif kind in ('symlink', 'fifo'):
                        self.file.unlink()
                    self.file.write_bytes(self.data)

    def test_old_modes_and_early_conflicts(self):
        for mode, _ in MODES:
            for extra in (('--stdin',), ('--stdin-batch',), ('--directory', self.temp.name),
                          ('--compare-files', self.file, self.file),
                          ('--compare-directories', self.temp.name, self.temp.name),
                          ('--compare-stdin-batches',),
                          ('--compare-stdin-before-directory', self.temp.name),
                          ('--compare-stdin-to-directory', self.temp.name),
                          ('--batch', self.file), (self.file,),
                          ('--require-json-only',),
                          (MODES[1][0] if mode == MODES[0][0] else MODES[0][0], self.file)):
                with self.subTest(mode=mode, extra=extra):
                    proc, parsed = invoke(mode, self.file, self.data, *extra)
                    self.assertEqual(proc.returncode, 2)
                    self.assertIsNone(parsed)
                    self.assertIn(b'cannot be combined', proc.stderr)
                    self.assertEqual(proc.stdout, b'')


if __name__ == '__main__':
    unittest.main()
