"""Symmetric file-list vs piped NDJSON comparison without staging."""
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
from types import SimpleNamespace
from unittest.mock import patch

import c0_manifest_preflight as c0
from test_c0_guidance import VALID

SCRIPT = Path(__file__).with_name('c0_manifest_preflight.py')
FWD = '--compare-files-to-stdin-batch'
REV = '--compare-stdin-batch-to-files'


class NamedFilesVsStreamTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.paths = [root / 'private-a.json', root / 'private-b.json']
        self.one = copy.deepcopy(VALID)
        self.two = copy.deepcopy(VALID)
        self.two['objects'][0].update(id='C0-P1', url='https://example.org/b', sha256='b'*64)
        for path, doc in zip(self.paths, (self.one, self.two)):
            path.write_text(json.dumps(doc))

    def stream(self, *docs):
        return b'\n'.join(json.dumps(doc).encode() for doc in docs) + b'\n'

    def invoke(self, direction, incoming, *extra, paths=None):
        paths = self.paths if paths is None else paths
        call = subprocess.run([sys.executable, str(SCRIPT), direction, *map(str, paths),
                               '--summary-json', *extra], input=incoming,
                              capture_output=True, timeout=6, check=False)
        self.assertEqual(call.stderr, b'')
        return call.returncode, json.loads(call.stdout)

    def assert_private(self, result):
        data = json.dumps(result)
        for fragment in (str(self.paths[0].parent), 'private-', 'C0-W1', 'C0-P1',
                         'https://', 'a'*64, 'b'*64):
            self.assertNotIn(fragment, data)
        self.assertEqual(result['authorization'], 'NO_AUTHORIZATION')
        self.assertEqual(result['collection'], 'C0_COLLECT_HOLD')
        self.assertEqual(result['network'], 'NO_NETWORK')
        self.assertEqual(len(result['evidence_gaps']), 5)

    def test_both_directions_unchanged_even_in_different_line_order(self):
        for flag, mode in ((FWD, 'NAMED_FILES_TO_STDIN_BATCH'),
                           (REV, 'STDIN_BATCH_TO_NAMED_FILES')):
            with self.subTest(flag=flag):
                code, data = self.invoke(flag, self.stream(self.two, self.one),
                                         '--fail-on-change')
                self.assertEqual((code, data['status'], data['review_mode']),
                                 (0, 'UNCHANGED', mode))
                self.assertEqual(data['object_change_counts'],
                                 {'added': 0, 'removed': 0, 'changed': 0})
                self.assertEqual((data['before']['observed'], data['after']['observed']), (2, 2))
                self.assert_private(data)

    def test_changed_field_counts_and_directional_add_remove(self):
        amended = copy.deepcopy(self.one)
        amended['objects'][0]['sha256'] = 'c'*64
        for flag in (FWD, REV):
            with self.subTest(flag=flag):
                code, data = self.invoke(flag, self.stream(amended, self.two),
                                         '--fail-on-change')
                self.assertEqual((code, data['status']), (3, 'CHANGED'))
                self.assertEqual(data['object_change_counts']['changed'], 1)
                self.assertEqual(data['object_field_change_counts']['sha256'], 1)
                self.assert_private(data)
        for flag, counts in ((FWD, {'added': 0, 'removed': 1, 'changed': 0}),
                             (REV, {'added': 1, 'removed': 0, 'changed': 0})):
            code, data = self.invoke(flag, self.stream(self.one), '--fail-on-change')
            self.assertEqual((code, data['status']), (3, 'CHANGED'))
            self.assertEqual(data['object_change_counts'], counts)
            self.assert_private(data)

    def test_either_side_invalid_or_cross_duplicate_refuses_with_null_counts(self):
        for flag in (FWD, REV):
            for payload in (b'{', self.stream(self.one, self.one), b'x' * (16*16385+1)):
                with self.subTest(flag=flag, payload=len(payload)):
                    code, data = self.invoke(flag, payload, '--fail-on-change')
                    self.assertEqual((code, data['status']), (2, 'REFUSED'))
                    self.assertEqual(data['object_changes'], 'UNAVAILABLE')
                    self.assertIsNone(data['object_change_counts'])
                    self.assertIsNone(data['object_field_change_counts'])
                    self.assert_private(data)
            self.paths[1].write_bytes(b'{')
            code, data = self.invoke(flag, self.stream(self.one, self.two))
            self.assertEqual((code, data['status']), (2, 'REFUSED'))
            self.assertIsNone(data['object_change_counts'])
            self.assert_private(data)
            self.paths[1].write_text(json.dumps(self.two))

    def test_unsafe_local_sources_refuse_without_fifo_block(self):
        for flag in (FWD, REV):
            for kind in ('fifo', 'symlink', 'missing'):
                with self.subTest(flag=flag, kind=kind):
                    self.paths[1].unlink()
                    if kind == 'fifo':
                        os.mkfifo(self.paths[1])
                    elif kind == 'symlink':
                        self.paths[1].symlink_to(self.paths[0])
                    code, data = self.invoke(flag, self.stream(self.one, self.two))
                    self.assertEqual((code, data['status']), (2, 'REFUSED'))
                    self.assertIsNone(data['object_change_counts'])
                    self.assert_private(data)
                    self.paths[1].unlink(missing_ok=True)
                    self.paths[1].write_text(json.dumps(self.two))

    def test_more_than_16_local_paths_reject_before_file_or_stdin_read(self):
        class NoRead:
            def read(self, *args):
                raise AssertionError('stdin must not be read')
        for flag in (FWD, REV):
            argv = [str(SCRIPT), flag, *([str(self.paths[0])]*17), '--summary-json']
            output, errors = io.StringIO(), io.StringIO()
            with patch.object(sys, 'argv', argv), \
                    patch.object(sys, 'stdin', SimpleNamespace(buffer=NoRead())), \
                    patch.object(c0, 'inspect_manifest', side_effect=AssertionError('file read')), \
                    redirect_stdout(output), redirect_stderr(errors):
                code = c0.main()
            self.assertEqual((code, errors.getvalue()), (2, ''))
            report = json.loads(output.getvalue())
            self.assertEqual(report['status'], 'REFUSED')
            self.assertIsNone(report['object_change_counts'])
            self.assert_private(report)

    def test_collision_routes_refuse_before_any_file_or_stdin_read(self):
        others = (('--stdin',), ('--stdin-batch',), ('--batch', self.paths[0]),
                  ('--directory', self.paths[0].parent), ('--compare-files', *self.paths),
                  ('--compare-before-files', self.paths[0]),
                  ('--batch-consistency',), ('--require-json-only',),
                  ('--compare-stdin-batches',), ('--capabilities-json',))
        for flag in (FWD, REV):
            for addition in others + ((REV if flag == FWD else FWD, self.paths[0]),):
                with self.subTest(flag=flag, other=addition):
                    argv = [str(SCRIPT), flag, str(self.paths[0]), *map(str, addition)]
                    with patch.object(sys, 'argv', argv), \
                            patch.object(c0, 'inspect_manifest',
                                         side_effect=AssertionError('file read')), \
                            patch.object(c0, 'inspect_stdin_batch',
                                         side_effect=AssertionError('stdin read')), \
                            redirect_stdout(io.StringIO()) as output, \
                            redirect_stderr(io.StringIO()) as errors, \
                            self.assertRaises(SystemExit) as exc:
                        c0.main()
                    self.assertEqual(exc.exception.code, 2)
                    self.assertEqual(output.getvalue(), '')
                    self.assertIn(('capabilities-json' if '--capabilities-json' in addition
                                   else 'compare-'), errors.getvalue())

    def test_static_capabilities_advertise_both_mode_names_without_sources(self):
        run = subprocess.run([sys.executable, str(SCRIPT), '--capabilities-json'],
                             capture_output=True, timeout=6, check=False)
        self.assertEqual((run.returncode, run.stderr), (0, b''))
        catalog = json.loads(run.stdout)
        self.assertIn('NAMED_FILES_TO_STDIN_BATCH', catalog['review_modes'])
        self.assertIn('STDIN_BATCH_TO_NAMED_FILES', catalog['review_modes'])
        self.assertEqual(catalog['limits']['batch_manifests'], 16)


if __name__ == '__main__':
    unittest.main()
