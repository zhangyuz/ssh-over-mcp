"""Named local JSON set vs independently bounded saved NDJSON snapshot."""
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

import c0_manifest_preflight as c0
from test_c0_guidance import VALID

SCRIPT = Path(__file__).with_name('c0_manifest_preflight.py')
FWD = '--compare-files-to-batch-file'
REV = '--compare-batch-file-to-files'


class NamedFilesAndSavedBatchTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.files = [root / 'private-first.json', root / 'private-second.json']
        self.batch = root / 'private-proposals.ndjson'
        self.first = copy.deepcopy(VALID)
        self.second = copy.deepcopy(VALID)
        self.second['objects'][0].update(id='C0-P1', url='https://example.org/second',
                                         sha256='b' * 64)
        for path, data in zip(self.files, (self.first, self.second)):
            path.write_text(json.dumps(data))
        self.write_batch(self.second, self.first)

    def write_batch(self, *docs):
        self.batch.write_bytes(b'\n'.join(json.dumps(d).encode() for d in docs) + b'\n')

    def invoke(self, direction, *extra, files=None, batch=None):
        files = self.files if files is None else files
        batch = self.batch if batch is None else batch
        run = subprocess.run([sys.executable, str(SCRIPT), direction, *map(str, files),
                              '--against-batch-file', str(batch), '--summary-json', *extra],
                             capture_output=True, check=False, timeout=6)
        self.assertEqual(run.stderr, b'')
        return run.returncode, json.loads(run.stdout)

    def private(self, data):
        raw = json.dumps(data)
        for secret in ('private-', str(self.batch.parent), 'C0-W1', 'C0-P1',
                       'https://', 'a' * 64, 'b' * 64):
            self.assertNotIn(secret, raw)
        self.assertEqual(data['authorization'], 'NO_AUTHORIZATION')
        self.assertEqual(data['collection'], 'C0_COLLECT_HOLD')
        self.assertEqual(data['network'], 'NO_NETWORK')
        self.assertEqual(len(data['evidence_gaps']), 5)

    def test_both_directions_unchanged_independent_of_record_order(self):
        for flag, mode in ((FWD, 'NAMED_FILES_TO_LOCAL_BATCH'),
                           (REV, 'LOCAL_BATCH_TO_NAMED_FILES')):
            with self.subTest(flag=flag):
                code, report = self.invoke(flag, '--fail-on-change')
                self.assertEqual((code, report['status'], report['review_mode']),
                                 (0, 'UNCHANGED', mode))
                self.assertEqual(report['object_change_counts'],
                                 {'added': 0, 'removed': 0, 'changed': 0})
                self.assertEqual((report['before']['observed'], report['after']['observed']),
                                 (2, 2))
                self.private(report)

    def test_changed_metadata_and_ordered_add_remove_flags(self):
        changed = copy.deepcopy(self.first)
        changed['objects'][0]['sha256'] = 'c' * 64
        self.write_batch(changed, self.second)
        for flag in (FWD, REV):
            code, report = self.invoke(flag, '--fail-on-change')
            self.assertEqual((code, report['status']), (3, 'CHANGED'))
            self.assertEqual(report['object_change_counts']['changed'], 1)
            self.assertEqual(report['object_field_change_counts']['sha256'], 1)
            self.private(report)
        self.write_batch(self.first)
        for flag, expected in ((FWD, {'added': 0, 'removed': 1, 'changed': 0}),
                               (REV, {'added': 1, 'removed': 0, 'changed': 0})):
            code, report = self.invoke(flag, '--fail-on-change')
            self.assertEqual((code, report['status']), (3, 'CHANGED'))
            self.assertEqual(report['object_change_counts'], expected)
            self.private(report)

    def test_refused_invalid_side_never_reports_partial_zero_changes(self):
        for flag in (FWD, REV):
            self.batch.write_bytes(b'{')
            code, report = self.invoke(flag, '--fail-on-change')
            self.assertEqual((code, report['status']), (2, 'REFUSED'))
            self.assertEqual(report['object_changes'], 'UNAVAILABLE')
            self.assertIsNone(report['object_change_counts'])
            self.assertIsNone(report['object_field_change_counts'])
            self.private(report)
            self.write_batch(self.first, self.second)
            self.files[1].write_bytes(b'{')
            code, report = self.invoke(flag, '--fail-on-change')
            self.assertEqual((code, report['status']), (2, 'REFUSED'))
            self.assertIsNone(report['object_change_counts'])
            self.private(report)
            self.files[1].write_text(json.dumps(self.second))

    def test_cross_source_collision_is_refused_per_side(self):
        self.files[1].write_bytes(self.files[0].read_bytes())
        for flag in (FWD, REV):
            code, report = self.invoke(flag)
            self.assertEqual((code, report['status']), (2, 'REFUSED'))
            self.assertIn('RESOLVE_DUPLICATE_OBJECT_ID', report['next_action_codes'])
            self.private(report)
        self.files[1].write_text(json.dumps(self.second))
        self.write_batch(self.first, self.first)
        for flag in (FWD, REV):
            code, report = self.invoke(flag)
            self.assertEqual((code, report['status']), (2, 'REFUSED'))
            self.assertIsNone(report['object_change_counts'])
            self.private(report)

    def test_unsafe_file_and_batch_types_or_oversize_refuse_without_hang(self):
        for flag in (FWD, REV):
            for kind in ('fifo', 'symlink', 'missing'):
                for target in (self.files[1], self.batch):
                    with self.subTest(flag=flag, kind=kind, target=target.name):
                        original = target.read_bytes()
                        target.unlink()
                        if kind == 'fifo':
                            os.mkfifo(target)
                        elif kind == 'symlink':
                            target.symlink_to(self.files[0])
                        try:
                            code, report = self.invoke(flag)
                            self.assertEqual((code, report['status']), (2, 'REFUSED'))
                            self.assertIsNone(report['object_change_counts'])
                            self.private(report)
                        finally:
                            target.unlink(missing_ok=True)
                            target.write_bytes(original)
            self.batch.write_bytes(b'x' * (16 * 16385 + 1))
            code, report = self.invoke(flag)
            self.assertEqual((code, report['status']), (2, 'REFUSED'))
            self.private(report)
            self.write_batch(self.first, self.second)

    def test_over_16_local_files_refuse_before_any_input_read(self):
        for flag in (FWD, REV):
            argv = [str(SCRIPT), flag, *([str(self.files[0])] * 17),
                    '--against-batch-file', str(self.batch), '--summary-json']
            with patch.object(sys, 'argv', argv), \
                    patch.object(c0, 'inspect_named_manifest_set',
                                 side_effect=AssertionError('local file read')), \
                    patch.object(c0, 'inspect_local_ndjson_batch',
                                 side_effect=AssertionError('batch file read')), \
                    redirect_stdout(io.StringIO()) as output, \
                    redirect_stderr(io.StringIO()) as err:
                code = c0.main()
            self.assertEqual((code, err.getvalue()), (2, ''))
            report = json.loads(output.getvalue())
            self.assertEqual(report['status'], 'REFUSED')
            self.assertIsNone(report['object_change_counts'])
            self.private(report)

    def test_cli_mode_collisions_and_orphan_batch_option_refuse_pre_read(self):
        other_inputs = (('--stdin',), ('--stdin-batch',),
                        ('--batch', self.files[0]), ('--directory', self.files[0].parent),
                        ('--compare-files', *self.files),
                        ('--compare-files-to-stdin-batch', self.files[0]),
                        ('--compare-before-files', self.files[0]),
                        ('--batch-consistency',), ('--require-json-only',),
                        ('--capabilities-json',))
        for flag in (FWD, REV):
            for extra in other_inputs + ((REV if flag == FWD else FWD, self.files[0]),):
                with self.subTest(flag=flag, extra=extra):
                    argv = [str(SCRIPT), flag, str(self.files[0]), '--against-batch-file',
                            str(self.batch), *map(str, extra)]
                    with patch.object(sys, 'argv', argv), \
                            patch.object(c0, 'inspect_named_manifest_set',
                                         side_effect=AssertionError('source read')), \
                            patch.object(c0, 'inspect_local_ndjson_batch',
                                         side_effect=AssertionError('batch read')), \
                            redirect_stdout(io.StringIO()) as out, \
                            redirect_stderr(io.StringIO()) as err, \
                            self.assertRaises(SystemExit) as exc:
                        c0.main()
                    self.assertEqual(exc.exception.code, 2)
                    self.assertEqual(out.getvalue(), '')
                    self.assertIn(('capabilities-json' if '--capabilities-json' in extra
                                   else 'compare-'), err.getvalue())
        for argv in ([str(SCRIPT), '--against-batch-file', str(self.batch)],
                     [str(SCRIPT), FWD, str(self.files[0])]):
            with patch.object(sys, 'argv', argv), \
                    patch.object(c0, 'inspect_manifest', side_effect=AssertionError('read')), \
                    redirect_stdout(io.StringIO()) as out, \
                    redirect_stderr(io.StringIO()) as err, \
                    self.assertRaises(SystemExit) as exc:
                c0.main()
            self.assertEqual(exc.exception.code, 2)
            self.assertEqual(out.getvalue(), '')

    def test_capabilities_publish_both_fixed_review_modes_without_file_read(self):
        result = subprocess.run([sys.executable, str(SCRIPT), '--capabilities-json'],
                                capture_output=True, timeout=6, check=False)
        self.assertEqual((result.returncode, result.stderr), (0, b''))
        modes = json.loads(result.stdout)['review_modes']
        self.assertIn('NAMED_FILES_TO_LOCAL_BATCH', modes)
        self.assertIn('LOCAL_BATCH_TO_NAMED_FILES', modes)


if __name__ == '__main__':
    unittest.main()
