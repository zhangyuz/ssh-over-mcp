"""Direct bounded comparison of two independently named local manifest sets."""
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


class NamedFileSetComparisonTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        before, after = self.root / 'secret-before', self.root / 'secret-after'
        before.mkdir()
        after.mkdir()
        self.before = [before / 'private-a.json', before / 'private-b.json']
        self.after = [after / 'private-y.json', after / 'private-x.json']
        one = copy.deepcopy(VALID)
        two = copy.deepcopy(VALID)
        two['objects'][0].update(id='C0-P1', url='https://example.org/second',
                                 sha256='b' * 64)
        for paths in (self.before, self.after):
            paths[0].write_text(json.dumps(one))
            paths[1].write_text(json.dumps(two))

    def command(self, *extra):
        return ['--compare-before-files', *self.before,
                '--compare-after-files', *self.after, *extra]

    def invoke(self, *flags, incoming=b''):
        result = subprocess.run([sys.executable, str(SCRIPT), *map(str, flags)],
                                input=incoming, capture_output=True, timeout=6, check=False)
        self.assertEqual(result.stderr, b'')
        return result.returncode, json.loads(result.stdout)

    def no_leak(self, data):
        serialized = json.dumps(data)
        for secret in ('private-', 'secret-', str(self.root), 'C0-W1', 'C0-P1',
                       'https://', 'a'*64, 'b'*64):
            self.assertNotIn(secret, serialized)

    def test_different_file_names_same_objects_unchanged_and_private(self):
        code, report = self.invoke(*self.command('--summary-json', '--fail-on-change'))
        self.assertEqual((code, report['status']), (0, 'UNCHANGED'))
        self.assertEqual(report['review_mode'], 'NAMED_FILES_COMPARISON')
        self.assertEqual(report['object_changes'], 'AVAILABLE')
        self.assertEqual(report['object_change_counts'],
                         {'added': 0, 'removed': 0, 'changed': 0})
        self.assertEqual(report['object_field_change_counts'],
                         {'url': 0, 'sha256': 0, 'bytes': 0, 'max_bytes': 0})
        self.assertEqual((report['before']['observed'], report['after']['observed']), (2, 2))
        self.assertEqual(report['authorization'], 'NO_AUTHORIZATION')
        self.assertEqual(report['collection'], 'C0_COLLECT_HOLD')
        self.assertEqual(report['network'], 'NO_NETWORK')
        self.assertEqual(len(report['evidence_gaps']), 5)
        self.no_leak(report)

    def test_changed_fields_and_directional_add_remove(self):
        edited = copy.deepcopy(VALID)
        edited['objects'][0].update(sha256='c'*64, bytes=3, max_bytes=7)
        self.after[0].write_text(json.dumps(edited))
        code, report = self.invoke(*self.command('--summary-json', '--fail-on-change'))
        self.assertEqual((code, report['status']), (3, 'CHANGED'))
        self.assertEqual(report['object_change_counts'],
                         {'added': 0, 'removed': 0, 'changed': 1})
        self.assertEqual(report['object_field_change_counts'],
                         {'url': 0, 'sha256': 1, 'bytes': 1, 'max_bytes': 1})
        self.no_leak(report)
        replacement = copy.deepcopy(VALID)
        replacement['objects'][0].update(id='C0-R1', url='https://example.org/new',
                                         sha256='c'*64)
        self.after[0].write_text(json.dumps(replacement))
        code, report = self.invoke(*self.command('--summary-json', '--fail-on-change'))
        self.assertEqual((code, report['status']), (3, 'CHANGED'))
        self.assertEqual(report['object_change_counts'],
                         {'added': 1, 'removed': 1, 'changed': 0})
        self.no_leak(report)

    def test_refused_either_side_never_exports_partial_difference(self):
        for side in ('before', 'after'):
            with self.subTest(side=side):
                target = self.before[1] if side == 'before' else self.after[1]
                original = target.read_bytes()
                try:
                    target.write_bytes(b'{')
                    code, report = self.invoke(*self.command('--summary-json', '--fail-on-change'))
                    self.assertEqual((code, report['status']), (2, 'REFUSED'))
                    self.assertEqual(report['object_changes'], 'UNAVAILABLE')
                    self.assertIsNone(report['object_change_counts'])
                    self.assertIsNone(report['object_field_change_counts'])
                    self.assertEqual(report[side]['refused'], 1)
                    self.assertEqual(report['before']['observed'], 2)
                    self.assertEqual(report['after']['observed'], 2)
                    self.no_leak(report)
                finally:
                    target.write_bytes(original)

    def test_cross_file_duplicates_and_metadata_conflict_are_refused(self):
        original = self.before[1].read_bytes()
        try:
            self.before[1].write_bytes(self.before[0].read_bytes())
            code, report = self.invoke(*self.command('--summary-json'))
            self.assertEqual((code, report['status']), (2, 'REFUSED'))
            self.assertIn('RESOLVE_DUPLICATE_OBJECT_ID', report['next_action_codes'])
            self.assertIsNone(report['object_change_counts'])
            self.no_leak(report)
        finally:
            self.before[1].write_bytes(original)
        other = copy.deepcopy(VALID)
        other['objects'][0].update(id='C0-P1', sha256='b'*64,
                                   url=VALID['objects'][0]['url'])
        self.before[1].write_text(json.dumps(other))
        code, report = self.invoke(*self.command('--summary-json'))
        self.assertEqual((code, report['status']), (2, 'REFUSED'))
        self.assertIn('RESOLVE_CROSS_FILE_CONFLICT', report['next_action_codes'])
        self.no_leak(report)

    def test_unsafe_and_over_16_files_refuse_without_deadlock_or_excess_io(self):
        for side in ('before', 'after'):
            for unsafe in ('fifo', 'symlink', 'missing'):
                with self.subTest(side=side, unsafe=unsafe):
                    path = (self.before if side == 'before' else self.after)[1]
                    original = path.read_bytes()
                    path.unlink()
                    if unsafe == 'fifo':
                        os.mkfifo(path)
                    if unsafe == 'symlink':
                        path.symlink_to((self.before if side == 'before' else self.after)[0])
                    try:
                        code, report = self.invoke(*self.command('--summary-json'))
                        self.assertEqual((code, report['status']), (2, 'REFUSED'))
                        self.assertEqual(report['object_changes'], 'UNAVAILABLE')
                        self.no_leak(report)
                    finally:
                        path.unlink(missing_ok=True)
                        path.write_bytes(original)
        for side in ('before', 'after'):
            before, after = list(self.before), list(self.after)
            if side == 'before':
                before = [self.before[0]]*17
            else:
                after = [self.after[0]]*17
            code, report = self.invoke('--compare-before-files', *before,
                                       '--compare-after-files', *after, '--summary-json')
            self.assertEqual((code, report['status']), (2, 'REFUSED'))
            self.assertEqual(report[side]['observed'], 0)
            self.assertIsNone(report['object_change_counts'])
            self.no_leak(report)

    def test_invalid_flag_combinations_are_refused_before_read(self):
        others = (('--stdin',), ('--stdin-batch',), ('--batch', self.before[0]),
                  ('--directory', self.root), ('--compare-files', self.before[0],
                                              self.after[0]),
                  ('--compare-stdin-batches',), ('--batch-consistency',),
                  ('--require-json-only',))
        for extra in others:
            with self.subTest(extra=extra):
                argv = [str(SCRIPT), *map(str, self.command(*extra))]
                with patch.object(sys, 'argv', argv), \
                        patch.object(cli, 'inspect_manifest',
                                     side_effect=AssertionError('unexpected file open')), \
                        patch.object(cli, 'inspect_stdin_batch',
                                     side_effect=AssertionError('unexpected stdin read')), \
                        redirect_stdout(io.StringIO()) as output, \
                        redirect_stderr(io.StringIO()) as err, \
                        self.assertRaises(SystemExit) as caught:
                    cli.main()
                self.assertEqual(caught.exception.code, 2)
                self.assertEqual(output.getvalue(), '')
                self.assertIn('compare-before-files', err.getvalue())
        for args in (['--compare-before-files', self.before[0]],
                     ['--compare-after-files', self.after[0]],
                     ['--capabilities-json', *self.command()]):
            with self.subTest(args=args):
                argv = [str(SCRIPT), *map(str, args)]
                with patch.object(sys, 'argv', argv), \
                        patch.object(cli, 'inspect_manifest',
                                     side_effect=AssertionError('file access')), \
                        redirect_stdout(io.StringIO()) as output, \
                        redirect_stderr(io.StringIO()) as err, \
                        self.assertRaises(SystemExit) as caught:
                    cli.main()
                self.assertEqual(caught.exception.code, 2)
                self.assertEqual(output.getvalue(), '')

    def test_capability_mode_is_fixed_and_discovery_remains_read_free(self):
        code, report = self.invoke('--capabilities-json')
        self.assertEqual(code, 0)
        self.assertIn('NAMED_FILES_COMPARISON', report['review_modes'])
        self.assertEqual(report['limits']['batch_manifests'], 16)
        self.no_leak(report)


if __name__ == '__main__':
    unittest.main()
