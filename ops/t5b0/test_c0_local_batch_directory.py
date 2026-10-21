"""Compare bounded local NDJSON file with bounded directory either direction."""
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
MODES = (('--compare-batch-file-to-directory', 'BATCH_FILE_TO_DIRECTORY'),
         ('--compare-directory-to-batch-file', 'DIRECTORY_TO_BATCH_FILE'))


def invoke(mode, batch, directory, *flags):
    operands = ((batch, directory) if mode == MODES[0][0]
                else (directory, batch))
    proc = subprocess.run([sys.executable, str(SCRIPT), mode,
                           *map(str, operands), *map(str, flags)],
                          capture_output=True, check=False, timeout=9)
    data = json.loads(proc.stdout) if proc.stdout.startswith(b'{') else None
    return proc, data


class LocalBatchDirectoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.batch = self.root / 'secret-local-batch.ndjson'
        self.directory = self.root / 'secret-snapshot'
        self.directory.mkdir()
        self.entry = self.directory / 'secret-one.json'
        self.original = json.dumps(VALID).encode()
        self.batch.write_bytes(self.original + b'\n')
        self.entry.write_bytes(self.original)

    def private(self, output):
        for item in (str(self.root), 'secret-', 'https://', 'a'*64, 'b'*64):
            self.assertNotIn(item, output)

    def test_both_directions_all_presentation_formats_unchanged(self):
        for mode, label in MODES:
            for flags in (('--summary-json',), ('--json',), ('--summary', '--guidance')):
                with self.subTest(mode=mode, flags=flags):
                    p, data = invoke(mode, self.batch, self.directory,
                                     *flags, '--fail-on-change')
                    self.assertEqual((p.returncode, p.stderr), (0, b''))
                    if '--json' not in flags:
                        self.private(p.stdout.decode())
                    if '--summary' in flags:
                        self.assertIn('C0 offline review: UNCHANGED', p.stdout.decode())
                    else:
                        self.assertEqual(data['status'], 'UNCHANGED')
                        self.assertEqual(data['authorization'], 'NO_AUTHORIZATION')
                        self.assertEqual(data['network'], 'NO_NETWORK')
                        self.assertEqual(data['collection'], 'C0_COLLECT_HOLD')
                        if '--summary-json' in flags:
                            self.assertEqual(data['review_mode'], label)
                            self.assertEqual(data['review_schema'],
                                             'som-t5b0-c0-summary-json-v1')
                            self.assertEqual(data['object_change_counts'],
                                             {'added': 0, 'removed': 0, 'changed': 0})
                        else:
                            self.assertEqual(data['object_diff']['status'], 'AVAILABLE')

    def test_added_removed_and_changed_field_direction(self):
        changed = copy.deepcopy(VALID)
        changed['objects'][0]['id'] = 'C0-P1'
        changed['objects'][0]['url'] = 'https://example.org/other-whl.whl'
        changed['objects'][0]['sha256'] = 'b'*64
        self.entry.write_bytes(json.dumps(changed).encode())
        for mode, label in MODES:
            p, data = invoke(mode, self.batch, self.directory,
                             '--json', '--fail-on-change')
            self.assertEqual((p.returncode, p.stderr), (3, b''))
            self.assertEqual(data['status'], 'CHANGED')
            delta = data['object_diff']
            self.assertEqual((delta['added'], delta['removed']),
                             (['C0-P1'], ['C0-W1']) if mode == MODES[0][0]
                             else (['C0-W1'], ['C0-P1']))
            p, data = invoke(mode, self.batch, self.directory,
                             '--summary-json', '--fail-on-change')
            self.assertEqual((p.returncode, data['review_mode']), (3, label))
            self.assertEqual(data['object_change_counts'],
                             {'added': 1, 'removed': 1, 'changed': 0})
            self.private(p.stdout.decode())
        changed['objects'][0]['id'] = 'C0-W1'
        self.entry.write_bytes(json.dumps(changed).encode())
        for mode, _ in MODES:
            p, data = invoke(mode, self.batch, self.directory,
                             '--summary-json')
            self.assertEqual(p.returncode, 0)
            self.assertEqual(data['status'], 'CHANGED')
            self.assertEqual(data['object_change_counts'],
                             {'added': 0, 'removed': 0, 'changed': 1})

    def test_either_side_refusal_no_partial_changes(self):
        for mode, label in MODES:
            for local, directory in ((b'{', self.original),
                                     (self.original+b'\n', b'{'),
                                     (b'X'*262161, self.original),
                                     (self.original+b'\n', b'X'*16385),
                                     (b'\xff', self.original)):
                with self.subTest(mode=mode, a=len(local), b=len(directory)):
                    self.batch.write_bytes(local)
                    self.entry.write_bytes(directory)
                    p, data = invoke(mode, self.batch, self.directory,
                                     '--summary-json', '--fail-on-change')
                    self.assertEqual((p.returncode, p.stderr), (2, b''))
                    self.assertEqual(data['status'], 'REFUSED')
                    self.assertEqual(data['review_mode'], label)
                    self.assertEqual(data['object_changes'], 'UNAVAILABLE')
                    self.assertIsNone(data['object_change_counts'])
                    self.private(p.stdout.decode())

    def test_directory_64_total_bound_default_and_strict(self):
        for i in range(63):
            (self.directory / f'ignored-{i}.txt').write_text('')
        for mode, _ in MODES:
            p, data = invoke(mode, self.batch, self.directory, '--summary-json')
            self.assertEqual((p.returncode, data['status']), (0, 'UNCHANGED'))
            p, data = invoke(mode, self.batch, self.directory,
                             '--summary-json', '--require-json-only')
            self.assertEqual((p.returncode, data['status']), (2, 'REFUSED'))
            self.assertIsNone(data['object_change_counts'])
        (self.directory / 'overflow.txt').write_text('')
        for mode, _ in MODES:
            p, data = invoke(mode, self.batch, self.directory, '--summary-json')
            self.assertEqual((p.returncode, data['status']), (2, 'REFUSED'))
            self.assertIsNone(data['object_change_counts'])

    def test_non_regular_batch_refuses_without_hang(self):
        for mode, _ in MODES:
            for kind in ('symlink', 'fifo', 'directory', 'missing'):
                with self.subTest(mode=mode, kind=kind):
                    self.batch.unlink(missing_ok=True)
                    if kind == 'symlink':
                        self.batch.symlink_to(self.entry)
                    elif kind == 'fifo':
                        os.mkfifo(self.batch)
                    elif kind == 'directory':
                        self.batch.mkdir()
                    p, data = invoke(mode, self.batch, self.directory,
                                     '--summary-json')
                    self.assertEqual(p.returncode, 2, p.stderr)
                    self.assertEqual(data['status'], 'REFUSED')
                    self.assertIsNone(data['object_change_counts'])
                    self.private(p.stdout.decode())
                    if kind == 'directory':
                        self.batch.rmdir()
                    elif kind != 'missing':
                        self.batch.unlink()
                    self.batch.write_bytes(self.original+b'\n')

    def test_cross_record_duplicate_and_metadata_conflict_each_side(self):
        changed = copy.deepcopy(VALID)
        changed['objects'][0].update(id='C0-P1', sha256='b'*64)
        for source in ('batch', 'directory'):
            for reason, other, code in (
                    ('duplicate', copy.deepcopy(VALID), 'RESOLVE_DUPLICATE_OBJECT_ID'),
                    ('conflicting_url', changed, 'RESOLVE_CROSS_FILE_CONFLICT')):
                with self.subTest(source=source, reason=reason):
                    self.batch.write_bytes(self.original + b'\n')
                    self.entry.write_bytes(self.original)
                    second = json.dumps(other).encode()
                    second_path = self.directory / 'secret-two.json'
                    if source == 'batch':
                        second_path.unlink(missing_ok=True)
                        self.batch.write_bytes(self.original + b'\n' + second + b'\n')
                    else:
                        second_path.write_bytes(second)
                    for mode, _ in MODES:
                        p, data = invoke(mode, self.batch, self.directory,
                                         '--summary-json', '--fail-on-change')
                        self.assertEqual((p.returncode, p.stderr), (2, b''))
                        self.assertEqual(data['status'], 'REFUSED')
                        self.assertIsNone(data['object_change_counts'])
                        self.assertIn(code, data['next_action_codes'])
                        self.private(p.stdout.decode())
                    second_path.unlink(missing_ok=True)

    def test_mode_collisions_do_not_read_file_directory_or_stdin(self):
        class NoReadStdin:
            @property
            def buffer(self):
                raise AssertionError('read stdin buffer')

            def read(self, *_a, **_kw):
                raise AssertionError('read stdin')

        for mode, _ in MODES:
            operands = ((self.batch, self.directory) if mode == MODES[0][0]
                        else (self.directory, self.batch))
            for extra in (('--stdin',), ('--stdin-batch',),
                          ('--compare-batch-files', self.batch, self.batch),
                          ('--directory', self.directory),
                          ('--capabilities-json',)):
                with self.subTest(mode=mode, extra=extra):
                    args = [str(SCRIPT), mode, *map(str, operands),
                            *map(str, extra)]
                    output, errors = io.StringIO(), io.StringIO()
                    with patch.object(sys, 'argv', args), \
                            patch.object(sys, 'stdin', NoReadStdin()), \
                            patch.object(cli, 'inspect_local_ndjson_batch',
                                         side_effect=AssertionError('read batch')), \
                            patch.object(cli, 'directory_report',
                                         side_effect=AssertionError('scan dir')), \
                            redirect_stdout(output), redirect_stderr(errors), \
                            self.assertRaises(SystemExit) as raised:
                        cli.main()
                    self.assertEqual(raised.exception.code, 2)
                    self.assertEqual(output.getvalue(), '')
                    self.assertIn('cannot be combined', errors.getvalue())

    def test_colliding_source_modes_error_before_output(self):
        for mode, _ in MODES:
            for flags in (('--stdin',), ('--stdin-batch',),
                          ('--batch', self.entry), ('--directory', self.directory),
                          ('--compare-batch-files', self.batch, self.batch),
                          ('--compare-file-to-batch', self.entry, self.batch),
                          ('--compare-directory-to-file', self.directory, self.entry),
                          ('--compare-directories', self.directory, self.directory),
                          ('--compare-stdin-batches',), ('--capabilities-json',),
                          (self.entry,),
                          (MODES[1][0] if mode == MODES[0][0] else MODES[0][0],
                           self.directory, self.batch)):
                with self.subTest(mode=mode, flags=flags):
                    p, _ = invoke(mode, self.batch, self.directory, *flags)
                    self.assertEqual(p.returncode, 2, p.stderr)
                    self.assertEqual(p.stdout, b'')
                    self.assertIn(b'cannot be combined', p.stderr)


if __name__ == '__main__':
    unittest.main()
