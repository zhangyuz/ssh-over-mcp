"""A single bounded on-disk manifest vs a bounded NDJSON stdin stream."""
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
MODES = (('--compare-file-to-stdin-batch', 'FILE_TO_STDIN_BATCH'),
         ('--compare-stdin-batch-to-file', 'STDIN_BATCH_TO_FILE'))


def invoke(mode, manifest, stream, *flags):
    proc = subprocess.run([sys.executable, str(SCRIPT), mode,
                           str(manifest), *map(str, flags)], input=stream,
                          capture_output=True, check=False, timeout=9)
    data = json.loads(proc.stdout) if proc.stdout.startswith(b'{') else None
    return proc, data


class SingleFileStdinBatchTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.manifest = self.root / 'private-manifest.json'
        self.base = json.dumps(VALID).encode()
        self.manifest.write_bytes(self.base)

    def private(self, text):
        for token in (str(self.root), 'private-', 'https://', 'a'*64, 'b'*64,
                      'C0-W1', 'C0-P1'):
            self.assertNotIn(token, text)

    def test_both_directions_unchanged_all_presentations(self):
        for mode, label in MODES:
            for flags in (('--summary-json',), ('--json',),
                          ('--summary', '--guidance')):
                with self.subTest(mode=mode, flags=flags):
                    p, data = invoke(mode, self.manifest, self.base+b'\n',
                                     *flags, '--fail-on-change')
                    self.assertEqual((p.returncode, p.stderr), (0, b''))
                    if '--summary' in flags:
                        self.assertIn('C0 offline review: UNCHANGED', p.stdout.decode())
                        self.private(p.stdout.decode())
                    else:
                        self.assertEqual(data['status'], 'UNCHANGED')
                        self.assertEqual(data['network'], 'NO_NETWORK')
                        self.assertEqual(data['authorization'], 'NO_AUTHORIZATION')
                        self.assertEqual(data['collection'], 'C0_COLLECT_HOLD')
                        if '--summary-json' in flags:
                            self.assertEqual(data['review_mode'], label)
                            self.assertEqual(data['object_change_counts'],
                                             {'added': 0, 'removed': 0, 'changed': 0})
                            self.private(p.stdout.decode())
                        else:
                            self.assertEqual(data['object_diff']['status'], 'AVAILABLE')

    def test_directional_added_removed_and_changed_field(self):
        changed = copy.deepcopy(VALID)
        changed['objects'][0].update(id='C0-P1', url='https://example.org/other.whl',
                                     sha256='b'*64)
        updated = json.dumps(changed).encode()+b'\n'
        for mode, label in MODES:
            p, data = invoke(mode, self.manifest, updated,
                             '--json', '--fail-on-change')
            self.assertEqual((p.returncode, p.stderr), (3, b''))
            self.assertEqual(data['status'], 'CHANGED')
            self.assertEqual((data['object_diff']['added'], data['object_diff']['removed']),
                             (['C0-P1'], ['C0-W1']) if mode == MODES[0][0]
                             else (['C0-W1'], ['C0-P1']))
            p, data = invoke(mode, self.manifest, updated, '--summary-json')
            self.assertEqual(p.returncode, 0)
            self.assertEqual(data['status'], 'CHANGED')
            self.assertEqual(data['review_mode'], label)
            self.assertEqual(data['object_change_counts'],
                             {'added': 1, 'removed': 1, 'changed': 0})
            self.private(p.stdout.decode())
            self.manifest.write_bytes(self.base)
        updated_field = copy.deepcopy(VALID)
        updated_field['objects'][0]['max_bytes'] += 1
        for mode, _ in MODES:
            p, data = invoke(mode, self.manifest,
                             json.dumps(updated_field).encode()+b'\n',
                             '--summary-json', '--fail-on-change')
            self.assertEqual(p.returncode, 3)
            self.assertEqual(data['object_change_counts'],
                             {'added': 0, 'removed': 0, 'changed': 1})

    def test_either_side_refusal_never_exposes_partial_delta(self):
        for mode, label in MODES:
            for single, stream in ((b'{', self.base+b'\n'),
                                   (self.base, b'{'),
                                   (b'X'*16385, self.base+b'\n'),
                                   (self.base, b'X'*262161),
                                   (self.base, b'X'*16385+b'\n'),
                                   (self.base, (self.base+b'\n')*17),
                                   (self.base, (self.base+b'\n')*2),
                                   (self.base, b'\xff')):
                with self.subTest(mode=mode, left=len(single), right=len(stream)):
                    self.manifest.write_bytes(single)
                    p, data = invoke(mode, self.manifest, stream,
                                     '--summary-json', '--fail-on-change')
                    self.assertEqual((p.returncode, p.stderr), (2, b''))
                    self.assertEqual(data['status'], 'REFUSED')
                    self.assertEqual(data['review_mode'], label)
                    self.assertEqual(data['object_changes'], 'UNAVAILABLE')
                    self.assertIsNone(data['object_change_counts'])
                    self.private(p.stdout.decode())

    def test_special_files_nonblocking_refusal(self):
        for mode, _ in MODES:
            for kind in ('symlink', 'fifo', 'directory', 'missing'):
                with self.subTest(mode=mode, kind=kind):
                    self.manifest.unlink(missing_ok=True)
                    if kind == 'symlink':
                        target = self.root / 'target.json'
                        target.write_bytes(self.base)
                        self.manifest.symlink_to(target)
                    elif kind == 'fifo':
                        os.mkfifo(self.manifest)
                    elif kind == 'directory':
                        self.manifest.mkdir()
                    p, data = invoke(mode, self.manifest, self.base+b'\n',
                                     '--summary-json')
                    self.assertEqual(p.returncode, 2, p.stderr)
                    self.assertEqual(data['status'], 'REFUSED')
                    self.assertIsNone(data['object_change_counts'])
                    self.private(p.stdout.decode())
                    if kind == 'directory':
                        self.manifest.rmdir()
                    elif kind != 'missing':
                        self.manifest.unlink()
                    self.manifest.write_bytes(self.base)

    def test_cross_record_metadata_conflict_and_both_side_refusal(self):
        conflicting = copy.deepcopy(VALID)
        conflicting['objects'][0].update(id='C0-P1', sha256='b'*64)
        # Reuses the original URL with contradictory digest/length metadata.
        cross = self.base+b'\n'+json.dumps(conflicting).encode()+b'\n'
        for mode, label in MODES:
            with self.subTest(mode=mode, reason='cross_record'):
                self.manifest.write_bytes(self.base)
                p, data = invoke(mode, self.manifest, cross,
                                 '--summary-json', '--fail-on-change')
                self.assertEqual((p.returncode, p.stderr), (2, b''))
                self.assertEqual(data['review_mode'], label)
                self.assertEqual(data['status'], 'REFUSED')
                self.assertIsNone(data['object_change_counts'])
                self.assertIn('RESOLVE_CROSS_FILE_CONFLICT', data['next_action_codes'])
                self.private(p.stdout.decode())
            with self.subTest(mode=mode, reason='both_refused'):
                self.manifest.write_bytes(b'{')
                p, data = invoke(mode, self.manifest, b'{', '--summary-json')
                self.assertEqual((p.returncode, p.stderr), (2, b''))
                self.assertEqual(data['status'], 'REFUSED')
                self.assertIsNone(data['object_change_counts'])
                self.assertEqual(data['before']['status'], 'REFUSED')
                self.assertEqual(data['after']['status'], 'REFUSED')
                self.private(p.stdout.decode())

    def test_exact_single_manifest_and_line_byte_ceiling(self):
        padded = self.base + b' ' * (16384 - len(self.base))
        self.assertEqual(len(padded), 16384)
        for mode, _ in MODES:
            self.manifest.write_bytes(padded)
            p, data = invoke(mode, self.manifest, padded+b'\n', '--summary-json')
            self.assertEqual((p.returncode, p.stderr), (0, b''))
            self.assertEqual(data['status'], 'UNCHANGED')
            self.private(p.stdout.decode())
            p, data = invoke(mode, self.manifest, b'', '--summary-json')
            self.assertEqual((p.returncode, data['status']), (2, 'REFUSED'))
            self.assertIsNone(data['object_change_counts'])
            p, data = invoke(mode, self.manifest, b'\n', '--summary-json')
            self.assertEqual((p.returncode, data['status']), (2, 'REFUSED'))
            self.assertIsNone(data['object_change_counts'])

    def test_stdin_is_audited_even_when_local_file_refuses(self):
        for mode, _ in MODES:
            self.manifest.write_bytes(b'{')
            output = io.StringIO()
            stdin = io.TextIOWrapper(io.BytesIO(self.base+b'\n'), encoding='utf-8')
            with patch.object(sys, 'argv', [str(SCRIPT), mode,
                                            str(self.manifest), '--summary-json']), \
                    patch.object(sys, 'stdin', stdin), \
                    patch.object(cli, 'inspect_stdin_batch',
                                 wraps=cli.inspect_stdin_batch) as batch_spy, \
                    redirect_stdout(output):
                rc = cli.main()
            self.assertEqual(rc, 2)
            batch_spy.assert_called_once_with(capture_inventory=True)
            report = json.loads(output.getvalue())
            self.assertEqual(report['status'], 'REFUSED')
            self.assertIsNone(report['object_change_counts'])
            self.assertEqual(
                (report['before']['status'], report['after']['status']),
                ('REFUSED', 'STRUCTURE_ONLY_PASS') if mode == MODES[0][0]
                else ('STRUCTURE_ONLY_PASS', 'REFUSED'))
            self.private(output.getvalue())

    def test_colliding_modes_reject_without_accessing_sources(self):
        class NoRead:
            @property
            def buffer(self):
                raise AssertionError('read stdin')

        for mode, _ in MODES:
            for extra in (('--stdin',), ('--stdin-batch',),
                          ('--compare-files', self.manifest, self.manifest),
                          ('--compare-batch-files', self.manifest, self.manifest),
                          ('--compare-file-to-stdin', self.manifest),
                          ('--compare-stdin-batches',),
                          ('--compare-batch-file-to-stdin-batch', self.manifest),
                          ('--require-json-only',), ('--capabilities-json',),
                          (MODES[1][0] if mode == MODES[0][0] else MODES[0][0],
                           self.manifest), (self.manifest,)):
                with self.subTest(mode=mode, extra=extra):
                    args = [str(SCRIPT), mode, str(self.manifest),
                            *map(str, extra)]
                    stdout, stderr = io.StringIO(), io.StringIO()
                    with patch.object(sys, 'argv', args), \
                            patch.object(sys, 'stdin', NoRead()), \
                            patch.object(cli, 'inspect_manifest',
                                         side_effect=AssertionError('read file')), \
                            patch.object(cli, 'inspect_stdin_batch',
                                         side_effect=AssertionError('read stream')), \
                            redirect_stdout(stdout), redirect_stderr(stderr), \
                            self.assertRaises(SystemExit) as raised:
                        cli.main()
                    self.assertEqual(raised.exception.code, 2)
                    self.assertEqual(stdout.getvalue(), '')
                    self.assertIn('cannot be combined', stderr.getvalue())


if __name__ == '__main__':
    unittest.main()
