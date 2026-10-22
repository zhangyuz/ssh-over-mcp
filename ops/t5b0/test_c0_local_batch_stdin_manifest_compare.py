"""Safe bidirectional comparison of local NDJSON batch with single piped manifest."""
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
MODES = (('--compare-batch-file-to-stdin', 'LOCAL_BATCH_TO_STDIN'),
         ('--compare-stdin-to-batch-file', 'STDIN_TO_LOCAL_BATCH'))


def invoke(mode, batch, stream, *flags):
    proc = subprocess.run([sys.executable, str(SCRIPT), mode, str(batch),
                           *map(str, flags)], input=stream, capture_output=True,
                          check=False, timeout=9)
    data = json.loads(proc.stdout) if proc.stdout.startswith(b'{') else None
    return proc, data


class LocalBatchStdinManifestTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.batch = self.root / 'private-local-batch.ndjson'
        self.base = json.dumps(VALID).encode()
        self.batch.write_bytes(self.base + b'\n')

    def private(self, text):
        for token in (str(self.root), 'private-', 'https://', 'a'*64, 'b'*64,
                      'C0-W1', 'C0-P1'):
            self.assertNotIn(token, text)

    def test_unchanged_all_presentations_and_no_authority(self):
        for mode, label in MODES:
            for flags in (('--summary-json',), ('--json',),
                          ('--summary', '--guidance')):
                with self.subTest(mode=mode, flags=flags):
                    p, data = invoke(mode, self.batch, self.base,
                                     *flags, '--fail-on-change')
                    self.assertEqual((p.returncode, p.stderr), (0, b''))
                    if '--summary' in flags:
                        self.assertIn('C0 offline review: UNCHANGED', p.stdout.decode())
                        self.private(p.stdout.decode())
                    else:
                        self.assertEqual(data['status'], 'UNCHANGED')
                        self.assertEqual(data['authorization'], 'NO_AUTHORIZATION')
                        self.assertEqual(data['collection'], 'C0_COLLECT_HOLD')
                        self.assertEqual(data['network'], 'NO_NETWORK')
                        if '--summary-json' in flags:
                            self.assertEqual(data['review_mode'], label)
                            self.assertEqual(data['review_schema'],
                                             'som-t5b0-c0-summary-json-v1')
                            self.assertEqual(data['object_change_counts'],
                                             {'added': 0, 'removed': 0, 'changed': 0})
                            self.private(p.stdout.decode())
                        else:
                            self.assertEqual(data['object_diff']['status'], 'AVAILABLE')

    def test_before_after_orientation_and_change_exit(self):
        added = copy.deepcopy(VALID)
        added['objects'][0].update(id='C0-P1', url='https://example.org/other.whl',
                                   sha256='b'*64)
        self.batch.write_bytes(self.base+b'\n'+json.dumps(added).encode()+b'\n')
        for mode, label in MODES:
            p, data = invoke(mode, self.batch, self.base,
                             '--json', '--fail-on-change')
            self.assertEqual((p.returncode, p.stderr), (3, b''))
            self.assertEqual(data['status'], 'CHANGED')
            self.assertEqual((data['object_diff']['added'], data['object_diff']['removed']),
                             ([], ['C0-P1']) if mode == MODES[0][0]
                             else (['C0-P1'], []))
            p, data = invoke(mode, self.batch, self.base, '--summary-json')
            self.assertEqual(p.returncode, 0)
            self.assertEqual(data['status'], 'CHANGED')
            self.assertEqual(data['review_mode'], label)
            self.assertEqual(data['object_change_counts'],
                             {'added': 0, 'removed': 1, 'changed': 0}
                             if mode == MODES[0][0]
                             else {'added': 1, 'removed': 0, 'changed': 0})
            self.private(p.stdout.decode())
        self.batch.write_bytes(self.base+b'\n')
        changed = copy.deepcopy(VALID)
        changed['objects'][0]['max_bytes'] += 1
        for mode, _ in MODES:
            p, data = invoke(mode, self.batch, json.dumps(changed).encode(),
                             '--summary-json', '--fail-on-change')
            self.assertEqual(p.returncode, 3)
            self.assertEqual(data['object_change_counts'],
                             {'added': 0, 'removed': 0, 'changed': 1})

    def test_refused_sources_never_produce_partial_diff(self):
        for mode, label in MODES:
            for batch, stream in ((b'{', self.base),
                                  (self.base+b'\n', b'{'),
                                  (self.base+b'\n', b''),
                                  (self.base+b'\n', b'\xff'),
                                  (self.base+b'\n', b'X'*16385),
                                  (b'X'*262161, self.base),
                                  ((self.base+b'\n')*17, self.base),
                                  ((self.base+b'\n')*2, self.base),
                                  (b'{', b'{')):
                with self.subTest(mode=mode, disk=len(batch), stream=len(stream)):
                    self.batch.write_bytes(batch)
                    p, data = invoke(mode, self.batch, stream,
                                     '--summary-json', '--fail-on-change')
                    self.assertEqual((p.returncode, p.stderr), (2, b''))
                    self.assertEqual(data['review_mode'], label)
                    self.assertEqual(data['status'], 'REFUSED')
                    self.assertEqual(data['object_changes'], 'UNAVAILABLE')
                    self.assertIsNone(data['object_change_counts'])
                    self.private(p.stdout.decode())

    def test_batch_cross_record_conflict(self):
        changed = copy.deepcopy(VALID)
        changed['objects'][0].update(id='C0-P1', sha256='b'*64)
        self.batch.write_bytes(self.base+b'\n'+json.dumps(changed).encode()+b'\n')
        for mode, _ in MODES:
            p, data = invoke(mode, self.batch, self.base, '--summary-json')
            self.assertEqual((p.returncode, p.stderr), (2, b''))
            self.assertEqual(data['status'], 'REFUSED')
            self.assertIsNone(data['object_change_counts'])
            self.assertIn('RESOLVE_CROSS_FILE_CONFLICT', data['next_action_codes'])
            self.private(p.stdout.decode())

    def test_nonregular_disk_symlink_fifo_directory_missing_refuse(self):
        for mode, _ in MODES:
            for kind in ('symlink', 'fifo', 'directory', 'missing'):
                with self.subTest(mode=mode, kind=kind):
                    self.batch.unlink(missing_ok=True)
                    if kind == 'symlink':
                        target = self.root / 'private-target.json'
                        target.write_bytes(self.base)
                        self.batch.symlink_to(target)
                    elif kind == 'fifo':
                        os.mkfifo(self.batch)
                    elif kind == 'directory':
                        self.batch.mkdir()
                    p, data = invoke(mode, self.batch, self.base, '--summary-json')
                    self.assertEqual(p.returncode, 2, p.stderr)
                    self.assertEqual(data['status'], 'REFUSED')
                    self.assertIsNone(data['object_change_counts'])
                    self.private(p.stdout.decode())
                    if kind == 'directory':
                        self.batch.rmdir()
                    elif kind != 'missing':
                        self.batch.unlink()
                    self.batch.write_bytes(self.base+b'\n')

    def test_stdin_still_audited_after_local_batch_refuses(self):
        for mode, _ in MODES:
            self.batch.write_bytes(b'{')
            output = io.StringIO()
            stdin = io.TextIOWrapper(io.BytesIO(self.base), encoding='utf-8')
            with patch.object(sys, 'argv', [str(SCRIPT), mode,
                                            str(self.batch), '--summary-json']), \
                    patch.object(sys, 'stdin', stdin), \
                    patch.object(cli, 'inspect_stdin',
                                 wraps=cli.inspect_stdin) as stream_spy, \
                    redirect_stdout(output):
                rc = cli.main()
            self.assertEqual(rc, 2)
            stream_spy.assert_called_once_with(capture_inventory=True)
            report = json.loads(output.getvalue())
            self.assertEqual(report['status'], 'REFUSED')
            self.assertIsNone(report['object_change_counts'])
            self.assertEqual(
                (report['before']['status'], report['after']['status']),
                ('REFUSED', 'STRUCTURE_ONLY_PASS') if mode == MODES[0][0]
                else ('STRUCTURE_ONLY_PASS', 'REFUSED'))
            self.private(output.getvalue())

    def test_conflicting_options_reject_before_read(self):
        class NoRead:
            @property
            def buffer(self):
                raise AssertionError('stdin buffer read')

        for mode, _ in MODES:
            for extra in (('--stdin',), ('--stdin-batch',),
                          ('--batch', self.batch), ('--compare-directories', self.root,
                                                  self.root),
                          ('--compare-files', self.batch, self.batch),
                          ('--compare-batch-files', self.batch, self.batch),
                          ('--compare-file-to-stdin-batch', self.batch),
                          ('--compare-batch-file-to-stdin-batch', self.batch),
                          ('--compare-stdin-batches',),
                          ('--require-json-only',), ('--capabilities-json',),
                          (MODES[1][0] if mode == MODES[0][0] else MODES[0][0],
                           self.batch), (self.batch,)):
                with self.subTest(mode=mode, extra=extra):
                    args = [str(SCRIPT), mode, str(self.batch), *map(str, extra)]
                    stdout, stderr = io.StringIO(), io.StringIO()
                    with patch.object(sys, 'argv', args), \
                            patch.object(sys, 'stdin', NoRead()), \
                            patch.object(cli, 'inspect_stdin',
                                         side_effect=AssertionError('read stdin')), \
                            patch.object(cli, 'inspect_local_ndjson_batch',
                                         side_effect=AssertionError('read batch')), \
                            redirect_stdout(stdout), redirect_stderr(stderr), \
                            self.assertRaises(SystemExit) as raised:
                        cli.main()
                    self.assertEqual(raised.exception.code, 2)
                    self.assertEqual(stdout.getvalue(), '')
                    self.assertIn('cannot be combined', stderr.getvalue())


if __name__ == '__main__':
    unittest.main()
