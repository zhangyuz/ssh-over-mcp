"""Opt-in cross-file consistency audit for bounded individual local manifests."""
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


class ExplicitBatchConsistencyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.a = self.root / 'secret-first.json'
        self.b = self.root / 'secret-second.json'
        self.a.write_text(json.dumps(VALID))
        self.second = copy.deepcopy(VALID)
        self.second['objects'][0].update(id='C0-P1', url='https://example.org/second',
                                         sha256='b'*64)
        self.b.write_text(json.dumps(self.second))

    def invoke(self, *flags):
        run = subprocess.run([sys.executable, str(SCRIPT), *map(str, flags)],
                             capture_output=True, timeout=6, check=False)
        self.assertEqual(run.stderr, b'')
        return run.returncode, json.loads(run.stdout)

    def private(self, report):
        raw = json.dumps(report)
        for secret in (str(self.root), 'secret-', 'C0-W1', 'C0-P1',
                       'https://', 'a'*64, 'b'*64):
            self.assertNotIn(secret, raw)

    def test_clean_cross_file_batch_positive_and_legacy_backcompat(self):
        code, report = self.invoke('--batch', self.a, self.b,
                                   '--batch-consistency', '--summary-json')
        self.assertEqual(code, 0)
        self.assertEqual((report['review_mode'], report['status']),
                         ('FILE_BATCH_CONSISTENT', 'STRUCTURE_ONLY_PASS'))
        self.assertEqual((report['input']['observed'], report['input']['passed']), (2, 2))
        self.assertEqual(report['authorization'], 'NO_AUTHORIZATION')
        self.assertEqual(report['collection'], 'C0_COLLECT_HOLD')
        self.assertEqual(report['network'], 'NO_NETWORK')
        self.assertEqual(len(report['evidence_gaps']), 5)
        self.private(report)
        code, legacy = self.invoke('--batch', self.a, self.b)
        self.assertEqual((code, legacy['status']), (0, 'STRUCTURE_ONLY_PASS'))

    def test_repeated_id_refused_only_opt_in_with_fixed_private_remediation(self):
        self.b.write_bytes(self.a.read_bytes())
        code, legacy = self.invoke('--batch', self.a, self.b)
        self.assertEqual((code, legacy['status']), (0, 'STRUCTURE_ONLY_PASS'))
        code, report = self.invoke('--batch', self.a, self.b,
                                   '--batch-consistency', '--summary-json')
        self.assertEqual((code, report['status']), (2, 'REFUSED'))
        self.assertEqual(report['input']['refused'], 2)
        self.assertIn('RESOLVE_DUPLICATE_OBJECT_ID', report['next_action_codes'])
        self.assertNotIn('VERIFY_INDEPENDENT_EVIDENCE', report['next_action_codes'])
        self.private(report)
        code, details = self.invoke('--batch', self.a, self.b, '--batch-consistency')
        self.assertEqual(code, 2)
        self.assertTrue(all('DUPLICATE_OBJECT_ID' in item['error_codes']
                            for item in details['results']))
        self.assertNotIn('C0-W1', json.dumps(details))
        self.assertNotIn('https://', json.dumps(details))

    def test_conflicting_url_digest_and_invalid_side_refuse(self):
        self.second['objects'][0]['url'] = VALID['objects'][0]['url']
        self.b.write_text(json.dumps(self.second))
        code, report = self.invoke('--batch', self.a, self.b,
                                   '--batch-consistency', '--summary-json')
        self.assertEqual((code, report['status']), (2, 'REFUSED'))
        self.assertIn('RESOLVE_CROSS_FILE_CONFLICT', report['next_action_codes'])
        self.private(report)
        self.b.write_bytes(b'{')
        code, report = self.invoke('--batch', self.a, self.b,
                                   '--batch-consistency', '--summary-json')
        self.assertEqual((code, report['status']), (2, 'REFUSED'))
        self.assertEqual(report['input']['passed'], 1)
        self.assertEqual(report['input']['refused'], 1)
        self.private(report)

    def test_shared_digest_with_conflicting_declared_size_refuses(self):
        self.second['objects'][0]['sha256'] = VALID['objects'][0]['sha256']
        self.second['objects'][0]['bytes'] = VALID['objects'][0]['bytes'] + 1
        self.second['objects'][0]['max_bytes'] = max(
            self.second['objects'][0]['bytes'], self.second['objects'][0]['max_bytes'])
        self.b.write_text(json.dumps(self.second))
        code, report = self.invoke('--batch', self.a, self.b,
                                   '--batch-consistency', '--summary-json')
        self.assertEqual((code, report['status']), (2, 'REFUSED'))
        self.assertIn('RESOLVE_CROSS_FILE_CONFLICT', report['next_action_codes'])
        self.private(report)

    def test_private_guidance_and_strict_same_fd_positive(self):
        # Repeatability matters, but never confuse structural acceptance with trust.
        command = [sys.executable, str(SCRIPT), '--batch', str(self.a), str(self.b),
                   '--batch-consistency', '--summary', '--guidance']
        process = subprocess.run(command, capture_output=True, timeout=6, check=False)
        self.assertEqual((process.returncode, process.stderr), (0, b''))
        self.assertIn('STRUCTURE_ONLY_PASS', process.stdout.decode())
        self.assertNotIn('https://', process.stdout.decode())
        self.assertNotIn(str(self.root), process.stdout.decode())
        self.assertIn('NO_AUTHORIZATION', process.stdout.decode())

    def test_refuse_fifo_symlink_missing_and_over_16_before_input_access(self):
        for kind in ('fifo', 'symlink', 'missing'):
            with self.subTest(kind=kind):
                self.b.unlink(missing_ok=True)
                if kind == 'fifo':
                    os.mkfifo(self.b)
                elif kind == 'symlink':
                    self.b.symlink_to(self.a)
                code, report = self.invoke('--batch', self.a, self.b,
                                           '--batch-consistency', '--summary-json')
                self.assertEqual((code, report['status']), (2, 'REFUSED'))
                self.private(report)
        code, report = self.invoke('--batch', *([self.a]*17), '--batch-consistency',
                                   '--summary-json')
        self.assertEqual((code, report['status']), (2, 'REFUSED'))
        self.assertEqual(report['input']['observed'], 0)
        self.private(report)

    def test_invalid_mode_or_output_collisions_refuse_before_any_read(self):
        class NoRead:
            @property
            def buffer(self):
                raise AssertionError('stdin access')
        wrong = (('--stdin',), ('--stdin-batch',), ('--directory', self.root),
                 ('--compare-files', self.a, self.b), ('--compare-stdin-batches',),
                 ('--compare-batch-file-to-stdin', self.a),
                 ('--capabilities-json',), ('--require-json-only',),
                 ('--fail-on-change',))
        for extra in wrong:
            args = [str(SCRIPT), '--batch', str(self.a), '--batch-consistency',
                    *map(str, extra)]
            with self.subTest(extra=extra), patch.object(sys, 'argv', args), \
                    patch.object(sys, 'stdin', NoRead()), \
                    patch.object(cli, 'inspect_manifest',
                                 side_effect=AssertionError('file read')), \
                    patch.object(cli, 'inspect_stdin_batch',
                                 side_effect=AssertionError('stdin parse')), \
                    patch.object(cli, 'directory_report',
                                 side_effect=AssertionError('directory scan')), \
                    redirect_stdout(io.StringIO()) as stdout, \
                    redirect_stderr(io.StringIO()) as stderr, \
                    self.assertRaises(SystemExit) as exc:
                cli.main()
            self.assertEqual(exc.exception.code, 2)
            self.assertEqual(stdout.getvalue(), '')
            self.assertIn(('--capabilities-json cannot be combined'
                           if '--capabilities-json' in extra else 'batch-consistency'),
                          stderr.getvalue())
        args = [str(SCRIPT), '--batch-consistency', str(self.a)]
        with patch.object(sys, 'argv', args), \
                patch.object(cli, 'inspect_manifest', side_effect=AssertionError('read')), \
                redirect_stdout(io.StringIO()) as stdout, \
                redirect_stderr(io.StringIO()) as stderr, \
                self.assertRaises(SystemExit) as exc:
            cli.main()
        self.assertEqual(exc.exception.code, 2)
        self.assertEqual(stdout.getvalue(), '')
        self.assertIn('batch-consistency', stderr.getvalue())

    def test_static_discovery_advertises_new_mode_without_input(self):
        code, report = self.invoke('--capabilities-json')
        self.assertEqual(code, 0)
        self.assertIn('FILE_BATCH_CONSISTENT', report['review_modes'])
        self.assertEqual(report['limits']['batch_manifests'], 16)
        self.private(report)


if __name__ == '__main__':
    unittest.main()
