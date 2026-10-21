"""Stable fail-closed offline C0 CLI capability discovery contract."""
import io
import json
import subprocess
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import c0_manifest_preflight as preflight

SCRIPT = Path(__file__).with_name('c0_manifest_preflight.py')
EXPECTED_MODES = {
    'MANIFEST_FILE', 'FILE_BATCH', 'DIRECTORY', 'STDIN_MANIFEST', 'STDIN_BATCH',
    'DIRECTORY_COMPARISON', 'DIRECTORY_TO_STDIN', 'STDIN_TO_DIRECTORY',
    'PAIRED_STDIN_COMPARISON', 'FILE_COMPARISON', 'FILE_TO_STDIN', 'STDIN_TO_FILE',
    'FILE_TO_DIRECTORY', 'DIRECTORY_TO_FILE', 'FILE_TO_BATCH', 'BATCH_TO_FILE', 'LOCAL_BATCH_COMPARISON',
}


class CapabilityDiscoveryTests(unittest.TestCase):
    def test_no_input_capabilities_json_is_static_bounded_and_safe(self):
        run = subprocess.run([sys.executable, str(SCRIPT), '--capabilities-json'],
                             input=b'{not valid and should not be read}', capture_output=True,
                             check=False, timeout=6)
        self.assertEqual((run.returncode, run.stderr), (0, b''))
        report = json.loads(run.stdout)
        self.assertEqual(report['schema'], 'som-t5b0-c0-capabilities-v1')
        self.assertEqual(report['review_schema'], 'som-t5b0-c0-summary-json-v1')
        self.assertEqual(set(report['review_modes']), EXPECTED_MODES)
        self.assertEqual(report['review_modes'], sorted(EXPECTED_MODES))
        self.assertEqual(report['limits'], {
            'manifest_bytes': 16384, 'directory_entries': 64,
            'directory_manifests': 16, 'batch_manifests': 16,
            'objects_per_manifest': 4, 'batch_file_bytes': 16 * 16385,
        })
        self.assertEqual(report['authorization'], 'NO_AUTHORIZATION')
        self.assertEqual(report['collection'], 'C0_COLLECT_HOLD')
        self.assertEqual(report['network'], 'NO_NETWORK')
        self.assertEqual(len(report['evidence_gaps']), 5)
        self.assertNotIn('not valid', run.stdout.decode())
        self.assertNotIn('https://', run.stdout.decode())
        self.assertNotIn('sha256', run.stdout.decode())
        second = subprocess.run([sys.executable, str(SCRIPT), '--capabilities-json'],
                                capture_output=True, timeout=6, check=False)
        self.assertEqual(run.stdout, second.stdout)

    def test_capabilities_conflicts_pre_read_with_all_mode_families(self):
        options = [
            ['example.json'], ['--batch', 'example.json'], ['--directory', 'folder'],
            ['--stdin'], ['--stdin-batch'], ['--compare-files', 'one', 'two'],
            ['--compare-directories', 'one', 'two'],
            ['--compare-batch-files', 'one', 'two'],
            ['--compare-file-to-batch', 'one', 'two'],
            ['--compare-batch-to-file', 'one', 'two'], ['--compare-file-to-stdin', 'one'],
            ['--compare-stdin-to-file', 'two'],
            ['--compare-file-to-directory', 'one', 'two'],
            ['--compare-directory-to-file', 'one', 'two'],
            ['--compare-stdin-to-directory', 'one'],
            ['--compare-stdin-before-directory', 'two'],
            ['--compare-stdin-batches'], ['--fail-on-change'], ['--require-json-only'],
            ['--summary-json'], ['--summary'], ['--json'], ['--guidance'],
        ]
        for flags in options:
            with self.subTest(flags=flags):
                args = [str(SCRIPT), '--capabilities-json', *flags]
                stdout, stderr = io.StringIO(), io.StringIO()
                with patch.object(sys, 'argv', args), \
                        patch.object(preflight, 'inspect_manifest',
                                     side_effect=AssertionError('read file')), \
                        patch.object(preflight, 'inspect_stdin',
                                     side_effect=AssertionError('read stdin')), \
                        patch.object(preflight, 'directory_report',
                                     side_effect=AssertionError('scan directory')), \
                        redirect_stdout(stdout), redirect_stderr(stderr), \
                        self.assertRaises(SystemExit) as exc:
                    preflight.main()
                self.assertEqual(exc.exception.code, 2)
                self.assertEqual(stdout.getvalue(), '')
                self.assertIn('--capabilities-json cannot be combined',
                              stderr.getvalue())

    def test_success_does_not_touch_stdin_file_or_directory(self):
        class NoRead:
            def read(self, *args, **kwargs):
                raise AssertionError('capability request must not touch stdin')

        output = io.StringIO()
        with patch.object(sys, 'argv', [str(SCRIPT), '--capabilities-json']), \
                patch.object(sys, 'stdin', SimpleNamespace(buffer=NoRead())), \
                patch.object(preflight, 'inspect_manifest',
                             side_effect=AssertionError('must not touch file')), \
                patch.object(preflight, 'inspect_stdin',
                             side_effect=AssertionError('must not read stdin')), \
                patch.object(preflight, 'directory_report',
                             side_effect=AssertionError('must not scan directory')), \
                redirect_stdout(output), redirect_stderr(io.StringIO()):
            self.assertEqual(preflight.main(), 0)
        self.assertEqual(json.loads(output.getvalue())['schema'],
                         'som-t5b0-c0-capabilities-v1')

    def test_capability_report_is_never_an_authorization(self):
        report = preflight.render_capabilities_json()
        self.assertEqual(json.loads(report)['authorization'], 'NO_AUTHORIZATION')
        self.assertEqual(json.loads(report)['collection'], 'C0_COLLECT_HOLD')
        self.assertNotIn('APPROVED', report)


if __name__ == '__main__':
    unittest.main()
