"""Real offline CLI summary acceptance, including adversarial output privacy."""
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

BASE = {'schema': 'som-t5b0-c0-preflight-v1', 'approval': None,
        'objects': [{'id': 'C0-W1', 'url': 'https://example.org/private-object.whl',
                     'sha256': 'a' * 64, 'bytes': 100, 'max_bytes': 100}]}
SCRIPT = Path(c0.__file__)


def invoke(args, data=b''):
    stdout, stderr = io.StringIO(), io.StringIO()
    with patch.object(sys, 'argv', [str(SCRIPT), *map(str, args)]), \
            patch.object(sys, 'stdin', SimpleNamespace(buffer=io.BytesIO(data))), \
            redirect_stdout(stdout), redirect_stderr(stderr):
        try:
            code = c0.main()
        except SystemExit as exc:
            code = exc.code
    return code, stdout.getvalue(), stderr.getvalue()


class SummaryTests(unittest.TestCase):
    def assert_safety(self, output):
        for marker in ('NO_AUTHORIZATION', 'C0_COLLECT_HOLD', 'NO_NETWORK'):
            self.assertIn(marker, output)
        for gap, _ in c0.EVIDENCE_GAPS:
            self.assertIn(f'{gap}: UNVERIFIED', output)
        self.assertIn('does not authorize collection or execution', output)
        for private in ('https://', 'private-object', 'a' * 64, '\x1b'):
            self.assertNotIn(private, output)

    def test_single_summary_and_json_remain_distinct(self):
        data = json.dumps(BASE).encode()
        code, output, error = invoke(['--stdin', '--summary'], data)
        self.assertEqual(code, 0, error)
        self.assertTrue(output.startswith('C0 offline review: STRUCTURE_ONLY_PASS\n'))
        self.assertIn('Input: STRUCTURE_ONLY_PASS; records observed=1, passed=1, refused=0', output)
        self.assert_safety(output)
        code, raw, error = invoke(['--stdin', '--json'], data)
        self.assertEqual(code, 0, error)
        self.assertEqual(json.loads(raw), c0.inspect_manifest(self.write_manifest(data)))
        self.assertNotIn('C0 offline review', raw)

    def write_manifest(self, data):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        path = Path(temporary.name) / 'input.json'
        path.write_bytes(data)
        return path

    def test_all_existing_modes_summary_same_exit_as_legacy(self):
        data = json.dumps(BASE).encode()
        with tempfile.TemporaryDirectory() as root:
            before, after = Path(root) / 'before', Path(root) / 'after'
            before.mkdir()
            after.mkdir()
            one, two = before / 'one.json', after / 'two.json'
            one.write_bytes(data)
            two.write_bytes(data)
            modes = [([one], b''), (['--batch', one], b''),
                     (['--directory', before, '--require-json-only'], b''),
                     (['--stdin'], data), (['--stdin-batch'], data),
                     (['--compare-directories', before, after], b''),
                     (['--compare-stdin-to-directory', before], data),
                     (['--compare-stdin-before-directory', after], data),
                     (['--compare-stdin-batches'], data + b'\n---\n' + data)]
            for args, incoming in modes:
                with self.subTest(args=args):
                    legacy = invoke(args, incoming)
                    result = invoke([*args, '--summary'], incoming)
                    self.assertEqual(result[0], legacy[0], result[2])
                    self.assertEqual(result[2], '')
                    self.assert_safety(result[1])
                    self.assertNotIn(root, result[1])
                    self.assertEqual(result, invoke([*args, '--summary'], incoming))
            code, output, _ = invoke(['--compare-directories', before, after, '--summary'], b'')
            self.assertEqual(code, 0)
            self.assertIn('Observed file changes: added=1, removed=1, changed=0, regressions=0', output)
            self.assertIn('Object changes: none', output)

    def test_semantic_delta_and_change_gate(self):
        new = copy.deepcopy(BASE)
        new['objects'][0].update(url='https://example.org/new.whl', sha256='b' * 64,
                                 bytes=90, max_bytes=120)
        data = json.dumps(BASE).encode() + b'\n---\n' + json.dumps(new).encode()
        for gate, expected in (([], 0), (['--fail-on-change'], 3)):
            code, output, error = invoke(['--compare-stdin-batches', '--summary', *gate], data)
            self.assertEqual(code, expected, error)
            self.assertIn('C0 offline review: CHANGED', output)
            self.assertIn('Changed C0-W1: bytes, max_bytes, sha256, url', output)
            self.assert_safety(output)
        new['objects'][0]['id'] = 'C0-P1'
        data = json.dumps(BASE).encode() + b'\n---\n' + json.dumps(new).encode()
        code, output, error = invoke(['--compare-stdin-batches', '--summary'], data)
        self.assertEqual(code, 0, error)
        self.assertIn('Added: C0-P1', output)
        self.assertIn('Removed: C0-W1', output)

    def test_refusal_suppresses_partial_semantic_changes(self):
        data = json.dumps(BASE).encode()
        for incoming in (data + b'\n---\n{', b'{\n---\n' + data, data,
                         data + b'\n---\n' + data + b'\n' + data):
            with self.subTest(incoming=incoming):
                code, output, error = invoke(
                    ['--compare-stdin-batches', '--summary', '--fail-on-change'], incoming)
                self.assertEqual(code, 2, error)
                self.assertIn('C0 offline review: REFUSED', output)
                self.assertIn('Object changes: UNAVAILABLE', output)
                for delta in ('Added:', 'Removed:', 'Changed C0-'):
                    self.assertNotIn(delta, output)
                self.assert_safety(output)
        code, output, error = invoke(['--stdin', '--summary'], b'{')
        self.assertEqual(code, 2, error)
        self.assertIn('INVALID_MANIFEST', output)

    def test_refusal_categories_and_no_path_or_terminal_injection(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / 'secret-\x1b[31m\nREFUSED-pretend.json'
            path.write_text('{')
            result = subprocess.run([sys.executable, str(SCRIPT), '--directory', root,
                                     '--summary'], capture_output=True, text=True,
                                    timeout=5, check=False)
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertIn('Record 1: REFUSED; INVALID_MANIFEST', result.stdout)
            self.assertNotIn('secret-', result.stdout)
            self.assertNotIn(root, result.stdout)
            self.assert_safety(result.stdout)
            path.unlink()
            (Path(root) / 'foreign.txt').write_text('unused')
            code, output, error = invoke(['--directory', root, '--require-json-only', '--summary'])
            self.assertEqual(code, 2, error)
            self.assertIn('INPUT_AUDIT_REFUSED', output)
            self.assertIn('records observed=0', output)

    def test_invalid_format_combination_rejected_before_read(self):
        class NoRead:
            def read(self, *args):
                raise AssertionError('must refuse options before reading')
        output, error = io.StringIO(), io.StringIO()
        with patch.object(sys, 'argv', [str(SCRIPT), '--stdin', '--json', '--summary']), \
                patch.object(sys, 'stdin', SimpleNamespace(buffer=NoRead())), \
                redirect_stdout(output), redirect_stderr(error):
            with self.assertRaises(SystemExit) as caught:
                c0.main()
        self.assertEqual(caught.exception.code, 2)
        self.assertIn('--summary cannot be combined with --json', error.getvalue())
        self.assertEqual(output.getvalue(), '')

    def test_summary_preserves_fifo_and_size_refusal(self):
        with tempfile.TemporaryDirectory() as root:
            fifo = Path(root) / 'fifo.json'
            os.mkfifo(fifo)
            large = Path(root) / 'large.json'
            large.write_bytes(b' ' * 16385)
            for path in (fifo, large):
                result = subprocess.run([sys.executable, str(SCRIPT), str(path), '--summary'],
                                        capture_output=True, text=True, timeout=5, check=False)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn('INVALID_MANIFEST', result.stdout)
                self.assert_safety(result.stdout)


if __name__ == '__main__':
    unittest.main()
