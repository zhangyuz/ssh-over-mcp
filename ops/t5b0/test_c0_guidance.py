"""Offline C0 operator guidance: stable, actionable, and private."""
import copy
import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import c0_manifest_preflight as c0

VALID = {'schema': 'som-t5b0-c0-preflight-v1', 'approval': None,
         'objects': [{'id': 'C0-W1', 'url': 'https://example.org/secret.wheel',
                      'sha256': 'a' * 64, 'bytes': 100, 'max_bytes': 100}]}


def run(args, stdin=b''):
    out, err = io.StringIO(), io.StringIO()
    with patch.object(sys, 'argv', [str(Path(c0.__file__)), *map(str, args)]), \
         patch.object(sys, 'stdin', SimpleNamespace(buffer=io.BytesIO(stdin))), \
         redirect_stdout(out), redirect_stderr(err):
        try:
            code = c0.main()
        except SystemExit as exc:
            code = exc.code
    return code, out.getvalue(), err.getvalue()


class GuidanceTests(unittest.TestCase):
    def test_valid_summary_has_non_authorizing_next_action(self):
        payload = json.dumps(VALID).encode()
        baseline = run(['--stdin', '--summary'], payload)
        result = run(['--stdin', '--summary', '--guidance'], payload)
        self.assertEqual((baseline[0], baseline[2]), (result[0], result[2]))
        self.assertTrue(result[1].startswith(baseline[1]))
        self.assertIn('Next actions:', result[1])
        self.assertIn('independent source', result[1])
        self.assertIn('OPERATOR_AUTHORIZATION: UNVERIFIED', result[1])
        self.assertNotIn('secret.wheel', result[1])

    def test_invalid_manifest_and_invalid_structure_have_distinct_guidance(self):
        invalid = run(['--stdin', '--summary', '--guidance'], b'{')
        structure = copy.deepcopy(VALID)
        structure['approval'] = 'approved'
        schema = run(['--stdin', '--summary', '--guidance'], json.dumps(structure).encode())
        self.assertEqual((invalid[0], schema[0]), (2, 2))
        self.assertIn('INVALID_MANIFEST', invalid[1])
        self.assertIn('regular file or bounded UTF-8 JSON', invalid[1])
        self.assertIn('INVALID_STRUCTURE', schema[1])
        self.assertIn('C0 schema', schema[1])
        self.assertNotIn('ready to collect', invalid[1] + schema[1])

    def test_all_nine_modes_and_change_exit_are_preserved(self):
        data = json.dumps(VALID).encode()
        modified = copy.deepcopy(VALID)
        modified['objects'][0]['max_bytes'] = 200
        newer = json.dumps(modified).encode()
        with tempfile.TemporaryDirectory() as root:
            before, after = Path(root) / 'before', Path(root) / 'after'
            before.mkdir()
            after.mkdir()
            b, a = before / 'private.json', after / 'private.json'
            b.write_bytes(data)
            a.write_bytes(newer)
            modes = [( [b], b''), (['--batch', b], b''),
                     (['--directory', before], b''), (['--stdin'], data),
                     (['--stdin-batch'], data),
                     (['--compare-directories', before, after, '--fail-on-change'], b''),
                     (['--compare-stdin-to-directory', before, '--fail-on-change'], newer),
                     (['--compare-stdin-before-directory', after, '--fail-on-change'], data),
                     (['--compare-stdin-batches', '--fail-on-change'],
                      data + b'\n---\n' + newer)]
            for args, incoming in modes:
                with self.subTest(args=args):
                    normal = run([*args, '--summary'], incoming)
                    result = run([*args, '--summary', '--guidance'], incoming)
                    self.assertEqual(result[0], normal[0])
                    self.assertEqual(result[2], normal[2])
                    self.assertEqual(result, run([*args, '--summary', '--guidance'], incoming))
                    self.assertIn('Next actions:', result[1])
                    self.assertIn('NO_AUTHORIZATION', result[1])
                    for secret in ('secret.wheel', root, 'https://', 'a' * 64, '\x1b'):
                        self.assertNotIn(secret, result[1])
                    if result[0] == 3:
                        self.assertIn('Review observed changes', result[1])

    def test_refused_pair_has_no_change_guidance_or_inventory(self):
        data = json.dumps(VALID).encode()
        refused = run(['--compare-stdin-batches', '--fail-on-change', '--summary',
                       '--guidance'], data + b'\n---\n{')
        self.assertEqual(refused[0], 2)
        self.assertIn('Object changes: UNAVAILABLE', refused[1])
        self.assertIn('Next actions:', refused[1])
        self.assertNotIn('Review observed changes', refused[1])

    def test_fixed_categories_only_and_audit_fallback(self):
        base = {'status': 'REFUSED', 'results': [
            {'status': 'REFUSED', 'error_codes': ['DUPLICATE_OBJECT_ID', 'CROSS_FILE_CONFLICT',
                                                'UNTRUSTED_EXTERNAL_VALUE\x1b[31m']}],
            'errors': ['sensitive https://example.org/private']}
        guidance = c0.render_guidance(base)
        self.assertIn('DUPLICATE_OBJECT_ID', guidance)
        self.assertIn('CROSS_FILE_CONFLICT', guidance)
        self.assertIn('INPUT_AUDIT_REFUSED', guidance)
        self.assertNotIn('UNTRUSTED_EXTERNAL_VALUE', guidance)
        self.assertNotIn('https://', guidance)
        self.assertNotIn('\x1b', guidance)

    def test_aggregate_refusal_cannot_be_interpreted_as_success(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / 'unexpected.txt'
            path.write_text('not a manifest')
            result = run(['--directory', root, '--require-json-only',
                          '--summary', '--guidance'])
            self.assertEqual(result[0], 2)
            self.assertIn('INPUT_AUDIT_REFUSED', result[1])
            self.assertIn('Review local input bounds', result[1])
            self.assertNotIn('independent source', result[1].split('Next actions:')[1])

    def test_pass_and_unchanged_guidance_have_distinct_claims(self):
        passed = c0.render_guidance({'status': 'STRUCTURE_ONLY_PASS'})
        unchanged = c0.render_guidance({'status': 'UNCHANGED'})
        self.assertIn('Input passed structural checks only', passed)
        self.assertNotIn('No compared changes', passed)
        self.assertIn('No compared changes were observed', unchanged)
        for output in (passed, unchanged):
            self.assertIn('independent source', output)
            self.assertIn('Do not collect', output)

    def test_unknown_status_refuses_to_suggest_success(self):
        output = c0.render_guidance({'status': 'UNEXPECTED'})
        self.assertIn('Unrecognized review status', output)
        self.assertNotIn('No structural changes or errors', output)
        self.assertIn('Do not collect', output)

    def test_machine_summary_all_modes_and_privacy(self):
        payload = json.dumps(VALID).encode()
        with tempfile.TemporaryDirectory() as root:
            before = Path(root) / 'before'
            after = Path(root) / 'after'
            before.mkdir()
            after.mkdir()
            (before / 'secret.json').write_bytes(payload)
            (after / 'secret.json').write_bytes(payload)
            modes = [([before / 'secret.json'], b''), (['--batch', before / 'secret.json'], b''),
                     (['--directory', before], b''), (['--stdin'], payload),
                     (['--stdin-batch'], payload),
                     (['--compare-directories', before, after], b''),
                     (['--compare-stdin-to-directory', before], payload),
                     (['--compare-stdin-before-directory', after], payload),
                     (['--compare-stdin-batches'], payload + b'\n---\n' + payload)]
            for args, data in modes:
                with self.subTest(args=args):
                    code, output, stderr = run([*args, '--summary-json'], data)
                    self.assertEqual((code, stderr), (0, ''))
                    report = json.loads(output)
                    self.assertEqual(report['authorization'], 'NO_AUTHORIZATION')
                    self.assertEqual(report['network'], 'NO_NETWORK')
                    self.assertEqual(len(report['evidence_gaps']), 5)
                    self.assertIn(report['status'], ('STRUCTURE_ONLY_PASS', 'UNCHANGED'))
                    for secret in (root, 'secret.json', 'secret.wheel', 'https://', 'a' * 64):
                        self.assertNotIn(secret, output)

    def test_machine_summary_refusal_and_conflicts(self):
        code, output, _ = run(['--stdin', '--summary-json'], b'{')
        self.assertEqual(code, 2)
        report = json.loads(output)
        self.assertEqual(report['status'], 'REFUSED')
        self.assertEqual(report['input']['refused'], 1)
        self.assertEqual(report['input']['error_codes'], ['INVALID_MANIFEST'])
        for args in (['--stdin', '--summary-json', '--json'],
                     ['--stdin', '--summary-json', '--summary'],
                     ['--stdin', '--summary-json', '--guidance']):
            with self.subTest(args=args):
                code, _, stderr = run(args, b'{')
                self.assertEqual(code, 2)
                self.assertIn('not allowed', stderr)

    def test_format_conflicts_reject_before_input(self):
        class NeverRead:
            def read(self, *args):
                raise AssertionError('CLI flags must fail before reading stdin')
        for args in (['--stdin', '--guidance'], ['--stdin', '--json', '--guidance'],
                     ['--stdin', '--summary', '--json', '--guidance']):
            with self.subTest(args=args):
                out, err = io.StringIO(), io.StringIO()
                with patch.object(sys, 'argv', [str(c0.__file__), *args]), \
                     patch.object(sys, 'stdin', SimpleNamespace(buffer=NeverRead())), \
                     redirect_stdout(out), redirect_stderr(err), \
                     self.assertRaises(SystemExit) as caught:
                    c0.main()
                self.assertEqual(caught.exception.code, 2)
                self.assertEqual(out.getvalue(), '')
                self.assertTrue(err.getvalue())


if __name__ == '__main__':
    unittest.main()
