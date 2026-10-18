"""Purely offline negative/positive structural fixtures; no network."""
import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from c0_manifest_preflight import parse_manifest, validate

BASE = {'schema': 'som-t5b0-c0-preflight-v1', 'approval': None,
        'objects': [{'id': 'C0-W1', 'url': 'https://files.pythonhosted.org/packages/sha256/immutable.whl',
                     'sha256': 'a' * 64, 'bytes': 100, 'max_bytes': 100}]}


class C0PreflightTests(unittest.TestCase):
    def test_structure_only_pass_not_approval(self):
        self.assertEqual(validate(BASE), [])

    def test_reject_duplicate_json_keys(self):
        with self.assertRaises(ValueError):
            parse_manifest('{"schema":"x","schema":"y","objects":[],"approval":null}')

    def test_untrusted_file_types_and_limits(self):
        script = Path(__file__).with_name('c0_manifest_preflight.py')
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            valid = root / 'valid.json'
            valid.write_text(json.dumps(BASE))
            oversized = root / 'oversized.json'
            oversized.write_bytes(b'x' * (16385 + 1024 * 1024))
            fifo = root / 'fifo.json'
            os.mkfifo(fifo)
            symlink = root / 'symlink.json'
            symlink.symlink_to(valid)
            deep = root / 'deep.json'
            deep.write_text('[' * 3000 + '0' + ']' * 3000)
            for path in (oversized, fifo, symlink, deep, root):
                with self.subTest(path=path):
                    result = subprocess.run([sys.executable, str(script), str(path)],
                                            capture_output=True, text=True, timeout=3, check=False)
                    self.assertEqual(result.returncode, 2, result.stderr)
                    self.assertIn('REFUSED:', result.stdout)
                    self.assertNotIn('Traceback', result.stderr)
            result = subprocess.run([sys.executable, str(script), str(valid)],
                                    capture_output=True, text=True, timeout=3, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('NO_AUTHORIZATION', result.stdout)

    def test_json_report_success_and_legacy_text(self):
        script = Path(__file__).with_name('c0_manifest_preflight.py')
        with tempfile.TemporaryDirectory() as folder:
            manifest = Path(folder) / 'valid.json'
            manifest.write_text(json.dumps(BASE))
            result = subprocess.run([sys.executable, str(script), '--json', str(manifest)],
                                    capture_output=True, text=True, timeout=3, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout), {
                'status': 'STRUCTURE_ONLY_PASS', 'errors': [], 'error_codes': [],
                'authorization': 'NO_AUTHORIZATION', 'collection': 'C0_COLLECT_HOLD',
                'network': 'NO_NETWORK',
            })
            self.assertEqual(result.stderr, '')
            legacy = subprocess.run([sys.executable, str(script), str(manifest)],
                                    capture_output=True, text=True, timeout=3, check=False)
            self.assertEqual(legacy.returncode, 0)
            self.assertEqual(legacy.stdout, 'STRUCTURE_ONLY_PASS; C0_COLLECT_HOLD; NO_NETWORK; NO_AUTHORIZATION\n')

    def test_json_report_failure_and_unreadable(self):
        script = Path(__file__).with_name('c0_manifest_preflight.py')
        with tempfile.TemporaryDirectory() as folder:
            manifest = Path(folder) / 'invalid.json'
            manifest.write_text(json.dumps({**BASE, 'approval': 'yes'}))
            for path in (manifest, Path(folder) / 'missing.json'):
                with self.subTest(path=path):
                    result = subprocess.run([sys.executable, str(script), '--json', str(path)],
                                            capture_output=True, text=True, timeout=3, check=False)
                    self.assertEqual(result.returncode, 2, result.stderr)
                    report = json.loads(result.stdout)
                    self.assertEqual(report['status'], 'REFUSED')
                    self.assertTrue(report['errors'])
                    self.assertEqual(report['authorization'], 'NO_AUTHORIZATION')
                    self.assertEqual(report['collection'], 'C0_COLLECT_HOLD')
                    self.assertEqual(report['network'], 'NO_NETWORK')
                    self.assertEqual(result.stderr, '')

    def test_json_error_codes_are_stable_and_classified(self):
        script = Path(__file__).with_name('c0_manifest_preflight.py')
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            cases = (
                ('valid', json.dumps(BASE), 0, []),
                ('structure', json.dumps({**BASE, 'approval': 'yes'}), 2, ['INVALID_STRUCTURE']),
                ('malformed', '{', 2, ['INVALID_MANIFEST']),
            )
            for name, payload, code, expected in cases:
                with self.subTest(name=name):
                    manifest = root / (name + '.json')
                    manifest.write_text(payload)
                    result = subprocess.run([sys.executable, str(script), '--json', str(manifest)],
                                            capture_output=True, text=True, timeout=3, check=False)
                    self.assertEqual(result.returncode, code, result.stderr)
                    self.assertEqual(json.loads(result.stdout)['error_codes'], expected)
            missing = subprocess.run([sys.executable, str(script), '--json', str(root / 'missing.json')],
                                     capture_output=True, text=True, timeout=3, check=False)
            self.assertEqual(missing.returncode, 2)
            self.assertEqual(json.loads(missing.stdout)['error_codes'], ['INVALID_MANIFEST'])

    def test_batch_reports_all_files_and_aggregate_refusal(self):
        script = Path(__file__).with_name('c0_manifest_preflight.py')
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            good1, bad, good2 = (root / name for name in ('good1.json', 'bad.json', 'good2.json'))
            good1.write_text(json.dumps(BASE))
            bad.write_text(json.dumps({**BASE, 'approval': 'yes'}))
            good2.write_text(json.dumps(BASE))
            result = subprocess.run([sys.executable, str(script), '--batch', str(good1), str(bad), str(good2)],
                                    capture_output=True, text=True, timeout=3, check=False)
            self.assertEqual(result.returncode, 2, result.stderr)
            report = json.loads(result.stdout)
            self.assertEqual(report['status'], 'REFUSED')
            self.assertEqual(report['authorization'], 'NO_AUTHORIZATION')
            self.assertEqual(report['collection'], 'C0_COLLECT_HOLD')
            self.assertEqual(report['network'], 'NO_NETWORK')
            self.assertEqual([item['path'] for item in report['results']], [str(good1), str(bad), str(good2)])
            self.assertEqual([item['status'] for item in report['results']],
                             ['STRUCTURE_ONLY_PASS', 'REFUSED', 'STRUCTURE_ONLY_PASS'])
            self.assertEqual([item['error_codes'] for item in report['results']],
                             [[], ['INVALID_STRUCTURE'], []])
            self.assertTrue(all(item['authorization'] == 'NO_AUTHORIZATION' and
                                item['collection'] == 'C0_COLLECT_HOLD' and
                                item['network'] == 'NO_NETWORK' for item in report['results']))
            self.assertEqual(result.stderr, '')
            success = subprocess.run([sys.executable, str(script), '--batch', str(good1), str(good2)],
                                     capture_output=True, text=True, timeout=3, check=False)
            self.assertEqual(success.returncode, 0, success.stderr)
            self.assertEqual(json.loads(success.stdout)['status'], 'STRUCTURE_ONLY_PASS')

    def test_batch_bounds_and_unreadable_fail_closed(self):
        script = Path(__file__).with_name('c0_manifest_preflight.py')
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            valid = root / 'valid.json'
            valid.write_text(json.dumps(BASE))
            missing = root / 'missing.json'
            result = subprocess.run([sys.executable, str(script), '--batch', str(valid), str(missing)],
                                    capture_output=True, text=True, timeout=3, check=False)
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertEqual(json.loads(result.stdout)['results'][1]['error_codes'], ['INVALID_MANIFEST'])
            oversized = subprocess.run([sys.executable, str(script), '--batch', *([str(valid)] * 17)],
                                       capture_output=True, text=True, timeout=3, check=False)
            self.assertEqual(oversized.returncode, 2, oversized.stderr)
            self.assertEqual(json.loads(oversized.stdout)['status'], 'REFUSED')
            self.assertEqual(json.loads(oversized.stdout)['results'], [])

    def test_fail_closed(self):
        for key, value in [('url', 'http://example.org/object'), ('url', 'https://example.org/x?latest=1'),
                           ('url', 'https://evil@host/path'), ('url', 'https://host/../path'),
                           ('url', 'https://host/'), ('url', 'https://host/%2e%2e/secret'),
                           ('url', 'https://host/a%2fb'), ('url', 'https://host/a//b'),
                           ('url', 'https://host/a/./b'), ('url', 'https://host/a\\b'),
                           ('url', 'https://host/%252e%252e/b'),
                           ('url', 'https://host:443/path'),
                           ('url', 'https://host:invalid/path'),
                           ('url', 'https://host/%E2%80%AE/path'), ('sha256', 'invalid'), ('bytes', True),
                           ('max_bytes', 0), ('id', 'C0-OTHER')]:
            with self.subTest(key=key, value=value):
                case = copy.deepcopy(BASE)
                case['objects'][0][key] = value
                self.assertTrue(validate(case))
        for change in ('duplicate', 'approval', 'extra', 'empty'):
            with self.subTest(change=change):
                case = copy.deepcopy(BASE)
                if change == 'duplicate':
                    case['objects'].append(case['objects'][0])
                elif change == 'approval':
                    case['approval'] = 'approved'
                elif change == 'extra':
                    case['objects'][0]['redirects'] = True
                else:
                    case['objects'] = []
                self.assertTrue(validate(case))


if __name__ == '__main__':
    unittest.main()
