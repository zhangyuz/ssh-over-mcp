"""Purely offline negative/positive structural fixtures; no network."""
import copy
import hashlib
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from io import BytesIO
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from c0_manifest_preflight import (
    compare_directories,
    compare_stdin_to_directory,
    directory_report,
    inspect_directory,
    inspect_manifest,
    parse_manifest,
    validate,
)

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

    def test_directory_audit_deterministic_counts_and_digests(self):
        import hashlib
        script = Path(__file__).with_name('c0_manifest_preflight.py')
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'b.json').write_text(json.dumps({**BASE, 'approval': 'yes'}))
            (root / 'a.json').write_text(json.dumps(BASE))
            (root / 'ignored.txt').write_text('not a manifest')
            (root / 'nested').mkdir()
            (root / 'nested' / 'nested.json').write_text('not inspected')
            result = subprocess.run([sys.executable, str(script), '--directory', str(root)],
                                    capture_output=True, text=True, timeout=3, check=False)
            self.assertEqual(result.returncode, 2, result.stderr)
            report = json.loads(result.stdout)
            self.assertEqual((report['passed'], report['refused']), (1, 1))
            self.assertEqual(report['status'], 'REFUSED')
            self.assertEqual([Path(x['path']).name for x in report['results']], ['a.json', 'b.json'])
            for item in report['results']:
                self.assertEqual(item['sha256'], hashlib.sha256(Path(item['path']).read_bytes()).hexdigest())
                self.assertEqual((item['authorization'], item['collection'], item['network']),
                                 ('NO_AUTHORIZATION', 'C0_COLLECT_HOLD', 'NO_NETWORK'))
            self.assertEqual(result.stderr, '')

    def test_directory_empty_overflow_and_symlink_fail_closed(self):
        script = Path(__file__).with_name('c0_manifest_preflight.py')
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            def run():
                result = subprocess.run([sys.executable, str(script), '--directory', str(root)],
                                        capture_output=True, text=True, timeout=3, check=False)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertEqual(json.loads(result.stdout)['status'], 'REFUSED')
                return json.loads(result.stdout)
            self.assertEqual(run()['results'], [])
            target = root / 'target.txt'
            target.write_text('outside manifest')
            (root / 'alias.json').symlink_to(target)
            report = run()
            self.assertEqual(report['refused'], 1)
            self.assertEqual(report['results'][0]['error_codes'], ['INVALID_MANIFEST'])
            self.assertIsNone(report['results'][0]['sha256'])
            (root / 'alias.json').unlink()
            for i in range(17):
                (root / f'{i:02d}.json').write_text(json.dumps(BASE))
            self.assertEqual(run()['results'], [])

    def test_directory_total_entry_budget_ignores_small_foreign_entries_then_refuses(self):
        script = Path(__file__).with_name('c0_manifest_preflight.py')
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'valid.json').write_text(json.dumps(BASE))
            for index in range(63):
                (root / f'ignored-{index:03}.txt').write_text('ignored')
            def run(*args):
                result = subprocess.run([sys.executable, str(script), *args],
                                        capture_output=True, text=True, timeout=4, check=False)
                return result, json.loads(result.stdout)
            ok, report = run('--directory', str(root))
            self.assertEqual(ok.returncode, 0, ok.stderr)
            self.assertEqual(report['status'], 'STRUCTURE_ONLY_PASS')
            self.assertEqual((report['passed'], report['refused']), (1, 0))
            self.assertEqual([Path(x['path']).name for x in report['results']], ['valid.json'])
            (root / 'ignored-063.txt').write_text('extra')
            refused, report = run('--directory', str(root))
            self.assertEqual(refused.returncode, 2, refused.stderr)
            self.assertEqual(report['status'], 'REFUSED')
            self.assertEqual(report['errors'], ['directory must contain at most 64 total entries'])
            self.assertEqual((report['passed'], report['refused'], report['results']), (0, 0, []))
            self.assertIsNone(report['audit_sha256'])
            self.assertEqual(report['authorization'], 'NO_AUTHORIZATION')
            self.assertEqual(report['evidence']['status'], 'UNVERIFIED')
            self.assertEqual(refused.stderr, '')

    def test_compare_refuses_excess_ignored_entries_without_partial_semantic_inventory(self):
        script = Path(__file__).with_name('c0_manifest_preflight.py')
        with tempfile.TemporaryDirectory() as folder:
            before, after = (Path(folder) / name for name in ('before', 'after'))
            before.mkdir()
            after.mkdir()
            for root in (before, after):
                (root / 'valid.json').write_text(json.dumps(BASE))
            for index in range(80):
                (after / f'ignored-{index:03}.txt').write_text('ignored')
            result = subprocess.run([sys.executable, str(script), '--compare-directories',
                                     str(before), str(after), '--fail-on-change'],
                                    capture_output=True, text=True, timeout=4, check=False)
            self.assertEqual(result.returncode, 2, result.stderr)
            report = json.loads(result.stdout)
            self.assertEqual(report['status'], 'REFUSED')
            self.assertEqual(report['before']['status'], 'STRUCTURE_ONLY_PASS')
            self.assertEqual(report['after']['status'], 'REFUSED')
            self.assertEqual(report['after']['results'], [])
            self.assertIsNone(report['after']['audit_sha256'])
            self.assertEqual(report['object_diff'],
                             {'status': 'UNAVAILABLE', 'reason': 'DIRECTORY_AUDIT_REFUSED'})
            self.assertEqual(report['network'], 'NO_NETWORK')
            self.assertEqual(report['collection'], 'C0_COLLECT_HOLD')

    def test_directory_success_special_file_and_directory_symlink(self):
        script = Path(__file__).with_name('c0_manifest_preflight.py')
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / 'manifests'
            root.mkdir()
            valid = root / 'valid.json'
            valid.write_text(json.dumps(BASE))
            def run(directory):
                result = subprocess.run([sys.executable, str(script), '--directory', str(directory)],
                                        capture_output=True, text=True, timeout=3, check=False)
                return result, json.loads(result.stdout)
            result, report = run(root)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((report['passed'], report['refused']), (1, 0))
            self.assertEqual(report['status'], 'STRUCTURE_ONLY_PASS')
            self.assertEqual(report['network'], 'NO_NETWORK')
            fifo = root / 'fifo.json'
            os.mkfifo(fifo)
            result, report = run(root)
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertEqual((report['passed'], report['refused']), (1, 1))
            self.assertEqual(report['results'][0]['sha256'], None)
            self.assertEqual(report['results'][0]['error_codes'], ['INVALID_MANIFEST'])
            alias = Path(folder) / 'alias'
            alias.symlink_to(root, target_is_directory=True)
            result, report = run(alias)
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertEqual(report['results'], [])

    def test_directory_audit_cross_file_conflicts_and_evidence_handoff(self):
        script = Path(__file__).with_name('c0_manifest_preflight.py')
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            def manifest(ident, url, digest='a' * 64, size=100):
                doc = copy.deepcopy(BASE)
                doc['objects'] = [{**BASE['objects'][0], 'id': ident, 'url': url,
                                   'sha256': digest, 'bytes': size, 'max_bytes': size}]
                return doc
            (root / 'a.json').write_text(json.dumps(manifest('C0-W1', 'https://host/x')))
            (root / 'b.json').write_text(json.dumps(manifest('C0-W1', 'https://host/y')))
            (root / 'c.json').write_text(json.dumps(manifest('C0-P1', 'https://host/x', 'b' * 64, 99)))
            (root / 'd.json').write_text(json.dumps(manifest('C0-R1', 'https://host/z')))
            def run():
                result = subprocess.run([sys.executable, str(script), '--directory', str(root)],
                                        capture_output=True, text=True, timeout=3, check=False)
                return result, json.loads(result.stdout)
            result, report = run()
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertEqual((report['passed'], report['refused']), (1, 3))
            self.assertEqual([x['status'] for x in report['results']],
                             ['REFUSED', 'REFUSED', 'REFUSED', 'STRUCTURE_ONLY_PASS'])
            self.assertIn('DUPLICATE_OBJECT_ID', report['results'][0]['error_codes'])
            self.assertIn('DUPLICATE_OBJECT_ID', report['results'][1]['error_codes'])
            self.assertIn('CROSS_FILE_CONFLICT', report['results'][0]['error_codes'])
            self.assertIn('CROSS_FILE_CONFLICT', report['results'][2]['error_codes'])
            self.assertEqual(report['authorization'], 'NO_AUTHORIZATION')
            self.assertEqual(report['collection'], 'C0_COLLECT_HOLD')
            self.assertEqual(report['network'], 'NO_NETWORK')
            self.assertEqual(report['evidence']['status'], 'UNVERIFIED')
            self.assertEqual({x['id'] for x in report['evidence']['gaps']},
                             {'SOURCE_AUTHENTICITY', 'TRUST_ROOT', 'TRUSTED_TIME',
                              'EXECUTION_ENVIRONMENT', 'OPERATOR_AUTHORIZATION'})
            self.assertTrue(all(x['status'] == 'UNVERIFIED' for x in report['evidence']['gaps']))
            self.assertRegex(report['audit_sha256'], r'^[0-9a-f]{64}$')
            self.assertEqual(run()[1], report)
            (root / 'd.json').write_text(json.dumps(manifest('C0-R1', 'https://host/z', 'c' * 64)))
            self.assertNotEqual(run()[1]['audit_sha256'], report['audit_sha256'])

    def test_directory_audit_duplicate_identical_object_and_bad_input(self):
        script = Path(__file__).with_name('c0_manifest_preflight.py')
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'a.json').write_text(json.dumps(BASE))
            (root / 'b.json').write_text(json.dumps(BASE))
            (root / 'c.json').write_text('{')
            result = subprocess.run([sys.executable, str(script), '--directory', str(root)],
                                    capture_output=True, text=True, timeout=3, check=False)
            self.assertEqual(result.returncode, 2, result.stderr)
            report = json.loads(result.stdout)
            self.assertEqual((report['passed'], report['refused']), (0, 3))
            self.assertEqual(report['results'][0]['error_codes'], ['DUPLICATE_OBJECT_ID'])
            self.assertEqual(report['results'][1]['error_codes'], ['DUPLICATE_OBJECT_ID'])
            self.assertEqual(report['results'][2]['error_codes'], ['INVALID_MANIFEST'])
            self.assertRegex(report['results'][2]['sha256'], r'^[0-9a-f]{64}$')
            self.assertEqual(report['evidence']['status'], 'UNVERIFIED')

    def test_directory_audit_valid_still_missing_external_evidence(self):
        script = Path(__file__).with_name('c0_manifest_preflight.py')
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'valid.json').write_text(json.dumps(BASE))
            result = subprocess.run([sys.executable, str(script), '--directory', str(root)],
                                    capture_output=True, text=True, timeout=3, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(result.stdout)
            self.assertEqual(report['status'], 'STRUCTURE_ONLY_PASS')
            self.assertEqual((report['passed'], report['refused']), (1, 0))
            self.assertEqual(report['evidence']['status'], 'UNVERIFIED')
            self.assertEqual(len(report['evidence']['gaps']), 5)
            self.assertRegex(report['audit_sha256'], r'^[0-9a-f]{64}$')
            self.assertEqual(result.stderr, '')

    def test_directory_audit_digest_size_conflict_and_unreadable_fingerprint(self):
        script = Path(__file__).with_name('c0_manifest_preflight.py')
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            first = copy.deepcopy(BASE)
            second = copy.deepcopy(BASE)
            second['objects'][0].update(id='C0-P1', url='https://host/different',
                                        bytes=99, max_bytes=99)
            (root / 'a.json').write_text(json.dumps(first))
            (root / 'b.json').write_text(json.dumps(second))
            def run():
                result = subprocess.run([sys.executable, str(script), '--directory', str(root)],
                                        capture_output=True, text=True, timeout=3, check=False)
                return result, json.loads(result.stdout)
            result, report = run()
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertEqual([x['error_codes'] for x in report['results']],
                             [['CROSS_FILE_CONFLICT'], ['CROSS_FILE_CONFLICT']])
            self.assertRegex(report['audit_sha256'], r'^[0-9a-f]{64}$')
            (root / 'b.json').unlink()
            (root / 'b.json').symlink_to(root / 'a.json')
            result, report = run()
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertEqual(report['audit_sha256'], None)
            self.assertEqual((report['passed'], report['refused']), (1, 1))
            self.assertEqual(report['results'][1]['error_codes'], ['INVALID_MANIFEST'])

    def test_review_diff_unchanged_and_changed(self):
        script = Path(__file__).with_name('c0_manifest_preflight.py')
        with tempfile.TemporaryDirectory() as folder:
            before, after = (Path(folder) / name for name in ('before', 'after'))
            before.mkdir()
            after.mkdir()
            (before / 'same.json').write_text(json.dumps(BASE))
            (after / 'same.json').write_text(json.dumps(BASE))
            def run():
                result = subprocess.run([sys.executable, str(script), '--compare-directories',
                                         str(before), str(after)], capture_output=True, text=True,
                                        timeout=4, check=False)
                return result, json.loads(result.stdout)
            result, report = run()
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(report['status'], 'UNCHANGED')
            self.assertEqual(report['added'], [])
            self.assertEqual(report['removed'], [])
            self.assertEqual(report['changed'], [])
            self.assertEqual(report['regressions'], [])
            self.assertEqual(report['before']['audit_sha256'], report['after']['audit_sha256'])
            self.assertEqual(report['evidence']['status'], 'UNVERIFIED')
            self.assertEqual((report['authorization'], report['collection'], report['network']),
                             ('NO_AUTHORIZATION', 'C0_COLLECT_HOLD', 'NO_NETWORK'))
            (after / 'same.json').write_text(json.dumps({**BASE, 'approval': 'yes'}))
            (after / 'new.json').write_text(json.dumps(BASE))
            result, report = run()
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertEqual(report['status'], 'REFUSED')
            self.assertEqual(report['changed'], ['same.json'])
            self.assertEqual(report['added'], ['new.json'])
            self.assertEqual(report['removed'], [])
            self.assertEqual(report['regressions'], ['same.json'])
            self.assertEqual(report['before']['status'], 'STRUCTURE_ONLY_PASS')
            self.assertEqual(report['after']['status'], 'REFUSED')
            self.assertNotEqual(report['before']['audit_sha256'], report['after']['audit_sha256'])

    def test_review_diff_added_removed_and_structurally_valid_change(self):
        script = Path(__file__).with_name('c0_manifest_preflight.py')
        with tempfile.TemporaryDirectory() as folder:
            before, after = (Path(folder) / name for name in ('before', 'after'))
            before.mkdir()
            after.mkdir()
            other = copy.deepcopy(BASE)
            other['objects'][0]['id'] = 'C0-P1'
            other['objects'][0]['url'] = 'https://host/other'
            (before / 'old.json').write_text(json.dumps(other))
            (before / 'common.json').write_text(json.dumps(BASE))
            changed = copy.deepcopy(BASE)
            changed['objects'][0]['sha256'] = 'b' * 64
            (after / 'common.json').write_text(json.dumps(changed))
            (after / 'new.json').write_text(json.dumps(other))
            result = subprocess.run([sys.executable, str(script), '--compare-directories',
                                     str(before), str(after)], capture_output=True, text=True,
                                    timeout=4, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(result.stdout)
            self.assertEqual(report['status'], 'CHANGED')
            self.assertEqual(report['added'], ['new.json'])
            self.assertEqual(report['removed'], ['old.json'])
            self.assertEqual(report['changed'], ['common.json'])
            self.assertEqual(report['regressions'], [])
            self.assertEqual(report['before']['status'], 'STRUCTURE_ONLY_PASS')
            self.assertEqual(report['after']['status'], 'STRUCTURE_ONLY_PASS')

    def test_review_diff_fail_closed_unreadable_or_symlink(self):
        script = Path(__file__).with_name('c0_manifest_preflight.py')
        with tempfile.TemporaryDirectory() as folder:
            before, after = (Path(folder) / name for name in ('before', 'after'))
            before.mkdir()
            after.mkdir()
            (before / 'a.json').write_text(json.dumps(BASE))
            (after / 'a.json').symlink_to(before / 'a.json')
            result = subprocess.run([sys.executable, str(script), '--compare-directories',
                                     str(before), str(after)], capture_output=True, text=True,
                                    timeout=4, check=False)
            self.assertEqual(result.returncode, 2, result.stderr)
            report = json.loads(result.stdout)
            self.assertEqual(report['status'], 'REFUSED')
            self.assertIsNone(report['after']['audit_sha256'])
            self.assertEqual(report['regressions'], ['a.json'])
            self.assertEqual(report['evidence']['status'], 'UNVERIFIED')
            self.assertEqual(result.stderr, '')
            (after / 'a.json').unlink()
            for i in range(17):
                (after / f'{i:02d}.json').write_text(json.dumps(BASE))
            result = subprocess.run([sys.executable, str(script), '--compare-directories',
                                     str(before), str(after)], capture_output=True, text=True,
                                    timeout=4, check=False)
            self.assertEqual(result.returncode, 2, result.stderr)
            report = json.loads(result.stdout)
            self.assertEqual(report['status'], 'REFUSED')
            self.assertEqual(report['after']['results'], [])
            self.assertIsNone(report['after']['audit_sha256'])

    def test_semantic_object_diff_across_filename_changes(self):
        script = Path(__file__).with_name('c0_manifest_preflight.py')
        with tempfile.TemporaryDirectory() as folder:
            before, after = (Path(folder) / name for name in ('before', 'after'))
            before.mkdir()
            after.mkdir()
            doc = copy.deepcopy(BASE)
            (before / 'old.json').write_text(json.dumps(doc))
            (after / 'renamed.json').write_text(json.dumps(doc))
            def run():
                result = subprocess.run([sys.executable, str(script), '--compare-directories',
                                         str(before), str(after)], capture_output=True, text=True,
                                        timeout=4, check=False)
                return result, json.loads(result.stdout)
            result, report = run()
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(report['status'], 'CHANGED')
            self.assertEqual(report['object_diff'], {'status': 'AVAILABLE', 'added': [],
                                                     'removed': [], 'changed': []})
            doc['objects'][0]['sha256'] = 'b' * 64
            doc['objects'][0]['bytes'] = 42
            doc['objects'][0]['max_bytes'] = 42
            (after / 'renamed.json').write_text(json.dumps(doc))
            result, report = run()
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(report['object_diff']['changed'],
                             [{'id': 'C0-W1', 'fields': ['bytes', 'max_bytes', 'sha256']}])
            self.assertNotIn('b' * 64, json.dumps(report['object_diff']))
            self.assertEqual(report['object_diff']['added'], [])
            self.assertEqual(report['object_diff']['removed'], [])

    def test_semantic_object_add_remove_and_refused_suppression(self):
        script = Path(__file__).with_name('c0_manifest_preflight.py')
        with tempfile.TemporaryDirectory() as folder:
            before, after = (Path(folder) / name for name in ('before', 'after'))
            before.mkdir()
            after.mkdir()
            first = copy.deepcopy(BASE)
            second = copy.deepcopy(BASE)
            second['objects'][0].update(id='C0-P1', url='https://host/other')
            (before / 'a.json').write_text(json.dumps(first))
            (after / 'b.json').write_text(json.dumps(second))
            def run():
                result = subprocess.run([sys.executable, str(script), '--compare-directories',
                                         str(before), str(after)], capture_output=True, text=True,
                                        timeout=4, check=False)
                return result, json.loads(result.stdout)
            result, report = run()
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(report['object_diff'], {'status': 'AVAILABLE', 'added': ['C0-P1'],
                                                     'removed': ['C0-W1'], 'changed': []})
            (after / 'b.json').write_text('{')
            result, report = run()
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertEqual(report['object_diff'], {'status': 'UNAVAILABLE',
                                                     'reason': 'DIRECTORY_AUDIT_REFUSED'})
            self.assertEqual(report['evidence']['status'], 'UNVERIFIED')

    def test_semantic_object_diff_url_only_and_cross_file_refusal(self):
        script = Path(__file__).with_name('c0_manifest_preflight.py')
        with tempfile.TemporaryDirectory() as folder:
            before, after = (Path(folder) / name for name in ('before', 'after'))
            before.mkdir()
            after.mkdir()
            doc = copy.deepcopy(BASE)
            (before / 'a.json').write_text(json.dumps(doc))
            doc['objects'][0]['url'] = 'https://host/changed'
            (after / 'a.json').write_text(json.dumps(doc))
            def run():
                result = subprocess.run([sys.executable, str(script), '--compare-directories',
                                         str(before), str(after)], capture_output=True, text=True,
                                        timeout=4, check=False)
                return result, json.loads(result.stdout)
            result, report = run()
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(report['object_diff']['changed'],
                             [{'id': 'C0-W1', 'fields': ['url']}])
            self.assertNotIn('https://host/changed', json.dumps(report['object_diff']))
            (after / 'duplicate.json').write_text(json.dumps(doc))
            result, report = run()
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertEqual(report['object_diff'], {'status': 'UNAVAILABLE',
                                                     'reason': 'DIRECTORY_AUDIT_REFUSED'})
            self.assertEqual(report['after']['refused'], 2)

    def test_compare_fail_on_change_exit_codes_and_report_compatibility(self):
        script = Path(__file__).with_name('c0_manifest_preflight.py')
        with tempfile.TemporaryDirectory() as folder:
            before, after = (Path(folder) / name for name in ('before', 'after'))
            before.mkdir()
            after.mkdir()
            (before / 'a.json').write_text(json.dumps(BASE))
            (after / 'a.json').write_text(json.dumps(BASE))
            def run(strict):
                cmd = [sys.executable, str(script), '--compare-directories', str(before), str(after)]
                if strict:
                    cmd.append('--fail-on-change')
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=4, check=False)
                return result, json.loads(result.stdout)
            regular, regular_report = run(False)
            strict, strict_report = run(True)
            self.assertEqual((regular.returncode, strict.returncode), (0, 0))
            self.assertEqual(regular_report, strict_report)
            (after / 'renamed.json').write_text((after / 'a.json').read_text())
            (after / 'a.json').unlink()
            regular, regular_report = run(False)
            strict, strict_report = run(True)
            self.assertEqual((regular.returncode, strict.returncode), (0, 3))
            self.assertEqual(regular_report, strict_report)
            self.assertEqual(strict_report['status'], 'CHANGED')
            self.assertEqual(strict_report['object_diff']['status'], 'AVAILABLE')
            self.assertEqual(strict_report['object_diff']['changed'], [])
            (after / 'renamed.json').write_text('{')
            regular, regular_report = run(False)
            strict, strict_report = run(True)
            self.assertEqual((regular.returncode, strict.returncode), (2, 2))
            self.assertEqual(regular_report, strict_report)
            self.assertEqual(strict_report['status'], 'REFUSED')
            self.assertEqual(strict_report['object_diff']['status'], 'UNAVAILABLE')

    def test_fail_on_change_rejects_other_input_modes(self):
        script = Path(__file__).with_name('c0_manifest_preflight.py')
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            manifest = root / 'a.json'
            manifest.write_text(json.dumps(BASE))
            for args in ([str(manifest)], ['--json', str(manifest)],
                         ['--directory', str(root)], ['--batch', str(manifest)], []):
                with self.subTest(args=args):
                    result = subprocess.run([sys.executable, str(script), '--fail-on-change', *args],
                                            capture_output=True, text=True, timeout=4, check=False)
                    self.assertEqual(result.returncode, 2)
                    self.assertIn('--fail-on-change requires --compare-directories', result.stderr)
                    self.assertEqual(result.stdout, '')

    def test_require_json_only_rejects_extra_entries_before_any_manifest_read(self):
        script = Path(__file__).with_name('c0_manifest_preflight.py')
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'valid.json').write_text(json.dumps(BASE))
            (root / 'note.txt').write_text('ignored by legacy mode')
            def run(strict):
                args = [sys.executable, str(script), '--directory', str(root)]
                if strict:
                    args.append('--require-json-only')
                result = subprocess.run(args, capture_output=True, text=True, timeout=4, check=False)
                return result, json.loads(result.stdout)
            legacy, report = run(False)
            self.assertEqual(legacy.returncode, 0, legacy.stderr)
            self.assertEqual(report['status'], 'STRUCTURE_ONLY_PASS')
            strict, report = run(True)
            self.assertEqual(strict.returncode, 2, strict.stderr)
            self.assertEqual(report['status'], 'REFUSED')
            self.assertEqual(report['errors'], ['directory contains non-json entry'])
            self.assertEqual((report['passed'], report['refused'], report['results']), (0, 0, []))
            self.assertIsNone(report['audit_sha256'])
            self.assertEqual(report['evidence']['status'], 'UNVERIFIED')
            self.assertEqual(report['collection'], 'C0_COLLECT_HOLD')
            self.assertEqual(strict.stderr, '')
            (root / 'note.txt').unlink()
            strict, report = run(True)
            self.assertEqual(strict.returncode, 0, strict.stderr)
            self.assertEqual(report['status'], 'STRUCTURE_ONLY_PASS')
            self.assertEqual(len(report['results']), 1)

    def test_require_json_only_compare_refuses_partial_semantics(self):
        script = Path(__file__).with_name('c0_manifest_preflight.py')
        with tempfile.TemporaryDirectory() as folder:
            before, after = (Path(folder) / x for x in ('before', 'after'))
            before.mkdir()
            after.mkdir()
            for directory in (before, after):
                (directory / 'a.json').write_text(json.dumps(BASE))
            (after / 'hidden').mkdir()
            args = [sys.executable, str(script), '--compare-directories',
                    str(before), str(after)]
            baseline = subprocess.run(args, capture_output=True, text=True, timeout=4, check=False)
            self.assertEqual(baseline.returncode, 0, baseline.stderr)
            self.assertEqual(json.loads(baseline.stdout)['status'], 'UNCHANGED')
            result = subprocess.run([*args, '--require-json-only', '--fail-on-change'],
                                    capture_output=True, text=True, timeout=4, check=False)
            self.assertEqual(result.returncode, 2, result.stderr)
            report = json.loads(result.stdout)
            self.assertEqual(report['status'], 'REFUSED')
            self.assertEqual(report['before']['status'], 'STRUCTURE_ONLY_PASS')
            self.assertEqual(report['after']['status'], 'REFUSED')
            self.assertEqual(report['object_diff'],
                             {'status': 'UNAVAILABLE', 'reason': 'DIRECTORY_AUDIT_REFUSED'})
            self.assertEqual(report['after']['results'], [])
            self.assertEqual(report['evidence']['status'], 'UNVERIFIED')

    def test_strict_default_shared_total_entry_budget_and_refusal(self):
        script = Path(__file__).with_name('c0_manifest_preflight.py')
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'a.json').write_text(json.dumps(BASE))
            for idx in range(63):
                (root / f'extra-{idx:03d}.txt').write_text('ignored by default')
            def run(*flags):
                proc = subprocess.run([sys.executable, str(script), '--directory', str(root),
                                       *flags], capture_output=True, text=True, timeout=4, check=False)
                return proc, json.loads(proc.stdout)
            default, report = run()
            self.assertEqual(default.returncode, 0, default.stderr)
            self.assertEqual(report['status'], 'STRUCTURE_ONLY_PASS')
            strict, report = run('--require-json-only')
            self.assertEqual(strict.returncode, 2, strict.stderr)
            self.assertEqual(report['results'], [])
            self.assertEqual(report['errors'], ['directory contains non-json entry'])
            (root / 'extra-063.txt').write_text('now 65 immediate entries')
            default, report = run()
            self.assertEqual(default.returncode, 2, default.stderr)
            self.assertEqual(report['errors'], ['directory must contain at most 64 total entries'])
            self.assertEqual(report['results'], [])
            self.assertIsNone(report['audit_sha256'])
            strict, report = run('--require-json-only')
            self.assertEqual(strict.returncode, 2, strict.stderr)
            self.assertEqual(report['status'], 'REFUSED')
            self.assertEqual(report['results'], [])
            self.assertIsNone(report['audit_sha256'])
            self.assertEqual(report['collection'], 'C0_COLLECT_HOLD')

    def test_compare_strict_and_default_total_budget_never_leaks_objects_on_refusal(self):
        script = Path(__file__).with_name('c0_manifest_preflight.py')
        with tempfile.TemporaryDirectory() as folder:
            before, after = (Path(folder) / name for name in ('before', 'after'))
            before.mkdir()
            after.mkdir()
            for root in (before, after):
                (root / 'a.json').write_text(json.dumps(BASE))
            for idx in range(65):
                (after / f'foreign-{idx:03d}.txt').write_text('foreign')
            for flags in ((), ('--require-json-only',)):
                with self.subTest(flags=flags):
                    proc = subprocess.run([sys.executable, str(script), '--compare-directories',
                                           str(before), str(after), '--fail-on-change', *flags],
                                          capture_output=True, text=True, timeout=4, check=False)
                    self.assertEqual(proc.returncode, 2, proc.stderr)
                    report = json.loads(proc.stdout)
                    self.assertEqual(report['status'], 'REFUSED')
                    self.assertEqual(report['before']['status'], 'STRUCTURE_ONLY_PASS')
                    self.assertEqual(report['after']['status'], 'REFUSED')
                    self.assertEqual(report['after']['results'], [])
                    self.assertIsNone(report['after']['audit_sha256'])
                    self.assertEqual(report['object_diff'],
                                     {'status': 'UNAVAILABLE', 'reason': 'DIRECTORY_AUDIT_REFUSED'})
                    self.assertEqual(report['network'], 'NO_NETWORK')

    def test_require_json_only_rejects_unrelated_modes(self):
        script = Path(__file__).with_name('c0_manifest_preflight.py')
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            manifest = root / 'a.json'
            manifest.write_text(json.dumps(BASE))
            for mode in ([], [str(manifest)], ['--json', str(manifest)],
                         ['--batch', str(manifest)]):
                with self.subTest(mode=mode):
                    result = subprocess.run([sys.executable, str(script),
                                             '--require-json-only', *mode],
                                            capture_output=True, text=True, timeout=4, check=False)
                    self.assertEqual(result.returncode, 2)
                    self.assertIn('--require-json-only requires --directory or --compare-directories',
                                  result.stderr)
                    self.assertEqual(result.stdout, '')

    def test_stdin_preflight_json_and_legacy_text_without_disk_manifest(self):
        script = Path(__file__).with_name('c0_manifest_preflight.py')
        valid = json.dumps(BASE)
        def run(data, *args):
            return subprocess.run([sys.executable, str(script), '--stdin', *args],
                                  input=data, capture_output=True, text=True,
                                  timeout=4, check=False)
        result = run(valid, '--json')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), {
            'status': 'STRUCTURE_ONLY_PASS', 'errors': [], 'error_codes': [],
            'authorization': 'NO_AUTHORIZATION', 'collection': 'C0_COLLECT_HOLD',
            'network': 'NO_NETWORK',
        })
        self.assertEqual(result.stderr, '')
        result = run(valid)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout,
                         'STRUCTURE_ONLY_PASS; C0_COLLECT_HOLD; NO_NETWORK; NO_AUTHORIZATION\n')

    def test_stdin_preflight_refuses_structure_parse_and_oversize_without_leak(self):
        script = Path(__file__).with_name('c0_manifest_preflight.py')
        for name, payload, expected in (
            ('structure', json.dumps({**BASE, 'approval': 'yes'}), 'INVALID_STRUCTURE'),
            ('malformed', '{', 'INVALID_MANIFEST'),
            ('duplicate', '{"schema":"x","schema":"x"}', 'INVALID_MANIFEST'),
            ('oversized', 'SECRET' + 'x' * 16390, 'INVALID_MANIFEST'),
            ('empty', '', 'INVALID_MANIFEST'),
        ):
            with self.subTest(name=name):
                result = subprocess.run([sys.executable, str(script), '--stdin', '--json'],
                                        input=payload, capture_output=True, text=True,
                                        timeout=4, check=False)
                self.assertEqual(result.returncode, 2, result.stderr)
                report = json.loads(result.stdout)
                self.assertEqual(report['status'], 'REFUSED')
                self.assertEqual(report['error_codes'], [expected])
                self.assertEqual(report['authorization'], 'NO_AUTHORIZATION')
                self.assertEqual(report['network'], 'NO_NETWORK')
                self.assertNotIn('SECRET', result.stdout)
                self.assertEqual(result.stderr, '')

    def test_stdin_requires_utf8_without_json_encoding_autodetection(self):
        script = Path(__file__).with_name('c0_manifest_preflight.py')
        for encoding, expected in (
            ('utf-8', 0), ('utf-8-sig', 0),
            ('utf-16', 2), ('utf-16-le', 2), ('utf-16-be', 2),
            ('utf-32', 2), ('utf-32-le', 2), ('utf-32-be', 2),
        ):
            for args in ([], ['--json']):
                with self.subTest(encoding=encoding, args=args):
                    result = subprocess.run(
                        [sys.executable, str(script), '--stdin', *args],
                        input=json.dumps(BASE).encode(encoding),
                        capture_output=True, timeout=4, check=False)
                    self.assertEqual(result.returncode, expected, result.stderr)
                    self.assertEqual(result.stderr, b'')
                    self.assertNotIn(BASE['objects'][0]['url'].encode(), result.stdout)
                    if args:
                        report = json.loads(result.stdout)
                        self.assertEqual(report['error_codes'],
                                         ['INVALID_MANIFEST'] if expected else [])
                        self.assertEqual(report['status'],
                                         'REFUSED' if expected else 'STRUCTURE_ONLY_PASS')
                        self.assertEqual(report['authorization'], 'NO_AUTHORIZATION')
                        self.assertEqual(report['collection'], 'C0_COLLECT_HOLD')
                        self.assertEqual(report['network'], 'NO_NETWORK')
                    else:
                        self.assertIn(b'REFUSED:' if expected else b'STRUCTURE_ONLY_PASS',
                                      result.stdout)

    def test_stdin_preflight_refuses_mixed_input_modes(self):
        script = Path(__file__).with_name('c0_manifest_preflight.py')
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'a.json'
            path.write_text(json.dumps(BASE))
            for args in ([str(path)], ['--batch', str(path)],
                         ['--directory', str(Path(folder))],
                         ['--compare-directories', folder, folder]):
                with self.subTest(args=args):
                    result = subprocess.run([sys.executable, str(script), '--stdin', *args],
                                            input=json.dumps(BASE), capture_output=True,
                                            text=True, timeout=4, check=False)
                    self.assertEqual(result.returncode, 2)
                    self.assertIn('--stdin cannot be combined with other input modes',
                                  result.stderr)
                    self.assertEqual(result.stdout, '')

    def test_stdin_batch_two_valid_manifests_and_stable_aggregate(self):
        script = Path(__file__).with_name('c0_manifest_preflight.py')
        other = copy.deepcopy(BASE)
        other['objects'][0].update(id='C0-P1', url='https://host/second',
                                   sha256='b' * 64, bytes=90, max_bytes=120)
        payload = (json.dumps(BASE) + '\n' + json.dumps(other) + '\n').encode()
        result = subprocess.run([sys.executable, str(script), '--stdin-batch'], input=payload,
                                capture_output=True, timeout=5, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report['status'], 'STRUCTURE_ONLY_PASS')
        self.assertEqual(report['errors'], [])
        self.assertEqual([x['path'] for x in report['results']], ['stdin:1', 'stdin:2'])
        self.assertEqual([x['status'] for x in report['results']],
                         ['STRUCTURE_ONLY_PASS', 'STRUCTURE_ONLY_PASS'])
        self.assertEqual((report['authorization'], report['collection'], report['network']),
                         ('NO_AUTHORIZATION', 'C0_COLLECT_HOLD', 'NO_NETWORK'))
        self.assertEqual(result.stderr, b'')

    def test_stdin_batch_rejects_malformed_input_and_cross_manifest_conflicts(self):
        script = Path(__file__).with_name('c0_manifest_preflight.py')
        second = copy.deepcopy(BASE)
        second['objects'][0].update(id='C0-P1', url='https://host/SECRET')
        first = copy.deepcopy(BASE)
        first['objects'][0]['url'] = 'https://host/SECRET'
        for name, content, codes in (
            ('malformed', (json.dumps(BASE) + '\n{' + '\n').encode(),
             ['INVALID_MANIFEST']),
            ('duplicate', (json.dumps(BASE) + '\n' + json.dumps(BASE)).encode(),
             ['DUPLICATE_OBJECT_ID']),
            ('conflict_url', (json.dumps(first) + '\n' + json.dumps(second)).encode(),
             ['CROSS_FILE_CONFLICT']),
        ):
            with self.subTest(case=name):
                result = subprocess.run([sys.executable, str(script), '--stdin-batch'],
                                        input=content, capture_output=True,
                                        timeout=5, check=False)
                self.assertEqual(result.returncode, 2, result.stderr)
                report = json.loads(result.stdout)
                self.assertEqual(report['status'], 'REFUSED')
                self.assertEqual(len(report['results']), 2)
                self.assertTrue(any(code in item['error_codes'] for code in codes
                                    for item in report['results']))
                self.assertNotIn(b'SECRET', result.stdout)
                self.assertEqual(report['network'], 'NO_NETWORK')

    def test_stdin_batch_total_and_line_limits_refuse_without_partial_output(self):
        script = Path(__file__).with_name('c0_manifest_preflight.py')
        for name, payload, expected in (
            ('empty', b'', 'stdin batch must contain 1 to 16 manifests'),
            ('too_many', b'{}\n' * 17, 'stdin batch must contain 1 to 16 manifests'),
            ('long_line', b'X' * 16385 + b'\n', 'stdin batch line too large'),
            ('oversized_total', b'X' * (16 * 16385 + 1), 'stdin batch exceeds total byte budget'),
        ):
            with self.subTest(case=name):
                result = subprocess.run([sys.executable, str(script), '--stdin-batch'],
                                        input=payload, capture_output=True,
                                        timeout=5, check=False)
                self.assertEqual(result.returncode, 2, result.stderr)
                report = json.loads(result.stdout)
                self.assertEqual(report['status'], 'REFUSED')
                self.assertEqual(report['errors'], [expected])
                self.assertEqual(report['results'], [])
                self.assertEqual(report['authorization'], 'NO_AUTHORIZATION')
                self.assertEqual(report['collection'], 'C0_COLLECT_HOLD')
                self.assertEqual(result.stderr, b'')

    def test_stdin_batch_requires_utf8_without_json_encoding_autodetection(self):
        script = Path(__file__).with_name('c0_manifest_preflight.py')
        for encoding, expected in (
            ('utf-8', 0), ('utf-8-sig', 0),
            ('utf-16', 2), ('utf-16-le', 2), ('utf-16-be', 2),
            ('utf-32', 2), ('utf-32-le', 2), ('utf-32-be', 2),
        ):
            with self.subTest(encoding=encoding):
                result = subprocess.run(
                    [sys.executable, str(script), '--stdin-batch'],
                    input=json.dumps(BASE).encode(encoding),
                    capture_output=True, timeout=5, check=False)
                self.assertEqual(result.returncode, expected, result.stderr)
                self.assertEqual(result.stderr, b'')
                self.assertNotIn(BASE['objects'][0]['url'].encode(), result.stdout)
                report = json.loads(result.stdout)
                self.assertEqual(report['status'],
                                 'REFUSED' if expected else 'STRUCTURE_ONLY_PASS')
                self.assertEqual(report['results'][0]['error_codes'],
                                 ['INVALID_MANIFEST'] if expected else [])
                self.assertEqual(report['authorization'], 'NO_AUTHORIZATION')
                self.assertEqual(report['collection'], 'C0_COLLECT_HOLD')
                self.assertEqual(report['network'], 'NO_NETWORK')

    def test_stdin_batch_rejects_other_input_modes_before_reading(self):
        script = Path(__file__).with_name('c0_manifest_preflight.py')
        for args in (['--stdin'], ['--batch', 'anything.json'],
                     ['--directory', 'anything'], ['--compare-directories', 'a', 'b'],
                     ['--require-json-only'], ['--fail-on-change'], ['anything.json']):
            with self.subTest(args=args):
                result = subprocess.run([sys.executable, str(script), '--stdin-batch', *args],
                                        input=b'SECRET', capture_output=True, timeout=5,
                                        check=False)
                self.assertEqual(result.returncode, 2)
                self.assertIn(b'--stdin-batch cannot be combined with other input modes',
                              result.stderr)
                self.assertEqual(result.stdout, b'')

    def test_stdin_directory_compare_unchanged_and_semantic_delta(self):
        script = Path(__file__).with_name('c0_manifest_preflight.py')
        with tempfile.TemporaryDirectory() as folder:
            before = Path(folder) / 'before'
            before.mkdir()
            (before / 'original.json').write_text(json.dumps(BASE))
            same_payload = (json.dumps(BASE, separators=(',', ':')) + '\n').encode()
            same = subprocess.run(
                [sys.executable, str(script), '--compare-stdin-to-directory', str(before)],
                input=same_payload, capture_output=True, timeout=5, check=False)
            self.assertEqual(same.returncode, 0, same.stderr)
            report = json.loads(same.stdout)
            self.assertEqual(report['status'], 'UNCHANGED')
            self.assertEqual(report['object_diff'],
                             {'status': 'AVAILABLE', 'added': [], 'removed': [], 'changed': []})
            self.assertEqual(report['before']['status'], 'STRUCTURE_ONLY_PASS')
            self.assertEqual(report['after']['results'][0]['path'], 'stdin:1')
            self.assertEqual((report['authorization'], report['collection'], report['network']),
                             ('NO_AUTHORIZATION', 'C0_COLLECT_HOLD', 'NO_NETWORK'))
            self.assertEqual(report['evidence']['status'], 'UNVERIFIED')

            changed = copy.deepcopy(BASE)
            changed['objects'][0].update(url='https://host/SECRET',
                                         sha256='b' * 64)
            delta = subprocess.run(
                [sys.executable, str(script), '--compare-stdin-to-directory',
                 str(before), '--fail-on-change'],
                input=json.dumps(changed).encode(), capture_output=True, timeout=5, check=False)
            self.assertEqual(delta.returncode, 3, delta.stderr)
            result = json.loads(delta.stdout)
            self.assertEqual(result['status'], 'CHANGED')
            self.assertEqual(result['object_diff'],
                             {'status': 'AVAILABLE', 'added': [], 'removed': [],
                              'changed': [{'id': 'C0-W1', 'fields': ['sha256', 'url']}]})
            self.assertNotIn(b'SECRET', delta.stdout)
            self.assertNotIn(b'bbbbbbbb', delta.stdout)

            alternate = copy.deepcopy(BASE)
            alternate['objects'][0].update(id='C0-P1', url='https://host/second',
                                           sha256='c' * 64)
            replaced = subprocess.run(
                [sys.executable, str(script), '--compare-stdin-to-directory', str(before)],
                input=json.dumps(alternate).encode(), capture_output=True, timeout=5, check=False)
            self.assertEqual(replaced.returncode, 0, replaced.stderr)
            self.assertEqual(json.loads(replaced.stdout)['object_diff'],
                             {'status': 'AVAILABLE', 'added': ['C0-P1'],
                              'removed': ['C0-W1'], 'changed': []})

    def test_stdin_directory_compare_fails_closed_without_partial_semantic_inventory(self):
        script = Path(__file__).with_name('c0_manifest_preflight.py')
        with tempfile.TemporaryDirectory() as folder:
            before = Path(folder) / 'before'
            before.mkdir()
            (before / 'original.json').write_text(json.dumps(BASE))
            for label, payload in (
                ('bad_utf8', b'\xff\n'),
                ('bad_json', b'{\n'),
                ('duplicate', (json.dumps(BASE) + '\n' + json.dumps(BASE)).encode()),
                ('overflow', b'X' * (16 * 16385 + 1)),
            ):
                with self.subTest(label=label):
                    result = subprocess.run(
                        [sys.executable, str(script), '--compare-stdin-to-directory',
                         str(before), '--fail-on-change'],
                        input=payload, capture_output=True, timeout=5, check=False)
                    self.assertEqual(result.returncode, 2, result.stderr)
                    report = json.loads(result.stdout)
                    self.assertEqual(report['status'], 'REFUSED')
                    self.assertEqual(report['object_diff']['status'], 'UNAVAILABLE')
                    self.assertEqual(report['after']['status'], 'REFUSED')
                    if label == 'overflow':
                        self.assertEqual(report['after']['results'], [])
                    self.assertEqual(report['collection'], 'C0_COLLECT_HOLD')

    def test_stdin_directory_compare_baseline_resource_and_strict_mode(self):
        script = Path(__file__).with_name('c0_manifest_preflight.py')
        with tempfile.TemporaryDirectory() as folder:
            before = Path(folder) / 'before'
            before.mkdir()
            (before / 'a.json').write_text(json.dumps(BASE))
            payload = json.dumps(BASE).encode()
            stray = before / 'notes.txt'
            stray.write_text('ignored unless strict')
            base_cmd = [sys.executable, str(script), '--compare-stdin-to-directory', str(before)]
            allowed = subprocess.run(base_cmd, input=payload, capture_output=True,
                                     timeout=5, check=False)
            self.assertEqual(allowed.returncode, 0, allowed.stderr)
            strict = subprocess.run(base_cmd + ['--require-json-only'], input=payload,
                                    capture_output=True, timeout=5, check=False)
            self.assertEqual(strict.returncode, 2, strict.stderr)
            self.assertEqual(json.loads(strict.stdout)['object_diff']['status'], 'UNAVAILABLE')
            for i in range(63):
                (before / f'extra-{i}.txt').write_text('x')
            # 1 JSON plus 64 non-JSON = 65 immediate entries.
            overflow = subprocess.run(base_cmd, input=payload, capture_output=True,
                                      timeout=5, check=False)
            self.assertEqual(overflow.returncode, 2, overflow.stderr)
            self.assertEqual(json.loads(overflow.stdout)['before']['errors'],
                             ['directory must contain at most 64 total entries'])

    def test_stdin_directory_compare_rejects_conflicting_modes_before_stdin(self):
        script = Path(__file__).with_name('c0_manifest_preflight.py')
        with tempfile.TemporaryDirectory() as folder:
            before = Path(folder)
            for arguments in (
                ['--stdin'], ['--stdin-batch'], ['--batch', 'anything.json'],
                ['--directory', str(before)], ['--compare-directories', 'a', 'b'],
                ['anything.json'],
            ):
                with self.subTest(arguments=arguments):
                    result = subprocess.run(
                        [sys.executable, str(script), '--compare-stdin-to-directory',
                         str(before), *arguments],
                        input=b'SECRET', capture_output=True, timeout=5, check=False)
                    self.assertEqual(result.returncode, 2)
                    self.assertIn(b'--compare-stdin-to-directory cannot be combined',
                                  result.stderr)
                    self.assertEqual(result.stdout, b'')

    def test_stdin_directory_compare_symlink_and_conflict_are_refused(self):
        script = Path(__file__).with_name('c0_manifest_preflight.py')
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            before = root / 'before'
            before.mkdir()
            (before / 'original.json').write_text(json.dumps(BASE))
            link = root / 'untrusted_link'
            link.symlink_to(before, target_is_directory=True)
            invalid = subprocess.run(
                [sys.executable, str(script), '--compare-stdin-to-directory', str(link)],
                input=json.dumps(BASE).encode(), capture_output=True, timeout=5, check=False)
            self.assertEqual(invalid.returncode, 2, invalid.stderr)
            self.assertEqual(json.loads(invalid.stdout)['object_diff']['status'], 'UNAVAILABLE')

            one = copy.deepcopy(BASE)
            two = copy.deepcopy(BASE)
            one['objects'][0]['url'] = 'https://host/SECRET'
            two['objects'][0].update(id='C0-P1', url='https://host/SECRET',
                                     sha256='b' * 64)
            payload = (json.dumps(one) + '\n' + json.dumps(two)).encode()
            conflict = subprocess.run(
                [sys.executable, str(script), '--compare-stdin-to-directory', str(before)],
                input=payload, capture_output=True, timeout=5, check=False)
            self.assertEqual(conflict.returncode, 2, conflict.stderr)
            report = json.loads(conflict.stdout)
            self.assertEqual(report['object_diff']['status'], 'UNAVAILABLE')
            self.assertTrue(any('CROSS_FILE_CONFLICT' in row['error_codes']
                                for row in report['after']['results']))
            self.assertNotIn(b'SECRET', conflict.stdout)
            self.assertNotIn(b'bbbbbbbb', conflict.stdout)

    def test_stdin_directory_compare_redacts_baseline_conflict_values(self):
        script = Path(__file__).with_name('c0_manifest_preflight.py')
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            before = root / 'before'
            before.mkdir()
            first = copy.deepcopy(BASE)
            second = copy.deepcopy(BASE)
            second['objects'][0]['id'] = 'C0-P1'
            for name, url, digest, first_size, second_size in (
                ('url', 'https://host/SENTINEL_BASELINE_URL', 'b' * 64, 100, 100),
                ('sha', 'https://host/distinct', 'f' * 64, 100, 101),
            ):
                with self.subTest(conflict=name):
                    first['objects'][0].update(
                        url=url if name == 'url' else 'https://host/first',
                        sha256=digest,
                        bytes=first_size, max_bytes=1000)
                    second['objects'][0].update(
                        url=url, sha256=digest,
                        bytes=second_size, max_bytes=1000)
                    (before / 'one.json').write_text(json.dumps(first))
                    (before / 'two.json').write_text(json.dumps(second))
                    cmd = [sys.executable, str(script), '--compare-stdin-to-directory',
                           str(before)]
                    result = subprocess.run(cmd, input=json.dumps(BASE).encode(),
                                            capture_output=True, timeout=5, check=False)
                    self.assertEqual(result.returncode, 2, result.stderr)
                    report = json.loads(result.stdout)
                    self.assertEqual(report['status'], 'REFUSED')
                    self.assertEqual(report['object_diff']['status'], 'UNAVAILABLE')
                    self.assertEqual(report['before']['status'], 'REFUSED')
                    self.assertEqual(report['after']['status'], 'STRUCTURE_ONLY_PASS')
                    self.assertTrue(all('CROSS_FILE_CONFLICT' in item['error_codes']
                                        for item in report['before']['results']))
                    self.assertNotIn(url.encode(), result.stdout)
                    self.assertNotIn(digest.encode(), result.stdout)
                    self.assertNotIn(b'SENTINEL_BASELINE_URL', result.stdout)
                    self.assertEqual(report['collection'], 'C0_COLLECT_HOLD')
                    self.assertEqual(report['network'], 'NO_NETWORK')
                    # Directory and streamed compare now share fixed conflict diagnostics.
                    legacy = subprocess.run([sys.executable, str(script), '--directory',
                                             str(before)], capture_output=True,
                                            timeout=5, check=False)
                    self.assertEqual(legacy.returncode, 2, legacy.stderr)
                    standalone = json.loads(legacy.stdout)
                    self.assertEqual(standalone['status'], 'REFUSED')
                    self.assertTrue(all(
                        'CROSS_FILE_CONFLICT' in row['error_codes']
                        for row in standalone['results']))
                    self.assertTrue(all(
                        'conflicting cross-manifest object metadata' in row['errors']
                        for row in standalone['results']))
                    self.assertNotIn(url.encode(), legacy.stdout)
                    self.assertNotIn(digest.encode(), legacy.stdout)

    def test_stdin_directory_compare_help_mentions_both_change_modes(self):
        script = Path(__file__).with_name('c0_manifest_preflight.py')
        result = subprocess.run([sys.executable, str(script), '--help'],
                                capture_output=True, timeout=5, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(b'--compare-directories', result.stdout)
        self.assertIn(b'--compare-stdin-to-directory', result.stdout)
        change_help = result.stdout.split(b'--fail-on-change', 2)[-1]
        self.assertIn(b'--compare-stdin-to-directory', change_help.replace(b'\n                        ', b''))

    def test_regular_manifest_same_size_inplace_rewrite_refuses_before_reporting(self):
        script_obj = copy.deepcopy(BASE)
        modified = copy.deepcopy(BASE)
        modified['objects'][0]['sha256'] = 'b' * 64
        original_bytes = json.dumps(script_obj).encode()
        modified_bytes = json.dumps(modified).encode()
        self.assertEqual(len(original_bytes), len(modified_bytes))

        with tempfile.TemporaryDirectory() as folder:
            directory = Path(folder)
            manifest = directory / 'candidate.json'
            real_read = os.read
            for mode in ('single', 'directory'):
                with self.subTest(mode=mode):
                    manifest.write_bytes(original_bytes)
                    observed = os.stat(manifest)
                    mutated = False

                    def concurrent_rewrite(fd, byte_count, initial=observed):
                        nonlocal mutated
                        if not mutated:
                            mutated = True
                            with manifest.open('r+b') as writer:
                                writer.write(modified_bytes)
                                writer.flush()
                                os.fsync(writer.fileno())
                            # Force observable drift independent of filesystem clock resolution.
                            os.utime(manifest, ns=(initial.st_atime_ns,
                                                   initial.st_mtime_ns + 3_000_000_000))
                        return real_read(fd, byte_count)

                    with patch('c0_manifest_preflight.os.read', side_effect=concurrent_rewrite):
                        if mode == 'single':
                            report = inspect_manifest(manifest)
                        else:
                            report = directory_report(directory)
                    self.assertTrue(mutated)
                    self.assertEqual(report['status'], 'REFUSED')
                    self.assertEqual(report['collection'], 'C0_COLLECT_HOLD')
                    self.assertEqual(report['network'], 'NO_NETWORK')
                    error_report = report if mode == 'single' else report['results'][0]
                    self.assertEqual(error_report['error_codes'], ['INVALID_MANIFEST'])
                    self.assertNotIn(modified['objects'][0]['sha256'],
                                     json.dumps(error_report))

    def test_regular_manifest_restored_mtime_ctime_only_drift_refuses(self):
        original = json.dumps(BASE).encode()
        other = copy.deepcopy(BASE)
        other['objects'][0]['sha256'] = 'c' * 64
        replacement = json.dumps(other).encode()
        self.assertEqual(len(original), len(replacement))

        with tempfile.TemporaryDirectory() as folder:
            directory = Path(folder)
            manifest = directory / 'candidate.json'
            real_fstat, real_read = os.fstat, os.read
            for mode in ('single', 'directory'):
                with self.subTest(mode=mode):
                    manifest.write_bytes(original)
                    start = os.stat(manifest)
                    snapshots = []
                    mutations = {'rewritten': False}

                    def monitored_fstat(fd, initial=start, seen=snapshots,
                                        state=mutations):
                        current = real_fstat(fd)
                        if (current.st_dev, current.st_ino) != (initial.st_dev, initial.st_ino):
                            return current
                        # Synthetic fstat timestamp delta is deterministic on APFS/ext4.
                        # All metadata except ctime stays identical across observations.
                        result = SimpleNamespace(
                            st_dev=initial.st_dev, st_ino=initial.st_ino,
                            st_mode=initial.st_mode, st_size=initial.st_size,
                            st_mtime_ns=initial.st_mtime_ns,
                            st_ctime_ns=initial.st_ctime_ns + (
                                3_000_000_000 if state['rewritten'] else 0),
                            st_atime_ns=initial.st_atime_ns,
                        )
                        seen.append(result)
                        return result

                    def rewrite_then_read(fd, count, initial=start,
                                              state=mutations):
                        state['rewritten'] = True
                        with manifest.open('r+b') as writer:
                            writer.write(replacement)
                            writer.flush()
                            os.fsync(writer.fileno())
                        os.utime(manifest, ns=(initial.st_atime_ns, initial.st_mtime_ns))
                        self.assertEqual(os.stat(manifest).st_mtime_ns,
                                         initial.st_mtime_ns)
                        return real_read(fd, count)

                    with patch('c0_manifest_preflight.os.fstat',
                               side_effect=monitored_fstat), patch(
                                   'c0_manifest_preflight.os.read',
                                   side_effect=rewrite_then_read):
                        report = (inspect_manifest(manifest, include_digest=True,
                                                   capture_objects=True)
                                  if mode == 'single' else directory_report(directory))
                    self.assertTrue(mutations['rewritten'])
                    self.assertEqual(len(snapshots), 2)
                    initial, final = snapshots
                    self.assertEqual(
                        (initial.st_dev, initial.st_ino, initial.st_mode, initial.st_size,
                         initial.st_mtime_ns, initial.st_atime_ns),
                        (final.st_dev, final.st_ino, final.st_mode, final.st_size,
                         final.st_mtime_ns, final.st_atime_ns))
                    self.assertNotEqual(initial.st_ctime_ns, final.st_ctime_ns)
                    self.assertEqual(report['status'], 'REFUSED')
                    self.assertEqual(report['network'], 'NO_NETWORK')
                    self.assertEqual(report['collection'], 'C0_COLLECT_HOLD')
                    if mode == 'single':
                        self.assertEqual(report['error_codes'], ['INVALID_MANIFEST'])
                        self.assertIsNone(report['sha256'])
                        self.assertIsNone(report['_objects'])
                    else:
                        self.assertEqual(report['results'][0]['error_codes'],
                                         ['INVALID_MANIFEST'])
                        self.assertIsNone(report['results'][0]['sha256'])
                        self.assertEqual(report['refused'], 1)

    def test_regular_manifest_atime_only_drift_does_not_refuse(self):
        with tempfile.TemporaryDirectory() as folder:
            directory = Path(folder)
            manifest = directory / 'candidate.json'
            data = json.dumps(BASE).encode()
            manifest.write_bytes(data)
            original = os.stat(manifest)
            real_fstat = os.fstat
            for mode in ('single', 'directory'):
                with self.subTest(mode=mode):
                    snapshots = []

                    def monitored_fstat(fd, seen=snapshots):
                        current = real_fstat(fd)
                        if (current.st_dev, current.st_ino) != (original.st_dev,
                                                               original.st_ino):
                            return current
                        result = SimpleNamespace(
                            st_dev=original.st_dev, st_ino=original.st_ino,
                            st_mode=original.st_mode, st_size=original.st_size,
                            st_mtime_ns=original.st_mtime_ns,
                            st_ctime_ns=original.st_ctime_ns,
                            st_atime_ns=original.st_atime_ns + (
                                3_000_000_000 if seen else 0),
                        )
                        seen.append(result)
                        return result

                    with patch('c0_manifest_preflight.os.fstat',
                               side_effect=monitored_fstat):
                        report = (inspect_manifest(manifest, include_digest=True,
                                                   capture_objects=True)
                                  if mode == 'single' else directory_report(directory))
                    self.assertEqual(len(snapshots), 2)
                    initial, final = snapshots
                    self.assertNotEqual(initial.st_atime_ns, final.st_atime_ns)
                    self.assertEqual(
                        (initial.st_dev, initial.st_ino, initial.st_mode, initial.st_size,
                         initial.st_mtime_ns, initial.st_ctime_ns),
                        (final.st_dev, final.st_ino, final.st_mode, final.st_size,
                         final.st_mtime_ns, final.st_ctime_ns))
                    self.assertEqual(report['status'], 'STRUCTURE_ONLY_PASS')
                    self.assertEqual(report['authorization'], 'NO_AUTHORIZATION')
                    if mode == 'single':
                        self.assertEqual(report['error_codes'], [])
                        self.assertEqual(report['sha256'], hashlib.sha256(data).hexdigest())
                        self.assertEqual(report['_objects'], BASE['objects'])
                    else:
                        self.assertEqual(report['passed'], 1)
                        self.assertEqual(report['refused'], 0)

    def test_regular_manifest_unchanged_bytes_still_pass(self):
        with tempfile.TemporaryDirectory() as folder:
            directory = Path(folder)
            manifest = directory / 'candidate.json'
            manifest.write_bytes(json.dumps(BASE).encode())
            one = inspect_manifest(manifest)
            aggregate = directory_report(directory)
            self.assertEqual(one['status'], 'STRUCTURE_ONLY_PASS')
            self.assertEqual(aggregate['status'], 'STRUCTURE_ONLY_PASS')
            self.assertEqual(aggregate['passed'], 1)
            self.assertEqual(aggregate['refused'], 0)
            self.assertEqual(aggregate['authorization'], 'NO_AUTHORIZATION')


    def test_intra_manifest_conflicts_refuse_every_existing_entrypoint(self):
        script = Path(__file__).with_name('c0_manifest_preflight.py')
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            input_dir = root / 'input'
            before = root / 'before'
            input_dir.mkdir()
            before.mkdir()
            (before / 'base.json').write_text(json.dumps(BASE))
            first = copy.deepcopy(BASE['objects'][0])
            second = copy.deepcopy(first)
            second['id'] = 'C0-P1'
            cases = (
                ('duplicate_url_different_digest', {
                    **second, 'sha256': 'b' * 64}),
                ('duplicate_url_same_metadata', second),
                ('shared_sha_different_size', {
                    **second, 'url': 'https://host/second', 'bytes': 101,
                    'max_bytes': 101}),
            )
            for label, other in cases:
                with self.subTest(case=label):
                    doc = copy.deepcopy(BASE)
                    doc['objects'].append(other)
                    payload = json.dumps(doc).encode()
                    file_path = input_dir / 'proposal.json'
                    file_path.write_bytes(payload)
                    for mode, options in (
                        ('single', ['--json', str(file_path)]),
                        ('stdin', ['--stdin', '--json']),
                        ('batch', ['--batch', str(file_path)]),
                        ('stdin_batch', ['--stdin-batch']),
                        ('directory', ['--directory', str(input_dir)]),
                        ('compare', ['--compare-stdin-to-directory', str(before)]),
                        ('compare_dirs', ['--compare-directories', str(before), str(input_dir)]),
                    ):
                        with self.subTest(mode=mode):
                            result = subprocess.run(
                                [sys.executable, str(script), *options],
                                input=payload if mode in ('stdin', 'stdin_batch', 'compare') else None,
                                capture_output=True, timeout=5, check=False)
                            self.assertEqual(result.returncode, 2, (label, mode, result.stderr))
                            report = json.loads(result.stdout)
                            self.assertEqual(report['status'], 'REFUSED')
                            entry = (report['after']['results'][0] if mode in ('compare', 'compare_dirs') else
                                     report['results'][0] if mode in ('batch', 'stdin_batch', 'directory')
                                     else report)
                            self.assertIn('INVALID_STRUCTURE', entry['error_codes'])
                            self.assertEqual(report['authorization'], 'NO_AUTHORIZATION')
                            self.assertEqual(report['collection'], 'C0_COLLECT_HOLD')
                            self.assertEqual(report['network'], 'NO_NETWORK')
                            if mode in ('compare', 'compare_dirs'):
                                self.assertEqual(report['object_diff']['status'], 'UNAVAILABLE')
                            self.assertNotIn(b'https://host/second', result.stdout)
                            self.assertNotIn(b'bbbbbbbb', result.stdout)

    def test_intra_manifest_same_digest_same_size_distinct_urls_is_allowed(self):
        doc = copy.deepcopy(BASE)
        second = copy.deepcopy(doc['objects'][0])
        second['id'] = 'C0-P1'
        second['url'] = 'https://host/mirror'
        doc['objects'].append(second)
        self.assertEqual(validate(doc), [])

        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'mirror.json'
            path.write_text(json.dumps(doc))
            result = subprocess.run(
                [sys.executable, str(Path(__file__).with_name('c0_manifest_preflight.py')),
                 '--json', str(path)], capture_output=True, timeout=5, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout)['status'], 'STRUCTURE_ONLY_PASS')

    def test_directory_namespace_mutation_refuses_without_partial_report(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            before = root / 'before'
            after = root / 'after'
            before.mkdir()
            after.mkdir()
            (before / 'candidate.json').write_text(json.dumps(BASE))
            (after / 'candidate.json').write_text(json.dumps(BASE))

            for mode in ('directory', 'compare_directories', 'compare_stdin'):
                with self.subTest(mode=mode):
                    notes = before / 'added.txt'
                    notes.unlink(missing_ok=True)
                    mutation_count = 0

                    def mutate_after_read(path, *, audit_notes=notes, **kwargs):
                        nonlocal mutation_count
                        result = inspect_manifest(path, **kwargs)
                        if mutation_count == 0:
                            audit_notes.write_text('namespace changed after a valid manifest read')
                        mutation_count += 1
                        return result

                    with patch('c0_manifest_preflight.inspect_manifest',
                               side_effect=mutate_after_read):
                        if mode == 'directory':
                            result = directory_report(before, capture_inventory=True)
                        elif mode == 'compare_directories':
                            result = compare_directories(before, after)
                        else:
                            original = sys.stdin
                            try:
                                sys.stdin = SimpleNamespace(
                                    buffer=BytesIO(json.dumps(BASE).encode()))
                                result = compare_stdin_to_directory(before)
                            finally:
                                sys.stdin = original

                    self.assertEqual(mutation_count, 1 if mode == 'directory' else
                                     2 if mode == 'compare_directories' else 1)
                    self.assertEqual(result['status'], 'REFUSED')
                    audited = result if mode == 'directory' else result['before']
                    self.assertEqual(audited['errors'], ['directory changed during audit'])
                    self.assertEqual(audited['results'], [])
                    if mode == 'directory':
                        self.assertEqual(audited['_inventory'], {})
                    self.assertIsNone(audited['audit_sha256'])
                    self.assertEqual((audited['passed'], audited['refused']), (0, 0))
                    self.assertEqual(audited['authorization'], 'NO_AUTHORIZATION')
                    if mode != 'directory':
                        self.assertEqual(result['object_diff']['status'], 'UNAVAILABLE')

    def test_directory_stat_ctime_only_refuses_and_atime_only_passes(self):
        with tempfile.TemporaryDirectory() as folder:
            directory = Path(folder)
            (directory / 'candidate.json').write_text(json.dumps(BASE))
            real_fstat = os.fstat
            for field, must_refuse in (('st_ctime_ns', True), ('st_atime_ns', False)):
                with self.subTest(field=field):
                    directory_stats = 0

                    def only_one_stat_field_changes(fd, *, observed_field=field):
                        nonlocal directory_stats
                        observed = real_fstat(fd)
                        if stat.S_ISDIR(observed.st_mode):
                            directory_stats += 1
                            if directory_stats == 2:
                                keys = ('st_dev', 'st_ino', 'st_mode', 'st_size',
                                        'st_mtime_ns', 'st_ctime_ns', 'st_atime_ns')
                                data = {key: getattr(observed, key) for key in keys}
                                data[observed_field] += 1_000_000_000
                                return SimpleNamespace(**data)
                        return observed

                    with patch('c0_manifest_preflight.os.fstat',
                               side_effect=only_one_stat_field_changes):
                        report = directory_report(directory)
                    self.assertEqual(directory_stats, 2)
                    if must_refuse:
                        self.assertEqual(report['status'], 'REFUSED')
                        self.assertEqual(report['errors'], ['directory changed during audit'])
                        self.assertEqual(report['results'], [])
                        self.assertIsNone(report['audit_sha256'])
                    else:
                        self.assertEqual(report['status'], 'STRUCTURE_ONLY_PASS')
                        self.assertEqual(report['passed'], 1)
                        self.assertIsNotNone(report['audit_sha256'])

    def test_directory_conflict_diagnostics_never_echo_raw_url_or_sha(self):
        script = Path(__file__).with_name('c0_manifest_preflight.py')
        private_url = 'https://secret.example/opaque-candidate-bundle'
        private_sha = 'c' * 64
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            before = root / 'before'
            after = root / 'after'
            before.mkdir()
            after.mkdir()
            first = copy.deepcopy(BASE['objects'][0])
            first['url'] = private_url
            first['sha256'] = private_sha
            second = copy.deepcopy(first)
            second['id'] = 'C0-P1'
            for case in ('url_conflict', 'digest_size_conflict'):
                with self.subTest(case=case):
                    candidate = copy.deepcopy(second)
                    if case == 'url_conflict':
                        candidate['sha256'] = 'd' * 64
                    else:
                        candidate['url'] = 'https://other.example/different'
                        candidate['bytes'] = 101
                        candidate['max_bytes'] = 101
                    for path in (before, after):
                        (path / '1.json').write_text(json.dumps({
                            **BASE, 'objects': [first]}))
                        (path / '2.json').write_text(json.dumps({
                            **BASE, 'objects': [candidate]}))
                    for strict in (False, True):
                        flag = ['--require-json-only'] if strict else []
                        for mode, args in (
                            ('directory', ['--directory', str(before), *flag]),
                            ('two-directories', ['--compare-directories',
                                                 str(before), str(after), *flag]),
                            ('stream-successor', ['--compare-stdin-to-directory',
                                                  str(before), *flag]),
                        ):
                            with self.subTest(mode=mode, strict=strict):
                                input_bytes = (json.dumps({
                                    **BASE, 'objects': [first]}).encode() + b'\n'
                                    if mode == 'stream-successor' else None)
                                result = subprocess.run(
                                    [sys.executable, str(script), *args],
                                    input=input_bytes, capture_output=True,
                                    timeout=6, check=False)
                                self.assertEqual(result.returncode, 2, (case, args))
                                self.assertNotIn(private_url.encode(), result.stdout)
                                self.assertNotIn(private_sha.encode(), result.stdout)
                                report = json.loads(result.stdout)
                                self.assertEqual(report['status'], 'REFUSED')
                                audited = (report if mode == 'directory'
                                           else report['before'])
                                self.assertTrue(any(
                                    'CROSS_FILE_CONFLICT' in item['error_codes']
                                    for item in audited['results']))
                                if mode != 'directory':
                                    self.assertEqual(
                                        report['object_diff']['status'], 'UNAVAILABLE')
                                self.assertEqual(
                                    report['authorization'], 'NO_AUTHORIZATION')
                                self.assertEqual(report['collection'], 'C0_COLLECT_HOLD')
                                self.assertEqual(report['network'], 'NO_NETWORK')

    def test_refused_directory_never_returns_partial_internal_inventory(self):
        with tempfile.TemporaryDirectory() as folder:
            directory = Path(folder)
            first = copy.deepcopy(BASE)
            other = copy.deepcopy(BASE)
            other['objects'][0]['id'] = 'C0-P1'
            other['objects'][0]['sha256'] = 'b' * 64
            cases = (
                ('cross_file_url_conflict', first, other),
                ('duplicate_cross_file_id', first, first),
                ('invalid_second_manifest', first, None),
            )
            for name, left, right in cases:
                with self.subTest(case=name):
                    (directory / 'first.json').write_text(json.dumps(left))
                    second = ('{' if right is None else json.dumps(right))
                    (directory / 'second.json').write_text(second)
                    report = directory_report(directory, capture_inventory=True)
                    self.assertEqual(report['status'], 'REFUSED')
                    self.assertEqual(report['_inventory'], {})
                    self.assertGreaterEqual(report['refused'], 1)
                    self.assertEqual(report['authorization'], 'NO_AUTHORIZATION')
                    self.assertEqual(report['collection'], 'C0_COLLECT_HOLD')
                    self.assertEqual(report['network'], 'NO_NETWORK')
            (directory / 'second.json').unlink()
            allowed = directory_report(directory, capture_inventory=True)
            self.assertEqual(allowed['status'], 'STRUCTURE_ONLY_PASS')
            self.assertEqual(allowed['_inventory'], {'C0-W1': first['objects'][0]})
            self.assertEqual(allowed['passed'], 1)

    def test_direct_directory_inspection_redacts_cross_file_values(self):
        """Direct callers must get the same sanitized boundary as CLI wrappers."""
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            url = 'https://sensitive.example/opaque-untrusted-metadata'
            digest = 'e' * 64
            source = copy.deepcopy(BASE['objects'][0])
            source.update(url=url, sha256=digest)
            cases = {
                'url': {**source, 'id': 'C0-P1', 'sha256': 'f' * 64},
                'sha-size': {**source, 'id': 'C0-P1',
                             'url': 'https://second.example/other',
                             'bytes': 101, 'max_bytes': 101},
                'duplicate-id': {**source, 'url': 'https://second.example/other',
                                 'sha256': 'f' * 64},
            }
            for name, second in cases.items():
                with self.subTest(case=name):
                    (root / 'first.json').write_text(json.dumps({
                        **BASE, 'objects': [source]}))
                    (root / 'second.json').write_text(json.dumps({
                        **BASE, 'objects': [second]}))
                    for strict in (False, True):
                        for capture in (False, True):
                            with self.subTest(strict=strict, capture=capture):
                                observed = inspect_directory(
                                    root, capture_inventory=capture,
                                    require_json_only=strict)
                                results, errors = observed[:2]
                                self.assertEqual(errors, [])
                                self.assertTrue(all(item['status'] == 'REFUSED'
                                                    for item in results))
                                payload = json.dumps(results)
                                self.assertNotIn(url, payload)
                                self.assertNotIn(digest, payload)
                                if capture:
                                    self.assertEqual(observed[2], {})
                                for row in results:
                                    self.assertTrue(any(
                                        code in row['error_codes']
                                        for code in ('CROSS_FILE_CONFLICT',
                                                     'DUPLICATE_OBJECT_ID')))
                                    self.assertTrue(all(
                                        error in ('duplicate cross-manifest object id',
                                                  'conflicting cross-manifest object metadata')
                                        for error in row['errors']))
            (root / 'second.json').unlink()
            accepted, errors, objects = inspect_directory(
                root, capture_inventory=True)
            self.assertEqual(errors, [])
            self.assertEqual([r['status'] for r in accepted],
                             ['STRUCTURE_ONLY_PASS'])
            self.assertEqual(objects, {'C0-W1': source})

    def test_noncanonical_https_hostname_refuses_without_network(self):
        script = Path(__file__).with_name('c0_manifest_preflight.py')
        invalid_hosts = (
            'exa%6dple.org',
            'bad..example.org',
            '.example.org',
            'example.org.',
            '-bad.example.org',
            'bad-.example.org',
            'bad_host.example.org',
            'a' * 64 + '.example.org',
            'a' * 63 + '.' + 'b' * 63 + '.' + 'c' * 63 + '.' + 'd' * 63,
        )
        for host in invalid_hosts:
            with self.subTest(host=host):
                doc = copy.deepcopy(BASE)
                doc['objects'][0]['url'] = f'https://{host}/pinned.whl'
                errors = validate(doc)
                self.assertTrue(any('URL not pinned' in item for item in errors),
                                (host, errors))
                for args in (['--stdin', '--json'], ['--stdin']):
                    with self.subTest(args=args):
                        run = subprocess.run(
                            [sys.executable, str(script), *args],
                            input=json.dumps(doc).encode(), capture_output=True,
                            timeout=5, check=False)
                        self.assertEqual(run.returncode, 2, (host, args, run.stdout))
                        self.assertNotIn(b'STRUCTURE_ONLY_PASS', run.stdout)
        for host in ('example.org', 'sub1.example-foo.org',
                     'xn--bcher-kva.example', '192.0.2.1', 'host'):
            with self.subTest(accepted_host=host):
                doc = copy.deepcopy(BASE)
                doc['objects'][0]['url'] = f'https://{host}/pinned.whl'
                self.assertEqual(validate(doc), [])

    def test_noncanonical_numeric_ipv4_host_refusal(self):
        for host in ('192.0.2', '0300.0.2.1', '0xc0000201', '3221225985'):
            with self.subTest(host=host):
                candidate = copy.deepcopy(BASE)
                candidate['objects'][0]['url'] = 'https://' + host + '/candidate.whl'
                self.assertTrue(validate(candidate))
        self.assertEqual(validate(copy.deepcopy(BASE)), [])
        for host in ('192.0.2.1', '198.51.100.42', 'a.1.example'):
            candidate = copy.deepcopy(BASE)
            candidate['objects'][0]['url'] = 'https://' + host + '/candidate.whl'
            self.assertEqual(validate(candidate), [])
        candidate['objects'][0]['url'] = 'https://192.0.2/candidate.whl'
        script = Path(__file__).with_name('c0_manifest_preflight.py')
        run = subprocess.run([sys.executable, str(script), '--stdin', '--json'],
                             input=json.dumps(candidate).encode(),
                             capture_output=True, timeout=5, check=False)
        self.assertEqual(run.returncode, 2)
        self.assertEqual(json.loads(run.stdout)['status'], 'REFUSED')

    def test_numeric_dns_suffix_is_not_canonical_https_host(self):
        for host in ('example.123', 'abc.127.1', 'a.0x7f',
                     'sub.example.0001', 'foo.0x7f000001'):
            with self.subTest(rejected_host=host):
                candidate = copy.deepcopy(BASE)
                candidate['objects'][0]['url'] = 'https://' + host + '/pinned.whl'
                self.assertTrue(any('URL not pinned' in e for e in validate(candidate)))
        for host in ('192.0.2.1', 'host', 'www.example.org',
                     'a.1.example', 'xn--bcher-kva.example'):
            with self.subTest(accepted_host=host):
                candidate = copy.deepcopy(BASE)
                candidate['objects'][0]['url'] = 'https://' + host + '/pinned.whl'
                self.assertEqual(validate(candidate), [])

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
