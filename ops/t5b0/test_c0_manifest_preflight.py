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
