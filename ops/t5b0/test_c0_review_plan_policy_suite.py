"""Bounded read-once C0 offline plan evaluation against multiple policy profiles."""
import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import c0_manifest_preflight as c0
import c0_review_plan as runner
from test_c0_guidance import VALID

SCRIPT = Path(__file__).with_name('c0_review_plan.py')
SCHEMA = 'som-t5b0-c0-review-policy-suite-v1'
POLICY = 'som-t5b0-c0-review-policy-v1'


def limits(count, *, max_changed=0, deny=()):
    return {'case_limits': [{'max_added': 0, 'max_removed': 0,
                             'max_changed': max_changed,
                             'deny_changed_fields': list(deny)} for _ in range(count)],
            'aggregate_limits': {'max_changed_cases': count,
                                 'max_added': 0, 'max_removed': 0,
                                 'max_changed': max_changed * count}}


class SuiteTests(unittest.TestCase):
    def setUp(self):
        t = tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        self.root = Path(t.name)
        base = copy.deepcopy(VALID)
        newer = copy.deepcopy(VALID)
        newer['objects'][0]['sha256'] = 'b' * 64
        other = copy.deepcopy(VALID)
        other['objects'][0].update(id='C0-P1', sha256='c' * 64,
                                    url='https://example.org/other')
        for name, value in [('base.json', base), ('new.json', newer),
                            ('other.json', other)]:
            self.save(name, value)
        self.save('base.ndjson', json.dumps(base) + '\n')
        self.save('plan.json', {'schema': 'som-t5b0-c0-review-plan-v1',
             'cases': [{'before': {'json_files': ['base.json']},
                        'after': {'json_files': ['new.json']}},
                       {'before': {'ndjson_file': 'base.ndjson'},
                        'after': {'json_files': ['base.json']}}]})
        self.suite([limits(2, max_changed=0), limits(2, max_changed=1)])

    def save(self, name, value):
        file = self.root / name
        file.write_text(value if isinstance(value, str) else json.dumps(value))
        return file

    def suite(self, profiles):
        return self.save('suite.json', {'schema': SCHEMA, 'profiles': profiles})

    def invoke(self, *opts):
        return subprocess.run([sys.executable, str(SCRIPT), str(self.root / 'plan.json'),
                               '--policy-suite-file', 'suite.json', *opts],
                              input=b'PRIVATE NO STDIN READ', capture_output=True,
                              timeout=6, check=False)

    def private(self, result):
        doc = json.loads(result.stdout)
        raw = result.stdout.decode()
        for secret in (str(self.root), 'suite.json', 'base.json', 'new.json',
                       'base.ndjson', 'C0-W1', 'C0-P1', 'https://',
                       'b' * 64, 'c' * 64, 'PRIVATE'):
            self.assertNotIn(secret, raw)
        self.assertEqual(doc['schema'], 'som-t5b0-c0-review-policy-suite-summary-v1')
        self.assertEqual(doc['network'], 'NO_NETWORK')
        self.assertEqual(doc['authorization'], 'NO_AUTHORIZATION')
        self.assertEqual(doc['collection'], 'C0_COLLECT_HOLD')
        self.assertEqual(len(doc['evidence_gaps']), 5)
        return doc

    def test_mixed_strict_and_permissive_profiles_violate_with_full_observation(self):
        res = self.invoke()
        self.assertEqual((res.returncode, res.stderr), (3, b''))
        doc = self.private(res)
        self.assertEqual(doc['status'], 'POLICY_SUITE_VIOLATION')
        self.assertEqual(doc['review_status'], 'CHANGED')
        self.assertEqual((doc['total_cases'], doc['changed_cases'],
                          doc['unchanged_cases']), (2, 1, 1))
        self.assertEqual([p['status'] for p in doc['profiles']],
                         ['POLICY_VIOLATION', 'POLICY_PASS'])
        self.assertEqual([p['index'] for p in doc['profiles']], [1, 2])
        self.assertEqual((doc['passed_profiles'], doc['violated_profiles']), (1, 1))
        self.assertEqual(doc['cases'][0]['object_change_counts']['changed'], 1)
        self.assertEqual(doc['profiles'][0]['case_results'][0]['violation_codes'],
                         ['CASE_MAX_CHANGED'])
        self.assertEqual(doc['profiles'][1]['aggregate_violation_codes'], [])
        self.assertEqual(res.stdout, self.invoke().stdout)

    def test_all_permissive_profiles_pass_despite_observed_changed(self):
        self.suite([limits(2, max_changed=1)] * 3)
        p = self.invoke()
        self.assertEqual((p.returncode, p.stderr), (0, b''))
        doc = self.private(p)
        self.assertEqual(doc['status'], 'POLICY_SUITE_PASS')
        self.assertEqual(doc['review_status'], 'CHANGED')
        self.assertEqual((doc['passed_profiles'], doc['violated_profiles']), (3, 0))

    def test_forbidden_changed_field_is_profile_specific(self):
        self.suite([limits(2, max_changed=5, deny=['sha256']),
                    limits(2, max_changed=5)])
        p = self.invoke()
        self.assertEqual(p.returncode, 3)
        doc = self.private(p)
        self.assertEqual(doc['profiles'][0]['case_results'][0]['violation_codes'],
                         ['CASE_DENY_SHA256'])
        self.assertEqual(doc['profiles'][1]['status'], 'POLICY_PASS')

    def test_unchanged_review_passes_strict_profiles(self):
        plan = {'schema': 'som-t5b0-c0-review-plan-v1', 'cases': [
             {'before': {'json_files': ['base.json']},
              'after': {'ndjson_file': 'base.ndjson'}}]}
        self.save('plan.json', plan)
        self.suite([limits(1), limits(1)])
        p = self.invoke()
        self.assertEqual(p.returncode, 0)
        doc = self.private(p)
        self.assertEqual(doc['review_status'], 'UNCHANGED')
        self.assertEqual(doc['passed_profiles'], 2)

    def test_invalid_any_profile_refuses_all_without_partial_policy_results(self):
        for invalid in ([limits(2), {'case_limits': [], 'aggregate_limits': {}}],
                        [limits(2), limits(2, max_changed=1) | {'extra': 1}],
                        [limits(2), {'case_limits': limits(2)['case_limits'],
                                     'aggregate_limits': limits(2)['aggregate_limits']
                                     | {'max_changed': True}}],
                        [], [limits(2)] * 9):
            with self.subTest(count=len(invalid)):
                self.suite(invalid)
                p = self.invoke()
                self.assertEqual((p.returncode, p.stderr), (2, b''))
                doc = self.private(p)
                self.assertEqual(doc['status'], 'REFUSED')
                self.assertIsNone(doc['total_cases'])
                self.assertIsNone(doc['changed_cases'])
                self.assertIsNone(doc['passed_profiles'])
                self.assertEqual(doc['cases'], [])
                self.assertEqual(doc['profiles'], [])

    def test_bad_suite_refuses_before_reading_any_referenced_manifest(self):
        self.suite([limits(1)])
        with patch.object(c0, 'inspect_manifest',
                          side_effect=AssertionError('must not read a source')):
            code, doc = runner.review_plan(self.root / 'plan.json', suite_name='suite.json')
        self.assertEqual((code, doc['status']), (2, 'REFUSED'))
        self.assertEqual(doc['profiles'], [])

    def test_source_refusal_blocks_all_profiles_without_partial_results(self):
        self.save('plan.json', {'schema': 'som-t5b0-c0-review-plan-v1', 'cases': [
            {'before': {'json_files': ['base.json']},
             'after': {'json_files': ['new.json']}},
            {'before': {'json_files': ['not-found.json']},
             'after': {'json_files': ['base.json']}}]})
        p = self.invoke()
        self.assertEqual(p.returncode, 2)
        doc = self.private(p)
        self.assertEqual(doc['profiles'], [])
        self.assertEqual(doc['cases'], [])
        self.assertIsNone(doc['violated_profiles'])

    def test_suite_symlink_fifo_oversize_missing_and_duplicate_keys_refuse(self):
        for mode in ('symlink', 'fifo', 'missing', 'oversize', 'duplicates'):
            with self.subTest(mode=mode):
                self.suite([limits(2)])
                path = self.root / 'suite.json'
                path.unlink()
                if mode == 'symlink':
                    path.symlink_to(self.root / 'base.json')
                elif mode == 'fifo':
                    os.mkfifo(path)
                elif mode == 'oversize':
                    path.write_bytes(b'x' * 32769)
                elif mode == 'duplicates':
                    path.write_text('{"schema":"x","schema":"x","profiles":[]}')
                try:
                    result = self.invoke()
                    self.assertEqual(result.returncode, 2)
                    self.assertEqual(self.private(result)['status'], 'REFUSED')
                finally:
                    path.unlink(missing_ok=True)

    def test_bad_suite_filename_refuses_without_echo(self):
        for name in ('../private.json', '/tmp/secret', 'https://secret.example',
                     'sub/file.json', 'C0-W1', 'new.json', 'plan.json'):
            with self.subTest(name=name):
                p = subprocess.run([sys.executable, str(SCRIPT), str(self.root / 'plan.json'),
                                    '--policy-suite-file', name], capture_output=True,
                                   timeout=6, check=False)
                self.assertEqual(p.returncode, 2)
                self.assertNotIn(name.encode(), p.stdout + p.stderr)
                self.assertEqual(self.private(p)['status'], 'REFUSED')

    def test_conflicts_with_existing_modes_before_reading_sources(self):
        for option in ('--policy-file', '--fail-on-change'):
            with self.subTest(option=option):
                args = ['policy.json'] if option == '--policy-file' else []
                p = self.invoke(option, *args)
                self.assertEqual((p.returncode, p.stdout), (2, b''))
                self.assertIn(b'--policy-suite-file', p.stderr)

    def test_shared_sources_are_read_once_for_all_profile_decisions(self):
        opened = []
        original = c0.inspect_manifest
        def capture(name, *args, **kwargs):
            opened.append(name)
            return original(name, *args, **kwargs)
        with patch.object(c0, 'inspect_manifest', side_effect=capture):
            code, doc = runner.review_plan(self.root / 'plan.json', suite_name='suite.json')
        self.assertEqual(code, 3)
        self.assertEqual(doc['status'], 'POLICY_SUITE_VIOLATION')
        self.assertEqual(sorted(opened), ['base.json', 'new.json'])

    def test_legacy_policy_and_plan_output_modes_unchanged(self):
        original = subprocess.run([sys.executable, str(SCRIPT),
                                   str(self.root / 'plan.json'), '--fail-on-change'],
                                  capture_output=True, timeout=6)
        self.assertEqual(original.returncode, 3)
        self.assertEqual(json.loads(original.stdout)['schema'],
                         'som-t5b0-c0-review-plan-summary-v1')
        self.save('policy.json', {'schema': POLICY, **limits(2, max_changed=1)})
        selected = subprocess.run([sys.executable, str(SCRIPT),
                                   str(self.root / 'plan.json'),
                                   '--policy-file', 'policy.json'],
                                  capture_output=True, timeout=6)
        self.assertEqual(selected.returncode, 0)
        self.assertEqual(json.loads(selected.stdout)['schema'],
                         'som-t5b0-c0-review-policy-summary-v1')


if __name__ == '__main__':
    unittest.main()
