"""Integrated opt-in fail-closed numeric/field CI policy for offline C0 plans."""
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
POLICY = 'som-t5b0-c0-review-policy-v1'
PLAN = 'som-t5b0-c0-review-plan-v1'
FIELDS = ['url', 'sha256', 'bytes', 'max_bytes']


class PlanPolicyTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.old = copy.deepcopy(VALID)
        self.changed = copy.deepcopy(VALID)
        self.changed['objects'][0]['sha256'] = 'b' * 64
        self.removed = copy.deepcopy(VALID)
        self.removed['objects'] = []
        self.added = copy.deepcopy(VALID)
        self.added['objects'].append({**copy.deepcopy(VALID['objects'][0]),
                                      'id': 'C0-P1', 'url': 'https://example.org/new',
                                      'sha256': 'c' * 64})
        for name, doc in [('old.json', self.old), ('changed.json', self.changed),
                          ('removed.json', self.removed), ('added.json', self.added)]:
            (self.root / name).write_text(json.dumps(doc))
        self.make_plan([('old.json', 'changed.json'),
                        ('old.json', 'old.json')])
        self.make_policy()

    def make_plan(self, pairs):
        self.write('plan.json', {'schema': PLAN, 'cases': [
            {'before': {'json_files': [before]}, 'after': {'json_files': [after]}}
            for before, after in pairs]})

    def write(self, name, value):
        p = self.root / name
        p.write_text(value if isinstance(value, str) else json.dumps(value))
        return p

    def make_policy(self, *, case_count=2, per=None, aggregate=None):
        per = per if per is not None else {'max_added': 0, 'max_removed': 0,
            'max_changed': 0, 'deny_changed_fields': []}
        aggregate = aggregate if aggregate is not None else {
            'max_changed_cases': 0, 'max_added': 0,
            'max_removed': 0, 'max_changed': 0}
        return self.write('policy.json', {'schema': POLICY,
            'case_limits': [copy.deepcopy(per) for _ in range(case_count)],
            'aggregate_limits': aggregate})

    def invoke(self, *extra):
        return subprocess.run([sys.executable, str(SCRIPT), str(self.root / 'plan.json'),
                               '--policy-file', 'policy.json', *extra],
                              input=b'PRIVATE stdin data', capture_output=True,
                              timeout=6, check=False)

    def check_private(self, data):
        out = data.decode()
        for sensitive in ('PRIVATE', str(self.root), 'old.json', 'changed.json',
                          'policy.json', 'C0-W1', 'https://', 'b' * 64, 'c' * 64):
            self.assertNotIn(sensitive, out)
        doc = json.loads(data)
        self.assertEqual(doc['schema'], 'som-t5b0-c0-review-policy-summary-v1')
        self.assertEqual(doc['authorization'], 'NO_AUTHORIZATION')
        self.assertEqual(doc['network'], 'NO_NETWORK')
        self.assertEqual(doc['collection'], 'C0_COLLECT_HOLD')
        self.assertEqual(len(doc['evidence_gaps']), 5)
        return doc

    def test_default_exact_budgets_violate_but_observation_remains_changed(self):
        p = self.invoke()
        self.assertEqual((p.returncode, p.stderr), (3, b''))
        doc = self.check_private(p.stdout)
        self.assertEqual(doc['status'], 'POLICY_VIOLATION')
        self.assertEqual(doc['review_status'], 'CHANGED')
        self.assertEqual((doc['changed_cases'], doc['unchanged_cases']), (1, 1))
        self.assertEqual(doc['policy_violation_cases'], 1)
        self.assertEqual([c['policy_status'] for c in doc['cases']], ['VIOLATION', 'PASS'])
        self.assertIn('CASE_MAX_CHANGED', doc['cases'][0]['violation_codes'])
        self.assertIn('TOTAL_MAX_CHANGED', doc['aggregate_violation_codes'])
        self.assertIn('TOTAL_MAX_CHANGED_CASES', doc['aggregate_violation_codes'])
        self.assertEqual(doc['cases'][0]['object_change_counts']['changed'], 1)
        self.assertEqual(p.stdout, self.invoke().stdout)

    def test_allowed_one_change_passes_even_though_review_detected_change(self):
        self.make_policy(per={'max_added': 0, 'max_removed': 0,
                              'max_changed': 1, 'deny_changed_fields': []},
                         aggregate={'max_changed_cases': 1, 'max_added': 0,
                                    'max_removed': 0, 'max_changed': 1})
        p = self.invoke()
        self.assertEqual((p.returncode, p.stderr), (0, b''))
        doc = self.check_private(p.stdout)
        self.assertEqual((doc['status'], doc['review_status'],
                          doc['policy_violation_cases']), ('POLICY_PASS', 'CHANGED', 0))
        self.assertEqual(doc['aggregate_violation_codes'], [])

    def test_deny_changed_fields_overrides_numeric_change_budget(self):
        self.make_policy(per={'max_added': 0, 'max_removed': 0,
                              'max_changed': 3, 'deny_changed_fields': ['sha256']},
                         aggregate={'max_changed_cases': 2, 'max_added': 3,
                                    'max_removed': 3, 'max_changed': 3})
        p = self.invoke()
        self.assertEqual((p.returncode, p.stderr), (3, b''))
        doc = self.check_private(p.stdout)
        self.assertEqual(doc['aggregate_violation_codes'], [])
        self.assertEqual(doc['cases'][0]['violation_codes'], ['CASE_DENY_SHA256'])

    def test_added_removed_and_total_budget_gates(self):
        self.make_plan([('old.json', 'added.json'), ('added.json', 'old.json')])
        p = self.invoke()
        self.assertEqual(p.returncode, 3)
        doc = self.check_private(p.stdout)
        self.assertEqual(doc['cases'][0]['object_change_counts']['added'], 1)
        self.assertEqual(doc['cases'][1]['object_change_counts']['removed'], 1)
        self.assertIn('CASE_MAX_ADDED', doc['cases'][0]['violation_codes'])
        self.assertIn('CASE_MAX_REMOVED', doc['cases'][1]['violation_codes'])
        self.assertIn('TOTAL_MAX_ADDED', doc['aggregate_violation_codes'])
        self.assertIn('TOTAL_MAX_REMOVED', doc['aggregate_violation_codes'])

    def test_no_changes_pass_with_zero_policy_limits(self):
        self.make_plan([('old.json', 'old.json'), ('old.json', 'old.json')])
        p = self.invoke()
        self.assertEqual(p.returncode, 0)
        doc = self.check_private(p.stdout)
        self.assertEqual((doc['status'], doc['review_status']), ('POLICY_PASS', 'UNCHANGED'))

    def test_any_invalid_plan_or_source_makes_entire_policy_refused(self):
        self.make_plan([('old.json', 'old.json'), ('missing.json', 'changed.json')])
        p = self.invoke()
        self.assertEqual((p.returncode, p.stderr), (2, b''))
        doc = self.check_private(p.stdout)
        self.assertEqual(doc['status'], 'REFUSED')
        self.assertEqual(doc['cases'], [])
        self.assertIsNone(doc['changed_cases'])
        self.assertIsNone(doc['policy_violation_cases'])
        self.assertIsNone(doc['review_status'])
        self.assertEqual(doc['aggregate_violation_codes'], [])

    def test_reject_invalid_policy_schema_numbers_boolean_fields_duplicates(self):
        examples = [
            {'schema': 'invalid'}, {'schema': POLICY, 'case_limits': [],
                                     'aggregate_limits': {}},
            {'schema': POLICY, 'case_limits': [{'max_added': True}],
                                     'aggregate_limits': {}},
            {'schema': POLICY, 'case_limits': [{'max_added': -1}],
                                     'aggregate_limits': {}},
            {'schema': POLICY, 'case_limits': [{'max_added': 1.0}],
                                     'aggregate_limits': {}},
        ]
        for policy in examples:
            with self.subTest(policy=policy):
                self.write('policy.json', policy)
                p = self.invoke()
                self.assertEqual((p.returncode, p.stderr), (2, b''))
                self.assertEqual(self.check_private(p.stdout)['status'], 'REFUSED')
        self.write('policy.json', '{"schema":"x","schema":"x"}')
        self.assertEqual(self.invoke().returncode, 2)
        self.write('policy.json', ' ' * 4097)
        self.assertEqual(self.invoke().returncode, 2)

    def test_policy_case_count_mismatch_refuses_before_source_read(self):
        self.make_policy(case_count=1)
        with patch.object(c0, 'inspect_manifest',
                          side_effect=AssertionError('source must not be read')):
            code, doc = runner.review_plan(self.root / 'plan.json', policy_name='policy.json')
        self.assertEqual(code, 2)
        self.assertEqual(doc['status'], 'REFUSED')
        self.assertEqual(doc['cases'], [])

    def test_deny_changed_fields_reject_unknown_duplicates_and_bad_order(self):
        for fields in (['unknown'], ['sha256', 'sha256'], ['sha256', 'url'], [123]):
            with self.subTest(fields=fields):
                self.make_policy(per={'max_added': 0, 'max_removed': 0,
                                     'max_changed': 1, 'deny_changed_fields': fields})
                result = self.invoke()
                self.assertEqual(result.returncode, 2)
                self.assertEqual(self.check_private(result.stdout)['status'], 'REFUSED')

    def test_bad_policy_path_symlinks_fifo_and_missing_refuse_bounded(self):
        for mode in ('symlink', 'fifo', 'missing', 'oversize'):
            with self.subTest(mode=mode):
                self.make_policy()
                file = self.root / 'policy.json'
                file.unlink()
                if mode == 'symlink':
                    file.symlink_to(self.root / 'old.json')
                elif mode == 'fifo':
                    os.mkfifo(file)
                elif mode == 'oversize':
                    file.write_bytes(b'x' * 4097)
                try:
                    p = self.invoke()
                    self.assertEqual((p.returncode, p.stderr), (2, b''))
                    self.assertEqual(self.check_private(p.stdout)['status'], 'REFUSED')
                finally:
                    file.unlink(missing_ok=True)
        for unsafe in ('../private.json', '/tmp/secret', 'https://secret.example', 'x/y'):
            with self.subTest(unsafe=unsafe):
                p = subprocess.run([sys.executable, str(SCRIPT), str(self.root / 'plan.json'),
                                    '--policy-file', unsafe], capture_output=True,
                                   timeout=6, check=False)
                self.assertEqual(p.returncode, 2)
                self.assertNotIn(unsafe.encode(), p.stdout + p.stderr)

    def test_policy_and_fail_on_change_are_mutually_exclusive_pre_read(self):
        p = self.invoke('--fail-on-change')
        self.assertEqual((p.returncode, p.stdout), (2, b''))
        self.assertIn(b'--policy-file', p.stderr)

    def test_legacy_plan_behavior_without_policy_unchanged(self):
        original = subprocess.run([sys.executable, str(SCRIPT), str(self.root / 'plan.json'),
                                   '--fail-on-change'], capture_output=True,
                                  check=False, timeout=6)
        self.assertEqual((original.returncode, original.stderr), (3, b''))
        legacy = json.loads(original.stdout)
        self.assertEqual(legacy['schema'], 'som-t5b0-c0-review-plan-summary-v1')
        self.assertEqual((legacy['status'], legacy['changed_cases']), ('CHANGED', 1))
        self.assertNotIn('policy_status', original.stdout.decode())


if __name__ == '__main__':
    unittest.main()
