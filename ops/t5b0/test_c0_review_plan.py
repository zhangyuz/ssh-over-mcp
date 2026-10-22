"""Integrated C0 multi-case local review plan: real operator positive/refusal paths."""
import copy
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from test_c0_guidance import VALID

SCRIPT = Path(__file__).with_name('c0_review_plan.py')
SCHEMA = 'som-t5b0-c0-review-plan-v1'


def side_json(*names):
    return {'json_files': list(names)}


def side_batch(name):
    return {'ndjson_file': name}


class LocalMulticasePlanTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.base = copy.deepcopy(VALID)
        self.changed = copy.deepcopy(VALID)
        self.changed['objects'][0]['sha256'] = 'b' * 64
        self.second = copy.deepcopy(VALID)
        self.second['objects'][0].update(id='C0-P1', url='https://example.org/second',
                                          sha256='c' * 64)
        for name, doc in (('base.json', self.base), ('base-copy.json', self.base),
                          ('changed.json', self.changed), ('second.json', self.second)):
            self.write(name, json.dumps(doc))
        self.write('base.ndjson', json.dumps(self.base) + '\n')
        self.write('changed.ndjson', json.dumps(self.changed) + '\n')
        self.write('two.ndjson', json.dumps(self.base) + '\n' + json.dumps(self.second) + '\n')
        self.plan([{'before': side_json('base.json'),
                    'after': side_json('base-copy.json')},
                   {'before': side_batch('base.ndjson'),
                    'after': side_json('changed.json')}])

    def write(self, name, data):
        p = self.root / name
        p.write_bytes(data if isinstance(data, bytes) else data.encode())
        return p

    def plan(self, cases):
        return self.write('plan.json', json.dumps({'schema': SCHEMA, 'cases': cases}))

    def invoke(self, *extra, plan=None):
        path = self.root / 'plan.json' if plan is None else plan
        return subprocess.run([sys.executable, str(SCRIPT), str(path), *extra],
                              input=b'{PRIVATE stdin must not be read}',
                              capture_output=True, check=False, timeout=6)

    def privacy(self, output):
        raw = output.decode()
        for secret in (str(self.root), 'base.json', 'changed.json',
                       'base.ndjson', 'C0-W1', 'C0-P1', 'https://',
                       'b' * 64, 'c' * 64, 'PRIVATE'):
            self.assertNotIn(secret, raw)
        doc = json.loads(output)
        self.assertEqual(doc['network'], 'NO_NETWORK')
        self.assertEqual(doc['authorization'], 'NO_AUTHORIZATION')
        self.assertEqual(doc['collection'], 'C0_COLLECT_HOLD')
        self.assertEqual(len(doc['evidence_gaps']), 5)
        return doc

    def test_multiple_independent_cases_changed_gate_and_private_counters(self):
        for flag, expected_code in (((), 0), (('--fail-on-change',), 3)):
            with self.subTest(flags=flag):
                run = self.invoke(*flag)
                self.assertEqual((run.returncode, run.stderr), (expected_code, b''))
                doc = self.privacy(run.stdout)
                self.assertEqual(doc['schema'], 'som-t5b0-c0-review-plan-summary-v1')
                self.assertEqual((doc['status'], doc['total_cases'], doc['changed_cases'],
                                  doc['unchanged_cases']), ('CHANGED', 2, 1, 1))
                self.assertEqual([x['status'] for x in doc['cases']],
                                 ['UNCHANGED', 'CHANGED'])
                self.assertEqual([x['index'] for x in doc['cases']], [1, 2])
                self.assertEqual(doc['cases'][0]['object_change_counts'],
                                 {'added': 0, 'removed': 0, 'changed': 0})
                self.assertEqual(doc['cases'][1]['object_change_counts']['changed'], 1)
                self.assertEqual(doc['cases'][1]['object_field_change_counts']['sha256'], 1)

    def test_unchanged_case_and_source_orientation_for_json_and_ndjson(self):
        cases = [{'before': side_json('base.json'), 'after': side_batch('base.ndjson')},
                 {'before': side_batch('base.ndjson'), 'after': side_json('base-copy.json')},
                 {'before': side_batch('base.ndjson'), 'after': side_batch('changed.ndjson')},
                 {'before': side_json('base.json'), 'after': side_json('changed.json')}]
        self.plan(cases)
        run = self.invoke('--fail-on-change')
        self.assertEqual((run.returncode, run.stderr), (3, b''))
        doc = self.privacy(run.stdout)
        self.assertEqual((doc['changed_cases'], doc['unchanged_cases']), (2, 2))
        self.assertEqual([c['status'] for c in doc['cases']],
                         ['UNCHANGED', 'UNCHANGED', 'CHANGED', 'CHANGED'])

    def test_order_independent_named_json_sets_and_cross_file_refusal(self):
        self.plan([{'before': side_json('base.json', 'second.json'),
                    'after': side_batch('two.ndjson')}])
        self.assertEqual(self.privacy(self.invoke('--fail-on-change').stdout)['status'],
                         'UNCHANGED')
        self.plan([{'before': side_json('base.json', 'base-copy.json'),
                    'after': side_batch('two.ndjson')}])
        run = self.invoke()
        self.assertEqual((run.returncode, run.stderr), (2, b''))
        self.assertEqual(self.privacy(run.stdout)['status'], 'REFUSED')

    def test_any_refused_case_blocks_all_results_and_counters(self):
        self.plan([{'before': side_json('base.json'), 'after': side_batch('base.ndjson')},
                   {'before': side_json('not-here.json'),
                    'after': side_json('base-copy.json')}])
        run = self.invoke('--fail-on-change')
        self.assertEqual((run.returncode, run.stderr), (2, b''))
        doc = self.privacy(run.stdout)
        self.assertEqual(doc['status'], 'REFUSED')
        self.assertIsNone(doc['changed_cases'])
        self.assertIsNone(doc['unchanged_cases'])
        self.assertIsNone(doc['total_cases'])
        self.assertEqual(doc['cases'], [])
        self.assertNotIn('object_change_counts', doc)

    def test_over_budget_or_invalid_plans_refuse_before_any_source_read(self):
        basic = {'before': side_json('base.json'), 'after': side_json('changed.json')}
        invalid = [[], [basic] * 9,
                   [{'before': side_json(), 'after': side_json('base.json')}],
                   [{'before': side_json(*['base.json'] * 17),
                     'after': side_json('changed.json')}],
                   [{'before': side_json('base.json'), 'after': {'json_files': [], 'ndjson_file': 'a'}}],
                   [{'before': side_json('base.json'), 'after': side_batch('a.ndjson'), 'extra': 1}],
                   [{'before': side_json('base.json'), 'after': side_json('changed.json')}] * 0]
        for cases in invalid:
            with self.subTest(size=len(cases)):
                self.plan(cases)
                run = self.invoke()
                self.assertEqual((run.returncode, run.stderr), (2, b''))
                self.assertEqual(self.privacy(run.stdout)['status'], 'REFUSED')
        self.write('plan.json', b' ' * 16385)
        self.assertEqual(self.invoke().returncode, 2)
        self.write('plan.json', b'{"schema":"x","schema":"x","cases":[]}')
        self.assertEqual(self.invoke().returncode, 2)

    def test_plan_rejects_traversal_absolute_urls_and_unsupported_filename_chars(self):
        for name in ('../private.json', '/tmp/private.json', 'x/y.json',
                     'https://secret.example', '.', '..', 'a\\b.json',
                     'secret name.json', '\u00e9.json', 'a' * 81):
            with self.subTest(name=name):
                self.plan([{'before': side_json(name), 'after': side_json('base.json')}])
                run = self.invoke()
                self.assertEqual((run.returncode, run.stderr), (2, b''))
                self.privacy(run.stdout)

    def test_symlink_fifo_nonregular_missing_and_oversize_refuse_bounded(self):
        for target_name in ('plan.json', 'base.json', 'base.ndjson'):
            for mode in ('symlink', 'fifo', 'missing', 'oversize'):
                with self.subTest(target=target_name, mode=mode):
                    self.plan([{'before': side_json('base.json'),
                                'after': side_batch('base.ndjson')}])
                    p = self.root / target_name
                    old = p.read_bytes()
                    p.unlink()
                    if mode == 'symlink':
                        p.symlink_to(self.root / 'base-copy.json')
                    elif mode == 'fifo':
                        os.mkfifo(p)
                    elif mode == 'oversize':
                        p.write_bytes(b'x' * (16385 if p.suffix == '.json' else 262161))
                    try:
                        run = self.invoke()
                        self.assertEqual((run.returncode, run.stderr), (2, b''))
                        self.assertEqual(self.privacy(run.stdout)['status'], 'REFUSED')
                    finally:
                        p.unlink(missing_ok=True)
                        p.write_bytes(old)

    def test_duplicate_referenced_files_read_once_across_cases(self):
        # The same file has one same-FD bounded snapshot for the whole plan.
        import c0_review_plan as runner
        import c0_manifest_preflight as c0
        opened = []
        original = c0.read_regular_manifest
        def recording(path, *args, **kwargs):
            opened.append(str(path))
            return original(path, *args, **kwargs)
        self.plan([{'before': side_json('base.json'), 'after': side_json('base-copy.json')}]*4)
        with patch.object(c0, 'read_regular_manifest', side_effect=recording):
            exit_code, result = runner.review_plan(self.root / 'plan.json')
        self.assertEqual(exit_code, 0)
        self.assertEqual(result['status'], 'UNCHANGED')
        self.assertEqual(opened.count('base.json'), 1)
        self.assertEqual(opened.count('base-copy.json'), 1)

    def test_invalid_schema_and_more_than_32_distinct_sources_refuse(self):
        self.write('plan.json', '{"schema":"other","cases":[]}')
        self.assertEqual(self.invoke().returncode, 2)
        # 33 unique names across 2 cases and 16+16 named sources is rejected.
        source_names = [f's{i}.json' for i in range(33)]
        self.plan([{'before': side_json(*source_names[:16]),
                    'after': side_json(*source_names[16:32])},
                   {'before': side_json(source_names[32]),
                    'after': side_json('base.json')}])
        self.assertEqual(self.privacy(self.invoke().stdout)['status'], 'REFUSED')

    def test_cli_options_and_unchanged_filesystem(self):
        prior = {p.name: p.read_bytes() for p in self.root.iterdir()}
        for flags in (('--unknown-flag',), ('--fail-on-change', '--fail-on-change')):
            with self.subTest(flags=flags):
                result = self.invoke(*flags)
                self.assertEqual(result.returncode, 2)
        self.invoke()
        after = {p.name: p.read_bytes() for p in self.root.iterdir()}
        self.assertEqual(prior, after)


if __name__ == '__main__':
    unittest.main()
