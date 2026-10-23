"""Complete offline before×after C0 matrix: bounded and private operator results."""
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
from test_c0_guidance import VALID

SCRIPT = Path(__file__).with_name('c0_review_matrix.py')
CONFIG = 'som-t5b0-c0-review-matrix-v1'
REPORT = 'som-t5b0-c0-review-matrix-summary-v1'


def files(*names):
    return {'json_files': list(names)}


def ndjson(name):
    return {'ndjson_file': name}


class OfflineMatrixTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        old = copy.deepcopy(VALID)
        newer = copy.deepcopy(VALID)
        newer['objects'][0]['sha256'] = 'b' * 64
        extra = copy.deepcopy(VALID)
        extra['objects'][0].update(id='C0-P1', url='https://hidden.example/one',
                                   sha256='c' * 64)
        self.put('old.json', json.dumps(old))
        self.put('old-copy.json', json.dumps(old))
        self.put('new.json', json.dumps(newer))
        self.put('extra.json', json.dumps(extra))
        self.put('old.ndjson', json.dumps(old) + '\n')
        self.put('new.ndjson', json.dumps(newer) + '\n')
        self.put('two.ndjson', json.dumps(old) + '\n' + json.dumps(extra) + '\n')
        self.matrix([files('old.json'), ndjson('old.ndjson')],
                    [files('old-copy.json'), files('new.json')])

    def put(self, name, value):
        target = self.root / name
        target.write_bytes(value if isinstance(value, bytes) else value.encode())
        return target

    def matrix(self, before, after):
        return self.put('matrix.json', json.dumps({'schema': CONFIG,
                                                    'before': before, 'after': after}))

    def invoke(self, *args, config=None):
        path = self.root / 'matrix.json' if config is None else config
        return subprocess.run([sys.executable, str(SCRIPT), str(path), *args],
                              input=b'PRIVATE STDIN', capture_output=True,
                              check=False, timeout=6)

    def check_private(self, result):
        text = result.stdout.decode()
        for secret in (str(self.root), 'old.json', 'new.json', 'old.ndjson',
                       'matrix.json', 'C0-W1', 'C0-P1', 'https://',
                       'b' * 64, 'c' * 64, 'PRIVATE'):
            self.assertNotIn(secret, text)
        out = json.loads(result.stdout)
        self.assertEqual(out['schema'], REPORT)
        self.assertEqual(out['network'], 'NO_NETWORK')
        self.assertEqual(out['authorization'], 'NO_AUTHORIZATION')
        self.assertEqual(out['collection'], 'C0_COLLECT_HOLD')
        self.assertEqual(len(out['evidence_gaps']), 5)
        return out

    def test_two_by_two_private_matrix_with_semantic_change_gate(self):
        for args, exit_code in (((), 0), (('--fail-on-change',), 3)):
            with self.subTest(args=args):
                res = self.invoke(*args)
                self.assertEqual((res.returncode, res.stderr), (exit_code, b''))
                report = self.check_private(res)
                self.assertEqual((report['status'], report['before_count'],
                                  report['after_count'], report['total_cells']),
                                 ('CHANGED', 2, 2, 4))
                self.assertEqual((report['changed_cells'], report['unchanged_cells']), (2, 2))
                self.assertEqual([(c['before_index'], c['after_index'], c['status'])
                                  for c in report['cells']],
                                 [(1, 1, 'UNCHANGED'), (1, 2, 'CHANGED'),
                                  (2, 1, 'UNCHANGED'), (2, 2, 'CHANGED')])
                self.assertEqual(report['cells'][1]['object_change_counts'],
                                 {'added': 0, 'removed': 0, 'changed': 1})
                self.assertEqual(report['cells'][1]['object_field_change_counts']['sha256'], 1)
                self.assertEqual(res.stdout, self.invoke(*args).stdout)

    def test_full_eight_by_eight_matrix_bounded_at_64(self):
        before = [files('old.json') if i % 2 else ndjson('old.ndjson')
                  for i in range(8)]
        after = [files('old-copy.json') if i % 2 else files('new.json')
                 for i in range(8)]
        self.matrix(before, after)
        res = self.invoke('--fail-on-change')
        self.assertEqual((res.returncode, res.stderr), (3, b''))
        out = self.check_private(res)
        self.assertEqual((out['total_cells'], out['changed_cells'],
                          out['unchanged_cells']), (64, 32, 32))
        self.assertEqual(len(out['cells']), 64)
        self.assertEqual(out['cells'][0]['before_index'], 1)
        self.assertEqual(out['cells'][-1]['after_index'], 8)
        self.assertLess(len(res.stdout), 65000)

    def test_ndjson_and_json_set_produce_same_semantic_set(self):
        self.matrix([files('old.json', 'extra.json')], [ndjson('two.ndjson')])
        res = self.invoke('--fail-on-change')
        self.assertEqual((res.returncode, res.stderr), (0, b''))
        out = self.check_private(res)
        self.assertEqual(out['status'], 'UNCHANGED')
        self.assertEqual(out['cells'][0]['object_change_counts'],
                         {'added': 0, 'removed': 0, 'changed': 0})

    def test_added_removed_counts_preserve_direction(self):
        self.matrix([files('old.json', 'extra.json'), ndjson('old.ndjson')],
                    [ndjson('old.ndjson'), ndjson('two.ndjson')])
        out = self.check_private(self.invoke('--fail-on-change'))
        self.assertEqual(out['cells'][0]['object_change_counts']['removed'], 1)
        self.assertEqual(out['cells'][3]['object_change_counts']['added'], 1)

    def test_single_before_and_after_unchanged_is_exit_zero(self):
        self.matrix([files('old.json')], [ndjson('old.ndjson')])
        res = self.invoke('--fail-on-change')
        self.assertEqual(res.returncode, 0)
        out = self.check_private(res)
        self.assertEqual((out['status'], out['changed_cells']), ('UNCHANGED', 0))

    def test_invalid_matrix_schema_counts_and_keys_fail_closed(self):
        examples = [
            {'schema': CONFIG, 'before': [], 'after': [files('old.json')]},
            {'schema': CONFIG, 'before': [files('old.json')] * 9,
             'after': [files('new.json')]},
            {'schema': CONFIG, 'before': [files('old.json')], 'after': []},
            {'schema': CONFIG, 'before': [files('old.json')],
             'after': [files('new.json')], 'extra': 1},
            {'schema': 'wrong', 'before': [files('old.json')],
             'after': [files('new.json')]},
            {'schema': CONFIG, 'before': [files()], 'after': [files('new.json')]},
            {'schema': CONFIG, 'before': [files(*['old.json'] * 17)],
             'after': [files('new.json')]},
            {'schema': CONFIG, 'before': [files('old.json')],
             'after': [{'json_files': ['new.json'], 'ndjson_file': 'old.ndjson'}]},
        ]
        for i, example in enumerate(examples):
            with self.subTest(i=i):
                self.put('matrix.json', json.dumps(example))
                res = self.invoke('--fail-on-change')
                self.assertEqual((res.returncode, res.stderr), (2, b''))
                out = self.check_private(res)
                self.assertEqual(out['status'], 'REFUSED')
                self.assertIsNone(out['changed_cells'])
                self.assertIsNone(out['total_cells'])
                self.assertEqual(out['cells'], [])
        self.put('matrix.json', b' ' * 16385)
        self.assertEqual(self.invoke().returncode, 2)
        self.put('matrix.json', '{"schema":"x","schema":"x"}')
        self.assertEqual(self.invoke().returncode, 2)

    def test_unsafe_source_names_refuse_without_reflection(self):
        for name in ('../private.json', '/tmp/private', 'x/y', 'https://hidden.example',
                     'file name.json', '\u00e9.json', 'x' * 81, '.', '..',
                     'matrix.json', 'old\\json'):
            with self.subTest(name=name):
                self.matrix([files(name)], [files('old.json')])
                res = self.invoke()
                self.assertEqual((res.returncode, res.stderr), (2, b''))
                self.assertEqual(self.check_private(res)['status'], 'REFUSED')
                self.assertNotIn(name.encode(), res.stdout + res.stderr)

    def test_duplicate_source_set_and_global_kind_collision_fail_before_reads(self):
        import c0_review_matrix as runner
        plans = [([files('old.json', 'old.json')], [files('new.json')]),
                 ([files('old.json'), ndjson('old.json')], [files('new.json')])]
        for before, after in plans:
            with self.subTest(before=before):
                self.matrix(before, after)
                with patch.object(c0, 'inspect_manifest',
                                  side_effect=AssertionError('source touched')):
                    code, result = runner.review_matrix(self.root / 'matrix.json')
                self.assertEqual((code, result['status']), (2, 'REFUSED'))
                self.assertEqual(result['cells'], [])

    def test_all_or_nothing_refusal_on_missing_or_conflicting_source(self):
        self.matrix([files('old.json'), files('missing.json')],
                    [files('new.json')])
        res = self.invoke('--fail-on-change')
        self.assertEqual(res.returncode, 2)
        out = self.check_private(res)
        self.assertEqual(out['cells'], [])
        self.assertIsNone(out['before_count'])
        self.assertIsNone(out['changed_cells'])
        self.matrix([files('old.json', 'old-copy.json')], [files('new.json')])
        res = self.invoke()
        self.assertEqual(res.returncode, 2)
        self.assertEqual(self.check_private(res)['status'], 'REFUSED')

    def test_symlinks_fifo_nonregular_and_oversized_sources_fail_promptly(self):
        for filename in ('matrix.json', 'old.json', 'old.ndjson'):
            for mode in ('symlink', 'fifo', 'missing', 'oversize'):
                with self.subTest(filename=filename, mode=mode):
                    self.matrix([files('old.json')], [ndjson('old.ndjson')])
                    path = self.root / filename
                    previous = path.read_bytes()
                    path.unlink()
                    if mode == 'symlink':
                        path.symlink_to(self.root / 'new.json')
                    elif mode == 'fifo':
                        os.mkfifo(path)
                    elif mode == 'oversize':
                        path.write_bytes(b'x' * (262161 if filename.endswith('.ndjson')
                                                   else 16385))
                    try:
                        res = self.invoke()
                        self.assertEqual((res.returncode, res.stderr), (2, b''))
                        self.assertEqual(self.check_private(res)['status'], 'REFUSED')
                    finally:
                        path.unlink(missing_ok=True)
                        path.write_bytes(previous)

    def test_source_is_read_once_across_sixty_four_matrix_cells(self):
        import c0_review_matrix as runner
        self.matrix([files('old.json')]*8, [files('new.json')]*8)
        reads=[]
        original=c0.inspect_manifest
        def recorded(name,*args,**kwargs):
            reads.append(name)
            return original(name,*args,**kwargs)
        with patch.object(c0,'inspect_manifest', side_effect=recorded):
            code, result=runner.review_matrix(self.root / 'matrix.json')
        self.assertEqual((code, result['total_cells']), (0, 64))
        self.assertEqual(sorted(reads), ['new.json', 'old.json'])

    def test_global_file_limit_rejected_before_any_source_read(self):
        import c0_review_matrix as runner
        before = [files(*[f'a{i}_{j}.json' for j in range(16)]) for i in range(2)]
        after = [files('z.json')]
        self.matrix(before, after)
        with patch.object(c0, 'inspect_manifest',
                          side_effect=AssertionError('read before validation')):
            code, out = runner.review_matrix(self.root / 'matrix.json')
        self.assertEqual(code, 2)
        self.assertEqual(out['cells'], [])
        self.assertIsNone(out['total_cells'])

    def test_source_and_configuration_are_unchanged_after_execution(self):
        before={p.name:p.read_bytes() for p in self.root.iterdir()}
        self.invoke('--fail-on-change')
        after={p.name:p.read_bytes() for p in self.root.iterdir()}
        self.assertEqual(before, after)
        for arg in ('--unknown-option','--fail-on-change'):
            opts=(arg, arg) if arg=='--fail-on-change' else (arg,)
            self.assertEqual(self.invoke(*opts).returncode, 2)


if __name__ == '__main__':
    unittest.main()
