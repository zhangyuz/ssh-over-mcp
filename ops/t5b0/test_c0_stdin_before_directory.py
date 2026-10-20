"""Reverse-streamed baseline C0 reviewer contracts; strictly offline."""
import copy
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).with_name('c0_manifest_preflight.py')
BASE = {
    'schema': 'som-t5b0-c0-preflight-v1',
    'approval': None,
    'objects': [{
        'id': 'C0-W1', 'url': 'https://host/one.whl',
        'sha256': 'a' * 64, 'bytes': 1, 'max_bytes': 1,
    }],
}


def run_review(root, baseline, after_docs=None, flags=()):
    after = root / 'successor'
    after.mkdir(exist_ok=True)
    if after_docs is not None:
        for name, doc in after_docs.items():
            (after / name).write_text(doc if isinstance(doc, str) else json.dumps(doc))
    stdin = (b''.join(json.dumps(doc).encode() + b'\n' for doc in baseline)
             if isinstance(baseline, list) else baseline)
    args = [sys.executable, str(SCRIPT), '--compare-stdin-before-directory',
            str(after), *flags]
    proc = subprocess.run(args, input=stdin, capture_output=True, check=False, timeout=8)
    assert proc.stdout.lstrip().startswith(b'{'), proc.stderr
    return proc, json.loads(proc.stdout)


class ReverseStreamedCompareTests(unittest.TestCase):
    def test_unchanged_and_directory_strict_modes(self):
        for flags in ((), ('--require-json-only',),
                      ('--fail-on-change', '--require-json-only')):
            with self.subTest(flags=flags), tempfile.TemporaryDirectory() as tmp:
                proc, report = run_review(Path(tmp), [BASE], {'a.json': BASE}, flags)
                self.assertEqual(proc.returncode, 0, proc.stderr)
                self.assertEqual(report['status'], 'UNCHANGED')
                self.assertEqual(report['object_diff'], {
                    'status': 'AVAILABLE', 'added': [], 'removed': [], 'changed': []})
                self.assertEqual((report['before']['status'], report['after']['status']),
                                 ('STRUCTURE_ONLY_PASS', 'STRUCTURE_ONLY_PASS'))
                self.assertEqual(report['evidence']['status'], 'UNVERIFIED')
                self.assertEqual(len(report['evidence']['gaps']), 5)
                self.assertEqual(report['authorization'], 'NO_AUTHORIZATION')
                self.assertEqual(report['collection'], 'C0_COLLECT_HOLD')
                self.assertEqual(report['network'], 'NO_NETWORK')
                self.assertNotIn('_inventory', json.dumps(report))
                self.assertNotIn('https://host/one.whl', proc.stdout.decode())

    def test_semantic_delta_and_opt_in_change_gate(self):
        after = copy.deepcopy(BASE)
        after['objects'][0]['url'] = 'https://host/moved.whl'
        after['objects'].append({
            'id': 'C0-P1', 'url': 'https://host/two.whl', 'sha256': 'b' * 64,
            'bytes': 2, 'max_bytes': 2})
        for flags, code in (((), 0), (('--fail-on-change',), 3),
                            (('--require-json-only', '--fail-on-change'), 3)):
            with self.subTest(flags=flags), tempfile.TemporaryDirectory() as tmp:
                proc, report = run_review(Path(tmp), [BASE], {'a.json': after}, flags)
                self.assertEqual(proc.returncode, code, proc.stderr)
                self.assertEqual(report['status'], 'CHANGED')
                self.assertEqual(report['object_diff'], {
                    'status': 'AVAILABLE', 'added': ['C0-P1'], 'removed': [],
                    'changed': [{'id': 'C0-W1', 'fields': ['url']}]})
                self.assertNotIn('https://host/moved.whl', proc.stdout.decode())
                self.assertNotIn('bbbbbb', proc.stdout.decode())

    def test_either_side_refusal_suppresses_semantic_diff(self):
        for case in ('bad-stdin', 'bad-directory', 'cross-id', 'too-many-lines',
                     'oversized-line', 'directory-overflow-default',
                     'directory-overflow-strict', 'unexpected-file-strict'):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                baseline = [BASE]
                docs = {'a.json': BASE}
                flags = ('--fail-on-change',)
                if case == 'bad-stdin':
                    baseline = b'{\n'
                elif case == 'bad-directory':
                    docs = {'a.json': '{'}
                elif case == 'cross-id':
                    baseline = [BASE, BASE]
                elif case == 'too-many-lines':
                    baseline = [BASE] * 17
                elif case == 'oversized-line':
                    baseline = b'X' * 16385 + b'\n'
                elif case.startswith('directory-overflow'):
                    docs.update({f'ignored-{i}.txt': '' for i in range(65)})
                    if case.endswith('strict'):
                        flags += ('--require-json-only',)
                elif case == 'unexpected-file-strict':
                    docs['foreign.txt'] = ''
                    flags += ('--require-json-only',)
                proc, report = run_review(root, baseline, docs, flags)
                self.assertEqual(proc.returncode, 2, (case, proc.stderr, proc.stdout))
                self.assertEqual(report['status'], 'REFUSED')
                self.assertEqual(report['object_diff']['status'], 'UNAVAILABLE')
                self.assertEqual(report['authorization'], 'NO_AUTHORIZATION')
                self.assertEqual(report['collection'], 'C0_COLLECT_HOLD')
                self.assertEqual(report['network'], 'NO_NETWORK')
                self.assertNotIn('_inventory', json.dumps(report))

    def test_all_object_fields_and_add_remove_changes(self):
        for field, new_value in (('url', 'https://host/updated.whl'),
                                 ('sha256', 'c' * 64),
                                 ('bytes', 2), ('max_bytes', 3)):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as tmp:
                before = copy.deepcopy(BASE)
                before['objects'][0]['max_bytes'] = 2
                after = copy.deepcopy(before)
                after['objects'][0][field] = new_value
                proc, report = run_review(
                    Path(tmp), [before], {'a.json': after}, ('--fail-on-change',))
                self.assertEqual(proc.returncode, 3, proc.stderr)
                self.assertEqual(report['object_diff'], {
                    'status': 'AVAILABLE', 'added': [], 'removed': [],
                    'changed': [{'id': 'C0-W1', 'fields': [field]}]})
        with tempfile.TemporaryDirectory() as tmp:
            after = copy.deepcopy(BASE)
            after['objects'][0]['id'] = 'C0-P1'
            after['objects'][0]['url'] = 'https://host/second.whl'
            proc, report = run_review(
                Path(tmp), [BASE], {'next.json': after}, ('--fail-on-change',))
            self.assertEqual(proc.returncode, 3, proc.stderr)
            self.assertEqual(report['object_diff'], {
                'status': 'AVAILABLE', 'added': ['C0-P1'],
                'removed': ['C0-W1'], 'changed': []})
            self.assertNotIn('https://host/second.whl', proc.stdout.decode())

    def test_default_directory_cap_64_passes_and_65_refuses(self):
        for extra_count, accepted in ((63, True), (64, False)):
            with self.subTest(extra_count=extra_count), tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                after = root / 'successor'
                after.mkdir()
                (after / 'a.json').write_text(json.dumps(BASE))
                for i in range(extra_count):
                    (after / f'z{i:02}.txt').write_text('')
                proc = subprocess.run(
                    [sys.executable, str(SCRIPT), '--compare-stdin-before-directory',
                     str(after)], input=json.dumps(BASE).encode() + bytes([10]),
                    capture_output=True, timeout=8, check=False)
                report = json.loads(proc.stdout)
                self.assertEqual(proc.returncode, 0 if accepted else 2)
                self.assertEqual(report['status'], 'UNCHANGED' if accepted else 'REFUSED')
                self.assertEqual(report['object_diff']['status'],
                                 'AVAILABLE' if accepted else 'UNAVAILABLE')
                if not accepted:
                    self.assertEqual(report['after']['errors'],
                                     ['directory must contain at most 64 total entries'])

    def test_incompatible_modes_rejected_at_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / 'a.json').write_text(json.dumps(BASE))
            for extra in (('--stdin',), ('--stdin-batch',), ('--directory', str(root)),
                          ('--compare-directories', str(root), str(root)),
                          ('--compare-stdin-to-directory', str(root)),
                          ('--batch', str(root / 'a.json')),
                          (str(root / 'a.json'),)):
                with self.subTest(extra=extra):
                    proc = subprocess.run(
                        [sys.executable, str(SCRIPT), '--compare-stdin-before-directory',
                         str(root), *extra], input=json.dumps(BASE).encode() + b'\n',
                        capture_output=True, timeout=5, check=False)
                    self.assertEqual(proc.returncode, 2, proc.stderr)
                    self.assertIn(b'cannot be combined', proc.stderr)


if __name__ == '__main__':
    unittest.main()
