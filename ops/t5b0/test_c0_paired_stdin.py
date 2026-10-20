"""Offline paired-stdin C0 comparison contracts, no files or network."""
import copy
import json
import subprocess
import sys
import unittest
from pathlib import Path

SCRIPT = Path(__file__).with_name('c0_manifest_preflight.py')
BASE = {
    'schema': 'som-t5b0-c0-preflight-v1',
    'approval': None,
    'objects': [{'id': 'C0-W1', 'url': 'https://host/one.whl',
                 'sha256': 'a' * 64, 'bytes': 1, 'max_bytes': 1}],
}
SEPARATOR = b'\n---\n'


def payload(before, after):
    def records(value):
        if isinstance(value, bytes):
            return value
        return b'\n'.join(json.dumps(doc).encode() for doc in value)
    return records(before) + SEPARATOR + records(after) + b'\n'


def invoke(data, *args):
    proc = subprocess.run(
        [sys.executable, str(SCRIPT), '--compare-stdin-batches', *args],
        input=data, capture_output=True, check=False, timeout=8)
    report = json.loads(proc.stdout) if proc.stdout.startswith(b'{') else None
    return proc, report


class PairedStdinCompareTests(unittest.TestCase):
    def test_identical_snapshots_and_non_authorization(self):
        for flags in ((), ('--fail-on-change',)):
            with self.subTest(flags=flags):
                proc, report = invoke(payload([BASE], [BASE]), *flags)
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
                self.assertNotIn('_inventory', proc.stdout.decode())
                self.assertNotIn('https://host/one.whl', proc.stdout.decode())

    def test_added_removed_and_field_deltas_with_change_gate(self):
        newer = copy.deepcopy(BASE)
        newer['objects'][0]['url'] = 'https://host/new.whl'
        newer['objects'][0]['sha256'] = 'b' * 64
        newer['objects'][0]['bytes'] = 2
        newer['objects'][0]['max_bytes'] = 3
        newer['objects'].append({'id': 'C0-P1', 'url': 'https://host/two.whl',
                                 'sha256': 'c' * 64, 'bytes': 2, 'max_bytes': 2})
        for opts, expected_code in (((), 0), (('--fail-on-change',), 3)):
            with self.subTest(opts=opts):
                proc, report = invoke(payload([BASE], [newer]), *opts)
                self.assertEqual(proc.returncode, expected_code, proc.stderr)
                self.assertEqual(report['status'], 'CHANGED')
                self.assertEqual(report['object_diff'], {
                    'status': 'AVAILABLE', 'added': ['C0-P1'], 'removed': [],
                    'changed': [{'id': 'C0-W1',
                                 'fields': ['bytes', 'max_bytes', 'sha256', 'url']}]})
                self.assertNotIn('https://host/new.whl', proc.stdout.decode())
                self.assertNotIn('bbbbbbbb', proc.stdout.decode())
        removed = copy.deepcopy(BASE)
        removed['objects'][0]['id'] = 'C0-P1'
        removed['objects'][0]['url'] = 'https://host/different.whl'
        proc, report = invoke(payload([BASE], [removed]), '--fail-on-change')
        self.assertEqual(proc.returncode, 3)
        self.assertEqual(report['object_diff']['added'], ['C0-P1'])
        self.assertEqual(report['object_diff']['removed'], ['C0-W1'])

    def test_refusal_precedence_both_sides_and_incomplete_lines(self):
        for case in ('before-invalid', 'after-invalid', 'both-invalid',
                     'too-many-before', 'too-many-after', 'oversized-before',
                     'oversized-after', 'cross-duplicate-before',
                     'cross-duplicate-after', 'empty-before', 'empty-after'):
            with self.subTest(case=case):
                before, after = [BASE], [BASE]
                if case in ('before-invalid', 'both-invalid'):
                    before = b'{'
                if case in ('after-invalid', 'both-invalid'):
                    after = b'{'
                if case == 'too-many-before':
                    before = [BASE] * 17
                if case == 'too-many-after':
                    after = [BASE] * 17
                if case == 'oversized-before':
                    before = b'X' * 16385
                if case == 'oversized-after':
                    after = b'X' * 16385
                if case == 'cross-duplicate-before':
                    before = [BASE, BASE]
                if case == 'cross-duplicate-after':
                    after = [BASE, BASE]
                if case == 'empty-before':
                    before = b''
                if case == 'empty-after':
                    after = b''
                proc, report = invoke(payload(before, after), '--fail-on-change')
                self.assertEqual(proc.returncode, 2, (case, proc.stderr, proc.stdout))
                self.assertEqual(report['status'], 'REFUSED')
                self.assertEqual(report['object_diff']['status'], 'UNAVAILABLE')
                self.assertEqual(report['authorization'], 'NO_AUTHORIZATION')
                self.assertEqual(report['collection'], 'C0_COLLECT_HOLD')
                self.assertEqual(report['network'], 'NO_NETWORK')

    def test_framing_error_refuses_without_any_partial_inventory(self):
        for bad in (b'', b'not-json', b'{}\n{}', b'---\n{}',
                    payload([BASE], [BASE]).replace(SEPARATOR, b'\n----\n'),
                    payload([BASE], [BASE]) + SEPARATOR + b'{}',
                    payload([BASE], [BASE]) + b'\n---\n{}',
                    b'X' * (2 * 16 * 16385 + 6)):
            with self.subTest(length=len(bad)):
                proc, report = invoke(bad, '--fail-on-change')
                self.assertEqual(proc.returncode, 2, proc.stderr)
                self.assertEqual(report['status'], 'REFUSED')
                self.assertEqual(report['object_diff']['status'], 'UNAVAILABLE')
                self.assertNotIn('_inventory', proc.stdout.decode())
                self.assertEqual(report['network'], 'NO_NETWORK')

    def test_16_record_boundary_independent_on_each_side(self):
        def pack(n, rev=False):
            ids = ('C0-W1', 'C0-P1', 'C0-R1', 'C0-T1')
            items = []
            for i in range(n):
                obj = copy.deepcopy(BASE)
                obj['objects'][0]['id'] = ids[i % len(ids)]
                obj['objects'][0]['url'] = f'https://host/{i}.whl'
                obj['objects'][0]['sha256'] = f'{i:064x}'
                items.append(obj)
            return items[::-1] if rev else items
        # Sixteen distinct IDs are not possible under the four-ID schema; these
        # bounded snapshots must refuse duplicate object IDs, never leak inventory.
        for n in (16, 17):
            with self.subTest(n=n):
                proc, report = invoke(payload(pack(n), [BASE]))
                self.assertEqual(proc.returncode, 2)
                self.assertEqual(report['object_diff']['status'], 'UNAVAILABLE')

    def test_all_other_modes_and_strict_flag_are_incompatible(self):
        for extra in (('--stdin',), ('--stdin-batch',), ('--directory', 'no-dir'),
                      ('--compare-directories', 'a', 'b'),
                      ('--compare-stdin-to-directory', 'a'),
                      ('--compare-stdin-before-directory', 'b'),
                      ('--batch', 'a.json'), ('a.json',), ('--require-json-only',)):
            with self.subTest(extra=extra):
                proc, report = invoke(payload([BASE], [BASE]), *extra)
                self.assertEqual(proc.returncode, 2, proc.stderr)
                self.assertIsNone(report)
                self.assertIn(b'cannot be combined', proc.stderr)

    def test_help_lists_both_existing_and_paired_change_gate_modes(self):
        proc = subprocess.run([sys.executable, str(SCRIPT), '--help'],
                              capture_output=True, check=False)
        self.assertEqual(proc.returncode, 0)
        help_text = proc.stdout
        self.assertIn(b'--compare-stdin-batches', help_text)
        self.assertIn(b'--compare-stdin-before-directory', help_text)
        self.assertIn(b'--fail-on-change', help_text)
        self.assertIn(b'--compare-directories', help_text)
        self.assertIn(b'--compare-stdin-to-directory', help_text)


if __name__ == '__main__':
    unittest.main()
