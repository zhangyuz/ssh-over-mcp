"""Read-free curated C0 operator recipes, with examples checked against the CLI."""
import copy
import io
import json
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import c0_manifest_preflight as c0
from test_c0_guidance import VALID

SCRIPT = Path(__file__).with_name('c0_manifest_preflight.py')
IDS = {
    'inspect-one-file', 'inspect-stdin-manifest', 'inspect-stdin-batch',
    'inspect-named-files-consistently', 'compare-two-named-file-sets',
    'compare-named-files-to-stdin-batch', 'compare-stdin-batch-to-named-files',
    'compare-named-files-to-saved-batch', 'compare-saved-batch-to-named-files',
    'compare-two-saved-batches',
}


class StaticRecipesTests(unittest.TestCase):
    def discover(self):
        run = subprocess.run([sys.executable, str(SCRIPT), '--recipes-json'],
                             input=b'{private\nC0-W1 https://secret.example',
                             capture_output=True, timeout=6, check=False)
        self.assertEqual((run.returncode, run.stderr), (0, b''))
        return run.stdout, json.loads(run.stdout)

    def test_static_schema_and_explicit_curated_coverage(self):
        raw, doc = self.discover()
        self.assertEqual(doc['schema'], 'som-t5b0-c0-recipes-v1')
        self.assertEqual(doc['review_schema'], 'som-t5b0-c0-summary-json-v1')
        self.assertEqual(doc['catalog_scope'], 'CURATED_NOT_EXHAUSTIVE')
        self.assertEqual(doc['authorization'], 'NO_AUTHORIZATION')
        self.assertEqual(doc['collection'], 'C0_COLLECT_HOLD')
        self.assertEqual(doc['network'], 'NO_NETWORK')
        self.assertEqual(len(doc['evidence_gaps']), 5)
        self.assertEqual({x['id'] for x in doc['recipes']}, IDS)
        self.assertEqual([x['id'] for x in doc['recipes']], sorted(IDS))
        self.assertLess(len(raw), 8000)
        self.assertNotIn(b'C0-W1', raw)
        self.assertNotIn(b'https://', raw)
        self.assertNotIn(b'sha256', raw)
        self.assertEqual(raw, subprocess.run(
            [sys.executable, str(SCRIPT), '--recipes-json'],
            capture_output=True, timeout=6, check=False).stdout)

    def test_recipe_argv_arrays_are_bounded_allowlisted_and_consistent(self):
        _, doc = self.discover()
        catalog = json.loads(subprocess.run(
            [sys.executable, str(SCRIPT), '--capabilities-json'],
            capture_output=True, timeout=6, check=False).stdout)
        for recipe in doc['recipes']:
            with self.subTest(recipe=recipe['id']):
                self.assertIn(recipe['review_mode'], catalog['review_modes'])
                self.assertIn(recipe['stdin_format'], ('NONE', 'JSON', 'NDJSON'))
                args = recipe['argv']
                self.assertIsInstance(args, list)
                self.assertLessEqual(len(args), 12)
                self.assertTrue(all(isinstance(s, str) and 0 < len(s) <= 55
                                    and '\n' not in s and '\x00' not in s
                                    for s in args))
                self.assertIn('--summary-json', args)
                self.assertNotIn('--recipes-json', args)
                self.assertNotIn('--capabilities-json', args)
                self.assertFalse(any('https://' in s or 'C0-' in s for s in args))

    def test_every_published_example_parses_and_refuses_missing_inputs_safely(self):
        _, doc = self.discover()
        for recipe in doc['recipes']:
            with self.subTest(recipe=recipe['id']):
                run = subprocess.run([sys.executable, str(SCRIPT), *recipe['argv']],
                                     input=b'', capture_output=True, timeout=6, check=False)
                # Named example paths do not exist; lack of inputs must be a structured
                # C0 refusal, not argparse's unstructured usage error or a hang.
                self.assertEqual((run.returncode, run.stderr), (2, b''))
                report = json.loads(run.stdout)
                self.assertEqual(report['review_mode'], recipe['review_mode'])
                self.assertEqual(report['status'], 'REFUSED')
                self.assertEqual(report['authorization'], 'NO_AUTHORIZATION')
                self.assertEqual(report['network'], 'NO_NETWORK')

    def test_all_curated_recipes_work_on_valid_local_demo_inputs(self):
        # Concrete end-to-end examples, not just parser smoke tests.
        _, catalog = self.discover()
        with tempfile.TemporaryDirectory() as root:
            root_path = Path(root)
            first = copy.deepcopy(VALID)
            second = copy.deepcopy(VALID)
            second['objects'][0].update(id='C0-P1', url='https://example.org/b',
                                        sha256='b' * 64)
            for name, data in {
                'example.json': first, 'one.json': first, 'two.json': second,
                'before-a.json': first, 'before-b.json': second,
                'after-a.json': first, 'after-b.json': second,
            }.items():
                (root_path / name).write_text(json.dumps(data))
            stream = (json.dumps(first) + '\n' + json.dumps(second) + '\n').encode()
            for name in ('before.ndjson', 'after.ndjson'):
                (root_path / name).write_bytes(stream)
            for entry in catalog['recipes']:
                with self.subTest(recipe=entry['id']):
                    incoming = (json.dumps(first).encode() if entry['stdin_format'] == 'JSON'
                                else stream if entry['stdin_format'] == 'NDJSON' else b'')
                    run = subprocess.run([sys.executable, str(SCRIPT), *entry['argv']],
                                         cwd=root_path, input=incoming,
                                         capture_output=True, timeout=6, check=False)
                    self.assertEqual((run.returncode, run.stderr), (0, b''))
                    report = json.loads(run.stdout)
                    self.assertIn(report['status'], ('STRUCTURE_ONLY_PASS', 'UNCHANGED'))
                    self.assertEqual(report['review_mode'], entry['review_mode'])
                    self.assertEqual(report['authorization'], 'NO_AUTHORIZATION')
                    self.assertEqual(report['collection'], 'C0_COLLECT_HOLD')
                    self.assertEqual(report['network'], 'NO_NETWORK')
                    self.assertNotIn('https://', run.stdout.decode())
                    self.assertNotIn('C0-W1', run.stdout.decode())
                    self.assertNotIn(str(root_path), run.stdout.decode())

    def test_discovery_cannot_open_any_file_directory_or_stdin(self):
        class NoRead:
            def read(self, *args):
                raise AssertionError('unexpected stdin read')
        out = io.StringIO()
        with patch.object(sys, 'argv', [str(SCRIPT), '--recipes-json']), \
                patch.object(sys, 'stdin', SimpleNamespace(buffer=NoRead())), \
                patch.object(c0, 'inspect_manifest', side_effect=AssertionError('file')), \
                patch.object(c0, 'inspect_local_ndjson_batch',
                             side_effect=AssertionError('NDJSON')), \
                patch.object(c0, 'directory_report', side_effect=AssertionError('dir')), \
                redirect_stdout(out), redirect_stderr(io.StringIO()):
            self.assertEqual(c0.main(), 0)
        self.assertEqual(json.loads(out.getvalue())['schema'],
                         'som-t5b0-c0-recipes-v1')

    def test_every_input_family_or_output_collision_refuses_pre_read(self):
        bad = [
            ['a.json'], ['--batch', 'a.json'], ['--directory', 'dirname'],
            ['--stdin'], ['--stdin-batch'], ['--batch-consistency'],
            ['--compare-files', 'a.json', 'b.json'],
            ['--compare-before-files', 'a.json'],
            ['--compare-files-to-stdin-batch', 'a.json'],
            ['--compare-files-to-batch-file', 'a.json'],
            ['--against-batch-file', 'a.ndjson'],
            ['--compare-batch-file-to-files', 'a.json'],
            ['--compare-batch-files', 'a.ndjson', 'b.ndjson'],
            ['--compare-stdin-batches'], ['--capabilities-json'],
            ['--summary-json'], ['--summary'], ['--json'], ['--guidance'],
            ['--fail-on-change'], ['--require-json-only'],
        ]
        for flags in bad:
            with self.subTest(flags=flags):
                stdout, stderr = io.StringIO(), io.StringIO()
                with patch.object(sys, 'argv', [str(SCRIPT), '--recipes-json', *flags]), \
                        patch.object(c0, 'inspect_manifest',
                                     side_effect=AssertionError('file opened')), \
                        patch.object(c0, 'inspect_stdin_batch',
                                     side_effect=AssertionError('stdin opened')), \
                        patch.object(c0, 'directory_report',
                                     side_effect=AssertionError('directory opened')), \
                        redirect_stdout(stdout), redirect_stderr(stderr), \
                        self.assertRaises(SystemExit) as caught:
                    c0.main()
                self.assertEqual(caught.exception.code, 2)
                self.assertEqual(stdout.getvalue(), '')
                self.assertIn('--recipes-json', stderr.getvalue())


if __name__ == '__main__':
    unittest.main()
