"""Privacy-safe, read-free lookup of one curated operator argv recipe by stable ID."""
import io
import json
import subprocess
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import c0_manifest_preflight as c0

SCRIPT = Path(__file__).with_name('c0_manifest_preflight.py')


class SingleRecipeLookupTests(unittest.TestCase):
    @staticmethod
    def invoke(*flags):
        return subprocess.run([sys.executable, str(SCRIPT), *flags],
                              input=b'{C0-W1 https://private.example}',
                              capture_output=True, timeout=6, check=False)

    def test_all_ten_id_lookups_match_catalog_recipe_exactly(self):
        catalog = json.loads(self.invoke('--recipes-json').stdout)
        self.assertEqual(len(catalog['recipes']), 10)
        for item in catalog['recipes']:
            with self.subTest(recipe=item['id']):
                res = self.invoke('--recipe-json', item['id'])
                self.assertEqual((res.returncode, res.stderr), (0, b''))
                found = json.loads(res.stdout)
                self.assertEqual(found['schema'], 'som-t5b0-c0-recipe-json-v1')
                self.assertEqual(found['review_schema'], catalog['review_schema'])
                self.assertEqual(found['catalog_scope'], 'CURATED_NOT_EXHAUSTIVE')
                self.assertEqual(found['recipe'], item)
                self.assertEqual(found['authorization'], 'NO_AUTHORIZATION')
                self.assertEqual(found['collection'], 'C0_COLLECT_HOLD')
                self.assertEqual(found['network'], 'NO_NETWORK')
                self.assertEqual(found['evidence_gaps'], catalog['evidence_gaps'])
                self.assertLess(len(res.stdout), 2000)
                self.assertNotIn(b'https://', res.stdout)
                self.assertNotIn(b'C0-W1', res.stdout)
                self.assertNotIn(b'sha256', res.stdout)
                self.assertEqual(res.stdout, self.invoke('--recipe-json', item['id']).stdout)

    def test_unknown_ids_fail_closed_with_no_user_input_reflection(self):
        for unknown in ('unknown', '/tmp/secret-personal-file',
                        'https://sensitive.example', 'C0-W1', 'inspect-stdin',
                        '../private.json', 'x' * 200):
            with self.subTest(unknown=unknown[:24]):
                result = self.invoke('--recipe-json', unknown)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, b'')
                self.assertIn(b'--recipe-json', result.stderr)
                self.assertNotIn(unknown.encode(), result.stderr)

    def test_lookup_never_reads_stdin_files_or_directory(self):
        class NoRead:
            def read(self, *args):
                raise AssertionError('stdin read')
        out = io.StringIO()
        with patch.object(sys, 'argv', [str(SCRIPT), '--recipe-json', 'inspect-one-file']), \
                patch.object(sys, 'stdin', SimpleNamespace(buffer=NoRead())), \
                patch.object(c0, 'inspect_manifest', side_effect=AssertionError('file')), \
                patch.object(c0, 'inspect_local_ndjson_batch',
                             side_effect=AssertionError('batch')), \
                patch.object(c0, 'directory_report', side_effect=AssertionError('dir')), \
                redirect_stdout(out), redirect_stderr(io.StringIO()):
            self.assertEqual(c0.main(), 0)
        doc = json.loads(out.getvalue())
        self.assertEqual(doc['recipe']['id'], 'inspect-one-file')

    def test_mixed_input_and_report_flags_reject_before_source_read(self):
        modes = (
            ('a.json',), ('--stdin',), ('--stdin-batch',), ('--batch', 'a.json'),
            ('--directory', 'safe'), ('--batch-consistency',),
            ('--compare-files', 'a.json', 'b.json'),
            ('--compare-before-files', 'a.json'),
            ('--compare-after-files', 'a.json'),
            ('--compare-files-to-stdin-batch', 'a.json'),
            ('--compare-files-to-batch-file', 'a.json'),
            ('--compare-batch-file-to-files', 'a.json'),
            ('--against-batch-file', 'a.ndjson'),
            ('--compare-batch-files', 'a.ndjson', 'b.ndjson'),
            ('--capabilities-json',), ('--recipes-json',), ('--summary-json',),
            ('--summary',), ('--json',), ('--guidance',),
            ('--fail-on-change',), ('--require-json-only',),
        )
        for extra in modes:
            with self.subTest(extra=extra):
                out, err = io.StringIO(), io.StringIO()
                with patch.object(sys, 'argv', [str(SCRIPT), '--recipe-json',
                                                 'inspect-one-file', *extra]), \
                        patch.object(c0, 'inspect_manifest',
                                     side_effect=AssertionError('file read')), \
                        patch.object(c0, 'inspect_stdin_batch',
                                     side_effect=AssertionError('stdin read')), \
                        patch.object(c0, 'directory_report',
                                     side_effect=AssertionError('directory scan')), \
                        redirect_stdout(out), redirect_stderr(err), \
                        self.assertRaises(SystemExit) as exc:
                    c0.main()
                self.assertEqual(exc.exception.code, 2)
                self.assertEqual(out.getvalue(), '')
                self.assertIn('--recipe-json', err.getvalue())

    def test_no_id_is_parse_error_and_catalog_unchanged(self):
        missing = self.invoke('--recipe-json')
        self.assertEqual((missing.returncode, missing.stdout), (2, b''))
        baseline = json.loads(self.invoke('--recipes-json').stdout)
        self.assertEqual(baseline['schema'], 'som-t5b0-c0-recipes-v1')
        self.assertEqual(len(baseline['recipes']), 10)
        existing = json.loads(self.invoke('--capabilities-json').stdout)
        self.assertEqual(existing['schema'], 'som-t5b0-c0-capabilities-v1')
        self.assertEqual(existing['review_schema'], 'som-t5b0-c0-summary-json-v1')


if __name__ == '__main__':
    unittest.main()
