"""Input-free, deterministic aggregate of all existing reviewed recipe contracts."""
import io
import json
import subprocess
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import c0_manifest_preflight as cli

SCRIPT = Path(__file__).with_name('c0_manifest_preflight.py')


class ContractCatalogTests(unittest.TestCase):
    @staticmethod
    def invoke(*args):
        return subprocess.run([sys.executable, str(SCRIPT), *args],
                              capture_output=True, timeout=6, check=False)

    def test_aggregate_contains_exactly_all_ten_current_contracts(self):
        result = self.invoke('--recipe-contracts-json')
        self.assertEqual((result.returncode, result.stderr), (0, b''))
        doc = json.loads(result.stdout)
        recipes = json.loads(self.invoke('--recipes-json').stdout)
        self.assertEqual(doc['schema'], 'som-t5b0-c0-recipe-contracts-json-v1')
        self.assertEqual(doc['recipe_contract_schema'],
                         'som-t5b0-c0-recipe-contract-json-v1')
        self.assertEqual(doc['review_schema'], recipes['review_schema'])
        self.assertEqual(doc['catalog_scope'], 'CURATED_NOT_EXHAUSTIVE')
        self.assertEqual(doc['authorization'], 'NO_AUTHORIZATION')
        self.assertEqual(doc['collection'], 'C0_COLLECT_HOLD')
        self.assertEqual(doc['network'], 'NO_NETWORK')
        self.assertEqual(doc['evidence_gaps'], recipes['evidence_gaps'])
        self.assertEqual(len(doc['contracts']), 10)
        ids = [c['recipe']['id'] for c in doc['contracts']]
        self.assertEqual(ids, sorted(ids))
        self.assertEqual(ids, [r['id'] for r in recipes['recipes']])
        for contract in doc['contracts']:
            with self.subTest(id=contract['recipe']['id']):
                single = json.loads(self.invoke('--recipe-contract-json',
                                                 contract['recipe']['id']).stdout)
                self.assertEqual(contract, single)
        self.assertLess(len(result.stdout), 20000)
        self.assertEqual(result.stdout, self.invoke('--recipe-contracts-json').stdout)
        self.assertNotIn(b'https://', result.stdout)
        self.assertNotIn(b'C0-W1', result.stdout)

    def test_no_stdin_or_file_directory_access(self):
        class ReadDenied:
            def read(self, *args):
                raise AssertionError('stdin should not be read')
        out, err = io.StringIO(), io.StringIO()
        with patch.object(sys, 'argv', [str(SCRIPT), '--recipe-contracts-json']), \
                patch.object(sys, 'stdin', SimpleNamespace(buffer=ReadDenied())), \
                patch.object(cli, 'inspect_manifest', side_effect=AssertionError('file')), \
                patch.object(cli, 'inspect_stdin_batch', side_effect=AssertionError('stdin')), \
                patch.object(cli, 'inspect_local_ndjson_batch',
                             side_effect=AssertionError('batch')), \
                patch.object(cli, 'directory_report', side_effect=AssertionError('dir')), \
                redirect_stdout(out), redirect_stderr(err):
            self.assertEqual(cli.main(), 0)
        self.assertEqual(err.getvalue(), '')
        self.assertEqual(len(json.loads(out.getvalue())['contracts']), 10)

    def test_input_and_output_combinations_refuse_before_access(self):
        others = (('file.json',), ('--stdin',), ('--stdin-batch',),
                  ('--batch', 'file.json'), ('--directory', 'files'),
                  ('--compare-files', 'a.json', 'b.json'),
                  ('--compare-before-files', 'file.json'),
                  ('--compare-files-to-stdin-batch', 'file.json'),
                  ('--compare-files-to-batch-file', 'file.json'),
                  ('--against-batch-file', 'before.ndjson'),
                  ('--recipe-json', 'inspect-one-file'),
                  ('--recipe-contract-json', 'inspect-one-file'),
                  ('--recipes-json',), ('--capabilities-json',),
                  ('--summary-json',), ('--summary',), ('--json',),
                  ('--guidance',), ('--fail-on-change',),
                  ('--require-json-only',), ('--batch-consistency',))
        for extra in others:
            with self.subTest(extra=extra):
                out, err = io.StringIO(), io.StringIO()
                with patch.object(sys, 'argv', [str(SCRIPT), '--recipe-contracts-json',
                                                 *extra]), \
                        patch.object(cli, 'inspect_manifest',
                                     side_effect=AssertionError('file')), \
                        patch.object(cli, 'inspect_stdin_batch',
                                     side_effect=AssertionError('stdin')), \
                        redirect_stdout(out), redirect_stderr(err), \
                        self.assertRaises(SystemExit) as exit_result:
                    cli.main()
                self.assertEqual(exit_result.exception.code, 2)
                self.assertEqual(out.getvalue(), '')
                self.assertIn('--recipe-contracts-json', err.getvalue())

    def test_existing_single_and_static_schema_versions_remain_unmodified(self):
        self.assertEqual(json.loads(self.invoke('--recipes-json').stdout)['schema'],
                         'som-t5b0-c0-recipes-v1')
        self.assertEqual(json.loads(self.invoke('--recipe-json', 'inspect-one-file').stdout)['schema'],
                         'som-t5b0-c0-recipe-json-v1')
        self.assertEqual(json.loads(self.invoke('--recipe-contract-json',
                                               'inspect-one-file').stdout)['schema'],
                         'som-t5b0-c0-recipe-contract-json-v1')
        self.assertEqual(json.loads(self.invoke('--capabilities-json').stdout)['schema'],
                         'som-t5b0-c0-capabilities-v1')


if __name__ == '__main__':
    unittest.main()
