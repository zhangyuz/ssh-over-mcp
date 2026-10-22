"""Machine-readable, source-free resource contracts for reviewed recipes."""
import io
import json
import subprocess
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

import c0_manifest_preflight as cli

SCRIPT = Path(__file__).with_name('c0_manifest_preflight.py')
J, S, N, F = 'LOCAL_JSON', 'STDIN_JSON', 'STDIN_NDJSON', 'LOCAL_NDJSON'
EXPECTED = {
    'inspect-one-file': [('input', J, 1)],
    'inspect-stdin-manifest': [('input', S, 1)],
    'inspect-stdin-batch': [('input', N, 1)],
    'inspect-named-files-consistently': [('input', J, 16)],
    'compare-two-named-file-sets': [('before', J, 16), ('after', J, 16)],
    'compare-named-files-to-stdin-batch': [('before', J, 16), ('after', N, 1)],
    'compare-stdin-batch-to-named-files': [('before', N, 1), ('after', J, 16)],
    'compare-named-files-to-saved-batch': [('before', J, 16), ('after', F, 1)],
    'compare-saved-batch-to-named-files': [('before', F, 1), ('after', J, 16)],
    'compare-two-saved-batches': [('before', F, 1), ('after', F, 1)],
}


class RecipeContractTests(unittest.TestCase):
    def invoke(self, *args):
        return subprocess.run([sys.executable, str(SCRIPT), *args],
                              capture_output=True, timeout=6, check=False)

    def test_ten_id_contracts_match_catalog_and_resource_ceiling(self):
        catalog = json.loads(self.invoke('--recipes-json').stdout)
        self.assertEqual(set(EXPECTED), {v['id'] for v in catalog['recipes']})
        for item in catalog['recipes']:
            with self.subTest(id=item['id']):
                result = self.invoke('--recipe-contract-json', item['id'])
                self.assertEqual((result.returncode, result.stderr), (0, b''))
                doc = json.loads(result.stdout)
                self.assertEqual(doc['schema'], 'som-t5b0-c0-recipe-contract-json-v1')
                self.assertEqual(doc['recipe'], item)
                self.assertEqual(doc['authorization'], 'NO_AUTHORIZATION')
                self.assertEqual(doc['collection'], 'C0_COLLECT_HOLD')
                self.assertEqual(doc['network'], 'NO_NETWORK')
                self.assertEqual(doc['evidence_gaps'], catalog['evidence_gaps'])
                self.assertEqual([(x['role'], x['format'], x['max_sources'])
                                  for x in doc['sources']], EXPECTED[item['id']])
                self.assertEqual(doc['refused_exit_code'], 2)
                self.assertEqual(doc['non_authorizing_exit_code'], 0)
                self.assertEqual(doc['changed_exit_code'],
                                 3 if len(doc['sources']) == 2 else None)
                for source in doc['sources']:
                    self.assertEqual(source['min_sources'], 1)
                    if source['format'] in (J, S):
                        self.assertEqual(source['max_bytes_per_source'], 16384)
                        self.assertEqual(source['max_records_per_source'], 1)
                    else:
                        self.assertEqual(source['max_bytes_per_source'], 262160)
                        self.assertEqual(source['max_records_per_source'], 16)
                self.assertLess(len(result.stdout), 3500)
                self.assertEqual(result.stdout,
                                 self.invoke('--recipe-contract-json', item['id']).stdout)

    def test_unknown_ids_are_refused_without_echoing_values(self):
        for unknown in ('not-supported', '../relative-path', 'ftp://host/file', 'x' * 140):
            with self.subTest(unknown=unknown[:16]):
                result = self.invoke('--recipe-contract-json', unknown)
                self.assertEqual((result.returncode, result.stdout), (2, b''))
                self.assertIn(b'--recipe-contract-json', result.stderr)
                self.assertNotIn(unknown.encode(), result.stderr)

    def test_mode_exclusivity_before_source_io(self):
        for extra in (('fixture.json',), ('--stdin',), ('--stdin-batch',),
                      ('--batch', 'fixture.json'), ('--directory', 'directory'),
                      ('--compare-files', 'a.json', 'b.json'),
                      ('--compare-files-to-batch-file', 'a.json'),
                      ('--recipe-json', 'inspect-one-file'), ('--recipes-json',),
                      ('--capabilities-json',), ('--summary-json',), ('--json',),
                      ('--summary',), ('--fail-on-change',)):
            with self.subTest(extra=extra):
                out, err = io.StringIO(), io.StringIO()
                with patch.object(sys, 'argv', [str(SCRIPT), '--recipe-contract-json',
                                                 'inspect-one-file', *extra]), \
                        patch.object(cli, 'inspect_manifest',
                                     side_effect=AssertionError('I/O forbidden')), \
                        redirect_stdout(out), redirect_stderr(err), \
                        self.assertRaises(SystemExit) as result:
                    cli.main()
                self.assertEqual(result.exception.code, 2)
                self.assertEqual(out.getvalue(), '')
                self.assertIn('--recipe-contract-json', err.getvalue())

    def test_existing_static_catalogs_unchanged(self):
        self.assertEqual(self.invoke('--recipe-contract-json').returncode, 2)
        self.assertEqual(json.loads(self.invoke('--recipes-json').stdout)['schema'],
                         'som-t5b0-c0-recipes-v1')
        self.assertEqual(json.loads(self.invoke('--recipe-json', 'inspect-one-file').stdout)['schema'],
                         'som-t5b0-c0-recipe-json-v1')
        self.assertEqual(json.loads(self.invoke('--capabilities-json').stdout)['schema'],
                         'som-t5b0-c0-capabilities-v1')


if __name__ == '__main__':
    unittest.main()
