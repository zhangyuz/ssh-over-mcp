"""Stable version discriminator for private C0 machine review."""
import copy
import json
import tempfile
import unittest
from pathlib import Path

import c0_manifest_preflight as c0
from test_c0_guidance import VALID, run

EXPECTED_SCHEMA = 'som-t5b0-c0-summary-json-v1'


class ReviewSchemaTests(unittest.TestCase):
    def test_opt_in_json_schema_for_all_nine_input_modes(self):
        data = json.dumps(VALID).encode()
        with tempfile.TemporaryDirectory() as tmp:
            a, b = Path(tmp) / 'a', Path(tmp) / 'b'
            a.mkdir()
            b.mkdir()
            (a / 'private.json').write_bytes(data)
            (b / 'private.json').write_bytes(data)
            cases = [([a / 'private.json'], b''), (['--batch', a / 'private.json'], b''),
                     (['--directory', a], b''), (['--stdin'], data),
                     (['--stdin-batch'], data),
                     (['--compare-directories', a, b], b''),
                     (['--compare-stdin-to-directory', a], data),
                     (['--compare-stdin-before-directory', b], data),
                     (['--compare-stdin-batches'], data + b'\n---\n' + data)]
            for flags, incoming in cases:
                with self.subTest(flags=flags):
                    code, output, err = run([*flags, '--summary-json'], incoming)
                    self.assertEqual((code, err), (0, ''))
                    report = json.loads(output)
                    self.assertEqual(report['review_schema'], EXPECTED_SCHEMA)
                    self.assertIn('review_mode', report)
                    self.assertIn('next_action_codes', report)
                    for token in (tmp, 'private.json', 'https://'):
                        self.assertNotIn(token, output)

    def test_refusal_and_changed_keep_same_schema(self):
        data = json.dumps(VALID).encode()
        changed = copy.deepcopy(VALID)
        changed['objects'][0]['sha256'] = 'b'*64
        for incoming, exit_code, expected in (
            (data + b'\n---\n{', 2, 'REFUSED'),
            (data + b'\n---\n' + json.dumps(changed).encode(), 3, 'CHANGED'),
        ):
            with self.subTest(status=expected):
                code, output, err = run(['--compare-stdin-batches', '--fail-on-change',
                                         '--summary-json'], incoming)
                self.assertEqual((code, err), (exit_code, ''))
                report = json.loads(output)
                self.assertEqual(report['status'], expected)
                self.assertEqual(report['review_schema'], EXPECTED_SCHEMA)
                self.assertEqual(report['authorization'], 'NO_AUTHORIZATION')
                self.assertNotIn('https://', output)
                self.assertNotIn('b'*64, output)

    def test_renderer_direct_has_schema_and_legacy_outputs_do_not(self):
        self.assertEqual(json.loads(c0.render_summary_json(
            {'status':'STRUCTURE_ONLY_PASS'}))['review_schema'], EXPECTED_SCHEMA)
        data=json.dumps(VALID).encode()
        for options in (['--json'], ['--summary']):
            code,output,err=run(['--stdin',*options],data)
            self.assertEqual((code,err),(0,''))
            self.assertNotIn('review_schema',output)


if __name__ == '__main__':
    unittest.main()
