"""Stable private review-mode identifiers for C0 offline machine output."""
import json
import tempfile
import unittest
from pathlib import Path

import c0_manifest_preflight as c0
from test_c0_guidance import VALID, run


class MachineModeTests(unittest.TestCase):
    def test_all_nine_review_modes_are_constant_and_private(self):
        data = json.dumps(VALID).encode()
        with tempfile.TemporaryDirectory() as tmp:
            a, b = Path(tmp) / 'before', Path(tmp) / 'after'
            a.mkdir()
            b.mkdir()
            (a / 'hidden.json').write_bytes(data)
            (b / 'hidden.json').write_bytes(data)
            cases = [([a / 'hidden.json'], b'', 'MANIFEST_FILE'),
                     (['--batch', a / 'hidden.json'], b'', 'FILE_BATCH'),
                     (['--directory', a], b'', 'DIRECTORY'),
                     (['--stdin'], data, 'STDIN_MANIFEST'),
                     (['--stdin-batch'], data, 'STDIN_BATCH'),
                     (['--compare-directories', a, b], b'', 'DIRECTORY_COMPARISON'),
                     (['--compare-stdin-to-directory', a], data, 'DIRECTORY_TO_STDIN'),
                     (['--compare-stdin-before-directory', b], data,
                      'STDIN_TO_DIRECTORY'),
                     (['--compare-stdin-batches'], data + b'\n---\n' + data,
                      'PAIRED_STDIN_COMPARISON')]
            for flags, incoming, expected in cases:
                with self.subTest(mode=expected):
                    code, output, err = run([*flags, '--summary-json'], incoming)
                    self.assertEqual((code, err), (0, ''))
                    report = json.loads(output)
                    self.assertEqual(report['review_mode'], expected)
                    self.assertEqual(report['authorization'], 'NO_AUTHORIZATION')
                    for secret in (tmp, 'hidden.json', 'https://', 'a' * 64):
                        self.assertNotIn(secret, output)
                    old = run([*flags, '--summary'], incoming)
                    self.assertEqual(code, old[0])

    def test_non_summary_formats_and_untrusted_mode_cannot_leak(self):
        data = json.dumps(VALID).encode()
        code, legacy, err = run(['--stdin', '--json'], data)
        self.assertEqual((code, err), (0, ''))
        self.assertNotIn('review_mode', json.loads(legacy))
        code, text_summary, err = run(['--stdin', '--summary'], data)
        self.assertEqual((code, err), (0, ''))
        self.assertNotIn('review_mode', text_summary)
        malformed = c0.render_summary_json({'status': 'STRUCTURE_ONLY_PASS'},
                                            review_mode='SECRET_URL_https://evil.invalid')
        self.assertNotIn('review_mode', json.loads(malformed))
        self.assertNotIn('evil.invalid', malformed)

    def test_mode_retained_for_refused_input_and_changed_compare(self):
        data = json.dumps(VALID).encode()
        cases = [(['--stdin'], b'{', 'STDIN_MANIFEST', 2),
                 (['--compare-stdin-batches', '--fail-on-change'],
                  data + b'\n---\n{', 'PAIRED_STDIN_COMPARISON', 2)]
        for flags, incoming, expected, exit_code in cases:
            with self.subTest(flags=flags):
                code, output, err = run([*flags, '--summary-json'], incoming)
                self.assertEqual((code, err), (exit_code, ''))
                report = json.loads(output)
                self.assertEqual(report['review_mode'], expected)
                self.assertEqual(report['status'], 'REFUSED')
                self.assertNotIn('https://', output)


if __name__ == '__main__':
    unittest.main()
