"""Purely offline negative/positive structural fixtures; no network."""
import copy
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
import unittest
from c0_manifest_preflight import validate, parse_manifest

BASE = {'schema': 'som-t5b0-c0-preflight-v1', 'approval': None,
        'objects': [{'id': 'C0-W1', 'url': 'https://files.pythonhosted.org/packages/sha256/immutable.whl',
                     'sha256': 'a' * 64, 'bytes': 100, 'max_bytes': 100}]}


class C0PreflightTests(unittest.TestCase):
    def test_structure_only_pass_not_approval(self):
        self.assertEqual(validate(BASE), [])

    def test_reject_duplicate_json_keys(self):
        with self.assertRaises(ValueError):
            parse_manifest('{"schema":"x","schema":"y","objects":[],"approval":null}')

    def test_untrusted_file_types_and_limits(self):
        script = Path(__file__).with_name('c0_manifest_preflight.py')
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            valid = root / 'valid.json'
            valid.write_text(json.dumps(BASE))
            oversized = root / 'oversized.json'
            oversized.write_bytes(b'x' * (16385 + 1024 * 1024))
            fifo = root / 'fifo.json'
            os.mkfifo(fifo)
            symlink = root / 'symlink.json'
            symlink.symlink_to(valid)
            deep = root / 'deep.json'
            deep.write_text('[' * 3000 + '0' + ']' * 3000)
            for path in (oversized, fifo, symlink, deep, root):
                with self.subTest(path=path):
                    result = subprocess.run([sys.executable, str(script), str(path)],
                                            capture_output=True, text=True, timeout=3)
                    self.assertEqual(result.returncode, 2, result.stderr)
                    self.assertIn('REFUSED:', result.stdout)
                    self.assertNotIn('Traceback', result.stderr)
            result = subprocess.run([sys.executable, str(script), str(valid)],
                                    capture_output=True, text=True, timeout=3)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('NO_AUTHORIZATION', result.stdout)

    def test_fail_closed(self):
        for key, value in [('url', 'http://example.org/object'), ('url', 'https://example.org/x?latest=1'),
                           ('url', 'https://evil@host/path'), ('url', 'https://host/../path'),
                           ('url', 'https://host/'), ('sha256', 'invalid'), ('bytes', True),
                           ('max_bytes', 0), ('id', 'C0-OTHER')]:
            with self.subTest(key=key, value=value):
                case = copy.deepcopy(BASE)
                case['objects'][0][key] = value
                self.assertTrue(validate(case))
        for change in ('duplicate', 'approval', 'extra', 'empty'):
            with self.subTest(change=change):
                case = copy.deepcopy(BASE)
                if change == 'duplicate':
                    case['objects'].append(case['objects'][0])
                elif change == 'approval':
                    case['approval'] = 'approved'
                elif change == 'extra':
                    case['objects'][0]['redirects'] = True
                else:
                    case['objects'] = []
                self.assertTrue(validate(case))


if __name__ == '__main__':
    unittest.main()
