"""Offline file-directory snapshot comparison with no authority or network."""
import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from test_c0_guidance import VALID

SCRIPT = Path(__file__).with_name('c0_manifest_preflight.py')
MODES = (('--compare-file-to-directory', 'FILE_TO_DIRECTORY'),
         ('--compare-directory-to-file', 'DIRECTORY_TO_FILE'))


def invoke(mode, file, directory, *flags):
    args = [sys.executable, str(SCRIPT), mode]
    args.extend([str(file), str(directory)] if mode == MODES[0][0]
                else [str(directory), str(file)])
    args.extend(map(str, flags))
    run = subprocess.run(args, capture_output=True, timeout=8, check=False)
    report = json.loads(run.stdout) if run.stdout.startswith(b'{') else None
    return run, report


class FileDirectoryComparisonTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.file = self.root / 'secret-individual.json'
        self.directory = self.root / 'secret-directory'
        self.directory.mkdir()
        self.dir_entry = self.directory / 'secret-record.json'
        self.file.write_bytes(json.dumps(VALID).encode())
        self.dir_entry.write_bytes(json.dumps(VALID).encode())

    def assert_private(self, output):
        for private in (self.tmp.name, 'secret-record', 'secret-individual',
                        'secret-directory', 'https://', 'a'*64, 'b'*64):
            self.assertNotIn(private, output)

    def test_both_directions_positive_and_existing_json_summary_formats(self):
        for mode, mode_label in MODES:
            for flags in (('--json',), ('--summary-json',),
                          ('--summary',), ('--summary', '--guidance')):
                with self.subTest(mode=mode, flags=flags):
                    proc, report = invoke(mode, self.file, self.directory,
                                          '--fail-on-change', *flags)
                    self.assertEqual((proc.returncode, proc.stderr), (0, b''))
                    self.assert_private(proc.stdout.decode())
                    if '--summary' in flags:
                        self.assertIn('C0 offline review: UNCHANGED', proc.stdout.decode())
                    else:
                        self.assertEqual(report['status'], 'UNCHANGED')
                        self.assertEqual(report['authorization'], 'NO_AUTHORIZATION')
                        self.assertEqual(report['network'], 'NO_NETWORK')
                        self.assertEqual(report['collection'], 'C0_COLLECT_HOLD')
                        if '--summary-json' in flags:
                            self.assertEqual(report['review_mode'], mode_label)
                            self.assertEqual(report['review_schema'], 'som-t5b0-c0-summary-json-v1')
                            self.assertEqual(report['object_change_counts'],
                                             {'added': 0, 'removed': 0, 'changed': 0})
                            self.assertEqual(report['next_action_codes'],
                                             ['VERIFY_INDEPENDENT_EVIDENCE'])
                        else:
                            self.assertEqual(report['object_diff']['status'], 'AVAILABLE')

    def test_changed_field_and_baseline_direction(self):
        changed = copy.deepcopy(VALID)
        changed['objects'][0].update(sha256='b'*64, max_bytes=110)
        self.dir_entry.write_bytes(json.dumps(changed).encode())
        for mode, label in MODES:
            with self.subTest(mode=mode):
                proc, report = invoke(mode, self.file, self.directory,
                                      '--summary-json', '--fail-on-change')
                self.assertEqual((proc.returncode, proc.stderr), (3, b''))
                self.assertEqual(report['status'], 'CHANGED')
                self.assertEqual(report['review_mode'], label)
                self.assertEqual(report['object_change_counts'],
                                 {'added': 0, 'removed': 0, 'changed': 1})
                self.assert_private(proc.stdout.decode())
        changed['objects'][0]['id'] = 'C0-P1'
        self.dir_entry.write_bytes(json.dumps(changed).encode())
        for mode, _ in MODES:
            with self.subTest(mode=mode):
                proc, report = invoke(mode, self.file, self.directory,
                                      '--json', '--fail-on-change')
                self.assertEqual(proc.returncode, 3)
                delta = report['object_diff']
                self.assertEqual(delta['status'], 'AVAILABLE')
                self.assertEqual((delta['added'], delta['removed']),
                                 (['C0-P1'], ['C0-W1']) if mode == MODES[0][0]
                                 else (['C0-W1'], ['C0-P1']))

    def test_either_side_refusal_unavailable_and_no_private_values(self):
        data = json.dumps(VALID).encode()
        for mode, label in MODES:
            for broken_file, broken_dir in ((b'{', data), (data, b'{'),
                                            (b'X'*16385, data),
                                            (data, b'X'*16385)):
                with self.subTest(mode=mode, a=len(broken_file), b=len(broken_dir)):
                    self.file.write_bytes(broken_file)
                    self.dir_entry.write_bytes(broken_dir)
                    proc, report = invoke(mode, self.file, self.directory,
                                          '--summary-json', '--fail-on-change')
                    self.assertEqual((proc.returncode, proc.stderr), (2, b''))
                    self.assertEqual(report['status'], 'REFUSED')
                    self.assertEqual(report['review_mode'], label)
                    self.assertEqual(report['object_changes'], 'UNAVAILABLE')
                    self.assertIsNone(report['object_change_counts'])
                    self.assertIn('RETRY_OFFLINE_REVIEW', report['next_action_codes'])
                    self.assert_private(proc.stdout.decode())

    def test_strict_and_default_directory_resource_bounds(self):
        for mode, _ in MODES:
            with self.subTest(mode=mode):
                for i in range(63):
                    (self.directory / f'ignored-{i}.txt').write_text('')
                result, report = invoke(mode, self.file, self.directory,
                                        '--summary-json')
                self.assertEqual(result.returncode, 0)
                self.assertEqual(report['status'], 'UNCHANGED')
                strict, value = invoke(mode, self.file, self.directory,
                                       '--summary-json', '--require-json-only')
                self.assertEqual(strict.returncode, 2)
                self.assertEqual(value['status'], 'REFUSED')
                self.assertIsNone(value['object_change_counts'])
                (self.directory / 'overflow.txt').write_text('')
                over, report = invoke(mode, self.file, self.directory,
                                      '--summary-json')
                self.assertEqual(over.returncode, 2)
                self.assertEqual(report['status'], 'REFUSED')
                self.assertIsNone(report['object_change_counts'])
                for item in self.directory.glob('*.txt'):
                    item.unlink()

    def test_bad_file_symlink_fifo_and_conflicting_routes(self):
        for mode, _ in MODES:
            for kind in ('symlink', 'fifo', 'directory', 'missing'):
                with self.subTest(mode=mode, kind=kind):
                    self.file.unlink(missing_ok=True)
                    if kind == 'symlink':
                        self.file.symlink_to(self.dir_entry)
                    elif kind == 'fifo':
                        os.mkfifo(self.file)
                    elif kind == 'directory':
                        self.file.mkdir()
                    proc, report = invoke(mode, self.file, self.directory,
                                          '--summary-json')
                    self.assertEqual(proc.returncode, 2, proc.stderr)
                    self.assertEqual(report['status'], 'REFUSED')
                    self.assertIsNone(report['object_change_counts'])
                    self.assert_private(proc.stdout.decode())
                    if kind == 'directory':
                        self.file.rmdir()
                    elif kind in ('symlink', 'fifo'):
                        self.file.unlink()
                    self.file.write_bytes(json.dumps(VALID).encode())
            for flags in (('--stdin',), ('--stdin-batch',),
                          ('--compare-files', self.file, self.file),
                          ('--compare-stdin-batches',),
                          ('--compare-file-to-stdin', self.file),
                          ('--compare-stdin-to-file', self.file),
                          ('--directory', self.directory),
                          ('--compare-directories', self.directory, self.directory),
                          ('--compare-stdin-to-directory', self.directory),
                          ('--compare-stdin-before-directory', self.directory),
                          ('--batch', self.file), (self.file,),
                          (MODES[1][0] if mode == MODES[0][0] else MODES[0][0],
                           self.directory, self.file)):
                with self.subTest(mode=mode, flags=flags):
                    proc, report = invoke(mode, self.file, self.directory, *flags)
                    self.assertEqual(proc.returncode, 2)
                    self.assertIsNone(report)
                    self.assertEqual(proc.stdout, b'')
                    self.assertIn(b'cannot be combined', proc.stderr)


if __name__ == '__main__':
    unittest.main()
