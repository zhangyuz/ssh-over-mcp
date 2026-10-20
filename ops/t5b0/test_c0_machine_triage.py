"""Fail-closed remediation routing for privacy-safe machine review."""
import copy
import json
import unittest

import c0_manifest_preflight as c0
from test_c0_guidance import VALID, run


class MachineTriageTests(unittest.TestCase):
    def test_known_results_offer_only_non_authorizing_triage(self):
        expectations = {
            'STRUCTURE_ONLY_PASS': ['VERIFY_INDEPENDENT_EVIDENCE'],
            'UNCHANGED': ['VERIFY_INDEPENDENT_EVIDENCE'],
            'CHANGED': ['REVIEW_OBSERVED_CHANGES', 'VERIFY_INDEPENDENT_EVIDENCE'],
        }
        for status, codes in expectations.items():
            with self.subTest(status=status):
                data = json.loads(c0.render_summary_json({'status': status}))
                self.assertEqual(data['next_action_codes'], codes)
                self.assertEqual(data['authorization'], 'NO_AUTHORIZATION')
                self.assertEqual(data['collection'], 'C0_COLLECT_HOLD')

    def test_refusal_routes_allowlisted_categories_and_audit_level(self):
        fake = {'status': 'REFUSED', 'errors': ['private https://elsewhere.invalid'],
                'results': [{'status': 'REFUSED', 'error_codes': [
                    'INVALID_STRUCTURE', 'CROSS_FILE_CONFLICT', 'PRIVATE_INJECTED_CODE']}]}
        serialized = c0.render_summary_json(fake)
        data = json.loads(serialized)
        self.assertEqual(data['next_action_codes'], [
            'REVIEW_INPUT_AUDIT', 'REPAIR_INVALID_STRUCTURE',
            'RESOLVE_CROSS_FILE_CONFLICT', 'RETRY_OFFLINE_REVIEW'])
        self.assertNotIn('PRIVATE_INJECTED_CODE', serialized)
        self.assertNotIn('elsewhere.invalid', serialized)
        self.assertNotIn('https://', serialized)
        self.assertNotIn('VERIFY_INDEPENDENT_EVIDENCE', data['next_action_codes'])

    def test_mixed_refused_compared_side_cannot_offer_change_review(self):
        before = {'status': 'STRUCTURE_ONLY_PASS', 'results': [
            {'status': 'STRUCTURE_ONLY_PASS'}]}
        after = {'status': 'REFUSED', 'errors': [], 'results': [
            {'status': 'REFUSED', 'error_codes': ['INVALID_MANIFEST']}]}
        fake = {'status': 'REFUSED', 'before': before, 'after': after,
                'object_diff': {'status': 'UNAVAILABLE'}}
        result = json.loads(c0.render_summary_json(fake))
        self.assertEqual(result['next_action_codes'], [
            'REPAIR_INVALID_MANIFEST', 'RETRY_OFFLINE_REVIEW'])
        self.assertNotIn('REVIEW_OBSERVED_CHANGES', result['next_action_codes'])

    def test_unknown_status_fails_closed(self):
        data = json.loads(c0.render_summary_json({'status': 'UNRECOGNIZED_PRIVATE_STATUS'}))
        self.assertEqual(data['next_action_codes'], ['STOP_UNKNOWN_REVIEW_STATUS'])
        self.assertNotIn('UNRECOGNIZED_PRIVATE_STATUS', json.dumps(data))

    def test_cli_triage_is_private_and_matches_exit(self):
        original = json.dumps(VALID).encode()
        altered = copy.deepcopy(VALID)
        altered['objects'][0]['sha256'] = 'b' * 64
        modified = json.dumps(altered).encode()
        for input_data, status, exit_code, expected_code in (
            (original + b'\n---\n' + original, 'UNCHANGED', 0,
             'VERIFY_INDEPENDENT_EVIDENCE'),
            (original + b'\n---\n' + modified, 'CHANGED', 3,
             'REVIEW_OBSERVED_CHANGES'),
            (original + b'\n---\n{', 'REFUSED', 2,
             'REPAIR_INVALID_MANIFEST'),
        ):
            with self.subTest(status=status):
                code, output, err = run(['--compare-stdin-batches', '--summary-json',
                                         '--fail-on-change'], input_data)
                self.assertEqual((code, err), (exit_code, ''))
                data = json.loads(output)
                self.assertEqual(data['status'], status)
                self.assertIn(expected_code, data['next_action_codes'])
                self.assertNotIn('https://', output)
                self.assertNotIn('b' * 64, output)


if __name__ == '__main__':
    unittest.main()
