"""Bounded, non-authorizing offline review of several named local C0 comparisons.

Each plan is a single JSON file and all source basenames live in its parent
folder. No source is reopened between comparisons, and no input path or
manifest-derived identifier is emitted in the fixed private machine report.
"""

import argparse
import copy
import json
import os
import re
import stat
from pathlib import Path

import c0_manifest_preflight as c0

PLAN_SCHEMA = 'som-t5b0-c0-review-plan-v1'
SUMMARY_SCHEMA = 'som-t5b0-c0-review-plan-summary-v1'
MAX_CHECKS = 8
MAX_SOURCES = 32
SAFE_NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,79}')

POLICY_SCHEMA = 'som-t5b0-c0-review-policy-v1'
POLICY_SUMMARY_SCHEMA = 'som-t5b0-c0-review-policy-summary-v1'
FIELDS = ('url', 'sha256', 'bytes', 'max_bytes')
BUDGET_KEYS = ('max_added', 'max_removed', 'max_changed')
CASE_KEYS = frozenset((*BUDGET_KEYS, 'deny_changed_fields'))
AGGREGATE_KEYS = frozenset((*BUDGET_KEYS, 'max_changed_cases'))


def _policy_refusal():
    output = _refusal()
    output.update(schema=POLICY_SUMMARY_SCHEMA, review_status=None,
                  policy_violation_cases=None, aggregate_violation_codes=[])
    return output


def _validate_policy(data, count):
    policy = c0.parse_manifest(data.decode('utf-8-sig'))
    if (not isinstance(policy, dict)
            or set(policy) != {'schema', 'case_limits', 'aggregate_limits'}
            or policy['schema'] != POLICY_SCHEMA
            or not isinstance(policy['case_limits'], list)
            or len(policy['case_limits']) != count
            or not isinstance(policy['aggregate_limits'], dict)
            or set(policy['aggregate_limits']) != AGGREGATE_KEYS):
        raise ValueError('invalid policy schema or cardinality')
    for rule in policy['case_limits']:
        if not isinstance(rule, dict) or set(rule) != CASE_KEYS:
            raise ValueError('invalid case policy')
        fields = rule['deny_changed_fields']
        if (not isinstance(fields, list) or not all(isinstance(x, str) for x in fields)
                or fields != [x for x in FIELDS if x in fields]):
            raise ValueError('invalid denied field set')
        for key in BUDGET_KEYS:
            _budget(rule[key])
    for key in AGGREGATE_KEYS:
        _budget(policy['aggregate_limits'][key])
    return policy


def _budget(value):
    if type(value) is not int or not 0 <= value <= 4096:
        raise ValueError('invalid numeric budget')
    return value


def _apply_policy(summary, policy):
    result = dict(summary)
    result['schema'] = POLICY_SUMMARY_SCHEMA
    result['review_status'] = summary['status']
    totals = {key: 0 for key in ('added', 'removed', 'changed')}
    annotated = []
    for record, rule in zip(summary['cases'], policy['case_limits'], strict=True):
        counts = record['object_change_counts']
        fields = record['object_field_change_counts']
        violations = []
        for kind in ('added', 'removed', 'changed'):
            totals[kind] += counts[kind]
            if counts[kind] > rule['max_' + kind]:
                violations.append('CASE_MAX_' + kind.upper())
        for field in rule['deny_changed_fields']:
            if fields[field] > 0:
                violations.append('CASE_DENY_' + field.upper())
        annotated.append({**record, 'policy_status': 'VIOLATION' if violations else 'PASS',
                          'violation_codes': sorted(violations)})
    limits = policy['aggregate_limits']
    aggregate_codes = []
    for kind in ('added', 'removed', 'changed'):
        if totals[kind] > limits['max_' + kind]:
            aggregate_codes.append('TOTAL_MAX_' + kind.upper())
    if summary['changed_cases'] > limits['max_changed_cases']:
        aggregate_codes.append('TOTAL_MAX_CHANGED_CASES')
    violations = sum(x['policy_status'] == 'VIOLATION' for x in annotated)
    overall = bool(violations or aggregate_codes)
    result.update(status='POLICY_VIOLATION' if overall else 'POLICY_PASS',
                  cases=annotated, policy_violation_cases=violations,
                  aggregate_violation_codes=sorted(aggregate_codes),
                  next_action_codes=(['REVIEW_POLICY_VIOLATIONS', 'VERIFY_INDEPENDENT_EVIDENCE']
                                     if overall else ['VERIFY_INDEPENDENT_EVIDENCE']))
    return (3 if overall else 0), result


def _refusal():
    return {
        'schema': SUMMARY_SCHEMA, 'status': 'REFUSED',
        'total_cases': None, 'changed_cases': None, 'unchanged_cases': None,
        'cases': [], 'next_action_codes': ['RETRY_OFFLINE_REVIEW'],
        'network': 'NO_NETWORK', 'authorization': 'NO_AUTHORIZATION',
        'collection': 'C0_COLLECT_HOLD',
        'evidence_gaps': [key for key, _ in c0.EVIDENCE_GAPS],
    }


def _safe_name(value):
    return (isinstance(value, str) and value not in ('.', '..')
            and SAFE_NAME.fullmatch(value) is not None)


def _validated_cases(data, plan_name):
    """Validate the entire finite plan *before* reading its referenced files."""
    doc = c0.parse_manifest(data.decode('utf-8-sig'))
    if (not isinstance(doc, dict) or set(doc) != {'schema', 'cases'}
            or doc['schema'] != PLAN_SCHEMA or not isinstance(doc['cases'], list)
            or not 1 <= len(doc['cases']) <= MAX_CHECKS):
        raise ValueError('invalid plan schema/count')
    sources = {}
    parsed = []
    for case in doc['cases']:
        if not isinstance(case, dict) or set(case) != {'before', 'after'}:
            raise ValueError('invalid case')
        endpoints = []
        for label in ('before', 'after'):
            side = case[label]
            if not isinstance(side, dict) or len(side) != 1:
                raise ValueError('invalid side')
            if 'json_files' in side:
                names = side['json_files']
                kind = 'json'
                if (not isinstance(names, list) or not 1 <= len(names) <= 16
                        or len(names) != len({x for x in names if isinstance(x, str)})):
                    raise ValueError('invalid json file set')
            elif 'ndjson_file' in side:
                names = [side['ndjson_file']]
                kind = 'ndjson'
            else:
                raise ValueError('invalid side type')
            for name in names:
                if not _safe_name(name) or name == plan_name:
                    raise ValueError('unsafe name')
                old = sources.setdefault(name, kind)
                if old != kind:
                    raise ValueError('conflicting source type')
            endpoints.append((kind, tuple(names)))
        parsed.append(tuple(endpoints))
    if len(sources) > MAX_SOURCES:
        raise ValueError('too many unique source files')
    return parsed


def _inspect_json(name, dir_fd):
    report = c0.inspect_manifest(name, dir_fd=dir_fd, capture_objects=True)
    objects = report.pop('_objects')
    return report, objects


def _inspect_ndjson(name, dir_fd):
    data = c0.read_regular_manifest(name, dir_fd=dir_fd, max_bytes=16 * 16385)
    return c0.inspect_stdin_batch(data=data, capture_inventory=True)


def _side_report(spec, dir_fd, cache):
    kind, names = spec
    if kind == 'ndjson':
        name = names[0]
        if name not in cache:
            cache[name] = _inspect_ndjson(name, dir_fd)
        report, inventory = cache[name]
        if report['status'] == 'REFUSED':
            raise ValueError('invalid batch snapshot')
        return report, inventory

    reports, contents = [], []
    for name in names:
        if name not in cache:
            cache[name] = _inspect_json(name, dir_fd)
        report, objects = cache[name]
        if report['status'] == 'REFUSED' or objects is None:
            raise ValueError('invalid manifest snapshot')
        reports.append({'path': name, **copy.deepcopy(report)})
        contents.append(objects)
    c0.cross_file_consistency(reports, contents)
    c0.redact_cross_manifest_diagnostics(reports)
    if any(item['status'] == 'REFUSED' for item in reports):
        raise ValueError('cross-file conflicts')
    inventory = {obj['id']: obj for objects in contents for obj in objects}
    result = {
        'status': 'STRUCTURE_ONLY_PASS', 'errors': [], 'results': reports,
        'network': 'NO_NETWORK', 'authorization': 'NO_AUTHORIZATION',
        'collection': 'C0_COLLECT_HOLD',
    }
    return result, inventory


def review_plan(path, *, policy_name=None):
    """Review an offline plan; opt-in policy is checked before source reads."""
    try:
        path = Path(path)
        if not _safe_name(path.name):
            raise ValueError('unsafe plan file name')
        if policy_name is not None and (not _safe_name(policy_name)
                                        or policy_name == path.name):
            raise ValueError('invalid policy file name')
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_DIRECTORY
        if hasattr(os, 'O_CLOEXEC'):
            flags |= os.O_CLOEXEC
        dir_fd = os.open(path.parent, flags)
        try:
            if not stat.S_ISDIR(os.fstat(dir_fd).st_mode):
                raise ValueError('source directory is not regular')
            plan_bytes = c0.read_regular_manifest(path.name, dir_fd=dir_fd)
            cases = _validated_cases(plan_bytes, path.name)
            policy = None
            if policy_name is not None:
                # Policy is a separate safe regular file; validate its shape and
                # full case alignment before opening any referenced source.
                if any(policy_name in names for case in cases for _, names in case):
                    raise ValueError('policy cannot be a reviewed source')
                policy = _validate_policy(c0.read_regular_manifest(
                    policy_name, dir_fd=dir_fd, max_bytes=4096), len(cases))
            cache, results = {}, []
            for idx, (before_spec, after_spec) in enumerate(cases, start=1):
                before, old = _side_report(before_spec, dir_fd, cache)
                after, new = _side_report(after_spec, dir_fd, cache)
                compared = c0.compare_stream_directory_reports(before, old, after, new)
                if compared['status'] == 'REFUSED':
                    raise ValueError('refused comparison')
                private = json.loads(c0.render_summary_json(compared))
                results.append({
                    'index': idx,
                    'status': private['status'],
                    'object_change_counts': private['object_change_counts'],
                    'object_field_change_counts': private['object_field_change_counts'],
                })
        finally:
            os.close(dir_fd)
        changed = sum(x['status'] == 'CHANGED' for x in results)
        result = {
            'schema': SUMMARY_SCHEMA,
            'status': 'CHANGED' if changed else 'UNCHANGED',
            'total_cases': len(results),
            'changed_cases': changed,
            'unchanged_cases': len(results) - changed,
            'cases': results,
            'next_action_codes': (['REVIEW_OBSERVED_CHANGES', 'VERIFY_INDEPENDENT_EVIDENCE']
                                  if changed else ['VERIFY_INDEPENDENT_EVIDENCE']),
            'network': 'NO_NETWORK', 'authorization': 'NO_AUTHORIZATION',
            'collection': 'C0_COLLECT_HOLD',
            'evidence_gaps': [key for key, _ in c0.EVIDENCE_GAPS],
        }
        return _apply_policy(result, policy) if policy is not None else (0, result)
    except (OSError, ValueError, TypeError, UnicodeError, RecursionError):
        return 2, _policy_refusal() if policy_name is not None else _refusal()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('plan', type=Path, help='bounded local JSON plan; all sources are sibling basenames')
    parser.add_argument('--fail-on-change', action='store_true', help='exit 3 if any valid case changes')
    parser.add_argument('--policy-file', metavar='POLICY_JSON',
                        help='enforce a bounded local case/aggregate offline change-budget policy')
    if argv is None:
        import sys
        argv = sys.argv[1:]
    if argv.count('--fail-on-change') > 1:
        parser.error('--fail-on-change may occur once')
    args = parser.parse_args(argv)
    if args.policy_file is not None and args.fail_on_change:
        parser.error('--policy-file and --fail-on-change are mutually exclusive')
    exit_code, result = review_plan(args.plan, policy_name=args.policy_file)
    print(json.dumps(result, sort_keys=True))
    if exit_code != 0:
        return exit_code
    return 3 if args.fail_on_change and result['status'] == 'CHANGED' else 0


if __name__ == '__main__':
    raise SystemExit(main())
