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


def review_plan(path):
    """Return (exit_code_without_change_gate, private_report); never writes."""
    try:
        path = Path(path)
        if not _safe_name(path.name):
            raise ValueError('unsafe plan file name')
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_DIRECTORY
        if hasattr(os, 'O_CLOEXEC'):
            flags |= os.O_CLOEXEC
        dir_fd = os.open(path.parent, flags)
        try:
            if not stat.S_ISDIR(os.fstat(dir_fd).st_mode):
                raise ValueError('source directory is not regular')
            plan_bytes = c0.read_regular_manifest(path.name, dir_fd=dir_fd)
            cases = _validated_cases(plan_bytes, path.name)
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
        return 0, result
    except (OSError, ValueError, TypeError, UnicodeError, RecursionError):
        return 2, _refusal()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('plan', type=Path, help='bounded local JSON plan; all sources are sibling basenames')
    parser.add_argument('--fail-on-change', action='store_true', help='exit 3 if any valid case changes')
    if argv is None:
        import sys
        argv = sys.argv[1:]
    if argv.count('--fail-on-change') > 1:
        parser.error('--fail-on-change may occur once')
    args = parser.parse_args(argv)
    exit_code, result = review_plan(args.plan)
    print(json.dumps(result, sort_keys=True))
    if exit_code != 0:
        return exit_code
    return 3 if args.fail_on_change and result['status'] == 'CHANGED' else 0


if __name__ == '__main__':
    raise SystemExit(main())
