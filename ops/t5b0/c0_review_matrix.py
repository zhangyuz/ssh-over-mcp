"""Bounded offline before×after matrix review with one source observation per file.

A local matrix config lists up to eight before and eight after source groups.
The tool compares all pairs via the established C0 semantic validator. It
never authorizes sources, collects artifacts, writes to inputs, or uses network.
"""

import argparse
import json
import os
import stat
from pathlib import Path

import c0_manifest_preflight as c0
import c0_review_plan as plan

MATRIX_SCHEMA = 'som-t5b0-c0-review-matrix-v1'
SUMMARY_SCHEMA = 'som-t5b0-c0-review-matrix-summary-v1'
MAX_GROUPS_PER_SIDE = 8
MAX_UNIQUE_SOURCES = 32


def _refusal():
    """No partial observed results can survive a refused matrix."""
    return {
        'schema': SUMMARY_SCHEMA,
        'status': 'REFUSED',
        'before_count': None,
        'after_count': None,
        'total_cells': None,
        'changed_cells': None,
        'unchanged_cells': None,
        'cells': [],
        'next_action_codes': ['RETRY_OFFLINE_REVIEW'],
        'network': 'NO_NETWORK',
        'authorization': 'NO_AUTHORIZATION',
        'collection': 'C0_COLLECT_HOLD',
        'evidence_gaps': [code for code, _ in c0.EVIDENCE_GAPS],
    }


def _validate_matrix(data, config_basename):
    """Validate whole matrix and total file budget before any source I/O."""
    doc = c0.parse_manifest(data.decode('utf-8-sig'))
    if (not isinstance(doc, dict)
            or set(doc) != {'schema', 'before', 'after'}
            or doc['schema'] != MATRIX_SCHEMA):
        raise ValueError('invalid matrix schema')
    sources = {}
    validated = []
    for label in ('before', 'after'):
        values = doc[label]
        if (not isinstance(values, list)
                or not 1 <= len(values) <= MAX_GROUPS_PER_SIDE):
            raise ValueError('invalid group count')
        groups = []
        for value in values:
            # Reuse the existing strict review-plan source shape/duplicate-
            # key/basename limits; a virtual one-case plan reads no sources.
            shape = {'schema': plan.PLAN_SCHEMA,
                     'cases': [{'before': value, 'after': value}]}
            one = plan._validated_cases(
                json.dumps(shape).encode('utf-8'), config_basename)[0][0]
            kind, names = one
            for name in names:
                previous = sources.setdefault(name, kind)
                if previous != kind:
                    raise ValueError('source filename used with incompatible formats')
            groups.append(one)
        validated.append(tuple(groups))
    if len(sources) > MAX_UNIQUE_SOURCES:
        raise ValueError('matrix source budget exceeded')
    return tuple(validated)


def review_matrix(path):
    """Return (exit_code_without_change_flag, fixed-private report), no writes."""
    try:
        path = Path(path)
        if not plan._safe_name(path.name):
            raise ValueError('unsafe config basename')
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_DIRECTORY
        if hasattr(os, 'O_CLOEXEC'):
            flags |= os.O_CLOEXEC
        dir_fd = os.open(path.parent, flags)
        try:
            if not stat.S_ISDIR(os.fstat(dir_fd).st_mode):
                raise ValueError('unsafe config directory')
            config = c0.read_regular_manifest(path.name, dir_fd=dir_fd)
            before_groups, after_groups = _validate_matrix(config, path.name)
            cache = {}
            cells = []
            # Each unique source name is opened only once via the shared cache.
            for before_index, before_spec in enumerate(before_groups, start=1):
                before_report, before_objects = plan._side_report(
                    before_spec, dir_fd, cache)
                for after_index, after_spec in enumerate(after_groups, start=1):
                    after_report, after_objects = plan._side_report(
                        after_spec, dir_fd, cache)
                    comparison = c0.compare_stream_directory_reports(
                        before_report, before_objects, after_report, after_objects)
                    if comparison['status'] == 'REFUSED':
                        raise ValueError('refused source comparison')
                    private = json.loads(c0.render_summary_json(comparison))
                    cells.append({
                        'before_index': before_index,
                        'after_index': after_index,
                        'status': private['status'],
                        'object_change_counts': private['object_change_counts'],
                        'object_field_change_counts': private['object_field_change_counts'],
                    })
        finally:
            os.close(dir_fd)
        changed = sum(item['status'] == 'CHANGED' for item in cells)
        result = {
            'schema': SUMMARY_SCHEMA,
            'status': 'CHANGED' if changed else 'UNCHANGED',
            'before_count': len(before_groups),
            'after_count': len(after_groups),
            'total_cells': len(cells),
            'changed_cells': changed,
            'unchanged_cells': len(cells) - changed,
            'cells': cells,
            'next_action_codes': (
                ['REVIEW_OBSERVED_CHANGES', 'VERIFY_INDEPENDENT_EVIDENCE']
                if changed else ['VERIFY_INDEPENDENT_EVIDENCE']),
            'network': 'NO_NETWORK',
            'authorization': 'NO_AUTHORIZATION',
            'collection': 'C0_COLLECT_HOLD',
            'evidence_gaps': [code for code, _ in c0.EVIDENCE_GAPS],
        }
        return 0, result
    except (OSError, ValueError, KeyError, TypeError, UnicodeError, RecursionError):
        return 2, _refusal()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('matrix', type=Path, help='one strict local matrix config JSON')
    parser.add_argument('--fail-on-change', action='store_true',
                        help='exit 3 if any valid matrix comparison differs')
    if argv is None:
        import sys
        argv = sys.argv[1:]
    if argv.count('--fail-on-change') > 1:
        parser.error('--fail-on-change must occur at most once')
    args = parser.parse_args(argv)
    code, result = review_matrix(args.matrix)
    print(json.dumps(result, sort_keys=True))
    if code:
        return code
    return 3 if args.fail_on_change and result['status'] == 'CHANGED' else 0


if __name__ == '__main__':
    raise SystemExit(main())
