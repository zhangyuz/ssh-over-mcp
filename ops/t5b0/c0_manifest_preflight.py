"""Offline, fail-closed structural preflight; NEVER downloads or approves collection."""
import argparse
import json
import os
import re
import stat
from pathlib import Path
from urllib.parse import unquote, urlsplit

IDS = frozenset({'C0-W1', 'C0-P1', 'C0-R1', 'C0-T1'})
HEX = re.compile(r'^[0-9a-f]{64}$')
FIELDS = frozenset({'id', 'url', 'sha256', 'bytes', 'max_bytes'})


def validate(doc):
    errors = []
    if not isinstance(doc, dict) or set(doc) != {'schema', 'objects', 'approval'}:
        return ['top-level schema mismatch']
    if doc['schema'] != 'som-t5b0-c0-preflight-v1':
        errors.append('unknown schema')
    # This is deliberately not an approval mechanism: no file can satisfy this gate.
    if doc['approval'] is not None:
        errors.append('approval must be null; consent is an external separate decision')
    objects = doc['objects']
    if not isinstance(objects, list) or not 1 <= len(objects) <= len(IDS):
        return errors + ['objects must be finite nonempty list of at most four']
    seen = set()
    for i, obj in enumerate(objects):
        prefix = f'objects[{i}]'
        if not isinstance(obj, dict) or set(obj) != FIELDS:
            errors.append(prefix + ': object schema mismatch')
            continue
        ident = obj['id']
        if not isinstance(ident, str) or ident not in IDS or ident in seen:
            errors.append(prefix + ': unknown or repeated id')
        else:
            seen.add(ident)
        url = obj['url']
        if not isinstance(url, str) or len(url) > 2048 or any(c.isspace() for c in url):
            errors.append(prefix + ': invalid URL')
        else:
            try:
                p = urlsplit(url)
                port = p.port
            except ValueError:
                errors.append(prefix + ': malformed URL authority')
                continue
            # Reject encoded path separators/dot segments and noncanonical spellings.
            # No URL here is a download authorization or an endpoint allowlist.
            canonical_path = unquote(p.path)
            if (p.scheme != 'https' or not p.hostname or p.username or p.password
                    or port is not None or p.fragment or p.query or not p.path.startswith('/')
                    or p.path == '/' or p.netloc != p.hostname
                    or canonical_path != p.path or any(segment in ('.', '..', '') for segment in p.path.split('/')[1:])
                    or '\\' in p.path or any(ord(c) < 33 or ord(c) > 126 for c in url)):
                errors.append(prefix + ': URL not pinned to a single HTTPS object path')
        if not isinstance(obj['sha256'], str) or not HEX.fullmatch(obj['sha256']):
            errors.append(prefix + ': missing SHA256')
        size, cap = obj['bytes'], obj['max_bytes']
        if type(size) is not int or type(cap) is not int or not (0 < size <= cap <= 100_000_000):
            errors.append(prefix + ': invalid size/cap')
    return errors


def reject_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate JSON key')
        result[key] = value
    return result


def parse_manifest(data):
    return json.loads(data, object_pairs_hook=reject_duplicate_keys,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite number')))


def read_regular_manifest(path):
    flags = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW
    if hasattr(os, 'O_CLOEXEC'):
        flags |= os.O_CLOEXEC
    fd = os.open(path, flags)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise ValueError('manifest is not a regular file')
        if info.st_size > 16384:
            raise ValueError('manifest too large')
        data = os.read(fd, 16385)
        if len(data) > 16384:
            raise ValueError('manifest too large')
        if len(data) != info.st_size:
            raise ValueError('manifest size changed during read')
        return data
    finally:
        os.close(fd)


def inspect_manifest(path):
    error_codes = []
    try:
        data = read_regular_manifest(path)
        doc = parse_manifest(data)
        errors = validate(doc)
        if errors:
            error_codes.append('INVALID_STRUCTURE')
    except (OSError, UnicodeError, ValueError, TypeError, RecursionError) as exc:
        errors = [f'unreadable/invalid manifest: {type(exc).__name__}']
        error_codes.append('INVALID_MANIFEST')
    return {
        'status': 'REFUSED' if errors else 'STRUCTURE_ONLY_PASS',
        'errors': errors,
        'error_codes': error_codes,
        'authorization': 'NO_AUTHORIZATION',
        'collection': 'C0_COLLECT_HOLD',
        'network': 'NO_NETWORK',
    }


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('manifest', type=Path, nargs='?')
    p.add_argument('--json', action='store_true', help='emit a machine-readable offline report')
    p.add_argument('--batch', type=Path, nargs='+', metavar='MANIFEST',
                   help='inspect up to 16 manifests and emit one aggregate JSON report')
    args = p.parse_args()
    if args.batch is not None:
        if args.manifest is not None:
            p.error('positional manifest cannot be combined with --batch')
        if len(args.batch) > 16:
            results = []
            errors = ['batch must contain at most 16 manifests']
        else:
            results = [{'path': str(path), **inspect_manifest(path)} for path in args.batch]
            errors = []
        refused = bool(errors) or any(item['status'] == 'REFUSED' for item in results)
        print(json.dumps({
            'status': 'REFUSED' if refused else 'STRUCTURE_ONLY_PASS',
            'errors': errors,
            'results': results,
            'authorization': 'NO_AUTHORIZATION',
            'collection': 'C0_COLLECT_HOLD',
            'network': 'NO_NETWORK',
        }, sort_keys=True))
        return 2 if refused else 0
    if args.manifest is None:
        p.error('manifest is required unless --batch is specified')
    report = inspect_manifest(args.manifest)
    if args.json:
        print(json.dumps(report, sort_keys=True))
        return 2 if report['errors'] else 0
    for err in report['errors']:
        print('REFUSED:', err)
    if report['errors']:
        return 2
    print('STRUCTURE_ONLY_PASS; C0_COLLECT_HOLD; NO_NETWORK; NO_AUTHORIZATION')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
