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


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('manifest', type=Path)
    args = p.parse_args()
    try:
        data = read_regular_manifest(args.manifest)
        doc = parse_manifest(data)
        errors = validate(doc)
    except (OSError, UnicodeError, ValueError, TypeError, RecursionError) as exc:
        errors = [f'unreadable/invalid manifest: {type(exc).__name__}']
    for err in errors:
        print('REFUSED:', err)
    if errors:
        return 2
    print('STRUCTURE_ONLY_PASS; C0_COLLECT_HOLD; NO_NETWORK; NO_AUTHORIZATION')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
