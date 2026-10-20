"""Offline, fail-closed structural preflight; NEVER downloads or approves collection."""
import argparse
import hashlib
import ipaddress
import json
import os
import re
import stat
import sys
from pathlib import Path
from urllib.parse import unquote, urlsplit

IDS = frozenset({'C0-W1', 'C0-P1', 'C0-R1', 'C0-T1'})
MAX_DIRECTORY_ENTRIES = 64  # Bounds iteration even when non-JSON names are ignored.
HEX = re.compile(r'^[0-9a-f]{64}$')
HOST_LABEL = re.compile(r'^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$')
FIELDS = frozenset({'id', 'url', 'sha256', 'bytes', 'max_bytes'})
NUMERIC_IP_HOST = re.compile(r'^(?:0x[0-9a-f]+|[0-9]+)(?:\.(?:0x[0-9a-f]+|[0-9]+))*$')
EVIDENCE_GAPS = (
    ('SOURCE_AUTHENTICITY', 'Independent source identity and exact material provenance not verified'),
    ('TRUST_ROOT', 'Out-of-band root, signing chain and transparency policy not verified'),
    ('TRUSTED_TIME', 'Independent time, freshness, revocation and rollback policy not verified'),
    ('EXECUTION_ENVIRONMENT', 'Isolated execution image, downloader and dependency closure not admitted'),
    ('OPERATOR_AUTHORIZATION', 'Separate operator consent to collect or execute has not been granted'),
)


def noncanonical_numeric_ip_host(host):
    """Reject alternative numeric IPv4 spellings without resolving DNS."""
    if host.rsplit('.', 1)[-1] == '0x':
        return True
    if not NUMERIC_IP_HOST.fullmatch(host):
        # Numeric final DNS labels take the IPv4 parsing path in URL clients.
        return bool(NUMERIC_IP_HOST.fullmatch(host.rsplit('.', 1)[-1]))
    try:
        return str(ipaddress.IPv4Address(host)) != host
    except ValueError:
        return True


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
    seen_urls = set()
    sha_sizes = {}
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
            if (p.scheme != 'https' or not url.startswith('https://')
                    or not p.hostname or p.username or p.password
                    or port is not None or '?' in url or '#' in url
                    or p.fragment or p.query or not p.path.startswith('/')
                    or p.path == '/' or p.netloc != p.hostname
                    or len(p.hostname) > 253
                    or any(not HOST_LABEL.fullmatch(label) for label in p.hostname.split('.'))
                    or noncanonical_numeric_ip_host(p.hostname)
                    or '%' in p.path
                    or any(ch in p.path for ch in ('<', '>', '"', '{', '}', chr(96)))
                    or canonical_path != p.path
                    or any(segment in ('.', '..', '') for segment in p.path.split('/')[1:])
                    or '\\' in p.path or any(ord(c) < 33 or ord(c) > 126 for c in url)):
                errors.append(prefix + ': URL not pinned to a single HTTPS object path')
            elif url in seen_urls:
                errors.append(prefix + ': duplicate object URL')
            else:
                seen_urls.add(url)
        if not isinstance(obj['sha256'], str) or not HEX.fullmatch(obj['sha256']):
            errors.append(prefix + ': missing SHA256')
        elif type(obj['bytes']) is int and obj['bytes'] > 0:
            previous_size = sha_sizes.get(obj['sha256'])
            if previous_size is not None and previous_size != obj['bytes']:
                errors.append(prefix + ': conflicting SHA256 declared bytes')
            else:
                sha_sizes[obj['sha256']] = obj['bytes']
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


def read_regular_manifest(path, *, dir_fd=None):
    flags = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW
    if hasattr(os, 'O_CLOEXEC'):
        flags |= os.O_CLOEXEC
    fd = os.open(path, flags, dir_fd=dir_fd)
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
        after = os.fstat(fd)
        # A same-length rewrite can otherwise yield valid JSON and a false
        # structure-only PASS. Atime is omitted: ordinary reads may update it.
        initial_identity = (info.st_dev, info.st_ino, info.st_mode, info.st_size,
                            info.st_mtime_ns, info.st_ctime_ns)
        final_identity = (after.st_dev, after.st_ino, after.st_mode, after.st_size,
                          after.st_mtime_ns, after.st_ctime_ns)
        if final_identity != initial_identity:
            raise ValueError('manifest changed during read')
        return data
    finally:
        os.close(fd)


def inspect_manifest(path, *, dir_fd=None, include_digest=False, capture_objects=False):
    error_codes = []
    digest = None
    valid_objects = None
    try:
        data = read_regular_manifest(path, dir_fd=dir_fd)
        if include_digest:
            digest = hashlib.sha256(data).hexdigest()
        doc = parse_manifest(data)
        errors = validate(doc)
        if errors:
            error_codes.append('INVALID_STRUCTURE')
        elif capture_objects:
            valid_objects = doc['objects']
    except (OSError, UnicodeError, ValueError, TypeError, RecursionError) as exc:
        errors = [f'unreadable/invalid manifest: {type(exc).__name__}']
        error_codes.append('INVALID_MANIFEST')
    report = {
        'status': 'REFUSED' if errors else 'STRUCTURE_ONLY_PASS',
        'errors': errors,
        'error_codes': error_codes,
        'authorization': 'NO_AUTHORIZATION',
        'collection': 'C0_COLLECT_HOLD',
        'network': 'NO_NETWORK',
    }
    if include_digest:
        report['sha256'] = digest
    if capture_objects:
        report['_objects'] = valid_objects
    return report


def inspect_stdin(*, capture_inventory=False):
    """Parse at most 16 KiB of explicitly piped bytes; never touch the network."""
    try:
        data = sys.stdin.buffer.read(16385)
        if len(data) > 16384:
            raise ValueError('manifest too large')
        doc = parse_manifest(data.decode('utf-8-sig'))
        errors = validate(doc)
        error_codes = ['INVALID_STRUCTURE'] if errors else []
    except (OSError, UnicodeError, ValueError, TypeError, RecursionError) as exc:
        errors = [f'unreadable/invalid manifest: {type(exc).__name__}']
        error_codes = ['INVALID_MANIFEST']
    report = {
        'status': 'REFUSED' if errors else 'STRUCTURE_ONLY_PASS',
        'errors': errors,
        'error_codes': error_codes,
        'authorization': 'NO_AUTHORIZATION',
        'collection': 'C0_COLLECT_HOLD',
        'network': 'NO_NETWORK',
    }
    if capture_inventory:
        return report, ({obj['id']: obj for obj in doc['objects']} if not errors else {})
    return report


def inspect_stdin_batch(*, capture_inventory=False, data=None):
    """Audit bounded NDJSON proposals from stdin; never interpret them as consent."""
    results = []
    errors = []
    try:
        if data is None:
            data = sys.stdin.buffer.read(16 * 16385 + 1)
        if len(data) > 16 * 16385:
            errors = ['stdin batch exceeds total byte budget']
        else:
            lines = data.split(b'\n')
            if lines and lines[-1] == b'':
                lines.pop()
            if not 1 <= len(lines) <= 16:
                errors = ['stdin batch must contain 1 to 16 manifests']
            elif any(len(line) > 16384 for line in lines):
                errors = ['stdin batch line too large']
            else:
                objects_by_line = []
                for index, line in enumerate(lines, start=1):
                    objects = None
                    try:
                        doc = parse_manifest(line.decode('utf-8-sig'))
                        item_errors = validate(doc)
                        codes = ['INVALID_STRUCTURE'] if item_errors else []
                        if not item_errors:
                            objects = doc['objects']
                    except (OSError, UnicodeError, ValueError, TypeError, RecursionError) as exc:
                        item_errors = [f'unreadable/invalid manifest: {type(exc).__name__}']
                        codes = ['INVALID_MANIFEST']
                    results.append({
                        'path': f'stdin:{index}',
                        'status': 'REFUSED' if item_errors else 'STRUCTURE_ONLY_PASS',
                        'errors': item_errors,
                        'error_codes': codes,
                        'authorization': 'NO_AUTHORIZATION',
                        'collection': 'C0_COLLECT_HOLD',
                        'network': 'NO_NETWORK',
                    })
                    objects_by_line.append(objects)
                cross_file_consistency(results, objects_by_line)
                # Only fixed diagnostics cross the untrusted stream boundary.
                redact_cross_manifest_diagnostics(results)
    except (OSError, ValueError, TypeError) as exc:
        errors = [f'unreadable/invalid stdin batch: {type(exc).__name__}']
        results = []
    refused = bool(errors) or any(item['status'] == 'REFUSED' for item in results)
    report = {
        'status': 'REFUSED' if refused else 'STRUCTURE_ONLY_PASS',
        'errors': errors,
        'results': results,
        'authorization': 'NO_AUTHORIZATION',
        'collection': 'C0_COLLECT_HOLD',
        'network': 'NO_NETWORK',
    }
    if capture_inventory:
        # Never expose a partial semantic inventory after any refusal.
        inventory = {}
        if not refused:
            for objects in objects_by_line:
                for obj in objects:
                    inventory[obj['id']] = obj
        return report, inventory
    return report


def redact_cross_manifest_diagnostics(results):
    """Strip raw URL/digest conflict values from untrusted cross-record reports."""
    for item in results:
        if ('DUPLICATE_OBJECT_ID' in item['error_codes']
                or 'CROSS_FILE_CONFLICT' in item['error_codes']):
            item['errors'] = [
                ('duplicate cross-manifest object id' if code == 'DUPLICATE_OBJECT_ID'
                 else 'conflicting cross-manifest object metadata')
                for code in item['error_codes']
                if code in ('DUPLICATE_OBJECT_ID', 'CROSS_FILE_CONFLICT')
            ]


def cross_file_consistency(results, objects_by_file):
    """Compare only structurally valid objects, without reopening input paths."""
    by_id, by_url, by_digest = {}, {}, {}
    for index, objects in enumerate(objects_by_file):
        if objects is None:
            continue
        for obj in objects:
            for group, key in ((by_id, obj['id']), (by_url, obj['url']),
                               (by_digest, obj['sha256'])):
                group.setdefault(key, []).append((index, obj))

    def refuse(members, code, reason):
        for index in sorted({index for index, _ in members}):
            item = results[index]
            item['status'] = 'REFUSED'
            if code not in item['error_codes']:
                item['error_codes'].append(code)
            if reason not in item['errors']:
                item['errors'].append(reason)

    for ident, members in sorted(by_id.items()):
        if len({index for index, _ in members}) > 1:
            refuse(members, 'DUPLICATE_OBJECT_ID', f'duplicate cross-file object id: {ident}')
            if len({(obj['url'], obj['sha256'], obj['bytes'], obj['max_bytes'])
                    for _, obj in members}) > 1:
                refuse(members, 'CROSS_FILE_CONFLICT', f'conflicting cross-file object id: {ident}')
    for url, members in sorted(by_url.items()):
        if len({index for index, _ in members}) > 1 and len({
                (obj['id'], obj['sha256'], obj['bytes'], obj['max_bytes'])
                for _, obj in members}) > 1:
            refuse(members, 'CROSS_FILE_CONFLICT', f'conflicting cross-file URL: {url}')
    for digest, members in sorted(by_digest.items()):
        if len({index for index, _ in members}) > 1 and len({
                obj['bytes'] for _, obj in members}) > 1:
            refuse(members, 'CROSS_FILE_CONFLICT', f'conflicting cross-file SHA256 size: {digest}')


def audit_fingerprint(results):
    """Deterministic digest of observed input names and exact-read byte digests."""
    if not results or any(item['sha256'] is None for item in results):
        return None
    entries = [(Path(item['path']).name, item['sha256']) for item in results]
    payload = json.dumps(entries, ensure_ascii=True, separators=(',', ':')).encode('ascii')
    return hashlib.sha256(payload).hexdigest()


def evidence_handoff():
    return {
        'status': 'UNVERIFIED',
        'gaps': [{'id': ident, 'status': 'UNVERIFIED', 'reason': reason}
                 for ident, reason in EVIDENCE_GAPS],
    }


def inspect_directory(directory, *, capture_inventory=False, require_json_only=False):
    results = []
    errors = []
    inventory = {}
    try:
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        if hasattr(os, 'O_CLOEXEC'):
            flags |= os.O_CLOEXEC
        fd = os.open(directory, flags)
        try:
            initial = os.fstat(fd)
            names = []
            with os.scandir(fd) as entries:
                for count, entry in enumerate(entries, start=1):
                    if count > MAX_DIRECTORY_ENTRIES:
                        errors = ['directory must contain at most 64 total entries']
                        break
                    if not entry.name.endswith('.json'):
                        if require_json_only:
                            errors = ['directory contains non-json entry']
                            break
                        continue
                    names.append(entry.name)
                    if len(names) > 16:
                        errors = ['directory must contain 1 to 16 .json entries']
                        break
            names.sort()
            if not errors and not 1 <= len(names) <= 16:
                errors = ['directory must contain 1 to 16 .json entries']
            if not errors:
                objects_by_file = []
                for name in names:
                    report = inspect_manifest(name, dir_fd=fd, include_digest=True,
                                              capture_objects=True)
                    objects = report.pop('_objects')
                    objects_by_file.append(objects)
                    if capture_inventory and objects is not None:
                        for obj in objects:
                            inventory[obj['id']] = obj
                    results.append({'path': str(directory / name), **report})
                cross_file_consistency(results, objects_by_file)
            final = os.fstat(fd)
            # Namespace drift can invalidate a scan even if each file read is stable.
            # Atime is omitted because a normal directory enumeration may change it.
            fields = ('st_dev', 'st_ino', 'st_mode', 'st_mtime_ns', 'st_ctime_ns')
            if any(getattr(initial, field) != getattr(final, field) for field in fields):
                errors = ['directory changed during audit']
                results = []
                inventory = {}
        finally:
            os.close(fd)
    except (OSError, ValueError) as exc:
        errors = [f'unreadable/invalid directory: {type(exc).__name__}']
        results = []
        inventory = {}
    # Sanitize at the direct directory interface, not only in CLI wrappers.
    redact_cross_manifest_diagnostics(results)
    # No refused directory may export a partially accepted semantic inventory.
    if errors or any(item['status'] == 'REFUSED' for item in results):
        inventory = {}
    if capture_inventory:
        return results, errors, inventory
    return results, errors


def directory_report(directory, *, capture_inventory=False, require_json_only=False):
    """Return the exact legacy directory report shape for reuse by comparison."""
    inspected = inspect_directory(directory, capture_inventory=capture_inventory,
                                  require_json_only=require_json_only)
    results, errors = inspected[:2]
    # Directory reports can reach CI logs; never echo proposal URLs or digests.
    redact_cross_manifest_diagnostics(results)
    refused = bool(errors) or any(item['status'] == 'REFUSED' for item in results)
    report = {
        'status': 'REFUSED' if refused else 'STRUCTURE_ONLY_PASS',
        'errors': errors,
        'passed': sum(item['status'] == 'STRUCTURE_ONLY_PASS' for item in results),
        'refused': sum(item['status'] == 'REFUSED' for item in results),
        'audit_sha256': audit_fingerprint(results),
        'evidence': evidence_handoff(),
        'results': results,
        'authorization': 'NO_AUTHORIZATION',
        'collection': 'C0_COLLECT_HOLD',
        'network': 'NO_NETWORK',
    }
    if capture_inventory:
        report['_inventory'] = inspected[2]
    return report


def semantic_object_diff(before_inventory, after_inventory):
    before_ids, after_ids = set(before_inventory), set(after_inventory)
    changed = []
    for ident in sorted(before_ids & after_ids):
        fields = sorted(field for field in ('url', 'sha256', 'bytes', 'max_bytes')
                        if before_inventory[ident][field] != after_inventory[ident][field])
        if fields:
            changed.append({'id': ident, 'fields': fields})
    return {
        'status': 'AVAILABLE',
        'added': sorted(after_ids - before_ids),
        'removed': sorted(before_ids - after_ids),
        'changed': changed,
    }


def compare_directories(before_path, after_path, *, require_json_only=False):
    """Observe two independent offline snapshots; neither is a trusted baseline."""
    before = directory_report(before_path, capture_inventory=True,
                              require_json_only=require_json_only)
    after = directory_report(after_path, capture_inventory=True,
                             require_json_only=require_json_only)
    before_inventory = before.pop('_inventory')
    after_inventory = after.pop('_inventory')
    old = {Path(item['path']).name: item for item in before['results']}
    new = {Path(item['path']).name: item for item in after['results']}
    added = sorted(new.keys() - old.keys())
    removed = sorted(old.keys() - new.keys())
    changed = sorted(name for name in old.keys() & new.keys()
                     if old[name]['sha256'] != new[name]['sha256'])
    regressions = sorted(name for name in old.keys() & new.keys()
                         if old[name]['status'] == 'STRUCTURE_ONLY_PASS'
                         and new[name]['status'] == 'REFUSED')
    refused = before['status'] == 'REFUSED' or after['status'] == 'REFUSED'
    status = ('REFUSED' if refused else
              'CHANGED' if added or removed or changed else 'UNCHANGED')
    object_diff = ({'status': 'UNAVAILABLE', 'reason': 'DIRECTORY_AUDIT_REFUSED'}
                   if refused else semantic_object_diff(before_inventory, after_inventory))
    return {
        'status': status,
        'object_diff': object_diff,
        'before': before,
        'after': after,
        'added': added,
        'removed': removed,
        'changed': changed,
        'regressions': regressions,
        'evidence': evidence_handoff(),
        'authorization': 'NO_AUTHORIZATION',
        'collection': 'C0_COLLECT_HOLD',
        'network': 'NO_NETWORK',
    }


def compare_stream_directory_reports(before, before_inventory, after, after_inventory):
    """Shared non-authorizing delta for one bounded stream and one directory."""
    refused = before['status'] == 'REFUSED' or after['status'] == 'REFUSED'
    object_diff = ({'status': 'UNAVAILABLE', 'reason': 'INPUT_AUDIT_REFUSED'}
                   if refused else semantic_object_diff(before_inventory, after_inventory))
    changed = not refused and any(object_diff[key] for key in ('added', 'removed', 'changed'))
    return {
        'status': 'REFUSED' if refused else 'CHANGED' if changed else 'UNCHANGED',
        'before': before,
        'after': after,
        'object_diff': object_diff,
        'evidence': evidence_handoff(),
        'authorization': 'NO_AUTHORIZATION',
        'collection': 'C0_COLLECT_HOLD',
        'network': 'NO_NETWORK',
    }


def compare_stdin_to_directory(before_directory, *, require_json_only=False):
    """Compare a directory baseline with an unpersisted streamed successor."""
    before = directory_report(before_directory, capture_inventory=True,
                              require_json_only=require_json_only)
    before_inventory = before.pop('_inventory')
    after, after_inventory = inspect_stdin_batch(capture_inventory=True)
    return compare_stream_directory_reports(before, before_inventory, after, after_inventory)


def compare_stdin_before_directory(after_directory, *, require_json_only=False):
    """Compare an unpersisted streamed baseline with a directory successor."""
    before, before_inventory = inspect_stdin_batch(capture_inventory=True)
    after = directory_report(after_directory, capture_inventory=True,
                             require_json_only=require_json_only)
    after_inventory = after.pop('_inventory')
    return compare_stream_directory_reports(before, before_inventory, after, after_inventory)


def compare_manifest_files(before_path, after_path):
    """Compare two independent, bounded regular-file reads; never trust either."""
    before = inspect_manifest(before_path, capture_objects=True)
    after = inspect_manifest(after_path, capture_objects=True)
    before_objects = before.pop('_objects')
    after_objects = after.pop('_objects')
    before_inventory = ({obj['id']: obj for obj in before_objects}
                        if before['status'] != 'REFUSED' else {})
    after_inventory = ({obj['id']: obj for obj in after_objects}
                       if after['status'] != 'REFUSED' else {})
    return compare_stream_directory_reports(
        before, before_inventory, after, after_inventory)


def compare_file_and_stdin(file_path, *, stdin_before=False):
    """Compare one bounded regular-file manifest and one unpersisted stdin manifest."""
    disk = inspect_manifest(file_path, capture_objects=True)
    objects = disk.pop('_objects')
    disk_inventory = ({obj['id']: obj for obj in objects}
                      if disk['status'] != 'REFUSED' else {})
    stream, stream_inventory = inspect_stdin(capture_inventory=True)
    if stdin_before:
        return compare_stream_directory_reports(stream, stream_inventory, disk, disk_inventory)
    return compare_stream_directory_reports(disk, disk_inventory, stream, stream_inventory)


def compare_paired_stdin_batches():
    """Review two untrusted NDJSON snapshots separated by an exact LF---LF."""
    delimiter = b'\n---\n'
    maximum = 2 * 16 * 16385 + len(delimiter)
    try:
        data = sys.stdin.buffer.read(maximum + 1)
        if len(data) > maximum or data.count(delimiter) != 1:
            raise ValueError('paired stdin framing or total byte budget invalid')
    except (OSError, ValueError, TypeError) as exc:
        error = f'unreadable/invalid paired stdin: {type(exc).__name__}'
        refused = {
            'status': 'REFUSED', 'errors': [error], 'results': [],
            'authorization': 'NO_AUTHORIZATION',
            'collection': 'C0_COLLECT_HOLD', 'network': 'NO_NETWORK',
        }
        return compare_stream_directory_reports(refused, {}, dict(refused), {})
    before_data, after_data = data.split(delimiter)
    before, before_inventory = inspect_stdin_batch(
        capture_inventory=True, data=before_data)
    after, after_inventory = inspect_stdin_batch(
        capture_inventory=True, data=after_data)
    return compare_stream_directory_reports(before, before_inventory, after, after_inventory)


def render_summary(report):
    """Render only controlled classifications; omit all input paths and values."""
    lines = [f"C0 offline review: {report['status']}",
             'Offline structure observation only; does not authorize collection or execution.',
             'NO_AUTHORIZATION; C0_COLLECT_HOLD; NO_NETWORK']
    sides = (('Before', report['before']), ('After', report['after'])) if 'before' in report else (
        ('Input', report),)
    for label, audit in sides:
        records = audit.get('results', [audit])
        passed = sum(item['status'] == 'STRUCTURE_ONLY_PASS' for item in records)
        refused = sum(item['status'] == 'REFUSED' for item in records)
        lines.append(f"{label}: {audit['status']}; records observed={len(records)}, "
                     f"passed={passed}, refused={refused}")
        if audit.get('errors'):
            lines.append(f'{label} diagnostics: INPUT_AUDIT_REFUSED')
        for index, item in enumerate(records, start=1):
            if item['status'] != 'REFUSED':
                continue
            codes = sorted(set(item.get('error_codes', [])) & {
                'INVALID_MANIFEST', 'INVALID_STRUCTURE', 'DUPLICATE_OBJECT_ID',
                'CROSS_FILE_CONFLICT'})
            lines.append(f"  Record {index}: REFUSED; {', '.join(codes) or 'INPUT_AUDIT_REFUSED'}")
    if all(key in report for key in ('added', 'removed', 'changed', 'regressions')):
        lines.append('Observed file changes: ' + ', '.join(
            f'{key}={len(report[key])}' for key in ('added', 'removed', 'changed', 'regressions')))
        if report['status'] == 'REFUSED':
            lines.append('File counts are partial diagnostics, not a complete inventory.')
    delta = report.get('object_diff')
    if delta is not None:
        if report['status'] == 'REFUSED' or delta['status'] != 'AVAILABLE':
            lines.append('Object changes: UNAVAILABLE')
        elif not any(delta[key] for key in ('added', 'removed', 'changed')):
            lines.append('Object changes: none')
        else:
            lines.append('Object changes: AVAILABLE')
            for key in ('added', 'removed'):
                identifiers = sorted(set(delta[key]) & IDS)
                if identifiers:
                    lines.append(f"{key.title()}: {', '.join(identifiers)}")
            for item in delta['changed']:
                if item['id'] in IDS:
                    fields = sorted(set(item['fields']) & (FIELDS - {'id'}))
                    lines.append(f"Changed {item['id']}: {', '.join(fields)}")
    lines.append('Evidence: UNVERIFIED')
    lines.extend(f'  {key}: UNVERIFIED' for key, _ in EVIDENCE_GAPS)
    return '\n'.join(lines)


GUIDANCE_ACTIONS = {
    'INVALID_MANIFEST': (
        'Replace unreadable input with a regular file or bounded UTF-8 JSON; '
        'inspect malformed framing locally without bypassing size limits.'),
    'INVALID_STRUCTURE': (
        'Correct the C0 schema, known object IDs, pinned HTTPS syntax, '
        'digest and byte caps, and null approval; do not treat a fix as approval.'),
    'DUPLICATE_OBJECT_ID': (
        'Resolve repeated object IDs across the proposal snapshot; '
        'do not choose a record without independent evidence.'),
    'CROSS_FILE_CONFLICT': (
        'Resolve conflicting URL, digest or size claims using independent '
        'offline evidence; never select an arbitrary value.'),
    'INPUT_AUDIT_REFUSED': (
        'Review local input bounds, directory entry types, stream framing '
        'and observed filesystem changes before retrying.'),
}


def render_guidance(report):
    """Emit fixed instructions only; never reuse untrusted diagnostic strings."""
    lines = ['Next actions:']
    if report['status'] == 'REFUSED':
        sides = (('Before', report['before']), ('After', report['after'])) \
            if 'before' in report else (('Input', report),)
        for label, audit in sides:
            if audit['status'] != 'REFUSED':
                continue
            codes = set()
            for item in audit.get('results', [audit]):
                if item['status'] == 'REFUSED':
                    codes.update(set(item.get('error_codes', [])) & GUIDANCE_ACTIONS.keys())
            if audit.get('errors') or not codes:
                codes.add('INPUT_AUDIT_REFUSED')
            for code in sorted(codes):
                lines.append(f'  {label} {code}: {GUIDANCE_ACTIONS[code]}')
        lines.append('  Refusal blocks semantic comparison; fix and rerun locally.')
    elif report['status'] == 'CHANGED':
        lines.append('  Review observed changes in object IDs, field names and '
                     'file counts; compare again before requesting separate approval.')
    elif report['status'] == 'STRUCTURE_ONLY_PASS':
        lines.append('  Input passed structural checks only; obtain independent '
                     'source, trust, time, environment and operator evidence.')
    elif report['status'] == 'UNCHANGED':
        lines.append('  No compared changes were observed; obtain independent '
                     'source, trust, time, environment and operator evidence.')
    else:
        lines.append('  Unrecognized review status; inspect locally and do not rely on this result.')
    lines.append('  Do not collect, execute, install or grant access based on this report.')
    return '\n'.join(lines)


MACHINE_REVIEW_ACTION_CODES = (
    ('INPUT_AUDIT_REFUSED', 'REVIEW_INPUT_AUDIT'),
    ('INVALID_MANIFEST', 'REPAIR_INVALID_MANIFEST'),
    ('INVALID_STRUCTURE', 'REPAIR_INVALID_STRUCTURE'),
    ('DUPLICATE_OBJECT_ID', 'RESOLVE_DUPLICATE_OBJECT_ID'),
    ('CROSS_FILE_CONFLICT', 'RESOLVE_CROSS_FILE_CONFLICT'),
)
MACHINE_REPORT_STATUSES = frozenset({
    'REFUSED', 'CHANGED', 'UNCHANGED', 'STRUCTURE_ONLY_PASS',
})


REVIEW_SUMMARY_SCHEMA = 'som-t5b0-c0-summary-json-v1'


REVIEW_MODES = frozenset({
    'MANIFEST_FILE', 'FILE_BATCH', 'DIRECTORY', 'STDIN_MANIFEST', 'STDIN_BATCH',
    'DIRECTORY_COMPARISON', 'DIRECTORY_TO_STDIN', 'STDIN_TO_DIRECTORY',
    'PAIRED_STDIN_COMPARISON', 'FILE_COMPARISON', 'FILE_TO_STDIN', 'STDIN_TO_FILE',
})


def render_summary_json(report, *, review_mode=None):
    """Machine-readable allowlisted observations; never serialize source values."""
    def audit_counts(audit):
        records = audit.get('results', [audit])
        safe_status = (audit['status'] if audit['status'] in MACHINE_REPORT_STATUSES
                       else 'REFUSED')
        allowed = frozenset(GUIDANCE_ACTIONS)
        codes = sorted({code for item in records if item['status'] == 'REFUSED'
                        for code in item.get('error_codes', []) if code in allowed})
        if audit.get('errors') or (audit['status'] == 'REFUSED' and not codes):
            codes = sorted(set(codes) | {'INPUT_AUDIT_REFUSED'})
        return {'status': safe_status, 'observed': len(records),
                'passed': sum(item['status'] == 'STRUCTURE_ONLY_PASS' for item in records),
                'refused': sum(item['status'] == 'REFUSED' for item in records),
                'error_codes': codes}

    raw_status = report['status']
    status = raw_status if raw_status in MACHINE_REPORT_STATUSES else 'REFUSED'
    result = {'status': status, 'review_schema': REVIEW_SUMMARY_SCHEMA,
              'authorization': 'NO_AUTHORIZATION',
              'collection': 'C0_COLLECT_HOLD', 'network': 'NO_NETWORK',
              'evidence_gaps': [key for key, _ in EVIDENCE_GAPS]}
    if review_mode in REVIEW_MODES:
        result['review_mode'] = review_mode
    if 'before' in report:
        result['before'] = audit_counts(report['before'])
        result['after'] = audit_counts(report['after'])
    else:
        result['input'] = audit_counts(report)
    if all(key in report for key in ('added', 'removed', 'changed', 'regressions')):
        result['file_counts_partial'] = report['status'] == 'REFUSED'
        result['file_counts'] = {key: len(report[key]) for key in
                                 ('added', 'removed', 'changed', 'regressions')}
    delta = report.get('object_diff')
    if delta is not None:
        available = status != 'REFUSED' and delta['status'] == 'AVAILABLE'
        result['object_changes'] = 'AVAILABLE' if available else 'UNAVAILABLE'
        # Refusal never means zero changes: comparison was not completed.
        result['object_change_counts'] = (
            {key: len(delta[key]) for key in ('added', 'removed', 'changed')}
            if available else None)
    if raw_status not in MACHINE_REPORT_STATUSES:
        actions = ['STOP_UNKNOWN_REVIEW_STATUS']
    elif status == 'REFUSED':
        audits = (result['before'], result['after']) if 'before' in result else (result['input'],)
        errors = {code for audit in audits for code in audit['error_codes']}
        actions = [action for code, action in MACHINE_REVIEW_ACTION_CODES if code in errors]
        actions.append('RETRY_OFFLINE_REVIEW')
    elif status == 'CHANGED':
        actions = ['REVIEW_OBSERVED_CHANGES', 'VERIFY_INDEPENDENT_EVIDENCE']
    else:
        actions = ['VERIFY_INDEPENDENT_EVIDENCE']
    result['next_action_codes'] = actions
    return json.dumps(result, sort_keys=True)


def emit_report(report, *, summary=False, guidance=False, summary_json=False,
                review_mode=None):
    if summary_json:
        print(render_summary_json(report, review_mode=review_mode))
    elif summary:
        output = render_summary(report)
        if guidance:
            output += '\n' + render_guidance(report)
        print(output)
    else:
        print(json.dumps(report, sort_keys=True))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('manifest', type=Path, nargs='?')
    p.add_argument('--stdin', action='store_true', help='validate <=16 KiB piped manifest offline')
    p.add_argument('--stdin-batch', action='store_true',
                   help='audit 1–16 newline-delimited <=16 KiB C0 proposals offline')
    p.add_argument('--json', action='store_true', help='emit a machine-readable offline report')
    p.add_argument('--summary', action='store_true',
                   help='emit a private human-readable offline review; excludes --json')
    p.add_argument('--summary-json', action='store_true',
                   help='emit allowlisted privacy-safe machine-readable offline review')
    p.add_argument('--guidance', action='store_true',
                   help='with --summary, append fixed privacy-safe remediation guidance')
    p.add_argument('--directory', type=Path, help='audit 1–16 .json entries in a directory, offline')
    p.add_argument('--compare-file-to-stdin', type=Path, metavar='BEFORE_FILE',
                   help='compare bounded offline manifest file with one piped successor JSON')
    p.add_argument('--compare-stdin-to-file', type=Path, metavar='AFTER_FILE',
                   help='compare one piped baseline JSON with bounded offline manifest file')
    p.add_argument('--compare-files', type=Path, nargs=2, metavar=('BEFORE', 'AFTER'),
                   help='offline semantic comparison of two <=16 KiB regular-file manifests')
    p.add_argument('--compare-directories', type=Path, nargs=2, metavar=('BEFORE', 'AFTER'),
                   help='offline review diff of two bounded directories')
    p.add_argument('--compare-stdin-to-directory', type=Path, metavar='BEFORE_DIR',
                   help='compare bounded piped NDJSON successor with offline directory baseline')
    p.add_argument('--compare-stdin-before-directory', type=Path, metavar='AFTER_DIR',
                   help='compare piped NDJSON baseline with directory successor; --fail-on-change supported')
    p.add_argument('--compare-stdin-batches', action='store_true',
                   help='compare bounded before/after NDJSON separated by LF---LF; supports --fail-on-change')
    p.add_argument('--fail-on-change', action='store_true',
                   help='with --compare-directories or --compare-stdin-to-directory, exit 3 on change; '
                        'also --compare-stdin-before-directory, --compare-stdin-batches '
                        'and --compare-files, --compare-file-to-stdin or --compare-stdin-to-file')
    p.add_argument('--require-json-only', action='store_true',
                   help='with directory audit or compare, refuse non-JSON immediate entries')
    p.add_argument('--batch', type=Path, nargs='+', metavar='MANIFEST',
                   help='inspect up to 16 manifests and emit one aggregate JSON report')
    args = p.parse_args()
    # Validate the new input route before reading any file or stdin bytes.
    if (args.compare_file_to_stdin is not None or args.compare_stdin_to_file is not None) and (
            args.manifest is not None or args.batch is not None
            or args.stdin or args.stdin_batch or args.directory is not None
            or args.compare_files is not None or args.compare_directories is not None
            or args.compare_stdin_to_directory is not None
            or args.compare_stdin_before_directory is not None
            or args.compare_stdin_batches or args.require_json_only
            or (args.compare_file_to_stdin is not None and args.compare_stdin_to_file is not None)):
        p.error('--compare-file-to-stdin/--compare-stdin-to-file cannot be combined '
                'with other input modes or --require-json-only')
    if args.compare_files is not None and (
            args.manifest is not None or args.batch is not None
            or args.stdin or args.stdin_batch or args.directory is not None
            or args.compare_directories is not None
            or args.compare_stdin_to_directory is not None
            or args.compare_stdin_before_directory is not None
            or args.compare_stdin_batches or args.require_json_only):
        p.error('--compare-files cannot be combined with other input modes or --require-json-only')
    if args.summary_json and (args.summary or args.json or args.guidance):
        p.error('--summary-json not allowed with --summary, --json or --guidance')
    if args.summary and args.json:
        p.error('--summary cannot be combined with --json')
    if args.guidance and not args.summary:
        p.error('--guidance requires --summary')
    if args.compare_stdin_batches and (
            args.stdin or args.stdin_batch or args.manifest is not None
            or args.batch is not None or args.directory is not None
            or args.compare_directories is not None
            or args.compare_stdin_to_directory is not None
            or args.compare_stdin_before_directory is not None
            or args.require_json_only):
        p.error('--compare-stdin-batches cannot be combined with other input modes or --require-json-only')
    if args.compare_stdin_before_directory is not None and (
            args.stdin or args.stdin_batch or args.manifest is not None
            or args.batch is not None or args.directory is not None
            or args.compare_directories is not None
            or args.compare_stdin_to_directory is not None):
        p.error('--compare-stdin-before-directory cannot be combined with other input modes')
    if args.compare_stdin_to_directory is not None and (
            args.stdin or args.stdin_batch or args.manifest is not None
            or args.batch is not None or args.directory is not None
            or args.compare_directories is not None):
        p.error('--compare-stdin-to-directory cannot be combined with other input modes')
    if args.stdin_batch and (args.stdin or args.manifest is not None or args.batch is not None
                             or args.directory is not None or args.compare_directories is not None
                             or args.require_json_only or args.fail_on_change):
        p.error('--stdin-batch cannot be combined with other input modes')
    if args.stdin and (args.manifest is not None or args.batch is not None
                       or args.directory is not None or args.compare_directories is not None):
        p.error('--stdin cannot be combined with other input modes')
    if (args.fail_on_change and args.compare_files is None
            and args.compare_file_to_stdin is None and args.compare_stdin_to_file is None
            and args.compare_directories is None
            and args.compare_stdin_to_directory is None
            and args.compare_stdin_before_directory is None
            and not args.compare_stdin_batches):
        p.error('--fail-on-change requires --compare-directories or '
                '--compare-stdin-to-directory or --compare-stdin-before-directory '
                'or --compare-stdin-batches or --compare-files or '
                '--compare-file-to-stdin or --compare-stdin-to-file')
    if (args.require_json_only and args.compare_directories is None and args.directory is None
            and args.compare_stdin_to_directory is None
            and args.compare_stdin_before_directory is None):
        p.error('--require-json-only requires --directory or --compare-directories '
                'or --compare-stdin-to-directory or --compare-stdin-before-directory')
    # Fixed labels reflect the selected local input route, never an input value.
    review_mode = (
        'FILE_TO_STDIN' if args.compare_file_to_stdin is not None else
        'STDIN_TO_FILE' if args.compare_stdin_to_file is not None else
        'FILE_COMPARISON' if args.compare_files is not None else
        'PAIRED_STDIN_COMPARISON' if args.compare_stdin_batches else
        'STDIN_TO_DIRECTORY' if args.compare_stdin_before_directory is not None else
        'DIRECTORY_TO_STDIN' if args.compare_stdin_to_directory is not None else
        'DIRECTORY_COMPARISON' if args.compare_directories is not None else
        'STDIN_BATCH' if args.stdin_batch else
        'STDIN_MANIFEST' if args.stdin else
        'DIRECTORY' if args.directory is not None else
        'FILE_BATCH' if args.batch is not None else
        'MANIFEST_FILE'
    )
    if args.compare_file_to_stdin is not None or args.compare_stdin_to_file is not None:
        stdin_before = args.compare_stdin_to_file is not None
        path = (args.compare_stdin_to_file if stdin_before else args.compare_file_to_stdin)
        report = compare_file_and_stdin(path, stdin_before=stdin_before)
        emit_report(report, summary=args.summary, guidance=args.guidance,
                    summary_json=args.summary_json, review_mode=review_mode)
        if report['status'] == 'REFUSED':
            return 2
        if args.fail_on_change and report['status'] == 'CHANGED':
            return 3
        return 0
    if args.compare_files is not None:
        report = compare_manifest_files(*args.compare_files)
        emit_report(report, summary=args.summary, guidance=args.guidance,
                    summary_json=args.summary_json, review_mode=review_mode)
        if report['status'] == 'REFUSED':
            return 2
        if args.fail_on_change and report['status'] == 'CHANGED':
            return 3
        return 0
    if args.compare_stdin_batches:
        report = compare_paired_stdin_batches()
        emit_report(report, summary=args.summary, guidance=args.guidance,
                    summary_json=args.summary_json, review_mode=review_mode)
        if report['status'] == 'REFUSED':
            return 2
        if args.fail_on_change and report['status'] == 'CHANGED':
            return 3
        return 0
    if args.stdin_batch:
        report = inspect_stdin_batch()
        emit_report(report, summary=args.summary, guidance=args.guidance,
                    summary_json=args.summary_json, review_mode=review_mode)
        return 2 if report['status'] == 'REFUSED' else 0
    if args.compare_stdin_before_directory is not None:
        report = compare_stdin_before_directory(
            args.compare_stdin_before_directory, require_json_only=args.require_json_only)
        emit_report(report, summary=args.summary, guidance=args.guidance,
                    summary_json=args.summary_json, review_mode=review_mode)
        if report['status'] == 'REFUSED':
            return 2
        if args.fail_on_change and report['status'] == 'CHANGED':
            return 3
        return 0
    if args.compare_stdin_to_directory is not None:
        report = compare_stdin_to_directory(
            args.compare_stdin_to_directory, require_json_only=args.require_json_only)
        emit_report(report, summary=args.summary, guidance=args.guidance,
                    summary_json=args.summary_json, review_mode=review_mode)
        if report['status'] == 'REFUSED':
            return 2
        if args.fail_on_change and report['status'] == 'CHANGED':
            return 3
        return 0
    if args.compare_directories is not None:
        if args.manifest is not None or args.batch is not None or args.directory is not None:
            p.error('--compare-directories cannot be combined with other input modes')
        report = compare_directories(*args.compare_directories,
                                     require_json_only=args.require_json_only)
        emit_report(report, summary=args.summary, guidance=args.guidance,
                    summary_json=args.summary_json, review_mode=review_mode)
        if report['status'] == 'REFUSED':
            return 2
        if args.fail_on_change and report['status'] == 'CHANGED':
            return 3
        return 0
    if args.directory is not None:
        if args.manifest is not None or args.batch is not None:
            p.error('--directory cannot be combined with positional manifest or --batch')
        report = directory_report(args.directory, require_json_only=args.require_json_only)
        emit_report(report, summary=args.summary, guidance=args.guidance,
                    summary_json=args.summary_json, review_mode=review_mode)
        return 2 if report['status'] == 'REFUSED' else 0
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
        report = {
            'status': 'REFUSED' if refused else 'STRUCTURE_ONLY_PASS',
            'errors': errors,
            'results': results,
            'authorization': 'NO_AUTHORIZATION',
            'collection': 'C0_COLLECT_HOLD',
            'network': 'NO_NETWORK',
        }
        emit_report(report, summary=args.summary, guidance=args.guidance,
                    summary_json=args.summary_json, review_mode=review_mode)
        return 2 if refused else 0
    if args.stdin:
        report = inspect_stdin()
    else:
        if args.manifest is None:
            p.error('manifest is required unless --batch or --stdin is specified')
        report = inspect_manifest(args.manifest)
    if args.json or args.summary or args.summary_json:
        emit_report(report, summary=args.summary, guidance=args.guidance,
                    summary_json=args.summary_json, review_mode=review_mode)
        return 2 if report['errors'] else 0
    for err in report['errors']:
        print('REFUSED:', err)
    if report['errors']:
        return 2
    print('STRUCTURE_ONLY_PASS; C0_COLLECT_HOLD; NO_NETWORK; NO_AUTHORIZATION')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
