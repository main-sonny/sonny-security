"""SHA-256 manifests. Never deletes or repairs scanned files."""
import hashlib
import json
import os
from pathlib import Path


def sha256(path):
    value = hashlib.sha256()
    with Path(path).open('rb') as source:
        for block in iter(lambda: source.read(1024 * 1024), b''):
            value.update(block)
    return value.hexdigest()


def snapshot(folder, exclude=None):
    root = Path(folder).expanduser().resolve()
    if not root.is_dir():
        raise ValueError('Scan root must be a directory.')
    entries = {}
    def fail(error):
        raise error
    for current, dirs, names in os.walk(root, followlinks=False, onerror=fail):
        dirs[:] = sorted(d for d in dirs if not Path(current, d).is_symlink())
        for name in sorted(names):
            path = Path(current, name)
            if path.is_symlink() or not path.is_file() or path.resolve() == exclude:
                continue
            entries[path.relative_to(root).as_posix()] = sha256(path)
    return entries


def create(folder, manifest):
    destination = Path(manifest).expanduser().resolve()
    data = {'schema': 1, 'algorithm': 'sha256', 'files': snapshot(folder, destination)}
    # Exclusive creation protects existing baselines from accidental replacement.
    with destination.open('x', encoding='utf-8') as output:
        json.dump(data, output, indent=2, sort_keys=True)
    return {'manifest': str(destination), 'tracked_files': len(data['files'])}


def verify(folder, manifest):
    source = Path(manifest).expanduser().resolve()
    data = json.loads(source.read_text(encoding='utf-8'))
    if (not isinstance(data, dict) or data.get('schema') != 1
            or data.get('algorithm') != 'sha256' or not isinstance(data.get('files'), dict)):
        raise ValueError('Unsupported or invalid manifest.')
    previous = data['files']
    if any(not isinstance(k, str) or not isinstance(v, str) or len(v) != 64
           or any(c not in '0123456789abcdef' for c in v) for k, v in previous.items()):
        raise ValueError('Invalid manifest entries.')
    current = snapshot(folder, source)
    added = sorted(current.keys() - previous.keys())
    removed = sorted(previous.keys() - current.keys())
    changed = sorted(k for k in current.keys() & previous.keys() if current[k] != previous[k])
    return {'matches': not (added or removed or changed), 'added': added,
            'removed': removed, 'changed': changed}
