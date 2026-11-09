"""POSIX mode-bit checks, not an ACL or effective-access audit."""
import os
from pathlib import Path
import stat


def audit(folder):
    if os.name != 'posix':
        raise ValueError('Permission auditing requires a POSIX system (Linux/macOS).')
    root = Path(folder).expanduser().resolve()
    if not root.is_dir():
        raise ValueError('Scan root must be a directory.')
    findings, errors = [], []
    def inspect(path):
        try:
            mode = path.lstat().st_mode
            if stat.S_ISLNK(mode):
                return
            issues = []
            if mode & stat.S_IWOTH:
                issues.append('world-writable')
            if stat.S_ISREG(mode) and mode & (stat.S_ISUID | stat.S_ISGID):
                issues.append('setuid/setgid file: review necessity')
            if issues:
                findings.append({'path': str(path.relative_to(root)),
                                 'mode': oct(stat.S_IMODE(mode)), 'issues': issues})
        except OSError as error:
            errors.append(str(error))
    inspect(root)
    for current, dirs, names in os.walk(root, followlinks=False,
                                       onerror=lambda error: errors.append(str(error))):
        dirs[:] = sorted(d for d in dirs if not Path(current, d).is_symlink())
        for name in dirs + sorted(names):
            inspect(Path(current, name))
    return {'findings': findings, 'errors': errors, 'complete': not errors,
            'note': 'Review findings in context. Sticky-bit public temp directories may be intentional. '
                    'No permission changes are made; ACLs are not examined.'}
