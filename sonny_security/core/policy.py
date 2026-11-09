"""Optional trusted Lua policy loader."""
from pathlib import Path
import shutil
import subprocess

DEFAULTS = {
    'strict-transport-security': 'high',
    'content-security-policy': 'medium',
    'x-content-type-options': 'medium',
    'referrer-policy': 'low',
    'permissions-policy': 'low',
}

def load_policy(script=None):
    rules = dict(DEFAULTS)
    if script is None:
        return rules
    lua = next((shutil.which(n) for n in ('lua', 'lua5.4', 'lua5.3', 'luajit')
                if shutil.which(n)), None)
    if not lua:
        raise ValueError('Lua not found on PATH; install Lua or omit --policy.')
    result = subprocess.run([lua, str(Path(script).expanduser().resolve())],
                            capture_output=True, text=True, check=True, timeout=10)
    for line in result.stdout.splitlines():
        if not line.strip() or line.startswith('#'):
            continue
        name, sep, severity = line.partition('\t')
        if (not sep or not name or any(c not in 'abcdefghijklmnopqrstuvwxyz0123456789-' for c in name)
                or severity not in ('low', 'medium', 'high')):
            raise ValueError('Invalid Lua policy line: ' + repr(line))
        rules[name] = severity
    return rules
