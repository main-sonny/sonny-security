# SONNY Security Toolkit

**Developer: Sonny** • Version 1.0.0 • Python 3.10+ • Optional Lua 5.3/5.4 or LuaJIT

A modular, defensive cybersecurity CLI with an ASCII banner, automatic terminal colors, JSON reports, and customizable Lua header policies. Standard-library-only Python runtime. No exploitation, credential attacks, or bulk scanning.

## Structure

```text
sonny-security/
├── pyproject.toml
├── README.md
├── .gitignore
├── sonny_security/
│   ├── __init__.py
│   ├── __main__.py
│   ├── cli.py
│   ├── core/
│   │   ├── __init__.py
│   │   ├── output.py
│   │   └── policy.py
│   └── modules/
│       ├── __init__.py
│       ├── network.py
│       ├── integrity.py
│       └── permissions.py
├── lua/
│   └── header_policy.lua
└── tests/
    └── test_toolkit.py
```

## Run

Extract the archive, open a terminal in `sonny-security`, then:

```sh
python3 -m sonny_security --help
```

No install required. On Windows substitute `python` for `python3` and use Windows paths. The permission audit is POSIX-only; other modules are cross-platform.

Optional virtual-environment installation (build tooling may need internet):

```sh
python3 -m venv .venv
# Linux/macOS:
. .venv/bin/activate
# Windows PowerShell instead: .venv\Scripts\Activate.ps1
python -m pip install -e .
sonny --help
```

## Commands

Only check systems you own or have permission to assess. Replace `your-domain.example` with your authorized hostname.

```sh
# OS resolver address lookup, not a DNS-record inventory
python3 -m sonny_security dns your-domain.example

# Validated TLS handshake; certificate expiry, issuer, protocol, cipher
python3 -m sonny_security tls your-domain.example --port 443

# One HTTPS GET; inspect headers, do not read the response body or follow redirects
python3 -m sonny_security headers https://your-domain.example/

# Extend default header-presence rules with Lua
python3 -m sonny_security headers https://your-domain.example/ --policy lua/header_policy.lua

# Local file SHA-256
python3 -m sonny_security hash ./download.zip

# Create a baseline (refuses to overwrite an existing manifest)
python3 -m sonny_security baseline ./project ./baseline.json

# Compare current contents: added, removed, changed
python3 -m sonny_security verify ./project ./baseline.json

# Read-only POSIX world-writable and setuid/setgid checks
python3 -m sonny_security permissions ./project

# Machine-readable report: --json goes BEFORE the subcommand
python3 -m sonny_security --json headers https://your-domain.example/ > report.json
```

Exit codes: `0` command completed (findings can still be present), `1` runtime error, `2` integrity mismatch or argument error, `130` user interruption. Permission audit reports `complete: false` if it encounters inaccessible paths; inspect this field rather than relying solely on the exit code.

## Python + Lua architecture

Python owns argument validation, networking, hashing, filesystem checks, and reporting. Lua generates header policy rules via `header-name<TAB>severity`. Allowed severity values are `low`, `medium`, and `high`. Rules extend or override Python defaults. The Lua directory stays separate from the Python package; supply its explicit path when using an installed command.

Lua is optional and must be available on PATH for `--policy`. Only run trusted policy scripts: they execute as your user, are not sandboxed, and can access your machine. Script execution has a 10-second timeout. Python provides built-in defaults when no policy is supplied.

## Scope and limitations

- Header checks detect missing/empty headers, not invalid or insecure values. Requirements vary by application; findings are review prompts, not proof of a vulnerability or security certification.
- HTTPS/TLS use the Python/platform CA trust configuration, enforce hostname validation, and use an 8-second socket timeout. There is no certificate-revocation check, exhaustive protocol/cipher audit, redirect following, or whole-command deadline. DNS lookup duration depends on the OS resolver.
- Network requests contact the supplied target directly; there is no application telemetry or automatic upload of local files. Do not expose this CLI as a public server accepting untrusted targets without access controls and network isolation.
- Integrity manifests are unsigned: store them somewhere attackers cannot modify. Comparisons track regular file content only, excluding symlinks and the manifest itself. Metadata, empty directories, and ACLs are not tracked. Use a quiet filesystem; this is not an atomic snapshot. Interrupted manifest creation can leave an incomplete file.
- Permission checks examine mode bits, not ACLs or effective access. A world-writable sticky-bit temp folder can be legitimate. No permissions are changed.
- No file deletion, automatic repairs, privilege escalation, or automatic exploitation. Only `baseline` writes a local manifest; redirected reports are written by your shell.
- Reports can contain sensitive paths and server headers, including cookies. Protect report files and redact them before sharing.
- Set `NO_COLOR=1` to disable terminal colors. JSON escaping protects output from raw terminal control sequences.

## Tests

```sh
python3 -m unittest discover -s tests -v
```

Tests cover hashes, integrity change tracking and overwrite protection, rejected HTTP URLs, mocked header checks, default policies, and CLI error handling. They do not perform live network requests or require Lua.
