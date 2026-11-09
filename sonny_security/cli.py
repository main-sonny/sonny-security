"""Command routing; developer: Sonny."""
import argparse
import sys
from .core.output import show
from .core.policy import load_policy
from .modules import network, integrity, permissions


def port_number(value):
    number = int(value)
    if not 1 <= number <= 65535:
        raise argparse.ArgumentTypeError('port must be between 1 and 65535')
    return number


def main(argv=None):
    parser = argparse.ArgumentParser(description='SONNY Security Toolkit | Developer: Sonny')
    parser.add_argument('--json', action='store_true', help='Machine-readable output without banner')
    parser.add_argument('--version', action='version', version='Sonny Security 1.0.0')
    commands = parser.add_subparsers(dest='command', required=True)
    p = commands.add_parser('dns', help='Resolve a single hostname')
    p.add_argument('host')
    p = commands.add_parser('tls', help='Verify TLS certificate and show negotiated connection')
    p.add_argument('host')
    p.add_argument('--port', type=port_number, default=443)
    p = commands.add_parser('headers', help='Check HTTPS security header presence')
    p.add_argument('url')
    p.add_argument('--policy', help='Trusted Lua policy file')
    p = commands.add_parser('hash', help='Calculate a file SHA-256')
    p.add_argument('file')
    for name in ('baseline', 'verify'):
        p = commands.add_parser(name, help='Create or verify a file-integrity manifest')
        p.add_argument('folder')
        p.add_argument('manifest')
    p = commands.add_parser('permissions', help='Audit local POSIX permission bits')
    p.add_argument('folder')
    args = parser.parse_args(argv)
    try:
        if args.command == 'dns':
            result = network.dns(args.host)
        elif args.command == 'tls':
            result = network.tls(args.host, args.port)
        elif args.command == 'headers':
            result = network.headers(args.url, load_policy(args.policy))
        elif args.command == 'hash':
            result = {'file': args.file, 'sha256': integrity.sha256(args.file)}
        elif args.command == 'baseline':
            result = integrity.create(args.folder, args.manifest)
        elif args.command == 'verify':
            result = integrity.verify(args.folder, args.manifest)
        else:
            result = permissions.audit(args.folder)
        show(result, args.json)
        return 2 if args.command == 'verify' and not result['matches'] else 0
    except KeyboardInterrupt:
        return 130
    except Exception as error:
        show({'error': str(error), 'type': type(error).__name__}, args.json)
        return 1

if __name__ == '__main__':
    sys.exit(main())
