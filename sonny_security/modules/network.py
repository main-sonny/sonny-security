"""Single-host DNS, HTTPS header, and certificate checks. No scanning."""
import http.client
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlsplit


def host_name(value):
    if not value or any(c.isspace() for c in value) or any(c in value for c in '/@\\'):
        raise ValueError('Use a hostname or IP address, not a URL.')
    return value


def dns(host):
    host_name(host)
    results = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    return {'host': host, 'addresses': sorted({item[4][0] for item in results}),
            'note': 'Uses the operating-system resolver; not a full DNS record audit.'}


def tls(host, port=443, timeout=8):
    host_name(host)
    context = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=timeout) as raw:
        with context.wrap_socket(raw, server_hostname=host) as connection:
            cert = connection.getpeercert()
            expiry = ssl.cert_time_to_seconds(cert['notAfter'])
            return {
                'host': host, 'port': port, 'trusted_and_hostname_valid': True,
                'negotiated_protocol': connection.version(), 'cipher': connection.cipher(),
                'subject': cert.get('subject'), 'issuer': cert.get('issuer'),
                'expires': datetime.fromtimestamp(expiry, timezone.utc).isoformat(),
                'days_remaining': round((expiry - datetime.now(timezone.utc).timestamp()) / 86400, 1),
                'note': 'One verified handshake, not a cipher/protocol enumeration or revocation audit.',
            }


def headers(url, rules, timeout=8):
    parsed = urlsplit(url)
    if (parsed.scheme != 'https' or not parsed.hostname or parsed.username is not None
            or parsed.password is not None or parsed.fragment):
        raise ValueError('Use an HTTPS URL without credentials or a fragment.')
    path = parsed.path or '/'
    if parsed.query:
        path += '?' + parsed.query
    connection = http.client.HTTPSConnection(parsed.hostname, parsed.port or 443,
                                             timeout=timeout, context=ssl.create_default_context())
    try:
        connection.request('GET', path, headers={'User-Agent': 'Sonny-Security/1.0', 'Accept': '*/*'})
        response = connection.getresponse()
        received = {k.lower(): v for k, v in response.getheaders()}
        findings = [{'header': name, 'severity': severity, 'issue': 'Missing or empty header'}
                    for name, severity in rules.items() if not received.get(name, '').strip()]
        return {'url': url, 'status': response.status, 'headers': received,
                'findings': findings,
                'note': 'Presence checks only; values and application security are not validated. '
                        'Redirects are not followed; response body is not downloaded.'}
    finally:
        connection.close()
