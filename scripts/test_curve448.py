"""Independent OpenSSL X448 and Ed448 handshake/verification regressions."""
import base64
import hashlib
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import textwrap
import threading
import time
from types import SimpleNamespace
import unittest

from lab import certificates, exact, start_bridge
from matrix_lab import ROOT
from test_ccm import PAYLOAD, openssl, request, run_client, serve_http


def certificate_material(path):
    certificates(path)
    openssl('genpkey', '-algorithm', 'ED448', '-out', path / 'ed448.key')
    openssl('req', '-new', '-key', path / 'ed448.key', '-subj', '/CN=a.test',
            '-out', path / 'ed448.csr')
    openssl('genpkey', '-algorithm', 'ED448', '-out', path / 'ed448-ca.key')
    openssl('req', '-new', '-x509', '-key', path / 'ed448-ca.key', '-days', '1',
            '-subj', '/CN=Ed448 test CA', '-addext', 'basicConstraints=critical,CA:TRUE',
            '-addext', 'keyUsage=critical,keyCertSign', '-out', path / 'ed448-ca.pem')
    wrong_ext = path / 'wrong.ext'
    wrong_ext.write_text((path / 'a.ext').read_text().replace('DNS:a.test', 'DNS:wrong.test'))
    for feature, csr, ca in (
        ('ed448-leaf', 'ed448.csr', 'ca'),
        ('ed448-ca', 'a.csr', 'ed448-ca'),
    ):
        for mode, ext in [('valid', path / 'a.ext'), ('wrong-host', wrong_ext)]:
            openssl('x509', '-req', '-in', path / csr, '-CA', path / f'{ca}.pem',
                    '-CAkey', path / f'{ca}.key', '-CAcreateserial', '-days', '1',
                    '-extfile', ext, '-out', path / f'{feature}-{mode}.pem')
        pem = (path / f'{feature}-valid.pem').read_text()
        der = bytearray(base64.b64decode(''.join(pem.splitlines()[1:-1])))
        der[-1] ^= 1
        (path / f'{feature}-bad-certificate.pem').write_text(
            '-----BEGIN CERTIFICATE-----\n' +
            '\n'.join(textwrap.wrap(base64.b64encode(der).decode(), 64)) +
            '\n-----END CERTIFICATE-----\n')
    with (path / 'ca.pem').open('ab') as bundle:
        bundle.write((path / 'ed448-ca.pem').read_bytes())


def rewrite_handshake(message, mode, evidence):
    """Observe/mutate cleartext server messages without importing TLS secrets."""
    typ = message[0]
    data = bytearray(message[4:])
    if typ == 2:
        evidence['server_hellos'] = evidence.get('server_hellos', 0) + 1
        pos = 34
        pos += 1 + data[pos]
        evidence['selected_cipher'] = int.from_bytes(data[pos:pos + 2], 'big')
        pos += 3
        if pos < len(data):
            vector = pos
            pos += 2
            while pos + 4 <= len(data):
                kind = int.from_bytes(data[pos:pos + 2], 'big')
                size = int.from_bytes(data[pos + 2:pos + 4], 'big')
                end = pos + 4 + size
                if kind == 51:
                    evidence['group'] = int.from_bytes(data[pos + 4:pos + 6], 'big')
                    if size == 2:
                        evidence['hrr'] = True
                    else:
                        evidence['share_bytes'] = int.from_bytes(data[pos + 6:pos + 8], 'big')
                        if mode == 'zero-share':
                            data[pos + 8:end] = b'\x00' * (size - 4)
                            evidence['mutated'] = True
                        elif mode == 'short-share':
                            # Re-encode every enclosing length. This is a valid
                            # TLS vector containing an invalid 55-byte X448 key.
                            del data[end - 1]
                            data[pos + 6:pos + 8] = (size - 5).to_bytes(2, 'big')
                            data[pos + 2:pos + 4] = (size - 1).to_bytes(2, 'big')
                            n = int.from_bytes(data[vector:vector + 2], 'big')
                            data[vector:vector + 2] = (n - 1).to_bytes(2, 'big')
                            evidence['mutated'] = True
                            end -= 1
                pos = end
    elif typ == 12 and data[:1] == b'\x03':  # named-curve TLS 1.2 ServerKeyExchange
        evidence['group'] = int.from_bytes(data[1:3], 'big')
        size = data[3]
        evidence['share_bytes'] = size
        evidence['signature_algorithm'] = int.from_bytes(data[4 + size:6 + size], 'big')
        if mode == 'bad-handshake-signature':
            data[-1] ^= 1
            evidence['mutated'] = True
    return bytes([typ]) + len(data).to_bytes(3, 'big') + data


def relay(listener, target, version, mode, evidence):
    client = origin = sender = None
    try:
        client, _ = listener.accept()
        origin = socket.create_connection(('127.0.0.1', target), timeout=15)
        client.settimeout(15)
        origin.settimeout(15)

        def upstream():
            try:
                while True:
                    header = exact(client, 5)
                    data = exact(client, int.from_bytes(header[3:5], 'big'))
                    if header[0] == 22 and data[:1] == b'\x01':
                        evidence['client_hellos'] = evidence.get('client_hellos', 0) + 1
                    if header[0] == 21 and len(data) == 2:
                        evidence.setdefault('client_alerts', []).append(data[1])
                    origin.sendall(header + data)
            except (EOFError, OSError):
                try:
                    origin.shutdown(socket.SHUT_WR)
                except OSError:
                    pass

        sender = threading.Thread(target=upstream, daemon=True)
        sender.start()
        encrypted = False
        while True:
            header = bytearray(exact(origin, 5))
            data = exact(origin, int.from_bytes(header[3:5], 'big'))
            if header[0] == 20:
                encrypted = True
            if header[0] == 22 and (version == '1_3' or not encrypted):
                pos = 0
                changed = bytearray()
                while pos < len(data):
                    end = pos + 4 + int.from_bytes(data[pos + 1:pos + 4], 'big')
                    if end > len(data):
                        raise ValueError('fragmented OpenSSL fixture handshake')
                    changed.extend(rewrite_handshake(data[pos:end], mode, evidence))
                    pos = end
                data = changed
                header[3:5] = len(data).to_bytes(2, 'big')
            client.sendall(header + data)
    except (EOFError, OSError):
        pass
    except Exception as exc:
        evidence['relay_error'] = repr(exc)
    finally:
        if client:
            try:
                client.shutdown(socket.SHUT_WR)
            except OSError:
                pass
        if sender:
            sender.join(timeout=2)
        for stream in (client, origin, listener):
            if stream:
                stream.close()


class Curve448HandshakeTests(unittest.TestCase):
    def run_case(self, path, feature, version, mode, direct=False):
        case = path / f'{feature}-{version}-{mode}'
        case.mkdir()
        with socket.socket() as reserved:
            reserved.bind(('127.0.0.1', 0))
            origin_port = reserved.getsockname()[1]
        cert_mode = mode if mode in ('wrong-host', 'bad-certificate') else 'valid'
        cert = path / ('a.pem' if feature == 'x448' else f'{feature}-{cert_mode}.pem')
        key = path / ('ed448.key' if feature == 'ed448-leaf' else 'a.key')
        command = ['openssl', 's_server', '-accept', f'127.0.0.1:{origin_port}',
                   '-cert', str(cert), '-key', str(key), '-quiet', '-no_ign_eof',
                   '-naccept', '1', '-alpn', 'http/1.1', f'-tls{version}']
        if feature == 'x448':
            command += ['-groups', 'X448']
        if feature == 'ed448-leaf':
            command += ['-sigalgs', 'ed448']
        command += ['-cipher', 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256',
                    '-ciphersuites', 'TLS_AES_128_GCM_SHA256']
        listener = socket.socket()
        listener.bind(('127.0.0.1', 0))
        listener.listen(1)
        listener.settimeout(20)
        upstream_port = listener.getsockname()[1]
        wire, application = {}, {}
        proc = log = None
        with (case / 'origin.log').open('w+') as origin_log:
            origin = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                      stderr=origin_log)
            proxy = threading.Thread(target=relay,
                                     args=(listener, origin_port, version, mode, wire), daemon=True)
            worker = threading.Thread(target=serve_http,
                                      args=(origin, f'a.test:{upstream_port}', application), daemon=True)
            try:
                time.sleep(.15)
                self.assertIsNone(origin.poll(), 'OpenSSL origin failed to start')
                proxy.start()
                worker.start()
                if direct:
                    port, host = upstream_port, 'a.test'
                else:
                    proc, port, log = start_bridge(ROOT / 'target/debug/fingerprint-bridge', path,
                                                  SimpleNamespace(port=upstream_port), case / 'runtime')
                    host = 'b.test'
                sigs = 'rsa_pss_rsae_sha256:rsa_pkcs1_sha256:ecdsa_secp256r1_sha256'
                if mode != 'unoffered' or feature == 'x448':
                    sigs += ':ed448'
                groups = 'X25519'
                if feature == 'x448' and mode != 'unoffered':
                    groups = 'X25519:X448' if mode == 'hrr' else 'X448:X25519'
                client = run_client([
                    'openssl', 's_client', '-connect', f'127.0.0.1:{port}', '-servername', host,
                    '-verify_hostname', host, '-CAfile', str(path / 'ca.pem'), '-verify_return_error',
                    f'-tls{version}', '-alpn', 'http/1.1', '-quiet', '-no_ign_eof',
                    '-groups', groups, '-sigalgs', sigs,
                    '-cipher', 'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256',
                    '-ciphersuites', 'TLS_AES_128_GCM_SHA256',
                ], request(f'{host}:{port}'), case / 'client.log')
                origin.wait(timeout=15)
                proxy.join(timeout=5)
                worker.join(timeout=5)
                origin_log.seek(0)
                origin_errors = origin_log.read()
                if log:
                    expected_error = {
                        'zero-share': 'BAD_ECPOINT', 'short-share': 'BAD_ECPOINT',
                        'bad-handshake-signature': 'BAD_SIGNATURE',
                        'bad-certificate': 'CERTIFICATE_VERIFY_FAILED',
                        'wrong-host': 'CERTIFICATE_VERIFY_FAILED',
                    }.get(mode)
                    deadline = time.monotonic() + 2
                    while True:
                        log.seek(0)
                        bridge_log = log.read()
                        if (not expected_error or expected_error in bridge_log
                                or time.monotonic() >= deadline):
                            break
                        time.sleep(.01)
                else:
                    bridge_log = ''
                diagnostic = repr(wire) + repr(application) + origin_errors + bridge_log + client.stderr.decode(errors='replace')
                self.assertFalse(proxy.is_alive() or worker.is_alive(), diagnostic)
                self.assertNotIn('relay_error', wire, diagnostic)
                self.assertNotIn('http_error', application, diagnostic)
                positive = mode in ('valid', 'hrr')
                if positive:
                    self.assertEqual(len(application.get('requests', [])), 2, diagnostic)
                    remaining = client.stdout
                    for index, payload in enumerate((PAYLOAD, b'CCM-ok\x00\xff')):
                        header, remaining = remaining.split(b'\r\n\r\n', 1)
                        self.assertTrue(header.startswith(b'HTTP/1.1 200 OK'), diagnostic)
                        self.assertIn(f'Domain={host}'.encode(), header, diagnostic)
                        self.assertIn(f'Location: https://{host}:{port}/next'.encode(), header, diagnostic)
                        self.assertEqual(remaining[:len(payload)], payload, diagnostic)
                        remaining = remaining[len(payload):]
                        record = application['requests'][index]
                        self.assertIn(f'hOsT:\ta.test:{upstream_port} ', record['head'], diagnostic)
                        self.assertIn('Cookie: sid=from_B; flag=yes\r\n', record['head'], diagnostic)
                        expected = PAYLOAD if index == 0 else b'next\x00\xff'
                        self.assertEqual(record['body_sha256'], hashlib.sha256(expected).hexdigest(), diagnostic)
                    self.assertFalse(remaining, diagnostic)
                    if feature == 'x448':
                        self.assertEqual(wire.get('group'), 30, diagnostic)
                        self.assertEqual(wire.get('share_bytes'), 56, diagnostic)
                        self.assertEqual(wire.get('client_hellos'), 2 if mode == 'hrr' else 1, diagnostic)
                        self.assertEqual(bool(wire.get('hrr')), mode == 'hrr', diagnostic)
                    elif feature == 'ed448-leaf' and version == '1_2':
                        self.assertEqual(wire.get('signature_algorithm'), 0x0808, diagnostic)
                    if not direct:
                        outbound, = (case / 'runtime').glob('*.outbound.json')
                        fields = json.loads(outbound.read_text())['tls']['fields']
                        self.assertIn(30 if feature == 'x448' else 0x0808,
                                      fields['groups' if feature == 'x448' else 'signature_algorithms'], diagnostic)
                else:
                    self.assertFalse(application.get('requests'), diagnostic)
                    self.assertNotIn(b'HTTP/1.1 200', client.stdout, diagnostic)
                    if mode == 'unoffered':
                        self.assertRegex(origin_errors.lower(),
                                         'no shared cipher|no suitable key share|no suitable signature algorithm|no shared signature algorithms', diagnostic)
                    elif mode in ('zero-share', 'short-share'):
                        self.assertTrue(wire.get('mutated'), diagnostic)
                        if not direct:
                            self.assertIn(47, wire.get('client_alerts', []), diagnostic)
                            self.assertIn('BAD_ECPOINT', bridge_log, diagnostic)
                        else:
                            self.assertTrue(wire.get('client_alerts'), diagnostic)
                    elif mode == 'bad-handshake-signature':
                        self.assertTrue(wire.get('mutated'), diagnostic)
                        self.assertEqual(wire.get('signature_algorithm'), 0x0808, diagnostic)
                        if not direct:
                            self.assertIn('BAD_SIGNATURE', bridge_log, diagnostic)
                    elif not direct:
                        self.assertIn('CERTIFICATE_VERIFY_FAILED', bridge_log, diagnostic)
                return dict(feature=feature, tls=version, mode=mode, passed=True,
                            wire=wire, http_requests=len(application.get('requests', [])))
            finally:
                if proc:
                    proc.terminate()
                    proc.wait(timeout=5)
                if log:
                    log.close()
                if origin.poll() is None:
                    origin.terminate()
                    origin.wait(timeout=5)
                listener.close()
                if proxy.ident:
                    proxy.join(timeout=3)
                if worker.ident:
                    worker.join(timeout=3)
                origin.stdout.close()
                if not origin.stdin.closed:
                    origin.stdin.close()

    def test_x448_ed448_negotiation_and_rejections(self):
        cases = [('x448', '1_2', mode) for mode in ('valid', 'unoffered')]
        cases += [('x448', '1_3', mode) for mode in
                  ('valid', 'hrr', 'zero-share', 'short-share', 'unoffered')]
        for version in ('1_2', '1_3'):
            cases += [('ed448-leaf', version, mode) for mode in
                      ('valid', 'bad-certificate', 'wrong-host', 'unoffered')]
            cases += [('ed448-ca', version, mode) for mode in
                      ('valid', 'bad-certificate', 'wrong-host')]
        cases.append(('ed448-leaf', '1_2', 'bad-handshake-signature'))
        observations = []
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)
            certificate_material(path)
            for feature, version, mode in cases:
                with self.subTest(feature=feature, tls=version, mode=mode):
                    observations.append(self.run_case(path, feature, version, mode))
        self.assertEqual(len(observations), 22)
        output = ROOT / 'test-results/ci-curve448-lab'
        output.mkdir(parents=True, exist_ok=True)
        (output / 'summary.json').write_text(json.dumps(observations, indent=2) + '\n')
        print('CURVE448_RESULTS=' + json.dumps(observations, separators=(',', ':')), flush=True)


if __name__ == '__main__':
    unittest.main()
