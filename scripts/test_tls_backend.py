"""Real TLS negotiation regressions for the patched BoringSSL backend."""
import base64
import json
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import textwrap
import time
from types import SimpleNamespace
import unittest

from lab import Origin, certificates, exact, head, start_bridge
from matrix_lab import MatrixOrigin, client_command, ROOT


class BackendHandshakeTests(unittest.TestCase):
    @staticmethod
    def _rsapss_certificate(path, tamper):
        root_key = path / 'root.key'
        root_cert = path / 'root.pem'
        leaf_key = path / 'leaf.key'
        leaf_csr = path / 'leaf.csr'
        leaf_cert = path / 'leaf.pem'
        extensions = path / 'leaf.ext'
        extensions.write_text('subjectAltName=DNS:a.test\n'
                              'basicConstraints=critical,CA:FALSE\n'
                              'keyUsage=critical,digitalSignature\n'
                              'extendedKeyUsage=serverAuth\n')

        def openssl(*args):
            result = subprocess.run(['openssl', *args], capture_output=True, text=True, timeout=30)
            if result.returncode:
                raise AssertionError(result.stdout + result.stderr)

        openssl('genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048',
                '-out', str(root_key))
        openssl('req', '-x509', '-new', '-key', str(root_key), '-sha256', '-days', '1',
                '-subj', '/CN=RSA-PSS test CA', '-addext', 'basicConstraints=critical,CA:TRUE',
                '-addext', 'keyUsage=critical,keyCertSign', '-out', str(root_cert))
        openssl('genpkey', '-algorithm', 'RSA-PSS', '-pkeyopt', 'rsa_keygen_bits:2048',
                '-pkeyopt', 'rsa_pss_keygen_md:sha256',
                '-pkeyopt', 'rsa_pss_keygen_mgf1_md:sha256',
                '-pkeyopt', 'rsa_pss_keygen_saltlen:32', '-out', str(leaf_key))
        openssl('req', '-new', '-key', str(leaf_key), '-subj', '/CN=a.test',
                '-out', str(leaf_csr))
        openssl('x509', '-req', '-in', str(leaf_csr), '-CA', str(root_cert),
                '-CAkey', str(root_key), '-CAcreateserial', '-days', '1', '-sha256',
                '-sigopt', 'rsa_padding_mode:pss', '-sigopt', 'rsa_pss_saltlen:digest',
                '-extfile', str(extensions), '-out', str(leaf_cert))
        if tamper:
            lines = leaf_cert.read_text().strip().splitlines()
            der = bytearray(base64.b64decode(''.join(lines[1:-1])))
            der[-1] ^= 1  # Certificate.signatureValue, not the SPKI or extensions.
            encoded = base64.b64encode(der).decode()
            body = '\n'.join(textwrap.wrap(encoded, 64))
            leaf_cert.write_text(f'-----BEGIN CERTIFICATE-----\n{body}\n'
                                 '-----END CERTIFICATE-----\n')
        return root_cert, leaf_cert, leaf_key

    def test_rsapss_pss_certificate_verify_and_tampered_chain_rejection(self):
        binary = ROOT / 'target/debug/fingerprint-bridge'
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary); certificates(path)
            for tamper in (False, True):
                with self.subTest(tampered_certificate_signature=tamper):
                    case = path / ('pss-tampered' if tamper else 'pss-valid'); case.mkdir()
                    root, cert, key = self._rsapss_certificate(case, tamper)
                    with (path / 'ca.pem').open('ab') as bundle, root.open('rb') as ca:
                        bundle.write(ca.read())
                    with socket.socket() as reserved:
                        reserved.bind(('127.0.0.1', 0))
                        origin_port = reserved.getsockname()[1]
                    origin = subprocess.Popen([
                        'openssl', 's_server', '-accept', f'127.0.0.1:{origin_port}',
                        '-cert', str(cert), '-key', str(key), '-www', '-tls1_3',
                        '-trace', '-naccept', '1'
                    ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                    proc = log = None
                    try:
                        time.sleep(0.2)
                        self.assertIsNone(origin.poll(), origin.stdout.read() if origin.poll() else '')
                        upstream = SimpleNamespace(port=origin_port)
                        proc, port, log = start_bridge(binary, path, upstream, case / 'runtime')
                        ctx = ssl.create_default_context(cafile=str(path / 'ca.pem'))
                        response = b''
                        error = None
                        try:
                            with socket.create_connection(('127.0.0.1', port), timeout=10) as raw:
                                with ctx.wrap_socket(raw, server_hostname='b.test') as conn:
                                    conn.sendall(f'GET / HTTP/1.1\r\nHost: b.test:{port}\r\n'
                                                 'Cookie: sid=from_B\r\nConnection: close\r\n\r\n'.encode())
                                    while True:
                                        chunk = conn.recv(4096)
                                        if not chunk: break
                                        response += chunk
                        except (OSError, ssl.SSLError) as exc:
                            error = exc
                        trace = origin.communicate(timeout=15)[0]
                        log.flush(); log.seek(0); diagnostics = trace + '\nbridge: ' + log.read()
                        if tamper:
                            self.assertFalse(response.startswith(b'HTTP/1.0 200'),
                                             diagnostics + f'\nclient error: {error!r}')
                            self.assertIn('fatal', trace.lower(), diagnostics)
                        else:
                            self.assertIsNone(error, diagnostics)
                            self.assertTrue(response.startswith(b'HTTP/1.0 200'), diagnostics)
                            self.assertIn('rsa_pss_pss_sha256 (0x0809)', trace, diagnostics)
                            outgoing, = (case / 'runtime').glob('*.outbound.json')
                            signatures = json.loads(outgoing.read_text())['tls']['fields']['signature_algorithms']
                            self.assertTrue(all(value in signatures for value in (0x0809, 0x080a, 0x080b)),
                                            signatures)
                    finally:
                        if proc:
                            proc.terminate(); proc.wait(timeout=5)
                        if log: log.close()
                        if origin.poll() is None:
                            origin.terminate(); origin.wait(timeout=5)

    def test_mldsa_certificate_verify_and_tampered_chain_rejection(self):
        binary = ROOT / 'target/debug/fingerprint-bridge'
        probe = ROOT / 'target/matrix-clients/mldsa-probe'
        self.assertTrue(probe.is_file(), 'build scripts/clients/mldsa_probe.go first')
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary); certificates(path)
            for tamper in (False, True):
                with self.subTest(tampered_certificate_signature=tamper):
                    case = path / ('tampered' if tamper else 'valid'); case.mkdir()
                    command = [str(probe), 'origin', '--dir', str(case)]
                    if tamper: command.append('--tamper-certificate-signature')
                    origin = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    proc = log = None
                    try:
                        ready = json.loads(origin.stdout.readline())
                        with (path / 'ca.pem').open('ab') as bundle, Path(ready['ca']).open('rb') as ca:
                            bundle.write(ca.read())
                        upstream = SimpleNamespace(port=int(ready['address'].rsplit(':', 1)[1]))
                        proc, port, log = start_bridge(binary, path, upstream, case / 'runtime')
                        result = subprocess.run([str(probe), 'client', '--address', f'127.0.0.1:{port}',
                                                 '--ca', str(path / 'ca.pem')], capture_output=True,
                                                text=True, timeout=30)
                        origin_output, origin_error = origin.communicate(timeout=30)
                        peer = json.loads(origin_output.strip().splitlines()[-1])
                        log.flush(); log.seek(0)
                        diagnostics = (result.stdout + result.stderr + '\norigin: ' +
                                       json.dumps(peer) + '\norigin stderr: ' + origin_error +
                                       '\nbridge: ' + log.read())
                        if tamper:
                            self.assertNotEqual(result.returncode, 0, diagnostics)
                            self.assertFalse(peer['handshake'])
                            self.assertFalse(peer['http'])
                            self.assertTrue(peer['error'], origin_error)
                        else:
                            self.assertEqual(result.returncode, 0, diagnostics)
                            self.assertTrue(peer['handshake'])
                            self.assertTrue(peer['http'])
                            outgoing, = (case / 'runtime').glob('*.outbound.json')
                            signatures = json.loads(outgoing.read_text())['tls']['fields']['signature_algorithms']
                            self.assertEqual(signatures[:3], [0x0904, 0x0905, 0x0906])
                    finally:
                        if proc:
                            proc.terminate(); proc.wait(timeout=5)
                        if log: log.close()
                        if origin.poll() is None:
                            origin.terminate(); origin.wait(timeout=5)

    def test_client_observes_the_origin_negotiated_tls_version(self):
        binary = ROOT / 'target/debug/fingerprint-bridge'
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary); certificates(path)
            for version in (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3):
                with self.subTest(version=version.name):
                    origin = Origin(path, 'http/1.1', connections=2)
                    origin.ctx.minimum_version = origin.ctx.maximum_version = version
                    proc = log = None
                    try:
                        proc, port, log = start_bridge(binary, path, origin, path / version.name)
                        ctx = ssl.create_default_context(cafile=str(path / 'ca.pem'))
                        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
                        ctx.maximum_version = ssl.TLSVersion.TLSv1_3
                        observed = []
                        for host, target in [('a.test', origin.port), ('b.test', port)]:
                            with socket.create_connection(('127.0.0.1', target), timeout=10) as raw:
                                with ctx.wrap_socket(raw, server_hostname=host) as conn:
                                    observed.append(conn.version())
                                    for _ in range(2):
                                        conn.sendall(f'GET /version HTTP/1.1\r\nHost: {host}:{target}\r\nCookie: sid=from_B\r\n\r\n'.encode())
                                        self.assertTrue(head(conn).startswith(b'HTTP/1.1 200'))
                                        self.assertEqual(exact(conn, 7), b'a\x00b\xffcde')
                        self.assertTrue(origin.done.wait(10))
                        self.assertFalse(origin.errors)
                        self.assertEqual(len(origin.evidence), 2)
                        self.assertEqual(observed, [version.name.replace('_', '.'), version.name.replace('_', '.')])
                    finally:
                        if proc:
                            proc.terminate(); proc.wait(timeout=5)
                        if log: log.close()
                        origin.listener.close()

    def test_scsv_accepts_secure_renegotiation_server_extension(self):
        binary = ROOT / 'target/debug/fingerprint-bridge'
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary); certificates(path)
            origin = MatrixOrigin(path, 'http/1.1')
            origin.ctx.maximum_version = ssl.TLSVersion.TLSv1_2
            proc = log = None
            try:
                proc, port, log = start_bridge(binary, path, origin, path / 'runtime')
                result = subprocess.run(client_command('rust', path, 'http/1.1', origin.port, port),
                                        capture_output=True, text=True, timeout=45)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                origin.finish()
                # A completed encrypted response verifies the Finished transcript
                # and server certificate checks, not just a synthetic ClientHello.
                outgoing, = (path / 'runtime').glob('*.outbound.json')
                fields = json.loads(outgoing.read_text())['tls']['fields']
                self.assertIn(255, fields['ciphers'])
                self.assertNotIn(65281, fields['extensions'])
                self.assertNotIn(21, fields['extensions'])
            finally:
                if proc:
                    proc.terminate(); proc.wait(timeout=5)
                if log: log.close()
                origin.close()


if __name__ == '__main__':
    unittest.main()
