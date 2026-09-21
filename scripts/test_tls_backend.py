"""Real OpenSSL TLS 1.2 ServerHello/Finished regression for SCSV handling."""
import json
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
from types import SimpleNamespace
import unittest

from lab import Origin, certificates, exact, head, start_bridge
from matrix_lab import MatrixOrigin, client_command, ROOT


class BackendHandshakeTests(unittest.TestCase):
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
                        if tamper:
                            self.assertNotEqual(result.returncode, 0, result.stdout)
                            self.assertFalse(peer['handshake'])
                            self.assertFalse(peer['http'])
                            self.assertTrue(peer['error'], origin_error)
                        else:
                            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
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
