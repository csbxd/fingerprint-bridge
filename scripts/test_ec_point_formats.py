"""Real TLS 1.2 compressed-prime ECDHE negotiation and rejection tests."""
import json
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
from types import SimpleNamespace
import unittest

from lab import start_bridge
from matrix_lab import ROOT
from test_status_v2 import material


def python_client(ca, port):
    context = ssl.create_default_context(cafile=str(ca))
    context.maximum_version = ssl.TLSVersion.TLSv1_2
    context.set_alpn_protocols(['http/1.1'])
    with socket.create_connection(('127.0.0.1', port), timeout=15) as raw:
        with context.wrap_socket(raw, server_hostname='b.test') as client:
            request = (f'GET /point HTTP/1.1\r\nHost: b.test:{port}\r\n'
                       'Cookie: sid=from_B\r\nConnection: close\r\n\r\n')
            client.sendall(request.encode())
            response = bytearray()
            while True:
                block = client.recv(4096)
                if not block:
                    break
                response.extend(block)
                if b'EC_POINT_OK' in response:
                    break
            return bytes(response)


class ECPointFormatTests(unittest.TestCase):
    def test_compressed_prime_real_handshake_and_malformed_rejection(self):
        results = []
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)
            material(path)
            peer = path / 'ec-point-origin'
            built = subprocess.run(['go', 'build', '-o', str(peer),
                                    str(ROOT / 'scripts/clients/ec_point_probe.go')],
                                   capture_output=True, text=True, timeout=120)
            self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
            for mode in ('valid', 'malformed'):
                with self.subTest(mode=mode):
                    origin = subprocess.Popen([str(peer), '-cert', str(path / 'a.pem'),
                                               '-key', str(path / 'a.key'), '-mode', mode],
                                              stdout=subprocess.PIPE,
                                              stderr=subprocess.PIPE, text=True)
                    proc = log = None
                    try:
                        startup = json.loads(origin.stdout.readline())
                        proc, port, log = start_bridge(
                            ROOT / 'target/debug/fingerprint-bridge', path,
                            SimpleNamespace(port=startup['port']), path / f'runtime-point-{mode}')
                        if mode == 'valid':
                            response = python_client(path / 'ca.pem', port)
                            self.assertIn(b'200 OK', response)
                            self.assertIn(b'EC_POINT_OK', response)
                        else:
                            with self.assertRaises((ssl.SSLError, ConnectionError, OSError)):
                                python_client(path / 'ca.pem', port)
                        output, errors = origin.communicate(timeout=25)
                        evidence = json.loads(output)
                        log.flush(); log.seek(0)
                        diagnostic = repr(evidence) + errors + log.read()
                        self.assertEqual(evidence.get('outgoing_point_formats'), [0, 1], diagnostic)
                        self.assertTrue(evidence.get('compressed_prime_offered'), diagnostic)
                        self.assertTrue(evidence.get('compressed_server_key_sent'), diagnostic)
                        if mode == 'valid':
                            self.assertNotIn('error', evidence, diagnostic)
                            for field in ('client_finished_verified', 'http_request_received',
                                          'cookie_preserved', 'authority_rewritten'):
                                self.assertTrue(evidence.get(field), diagnostic)
                        else:
                            self.assertNotIn('error', evidence, diagnostic)
                            self.assertTrue(evidence.get('malformed_rejected'), diagnostic)
                            self.assertEqual(evidence.get('client_alert'), 47, diagnostic)
                            self.assertNotIn('http_request_received', evidence, diagnostic)
                        results.append(dict(evidence, passed=True))
                    finally:
                        if proc:
                            proc.terminate(); proc.wait(timeout=5)
                        if log:
                            log.close()
                        if origin.poll() is None:
                            origin.terminate(); origin.wait(timeout=5)
                        origin.stdout.close(); origin.stderr.close()
        self.assertEqual(len(results), 2)
        output = ROOT / 'test-results/ci-ec-point-lab'
        output.mkdir(parents=True, exist_ok=True)
        (output / 'summary.json').write_text(json.dumps(results, indent=2) + '\n')
        print('EC_POINT_RESULTS=' + json.dumps(results, separators=(',', ':')), flush=True)


if __name__ == '__main__':
    unittest.main()
