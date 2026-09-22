"""Independent OpenSSL negotiation and invalid-peer tests for all RFC 7919 groups."""
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest

from lab import certificates, exact, start_bridge
from matrix_lab import ROOT


class FFDHEHandshakeTests(unittest.TestCase):
    @staticmethod
    def relay(listener, port, mode, evidence):
        client = origin = None
        sender = None
        try:
            client, _ = listener.accept()
            origin = socket.create_connection(('127.0.0.1', port), timeout=15)
            client.settimeout(15)
            origin.settimeout(15)

            def upstream():
                try:
                    while True:
                        header = exact(client, 5)
                        body = exact(client, int.from_bytes(header[3:5], 'big'))
                        if header[0] == 21 and len(body) == 2:
                            evidence.setdefault('client_alerts', []).append(body[1])
                        if header[0] == 22 and body[:1] == b'\x01':
                            evidence['client_hellos'] = evidence.get('client_hellos', 0) + 1
                        origin.sendall(header + body)
                except (OSError, EOFError):
                    try:
                        origin.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass

            sender = threading.Thread(target=upstream, daemon=True)
            sender.start()
            while True:
                header = exact(origin, 5)
                body = bytearray(exact(origin, int.from_bytes(header[3:5], 'big')))
                if header[0] == 22:
                    pos = 0
                    while pos + 4 <= len(body):
                        kind = body[pos]
                        end = pos + 4 + int.from_bytes(body[pos + 1:pos + 4], 'big')
                        if end > len(body):
                            raise ValueError('fragmented test-server handshake')
                        if kind == 2:  # ServerHello or HelloRetryRequest
                            p = pos + 4 + 2 + 32
                            p += 1 + body[p] + 2 + 1
                            if p < end:
                                p += 2  # extensions vector length
                                while p + 4 <= end:
                                    typ = int.from_bytes(body[p:p + 2], 'big')
                                    n = int.from_bytes(body[p + 2:p + 4], 'big')
                                    if typ == 51 and n > 2:
                                        group = int.from_bytes(body[p + 4:p + 6], 'big')
                                        size = int.from_bytes(body[p + 6:p + 8], 'big')
                                        evidence['server_group'] = group
                                        evidence['server_share_bytes'] = size
                                        if mode in ('zero', 'one', 'too-large'):
                                            replacement = bytearray(size)
                                            if mode == 'one':
                                                replacement[-1] = 1
                                            elif mode == 'too-large':
                                                replacement[:] = b'\xff' * size
                                            body[p + 8:p + 8 + size] = replacement
                                            evidence['mutated'] = True
                                    p += 4 + n
                        elif kind == 12:  # TLS 1.2 finite-field ServerKeyExchange
                            evidence['server_prime_bytes'] = int.from_bytes(
                                body[pos + 4:pos + 6], 'big')
                        pos = end
                client.sendall(header + body)
        except (OSError, EOFError):
            pass  # the assertions below distinguish success from rejection
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

    def test_rfc7919_negotiation_hrr_and_illegal_public_keys(self):
        results = []
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)
            certificates(path)
            for group_id, bits in enumerate((2048, 3072, 4096, 6144, 8192), 256):
                group = f'ffdhe{bits}'
                params = path / f'{group}.pem'  # public domain parameters only
                subprocess.run(['openssl', 'genpkey', '-genparam', '-algorithm', 'DH',
                                '-pkeyopt', f'group:{group}', '-out', str(params)],
                               check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                for version, mode in [('1_2', 'valid'), ('1_3', 'valid'),
                                      ('1_3', 'zero'), ('1_3', 'one'),
                                      ('1_3', 'too-large'), ('1_3', 'unoffered')]:
                    with self.subTest(group=group, tls=version, mode=mode):
                        case = path / f'{group}-{version}-{mode}'
                        case.mkdir()
                        with socket.socket() as reserved:
                            reserved.bind(('127.0.0.1', 0))
                            origin_port = reserved.getsockname()[1]
                        server_command = [
                            'openssl', 's_server', '-accept', f'127.0.0.1:{origin_port}',
                            '-cert', str(path / 'a.pem'), '-key', str(path / 'a.key'),
                            '-www', f'-tls{version}', '-groups', group, '-naccept', '1'
                        ]
                        if version == '1_2':
                            server_command += ['-dhparam', str(params), '-cipher',
                                               'DHE-RSA-AES128-GCM-SHA256']
                        origin = subprocess.Popen(server_command, stdout=subprocess.PIPE,
                                                  stderr=subprocess.STDOUT, text=True)
                        listener = socket.socket()
                        listener.bind(('127.0.0.1', 0))
                        listener.listen(1)
                        listener.settimeout(20)
                        evidence = {}
                        relay = threading.Thread(target=self.relay,
                                                 args=(listener, origin_port, mode, evidence),
                                                 daemon=True)
                        proc = log = None
                        try:
                            time.sleep(0.2)
                            self.assertIsNone(origin.poll(), 'OpenSSL origin failed to start')
                            relay.start()
                            proc, port, log = start_bridge(
                                ROOT / 'target/debug/fingerprint-bridge', path,
                                SimpleNamespace(port=listener.getsockname()[1]), case / 'runtime')
                            groups = 'X25519' if mode == 'unoffered' else f'X25519:{group}'
                            request = (f'GET /ffdhe HTTP/1.1\r\nHost: b.test:{port}\r\n'
                                       'Cookie: sid=from_B\r\nConnection: close\r\n\r\n')
                            client = subprocess.run([
                                'openssl', 's_client', '-connect', f'127.0.0.1:{port}',
                                '-servername', 'b.test', '-verify_hostname', 'b.test',
                                '-CAfile', str(path / 'ca.pem'), '-verify_return_error',
                                f'-tls{version}', '-groups', groups, '-quiet'
                            ], input=request, capture_output=True, text=True, timeout=40)
                            trace = origin.communicate(timeout=15)[0]
                            relay.join(timeout=5)
                            log.flush()
                            log.seek(0)
                            diagnostic = repr(evidence) + client.stderr + trace + log.read()
                            self.assertNotIn('relay_error', evidence, diagnostic)
                            self.assertFalse(relay.is_alive(), diagnostic)
                            if mode == 'valid':
                                self.assertIn('HTTP/1.0 200', client.stdout, diagnostic)
                                outgoing, = (case / 'runtime').glob('*.outbound.json')
                                fields = json.loads(outgoing.read_text())['tls']['fields']
                                self.assertIn(group_id, fields['groups'], diagnostic)
                                if version == '1_3':
                                    self.assertEqual(evidence.get('server_group'), group_id, diagnostic)
                                    self.assertEqual(evidence.get('server_share_bytes'), bits // 8,
                                                     diagnostic)
                                    self.assertEqual(evidence.get('client_hellos'), 2, diagnostic)
                                else:
                                    self.assertEqual(evidence.get('server_prime_bytes'), bits // 8,
                                                     diagnostic)
                            else:
                                self.assertNotIn('HTTP/1.0 200', client.stdout, diagnostic)
                                self.assertFalse(list((case / 'runtime').glob('*.outbound.json')),
                                                 diagnostic)
                                if mode != 'unoffered':
                                    self.assertTrue(evidence.get('mutated'), diagnostic)
                                    self.assertIn(47, evidence.get('client_alerts', []), diagnostic)
                                else:
                                    self.assertNotIn('server_group', evidence, diagnostic)
                            results.append({'group': group_id, 'bits': bits, 'tls': version,
                                            'case': mode, 'pass': True, 'wire': evidence})
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
        output = ROOT / 'test-results/ci-ffdhe-lab'
        output.mkdir(parents=True, exist_ok=True)
        (output / 'summary.json').write_text(json.dumps({'pass': True, 'cases': results}, indent=2))
