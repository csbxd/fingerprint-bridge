"""Independent OpenSSL CCM negotiation, HTTP and record-authentication tests.

Only these controlled probes restrict cipher suites. The default matrix clients,
certificate verification and OpenSSL security level are unchanged.
"""
import hashlib
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


SUITES = (
    ('AES128-CCM', 0xc09c), ('AES256-CCM', 0xc09d),
    ('DHE-RSA-AES128-CCM', 0xc09e), ('DHE-RSA-AES256-CCM', 0xc09f),
    ('AES128-CCM8', 0xc0a0), ('AES256-CCM8', 0xc0a1),
    ('DHE-RSA-AES128-CCM8', 0xc0a2), ('DHE-RSA-AES256-CCM8', 0xc0a3),
    ('ECDHE-ECDSA-AES128-CCM', 0xc0ac), ('ECDHE-ECDSA-AES256-CCM', 0xc0ad),
    ('ECDHE-ECDSA-AES128-CCM8', 0xc0ae), ('ECDHE-ECDSA-AES256-CCM8', 0xc0af),
    ('TLS_AES_128_CCM_SHA256', 0x1304), ('TLS_AES_128_CCM_8_SHA256', 0x1305),
)
PAYLOAD = bytes(range(256)) * 160 + b'\x00\xffCCM-boundary'


def openssl(*args):
    subprocess.run(['openssl', *map(str, args)], check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=60)


def material(path):
    certificates(path)
    openssl('req', '-new', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256',
            '-nodes', '-subj', '/CN=a.test', '-keyout', path / 'a-ec.key',
            '-out', path / 'a-ec.csr')
    openssl('x509', '-req', '-in', path / 'a-ec.csr', '-CA', path / 'ca.pem',
            '-CAkey', path / 'ca.key', '-CAcreateserial', '-days', '1',
            '-extfile', path / 'a.ext', '-out', path / 'a-ec.pem')


def pipe_exact(stream, size):
    result = bytearray()
    while len(result) < size:
        chunk = stream.read(size - len(result))
        if not chunk:
            raise EOFError('HTTP pipe closed')
        result.extend(chunk)
    return bytes(result)


def pipe_head(stream):
    result = bytearray()
    while not result.endswith(b'\r\n\r\n'):
        result.extend(pipe_exact(stream, 1))
        if len(result) > 65536:
            raise ValueError('oversized HTTP header')
    return bytes(result)


def serve_http(origin, authority, evidence):
    """s_server stdout is authenticated plaintext, not a TLS trace."""
    try:
        for index in range(2):
            header = pipe_head(origin.stdout)
            length = next(int(line.split(b':', 1)[1]) for line in header.split(b'\r\n')
                          if line.lower().startswith(b'content-length:'))
            body = pipe_exact(origin.stdout, length)
            evidence.setdefault('requests', []).append({
                'head': header.decode('ascii'),
                'body_sha256': hashlib.sha256(body).hexdigest(),
                'body_length': len(body),
            })
            payload = PAYLOAD if index == 0 else b'CCM-ok\x00\xff'
            response = (f'HTTP/1.1 200 OK\r\nContent-Length: {len(payload)}\r\n'
                        'Set-Cookie: sid=from_A; Domain=a.test; Secure; HttpOnly\r\n'
                        f'Location: https://{authority}/next\r\n\r\n').encode() + payload
            origin.stdin.write(response)
            origin.stdin.flush()
    except (EOFError, BrokenPipeError):
        # A negative handshake/authentication test legitimately closes the pipe.
        pass
    except Exception as exc:
        evidence['http_error'] = repr(exc)
    finally:
        try:
            origin.stdin.close()
        except BrokenPipeError:
            pass


def relay(listener, target, mode, evidence):
    incoming = origin = sender = None
    try:
        incoming, _ = listener.accept()
        origin = socket.create_connection(('127.0.0.1', target), timeout=15)
        incoming.settimeout(15)
        origin.settimeout(15)

        def upstream():
            try:
                while True:
                    header = exact(incoming, 5)
                    body = exact(incoming, int.from_bytes(header[3:5], 'big'))
                    if header[0] == 21 and len(body) == 2:
                        evidence.setdefault('client_alerts', []).append(body[1])
                    origin.sendall(header + body)
            except (OSError, EOFError):
                try:
                    origin.shutdown(socket.SHUT_WR)
                except OSError:
                    pass

        sender = threading.Thread(target=upstream, daemon=True)
        sender.start()
        encrypted = False
        while True:
            header = exact(origin, 5)
            body = bytearray(exact(origin, int.from_bytes(header[3:5], 'big')))
            if header[0] == 20:
                encrypted = True
            if header[0] == 22 and not encrypted:
                offset = 0
                while offset + 4 <= len(body):
                    end = offset + 4 + int.from_bytes(body[offset + 1:offset + 4], 'big')
                    if end > len(body):
                        raise ValueError('fragmented test-server handshake')
                    if body[offset] == 2:
                        pos = offset + 4 + 2 + 32
                        pos += 1 + body[pos]
                        evidence['selected_cipher'] = int.from_bytes(body[pos:pos + 2], 'big')
                        if mode == 'unsolicited-cipher':
                            body[pos:pos + 2] = evidence['injected_cipher'].to_bytes(2, 'big')
                            evidence['mutated'] = True
                    offset = end
            if header[0] == 23:
                if mode == 'unsolicited-cipher':
                    # Send only the tampered ServerHello. The expected rejection
                    # must precede decryption, not merely a later bad-MAC error.
                    break
                evidence.setdefault('server_encrypted_record_lengths', []).append(len(body))
                if mode in ('bad-ciphertext', 'bad-tag') and not evidence.get('mutated'):
                    # TLS 1.2 CCM has an 8-byte explicit nonce, TLS 1.3 does not.
                    tls13 = evidence.get('selected_cipher') in (0x1304, 0x1305)
                    pos = -1 if mode == 'bad-tag' else (0 if tls13 else 8)
                    body[pos] ^= 1
                    evidence['mutated'] = True
                    evidence['mutation'] = mode
            incoming.sendall(header + body)
    except (OSError, EOFError):
        pass
    except Exception as exc:
        evidence['relay_error'] = repr(exc)
    finally:
        if incoming:
            try:
                incoming.shutdown(socket.SHUT_WR)
            except OSError:
                pass
        if sender:
            sender.join(timeout=2)
        for stream in (incoming, origin, listener):
            if stream:
                stream.close()


def client_command(path, port, host, cipher, version, offered=True):
    command = ['openssl', 's_client', '-connect', f'127.0.0.1:{port}',
               '-servername', host, '-verify_hostname', host,
               '-CAfile', str(path / 'ca.pem'), '-verify_return_error',
               f'-tls{version}', '-alpn', 'http/1.1', '-quiet', '-no_ign_eof']
    if version == '1_3':
        suites = 'TLS_AES_128_GCM_SHA256' + (f':{cipher}' if offered else '')
        command += ['-ciphersuites', suites]
    else:
        suites = 'ECDHE-RSA-AES128-GCM-SHA256' + (f':{cipher}' if offered else '')
        command += ['-cipher', suites]
    return command


def request(authority):
    result = bytearray()
    for index, body in enumerate((PAYLOAD, b'next\x00\xff')):
        result.extend((f'POST /ccm/{index} HTTP/1.1\r\nhOsT:\t{authority} \r\n'
                       'Cookie: sid=from_B; flag=yes\r\n'
                       f'Content-Length: {len(body)}\r\n\r\n').encode() + body)
    return bytes(result)


def run_client(command, payload, log_path):
    """Finish two HTTP responses, then close the verified client's connection.

    Closing stdin before reading replies truncates s_client's TLS connection;
    ignoring stdin EOF instead leaves B waiting for another keep-alive request.
    Separate pipe workers exercise full duplex I/O without either shortcut.
    """
    output = bytearray()
    sent = threading.Event()
    errors = []
    with log_path.open('w+b') as log:
        client = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=log)

        def send():
            try:
                client.stdin.write(payload)
                client.stdin.flush()
            except (BrokenPipeError, OSError):
                pass
            finally:
                sent.set()

        def receive():
            try:
                for _ in range(2):
                    header = pipe_head(client.stdout)
                    output.extend(header)
                    length = next(int(line.split(b':', 1)[1])
                                  for line in header.split(b'\r\n')
                                  if line.lower().startswith(b'content-length:'))
                    output.extend(pipe_exact(client.stdout, length))
            except (EOFError, OSError):
                pass
            except Exception as exc:
                errors.append(repr(exc))
            finally:
                if sent.wait(5):
                    try:
                        client.stdin.close()
                    except (BrokenPipeError, OSError):
                        pass

        sender = threading.Thread(target=send, daemon=True)
        reader = threading.Thread(target=receive, daemon=True)
        sender.start()
        reader.start()
        try:
            client.wait(timeout=30)
            sender.join(timeout=5)
            reader.join(timeout=5)
            if sender.is_alive() or reader.is_alive():
                raise AssertionError('OpenSSL client pipe workers did not finish')
            if errors:
                raise AssertionError(errors)
            log.seek(0)
            return SimpleNamespace(stdout=bytes(output), stderr=log.read(), returncode=client.returncode)
        finally:
            if client.poll() is None:
                client.terminate()
                client.wait(timeout=5)
            sender.join(timeout=5)
            reader.join(timeout=5)
            client.stdout.close()
            if not client.stdin.closed:
                client.stdin.close()


class CCMHandshakeTests(unittest.TestCase):
    def run_case(self, path, cipher, cipher_id, mode, direct=False):
        version = '1_3' if cipher_id in (0x1304, 0x1305) else '1_2'
        case = path / f'{cipher_id:04x}-{mode}'
        case.mkdir()
        with socket.socket() as reserved:
            reserved.bind(('127.0.0.1', 0))
            origin_port = reserved.getsockname()[1]
        cert = 'a-ec' if cipher.startswith('ECDHE-ECDSA-') else 'a'
        server_cipher = 'TLS_AES_128_GCM_SHA256' if mode == 'unsolicited-cipher' else cipher
        command = ['openssl', 's_server', '-accept', f'127.0.0.1:{origin_port}',
                   '-cert', str(path / f'{cert}.pem'), '-key', str(path / f'{cert}.key'),
                   '-quiet', '-no_ign_eof', '-naccept', '1', '-alpn', 'http/1.1',
                   f'-tls{version}', '-ciphersuites' if version == '1_3' else '-cipher', server_cipher]
        listener = socket.socket()
        listener.bind(('127.0.0.1', 0))
        listener.listen(1)
        listener.settimeout(20)
        upstream_port = listener.getsockname()[1]
        wire, application = {}, {}
        if mode == 'unsolicited-cipher':
            wire['injected_cipher'] = cipher_id
        proc = log = None
        with (case / 'origin.log').open('w+') as origin_log:
            origin = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                      stderr=origin_log)
            proxy = threading.Thread(target=relay,
                                     args=(listener, origin_port, mode, wire), daemon=True)
            worker = threading.Thread(target=serve_http,
                                      args=(origin, f'a.test:{upstream_port}', application),
                                      daemon=True)
            try:
                time.sleep(.15)
                self.assertIsNone(origin.poll(), 'OpenSSL origin failed to start')
                proxy.start()
                worker.start()
                if direct:
                    port, host = upstream_port, 'a.test'
                else:
                    proc, port, log = start_bridge(
                        ROOT / 'target/debug/fingerprint-bridge', path,
                        SimpleNamespace(port=upstream_port), case / 'runtime')
                    host = 'b.test'
                client = run_client(client_command(path, port, host, cipher, version,
                                                    mode not in ('unoffered', 'unsolicited-cipher')),
                                    request(f'{host}:{port}'), case / 'client.log')
                origin.wait(timeout=15)
                proxy.join(timeout=5)
                worker.join(timeout=5)
                origin_log.seek(0)
                bridge_log = ''
                if log:
                    log.flush()
                    log.seek(0)
                    bridge_log = log.read()
                origin_errors = origin_log.read()
                diagnostic = (repr(wire) + repr(application) + client.stderr.decode(errors='replace')
                              + origin_errors + bridge_log)
                self.assertFalse(proxy.is_alive(), diagnostic)
                self.assertFalse(worker.is_alive(), diagnostic)
                self.assertNotIn('relay_error', wire, diagnostic)
                self.assertNotIn('http_error', application, diagnostic)
                if mode == 'valid':
                    self.assertEqual(wire.get('selected_cipher'), cipher_id, diagnostic)
                    self.assertEqual(len(application.get('requests', [])), 2, diagnostic)
                    remaining = client.stdout
                    for index, payload in enumerate((PAYLOAD, b'CCM-ok\x00\xff')):
                        header, remaining = remaining.split(b'\r\n\r\n', 1)
                        self.assertTrue(header.startswith(b'HTTP/1.1 200 OK'), diagnostic)
                        self.assertIn(f'Domain={host}'.encode(), header, diagnostic)
                        self.assertIn(f'Location: https://{host}:{port}/next'.encode(), header,
                                      diagnostic)
                        self.assertEqual(remaining[:len(payload)], payload, diagnostic)
                        remaining = remaining[len(payload):]
                        recorded = application['requests'][index]
                        self.assertIn(f'hOsT:\ta.test:{upstream_port} ', recorded['head'], diagnostic)
                        self.assertIn('Cookie: sid=from_B; flag=yes\r\n', recorded['head'], diagnostic)
                        expected = PAYLOAD if index == 0 else b'next\x00\xff'
                        self.assertEqual(recorded['body_sha256'], hashlib.sha256(expected).hexdigest(),
                                         diagnostic)
                    self.assertFalse(remaining, diagnostic)
                    self.assertGreater(sum(wire['server_encrypted_record_lengths']), 32768, diagnostic)
                    if not direct:
                        outbound, = (case / 'runtime').glob('*.outbound.json')
                        ciphers = json.loads(outbound.read_text())['tls']['fields']['ciphers']
                        self.assertIn(cipher_id, ciphers, diagnostic)
                else:
                    self.assertNotIn(b'HTTP/1.1 200', client.stdout, diagnostic)
                    if mode == 'unoffered':
                        self.assertNotIn('selected_cipher', wire, diagnostic)
                        self.assertFalse(application.get('requests'), diagnostic)
                        self.assertIn('no shared cipher', origin_errors.lower(), diagnostic)
                    elif mode == 'unsolicited-cipher':
                        self.assertEqual(wire.get('selected_cipher'), 0x1301, diagnostic)
                        self.assertTrue(wire.get('mutated'), diagnostic)
                        self.assertFalse(wire.get('server_encrypted_record_lengths'), diagnostic)
                        self.assertFalse(application.get('requests'), diagnostic)
                        self.assertIn('WRONG_CIPHER_RETURNED', bridge_log, diagnostic)
                    else:
                        self.assertEqual(wire.get('selected_cipher'), cipher_id, diagnostic)
                        self.assertTrue(wire.get('mutated'), diagnostic)
                        if not direct:
                            self.assertIn('DECRYPTION_FAILED_OR_BAD_RECORD_MAC', bridge_log, diagnostic)
                        if version == '1_3':
                            self.assertFalse(application.get('requests'), diagnostic)
                return dict(cipher=cipher, cipher_id=cipher_id, tls=version, mode=mode,
                            passed=True, wire=wire, http_requests=len(application.get('requests', [])))
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
                proxy.join(timeout=3) if proxy.ident else None
                worker.join(timeout=3) if worker.ident else None
                origin.stdout.close()
                if not origin.stdin.closed:
                    origin.stdin.close()

    def test_real_ccm_suites_large_http_and_authenticated_rejections(self):
        results = []
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)
            material(path)
            for cipher, cipher_id in SUITES:
                modes = ['valid', 'bad-ciphertext', 'bad-tag', 'unoffered']
                if cipher_id in (0x1304, 0x1305):
                    modes.append('unsolicited-cipher')
                for mode in modes:
                    with self.subTest(cipher=cipher, mode=mode):
                        results.append(self.run_case(path, cipher, cipher_id, mode))
        self.assertEqual(len(results), 58)
        output = ROOT / 'test-results/ci-ccm-lab'
        output.mkdir(parents=True, exist_ok=True)
        (output / 'summary.json').write_text(json.dumps(results, indent=2) + '\n')
        print('CCM_RESULTS=' + json.dumps(results, separators=(',', ':')), flush=True)


if __name__ == '__main__':
    unittest.main()
