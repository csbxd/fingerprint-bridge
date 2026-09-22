"""RFC 7366: real TLS 1.2 CBC negotiation and authenticated record rejection.

OpenSSL peers are independent of B. All keys/key logs are synthetic, temporary,
and excluded from the saved evidence. Matrix clients and defaults are untouched.
"""
import hashlib
import hmac
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
from test_ccm import PAYLOAD, client_command, request, run_client, serve_http

# Cover both AES key sizes and every HMAC digest in the supported CBC catalog.
SUITES = (
    ('ECDHE-RSA-AES128-SHA', 0xc013, 'sha1', 'sha256'),
    ('ECDHE-RSA-AES256-SHA', 0xc014, 'sha1', 'sha256'),
    ('ECDHE-RSA-AES128-SHA256', 0xc027, 'sha256', 'sha256'),
    ('ECDHE-RSA-AES256-SHA384', 0xc028, 'sha384', 'sha384'),
)


def handshake_extensions(body, server):
    """The controlled OpenSSL probes emit their Hello in one handshake record."""
    pos = 4 + 2 + 32
    pos += 1 + body[pos]
    if server:
        cipher = int.from_bytes(body[pos:pos + 2], 'big')
        pos += 3
    else:
        cipher = None
        pos += 2 + int.from_bytes(body[pos:pos + 2], 'big')
        pos += 1 + body[pos]
    length_pos = pos
    end = pos + 2 + int.from_bytes(body[pos:pos + 2], "big")
    pos += 2
    extensions = []
    while pos + 4 <= end:
        kind, size = int.from_bytes(body[pos:pos + 2], 'big'), int.from_bytes(body[pos + 2:pos + 4], 'big')
        extensions.append((kind, bytes(body[pos + 4:pos + 4 + size])))
        pos += 4 + size
    return cipher, extensions, length_pos


def p_hash(secret, seed, digest, size):
    a = seed
    result = bytearray()
    while len(result) < size:
        a = hmac.new(secret, a, digest).digest()
        result.extend(hmac.new(secret, a + seed, digest).digest())
    return bytes(result[:size])


def authenticated_bad_padding(body, header, sequence, randoms, keylog, digest, prf):
    # Changing the preceding CBC block's last byte flips the final padding byte.
    # Recompute the correct EtM MAC so the test reaches padding validation.
    lines = keylog.read_text().splitlines()
    secret = next(bytes.fromhex(line.split()[2]) for line in lines
                  if line.startswith('CLIENT_RANDOM ') and
                  line.split()[1].lower() == randoms['client'].hex())
    mac_len = hashlib.new(digest).digest_size
    keys = p_hash(secret, b'key expansion' + randoms['server'] + randoms['client'],
                  prf, 2 * mac_len)
    fragment = bytearray(body[:-mac_len])
    fragment[-17] ^= 0x80
    ad = sequence.to_bytes(8, 'big') + header[:3] + len(fragment).to_bytes(2, 'big')
    return fragment + hmac.new(keys[mac_len:], ad + fragment, digest).digest()


def relay_etm(listener, target, mode, evidence, keylog, digest, prf):
    incoming = origin = sender = None
    randoms = {}
    try:
        incoming, _ = listener.accept()
        origin = socket.create_connection(('127.0.0.1', target), timeout=15)
        incoming.settimeout(15)
        origin.settimeout(15)

        def upstream():
            try:
                while True:
                    head = exact(incoming, 5)
                    body = exact(incoming, int.from_bytes(head[3:5], 'big'))
                    if head[0] == 22 and body[:1] == b'\x01' and 'client' not in randoms:
                        randoms['client'] = body[6:38]
                        _, extensions, _ = handshake_extensions(body, False)
                        evidence['offered_etm'] = (22, b'') in extensions
                    if head[0] == 21 and len(body) == 2:
                        evidence.setdefault('client_alerts', []).append(body[1])
                    origin.sendall(head + body)
            except (OSError, EOFError):
                try:
                    origin.shutdown(socket.SHUT_WR)
                except OSError:
                    pass

        sender = threading.Thread(target=upstream, daemon=True)
        sender.start()
        encrypted = False
        sequence = 0
        while True:
            head = exact(origin, 5)
            body = bytearray(exact(origin, int.from_bytes(head[3:5], 'big')))
            if head[0] == 22 and not encrypted and body[:1] == b'\x02':
                randoms['server'] = bytes(body[6:38])
                cipher, extensions, length_pos = handshake_extensions(body, True)
                evidence['selected_cipher'] = cipher
                evidence['negotiated_etm'] = (22, b'') in extensions
                if mode in ('unsolicited-aead', 'unsolicited-no-offer'):
                    # Inject an invalid EtM response for an AEAD suite. The client
                    # must reject this at ServerHello before Finished/HTTP.
                    first_end = 4 + int.from_bytes(body[1:4], 'big')
                    body[first_end:first_end] = b'\x00\x16\x00\x00'
                    body[length_pos:length_pos + 2] = (int.from_bytes(body[length_pos:length_pos + 2], 'big') + 4).to_bytes(2, 'big')
                    body[1:4] = (first_end).to_bytes(3, 'big')
                    evidence['mutated'] = True
            if head[0] == 23:
                evidence.setdefault('server_application_lengths', []).append(len(body))
                if mode.startswith('bad-') and not evidence.get('mutated'):
                    if mode == 'bad-iv':
                        body[0] ^= 1
                    elif mode == 'bad-mac':
                        body[-1] ^= 1
                    elif mode == 'bad-ciphertext':
                        body[16] ^= 1
                    elif mode == 'bad-truncated':
                        del body[-1:]
                    elif mode == 'bad-padding':
                        body = authenticated_bad_padding(body, head, sequence, randoms,
                                                         keylog, digest, prf)
                        evidence['padding_mac_recomputed'] = True
                    else:
                        raise AssertionError(mode)
                    evidence['mutated'] = True
                    evidence['mutation'] = mode
            incoming.sendall(head[:3] + len(body).to_bytes(2, 'big') + body)
            if encrypted:
                sequence += 1
            if head[0] == 20:
                encrypted = True
                sequence = 0
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


class EncryptThenMACTests(unittest.TestCase):
    def run_case(self, path, suite, mode):
        cipher, cipher_id, digest, prf = suite
        case = path / f'{cipher_id:04x}-{mode}'
        case.mkdir()
        with socket.socket() as reserved:
            reserved.bind(('127.0.0.1', 0))
            origin_port = reserved.getsockname()[1]
        server_cipher = 'ECDHE-RSA-AES128-GCM-SHA256' if mode in ('aead', 'unsolicited-aead') else cipher
        selected_id = 0xc02f if mode in ('aead', 'unsolicited-aead') else cipher_id
        keylog = case / 'synthetic-keylog'
        command = ['openssl', 's_server', '-accept', f'127.0.0.1:{origin_port}',
                   '-cert', str(path / 'a.pem'), '-key', str(path / 'a.key'),
                   '-quiet', '-no_ign_eof', '-naccept', '1', '-alpn', 'http/1.1',
                   '-tls1_2', '-cipher', server_cipher, '-keylogfile', str(keylog)]
        if mode == 'declined':
            command += ['-no_etm']
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
            proxy = threading.Thread(target=relay_etm,
                                     args=(listener, origin_port, mode, wire, keylog, digest, prf), daemon=True)
            worker = threading.Thread(target=serve_http,
                                      args=(origin, f'a.test:{upstream_port}', application), daemon=True)
            try:
                time.sleep(.15)
                self.assertIsNone(origin.poll(), 'OpenSSL origin failed to start')
                proxy.start()
                worker.start()
                proc, port, log = start_bridge(ROOT / 'target/debug/fingerprint-bridge', path,
                                               SimpleNamespace(port=upstream_port), case / 'runtime')
                client_args = client_command(path, port, 'b.test', cipher, '1_2')
                if mode in ('not-offered', 'unsolicited-no-offer'):
                    client_args += ['-no_etm']
                client = run_client(client_args, request(f'b.test:{port}'), case / 'client.log')
                origin.wait(timeout=15)
                proxy.join(timeout=5)
                worker.join(timeout=5)
                log.flush(); log.seek(0)
                bridge_log = log.read()
                origin_log.seek(0)
                diagnostic = repr(wire) + repr(application) + bridge_log + origin_log.read() + client.stderr.decode(errors='replace')
                self.assertFalse(proxy.is_alive(), diagnostic)
                self.assertFalse(worker.is_alive(), diagnostic)
                self.assertNotIn('relay_error', wire, diagnostic)
                self.assertNotIn('http_error', application, diagnostic)
                self.assertEqual(wire.get('selected_cipher'), selected_id, diagnostic)
                self.assertEqual(wire.get('offered_etm'), mode not in ('not-offered', 'unsolicited-no-offer'), diagnostic)
                self.assertEqual(wire.get('negotiated_etm'), mode not in ('not-offered', 'declined', 'aead', 'unsolicited-aead', 'unsolicited-no-offer'), diagnostic)
                if mode.startswith('bad-') or mode in ('unsolicited-aead', 'unsolicited-no-offer'):
                    self.assertNotIn(b'HTTP/1.1 200', client.stdout, diagnostic)
                    self.assertTrue(wire.get('mutated'), diagnostic)
                    expected = 'UNEXPECTED_EXTENSION' if mode in ('unsolicited-aead', 'unsolicited-no-offer') else 'DECRYPTION_FAILED_OR_BAD_RECORD_MAC'
                    self.assertIn(expected, bridge_log, diagnostic)
                    if mode in ('unsolicited-aead', 'unsolicited-no-offer'):
                        self.assertFalse(application.get('requests'), diagnostic)
                    if mode == 'bad-padding':
                        self.assertTrue(wire.get('padding_mac_recomputed'), diagnostic)
                else:
                    self.assertEqual(len(application.get('requests', [])), 2, diagnostic)
                    remaining = client.stdout
                    for index, payload in enumerate((PAYLOAD, b'CCM-ok\x00\xff')):
                        header, remaining = remaining.split(b'\r\n\r\n', 1)
                        self.assertTrue(header.startswith(b'HTTP/1.1 200 OK'), diagnostic)
                        self.assertIn(b'Domain=b.test', header, diagnostic)
                        self.assertIn(f'Location: https://b.test:{port}/next'.encode(), header, diagnostic)
                        self.assertEqual(remaining[:len(payload)], payload, diagnostic)
                        remaining = remaining[len(payload):]
                        recorded = application['requests'][index]
                        self.assertIn(f'hOsT:\ta.test:{upstream_port} ', recorded['head'], diagnostic)
                        self.assertIn('Cookie: sid=from_B; flag=yes\r\n', recorded['head'], diagnostic)
                        expected = PAYLOAD if index == 0 else b'next\x00\xff'
                        self.assertEqual(recorded['body_sha256'], hashlib.sha256(expected).hexdigest(), diagnostic)
                    self.assertFalse(remaining, diagnostic)
                    self.assertGreater(sum(wire['server_application_lengths']), 32768, diagnostic)
                return dict(cipher=cipher, cipher_id=cipher_id, mode=mode, passed=True, wire=wire)
            finally:
                if proc:
                    proc.terminate(); proc.wait(timeout=5)
                if log:
                    log.close()
                if origin.poll() is None:
                    origin.terminate(); origin.wait(timeout=5)
                listener.close()
                proxy.join(timeout=3) if proxy.ident else None
                worker.join(timeout=3) if worker.ident else None
                origin.stdout.close()
                if not origin.stdin.closed:
                    origin.stdin.close()

    def test_independent_3des_etm_handshake_and_authenticated_rejections(self):
        # The system OpenSSL TLS build omits 3DES suites. Use an independent
        # Go record peer; never lower an OpenSSL security level or alter matrix
        # defaults. The controlled client only enables existing B-side suites.
        import shlex
        from prepare_tls import prepare
        from test_ccm_limits import matching_build
        source = prepare()
        _cache, values, libraries = matching_build(source)
        results = []
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)
            certificates(path)
            peer = path / 'etm-3des-origin'
            built = subprocess.run(['go', 'build', '-o', str(peer),
                                    str(ROOT / 'scripts/clients/etm_3des_probe.go')],
                                   capture_output=True, text=True, timeout=120)
            self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
            client_binary = path / 'etm-3des-client'
            flags = shlex.split(values.get('CMAKE_CXX_FLAGS', ''))
            command = [values['CMAKE_CXX_COMPILER'], '-std=c++17', '-O0', *flags,
                       '-DBORINGSSL_IMPLEMENTATION', '-I', str(source),
                       '-I', str(source / 'include'),
                       str(ROOT / 'scripts/clients/etm_3des_client.cc'),
                       *(str(library) for library in libraries), '-pthread', '-ldl',
                       '-o', str(client_binary)]
            built = subprocess.run(command, capture_output=True, text=True, timeout=120)
            self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
            for mode in ('valid', 'bad-iv', 'bad-mac', 'bad-ciphertext', 'bad-truncated', 'bad-padding'):
                with self.subTest(mode=mode):
                    case = path / mode
                    case.mkdir()
                    origin = subprocess.Popen([str(peer), '-cert', str(path / 'a.pem'),
                                               '-key', str(path / 'a.key'), '-mode', mode],
                                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    proc = log = None
                    try:
                        startup = json.loads(origin.stdout.readline())
                        proc, port, log = start_bridge(ROOT / 'target/debug/fingerprint-bridge', path,
                                                       SimpleNamespace(port=startup['port']), case / 'runtime')
                        request_bytes = (f'GET /etm-3des HTTP/1.1\r\nHost: b.test:{port}\r\n'
                                         'Cookie: sid=from_B; flag=yes\r\n\r\n').encode()
                        client = subprocess.run([str(client_binary), str(port), str(path / 'ca.pem')],
                                                input=request_bytes, capture_output=True, timeout=25)
                        output, errors = origin.communicate(timeout=25)
                        evidence = json.loads(output)
                        log.flush(); log.seek(0)
                        bridge_log = log.read()
                        diagnostic = repr(evidence) + errors + client.stderr.decode(errors='replace') + bridge_log
                        self.assertNotIn('error', evidence, diagnostic)
                        self.assertEqual(evidence.get('selected_cipher'), 10, diagnostic)
                        for field in ('client_offered_3des_etm', 'negotiated_etm', 'client_finished_verified',
                                      'http_request_received', 'cookie_preserved', 'authority_rewritten'):
                            self.assertTrue(evidence.get(field), diagnostic)
                        if mode == 'valid':
                            self.assertEqual(client.returncode, 0, diagnostic)
                            header, body = client.stdout.split(b'\r\n\r\n', 1)
                            self.assertIn(b'HTTP/1.1 200 OK', header, diagnostic)
                            self.assertIn(b'Domain=b.test', header, diagnostic)
                            self.assertIn(f'Location: https://b.test:{port}/next'.encode(), header, diagnostic)
                            self.assertEqual(body, b'3DES-etm\x00\xff' * 97 + b'done', diagnostic)
                        else:
                            self.assertNotIn(b'HTTP/1.1 200', client.stdout, diagnostic)
                            self.assertIn('DECRYPTION_FAILED_OR_BAD_RECORD_MAC', bridge_log, diagnostic)
                            if mode == 'bad-padding':
                                self.assertTrue(evidence.get('authenticated_bad_padding'), diagnostic)
                        results.append(dict(evidence, passed=True))
                    finally:
                        if proc:
                            proc.terminate(); proc.wait(timeout=5)
                        if log:
                            log.close()
                        if origin.poll() is None:
                            origin.terminate(); origin.wait(timeout=5)
                        origin.stdout.close(); origin.stderr.close()
        self.assertEqual(len(results), 6)
        output = ROOT / 'test-results/ci-etm-3des-lab'
        output.mkdir(parents=True, exist_ok=True)
        (output / 'summary.json').write_text(json.dumps(results, indent=2) + '\n')
        print('ETM_3DES_RESULTS=' + json.dumps(results, separators=(',', ':')), flush=True)

    def test_real_etm_negotiation_http_and_authenticated_rejections(self):
        results = []
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)
            certificates(path)
            for suite in SUITES:
                for mode in ('valid', 'bad-iv', 'bad-mac', 'bad-ciphertext', 'bad-truncated', 'bad-padding'):
                    with self.subTest(cipher=suite[0], mode=mode):
                        results.append(self.run_case(path, suite, mode))
            for mode in ('not-offered', 'declined', 'aead', 'unsolicited-aead', 'unsolicited-no-offer'):
                with self.subTest(mode=mode):
                    results.append(self.run_case(path, SUITES[0], mode))
        self.assertEqual(len(results), 29)
        output = ROOT / 'test-results/ci-etm-lab'
        output.mkdir(parents=True, exist_ok=True)
        (output / 'summary.json').write_text(json.dumps(results, indent=2) + '\n')
        print('ETM_RESULTS=' + json.dumps(results, separators=(',', ':')), flush=True)


if __name__ == '__main__':
    unittest.main()
