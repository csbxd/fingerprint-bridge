"""Real TLS 1.2 sect283r1 tests against an independent system-libcrypto peer.

The default fingerprint matrix clients are untouched. Only these synthetic
capability probes explicitly offer the legacy binary curve. Negative probes
also test a correctly signed flight selecting an unoffered group or format.
"""
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import tempfile
import threading
from types import SimpleNamespace
import unittest

from lab import exact, start_bridge
from matrix_lab import ROOT
from test_ccm import pipe_exact, pipe_head
from test_status_v2 import material


CASES = ('compressed', 'uncompressed', 'malformed', 'off-curve',
         'small-subgroup', 'mixed-subgroup', 'infinity', 'format-not-offered',
         'group-not-offered', 'bad-certificate', 'bad-handshake-signature')


def run_client(command, request, log_path):
    """Keep stdin open until the verified client receives its full response.

    The relay can keep the client side open after A sends close_notify. Closing
    stdin after one complete HTTP response terminates s_client without truncating
    the request, waiting for a second request, or ignoring an incomplete reply.
    """
    output, errors = bytearray(), []
    with log_path.open('w+b') as log:
        client = subprocess.Popen(command, stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE, stderr=log)
        try:
            client.stdin.write(request)
            client.stdin.flush()
        except (BrokenPipeError, OSError):
            pass

        def receive():
            try:
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
                try:
                    client.stdin.close()
                except (BrokenPipeError, OSError):
                    pass

        reader = threading.Thread(target=receive, daemon=True)
        reader.start()
        try:
            client.wait(timeout=25)
            reader.join(timeout=5)
            if reader.is_alive() or errors:
                raise AssertionError(f'OpenSSL response reader failed: {errors}')
            log.seek(0)
            return SimpleNamespace(stdout=bytes(output), stderr=log.read(),
                                   returncode=client.returncode)
        finally:
            if client.poll() is None:
                client.terminate()
                client.wait(timeout=5)
            reader.join(timeout=5)
            client.stdout.close()
            if not client.stdin.closed:
                client.stdin.close()


def raw_negative_hello(port, mode):
    """A complete ClientHello suffices: B validates A before accepting its client.

    This avoids modifying an actual client's handshake transcript. The peer
    independently checks B's advertised vectors and proves B rejects the
    forbidden selection before ClientKeyExchange or any HTTP can be sent.
    """
    def u16(value):
        return struct.pack('!H', value)

    def extension(kind, value):
        return u16(kind) + u16(len(value)) + value

    groups = [23] if mode == 'group-not-offered' else [23, 10]
    formats = [0, 1] if mode == 'format-not-offered' else [0, 1, 2]
    host = b'b.test'
    server_name = b'\x00' + u16(len(host)) + host
    group_list = b''.join(u16(group) for group in groups)
    extensions = b''.join((
        extension(0, u16(len(server_name)) + server_name),
        extension(10, u16(len(group_list)) + group_list),
        extension(11, bytes([len(formats), *formats])),
        extension(13, b'\x00\x04\x04\x01\x08\x04'),
        extension(16, b'\x00\x09\x08http/1.1'),
        extension(65281, b'\x00'),
    ))
    body = (b'\x03\x03' + os.urandom(32) + b'\x00' +
            b'\x00\x02\xc0\x2f' + b'\x01\x00' +
            u16(len(extensions)) + extensions)
    hello = b'\x01' + len(body).to_bytes(3, 'big') + body
    with socket.create_connection(('127.0.0.1', port), timeout=15) as client:
        client.sendall(b'\x16\x03\x01' + u16(len(hello)) + hello)
        while client.recv(4096):
            pass


class Char2HandshakeTests(unittest.TestCase):
    def test_real_binary_curve_and_rejections(self):
        results = []
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)
            material(path)
            peer = path / 'char2-origin'
            env = dict(os.environ, CGO_ENABLED='1')
            built = subprocess.run(['go', 'build', '-o', str(peer),
                                    str(ROOT / 'scripts/clients/char2_probe.go')],
                                   capture_output=True, text=True, timeout=120, env=env)
            self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
            for mode in CASES:
                with self.subTest(mode=mode):
                    results.append(self.run_case(peer, path, mode))
            with self.subTest(mode='tls13-hrr-binary-group'):
                results.append(self.run_hrr_case(path))
        self.assertEqual(len(results), len(CASES) + 1)
        output = ROOT / 'test-results/ci-char2-lab'
        output.mkdir(parents=True, exist_ok=True)
        (output / 'summary.json').write_text(json.dumps(results, indent=2) + '\n')
        print('CHAR2_RESULTS=' + json.dumps(results, separators=(',', ':')), flush=True)

    def run_case(self, peer, path, mode):
        origin = subprocess.Popen([str(peer), '-cert', str(path / 'a.pem'),
                                   '-key', str(path / 'a.key'), '-mode', mode],
                                  stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, text=True)
        proc = log = None
        try:
            startup = json.loads(origin.stdout.readline())
            proc, port, log = start_bridge(
                ROOT / 'target/debug/fingerprint-bridge', path,
                SimpleNamespace(port=startup['port']), path / f'runtime-char2-{mode}')
            client_output, client_errors, client_code = b'', b'', None
            if mode in ('format-not-offered', 'group-not-offered'):
                try:
                    raw_negative_hello(port, mode)
                except (ConnectionResetError, BrokenPipeError):
                    pass
            else:
                request = (f'GET /char2 HTTP/1.1\r\nHost: b.test:{port}\r\n'
                           'Cookie: sid=from_B\r\nConnection: close\r\n\r\n').encode()
                client = run_client([
                    'openssl', 's_client', '-connect', f'127.0.0.1:{port}',
                    '-servername', 'b.test', '-verify_hostname', 'b.test',
                    '-CAfile', str(path / 'ca.pem'), '-verify_return_error',
                    '-tls1_2', '-alpn', 'http/1.1', '-groups', 'P-256:sect283r1',
                    '-cipher', 'ECDHE-RSA-AES128-GCM-SHA256', '-quiet', '-no_ign_eof',
                ], request, path / f'client-char2-{mode}.log')
                client_output, client_errors, client_code = client.stdout, client.stderr, client.returncode
            output, errors = origin.communicate(timeout=25)
            evidence = json.loads(output)
            log.flush()
            log.seek(0)
            bridge_log = log.read()
            diagnostic = (repr(evidence) + errors + bridge_log +
                          client_errors.decode(errors='replace'))
            self.assertNotIn('error', evidence, diagnostic)
            self.assertEqual(evidence.get('curve'), 'sect283r1', diagnostic)
            self.assertIn('OpenSSL', evidence.get('independent_crypto', ''), diagnostic)
            self.assertEqual(evidence.get('server_group'), 10, diagnostic)
            self.assertTrue(evidence.get('server_key_sent'), diagnostic)
            self.assertEqual(evidence.get('selected_group_offered'), mode != 'group-not-offered', diagnostic)
            self.assertEqual(evidence.get('compressed_char2_offered'), mode != 'format-not-offered', diagnostic)
            self.assertEqual(evidence.get('outgoing_point_formats'),
                             [0, 1] if mode == 'format-not-offered' else [0, 1, 2], diagnostic)
            if mode in ('compressed', 'uncompressed'):
                self.assertEqual(client_code, 0, diagnostic)
                self.assertIn(b'200 OK', client_output, diagnostic)
                self.assertIn(b'CHAR2_OK', client_output, diagnostic)
                for field in ('client_finished_verified', 'http_request_received',
                              'cookie_preserved', 'authority_rewritten'):
                    self.assertTrue(evidence.get(field), diagnostic)
                expected = 73 if mode == 'uncompressed' else 37
                self.assertEqual(evidence.get('server_point_bytes'), expected, diagnostic)
                self.assertIn(evidence.get('server_point_prefix'),
                              [4] if mode == 'uncompressed' else [2, 3], diagnostic)
            else:
                if client_code is not None:
                    self.assertNotEqual(client_code, 0, diagnostic)
                self.assertNotIn(b'200 OK', client_output, diagnostic)
                self.assertTrue(evidence.get('negative_rejected'), diagnostic)
                self.assertTrue(evidence.get('rejected_before_client_key_exchange'), diagnostic)
                self.assertNotIn('http_request_received', evidence, diagnostic)
                self.assertNotIn('client_finished_verified', evidence, diagnostic)
                if mode == 'bad-certificate':
                    self.assertIn('CERTIFICATE_VERIFY_FAILED', bridge_log, diagnostic)
                elif mode == 'bad-handshake-signature':
                    self.assertIn('BAD_SIGNATURE', bridge_log, diagnostic)
                else:
                    self.assertEqual(evidence.get('client_alert'), 47, diagnostic)
                if mode == 'small-subgroup':
                    self.assertTrue(evidence.get('fixture_order_two_confirmed'), diagnostic)
                if mode == 'mixed-subgroup':
                    self.assertTrue(evidence.get('fixture_mixed_subgroup_confirmed'), diagnostic)
                if mode == 'off-curve':
                    self.assertTrue(evidence.get('fixture_off_curve_confirmed'), diagnostic)
            return dict(evidence, passed=True, downstream_exit=client_code)
        finally:
            if proc:
                proc.terminate()
                proc.wait(timeout=5)
            if log:
                log.close()
            if origin.poll() is None:
                origin.terminate()
                origin.wait(timeout=5)
            origin.stdout.close()
            origin.stderr.close()

    def run_hrr_case(self, path):
        """An offered legacy group must never become a TLS 1.3 key share.

        The unmodified OpenSSL probe offers versions 1.3/1.2, groups 23/10 and
        only a P-256 key share. A synthetic HRR selecting binary group 10 must
        fail immediately, before a second ClientHello or application data.
        """
        wire = {'mode': 'tls13-hrr-binary-group'}
        listener = socket.socket()
        listener.bind(('127.0.0.1', 0))
        listener.listen(1)
        listener.settimeout(15)

        def server():
            try:
                with listener.accept()[0] as client:
                    client.settimeout(15)
                    header = exact(client, 5)
                    hello = exact(client, int.from_bytes(header[3:5], 'big'))
                    if header[0] != 22 or hello[0] != 1:
                        raise ValueError('expected initial ClientHello')
                    pos = 38
                    session = hello[pos + 1:pos + 1 + hello[pos]]
                    pos += 1 + hello[pos]
                    size = int.from_bytes(hello[pos:pos + 2], 'big')
                    ciphers = [int.from_bytes(hello[i:i + 2], 'big')
                               for i in range(pos + 2, pos + 2 + size, 2)]
                    pos += 2 + size
                    pos += 1 + hello[pos]
                    size = int.from_bytes(hello[pos:pos + 2], 'big')
                    pos += 2
                    if pos + size != len(hello):
                        raise ValueError('bad ClientHello extension length')
                    extensions = {}
                    while pos < len(hello):
                        kind = int.from_bytes(hello[pos:pos + 2], 'big')
                        size = int.from_bytes(hello[pos + 2:pos + 4], 'big')
                        extensions[kind] = hello[pos + 4:pos + 4 + size]
                        pos += 4 + size
                    groups = extensions.get(10, b'')
                    groups = [int.from_bytes(groups[i:i + 2], 'big')
                              for i in range(2, len(groups), 2)]
                    versions = extensions.get(43, b'')
                    versions = [int.from_bytes(versions[i:i + 2], 'big')
                                for i in range(1, len(versions), 2)]
                    shares = extensions.get(51, b'')
                    share_groups, pos = [], 2
                    while pos + 4 <= len(shares):
                        share_groups.append(int.from_bytes(shares[pos:pos + 2], 'big'))
                        size = int.from_bytes(shares[pos + 2:pos + 4], 'big')
                        pos += 4 + size
                    wire.update(outgoing_groups=groups, outgoing_versions=versions,
                                outgoing_keyshare_groups=share_groups)
                    if 10 not in groups or 0x0304 not in versions or 0x1301 not in ciphers:
                        raise ValueError('probe did not offer group 10 plus TLS 1.3/AES128-GCM')
                    if 10 in share_groups or 23 not in share_groups:
                        raise ValueError('unexpected initial key share')
                    magic = bytes.fromhex('cf21ad74e59a6111be1d8c021e65b891'
                                          'c2a211167abb8c5e079e09e2c8a8339c')
                    ext = b'\x00\x2b\x00\x02\x03\x04\x00\x33\x00\x02\x00\x0a'
                    body = (b'\x03\x03' + magic + bytes([len(session)]) + session +
                            b'\x13\x01\x00' + len(ext).to_bytes(2, 'big') + ext)
                    reply = b'\x02' + len(body).to_bytes(3, 'big') + body
                    client.sendall(b'\x16\x03\x03' + len(reply).to_bytes(2, 'big') + reply)
                    wire['hrr_group'] = 10
                    wire['hrr_sent'] = True
                    records = []
                    for _ in range(3):
                        header = exact(client, 5)
                        data = exact(client, int.from_bytes(header[3:5], 'big'))
                        records.append(header[0])
                        if header[0] == 20:  # permitted compatibility CCS
                            if data != b'\x01':
                                raise ValueError('bad compatibility CCS')
                            continue
                        if header[0] != 21 or len(data) != 2:
                            raise ValueError('binary group HRR was not immediately rejected')
                        wire['client_alert'] = data[1]
                        wire['rejected_before_second_client_hello'] = True
                        break
                    wire['records_after_hrr'] = records
            except Exception as exc:
                wire['error'] = repr(exc)
            finally:
                listener.close()

        worker = threading.Thread(target=server, daemon=True)
        proc = log = None
        worker.start()
        try:
            proc, port, log = start_bridge(
                ROOT / 'target/debug/fingerprint-bridge', path,
                SimpleNamespace(port=listener.getsockname()[1]),
                path / 'runtime-char2-tls13-hrr')
            client = subprocess.run([
                'openssl', 's_client', '-connect', f'127.0.0.1:{port}',
                '-servername', 'b.test', '-verify_hostname', 'b.test',
                '-CAfile', str(path / 'ca.pem'), '-verify_return_error',
                '-groups', 'P-256:sect283r1', '-quiet', '-ign_eof',
            ], input=b'GET / HTTP/1.1\r\nHost: b.test\r\n\r\n',
               capture_output=True, timeout=25)
            worker.join(timeout=20)
            log.flush()
            log.seek(0)
            diagnostic = repr(wire) + log.read() + client.stderr.decode(errors='replace')
            self.assertFalse(worker.is_alive(), diagnostic)
            self.assertNotIn('error', wire, diagnostic)
            self.assertTrue(wire.get('hrr_sent'), diagnostic)
            self.assertTrue(wire.get('rejected_before_second_client_hello'), diagnostic)
            self.assertEqual(wire.get('client_alert'), 47, diagnostic)
            self.assertNotIn(22, wire.get('records_after_hrr', []), diagnostic)
            self.assertNotIn(23, wire.get('records_after_hrr', []), diagnostic)
            self.assertNotIn(b'200 OK', client.stdout, diagnostic)
            self.assertNotEqual(client.returncode, 0, diagnostic)
            return dict(wire, passed=True)
        finally:
            if proc:
                proc.terminate()
                proc.wait(timeout=5)
            if log:
                log.close()
            listener.close()
            worker.join(timeout=3)


if __name__ == '__main__':
    unittest.main()
