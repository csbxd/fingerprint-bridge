"""Real TLS negotiation regressions for the patched BoringSSL backend."""
import base64
import json
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import textwrap
import threading
import time
from types import SimpleNamespace
import unittest

from lab import Origin, certificates, exact, head, start_bridge
from matrix_lab import MatrixOrigin, client_command, ROOT


class BackendHandshakeTests(unittest.TestCase):
    @staticmethod
    def _corrupt_first_server_application_record(listener, target_port, result):
        """Forward one TLS connection and corrupt its first server app-data record."""
        client = origin = None
        try:
            client, _ = listener.accept()
            origin = socket.create_connection(('127.0.0.1', target_port), timeout=10)
            client.settimeout(10)
            origin.settimeout(10)

            def upstream():
                try:
                    while data := client.recv(65536):
                        origin.sendall(data)
                    origin.shutdown(socket.SHUT_WR)
                except (OSError, TimeoutError):
                    pass

            sender = threading.Thread(target=upstream, daemon=True)
            sender.start()
            corrupted = False
            while True:
                header = b''
                while len(header) < 5:
                    chunk = origin.recv(5 - len(header))
                    if not chunk:
                        break
                    header += chunk
                if not header:
                    break
                if len(header) != 5:
                    raise EOFError('truncated TLS record header')
                size = int.from_bytes(header[3:5], 'big')
                body = bytearray()
                while len(body) < size:
                    chunk = origin.recv(size - len(body))
                    if not chunk:
                        raise EOFError('truncated TLS record body')
                    body.extend(chunk)
                if header[0] == 23 and body and not corrupted:
                    body[-1] ^= 1
                    corrupted = True
                    result['corrupted'] = True
                client.sendall(header + body)
            sender.join(timeout=2)
            result.setdefault('corrupted', corrupted)
        except Exception as exc:  # surfaced by the test after cleanup
            result['error'] = repr(exc)
        finally:
            for stream in (client, origin, listener):
                if stream:
                    try:
                        stream.close()
                    except OSError:
                        pass

    def test_dhe_rsa_chacha20_real_negotiation_and_bad_tag_rejection(self):
        binary = ROOT / 'target/debug/fingerprint-bridge'
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)
            certificates(path)
            for corrupt in (False, True):
                with self.subTest(corrupted_server_ciphertext=corrupt):
                    case = path / ('dhe-chacha-corrupt' if corrupt else 'dhe-chacha-valid')
                    case.mkdir()
                    with socket.socket() as reserved:
                        reserved.bind(('127.0.0.1', 0))
                        origin_port = reserved.getsockname()[1]
                    origin = subprocess.Popen([
                        'openssl', 's_server', '-accept', f'127.0.0.1:{origin_port}',
                        '-cert', str(path / 'a.pem'), '-key', str(path / 'a.key'),
                        '-www', '-tls1_2', '-cipher', 'DHE-RSA-CHACHA20-POLY1305',
                        '-trace', '-naccept', '1'
                    ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                    proxy_thread = None
                    proxy_result = {}
                    if corrupt:
                        listener = socket.socket()
                        listener.bind(('127.0.0.1', 0))
                        listener.listen(1)
                        upstream_port = listener.getsockname()[1]
                        proxy_thread = threading.Thread(
                            target=self._corrupt_first_server_application_record,
                            args=(listener, origin_port, proxy_result), daemon=True)
                        proxy_thread.start()
                    else:
                        upstream_port = origin_port
                    proc = log = None
                    try:
                        time.sleep(0.2)
                        self.assertIsNone(origin.poll(), origin.stdout.read() if origin.poll() else '')
                        proc, port, log = start_bridge(
                            binary, path, SimpleNamespace(port=upstream_port), case / 'runtime')
                        ctx = ssl.create_default_context(cafile=str(path / 'ca.pem'))
                        response = b''
                        error = None
                        try:
                            with socket.create_connection(('127.0.0.1', port), timeout=10) as raw:
                                with ctx.wrap_socket(raw, server_hostname='b.test') as conn:
                                    conn.sendall(f'GET / HTTP/1.1\r\nHost: b.test:{port}\r\n'
                                                 'Cookie: sid=from_B\r\nConnection: close\r\n\r\n'.encode())
                                    while chunk := conn.recv(4096):
                                        response += chunk
                        except (OSError, ssl.SSLError) as exc:
                            error = exc
                        trace = origin.communicate(timeout=15)[0]
                        if proxy_thread:
                            proxy_thread.join(timeout=5)
                        log.flush()
                        log.seek(0)
                        diagnostics = (trace + '\nbridge: ' + log.read() +
                                       f'\nproxy: {proxy_result!r}\nclient error: {error!r}')
                        self.assertIn('TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256',
                                      trace, diagnostics)
                        outgoing, = (case / 'runtime').glob('*.outbound.json')
                        ciphers = json.loads(outgoing.read_text())['tls']['fields']['ciphers']
                        self.assertIn(0xccaa, ciphers, diagnostics)
                        if corrupt:
                            self.assertTrue(proxy_result.get('corrupted'), diagnostics)
                            self.assertNotIn(b'HTTP/1.0 200', response, diagnostics)
                        else:
                            self.assertIsNone(error, diagnostics)
                            self.assertTrue(response.startswith(b'HTTP/1.0 200'), diagnostics)
                    finally:
                        if proc:
                            proc.terminate()
                            proc.wait(timeout=5)
                        if log:
                            log.close()
                        if origin.poll() is None:
                            origin.terminate()
                            origin.wait(timeout=5)

    def test_sha224_signature_real_negotiation_and_unoffered_rejection(self):
        binary = ROOT / 'target/debug/fingerprint-bridge'
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)
            certificates(path)
            subprocess.run([
                'openssl', 'req', '-new', '-newkey', 'ec',
                '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes',
                '-subj', '/CN=a.test', '-keyout', str(path / 'a-ec.key'),
                '-out', str(path / 'a-ec.csr')
            ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run([
                'openssl', 'x509', '-req', '-in', str(path / 'a-ec.csr'),
                '-CA', str(path / 'ca.pem'), '-CAkey', str(path / 'ca.key'),
                '-CAcreateserial', '-days', '1', '-extfile', str(path / 'a.ext'),
                '-out', str(path / 'a-ec.pem')
            ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            schemes = (
                ('rsa_pkcs1_sha224', 0x0301, path / 'a.pem', path / 'a.key'),
                ('ecdsa_sha224', 0x0303, path / 'a-ec.pem', path / 'a-ec.key'),
            )
            for scheme, scheme_id, certificate, key in schemes:
                for offer_sha224 in (True, False):
                    with self.subTest(signature_scheme=scheme,
                                      client_offers_sha224=offer_sha224):
                        case = path / f'{scheme}-{"offered" if offer_sha224 else "absent"}'
                        case.mkdir()
                        with socket.socket() as reserved:
                            reserved.bind(('127.0.0.1', 0))
                            origin_port = reserved.getsockname()[1]
                        origin = subprocess.Popen([
                            'openssl', 's_server', '-accept', f'127.0.0.1:{origin_port}',
                            '-cert', str(certificate), '-key', str(key),
                            '-www', '-tls1_2', '-cipher',
                            'ECDHE-RSA-AES128-GCM-SHA256:'
                            'ECDHE-ECDSA-AES128-GCM-SHA256:@SECLEVEL=0',
                            '-sigalgs', scheme, '-trace', '-naccept', '1'
                        ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                        proc = log = None
                        try:
                            time.sleep(0.2)
                            self.assertIsNone(
                                origin.poll(), origin.stdout.read() if origin.poll() else '')
                            proc, port, log = start_bridge(
                                binary, path, SimpleNamespace(port=origin_port),
                                case / 'runtime')
                            sigalgs = 'rsa_pss_rsae_sha256'
                            if offer_sha224:
                                sigalgs += f':{scheme}'
                            request = (f'GET /sha224 HTTP/1.1\r\nHost: b.test:{port}\r\n'
                                       'Cookie: sid=from_B\r\nConnection: close\r\n\r\n')
                            client = subprocess.run([
                                'openssl', 's_client', '-connect', f'127.0.0.1:{port}',
                                '-servername', 'b.test', '-CAfile', str(path / 'ca.pem'),
                                '-verify_return_error', '-tls1_2', '-cipher',
                                'ECDHE-RSA-AES128-GCM-SHA256:@SECLEVEL=0',
                                '-sigalgs', sigalgs, '-quiet'
                            ], input=request, capture_output=True, text=True, timeout=30)
                            trace = origin.communicate(timeout=15)[0]
                            log.flush()
                            log.seek(0)
                            diagnostics = (client.stdout + client.stderr + '\norigin: ' + trace +
                                           '\nbridge: ' + log.read())
                            if offer_sha224:
                                outgoing, = (case / 'runtime').glob('*.outbound.json')
                                signatures = json.loads(outgoing.read_text())['tls']['fields'][
                                    'signature_algorithms']
                                self.assertIn(scheme_id, signatures, diagnostics)
                                self.assertIn('sha224', trace.lower(), diagnostics)
                                self.assertIn('HTTP/1.0 200', client.stdout, diagnostics)
                            else:
                                self.assertFalse(
                                    list((case / 'runtime').glob('*.outbound.json')),
                                    diagnostics)
                                self.assertNotIn('HTTP/1.0 200', client.stdout, diagnostics)
                                self.assertTrue(
                                    client.returncode or 'fatal' in diagnostics.lower(),
                                    diagnostics)
                        finally:
                            if proc:
                                proc.terminate()
                                proc.wait(timeout=5)
                            if log:
                                log.close()
                            if origin.poll() is None:
                                origin.terminate()
                                origin.wait(timeout=5)

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
