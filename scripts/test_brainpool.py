"""Real RFC 8734 authentication and Brainpool certificate-chain verification.

Only isolated test peers restrict algorithms. Defaults in the 72-cell matrix,
certificate/hostname verification, and OpenSSL security levels are unchanged.
"""
import base64
import hashlib
import json
from pathlib import Path
import re
import socket
import subprocess
import tempfile
import textwrap
import threading
import time
from types import SimpleNamespace
import unittest

from lab import certificates, start_bridge
from matrix_lab import ROOT
from test_ccm import PAYLOAD, openssl, request, run_client, serve_http
from prepare_test_openssl import prepare as prepare_peer

CURVES = ((256, 'sha256', 0x081a), (384, 'sha384', 0x081b), (512, 'sha512', 0x081c))


def corrupt_certificate(source, destination):
    der = bytearray(base64.b64decode(''.join(source.read_text().splitlines()[1:-1])))
    der[-1] ^= 1
    destination.write_text('-----BEGIN CERTIFICATE-----\n' +
                           '\n'.join(textwrap.wrap(base64.b64encode(der).decode(), 64)) +
                           '\n-----END CERTIFICATE-----\n')


def material(path):
    certificates(path)
    wrong_ext = path / 'wrong.ext'
    wrong_ext.write_text((path / 'a.ext').read_text().replace('DNS:a.test', 'DNS:wrong.test'))
    for bits, digest, _scheme in CURVES:
        name = f'brainpool{bits}'
        openssl('genpkey', '-algorithm', 'EC', '-pkeyopt', f'ec_paramgen_curve:brainpoolP{bits}r1',
                '-out', path / f'{name}.key')
        openssl('req', '-new', '-key', path / f'{name}.key', '-subj', '/CN=a.test',
                f'-{digest}', '-out', path / f'{name}.csr')
        openssl('req', '-new', '-x509', '-newkey', 'ec', '-pkeyopt',
                f'ec_paramgen_curve:brainpoolP{bits}r1', '-nodes', '-days', '1',
                f'-{digest}', '-subj', f'/CN=Brainpool {bits} test CA',
                '-addext', 'basicConstraints=critical,CA:TRUE',
                '-addext', 'keyUsage=critical,keyCertSign',
                '-keyout', path / f'{name}-ca.key', '-out', path / f'{name}-ca.pem')
        for feature, csr, ca in [('leaf', f'{name}.csr', 'ca'),
                                 ('ca', 'a.csr', f'{name}-ca')]:
            prefix = f'{name}-{feature}'
            for mode, ext in [('valid', path / 'a.ext'), ('wrong-host', wrong_ext)]:
                openssl('x509', '-req', '-in', path / csr, '-CA', path / f'{ca}.pem',
                        '-CAkey', path / f'{ca}.key', '-CAcreateserial', '-days', '1',
                        f'-{digest}', '-extfile', ext, '-out', path / f'{prefix}-{mode}.pem')
            corrupt_certificate(path / f'{prefix}-valid.pem', path / f'{prefix}-bad-certificate.pem')
    # Add only these generated CA certificates. No system verification bypass.
    with (path / 'ca.pem').open('ab') as bundle:
        for bits, _digest, _scheme in CURVES:
            bundle.write((path / f'brainpool{bits}-ca.pem').read_bytes())


def certificate_verify_ids(trace):
    """OpenSSL's public handshake trace records its real CertificateVerify.

    This observes the independently generated message before TLS record
    encryption. No session keys or key-log files are produced or consumed.
    """
    messages = re.findall(r'>>> TLS 1\.3, Handshake[^\n]*CertificateVerify\n'
                          r'((?:[ \t]+[0-9a-f][0-9a-f ]*\n)+)', trace)
    ids = []
    for message in messages:
        wire = bytes.fromhex(message)
        if len(wire) < 8 or wire[0] != 15 or int.from_bytes(wire[1:4], 'big') != len(wire) - 4:
            raise AssertionError('Malformed OpenSSL CertificateVerify trace')
        if int.from_bytes(wire[6:8], 'big') != len(wire) - 8:
            raise AssertionError('Malformed CertificateVerify signature vector')
        ids.append(int.from_bytes(wire[4:6], 'big'))
    return ids


class BrainpoolHandshakeTests(unittest.TestCase):
    def run_case(self, path, bits, digest, scheme, feature, mode, peer):
        case = path / f'{bits}-{feature}-{mode}'
        case.mkdir()
        with socket.socket() as reserved:
            reserved.bind(('127.0.0.1', 0))
            origin_port = reserved.getsockname()[1]
        cert_mode = mode if mode in ('wrong-host', 'bad-certificate') else 'valid'
        cert = path / f'brainpool{bits}-{feature}-{cert_mode}.pem'
        key = path / (f'brainpool{bits}.key' if feature == 'leaf' else 'a.key')
        algorithm = f'ecdsa_brainpoolP{bits}r1tls13_{digest}'
        signature = algorithm if feature == 'leaf' else 'rsa_pss_rsae_sha256'
        command = [str(peer), 's_server', '-accept', f'127.0.0.1:{origin_port}',
                   '-cert', str(cert), '-key', str(key), '-quiet', '-no_ign_eof',
                   '-naccept', '1', '-alpn', 'http/1.1', '-tls1_3',
                   '-groups', 'X25519', '-sigalgs', signature,
                   '-ciphersuites', 'TLS_AES_128_GCM_SHA256',
                   '-msg', '-msgfile', str(case / 'handshake.log')]
        application = {}
        proc = log = None
        with (case / 'origin.log').open('w+') as origin_log:
            origin = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                      stderr=origin_log)
            worker = threading.Thread(target=serve_http,
                                      args=(origin, f'a.test:{origin_port}', application), daemon=True)
            try:
                time.sleep(.15)
                self.assertIsNone(origin.poll(), 'OpenSSL Brainpool origin failed to start')
                worker.start()
                proc, port, log = start_bridge(ROOT / 'target/debug/fingerprint-bridge', path,
                                              SimpleNamespace(port=origin_port), case / 'runtime')
                sigs = ('rsa_pss_rsae_sha256:rsa_pkcs1_sha256:rsa_pkcs1_sha384:rsa_pkcs1_sha512:'
                        'ecdsa_secp256r1_sha256:ecdsa_secp384r1_sha384:ecdsa_secp521r1_sha512')
                if mode != 'unoffered':
                    sigs += ':' + algorithm
                client = run_client([
                    str(peer), 's_client', '-connect', f'127.0.0.1:{port}', '-servername', 'b.test',
                    '-verify_hostname', 'b.test', '-CAfile', str(path / 'ca.pem'), '-verify_return_error',
                    '-tls1_3', '-alpn', 'http/1.1', '-quiet', '-no_ign_eof',
                    '-groups', 'X25519', '-sigalgs', sigs,
                    '-ciphersuites', 'TLS_AES_128_GCM_SHA256',
                ], request(f'b.test:{port}'), case / 'client.log')
                origin.wait(timeout=15)
                worker.join(timeout=5)
                origin_log.seek(0)
                errors = origin_log.read()
                log.seek(0)
                bridge_log = log.read()
                trace = (case / 'handshake.log').read_text()
                selected = certificate_verify_ids(trace)
                diagnostic = (repr(application) + errors + bridge_log +
                              client.stderr.decode(errors='replace') + repr(selected))
                self.assertFalse(worker.is_alive(), diagnostic)
                self.assertNotIn('http_error', application, diagnostic)
                if mode == 'valid':
                    self.assertEqual(selected, [scheme if feature == 'leaf' else 0x0804], diagnostic)
                    self.assertEqual(len(application.get('requests', [])), 2, diagnostic)
                    remaining = client.stdout
                    for index, payload in enumerate((PAYLOAD, b'CCM-ok\x00\xff')):
                        header, remaining = remaining.split(b'\r\n\r\n', 1)
                        self.assertTrue(header.startswith(b'HTTP/1.1 200 OK'), diagnostic)
                        self.assertIn(b'Domain=b.test', header, diagnostic)
                        self.assertIn(f'Location: https://b.test:{port}/next'.encode(), header, diagnostic)
                        self.assertEqual(remaining[:len(payload)], payload, diagnostic)
                        remaining = remaining[len(payload):]
                        record = application['requests'][index]
                        self.assertIn(f'hOsT:\ta.test:{origin_port} ', record['head'], diagnostic)
                        self.assertIn('Cookie: sid=from_B; flag=yes\r\n', record['head'], diagnostic)
                        expected = PAYLOAD if index == 0 else b'next\x00\xff'
                        self.assertEqual(record['body_sha256'], hashlib.sha256(expected).hexdigest(), diagnostic)
                    self.assertFalse(remaining, diagnostic)
                    outbound, = (case / 'runtime').glob('*.outbound.json')
                    fields = json.loads(outbound.read_text())['tls']['fields']
                    self.assertIn(scheme, fields['signature_algorithms'], diagnostic)
                    self.assertEqual(fields['groups'], [29], diagnostic)
                else:
                    self.assertFalse(application.get('requests'), diagnostic)
                    self.assertNotIn(b'HTTP/1.1 200', client.stdout, diagnostic)
                    if mode == 'unoffered':
                        self.assertFalse(selected, diagnostic)
                        self.assertRegex(errors.lower(),
                                         'no suitable signature algorithm|no shared signature algorithms', diagnostic)
                    else:
                        self.assertIn('CERTIFICATE_VERIFY_FAILED', bridge_log, diagnostic)
                return dict(curve=f'brainpoolP{bits}r1', feature=feature, tls='1_3', mode=mode,
                            scheme=scheme, certificate_verify=selected, passed=True,
                            http_requests=len(application.get('requests', [])))
            finally:
                if proc:
                    proc.terminate()
                    proc.wait(timeout=5)
                if log:
                    log.close()
                if origin.poll() is None:
                    origin.terminate()
                    origin.wait(timeout=5)
                if worker.ident:
                    worker.join(timeout=3)
                origin.stdout.close()
                if not origin.stdin.closed:
                    origin.stdin.close()

    def test_brainpool_signatures_certificates_and_rejections(self):
        observations = []
        peer = prepare_peer()
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)
            material(path)
            for bits, digest, scheme in CURVES:
                for feature in ('leaf', 'ca'):
                    modes = ['valid', 'bad-certificate', 'wrong-host']
                    if feature == 'leaf':
                        modes.append('unoffered')
                    for mode in modes:
                        with self.subTest(bits=bits, feature=feature, mode=mode):
                            observations.append(self.run_case(path, bits, digest, scheme, feature, mode, peer))
        self.assertEqual(len(observations), 21)
        output = ROOT / 'test-results/ci-brainpool-lab'
        output.mkdir(parents=True, exist_ok=True)
        (output / 'summary.json').write_text(json.dumps(observations, indent=2) + '\n')
        print('BRAINPOOL_RESULTS=' + json.dumps(observations, separators=(',', ':')), flush=True)


if __name__ == '__main__':
    unittest.main()
