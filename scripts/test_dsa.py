"""Independent OpenSSL TLS 1.2 DSA negotiation; no matrix-client changes."""
import base64
import json
import socket
import subprocess
import tempfile
import textwrap
import time
import unittest
from pathlib import Path
from types import SimpleNamespace

from lab import certificates, start_bridge
from matrix_lab import ROOT


SUITES = (
    ('DHE-DSS-AES128-SHA', 0x0032),
    ('DHE-DSS-AES256-SHA', 0x0038),
    ('DHE-DSS-AES128-SHA256', 0x0040),
    ('DHE-DSS-AES256-SHA256', 0x006a),
    ('DHE-DSS-AES128-GCM-SHA256', 0x00a2),
    ('DHE-DSS-AES256-GCM-SHA384', 0x00a3),
)
SCHEMES = (('SHA1', 0x0202), ('SHA224', 0x0302), ('SHA256', 0x0402),
           ('SHA384', 0x0502), ('SHA512', 0x0602))


def openssl(*args):
    result = subprocess.run(['openssl', *map(str, args)], capture_output=True,
                            text=True, timeout=60)
    if result.returncode:
        raise AssertionError(result.stdout + result.stderr)


def dsa_chain(path):
    params, root_key, root, key, csr, leaf = [path / name for name in (
        'params.pem', 'root.key', 'root.pem', 'leaf.key', 'leaf.csr', 'leaf.pem')]
    openssl('genpkey', '-genparam', '-algorithm', 'DSA', '-pkeyopt',
            'dsa_paramgen_bits:2048', '-pkeyopt', 'dsa_paramgen_q_bits:256',
            '-out', params)
    openssl('genpkey', '-paramfile', params, '-out', root_key)
    openssl('req', '-x509', '-new', '-key', root_key, '-sha256', '-days', '1',
            '-subj', '/CN=DSA test CA', '-addext', 'basicConstraints=critical,CA:TRUE',
            '-addext', 'keyUsage=critical,keyCertSign', '-out', root)
    openssl('genpkey', '-paramfile', params, '-out', key)
    openssl('req', '-new', '-key', key, '-subj', '/CN=a.test',
            '-addext', 'subjectAltName=DNS:a.test',
            '-addext', 'basicConstraints=critical,CA:FALSE',
            '-addext', 'keyUsage=critical,digitalSignature',
            '-addext', 'extendedKeyUsage=serverAuth', '-out', csr)
    openssl('x509', '-req', '-in', csr, '-CA', root, '-CAkey', root_key,
            '-CAcreateserial', '-days', '1', '-sha256', '-copy_extensions', 'copy',
            '-out', leaf)
    der = bytearray(base64.b64decode(''.join(leaf.read_text().splitlines()[1:-1])))
    der[-1] ^= 1
    tampered = path / 'tampered.pem'
    tampered.write_text('-----BEGIN CERTIFICATE-----\n' +
                        '\n'.join(textwrap.wrap(base64.b64encode(der).decode(), 64)) +
                        '\n-----END CERTIFICATE-----\n')
    return root, key, leaf, tampered


class DsaTests(unittest.TestCase):
    def test_real_dhe_dss_suites_signatures_and_rejections(self):
        observations = []
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)
            certificates(path)
            material = path / 'dsa'
            material.mkdir()
            root, key, leaf, tampered = dsa_chain(material)
            with (path / 'ca.pem').open('ab') as bundle:
                bundle.write(root.read_bytes())
            cases = [(cipher, cipher_id, sha, signature_id, 'valid')
                     for cipher, cipher_id in SUITES for sha, signature_id in SCHEMES]
            cases += [(SUITES[4][0], SUITES[4][1], 'SHA256', 0x0402, mode)
                      for mode in ('unoffered', 'tampered-certificate')]
            for index, (cipher, cipher_id, sha, signature_id, mode) in enumerate(cases):
                with self.subTest(cipher=cipher, signature=sha, mode=mode):
                    case = path / str(index)
                    case.mkdir()
                    with socket.socket() as reserved:
                        reserved.bind(('127.0.0.1', 0))
                        origin_port = reserved.getsockname()[1]
                    # A trace can exceed pipe capacity; use a file to avoid a
                    # deadlock while s_client waits for the HTTP response.
                    with (case / 'origin.log').open('w+') as origin_log:
                        origin = subprocess.Popen([
                            'openssl', 's_server', '-accept', f'127.0.0.1:{origin_port}',
                            '-cert', str(tampered if mode == 'tampered-certificate' else leaf),
                            '-key', str(key), '-www', '-tls1_2', '-cipher',
                            f'{cipher}:@SECLEVEL=0', '-sigalgs', f'DSA+{sha}',
                            '-trace', '-naccept', '1',
                        ], stdout=origin_log, stderr=subprocess.STDOUT)
                        proc = log = None
                        try:
                            time.sleep(.2)
                            self.assertIsNone(origin.poll())
                            proc, port, log = start_bridge(
                                ROOT / 'target/debug/fingerprint-bridge', path,
                                SimpleNamespace(port=origin_port), case / 'runtime')
                            sigs = ['rsa_pss_rsae_sha256']
                            if mode != 'unoffered':
                                sigs += list(dict.fromkeys([f'DSA+{sha}', 'DSA+SHA256']))
                            request = (f'GET /dsa HTTP/1.1\r\nHost: b.test:{port}\r\n'
                                       'Cookie: sid=from_B\r\nConnection: close\r\n\r\n')
                            client = subprocess.run([
                                'openssl', 's_client', '-connect', f'127.0.0.1:{port}',
                                '-servername', 'b.test', '-verify_hostname', 'b.test',
                                '-CAfile', str(path / 'ca.pem'), '-verify_return_error',
                                '-tls1_2', '-cipher',
                                f'ECDHE-RSA-AES128-GCM-SHA256:{cipher}:@SECLEVEL=0',
                                '-sigalgs', ':'.join(sigs), '-quiet',
                            ], input=request, capture_output=True, text=True, timeout=30)
                            origin.wait(timeout=15)
                            origin_log.seek(0)
                            trace = origin_log.read()
                            log.flush()
                            log.seek(0)
                            bridge_log = log.read()
                            diagnostics = client.stdout + client.stderr + trace + bridge_log
                            passed_http = 'HTTP/1.0 200' in client.stdout
                            if mode == 'valid':
                                self.assertTrue(passed_http, diagnostics)
                                self.assertIn(f'Signature Algorithm: dsa_{sha.lower()}',
                                              trace, diagnostics)
                                outgoing, = (case / 'runtime').glob('*.outbound.json')
                                fields = json.loads(outgoing.read_text())['tls']['fields']
                                self.assertIn(cipher_id, fields['ciphers'], diagnostics)
                                self.assertIn(signature_id, fields['signature_algorithms'], diagnostics)
                            else:
                                self.assertFalse(passed_http, diagnostics)
                                self.assertIn('fatal', trace.lower(), diagnostics)
                                self.assertFalse(list((case / 'runtime').glob('*.outbound.json')),
                                                 diagnostics)
                                if mode == 'tampered-certificate':
                                    self.assertIn('CERTIFICATE_VERIFY_FAILED', bridge_log, diagnostics)
                            observations.append(dict(cipher=cipher, cipher_id=cipher_id,
                                                     signature=sha, signature_id=signature_id,
                                                     mode=mode, http=passed_http, passed=True))
                        finally:
                            if proc:
                                proc.terminate()
                                proc.wait(timeout=5)
                            if log:
                                log.close()
                            if origin.poll() is None:
                                origin.terminate()
                                origin.wait(timeout=5)
        self.assertEqual(len(observations), 32)
        output = ROOT / 'test-results/ci-dsa-lab'
        output.mkdir(parents=True, exist_ok=True)
        (output / 'summary.json').write_text(json.dumps(observations, indent=2) + '\n')


if __name__ == '__main__':
    unittest.main()
