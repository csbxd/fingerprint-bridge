"""Real certificate verification, independently signed by OpenSSL DSA peers."""
import base64
import json
import ssl
import subprocess
import tempfile
import textwrap
import time
import unittest
from pathlib import Path
from types import SimpleNamespace

from lab import browser, certificates, start_bridge
from matrix_lab import ROOT
from test_dsa import dsa_chain, openssl


class DsaCertificateTests(unittest.TestCase):
    def test_sha384_sha512_certificates_and_corruptions(self):
        observations = []
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            peer_binary = work / 'dsa-certificate-probe'
            subprocess.run(['go', 'build', '-o', str(peer_binary),
                            str(ROOT / 'scripts/clients/dsa_certificate_probe.go')],
                           check=True, capture_output=True, timeout=120)
            issuer = work / 'issuer'
            issuer.mkdir()
            root, _, _, _ = dsa_chain(issuer)
            for digest, oid_tail in [('sha384', 3), ('sha512', 4)]:
                for version in [ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3]:
                    for mode in ['valid', 'tampered-signature', 'wrong-digest-oid']:
                        with self.subTest(digest=digest, version=version.name, mode=mode):
                            case = work / f'{digest}-{version.name}-{mode}'
                            case.mkdir()
                            certificates(case)
                            # Keep an RSA leaf key for TLS 1.3 CertificateVerify;
                            # its certificate is signed by an independent DSA CA.
                            openssl('x509', '-req', '-in', case / 'a.csr',
                                    '-CA', root, '-CAkey', issuer / 'root.key',
                                    '-CAcreateserial', '-days', '1', f'-{digest}',
                                    '-extfile', case / 'a.ext', '-out', case / 'a.pem')
                            with (case / 'ca.pem').open('ab') as bundle:
                                bundle.write(root.read_bytes())
                            cert = case / 'a.pem'
                            der = bytearray(base64.b64decode(''.join(cert.read_text().splitlines()[1:-1])))
                            oid = bytes.fromhex('06096086480165030403') + bytes([oid_tail])
                            # Check both inner and outer certificate algorithm IDs.
                            self.assertEqual(der.count(oid), 2)
                            if mode == 'tampered-signature':
                                der[-1] ^= 1
                            elif mode == 'wrong-digest-oid':
                                # Relabel both IDs, without resigning. The result
                                # must fail cryptographic verification, not just
                                # an inner/outer AlgorithmIdentifier comparison.
                                der = der.replace(oid, oid[:-1] + bytes([7 - oid_tail]))
                            if mode != 'valid':
                                cert.write_text('-----BEGIN CERTIFICATE-----\n' +
                                                '\n'.join(textwrap.wrap(base64.b64encode(der).decode(), 64)) +
                                                '\n-----END CERTIFICATE-----\n')
                            peer = subprocess.Popen(
                                [str(peer_binary), '-cert', str(cert), '-key', str(case / 'a.key'),
                                 '-version', str(int(version))], stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True)
                            origin = SimpleNamespace(port=json.loads(peer.stdout.readline())['port'])
                            proc = log = None
                            try:
                                proc, port, log = start_bridge(
                                    ROOT / 'target/debug/fingerprint-bridge', case,
                                    origin, case / 'runtime')
                                if mode == 'valid':
                                    browser(case, 'http/1.1', 'b.test', port, f'b.test:{port}')
                                else:
                                    with self.assertRaises((OSError, EOFError)):
                                        browser(case, 'http/1.1', 'b.test', port, f'b.test:{port}')
                                stdout, stderr = peer.communicate(timeout=20)
                                self.assertEqual(peer.returncode, 0, stderr)
                                evidence = json.loads(stdout)
                                # The peer can receive the fatal alert before B's
                                # connection task has logged its final error.
                                deadline = time.monotonic() + 2
                                while True:
                                    log.seek(0)
                                    bridge_log = log.read()
                                    if (mode == 'valid' or 'CERTIFICATE_VERIFY_FAILED' in bridge_log
                                            or time.monotonic() >= deadline):
                                        break
                                    time.sleep(.01)
                                if mode == 'valid':
                                    self.assertNotIn('error', evidence)
                                    self.assertTrue(evidence['handshake'])
                                    self.assertEqual(evidence['tls_version'], int(version))
                                    requests = evidence['requests']
                                    self.assertEqual(len(requests), 2)
                                    for request in requests:
                                        self.assertIn(f'hOsT:\ta.test:{origin.port} ', request)
                                        self.assertIn('Cookie: sid=from_B; flag=yes\r\n', request)
                                else:
                                    self.assertFalse(evidence['requests'], 'HTTP reached the origin')
                                    self.assertFalse(evidence['handshake'])
                                    self.assertTrue(evidence['error'])
                                    self.assertIn('CERTIFICATE_VERIFY_FAILED', bridge_log)
                                observations.append({'certificate_digest': digest,
                                                     'certificate_oid': f'2.16.840.1.101.3.4.3.{oid_tail}',
                                                     'tls_version': version.name, 'mode': mode,
                                                     'http_at_origin': bool(evidence['requests']), 'passed': True})
                            finally:
                                if proc:
                                    proc.terminate()
                                    proc.wait(timeout=5)
                                if log:
                                    log.close()
                                if peer.poll() is None:
                                    peer.terminate()
                                peer.communicate(timeout=5)
        self.assertEqual(len(observations), 12)
        output = ROOT / 'test-results/ci-dsa-certificates'
        output.mkdir(parents=True, exist_ok=True)
        (output / 'summary.json').write_text(json.dumps(observations, indent=2) + '\n')
        # Non-secret evidence remains reviewable in Actions logs if ZIP download
        # access is temporarily unavailable. This never includes key material.
        print('DSA_CERTIFICATE_RESULTS=' + json.dumps(observations, sort_keys=True))


if __name__ == '__main__':
    unittest.main()
