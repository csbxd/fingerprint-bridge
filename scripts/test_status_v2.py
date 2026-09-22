"""RFC 6961 real negotiation and OCSP validation tests.

The origin is an independent Go record peer and the downstream client is JSSE.
All certificates and OCSP responses are synthetic and generated per test run.
"""
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509 import ocsp

from lab import start_bridge
from matrix_lab import ROOT


def key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def name(common_name):
    return x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, common_name)])


def certificate(subject, issuer, public_key, issuer_key, serial, ca=False, san=None, path_length=None):
    now = datetime.now(timezone.utc)
    builder = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)
               .public_key(public_key).serial_number(serial)
               .not_valid_before(now - timedelta(hours=1))
               .not_valid_after(now + timedelta(days=2))
               .add_extension(x509.BasicConstraints(ca=ca, path_length=path_length if ca else None), critical=True)
               .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
               .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), critical=False))
    if ca:
        builder = builder.add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
    else:
        builder = (builder.add_extension(x509.KeyUsage(True, False, True, False, False, False, False, False, False), critical=True)
                   .add_extension(x509.ExtendedKeyUsage([x509.ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
                   .add_extension(x509.SubjectAlternativeName([x509.DNSName(san)]), critical=False))
    return builder.sign(issuer_key, hashes.SHA256())


def pem_private(value):
    return value.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                               serialization.NoEncryption())


def material(path):
    root_key, intermediate_key, a_key, b_key = key(), key(), key(), key()
    root_name, intermediate_name = name('Status v2 Lab Root'), name('Status v2 Lab Intermediate')
    root = certificate(root_name, root_name, root_key.public_key(), root_key, 1, ca=True, path_length=1)
    intermediate = certificate(intermediate_name, root_name, intermediate_key.public_key(), root_key, 2, ca=True, path_length=0)
    a = certificate(name('a.test'), intermediate_name, a_key.public_key(), intermediate_key, 3, san='a.test')
    b = certificate(name('b.test'), root_name, b_key.public_key(), root_key, 4, san='b.test')
    (path / 'ca.pem').write_bytes(root.public_bytes(serialization.Encoding.PEM))
    (path / 'a.pem').write_bytes(a.public_bytes(serialization.Encoding.PEM) +
                                 intermediate.public_bytes(serialization.Encoding.PEM))
    (path / 'a.key').write_bytes(pem_private(a_key))
    (path / 'b.pem').write_bytes(b.public_bytes(serialization.Encoding.PEM))
    (path / 'b.key').write_bytes(pem_private(b_key))
    now = datetime.now(timezone.utc)
    for filename, status in [('good.ocsp', ocsp.OCSPCertStatus.GOOD),
                             ('revoked.ocsp', ocsp.OCSPCertStatus.REVOKED)]:
        response = (ocsp.OCSPResponseBuilder()
                    .add_response(cert=a, issuer=intermediate, algorithm=hashes.SHA1(), cert_status=status,
                                  this_update=now - timedelta(minutes=1), next_update=now + timedelta(hours=12),
                                  revocation_time=(now - timedelta(minutes=2) if status == ocsp.OCSPCertStatus.REVOKED else None),
                                  revocation_reason=(x509.ReasonFlags.key_compromise if status == ocsp.OCSPCertStatus.REVOKED else None))
                    .responder_id(ocsp.OCSPResponderEncoding.HASH, intermediate)
                    .sign(intermediate_key, hashes.SHA256()))
        (path / filename).write_bytes(response.public_bytes(serialization.Encoding.DER))


class StatusRequestV2Tests(unittest.TestCase):
    def test_real_ocsp_multi_negotiation_and_rejections(self):
        results = []
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)
            material(path)
            peer = path / 'status-v2-origin'
            built = subprocess.run(['go', 'build', '-o', str(peer),
                                    str(ROOT / 'scripts/clients/status_v2_probe.go')],
                                   capture_output=True, text=True, timeout=120)
            self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
            clients = path / 'classes'
            clients.mkdir()
            built = subprocess.run(['javac', '-d', str(clients),
                                    str(ROOT / 'scripts/clients/StatusV2Client.java')],
                                   capture_output=True, text=True, timeout=120)
            self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
            hosts = path / 'hosts'
            hosts.write_text('127.0.0.1 a.test b.test\n')
            for mode in ('valid', 'revoked', 'bad-signature', 'malformed-list', 'omitted'):
                with self.subTest(mode=mode):
                    ocsp_file = path / ('revoked.ocsp' if mode == 'revoked' else 'good.ocsp')
                    origin = subprocess.Popen([str(peer), '-cert', str(path / 'a.pem'),
                                               '-key', str(path / 'a.key'), '-ocsp', str(ocsp_file),
                                               '-mode', mode], stdout=subprocess.PIPE,
                                              stderr=subprocess.PIPE, text=True)
                    proc = log = None
                    try:
                        startup = json.loads(origin.stdout.readline())
                        proc, port, log = start_bridge(ROOT / 'target/debug/fingerprint-bridge', path,
                                                       SimpleNamespace(port=startup['port']), path / f'runtime-{mode}')
                        client = subprocess.run([
                            'java', f'-Djdk.net.hosts.file={hosts}',
                            '-Djdk.tls.client.enableStatusRequestExtension=true',
                            '-cp', str(clients), 'StatusV2Client', str(path / 'ca.pem'), str(port)],
                            capture_output=True, text=True, timeout=25)
                        output, errors = origin.communicate(timeout=25)
                        evidence = json.loads(output)
                        log.flush(); log.seek(0)
                        bridge_log = log.read()
                        diagnostic = repr(evidence) + errors + client.stdout + client.stderr + bridge_log
                        self.assertTrue(evidence.get('exact_status_request_v2_offered'), diagnostic)
                        self.assertTrue(evidence.get('negotiated_status_request_v2'), diagnostic)
                        if mode == 'valid':
                            self.assertEqual(client.returncode, 0, diagnostic)
                            self.assertNotIn('error', evidence, diagnostic)
                            for field in ('client_finished_verified', 'http_request_received',
                                          'cookie_preserved', 'authority_rewritten'):
                                self.assertTrue(evidence.get(field), diagnostic)
                        else:
                            self.assertNotEqual(client.returncode, 0, diagnostic)
                            self.assertIn('client_alert', evidence, diagnostic)
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
        self.assertEqual(len(results), 5)
        output = ROOT / 'test-results/ci-status-v2-lab'
        output.mkdir(parents=True, exist_ok=True)
        (output / 'summary.json').write_text(json.dumps(results, indent=2) + '\n')
        print('STATUS_V2_RESULTS=' + json.dumps(results, separators=(',', ':')), flush=True)


if __name__ == '__main__':
    unittest.main()
