"""Real OpenSSL TLS 1.2 ServerHello/Finished regression for SCSV handling."""
import json
from pathlib import Path
import ssl
import subprocess
import tempfile
import unittest

from lab import certificates, start_bridge
from matrix_lab import MatrixOrigin, client_command, ROOT


class BackendHandshakeTests(unittest.TestCase):
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
