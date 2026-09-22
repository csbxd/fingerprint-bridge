"""Verify ARIA-GCM against independent OpenSSL vectors and negative cases."""
import json
import shlex
import subprocess
import tempfile
import unittest
from pathlib import Path

from prepare_tls import ROOT, prepare
from test_ccm_limits import matching_build


class AriaVectorTests(unittest.TestCase):
    def test_vectors_authentication_and_nonce_reuse(self):
        source = prepare()
        _cache, values, libraries = matching_build(source)
        with tempfile.TemporaryDirectory() as temporary:
            binary = Path(temporary) / 'aria-vectors'
            command = [
                values['CMAKE_CXX_COMPILER'], '-std=c++17', '-O0',
                *shlex.split(values.get('CMAKE_CXX_FLAGS', '')),
                '-DBORINGSSL_IMPLEMENTATION', '-I', str(source),
                '-I', str(source / 'include'),
                str(ROOT / 'scripts/clients/aria_vectors.cc'),
                *(str(path) for path in libraries), '-pthread', '-ldl',
                '-o', str(binary),
            ]
            built = subprocess.run(command, text=True, capture_output=True,
                                   timeout=120)
            self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
            result = subprocess.run([str(binary)], text=True,
                                    capture_output=True, timeout=30)
            self.assertEqual(result.returncode, 0,
                             result.stdout + result.stderr)
            summary = json.loads(result.stdout)
        self.assertEqual(summary, {
            'vectors': 2,
            'tampered_tags_rejected': 2,
            'repeated_nonces_rejected': 2,
        })


if __name__ == '__main__':
    unittest.main()
