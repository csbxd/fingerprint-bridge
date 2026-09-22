"""Independent OpenSSL TLS 1.2 ARIA-GCM negotiation and record tests."""
import json
from pathlib import Path
import shutil
import tempfile
import unittest

from matrix_lab import ROOT
from test_ccm import CCMHandshakeTests, material
from test_dsa import dsa_chain


RSA_AND_EC_SUITES = (
    ('ARIA128-GCM-SHA256', 0xc050),
    ('ARIA256-GCM-SHA384', 0xc051),
    ('DHE-RSA-ARIA128-GCM-SHA256', 0xc052),
    ('DHE-RSA-ARIA256-GCM-SHA384', 0xc053),
    ('ECDHE-ECDSA-ARIA128-GCM-SHA256', 0xc05c),
    ('ECDHE-ECDSA-ARIA256-GCM-SHA384', 0xc05d),
    ('ECDHE-ARIA128-GCM-SHA256', 0xc060),
    ('ECDHE-ARIA256-GCM-SHA384', 0xc061),
)
DSS_SUITES = (
    ('DHE-DSS-ARIA128-GCM-SHA256', 0xc056),
    ('DHE-DSS-ARIA256-GCM-SHA384', 0xc057),
)


class AriaHandshakeTests(CCMHandshakeTests):
    def test_real_aria_suites_large_http_and_authenticated_rejections(self):
        results = []
        modes = ('valid', 'bad-ciphertext', 'bad-tag', 'unoffered')
        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary)
            rsa = work / 'rsa'
            rsa.mkdir()
            material(rsa)
            dss = work / 'dss'
            dss.mkdir()
            material(dss)
            dsa_material = dss / 'dsa'
            dsa_material.mkdir()
            root, key, leaf, _tampered = dsa_chain(dsa_material)
            shutil.copyfile(key, dss / 'a.key')
            shutil.copyfile(leaf, dss / 'a.pem')
            with (dss / 'ca.pem').open('ab') as bundle:
                bundle.write(root.read_bytes())

            for path, suites in ((rsa, RSA_AND_EC_SUITES),
                                 (dss, DSS_SUITES)):
                for cipher, cipher_id in suites:
                    for mode in modes:
                        with self.subTest(cipher=cipher, mode=mode):
                            results.append(
                                self.run_case(path, cipher, cipher_id, mode))
        self.assertEqual(len(results), 40)
        output = ROOT / 'test-results/ci-aria-lab'
        output.mkdir(parents=True, exist_ok=True)
        (output / 'summary.json').write_text(
            json.dumps(results, indent=2) + '\n')
        print('ARIA_RESULTS=' +
              json.dumps(results, separators=(',', ':')), flush=True)


def load_tests(_loader, _tests, _pattern):
    """Run only ARIA cases here; CCM's inherited case has its own module."""
    return unittest.TestSuite((AriaHandshakeTests(
        'test_real_aria_suites_large_http_and_authenticated_rejections'),))


if __name__ == '__main__':
    unittest.main()
