"""Compile authentication constraints against the exact current native build."""
import json
import shlex
import subprocess
import tempfile
import unittest
from pathlib import Path

from prepare_tls import ROOT, prepare
from test_ccm_limits import matching_build


class BrainpoolConstraintTests(unittest.TestCase):
    def test_curve_digest_and_tls_version_constraints(self):
        source = prepare()
        _cache, values, libraries = matching_build(source)
        with tempfile.TemporaryDirectory() as temporary:
            binary = Path(temporary) / 'brainpool-constraints'
            command = [values['CMAKE_CXX_COMPILER'], '-std=c++17', '-O0',
                       *shlex.split(values.get('CMAKE_CXX_FLAGS', '')),
                       '-DBORINGSSL_IMPLEMENTATION', '-I', str(source),
                       '-I', str(source / 'include'),
                       str(ROOT / 'scripts/clients/brainpool_constraints.cc'),
                       *(str(path) for path in libraries), '-pthread', '-ldl',
                       '-o', str(binary)]
            built = subprocess.run(command, text=True, capture_output=True, timeout=120)
            self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
            result = subprocess.run([str(binary)], text=True, capture_output=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            rows = json.loads(result.stdout)
        self.assertEqual([row['scheme'] for row in rows], [0x081a, 0x081b, 0x081c])
        self.assertTrue(all(value is True for row in rows for key, value in row.items() if key != 'scheme'))
        output = ROOT / 'test-results/ci-brainpool-constraints'
        output.mkdir(parents=True, exist_ok=True)
        (output / 'summary.json').write_text(json.dumps({'backend_digest': source.name, 'cases': rows}, indent=2) + '\n')
        print('BRAINPOOL_CONSTRAINT_RESULTS=' + json.dumps(rows, separators=(',', ':')), flush=True)


if __name__ == '__main__':
    unittest.main()
