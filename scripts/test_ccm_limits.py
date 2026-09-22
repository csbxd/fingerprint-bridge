"""Exercise actual CCM record-limit branches without sending 2**23 records.

Compiles a fixture against the exact content-addressed backend used by Cargo.
No product hooks, lowered limits, real credentials, or network traffic are used.
"""
import json
import shlex
import subprocess
import tempfile
import unittest
from pathlib import Path

from prepare_tls import ROOT, prepare


def cache_values(path):
    values = {}
    for line in path.read_text().splitlines():
        if line and not line.startswith(('#', '//')) and '=' in line:
            key, value = line.split('=', 1)
            values[key.split(':', 1)[0]] = value
    return values


def matching_build(source):
    # prepare() computes the current patch digest; never pick a random old
    # bridge-native directory or link it to libraries built from other headers.
    target = source.parent.parent
    matches = []
    for cache in sorted(target.glob('debug/build/btls-sys-*/out/build/CMakeCache.txt')):
        values = cache_values(cache)
        if Path(values.get('CMAKE_HOME_DIRECTORY', '')).resolve() == source.resolve():
            libraries = [cache.parent / name for name in ['libssl.a', 'libcrypto.a']]
            if all(path.is_file() for path in libraries):
                matches.append((cache, values, libraries))
    if not matches:
        raise AssertionError(f'No native build of {source.name}. '
                             'Build the current patched binary first.')
    # Cargo may build separate dependency instances for test and binary targets.
    # Both are acceptable only after the exact current source digest matched.
    return matches[0]


class CcmLimitTests(unittest.TestCase):
    def test_per_key_budget_and_first_ccm8_trial_failure(self):
        source = prepare()
        self.assertEqual((source / '.bridge-ready').read_text().strip(), source.name)
        _cache, values, libraries = matching_build(source)
        with tempfile.TemporaryDirectory() as temporary:
            binary = Path(temporary) / 'ccm-limits'
            compiler = values['CMAKE_CXX_COMPILER']
            # Use the build's architecture/ABI flags but retain test assertions
            # even when a caller builds the backend in a release configuration.
            flags = shlex.split(values.get('CMAKE_CXX_FLAGS', ''))
            command = [compiler, '-std=c++17', '-O0', *flags,
                       '-DBORINGSSL_IMPLEMENTATION', '-I', str(source),
                       '-I', str(source / 'include'),
                       str(ROOT / 'scripts/clients/ccm_limits.cc'),
                       *(str(path) for path in libraries), '-pthread', '-ldl',
                       '-o', str(binary)]
            built = subprocess.run(command, text=True, capture_output=True, timeout=120)
            self.assertEqual(built.returncode, 0, built.stdout + built.stderr)
            result = subprocess.run([str(binary)], text=True, capture_output=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            rows = json.loads(result.stdout)
        budgets = [row for row in rows if row['kind'] == 'record-budget']
        self.assertEqual(len(budgets), 14)
        self.assertEqual(len({row['suite'] for row in budgets}), 14)
        self.assertTrue(all(row['limit'] == 2**23 and row['last_record_passed']
                            and row['next_record_rejected'] for row in budgets))
        rotations = [row for row in budgets if row['tls_version'] == 0x0304]
        self.assertEqual(len(rotations), 2)
        self.assertTrue(all(row['key_update_rotation_passed'] for row in rotations))
        trials = {row['suite']: row['first_failure_fatal'] for row in rows
                  if row['kind'] == 'rejected-0rtt-trial'}
        self.assertEqual(trials, {0x1305: True, 0x1304: False, 0x1301: False})
        output = ROOT / 'test-results/ci-ccm-limits'
        output.mkdir(parents=True, exist_ok=True)
        (output / 'summary.json').write_text(json.dumps({
            'backend_digest': source.name,
            'cases': rows,
        }, indent=2) + '\n')
        print('CCM_LIMIT_RESULTS=' + json.dumps(rows, separators=(',', ':')))


if __name__ == '__main__':
    unittest.main()
