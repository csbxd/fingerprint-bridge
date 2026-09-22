#!/usr/bin/env python3
"""Build a checksum-pinned, isolated OpenSSL peer for RFC 8734 tests.

Ubuntu's default OpenSSL 3.0 does not implement these TLS 1.3 signature
schemes. The output is used only by explicit algorithm regression probes;
this never changes PATH, system packages, or the default 72-cell clients.
"""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parent.parent
VERSION = '3.5.8'
# Official openssl/openssl release asset digest, verified against GitHub's
# release metadata on 2026-09-22. The official OpenSSL download page links it.
SHA256 = 'a8f84a39918ec6415ce765d9b429d313ba97b8143169c172e734b9514464f5b2'
URL = f'https://github.com/openssl/openssl/releases/download/openssl-{VERSION}/openssl-{VERSION}.tar.gz'
CONFIGURATION = ('no-shared', 'no-tests', 'no-module', 'no-docs')


def prepare():
    parent = ROOT / 'target/test-tools'
    parent.mkdir(parents=True, exist_ok=True)
    name = f'openssl-{VERSION}-{platform.machine()}-{SHA256[:12]}'
    destination = parent / name
    binary = destination / 'openssl'
    expected = {'version': VERSION, 'archive_sha256': SHA256,
                'architecture': platform.machine(), 'configuration': list(CONFIGURATION)}
    with (parent / f'{name}.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if binary.is_file() and (destination / 'source.json').is_file():
            if json.loads((destination / 'source.json').read_text()) == expected:
                return binary
        with tempfile.TemporaryDirectory(prefix=f'{name}-', dir=parent) as temporary:
            work = Path(temporary)
            archive = work / 'source.tar.gz'
            digest = hashlib.sha256()
            total = 0
            with urllib.request.urlopen(URL, timeout=60) as response, archive.open('wb') as output:
                while chunk := response.read(1 << 20):
                    total += len(chunk)
                    if total > 128 << 20:
                        raise ValueError('OpenSSL source archive exceeds size limit')
                    digest.update(chunk)
                    output.write(chunk)
            if digest.hexdigest() != SHA256:
                raise ValueError('OpenSSL source SHA256 does not match the pinned official release')
            with tarfile.open(archive) as bundle:
                # Reject escaping paths and unsafe links before executing any
                # source. Python's data filter also limits file permissions.
                bundle.extractall(work, filter='data')
            source = work / f'openssl-{VERSION}'
            build_log = parent / f'{name}.build.log'
            print(f'Building isolated OpenSSL {VERSION} test peer; log: {build_log}', file=sys.stderr)
            with build_log.open('w') as output:
                subprocess.run(['perl', 'Configure', *CONFIGURATION,
                                f'--prefix={work / "install"}',
                                f'--openssldir={work / "install/ssl"}'],
                               cwd=source, stdout=output, stderr=subprocess.STDOUT,
                               check=True, timeout=120)
                subprocess.run(['make', f'-j{min(os.cpu_count() or 1, 2)}', 'build_sw'],
                               cwd=source, stdout=output, stderr=subprocess.STDOUT,
                               check=True, timeout=1200)
            built = source / 'apps/openssl'
            version = subprocess.check_output([str(built), 'version'], text=True, timeout=10)
            if not version.startswith(f'OpenSSL {VERSION} '):
                raise AssertionError(f'Unexpected test-peer version: {version.strip()}')
            destination.mkdir(exist_ok=True)
            shutil.copy2(built, binary)
            (destination / 'source.json').write_text(json.dumps(expected, indent=2) + '\n')
    return binary


if __name__ == '__main__':
    print(prepare())
