#!/usr/bin/env python3
"""Build a private, checksum-pinned OpenSSL EC2M provider with no shared symbols.

This library is used only for one binary-field ECDH group. BoringSSL remains
the TLS implementation. Rename both definitions and archive references; leave
libc/compiler references intact. Never replace the system OpenSSL or clients.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shlex
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parent.parent
VERSION = '3.5.8'
SHA256 = 'a8f84a39918ec6415ce765d9b429d313ba97b8143169c172e734b9514464f5b2'
URL = f'https://github.com/openssl/openssl/releases/download/openssl-{VERSION}/openssl-{VERSION}.tar.gz'
CONFIGURATION = ('no-shared', 'no-tests', 'no-module', 'no-engine', 'no-dso', 'no-docs')
PREFIX = 'fingerprint_char2_'


def command(name, fallback):
    return shlex.split(os.environ.get(name, fallback))


def definitions(archive):
    output = subprocess.check_output(
        [*command('NM', 'nm'), '-g', '--defined-only', '-P', str(archive)],
        text=True, timeout=120)
    symbols = set()
    for line in output.splitlines():
        if not line.strip() or line.rstrip().endswith(':'):
            continue
        parts = line.split()
        if len(parts) < 2 or len(parts[1]) != 1:
            raise ValueError(f'Unrecognized nm definition line: {line!r}')
        symbol, kind = parts[:2]
        if kind not in 'TDBRCWSGVIi' or not re.fullmatch(r'[A-Za-z_][A-Za-z_0-9]*', symbol):
            raise ValueError(f'Cannot safely isolate global definition: {line!r}')
        symbols.add(symbol)
    if not symbols:
        raise ValueError('No globally defined libcrypto symbols found')
    return symbols


def prepare(output):
    if platform.system() != 'Linux' or platform.machine() not in ('x86_64', 'aarch64'):
        raise ValueError('char2 provider currently supports native Linux x86_64/aarch64 only')
    output = output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    expected = {
        'version': VERSION, 'source_sha256': SHA256,
        'machine': platform.machine(), 'configuration': list(CONFIGURATION),
        'script_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'wrapper_sha256': hashlib.sha256((ROOT / 'native/char2_provider.c').read_bytes()).hexdigest(),
        'tools': {name: os.environ.get(name, '') for name in ('CC', 'AR', 'NM', 'OBJCOPY', 'CFLAGS')},
    }
    # Cargo can use different OUT_DIR paths for build/test/clippy. Keep the
    # expensive native build in a process-locked content-addressed cache, then
    # copy its isolated artifacts into the requested linker directory.
    cache_parent = ROOT / 'target/bridge-char2'
    cache_parent.mkdir(parents=True, exist_ok=True)
    identity = hashlib.sha256(json.dumps(expected, sort_keys=True).encode()).hexdigest()
    cached = cache_parent / identity
    with (cache_parent / f'{identity}.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        manifest = cached / 'source.json'
        if (manifest.is_file() and json.loads(manifest.read_text()) == expected and
                (cached / 'libbridge_char2_provider.a').is_file() and
                (cached / 'libbridge_char2_crypto.a').is_file()):
            shutil.copytree(cached, output, dirs_exist_ok=True)
            return output
        with tempfile.TemporaryDirectory(prefix='char2-build-', dir=cache_parent) as temporary:
            work = Path(temporary)
            archive = work / 'source.tar.gz'
            digest = hashlib.sha256()
            total = 0
            with urllib.request.urlopen(URL, timeout=60) as response, archive.open('wb') as target:
                while chunk := response.read(1 << 20):
                    total += len(chunk)
                    if total > 128 << 20:
                        raise ValueError('OpenSSL source archive exceeds size limit')
                    digest.update(chunk)
                    target.write(chunk)
            if digest.hexdigest() != SHA256:
                raise ValueError('OpenSSL source checksum differs from pinned release')
            with tarfile.open(archive) as bundle:
                bundle.extractall(work, filter='data')
            source = work / f'openssl-{VERSION}'
            build_log = cache_parent / f'{identity}.build.log'
            print(f'Building private OpenSSL {VERSION} char2 provider; log: {build_log}', file=sys.stderr)
            with build_log.open('w') as log:
                subprocess.run(['perl', 'Configure', *CONFIGURATION,
                                f'--prefix={work / "install"}',
                                f'--openssldir={work / "install/ssl"}'],
                               cwd=source, stdout=log, stderr=subprocess.STDOUT,
                               check=True, timeout=120)
                subprocess.run(['make', f'-j{min(os.cpu_count() or 1, 2)}', 'build_libs'],
                               cwd=source, stdout=log, stderr=subprocess.STDOUT,
                               check=True, timeout=1200)
            libcrypto = source / 'libcrypto.a'
            symbols = definitions(libcrypto)
            if not {'EC_KEY_generate_key', 'ECDH_compute_key', 'EC_POINT_oct2point'} <= symbols:
                raise ValueError('Required EC implementation symbols are missing')
            result = work / 'result'
            result.mkdir()
            mapping = result / 'redefine-symbols.txt'
            mapping.write_text(''.join(f'{name} {PREFIX}{name}\n' for name in sorted(symbols)))
            header = result / 'char2_prefix.h'
            header.write_text('/* Generated from all global libcrypto definitions. */\n' +
                              ''.join(f'#define {name} {PREFIX}{name}\n' for name in sorted(symbols)))
            private_archive = result / 'libbridge_char2_crypto.a'
            shutil.copy2(libcrypto, private_archive)
            subprocess.run([*command('OBJCOPY', 'objcopy'), f'--redefine-syms={mapping}',
                            str(private_archive)], check=True, timeout=120)
            renamed = definitions(private_archive)
            if renamed != {PREFIX + name for name in symbols}:
                raise ValueError('Private libcrypto symbol isolation failed')
            provider_object = result / 'char2_provider.o'
            subprocess.run([*command('CC', 'cc'), '-std=c11', '-O2', '-fPIC',
                            '-Werror', '-Wall', '-Wextra', '-Wno-deprecated-declarations',
                            *shlex.split(os.environ.get('CFLAGS', '')),
                            '-I', str(result), '-I', str(source / 'include'),
                            '-c', str(ROOT / 'native/char2_provider.c'),
                            '-o', str(provider_object)], check=True, timeout=120)
            undefined = subprocess.check_output(
                [*command('NM', 'nm'), '-u', '-P', str(provider_object)],
                text=True, timeout=30)
            for line in undefined.splitlines():
                if line.split() and line.split()[0] in symbols:
                    raise ValueError('Provider references an unprefixed libcrypto symbol')
            subprocess.run([*command('AR', 'ar'), 'rcs', str(result / 'libbridge_char2_provider.a'),
                            str(provider_object)], check=True, timeout=120)
            shutil.copy2(source / 'LICENSE.txt', result / 'OPENSSL-LICENSE.txt')
            (result / 'source.json').write_text(json.dumps(expected, indent=2) + '\n')
            if cached.exists():
                shutil.rmtree(cached)
            result.rename(cached)
            shutil.copytree(cached, output, dirs_exist_ok=True)
    return output


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    prepare(args.output)
