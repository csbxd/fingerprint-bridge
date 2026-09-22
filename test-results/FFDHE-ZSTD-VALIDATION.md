# FFDHE and Zstandard certificate compression validation

Code under validation: `b3f3c207bafb31496fce414d193c0fdcb9fbebee` (2026-09-22).
Workflow: [fingerprint-regression #45](https://github.com/csbxd/fingerprint-bridge/actions/runs/35739991094).
Comparison baseline: [extension 50 run #40](SIGALGS-CERT-VALIDATION.md).

## Implemented capability

- All five RFC 7919 groups (`0x0100` through `0x0104`, 2048/3072/4096/6144/8192
  bits) now have native TLS 1.3 key-share implementations. Previously 2048/3072
  could appear in the supported-group list but had no TLS 1.3 key-share factory;
  the larger three were filtered out. B generates fresh DH keys, validates the
  peer public value and exact share width, and uses the padded shared secret
  required by TLS 1.3. Fixed public parameters were compared with OpenSSL and
  independently checked against the RFC prime-construction formula.
- TLS 1.2 may use the larger standard primes only if B's observed client offered
  the corresponding group and both the prime and generator exactly match.
  Arbitrary large or unoffered large DH groups remain rejected. Finite-field
  groups are excluded from the TLS 1.2 ECDHE selection path.
- Certificate compression algorithm 3 (Zstandard, extension 27) now has a real
  pure-Rust decoder (`ruzstd`), with independent libzstd encoding in tests.
  The decoder bounds the window and combined output to the TLS uint24 envelope,
  rejects truncated frames/trailing garbage, and explicitly checks optional
  frame checksums. Normal certificate chain and hostname verification remain on.
- The declared Rust minimum is now 1.87, as required by the decoder dependency;
  CI remains pinned to 1.98.1. Two equivalent divisibility checks were updated
  to satisfy the newly applicable Clippy lint. No fingerprint equality rules,
  exemptions, default matrix clients or strict gates changed.

## Verification method

The FFDHE lab has 32 independently negotiated cases: for every group, a TLS 1.2
HTTP exchange, TLS 1.3 HTTP exchange via HelloRetryRequest, rejection of public
values 0, 1 and an out-of-range value, and rejection when the server group was
not offered. Two additional TLS 1.2 cases reject unoffered 6144/8192-bit groups.
The wire observer records the actual group, share width, HRR/ClientHello count,
TLS 1.2 prime width and fatal illegal_parameter alert (47). HTTP is required in
positive cases and forbidden in negative cases.

The Zstandard test runs the actual B process between verified TLS 1.3 peers.
It requires the server compression callback to execute, valid encrypted HTTP,
B-to-A Host rewriting and preservation of `sid=from_B`. Corrupt compressed data
must fail with CERT_DECOMPRESSION_FAILED; a correctly compressed certificate
with a corrupted leaf signature must fail with CERTIFICATE_VERIFY_FAILED.
Neither negative case may deliver HTTP to the origin. Unit tests use a separate
libzstd encoder for checksum, every truncation offset and trailing-data negatives.
Only temporary synthetic lab certificates and loopback traffic are used.

Runs #41/#42 exposed lab issues, not passing evidence: the observer initially
parsed encrypted TLS 1.2 Finished records as plaintext; OpenSSL's TLS-1.2-only
mode also omits FFDHE from supported_groups even when configured. The repaired
probe offers its normal versions while the controlled origin selects TLS 1.2,
and explicitly checks that the incoming/outgoing group lists match. Run #43
was superseded after byte-for-byte fetch verification caught a duplicated old
class left by the web editor. Runs #43/#44 also identified the MSRV-dependent
Clippy checks. These intermediate runs are not the final validation result.

## Results

Both amd64 and arm64 regression jobs passed formatting, Clippy with warnings
forbidden, 41 Rust tests (38 fingerprint integration tests, one real Zstandard
TLS integration test and two unit tests; zero doctests), 23 Python tests,
all 32 FFDHE cases, all 18 hybrid cases and the existing independent HTTPS/TCP labs.

All eleven artifact archives (eight matrix environments, both regressions and
the final table) were downloaded and verified against GitHub's SHA-256 digests.
All 72 cells have independent direct-1/direct-2/bridged ClientHello and SYN
captures, plus same-connection inbound/outbound B evidence.

- Each new group 258/259/260 is preserved in all 28 cells offering it: Java
  16/16, Node 8/8 and Python 4/4. The unsupported-group limitations for these
  three IDs fall from 28 each to zero. This does **not** mean all of extension
  10 is identical: X448 (group 30) remains unsupported in 40 cells.
- All six Zstandard offers (Debian 13, Python HTTP/1.1 and Node HTTP/1.1/HTTP/2,
  both architectures) retain the exact certificate-compression extension body
  in the raw A-side ClientHello: `0400010003`. The same B-connection list is
  also `[1, 3]` on both sides. Unsupported-compression-3 limitations fall from
  six to zero. Actual Zstandard negotiation is additionally proved by the
  controlled TLS 1.3 test, because a default matrix origin need not select it.

| Check | Run #40 | Run #45 |
| --- | ---: | ---: |
| Stable direct baseline | 48/72 | 48/72 |
| TLS match | 16/72 | 16/72 |
| HTTP match | 64/72 | 65/72 |
| TCP match | 72/72 | 72/72 |
| Same B connection TLS match | 32/72 | 32/72 |
| Same B connection HTTP match | 72/72 | 72/72 |
| Final match | 8 | 8 |
| Final mismatch | 40 | 40 |
| Inconclusive direct baseline | 24 | 24 |

The single additional HTTP match is amd64 Debian Go HTTP/2, whose independent
direct baseline remains unstable. It is not counted as a new passing cell or
claimed as an HTTP implementation improvement.

Remaining observed limitations include X448, Ed448, DSA, Brainpool signature
schemes, several cipher suites, status_request_v2 (extension 17, 16 cells) and
encrypt_then_mac (extension 22, 24 cells). Unsupported capabilities are still
omitted and reported; none is advertised merely to manufacture a match.
Point-format and other wire-layout differences also remain.

Full 72-cell verdicts, raw extension bytes, capability lists, remaining
limitation counts, per-architecture FFDHE wire results and all artifact digests
are in [FFDHE-ZSTD-MATRIX-45.json](FFDHE-ZSTD-MATRIX-45.json).

The strict gate is not bypassed. Any remaining TLS differences or unstable
independent direct baselines remain failures/inconclusive results. TCP matches
in this matrix cover loopback and shared-runner kernels only, not arbitrary
client operating systems or Internet paths. This change does not establish
full TLS/HTTP/TCP fingerprint equivalence.
