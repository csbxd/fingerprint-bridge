# DSA SHA-384/SHA-512 certificate validation

Code under validation: `b167d644e9b8021c509fe7b62679be0ed6c54adf` (2026-09-22).
Workflow: [fingerprint-regression #47](https://github.com/csbxd/fingerprint-bridge/actions/runs/35753503175).
Baseline: [DSA handshake run #46](DSA-VALIDATION.md).

## Implemented capability

- Register DSA certificate-signature OIDs `2.16.840.1.101.3.4.3.3`
  (SHA-384) and `2.16.840.1.101.3.4.3.4` (SHA-512), using the
  [NIST algorithm registry](https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration).
  Connect each OID to the matching digest and the existing real DSA EVP verifier.
- Preserve `0x0502` and `0x0602` in `signature_algorithms_cert` (extension 50)
  with the patched backend. Remove their former unsupported-certificate filter
  only after verifying the underlying certificate capability. Unimplemented
  Ed448 remains filtered; the unpatched backend does not gain these algorithms.
- Reserve existing TLS-only FFDHE NIDs 972/973 in the object registry before
  allocating certificate NIDs 974/975. This prevents object-table regeneration
  from silently reusing the group identifiers. A Rust regression verifies both
  OID names and the distinct group IDs.
- No matrix clients, comparison normalization, certificate checks, strict gates,
  or direct/direct/bridged and same-connection comparison topology changed.

## Independent real-handshake tests

`scripts/test_dsa_certificates.py` has OpenSSL generate a temporary DSA CA
and sign an RSA leaf certificate with each digest. The independent Go server
in `scripts/clients/dsa_certificate_probe.go` serves this chain on loopback.
B performs its normal chain and hostname verification. The RSA leaf key is
used for TLS CertificateVerify; this does not assert DSA handshake-signature
support in TLS 1.3. Certificate signatures and handshake signatures are separate.

The 12 cases are two certificate digests, two actual upstream TLS versions
(1.2 and 1.3), and three certificate modes:

1. Valid certificate: negotiated version must match; two encrypted HTTP
   requests must arrive with A authority and unchanged B Cookie. The existing
   client also checks binary response content, Location and Cookie Domain
   rewriting, and the host-only cookie.
2. Corrupted certificate signature: no HTTP may reach the origin, and B must
   report certificate verification failure.
3. Both inner and outer signature OIDs relabeled to the other digest without
   resigning: the cryptographic verification must fail, not merely a mismatch
   between the two AlgorithmIdentifier fields.

The Rust wire test independently captures emitted extension 50 and requires
both newly supported schemes in order, while rejecting unsupported Ed448.
The Python test prints only its non-secret 12-case summary into Actions logs
and writes the same summary to the existing regression artifact path. Temporary
synthetic certificates and keys are removed, and no real site or traffic is used.

## Local verification and fixture portability

On x86_64: formatting, Clippy with warnings forbidden, 43 Rust tests, 25 Python
tests, and the 18-case independent hybrid-group lab passed. The full Python
regression used the system Python/OpenSSL 3.0.13, matching the CI runner family.

An initial fixture based on Python's OpenSSL 3.0.13 TLS server rejected these
DSA/SHA-384/512 leaf chains during `load_cert_chain` with `CA_MD_TOO_WEAK`,
before B could connect. The final independent Go server serves the actual
certificates, leaving B verification and the client defaults intact. No security
level or verification check was lowered to work around that fixture limitation.

A separate initial full regression under the local Python/OpenSSL 3.5.8 passed
the new 12 certificate cases, but the existing DHE-ChaCha test failed because
that Python default cipher list no longer offered `0xccaa`. That invocation is
not reported as a full-suite pass; the default cipher list was not changed.

## Actions results

Both amd64 and arm64 regression jobs passed formatting, Clippy, 43 Rust tests
(two unit tests, one certificate-compression test, 40 fingerprint tests),
25 Python tests, and all 18 independent hybrid-group cases. Each architecture
passed all 12 new DSA certificate cases, including the eight negative cases.
Independent HTTPS and TCP capture labs also passed their functional assertions.

All 72 matrix cells completed across two native architectures, four distributions
and five languages. The strict gate failed with exit code 1 on remaining
fingerprint differences and unstable direct baselines. There were no missing
cells, missing-evidence verdicts, runtime-error verdicts or coverage errors.

| Check | Run #46 | Run #47 |
| --- | ---: | ---: |
| Stable direct baseline | 48/72 | 49/72 |
| TLS match | 16/72 | 16/72 |
| HTTP match | 64/72 | 64/72 |
| TCP match | 72/72 | 72/72 |
| Same B connection TLS match | 32/72 | 32/72 |
| Same B connection HTTP match | 72/72 | 72/72 |
| Final match | 8 | 8 |
| Final mismatch | 40 | 41 |
| Inconclusive direct baseline | 24 | 23 |

Only one row changed: amd64 Debian Go HTTP/2 had a stable direct baseline this
run and was classified as mismatch instead of inconclusive-baseline. Its
TLS/HTTP/TCP and B-paired result columns did not change. This is not counted as
an improvement, and no new complete-fingerprint matches are claimed.

[DSA-CERTIFICATES-MATRIX-47.json](DSA-CERTIFICATES-MATRIX-47.json) archives all
72 rows from the consistency-gate log, both architectures' 12-case certificate
summaries, regression excerpts, job conclusions, and eleven artifact digests
reported by GitHub. Each digest is explicitly marked locally unverified.

The connector returned a file reference for a new run #47 matrix ZIP, but its
file download again returned HTTP 403 / error code 1010. Therefore an independent
local re-audit of the matrix's raw ClientHello and PCAP artifacts remains pending.
This record relies on the actual Actions test and strict-gate logs; it does not
claim per-matrix-cell retention counts for the newly supported certificate
algorithms. No browser security workaround was attempted.

## Remaining boundary

This increment closes the previously explicit DSA SHA-384/512 certificate-OID
capability gap. It does not implement Ed448, arbitrary session resumption or
cross-OS TCP emulation. The matrix still has TLS and HTTP differences, and its
TCP matches concern loopback traffic on GitHub Linux runners. Full TLS/HTTP/TCP
fingerprint equivalence for arbitrary clients is not established.
