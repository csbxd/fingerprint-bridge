# TLS 1.2 DHE-DSS and DSA validation

Code under validation: `a547af092bf3ce006f891e15eb4446d78d275f70` (2026-09-22).
Workflow: [fingerprint-regression #46](https://github.com/csbxd/fingerprint-bridge/actions/runs/35750103723).
Baseline: [FFDHE/Zstandard run #45](FFDHE-ZSTD-VALIDATION.md).

## Implemented capability

- Six real TLS 1.2 DHE-DSS suites: `0x0032`, `0x0038`, `0x0040`,
  `0x006a`, `0x00a2`, `0x00a3`. They use the existing finite-field DH,
  AES-CBC/HMAC and AES-GCM record implementations with actual DSA authentication.
- DSA handshake signatures with SHA-1/224/256/384/512:
  `0x0202`, `0x0302`, `0x0402`, `0x0502`, `0x0602`. An EVP method delegates
  signing and verification to the backend's DSA implementation, checking both
  operation success and signature validity. These schemes are TLS-1.2-only.
- DSA public-key decoding and certificate verification use the normal verified
  chain path. Extension 50 permits DSA SHA-1/224/256. DSA SHA-384/512
  **certificate signature OIDs** remain unsupported in this pinned backend
  and are filtered with explicit limitations, despite working handshake
  signatures with the same digests. Ed448 remains filtered too.
- The existing independent matrix clients, normalization, certificate checks,
  strict gates and comparison topology are unchanged.

## Independent verification

`scripts/test_dsa.py` starts an actual B process with independently generated
OpenSSL peers and temporary loopback-only test certificates. It exercises all
six suites with all five handshake signature digests (30 positive cases).
The origin permits only the selected suite and signature. Each positive case
must produce encrypted HTTP, the expected negotiated signature in the OpenSSL
wire trace, and the corresponding suite/signature in B's actual outbound
ClientHello evidence. The chain uses a DSA/SHA-256 CA and leaf signature.

Two negative cases require rejection: a DSA signature not offered by the client,
and a corrupted certificate signature. Neither may return origin HTTP; the
latter must report CERTIFICATE_VERIFY_FAILED. The controlled OpenSSL peers
explicitly select legacy algorithms only in this dedicated test; their local
security-level setting does not modify B verification or default matrix clients.
The test writes a 32-case non-secret summary and removes temporary keys.

The Rust integration test also captures emitted ClientHellos and checks exact
preservation of the six suites and five handshake signatures. A separate
negative test checks that unsupported extension-50 algorithms remain omitted.

## Results

Both amd64 and arm64 regression jobs passed formatting, Clippy with warnings
forbidden, 42 Rust tests (39 fingerprint integration tests, one certificate
compression integration test, two unit tests), and 24 Python tests. These
include all 32 DSA cases and the existing FFDHE regression. The independent
HTTPS, TCP and hybrid-group lab steps also passed.

Local x86_64 additionally passed the same 42 Rust tests, Clippy, and all 32
DSA cases. An initial local doctest invocation could not create `/tmp`; rerunning
with a writable TMPDIR completed successfully (zero doctests).

The full 72-cell matrix completed across both architectures, four distributions
and five languages. The strict gate failed on actual remaining differences and
unstable baselines, not a build or missing-environment error.

| Check | Run #45 | Run #46 |
| --- | ---: | ---: |
| Stable direct baseline | 48/72 | 48/72 |
| TLS match | 16/72 | 16/72 |
| HTTP match | 65/72 | 64/72 |
| TCP match | 72/72 | 72/72 |
| Same B connection TLS match | 32/72 | 32/72 |
| Same B connection HTTP match | 72/72 | 72/72 |
| Final match | 8 | 8 |
| Final mismatch | 40 | 40 |
| Inconclusive direct baseline | 24 | 24 |

The single changed row is amd64 Debian Go HTTP/2: its HTTP column changed
from MATCH to DIFF while its independent direct baseline remains unstable.
It is not evidence of a demonstrated stable HTTP regression, and is not counted
as a passing cell in either run. No new full-fingerprint matches are claimed.

[DSA-MATRIX-46.json](DSA-MATRIX-46.json) records all 72 rows from the Actions
summary job, regression log excerpts, and the GitHub-declared digests of all
eleven published artifacts. Each digest is explicitly marked locally unverified.

## Evidence access and boundaries

Actions job logs are readable and preserve the test outcomes. Artifact ZIPs
were successfully published by Actions, but their connector-provided download
URLs returned HTTP 403 (`error code: 1010`) in this session. The browser download
path timed out and subsequent browser access was explicitly rejected by browser
URL security policy. No attempt was made to bypass that policy.

Consequently this record does **not** claim a fresh local ZIP digest verification,
independent replay of all raw matrix captures, or per-cell retention counts for
DSA. Those checks remain pending artifact access; run #45 retention counts must
not be reused as run #46 results. Matrix layer counts above are from the Actions
aggregator, which checks evidence completeness on the runner.

Remaining TLS capabilities and wire-layout differences still prevent full
fingerprint equivalence. Matching TCP results cover shared Linux runner kernels
and loopback only, not arbitrary clients or Internet paths. No changes were
made to real A, user traffic, deployment or SSH.
