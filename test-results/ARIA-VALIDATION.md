# TLS 1.2 ARIA-GCM capability validation

Evidence record, 2026-09-22. Code under validation:
[`55137c95641f57102a12013167ff88f7adcded91`](https://github.com/csbxd/fingerprint-bridge/commit/55137c95641f57102a12013167ff88f7adcded91).
Workflow: [fingerprint-regression #50](https://github.com/csbxd/fingerprint-bridge/actions/runs/35772685051).
Previous complete matrix: [TLS capability validation, run #49](TLS-CAPABILITY-VALIDATION.md).
Machine-readable summary: [ARIA-MATRIX-50.json](ARIA-MATRIX-50.json).

This increment removes the measured ARIA cipher-list omissions by implementing
real TLS 1.2 ARIA-GCM record protection. Capability success is not a claim of
complete TLS, HTTP or TCP fingerprint equality.

## Implemented scope

The patched upstream TLS backend now supports all ten RFC 6209 GCM suites
observed in the matrix:

| Key exchange / authentication | ARIA-128 / SHA-256 | ARIA-256 / SHA-384 |
| --- | --- | --- |
| RSA | `0xc050` | `0xc051` |
| DHE-RSA | `0xc052` | `0xc053` |
| DHE-DSS | `0xc056` | `0xc057` |
| ECDHE-ECDSA | `0xc05c` | `0xc05d` |
| ECDHE-RSA | `0xc060` | `0xc061` |

The implementation contains ARIA-128/256 block encryption, 128-bit GCM,
TLS 1.2 explicit-nonce handling and 16-byte authentication tags. Decryption
authenticates the complete record before releasing plaintext. An outbound AEAD
context rejects reuse of a TLS explicit nonce. The ARIA S-box implementation
uses a full-table constant-time scan; this is an intentionally conservative,
slow implementation and has not received an independent side-channel or
cryptographic audit.

Only suites present in the incoming ClientHello are enabled for B's connection
to A, and their client order is preserved. The implementation does not map ARIA
identifiers to AES and does not claim ARIA CBC, TLS 1.3 or DTLS support.

## Independent primitive and real-wire tests

The primitive fixture compares the patched backend against ciphertext and tags
generated independently with the system OpenSSL ARIA-GCM implementation. Both
ARIA-128 and ARIA-256 vectors match byte-for-byte. For each key size, a changed
tag is rejected without exposing unauthenticated plaintext, and reuse of the
same outbound nonce is rejected.

For each of the ten suites, an independent OpenSSL TLS 1.2 origin runs four
cases: valid, changed ciphertext, changed tag and suite not offered. The valid
case completes the real handshake and exchanges two HTTP requests, including a
response larger than 16 KiB. It verifies B's Cookie, the rewritten authority,
binary body bytes, Location and Cookie Domain. Authentication failures do not
deliver corrupted HTTP, and the unoffered case performs no HTTP request.

Both x86_64 and ARM64 regression jobs passed:

| Check per architecture | Result |
| --- | ---: |
| Rust tests | 62/62 |
| Python test methods | 34/34 |
| Independent hybrid-group cases | 18/18 |
| ARIA real-wire cases | 40/40 |
| ARIA primitive vectors | 2/2 |
| Changed-tag rejections | 2/2 |
| Repeated-nonce rejections | 2/2 |

Formatting, Clippy, the HTTPS lab, certificate/hostname rejection tests and the
TCP capture lab also passed on both architectures. The Rust total comprises 5
unit, 4 Brainpool, 1 CCM, 1 certificate-compression, 6 Ed448 and 45 fingerprint
tests. The 40 ARIA wire cases and primitive-vector method are included in the
34 Python test methods rather than added to that count.

## Completed 72-cell matrix

All eight native environments ran nine client/protocol combinations: x86_64
and ARM64, Ubuntu 24.04/Debian 13/Fedora 43/Alpine 3.23, and the unchanged
default Python, Node, Go, Java and Rust clients. Each cell retains direct-1,
direct-2, bridged and same-B-connection evidence. Locally downloaded artifact
ZIP hashes matched GitHub's published SHA-256 digests.

| Measure | Run #49 | Run #50 |
| --- | ---: | ---: |
| Full match | 8 | 8 |
| Mismatch with stable baseline | 40 | 40 |
| Inconclusive direct baseline | 24 | 24 |
| Direct/bridge TLS MATCH | 16/72 | 16/72 |
| Direct/bridge HTTP MATCH | 65/72 | 66/72 |
| Direct/bridge TCP MATCH | 72/72 | 72/72 |
| Same-connection TLS MATCH | 32/72 | 32/72 |
| Same-connection HTTP MATCH | 72/72 | 72/72 |

The overall verdict does not improve because every Node row also retains point
formats `1` and `2`, which B still cannot reproduce. Thus removing ARIA is a
verified capability improvement without turning an overlapping row into a full
match. The one additional HTTP MATCH is in the already-unstable Go HTTP/2
baseline group and is not attributed to the ARIA change.

## Measured capability improvement

The complete ordered inbound/outbound cipher vector now matches in **72/72**
cells, up from 56/72 in run #49. Each listed identifier is present at B's output
in every cell that offered it:

| Suite | Offering cells | Retained by B |
| --- | ---: | ---: |
| `0xc050` | 16 | 16/16 |
| `0xc051` | 16 | 16/16 |
| `0xc052` | 16 | 16/16 |
| `0xc053` | 16 | 16/16 |
| `0xc056` | 12 | 12/12 |
| `0xc057` | 12 | 12/12 |
| `0xc05c` | 16 | 16/16 |
| `0xc05d` | 16 | 16/16 |
| `0xc060` | 16 | 16/16 |
| `0xc061` | 16 | 16/16 |

The eight RSA/DHE-RSA/ECDHE suites were offered by all 16 Node rows; the two
DHE-DSS suites were offered by 12 Node rows. No cipher-suite omission remains
in these 72 samples. This does not imply support for algorithms not offered in
the matrix or for TLS modes outside the explicit implementation scope.

## Remaining differences and acceptance status

Strict enforcement remains enabled. Both regression jobs succeeded; the eight
matrix jobs and summary gate failed with exit code 1 because actual differences
or unstable baselines remain. No ignore list, client default, certificate check
or acceptance rule changed.

The current measured B ingress/egress omissions are:

- EC point formats `1` and `2`: 24 rows, covering Python 8 and Node 16.
- `status_request_v2` extension `17`: all 16 Java rows.

Accordingly, stable TLS mismatches remain in Python 8, Node 16 and Java 16.
The 16 Rust rows remain inconclusive because their two independent direct
ClientHellos do not establish a stable extension-order baseline. All eight Go
HTTP/2 baselines are also unstable; six of them differ in independent HTTP/2
header order/HPACK bytes in this run. Same-connection HTTP still matches 72/72,
and TCP matches 72/72 on the loopback runner kernels.

Unknown or unsupported extensions are not copied blindly into an upstream
ClientHello. Safe `status_request_v2` support requires parsing and validating
the negotiated multi-certificate status response. Point formats `1` and `2`
require actual compressed prime-field and binary-field EC support; merely
copying their numbers would violate the real-capability rule.

The remaining work therefore continues; this record does not state that all
fingerprints are equal.
