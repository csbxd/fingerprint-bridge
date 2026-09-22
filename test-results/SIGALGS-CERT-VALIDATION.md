# Independent certificate signature extension validation

Validated on 2026-09-22 at commit `02cbeae201804a183c52547134d02ed93cfb871b`.

Workflow: [fingerprint-regression #40](https://github.com/csbxd/fingerprint-bridge/actions/runs/35728999286).
Comparison baseline: [SHA-224 run #38](SHA224-VALIDATION.md).

## Change

B now parses and emits `signature_algorithms_cert` (extension 50) separately
from the handshake signature list in extension 13. The pinned native backend
stores this list per connection and validates it against implemented algorithms.
No new cryptographic algorithm is claimed by this change. Unsupported schemes
remain explicit limitations instead of being advertised as supported.

The parser rejects empty, odd-length, truncated and trailing-byte vectors.
It retains the existing raw extension-body digest alongside the decoded list:
the comparison exemptions have not been enlarged. The unpatched backend does
not claim extension 50 support.

## Verification

Both amd64 and arm64 regression jobs passed formatting, clippy with warnings
denied, 38 Rust tests (37 integration tests and one unit test; zero doctests),
22 Python tests, the independent HTTPS/TCP labs and 18 hybrid-group cases.

The three new Rust tests cover malformed extension bodies, independently
configured native extension emission, and unsupported DSA rejection from the
outbound advertised list. They are supplemented by the unchanged matrix's
real TLS and encrypted HTTP exchanges. Existing certificate/AEAD negative
tests continue to pass; certificate verification remains enabled.

Run #39 exposed an overly broad new test assertion: the pinned backend's
default profile also offers unsupported group 65074. The test now asserts
that exact existing limitation and still requires exact extension ordering
and the independent certificate signature list. No production or matrix
client defaults were changed. Run #40 is the completed validation run.

## Raw evidence

All eight environment archives were downloaded and checked against GitHub's
SHA-256 artifact digests. Each environment contains all nine language/protocol
cases, direct-1, direct-2 and bridged ClientHello/JSON/PCAP samples, and the
same-connection B inbound/outbound evidence.

- 24 cells offer extension 50: eight Go cases and sixteen Java cases.
- All eight Go cases (Fedora 43/Alpine 3.23, both architectures, HTTP/1.1 and
  HTTP/2) retain the exact extension body in A-side ClientHello bytes and
  same-connection B evidence. Their TLS and paired TLS comparisons now match.
- Java now emits a distinct certificate list, but its body still differs:
  Ed448 (`0x0808`) and DSA (`0x0202`, `0x0302`, `0x0402`) are unsupported and
  are explicitly reported. None of these sixteen cases is claimed as an
  extension-body match.

## Complete 72-cell matrix

Coverage remains amd64/arm64, Ubuntu 24.04, Debian 13, Fedora 43 and Alpine
3.23, with Python, Node, Go, Java and Rust clients. All evidence is present.

| Check | Run #38 | Run #40 |
| --- | ---: | ---: |
| Stable direct baseline | 48/72 | 48/72 |
| TLS match | 8/72 | 16/72 |
| HTTP match | 64/72 | 64/72 |
| TCP match | 72/72 | 72/72 |
| Same B connection TLS match | 24/72 | 32/72 |
| Same B connection HTTP match | 72/72 | 72/72 |
| Final match | 4 | 8 |
| Final mismatch | 44 | 40 |
| Inconclusive direct baseline | 24 | 24 |

The four additional final matches are Go HTTP/1.1 on Fedora/Alpine across both
architectures. The corresponding HTTP/2 cases have matching TLS but remain
inconclusive because their independent direct baseline is unstable.

The strict gate still fails. Remaining differences include cipher suites,
groups, signature lists, extension sets/bodies, point formats and HTTP/2 wire
layout. Baseline instability is not converted into a pass. TCP results cover
the existing loopback/shared-runner-kernel lab, not arbitrary client OS and
Internet network paths. This validation does not claim all fingerprints match.

Machine-readable counts, all 72 verdicts, extension lists/limitations and
artifact digests are in [SIGALGS-CERT-MATRIX-40.json](SIGALGS-CERT-MATRIX-40.json).
