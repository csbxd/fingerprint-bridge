# RFC 6961 status_request_v2 validation

Evidence record, 2026-09-22. Final code under validation:
[`2a4e20d64346c90d149c67783f19bc84963f08ff`](https://github.com/csbxd/fingerprint-bridge/commit/2a4e20d64346c90d149c67783f19bc84963f08ff).
Workflow: [fingerprint-regression #55](https://github.com/csbxd/fingerprint-bridge/actions/runs/35791784140).
Previous complete matrix: [ARIA validation, run #50](ARIA-VALIDATION.md).
Machine-readable summary: [STATUS-V2-MATRIX-55.json](STATUS-V2-MATRIX-55.json).

This increment removes the measured Java `status_request_v2` omission by
implementing RFC 6961 `ocsp_multi` negotiation and validation in the patched TLS
backend. It does not claim complete TLS, HTTP or TCP fingerprint equality.

## Implemented scope

B now reproduces extension 17, including the exact ordered request body offered
by the Java client in the matrix. If A acknowledges it, B requires a TLS 1.2
`CertificateStatus` message of type `ocsp_multi` before key-exchange parameters.
Each non-empty response is parsed and checked against the corresponding
certificate and issuer from the chain that already passed normal X.509 path
validation. The check requires a current, correctly signed `GOOD` response.

The verified chain is used rather than only the certificates transmitted by A,
because A may omit the trust anchor. Certificate and hostname verification stay
enabled. A malformed list, a missing negotiated status message, a revoked
certificate or a changed response signature terminates the handshake before an
HTTP request can reach A.

Unknown extensions are still not copied blindly, and the implementation does
not substitute another status type or merely serialize extension 17.

## Real negotiation and negative cases

The independent origin is a Go TLS 1.2 record peer using
`TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`. It parses B's ClientHello, requires the
exact Java extension-17 body, sends an RFC 6961 response in protocol order, and
verifies the encrypted client Finished and HTTP request.

Both x86_64 and ARM64 passed all five cases:

| Case | Expected and observed result |
| --- | --- |
| Valid signed `GOOD` response | Handshake and encrypted HTTP complete |
| Signed `REVOKED` response | Alert 113; no HTTP reaches A |
| Changed OCSP signature | Alert 113; no HTTP reaches A |
| Malformed response list | Decode alert 50; no HTTP reaches A |
| Negotiated but omitted status | Alert 113; no HTTP reaches A |

The valid case also verifies B's Cookie is preserved and authority is rewritten
to A. The three semantic status failures produce
`bad_certificate_status_response`; the framing failure produces
`decode_error`.

Per architecture, Actions passed **63 Rust tests**, **35 Python test methods**,
**18 independent hybrid-group cases**, the HTTPS lab and TCP capture lab. The
status-v2 Python method executes the five wire cases above. Formatting and
Clippy passed as well.

## Completed 72-cell matrix

All eight native environments ran nine client/protocol combinations: x86_64
and ARM64, Ubuntu 24.04/Debian 13/Fedora 43/Alpine 3.23, and the unchanged
default Python, Node, Go, Java and Rust clients. Every cell retains independent
direct-1, direct-2 and bridged captures plus same-B-connection ingress/egress
evidence. All eleven downloaded artifact ZIP hashes matched the SHA-256 digests
published by GitHub Actions.

| Measure | Run #50 | Run #55 |
| --- | ---: | ---: |
| Full match | 8 | 24 |
| Mismatch with stable baseline | 40 | 24 |
| Inconclusive direct baseline | 24 | 24 |
| Direct/bridge TLS MATCH | 16/72 | 32/72 |
| Direct/bridge HTTP MATCH | 66/72 | 64/72 |
| Direct/bridge TCP MATCH | 72/72 | 72/72 |
| Same-connection TLS MATCH | 32/72 | 48/72 |
| Same-connection HTTP MATCH | 72/72 | 72/72 |

The two-cell HTTP change is baseline variation in the already-inconclusive Go
HTTP/2 group and is not attributed to this TLS change. Strict acceptance is
based on each current run, so those cells remain inconclusive rather than
passes.

## Measured capability improvement

The complete ordered extension vector now matches in **72/72** cells, up from
56/72 in run #50. Extension 17 was offered by all 16 Java rows and retained by
B in **16/16**; all 16 rows changed from stable mismatch to full match. Their
HTTP/1.1 and HTTP/2 wire comparisons, TCP comparisons and same-connection
comparisons also pass.

The complete ordered cipher, group, handshake-signature and
certificate-signature vectors remain 72/72. This result establishes capability
for the tested RFC 6961 form and the exercised real handshake. It is not a
claim about untested OCSP responder arrangements or other TLS versions.

## Remaining difference and acceptance status

The only stable TLS capability omission measured in this matrix is EC point
formats `1` and `2`: 24 rows, covering Python 8 and Node 16. B currently offers
only uncompressed format `0`. Reproducing `1` and `2` requires real compressed
prime-field and binary-field EC handling; adding only the identifiers would
violate the real-capability requirement.

The 16 Rust rows remain inconclusive because their two independent direct
ClientHellos do not establish a stable extension-order baseline. All eight Go
HTTP/2 rows also have unstable direct baselines. These are not silently
normalized or counted as matches.

Strict enforcement remains enabled. Both regression jobs succeeded; the eight
matrix jobs and summary gate failed because measured differences or unstable
baselines remain. No ignore list, client default, certificate check or
acceptance rule changed. Work therefore continues; this record does not state
that all fingerprints are equal.
