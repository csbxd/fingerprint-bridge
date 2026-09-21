# ML-DSA certificate validation

Date: 2026-09-21. This is an incremental TLS-backend improvement, not a claim of
complete TLS/HTTP/TCP fingerprint equivalence.

## Change and threat model

- Add ML-DSA-44/65/87 certificate-key parsing, X.509 signing and verification,
  certificate-signature OID mapping, TLS 1.3 signature-scheme definitions and
  peer SPKI parsing to the pinned BoringSSL backend.
- Keep certificate-chain and hostname verification enabled. The bridge does not
  merely advertise the numeric signature schemes: the positive test completes a
  real TLS 1.3 handshake and HTTP exchange, while a one-bit corruption inside the
  leaf certificate signature must be rejected before HTTP reaches A.
- The independent Go 1.27.1 peer uses `crypto/mldsa` to generate an ML-DSA-44 CA,
  leaf key and certificate. The client connects to B with SNI `b.test`; B connects
  to the synthetic A and validates its `a.test` certificate. The origin also
  checks the preserved `sid=from_B` cookie and rewritten `a.test:port` authority.
- The captured outbound ClientHello must begin its signature algorithm list with
  `0x0904`, `0x0905`, `0x0906`. This assertion is in addition to the successful
  cryptographic negotiation and the tampered-certificate negative case.

No client defaults, normalization exemptions, strict gates, certificate checks,
real A service, SSH deployment or private traffic were changed. Two test-probe
bugs found by CI were fixed without weakening the test: it now sends B's complete
configured authority including the port, and reads the response by HTTP
`Content-Length` instead of treating TCP connection close as the message boundary.

## Verified regression results

[Run #20](https://github.com/csbxd/fingerprint-bridge/actions/runs/35660210734)
tested code [`879062b`](https://github.com/csbxd/fingerprint-bridge/commit/879062b0620564556d5f19cc3e3b2f43cc54e827).
Both native regression jobs passed:

| Architecture | Job | Rust | Python | Hybrid-group cases | ML-DSA valid chain | Tampered signature |
| --- | --- | ---: | ---: | ---: | --- | --- |
| amd64 | [106533912167](https://github.com/csbxd/fingerprint-bridge/actions/runs/35660210734/job/106533912167) | 34 | 19 | 18 | pass | rejected before HTTP |
| arm64 | [106533912020](https://github.com/csbxd/fingerprint-bridge/actions/runs/35660210734/job/106533912020) | 34 | 19 | 18 | pass | rejected before HTTP |

The Rust total is one unit test plus 33 integration tests. The Python suite's new
nineteenth test runs both the valid and tampered ML-DSA certificate subcases. The
existing independent HTTPS/SYN labs and all 18 hybrid key-exchange cases also pass
on both architectures.

## Strict 72-case matrix

All eight native architecture/distribution environments completed and uploaded
their evidence. The unchanged strict consistency gate remains red:

| Measurement | Matches | Other |
| --- | ---: | --- |
| Independent TLS | 8/72 | 64 differences |
| Independent HTTP | 64/72 | 8 differences |
| TCP SYN | 72/72 | same runner kernel, loopback only |
| B-paired TLS | 24/72 | 48 differences |
| B-paired HTTP | 72/72 | 0 differences |
| Whole-case verdict | 4/72 | 44 mismatch, 24 inconclusive-baseline |

The four complete matches remain Go HTTP/1.1 on Ubuntu and Debian on both
architectures. Per-layer counts are unchanged from run #12. The change from 22 to
24 inconclusive baselines is run-to-run instability in the direct baseline, not a
fingerprint improvement and not a relaxed criterion. Missing or unstable evidence
is still never counted as a pass.

The [machine-readable run #20 record](MLDSA-MATRIX-20.json) contains all 72 rows,
regression job IDs, exact counts and metadata/digests for all 11 uploaded
artifacts. It was generated from the rendered consistency-gate table and
cross-checked against the gate log and GitHub artifact metadata.

## Remaining boundary

This result establishes genuine ML-DSA certificate verification for the targeted
TLS 1.3 path. It does not make arbitrary client fingerprints identical. Most
default language clients still differ in TLS signature algorithms, certificate
signature algorithms, ciphers or extensions; unsupported algorithms and complete
HRR/resumption/record-layout behavior remain open. HTTP and TCP limitations in the
README are unchanged, and the strict matrix accurately continues to fail.

