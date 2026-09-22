# RSA-PSS-PSS certificate validation

Run #24 started at 2026-09-21T23:53:24Z and completed at
2026-09-22T00:03:39Z. This is an incremental TLS-backend improvement, not a
claim of complete TLS/HTTP/TCP fingerprint equivalence.

## Change and threat model

- Add the three RFC 8446 RSA-PSS-PSS signature schemes (`0x0809`, `0x080a`,
  `0x080b`) to the pinned BoringSSL backend and the bridge's supported-profile
  filter.
- Parse parameter-constrained RSA-PSS SubjectPublicKeyInfo keys with the
  matching SHA-256, SHA-384 or SHA-512 restrictions and map those key types to
  RSA-PSS-PSS, rather than incorrectly treating them as RSA-PSS-RSAE.
- Keep certificate-chain and hostname verification enabled. The positive case
  generates a restricted RSA-PSS leaf key, negotiates TLS 1.3
  `rsa_pss_pss_sha256`, and completes an HTTP exchange. A one-bit corruption of
  the leaf certificate signature must fail before HTTP reaches A.
- Require the captured outbound ClientHello to contain all three schemes. This
  assertion supplements, rather than replaces, the real cryptographic
  negotiation and tampered-certificate negative case.

No client defaults, normalization exemptions, strict gates, certificate checks,
real A service, SSH deployment or private traffic were changed.

## Verified regression results

[Run #24](https://github.com/csbxd/fingerprint-bridge/actions/runs/35669578415)
tested code [`ffaf720`](https://github.com/csbxd/fingerprint-bridge/commit/ffaf72045f50b280da97a2f3c7f2954ae29c5f8b).
Both native regression jobs passed:

| Architecture | Job | Rust | Python | Hybrid-group cases | RSA-PSS-PSS valid chain | Tampered signature |
| --- | --- | ---: | ---: | ---: | --- | --- |
| amd64 | [106563166736](https://github.com/csbxd/fingerprint-bridge/actions/runs/35669578415/job/106563166736) | 34 | 20 | 18 | pass | rejected before HTTP |
| arm64 | [106563166557](https://github.com/csbxd/fingerprint-bridge/actions/runs/35669578415/job/106563166557) | 34 | 20 | 18 | pass | rejected before HTTP |

The Rust total is one unit test plus 33 integration tests. The Python suite's new
twentieth test runs both the valid and tampered RSA-PSS-PSS certificate subcases.
The independent HTTPS/SYN labs, ML-DSA validation and all 18 hybrid
key-exchange cases also continue to pass on both architectures.

## Observed ClientHello improvement

The eight architecture/distribution artifacts contain 40 matrix cells whose
direct Python, Node or Java ClientHello offers all three RSA-PSS-PSS schemes:

| Client | Protocols | Cells offering `0x0809/0x080a/0x080b` | B outbound also offers all three |
| --- | --- | ---: | ---: |
| Python | HTTP/1.1 | 8 | 8 |
| Node | HTTP/1.1, HTTP/2 | 16 | 16 |
| Java | HTTP/1.1, HTTP/2 | 16 | 16 |
| **Total** |  | **40** | **40** |

For example, run #20's Ubuntu/amd64 Python evidence omitted `2057,2058,2059`
from B's outbound signature-algorithm list. Run #24 preserves them in the same
position relative to that client's supported algorithms. The same assertion was
cross-checked from all eight run #24 matrix artifacts, not just from the backend
unit test.

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
| Whole-case verdict | 4/72 | 45 mismatch, 23 inconclusive-baseline |

The four complete matches remain Go HTTP/1.1 on Ubuntu and Debian on both
architectures. Whole-field match counts are unchanged because the affected
clients still have other non-exempt TLS differences. The change from run #20's
24 to 23 inconclusive baselines is direct-baseline run-to-run variation, not a
relaxed criterion or a claimed fingerprint improvement. Missing or unstable
evidence is still never counted as a pass.

The [machine-readable run #24 record](RSAPSS-MATRIX-24.json) contains exact
aggregate counts, regression job IDs, the 40-cell RSA-PSS-PSS assertion and
metadata/digests for all 11 artifacts. The report was generated from the strict
gate's rendered 72-row table and cross-checked against the individual evidence.

## Remaining boundary

This result establishes genuine RSA-PSS-PSS certificate verification and removes
one stable signature-algorithm-list difference. It does not make arbitrary
client fingerprints identical. Current remaining examples include Ed448 and
legacy signature schemes, unsupported TLS groups/ciphers/extensions, complete
HRR/resumption/record-layout behavior and HTTP/2 wire differences. The strict
matrix accurately continues to fail.
