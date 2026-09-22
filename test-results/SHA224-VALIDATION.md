# SHA-224 signature validation

Validated commit: `9b28880b2797d42a65e337f5c8bfcce8c4130f8c`

Workflow: [fingerprint-regression #38](https://github.com/csbxd/fingerprint-bridge/actions/runs/35683217273)

## Change

The patched backend now implements the TLS 1.2 signature schemes
`rsa_pkcs1_sha224` (`0x0301`) and `ecdsa_sha224` (`0x0303`) as real
cryptographic operations. The backend registers their SHA-224 digest and key
types, exposes their names to the TLS configuration layer, maps SHA-224 X.509
keys to the corresponding wire values, and permits them only when the
`patched-tls` feature is active.

Incoming clients that offer either scheme can therefore have the same value
retained in B's outbound ClientHello instead of receiving an unsupported-value
limitation.

## Cryptographic verification

Both amd64 and arm64 regression jobs exercised each scheme independently:

- The origin was restricted to TLS 1.2 and exactly one SHA-224 signature
  scheme. RSA and P-256 ECDSA origin certificates were used for `0x0301` and
  `0x0303`, respectively.
- The client offered both RSA- and ECDSA-authenticated cipher suites so that B
  could mirror a usable profile. The origin trace confirmed SHA-224 and an
  encrypted HTTP response completed through B.
- The outbound evidence contained the corresponding wire value (`0x0301` or
  `0x0303`).
- In the negative case the client omitted the target SHA-224 scheme while the
  origin still required it. No HTTP 200 or successful outbound evidence was
  produced, and the TLS exchange failed. This verifies negotiation and
  rejection rather than ClientHello-only advertising.

Certificate verification remained enabled throughout.

## Regression results

Both native architectures passed:

- 35 Rust tests (34 integration/unit tests plus one doctest)
- 22 Python tests
- 18 hybrid-group positive/negative cases
- formatting and clippy with warnings denied

No client defaults, exemptions, ignore lists or strict-gate rules were changed.

## 72-cell matrix

All 72 cells ran across amd64/arm64, Ubuntu 24.04, Debian 13, Fedora 43 and
Alpine 3.23 with Python, Node, Go, Java and Rust clients.

Across all eight archived environment evidence sets:

- 40 cells offered `0x0301`; B preserved it in all 40 outbound ClientHellos.
- 40 cells offered `0x0303`; B preserved it in all 40 outbound ClientHellos.
- For each scheme, coverage was Python 8/8, Node 16/16 and Java 16/16.
- No report retained an `unsupported signature algorithm 769` or
  `unsupported signature algorithm 771` limitation.

The overall strict result remains intentionally failing:

| Check | Result |
| --- | ---: |
| Stable direct baseline | 48/72 |
| TLS | 8/72 match |
| HTTP | 64/72 match |
| TCP | 72/72 match |
| Same B connection TLS | 24/72 match |
| Same B connection HTTP | 72/72 match |
| Final verdict | 4 match, 44 mismatch, 24 inconclusive |

Other TLS fields still differ, so this result does not claim complete
fingerprint equality. Direct-1, direct-2, bridged and same-connection B
comparisons remain separate and the strict gate remains unchanged.

Machine-readable evidence metadata is in
[`SHA224-MATRIX-38.json`](SHA224-MATRIX-38.json).
