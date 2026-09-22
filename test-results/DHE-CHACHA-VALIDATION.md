# DHE-RSA-ChaCha20 validation

Validated commit: \`da987de1003254c9d2f753b70cbb41ba7adc6259\`

Workflow: [fingerprint-regression #28](https://github.com/csbxd/fingerprint-bridge/actions/runs/35675965073)

## Change

The patched backend now implements TLS 1.2
\`TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256\` (\`0xccaa\`) as a real
cipher suite. It uses the backend's existing finite-field DHE, RSA
authentication, ChaCha20-Poly1305 AEAD and SHA-256 handshake machinery.

The cipher is registered in the public cipher catalog and in the ChaCha
preference group. The mirror therefore retains \`0xccaa\` instead of reporting
it as unsupported when the incoming client offered it.

## Cryptographic verification

Both amd64 and arm64 regression jobs passed a positive and a negative check:

- OpenSSL \`s_server\` was restricted to TLS 1.2 and
  \`DHE-RSA-CHACHA20-POLY1305\`. B completed the TLS handshake and an encrypted
  HTTP request; the server trace confirmed
  \`TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256\`.
- A forwarding fault proxy flipped one byte in the first encrypted server
  application-data record. B rejected the corrupted record and did not return
  an HTTP 200 response. This verifies real AEAD processing rather than a
  ClientHello-only advertisement.

The same test also checks that the outbound captured cipher list still contains
\`0xccaa\`.

## Regression results

Both native architectures passed:

- 34 Rust tests (33 integration/unit tests plus one doctest)
- 21 Python tests
- 18 hybrid-group positive/negative cases
- formatting and clippy with warnings denied

Certificate verification remained enabled. No client defaults, exemptions,
ignore lists or strict-gate rules were changed.

## 72-cell matrix

All 72 cells ran across amd64/arm64, Ubuntu 24.04, Debian 13, Fedora 43 and
Alpine 3.23 with Python, Node, Go, Java and Rust clients.

Across the archived raw evidence:

- 38 cells offered \`0xccaa\` on the first direct connection.
- B preserved \`0xccaa\` in all 38 corresponding outbound ClientHellos.
- By client: Python 6/6, Node 16/16, Java 16/16.

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
[\`DHE-CHACHA-MATRIX-28.json\`](DHE-CHACHA-MATRIX-28.json).
