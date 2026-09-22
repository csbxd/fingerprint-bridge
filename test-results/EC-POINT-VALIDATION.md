# TLS compressed-prime EC point validation

Validated source: `9d6f2c44f339a36f7ce28d1efe7f0cf8d1d56fc7`  
GitHub Actions: run `35797236075` (`#61`)

## Implemented increment

The bridge now mirrors EC point format `1` (`ansiX962_compressed_prime`) when it was present in the downstream ClientHello. The TLS 1.2 ECDHE client path accepts only SEC 1 compressed-prime prefixes `0x02` and `0x03`, parses the point on the selected prime-field group, validates it, and derives the real shared secret. Existing TLS 1.3 and hybrid-key-share paths stay uncompressed unless this connection-local TLS 1.2 opt-in is active.

The API rejects empty, duplicate, missing-uncompressed, unknown, DTLS, and post-handshake configurations. It copies only formats `0` and `1`; it does not claim format `2` support.

## Independent cryptographic validation

The independent Go peer is not linked to the bridge TLS backend.

- Positive: the peer sends a compressed P-256 ServerKeyExchange point. Both architectures verify ClientFinished, exchange encrypted HTTP, preserve `sid=from_B`, and rewrite the authority to A.
- Negative: the peer sends a correctly signed but invalid compressed point. Both architectures receive TLS alert `47` (`illegal_parameter`), and no HTTP request reaches the origin.
- Wire evidence in both cases shows the B-to-A ClientHello point-format vector is exactly `[0,1]`.

Each architecture passed 64 Rust tests, 36 Python test methods, 18 hybrid-group cases, and the two compressed-point cases. Certificate verification, strict gating, client defaults, and the comparison ignore set were not weakened.

## 72-cell matrix

The full native x86_64/ARM64, four-distribution, five-language matrix completed:

| Result | Count |
|---|---:|
| Full match | 24/72 |
| Stable mismatch | 24/72 |
| Unstable/missing direct baseline | 24/72 |
| TLS layer match | 32/72 |
| HTTP layer match | 64/72 |
| TCP layer match | 72/72 |
| Same-connection B ingress/egress TLS match | 48/72 |
| Same-connection B ingress/egress HTTP match | 72/72 |

Cipher, group, signature-algorithm, certificate-signature-algorithm, and extension order vectors match in 72/72 cells. Point-format vectors match in 48/72 cells. In all 24 applicable Python/Node cells the bridge improved from `[0]` to `[0,1]`, proving that compressed-prime is no longer discarded.

## Remaining boundary

Those 24 clients also advertise point format `2` (`ansiX962_compressed_char2`). It describes compressed points over binary-field curves. The pinned backend exposes only prime-field NIST TLS groups and has no binary-field EC arithmetic or TLS group implementation. Advertising `2` without implementing and negatively testing a real binary-field handshake would be a fake capability, so the bridge deliberately omits it and records `unsupported EC point format 2` in all 24 affected cells.

Consequently their exact vector remains `[0,1,2]` direct versus `[0,1]` through B, including the derived JA3 difference. The strict gate therefore continues to fail, as required. This increment is a verified cryptographic capability improvement, not a claim of complete TLS fingerprint equality.

Machine-readable counts, artifact IDs, and SHA-256 digests are in `test-results/EC-POINT-MATRIX-61.json`.
