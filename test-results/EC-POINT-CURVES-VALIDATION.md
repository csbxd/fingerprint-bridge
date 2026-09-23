# NIST compressed-prime curve validation

Validated source: `1ad7797be00b48cf9dfcd6aa8fda64e8457aa073`  
GitHub Actions: run `35799224464` (`#62`)

## Verified increment

The independent Go TLS 1.2 origin now exercises SEC 1 compressed points on all
three prime-field NIST groups supported by the bridge backend:

| Named group | TLS group ID | Positive case | Negative case |
|---|---:|---|---|
| P-256 | 23 | encrypted HTTP completed | invalid point rejected with alert 47 |
| P-384 | 24 | encrypted HTTP completed | invalid point rejected with alert 47 |
| P-521 | 25 | encrypted HTTP completed | invalid point rejected with alert 47 |

Every positive case verifies the client's Finished message at the independent
origin, receives the encrypted request, observes `sid=from_B`, and observes the
authority rewritten to A. Every negative case uses a correctly signed
ServerKeyExchange containing a malformed compressed point; B rejects it before
any HTTP request reaches the origin.

The peer also verifies that the selected group was genuinely offered and that
the B-to-A ClientHello point-format vector is exactly `[0,1]`. It is not linked
to the bridge TLS implementation.

Both x86_64 and ARM64 regression jobs passed. Each ran 64 Rust tests, 36 Python
test methods, 18 hybrid-group cases, and all six compressed-point subcases.
Certificate verification, client defaults, comparison fields, and the strict
gate were unchanged.

## 72-cell matrix

The native x86_64/ARM64, four-distribution, five-language matrix completed with
the same verdict as run #61:

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

The strict gate failed as designed because the remaining stable mismatch was
not ignored.

## Remaining TLS boundary

The 24 stable Python/Node mismatches advertise point formats `[0,1,2]`; B emits
`[0,1]`. Format `2` is `ansiX962_compressed_char2`, which requires a real
binary-field curve implementation. The pinned backend currently exposes only
prime-field NIST TLS groups and has no binary-field EC arithmetic. Merely
copying format `2` would claim a capability that cannot complete a handshake,
so it remains deliberately rejected and recorded as
`unsupported EC point format 2`.

The result therefore proves the implemented compressed-prime capability across
all supported NIST curves. It does not claim complete TLS fingerprint equality.
Machine-readable job, artifact, test, and matrix counts are in
`test-results/EC-POINT-CURVES-MATRIX-62.json`.
