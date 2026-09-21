# Hybrid groups and TLS 1.3 validation

Date: 2026-09-21. This is an incremental improvement; full TLS/HTTP/TCP equivalence
has not been achieved. The previous completed 72-case run is recorded in
[TLS-BACKEND-VALIDATION.md](TLS-BACKEND-VALIDATION.md).

## Changes

- Implement real SecP256r1MLKEM768 (4587) and SecP384r1MLKEM1024 (4589) key
  exchanges using the pinned backend's EC and ML-KEM primitives. Preserve group
  order and selected key-share shapes, generate fresh keys, and validate peer
  points, canonical ML-KEM public keys and exact share lengths. The composition
  and encoding follow the [IETF ECDHE-MLKEM specification, sections 4 and 7](https://www.ietf.org/archive/id/draft-ietf-tls-ecdhe-mlkem-03.html).
- Accept a genuine TLS 1.3-only cipher profile without requiring an unrelated
  legacy suite. Empty lists and invalid cipher names still fail. Do not add
  TLS 1.2 to a client's TLS 1.3-only supported_versions list.
- Enable TLS 1.3 at B's incoming connection. The btls Mozilla v4 acceptor profile
  explicitly disabled it; clearing that option retains the existing TLS 1.2
  cipher compatibility. B pins its incoming negotiated version to the origin's
  actual TLS 1.2 or TLS 1.3 result. A new regression first reproduced direct TLS
  1.2 versus bridged TLS 1.3 against a TLS-1.2-only origin, then passed after this
  alignment; TLS-1.3-only origins are covered too.
- Preserve the native key-share validator's illegal_parameter alert instead of
  replacing it with internal_error. This was caught by wire-level negative tests.

No client defaults, fingerprint exclusions, strict gates, certificate checks,
production A services or SSH deployments were changed. Only synthetic test peers
explicitly constrain groups to force negotiation of the new implementations.

## Local evidence

- 34 Rust tests (1 unit + 33 integration) pass, including real emitted group/share
  shapes, TLS 1.3-only ciphers/versions, empty-list and invalid-name rejection.
- 18 Python regressions pass, retaining the independent TLS 1.2 SCSV handshake
  and adding direct-versus-bridged negotiated-version assertions.
- The independent HTTP/1.1 and HTTP/2 lab passes, including hostname, CA and strict
  TLS rejection.
- Go 1.27.1's separate crypto/tls client and origin exercise both sides of B.
  Each new group completes a TLS 1.3 handshake and HTTP with the B cookie,
  both with its initial share and after an origin HelloRetryRequest.
- For each group, invalid server/client EC points, truncated server/client key
  shares and a non-canonical client ML-KEM public key produce illegal_parameter.
  Corrupted server ML-KEM ciphertext and an incorrect origin hostname fail before
  HTTP reaches A. In total there are 18 targeted cases (4 success, 14 rejection).
- The unchanged nine native language/protocol cases complete without runtime
  errors. Same-connection HTTP matches 9/9; independent HTTP matches 8/9. Go h2
  still has an unstable independent header/HPACK baseline. Paired Rust TLS matches
  2/2; the local Go supported_groups difference disappears, but ML-DSA signature
  schemes and signature_algorithms_cert extension 50 still differ.
- Local TCP capture is unavailable, so all nine full local verdicts correctly
  remain missing-evidence. They are not full fingerprint passes.

The [machine-readable local evidence summary](HYBRID-GROUP-LOCAL.json) archives
the targeted outcomes and the before/after Go TLS difference fields. ClientHello
captures and complete runtime files are uploaded as CI artifacts.

## CI and remaining work

The workflow retains the strict 72-case, eight-environment matrix. General
regressions and the 18-case independent hybrid lab now run on both native amd64
and arm64 runners. The two regression artifacts have architecture-specific names.

[Run #11](https://github.com/csbxd/fingerprint-bridge/actions/runs/35649048707)
tested code `4392bd5e82aa9cf7468823129ac6ea0cf13136b4`, before the follow-up
origin-version pinning. All 72 cases and 11 artifacts completed with no missing
environment/evidence or runtime errors. Both architecture regression jobs passed
(34 Rust, 17 Python and 18 independent hybrid cases per architecture, plus HTTPS
and SYN labs). The unchanged strict gate correctly remains red.

| Run #11 measurement | Matches | Other |
| --- | ---: | --- |
| Independent TLS | 8/72 | 64 differences |
| Independent HTTP | 64/72 | 8 differences |
| TCP SYN | 72/72 | same runner kernel, loopback only |
| B-paired TLS | 24/72 | 48 differences |
| B-paired HTTP | 72/72 | 0 differences |
| Whole-case verdict | 4/72 | 45 mismatch, 23 inconclusive-baseline |

[Archived 72-row summary](HYBRID-GROUP-MATRIX-11.json) comes from the rendered
Actions summary. These match counts equal run #10; the differing number of stable
Go h2 baselines is natural across runs, not a relaxed criterion. The improvement
is real hybrid capability, removal of the local Go 1.27 group-list difference,
and TLS 1.3 connection compatibility, not a claim of more full-matrix matches.

The follow-up negotiated-version fix has passed local Rust/Clippy, all 18 Python
regressions and all 18 hybrid cases. Its complete cross-platform rerun is pending;
the run #11 measurements must not be attributed to that follow-up revision.

Outstanding areas include ML-DSA/signature_algorithms_cert, other unsupported
groups/ciphers/extensions, full HRR/resumption behavior, cross-kernel TCP behavior
beyond SYN, and real browser profiles. Successful HRR negotiation here is not a
claim that every handshake message or record boundary has matching fingerprints.
