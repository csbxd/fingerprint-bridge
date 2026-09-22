# AES-CCM and AES-CCM8 validation

Code under validation: [`9944db7791e7f1c2897744a5805d093c2a2c4ad0`](https://github.com/csbxd/fingerprint-bridge/commit/9944db7791e7f1c2897744a5805d093c2a2c4ad0) (2026-09-22).
Workflow: [fingerprint-regression #48](https://github.com/csbxd/fingerprint-bridge/actions/runs/35757581608).
Previous completed matrix: [DSA certificate run #47](DSA-CERTIFICATES-VALIDATION.md).

## Implemented capability

The patched backend implements real AES-CCM record encryption and authentication
for fourteen explicitly offered TLS cipher suites. It reuses the existing AES
and CCM primitives with the TLS nonce construction, rather than advertising an
algorithm for which the bridge cannot complete a handshake.

| Protocol | Key exchange/authentication | Full 16-byte tag | Short 8-byte tag |
| --- | --- | --- | --- |
| TLS 1.2 | RSA, AES-128 / AES-256 | `0xc09c` / `0xc09d` | `0xc0a0` / `0xc0a1` |
| TLS 1.2 | DHE-RSA, AES-128 / AES-256 | `0xc09e` / `0xc09f` | `0xc0a2` / `0xc0a3` |
| TLS 1.2 | ECDHE-ECDSA, AES-128 / AES-256 | `0xc0ac` / `0xc0ad` | `0xc0ae` / `0xc0af` |
| TLS 1.3 | Negotiated TLS 1.3 key exchange, AES-128 | `0x1304` | `0x1305` |

TLS 1.2 uses a four-byte fixed IV and an eight-byte explicit nonce, with the
record sequence number supplying the explicit part. TLS 1.3 uses its normal
sequence-number XOR nonce and authenticates the record header. The CCM
`seal_scatter` implementation joins the main plaintext and extra input before
one MAC/CTR operation, including TLS 1.3's encrypted inner content type. It does
not independently pad or restart encryption for the two fragments. Temporary
storage is cleared, and the existing EVP wrappers clear unauthenticated output
on failure.

Cipher IDs and TLS 1.2 constructions follow
[RFC 6655, Section 3](https://www.rfc-editor.org/rfc/rfc6655.html#section-3) and
[RFC 7251, Section 2](https://www.rfc-editor.org/rfc/rfc7251.html#section-2).
TLS 1.3 record protection and suite definitions follow
[RFC 8446, Sections 5.2–5.3 and Appendix B.4](https://www.rfc-editor.org/rfc/rfc8446.html).

CCM record use is capped at `2^23` records per traffic key in both directions,
using the confidentiality bound in
[RFC 9147, Appendix B](https://www.rfc-editor.org/rfc/rfc9147.html#appendix-B).
CCM8's shorter tag also requires the stream connection to fail on its first
authentication error, including rejected-0RTT trial decryption. This increment
does not enable CCM for DTLS; its record-context creation is explicitly rejected.
TLS 1.2 must reconnect before exhausting the budget. TLS 1.3 can rotate keys
before exhaustion; automatic scheduling of KeyUpdate is not added here.

The TLS 1.3 client now explicitly checks that the ServerHello's suite was
offered, including a profile that supplies only a subset of supported suites.
The existing check that the final ServerHello agrees with HelloRetryRequest is
retained.

## Independent real-wire tests

`scripts/test_ccm.py` uses an independent OpenSSL `s_server` as the loopback
origin, OpenSSL `s_client` as the verified client of B, and the normal Rust bridge
between them. Only these targeted capability probes restrict cipher suites;
the default clients used by the fingerprint matrix are unchanged. Temporary
synthetic RSA/ECDSA certificates use the normal test CA. Hostname and certificate
verification remain enabled, and no OpenSSL security level is reduced.

The test completes 58 cases:

| Case | Count | Required evidence |
| --- | ---: | --- |
| Valid negotiation and HTTP | 14 | Origin's actual ServerHello selects the requested CCM suite; two requests and responses complete |
| Corrupted ciphertext | 14 | Wire mutation occurs and B reports `DECRYPTION_FAILED_OR_BAD_RECORD_MAC` |
| Corrupted tag | 14 | Tag mutation occurs and B reports `DECRYPTION_FAILED_OR_BAD_RECORD_MAC` |
| Client did not offer the suite | 14 | Origin reports `no shared cipher`; no ServerHello or HTTP request is accepted |
| Unsolicited TLS 1.3 ServerHello suite | 2 | Modified ServerHello is rejected with `WRONG_CIPHER_RETURNED` before encrypted server records are forwarded |

Each valid case transfers a binary body larger than 40 KiB in both directions,
spanning multiple TLS records, followed by a second request on the same
connection. Assertions check exact response bytes, request body digests,
rewritten A authority, unchanged B Cookie, response Cookie Domain, and Location.
The emitted outbound ClientHello must contain the selected suite.

The corruption tests target the first server application-data record. For TLS
1.2 this is an HTTP response after the handshake, so requests may already have
reached A; the assertion is that the corrupted response is rejected and no HTTP
200 is returned to the client. For TLS 1.3 the outer application-data record
carries encrypted handshake messages, so the rejection occurs before any HTTP
request reaches A. These distinct boundaries are recorded rather than claiming
that all corruption cases prevent requests from reaching the origin.

The unsolicited-suite probe changes only the ServerHello's selected suite from
an offered GCM suite to an unoffered CCM suite, then withholds encrypted records.
Requiring `WRONG_CIPHER_RETURNED` distinguishes actual negotiation validation
from a later, inevitable transcript or record-authentication failure.

## Primitive and internal record-layer tests

`tests/ccm_aead.rs` compares all four key-size/tag-size combinations with fixed
vectors generated by an independent OpenSSL-backed AESCCM implementation. Every
split position of the plaintext is tested, including empty main input, empty
extra input, and non-block-aligned boundaries. Decryption must recover the
plaintext. Changed ciphertext, tag, nonce, or AAD must fail and clear output;
truncated tags, invalid nonce lengths, and unsupported tag lengths must fail.

Two Rust ClientHello tests separately verify preservation of interleaved CCM
suite order, a CCM-only TLS 1.3 profile, and absence of CCM injection into a
profile that did not offer it. These wire-shape tests complement the independent
handshake tests; they are not used as substitutes for cryptographic evidence.

`scripts/test_ccm_limits.py` compiles `scripts/clients/ccm_limits.cc` against the
exact content-addressed backend source and libraries used by the Cargo build.
This standalone fixture opens no sockets and is not linked into the product.
Its 17 cases exercise actual internal record functions with synthetic keys:

- All fourteen suites successfully seal and open the record at sequence
  `2^23 - 1`, then reject the next read and write specifically with the overflow
  error. The fixture places counters at the boundary instead of sending
  millions of network records; the product limit is not lowered.
- The two TLS 1.3 cases additionally call the backend's traffic-key rotation
  function, verify changed secrets and reset counters, then seal and open a
  record with the new keys. This tests the function used by KeyUpdate, not a
  full on-wire KeyUpdate exchange or automatic recovery after a fatal error.
- Three rejected-0RTT trial cases require CCM8 to return fatal `bad_record_mac`
  on the first corrupted record without advancing the read sequence or counting
  it as skipped early data. Full-tag CCM and GCM are controls that retain the
  existing bounded early-data discard behavior.

These internal tests do not claim end-to-end session resumption, 0RTT support,
or a complete KeyUpdate interoperability test.

## Defaults, comparison gates, and evidence

The normal TLS client defaults and default matrix client implementations are
unchanged. CCM suites are available to B when explicitly present in the observed
profile; they are not injected into an unrelated profile. Existing `ALL` and
`AES` aliases retain their prior default offer, and the unpatched backend does
not gain these algorithms. No certificate-verification bypass, new fingerprint
normalization exemption, or strict-gate relaxation is introduced.

B's inbound server policy is unchanged. The controlled client offers both GCM
and the target CCM suite; the isolated origin accepts only the target CCM suite,
forcing the B-to-A handshake to exercise it. A CCM-only inbound client is not
claimed to work with the current default server policy.

The independent direct-1/direct-2/bridged comparisons and the same-connection
inbound/outbound comparisons remain in place. `scripts/matrix_lab.py` now also
prints `TLS_CAPABILITIES` records containing algorithm IDs, extension IDs, and
public lengths for all available samples, plus explicit backend limitations.
This enables review from Actions logs when raw artifact ZIP downloads are
unavailable. These diagnostics do not decide a verdict and do not contain
private keys, traffic secrets, Cookie values, or HTTP content. They do not
replace raw ClientHello/PCAP evidence for a complete packet re-audit.

## Local verification

The final local x86_64 regression passed:

- 46 Rust tests: two unit tests, one certificate-compression test, one CCM AEAD
  test, and 42 fingerprint tests.
- 27 Python tests, including all 58 real-wire CCM cases and all 17 internal
  record-limit/trial-decryption cases.
- All 18 independent hybrid-group cases.

Local test summaries identify backend patch digest
`40fa2b358422f4389bee27178fc117d43a5ccc2c684e03e788d0da1365bef0dd`.
The targeted CCM probes are additional capability tests, not 58 newly matching
fingerprint matrix cells.

## Actions results

Both native amd64 and arm64 regression jobs passed formatting, Clippy with
warnings forbidden, all 46 Rust tests, 27 Python tests, and the 18-case independent
hybrid-group lab. Each architecture passed all 58 CCM wire cases and 17 internal
record-limit/trial-decryption cases. The independent HTTPS and TCP capture labs
also passed their functional assertions.

All 72 cells completed across the two architectures, Ubuntu 24.04, Debian 13,
Fedora 43, Alpine 3.23, and the five existing default language clients. The
strict consistency gate exited 1 on remaining differences and unstable direct
baselines. There were no runtime-error or missing-evidence verdicts and no
coverage errors. The eight matrix jobs' failure conclusions are strict
fingerprint failures, not build or test-harness errors.

| Check | Run #47 | Run #48 |
| --- | ---: | ---: |
| Stable direct baseline | 49/72 | 48/72 |
| TLS match | 16/72 | 16/72 |
| HTTP match | 64/72 | 64/72 |
| TCP match | 72/72 | 72/72 |
| Same B connection TLS match | 32/72 | 32/72 |
| Same B connection HTTP match | 72/72 | 72/72 |
| Final match | 8 | 8 |
| Final mismatch | 41 | 40 |
| Inconclusive direct baseline | 23 | 24 |

The sole classification change is amd64 Debian Go HTTP/2: this run's two direct
connections had an unstable baseline, changing mismatch to inconclusive. None
of its layer comparison columns changed. This is not counted as an improvement
or a new complete-fingerprint match.

### Measured CCM offer retention

All 72 `TLS_CAPABILITIES` log records contain direct-1, direct-2, bridged,
B-inbound and B-outbound samples. Eighteen cells offered at least one newly
implemented CCM suite: Node in all sixteen cells and Python in the two Fedora
cells. Every such offer was retained, with the ordered CCM subsequence unchanged.
No new CCM suite was injected into a profile that did not offer it.

| Suite IDs | Observed offers and retained offers, per ID |
| --- | ---: |
| `c09c`, `c09d`, `c09e`, `c09f`, `c0ac`, `c0ad` | 18/18 each |
| `c0a0`, `c0a1`, `c0a2`, `c0a3`, `c0ae`, `c0af` | 4/4 each |
| `1304` | 2/2 |
| `1305` | 0 offers; not exercised by default matrix clients |

These are measured offer-retention counts, not counts of CCM negotiation by the
default matrix. All fourteen suites, including `1305`, are separately forced
through actual negotiation and authenticated HTTP by the independent OpenSSL
test. The matrix has other missing cipher IDs, so preserving the CCM subsequence
does not assert equality of the full cipher vector.

### Remaining observed TLS differences

The same 72 inbound/outbound records still show the following omissions:

| Field | Missing value | Affected cells |
| --- | --- | ---: |
| Supported groups | X448 (`30`) | 40 |
| Handshake signatures | Ed448 (`2056`) | 40 |
| Certificate signatures | Ed448 (`2056`) | 16 |
| Handshake signatures | Brainpool `2074`, `2075`, `2076` | 12 each |
| Cipher suites | ARIA `c050/c051/c052/c053/c05c/c05d/c060/c061` | 16 each |
| Cipher suites | ARIA `c056/c057` | 12 each |
| Extensions | encrypt_then_mac (`22`) | 24 |
| Extensions | status_request_v2 (`17`) | 16 |
| EC point formats | `1`, `2`; outbound retains only `0` | 24 each |

The point-format difference is visible in the actual fields even though it is
not separately listed in the runtime's limitation strings. These omissions are
concrete follow-up work; implementing them requires real cryptographic or
extension behavior, not just inserting their identifiers. Independent Rust
ClientHellos also vary their extension order between direct connections; the
strict baseline check retains that evidence and does not convert it to a pass.

### Archived evidence and limits

[CCM-MATRIX-48.json](CCM-MATRIX-48.json) contains all 72 strict-gate rows,
both architectures' complete CCM summaries, regression excerpts, retention
counts, remaining omission counts, job conclusions and eleven artifact digests
reported by GitHub. [CCM-CAPABILITIES-48.jsonl](CCM-CAPABILITIES-48.jsonl) preserves
all 72 measured capability records, each with five samples and its source job ID.

This verification uses the completed Actions logs. Raw ZIP re-audit remains
pending after earlier connector downloads returned HTTP 403 / error code 1010;
run #48 ZIPs were not downloaded locally. Artifact digests are explicitly marked
locally unverified. The new log diagnostics restore per-cell algorithm visibility
without claiming an independent local reparse of ClientHello bytes or PCAPs.

## Remaining boundary

This increment covers the fourteen listed CCM suites, not PSK-CCM suites or
DTLS. Other algorithm and extension gaps, session-resumption differences, and
HTTP/TCP limitations remain subject to the strict matrix. TCP results concern
GitHub Linux runners and loopback paths, not cross-OS or arbitrary network
fingerprint emulation. Full TLS/HTTP/TCP fingerprint equivalence is not established.
