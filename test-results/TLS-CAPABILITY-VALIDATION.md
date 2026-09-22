# TLS capability increment: X448, Ed448, Brainpool signatures and CBC EtM

Evidence record, 2026-09-22. Code under validation:
[`81759cf98a8c43e9ed22a51e7e921ba390808741`](https://github.com/csbxd/fingerprint-bridge/commit/81759cf98a8c43e9ed22a51e7e921ba390808741).
Workflow: [fingerprint-regression #49](https://github.com/csbxd/fingerprint-bridge/actions/runs/35763709003).
Previous complete matrix:
[CCM validation, run #48](CCM-VALIDATION.md).

This increment adds real upstream TLS operations. Algorithm presence in a
ClientHello is tested separately from successful negotiation and rejection of
invalid cryptographic input. Passing these capability tests does not establish
complete TLS, HTTP or TCP fingerprint equality.

## Implementation and scope

| Capability | On-wire identifier | Implemented scope | Explicit boundary |
| --- | --- | --- | --- |
| X448 | Supported group `30` (`0x001e`) | TLS 1.2 and TLS 1.3 key agreement, including TLS 1.3 HelloRetryRequest | Reject wrong-length peers and all-zero shared secrets; not a claim of identical retry/record fingerprints |
| PureEd448 | Signature scheme `0x0808`; public-key/signature OID `1.3.101.113` | TLS 1.2 ServerKeyExchange and TLS 1.3 CertificateVerify verification; Ed448 leaf keys and Ed448 certificate-chain signatures | Verification only; no Ed448 signing or private-key import, no prehash or nonempty Ed448 context |
| Brainpool ECDSA | `0x081a`, `0x081b`, `0x081c` | TLS 1.3 schemes bound to Brainpool P256r1/SHA-256, P384r1/SHA-384 and P512r1/SHA-512; public-key and certificate parsing/verification | No Brainpool TLS named-group/key-share negotiation is added; these TLS 1.3 schemes are not accepted as TLS 1.2 aliases |
| Encrypt-then-MAC | Extension `22` (`0x0016`) | B's upstream TLS 1.2 CBC record protection with existing AES/3DES and SHA-1/256/384 HMAC combinations | No EtM for TLS 1.3, AEAD or DTLS; B's inbound server does not claim newly implemented EtM support |

X448 and Ed448 use the pinned [CRRL 0.9.0 implementation](https://github.com/pornin/crrl).
This project has no independent security audit of that dependency or this
provider integration; CRRL must not be described as an independently audited
cryptographic library here. Native callback installation is atomic and cannot
replace an installed provider. Missing providers fail closed. Native-only test
programs can link without unresolved Rust callback symbols.

BoringSSL remains responsible for X448 randomness, handshake transcripts and
TLS key scheduling. Rust scalar/result temporaries and the native private scalar
are cleared; a rejected native shared-secret buffer is also cleared. A successful
shared secret is transferred to the existing TLS key schedule. This does not
claim that every internal CRRL stack copy is zeroized. The Ed448 provider requires
canonical encodings, exact public-key/signature lengths, and a non-neutral
public key in the prime-order subgroup. ASN.1 AlgorithmIdentifier parameters
must be absent for Ed448, including in certificate signatures; explicit NULL is
rejected. The signature verifier uses PureEd448 with an empty context.

Brainpool reuses the backend's existing generic prime-field EC arithmetic with
RFC 5639 curve parameters and generated Montgomery constants. Its three TLS
1.3 signature schemes check both curve and digest, rather than treating the
scheme numbers as aliases for NIST curves. This does not implement the separate
Brainpool TLS named groups, even though primitive tests perform scalar
multiplication on these curves.

EtM is enabled only when present in the incoming offer and selected by A for a
TLS 1.2 CBC suite. It authenticates the explicit IV and ciphertext with the
record sequence number and TLS record metadata before decrypting. Authenticated
plaintext must also pass CBC padding checks. A missing/declined extension
retains the existing record construction; an unsolicited EtM response, or an
EtM response for an AEAD suite, is rejected. The increment does not establish
session-resumption or renegotiation fingerprint equivalence.

The construction and encodings follow [RFC 7748](https://www.rfc-editor.org/rfc/rfc7748.html),
[RFC 8032](https://www.rfc-editor.org/rfc/rfc8032.html),
[RFC 8410](https://www.rfc-editor.org/rfc/rfc8410.html),
[RFC 5639](https://www.rfc-editor.org/rfc/rfc5639.html),
[RFC 8734](https://www.rfc-editor.org/rfc/rfc8734.html), and
[RFC 7366](https://www.rfc-editor.org/rfc/rfc7366.html).

## Local real-wire results

These results concern the local x86_64 development build. They do not substitute
for the two-architecture Actions regression or the complete 72-cell matrix.

| Test | Cases | Local status | Evidence |
| --- | ---: | --- | --- |
| X448/Ed448 OpenSSL interoperability | 22 | Passed | `scripts/test_curve448.py`; `ci-curve448-lab/summary.json` |
| AES-CBC EtM with OpenSSL peers | 29 | Passed | `scripts/test_etm.py`; `ci-etm-lab/summary.json` |
| 3DES-CBC EtM with independent Go origin | 6 | Passed | `scripts/test_etm.py`; `ci-etm-3des-lab/summary.json` |
| Brainpool TLS 1.3 and certificates | 21 | Passed | `scripts/test_brainpool.py` |
| Brainpool curve/digest/version constraints | 3 schemes | Passed | `scripts/test_brainpool_constraints.py` |
| Complete Rust regression | 61 | Passed | 5 unit + 4 Brainpool + 1 CCM + 1 certificate compression + 6 Ed448 + 44 fingerprint tests |
| Ed448 dedicated Rust regression | 6 | Passed | `tests/ed448.rs` |

Formatting and Clippy checks also passed. The final combined Python regression
passed all 32 test methods (97.856 seconds), including the individual wire cases.
All 18 independent hybrid-group cases also passed. The prepared native backend
digest was `7347e6c521bd15279b2e9945c046ae46b8ff97de1b85b9a1ab04598ce74a6a95`.

The 22 Curve448 cases comprise seven X448 cases and fifteen Ed448 cases:

- X448: TLS 1.2 valid/unoffered cases, and TLS 1.3 valid, retry, all-zero share,
  short share and unoffered cases. Valid cases require actual group `30`, a
  56-byte peer share and completed encrypted HTTP; malformed shares must fail.
- Ed448: Ed448 leaf authentication and an Ed448 CA signing an RSA leaf, under
  both TLS 1.2 and TLS 1.3. Cases cover successful HTTP, altered certificate
  signatures and incorrect hostnames. Ed448 leaf cases additionally require
  rejection when the algorithm is not offered. A TLS 1.2 wire mutation of the
  ServerKeyExchange signature must produce `BAD_SIGNATURE` before HTTP.

The Curve448 fixture uses independent OpenSSL clients and origins with isolated,
synthetic test certificates. Valid requests verify rewritten A authority,
unchanged B Cookie, binary response bytes, Cookie Domain and Location rewriting.
The targeted client configuration forces the capability under test; the matrix
clients' default implementations and settings are unchanged.

The 29 OpenSSL EtM cases cover four CBC suites (AES-128/SHA-1,
AES-256/SHA-1, AES-128/SHA-256 and AES-256/SHA-384), each with valid HTTP plus
IV, MAC, ciphertext, truncation and authenticated-invalid-padding cases. Five
controls cover no offer, server decline, AEAD selection and two unsolicited
extension responses. The padding case recomputes the correct MAC after changing
padding, so successful MAC rejection alone cannot satisfy that test. Valid
cases transfer multiple TLS records and two HTTP exchanges on one connection.

The additional six 3DES cases force `TLS_RSA_WITH_3DES_EDE_CBC_SHA` (`0x000a`).
The origin is a small independent Go TLS-record fixture using Go cryptographic
primitives; it verifies the actual client Finished and HTTP, then sends a valid
or deliberately malformed authenticated response. **Its C++ client of B links
the same patched backend as B**, so client and bridge are not independent of
each other in these six cases. The Go origin supplies independent evidence for
B's upstream record construction. This is not a claim of production-server
coverage or of independent coverage for every 3DES key-exchange variant. The
system OpenSSL lacks the required 3DES suites; the test does not reduce its
security level or modify the matrix clients to work around that limitation.

EtM corruption cases modify **server application responses after the handshake**.
A valid HTTP request may already have reached A. The required rejection is a
record-authentication/padding error with no corrupted HTTP 200 delivered to the
client, not prevention or rollback of an already valid request. Unsolicited
extension cases instead fail during ServerHello, before HTTP reaches A.

Brainpool's targeted peer is a checksum-pinned OpenSSL 3.5.8 CLI built by
`scripts/prepare_test_openssl.py`. It is invoked by absolute path, without
replacing the system OpenSSL, changing PATH, or changing any matrix client.
Each of the three curves passed seven real-wire cases: valid, altered
certificate and incorrect hostname for both leaf authentication and CA
signatures, plus an unoffered-scheme leaf case. A successful leaf case must
observe the actual CertificateVerify scheme as well as encrypted HTTP.

## Primitive, encoding and policy regression

`src/crypto_x448.rs` includes RFC 7748 known-answer tests and rejection/encoding
checks. `tests/ed448.rs` checks independent RFC 8032 public-key/signature vectors
through both Rust and native EVP, and rejects altered messages/signatures,
noncanonical points/scalars, wrong lengths, Ed448ph and nonempty contexts. Weak
public-key tests first demonstrate that the raw cofactored equation accepts a
forged signature for an identity/low-order key, then require the provider and
native EVP to reject it. SPKI tests check the OID, absent parameters, exact key
length and bit-string encoding. An isolated child process proves an unregistered
provider cannot verify a valid signature; other tests prohibit provider
replacement and signing.

`tests/brainpool.rs` uses RFC 8734 public-point/shared-secret vectors and checks
EC/DER and ECDSA behavior. SPKI tests reject unknown/t1 OIDs, absent/NULL/explicit
curve parameters, infinity and truncated/off-curve points. The native Brainpool constraint fixture operates on
actual TLS signature-verification objects for all three schemes, checking
wrong curves, NIST aliases, wrong digests, signature/transcript corruption and
TLS 1.1/1.2 rejection. Internal fixture results supplement independent handshakes;
they do not replace them. The Rust wire tests check offered-subsequence ordering
and absence of injected algorithms/extensions in unrelated profiles.

## Preserved acceptance rules

Only B's implementation and isolated test infrastructure change. Production A,
client implementations and real user traffic are untouched. Tests use temporary
synthetic certificates and, where necessary, temporary synthetic key logs;
these are not retained in result summaries or committed.

Certificate and hostname verification remain enabled. No unsupported algorithm
is advertised solely to match a vector. No fingerprint ignore list is expanded,
and no strict gate is removed or bypassed. The independent direct-1/direct-2/
bridge comparisons and same-connection ingress/egress comparisons remain intact.
A naturally unstable direct baseline remains inconclusive instead of becoming
a match. Capability-test success is not the matrix's `fingerprint_pass` result.

## Remaining capability boundaries

The previous completed run #48 identified the following additional gaps. The
completed matrix below measures their current affected-cell counts; old counts
are not copied into this run's result.

| Gap | Remaining behavior and required work |
| --- | --- |
| Ten ARIA suites: `c050/c051/c052/c053/c056/c057/c05c/c05d/c060/c061` | These remain unsupported. They require a real ARIA implementation, TLS 1.2 GCM record integration, successful independent negotiation and corruption/negative tests before their IDs can be retained. |
| `status_request_v2`, extension `17` | Not implemented. Existing `status_request` support is not equivalent to the multiple-certificate status protocol. Safe support requires parsing/processing the negotiated response and its certificate associations, plus negative tests; copying the request bytes alone is insufficient. |
| EC point formats `1` and `2` | The current TLS key-share path accepts and emits uncompressed format `0`. Compressed prime-field and compressed binary-field negotiation are not added. General EC parsing or Brainpool signature support does not establish either TLS capability; format `2` also needs the relevant binary-field curve support. |

See [RFC 6209](https://www.rfc-editor.org/rfc/rfc6209.html) for ARIA TLS suites,
[RFC 6961](https://www.rfc-editor.org/rfc/rfc6961.html) for status_request_v2,
and [RFC 4492](https://www.rfc-editor.org/rfc/rfc4492.html) for the original EC
point-format values. These are separate implementation gaps, not new comparison
exemptions. TLS session state, record framing, extension-order instability and
network-dependent TCP behavior also prevent extrapolating these local capability
results to equality of all client fingerprints.

## Completed GitHub Actions #49

Both native regression jobs succeeded. Each architecture passed 61 Rust tests,
32 Python test methods, and all 18 independent hybrid-group cases. Each also
passed 22 Curve448, 21 Brainpool and 35 EtM real-wire cases: **78 new capability
cases per architecture**, contained in the Python methods rather than added to
the matrix cell count. All three internal Brainpool constraint profiles and the
existing CCM/DSA/certificate rejection regressions passed. Formatting, Clippy,
HTTPS lab and TCP capture lab steps succeeded.

All eight native matrix environments ran all nine default client/protocol
combinations. The strict summary received all 72 unique rows and ran with
`ENFORCE: true`. Both regression jobs succeeded; all eight fingerprint jobs and
the summary gate failed with exit code 1 because differences or unstable
baselines remain. No infrastructure error, missing environment or missing layer
is being counted as a pass.

| Measure | Run #48 | Run #49 |
| --- | ---: | ---: |
| Full match | 8 | 8 |
| Mismatch with stable baseline | 40 | 40 |
| Inconclusive direct baseline | 24 | 24 |
| Direct/bridge TLS MATCH | 16/72 | 16/72 |
| Direct/bridge HTTP MATCH | 64/72 | 65/72 |
| Direct/bridge TCP MATCH | 72/72 | 72/72 |
| Same-connection TLS MATCH | 32/72 | 32/72 |
| Same-connection HTTP MATCH | 72/72 | 72/72 |

The one-cell HTTP difference occurs in the unstable Go HTTP/2 baseline group;
this increment does not claim an HTTP implementation improvement. The 24
inconclusive rows are the 16 Rust and eight Go HTTP/2 combinations. Stable TLS
mismatches remain in eight Python, 16 Node and 16 Java combinations. The eight
Go HTTP/1.1 combinations remain full matches.

## Measured capability improvement

Each identifier below was present in direct-1, direct-2, inbound, outbound and
bridged samples for every listed offering cell. The entire corresponding
inbound/outbound ordered vector also matched in those cells, so these are not
mere set-membership results. This still does not imply the whole ClientHello or
TLS fingerprint matched.

| Field / identifier | Offering cells | Removed by B in #48 | Retained by B in #49 |
| --- | ---: | ---: | ---: |
| X448 group `30` | 40 | 40 | 40/40 |
| Ed448 signature `0x0808` | 40 | 40 | 40/40 |
| Ed448 certificate signature `0x0808` | 16 | 16 | 16/16 |
| Brainpool `0x081a` | 12 | 12 | 12/12 |
| Brainpool `0x081b` | 12 | 12 | 12/12 |
| Brainpool `0x081c` | 12 | 12 | 12/12 |
| Encrypt-then-MAC extension `22` | 24 | 24 | 24/24 |

X448/Ed448 offers were Python 8, Node 16 and Java 16; Ed448 certificate offers
were Java 16. Each Brainpool scheme was offered by Python 4 and Node 8. EtM was
offered by Python 8 and Node 16. No unsupported-group/signature/EtM limitation
remains in these 72 logged cases. This does not claim support for every possible
algorithm outside the observed offers.

Across all 72 same-connection samples, complete ordered group, handshake
signature and certificate-signature vectors now match 72/72. Extension vectors
match 56/72, cipher vectors 56/72 and point-format vectors 48/72. The remaining
logged omissions are:

- Point formats `1` and `2`: 24 cells each, covering Python 8 and Node 16.
- `status_request_v2` extension `17`: Java 16 cells.
- ARIA suite IDs `c050/c051/c052/c053/c05c/c05d/c060/c061`: Node 16 cells each;
  `c056/c057`: Node 12 cells each.

These omissions overlap within cells. Rust's independent TLS extension order
still varies despite identical same-connection vectors. Seven Go HTTP/2
independent comparisons differ in HTTP while all eight direct baselines remain
unstable; their same-connection HTTP comparisons match. The public capability
log is not sufficient to identify the exact HTTP frame/HPACK field involved,
so this record does not invent a cause or change normalization.

## Evidence and reproducibility

- [Code commit](https://github.com/csbxd/fingerprint-bridge/commit/81759cf98a8c43e9ed22a51e7e921ba390808741)
- [Actions #49](https://github.com/csbxd/fingerprint-bridge/actions/runs/35763709003)
- [Machine-readable 72-row report and regression cases](TLS-CAPABILITY-MATRIX-49.json)
- [72 measured capability records, five samples per record](TLS-CAPABILITIES-49.jsonl)

The machine report retains all job conclusions and eleven artifact metadata
records: eight matrix artifacts, two regression artifacts and the summary.
The raw ClientHello/PCAP artifacts were generated by CI. They were **not
independently downloaded and re-audited locally in this run**; the archived
SHA256 digests are GitHub-reported metadata, not locally verified hashes.
Logged capability vectors contain public algorithm IDs and share lengths, not
private keys, key logs, real Cookie values or user traffic. They supplement the
strict runner comparisons without replacing raw packet re-audit.

Remaining protocol, algorithm and network boundaries above remain explicit.
Neither the successful capability tests nor preservation of all measured
signature/group lists is a claim that all fingerprints are identical.
