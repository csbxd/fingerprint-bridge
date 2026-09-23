# Binary-field point format validation

Source: `51a2bc1303bd55b01bece59a4e8df551f4ed87da`.
Actions: [run #65](https://github.com/csbxd/fingerprint-bridge/actions/runs/35823249113).
Completed on 2026-09-23 (UTC).

## Implementation

The bridge now has a real TLS 1.2 `sect283r1` (group 10) ECDHE provider.
This permits preserving an offered `ansiX962_compressed_char2` point format
instead of removing format 2 from `[0, 1, 2]`. Neither format 2 nor group 10
is inserted when the incoming client did not offer it.

The provider uses OpenSSL 3.5.8 source pinned by SHA256
`a8f84a39918ec6415ce765d9b429d313ba97b8143169c172e734b9514464f5b2`.
All static libcrypto definitions and references receive a private symbol
prefix; BoringSSL and provider objects never cross the callback boundary.
Configuration loading, dynamic modules and engines are disabled. The build
checks symbol isolation and caches the result by source, wrapper and tool
configuration. Native Linux x86_64 and ARM64 builds are supported.

Before using an ephemeral private key, point decoding requires the precise
length/prefix, canonical coordinates, a valid curve point, a non-infinite
point and membership in the prime-order subgroup. This last check rejects
both the order-two point and a nontrivial mixed-subgroup point. TLS 1.3
key shares and HRR cannot select this legacy group.

## Real handshake evidence

The independent Go peer uses the system libcrypto, not the bridge's private
provider, and implements TLS record/transcript processing separately.

| Case | Required evidence |
| --- | --- |
| Compressed / uncompressed sect283r1 | Real TLS 1.2 Finished verified; encrypted HTTP; B Cookie retained; Host rewritten to A; client exit 0 |
| Malformed / off-curve / infinity | Alert 47 before ClientKeyExchange or HTTP |
| Order-two / mixed-subgroup | Independently checked invalid subgroup fixture; alert 47 before ClientKeyExchange or HTTP |
| Unoffered format / group | Alert 47, with captured offered vectors proving no implicit capability insertion |
| Corrupt certificate / handshake signature | Certificate/signature verification failure before ClientKeyExchange or HTTP |
| TLS 1.3 HRR selecting group 10 | Alert 47 before a second ClientHello or HTTP |

All 12 cases pass locally. The six existing P-256/P-384/P-521 compressed-point
cases also pass and now observe the complete `[0, 1, 2]` format vector.
Rust tests (66), formatting and clippy pass. The default-Python independent
HTTP/1.1 and HTTP/2 lab passes TLS/HTTP and certificate rejection checks.
The 18 hybrid-group cases and ML-DSA regression also pass locally.

The strict-TLS rejection test formerly depended on format 2 being unsupported.
It now appends an explicit unknown non-GREASE extension 65000 to a test-only
ClientHello, and requires that exact field difference and strict-gate error
before HTTP. A complementary unchanged default-Python request must pass the
strict gate. No matrix client or comparison exemption was changed.

## Matrix result

All 72 cells completed on native x86_64 and ARM64 across Ubuntu 24.04,
Debian 13, Fedora 43 and Alpine 3.23, using unchanged default Python, Node,
Go, Java and Rust clients.

| Strict verdict | Previous complete run #63 | Run #65 |
| --- | ---: | ---: |
| Match | 24 | 48 |
| Stable mismatch | 24 | **0** |
| Independent baseline unstable | 24 | 24 |
| Missing / error | 0 | 0 |

The 24 affected Python/Node cells now contain `[0, 1, 2]` in all five
captures: direct-1, direct-2, B inbound, B outbound, and bridged arrival at A.
No TLS capability limitations are reported in any of the 72 cells.

| Comparison | Matching cells |
| --- | ---: |
| Independent TLS | 56/72 |
| Independent HTTP | 64/72 |
| Independent TCP SYN | 72/72 |
| Same-request B inbound/outbound TLS | 72/72 |
| Same-request B inbound/outbound HTTP | 72/72 |

Both regression jobs succeeded. Each architecture passed 66 Rust tests,
41 Python test methods (including the 12 char2 and six prime compressed-point
cases), and 18 separate hybrid-group cases. Certificate rejection, wrong
hostname, strict positive/negative and privileged TCP labs all passed.

The 24 remaining non-passes are still 16 Rust TLS extension-order/JA3
permutations and eight Go HTTP/2 header/HPACK-order changes between independent
direct connections. These are not converted into passes or ignored. The
matrix jobs and aggregate strict gate therefore deliberately exit 1, and
the overall workflow conclusion is `failure` despite zero stable mismatches.

Machine-readable verdicts, all 72 rows, the 24 affected five-sample point-format
vectors, both architectures' real handshake results, and artifact IDs/digests
are recorded in [CHAR2-MATRIX-65.json](CHAR2-MATRIX-65.json). These are synthetic
loopback/SYN results on distro containers sharing their runner's kernel, not
universal browser or arbitrary network-path TCP equivalence.

## Boundaries and local limitations

This increment implements B-to-A sect283r1 ECDHE. It does not implement
binary-curve ECDSA certificates or other binary curves. The ordinary B-side
acceptor still needs a mutually supported standard group; the capability
probe offers P-256 plus sect283r1, then verifies actual sect283r1 negotiation
on B-to-A. A client offering only group 10 is not certified by these tests.

The local environment lacks raw-socket permission, so its Python
direct-1/direct-2/bridged diagnostic records matching TLS/HTTP but correctly
remains `missing-evidence` for TCP. The first full local Python run also
reported missing javac / an unbuilt ML-DSA peer and a default Python/OpenSSL
cipher list omitting DHE-RSA-ChaCha20. The ML-DSA test passed after building
its existing independent peer. No client defaults were changed to hide the
remaining environment-dependent failures; Actions is the complete gate.

Run #64 was incomplete: Fedora amd64 dependency installation timed out,
leaving 63 real matrix cells and 9 missing cells. This increment excludes
optional Fedora weak desktop packages and bounds mirror stalls; it keeps
the distro's Java/JSSE, Node and other client implementations unchanged.

All traffic, keys and certificates in these tests are synthetic loopback
fixtures. There is no deployment, SSH activity or modification of real A.
