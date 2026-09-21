# TLS backend and same-request evidence validation

Code: `0d4ad8055b358ac43d665005eef67b7a4053dba1`.
[Actions run](https://github.com/csbxd/fingerprint-bridge/actions/runs/35640256861).

## Change

The pinned backend patch serializes configured, supported cipher suites in the
observed order (including mixed TLS 1.3/older suites and SCSV). It handles the
TLS 1.2 renegotiation_info response signaled by SCSV, without adding that extension
to the outgoing ClientHello. It preserves padding absence/presence on the first
ClientHello. Changes occur before transcript hashing, with fresh keys and normal
certificate/Finished verification. Unsupported algorithms are not advertised.

The opt-in plaintext capture records the same connection at B before and after
HTTP rewriting. An independent Python HPACK decoder/parser checks field order,
representation/index choices, Huffman flags, controls and frame layout. Only
permitted authority/origin/referer value bytes and necessary encoded lengths are
normalized. The independent direct-to-A comparisons and strict verdicts remain.

## Local validation

- 32 Rust tests (1 unit + 31 integration), rustfmt and strict Clippy passed.
- 17 Python regression tests passed, including a real Rust/rustls client -> B ->
  TLS-1.2-only OpenSSL origin handshake with SCSV and secure renegotiation_info.
- Independent HTTP/1.1 and HTTP/2 lab passed, including hostname/CA/strict-TLS
  rejection and response Cookie/Location rewriting.
- Native 9-case language run: HTTP matched for the same connection in all 9.
  Independent direct-vs-bridged HTTP matched 8/9; Go HTTP/2 differed across
  independent connections while its same-connection representation matched.
- Rust HTTP/1.1 and HTTP/2 TLS matched at B input/output, including SCSV.
  Independent Rust extension order remains naturally randomized across connections.
- Other local TLS profiles still expose unsupported suites, groups, signatures
  and extensions. Go 1.27 cipher ordering is now preserved, but its additional
  PQ groups/signatures and signature_algorithms_cert remain unsupported.
- Local environment cannot capture SYN packets. Its 9 matrix verdicts correctly
  remain missing-evidence; they are not full fingerprint passes.

## Cross-platform validation

Run #9 exposed an artifact ownership error: container-created mode-0600 diagnostic
files were unreadable to the host upload step. Run #10 adds an always-run ownership
transfer for this synthetic lab directory; file permissions remain private.
The complete matrix is rerun; incomplete #9 artifacts are not used as acceptance.

Run #10 completed all 72 cells with all 10 artifacts (8 environments, general
regression evidence, aggregated report). No missing environment/case/evidence or
infrastructure/runtime error remained. The general test job passed, including
Rust/Python regressions, independent HTTPS and SYN-capture labs.

| Measurement | Matches | Differences / other |
| --- | ---: | --- |
| Independent direct vs bridged TLS | 8/72 | 64 differences |
| Independent direct vs bridged HTTP | 64/72 | 8 Go HTTP/2 differences |
| Independent direct vs bridged TCP SYN | 72/72 | same runner kernel, loopback only |
| Same connection B input/output TLS | 24/72 | 48 differences |
| Same connection B input/output HTTP | 72/72 | 0 differences |
| Strict whole-case verdict | 4/72 | 44 mismatch, 24 inconclusive-baseline |

The four complete matches are Go HTTP/1.1 on Ubuntu 24.04 and Debian 13, on both
amd64 and arm64. Their Go HTTP/2 TLS also matches, but independent HTTP header
order/HPACK differs; all eight Go HTTP/2 direct baselines are unstable in this
run. The same-request HTTP checks pass for every Go case without sorting the
client headers or dropping the independent differences.

The 24 paired TLS matches are all 16 Rust cases plus 8 Go cases on Ubuntu/Debian.
Rust still has randomized extension order across independent connections, so
its 16 whole-case verdicts remain inconclusive. Fedora/Alpine Go and all Python,
Node and Java TLS profiles still differ. Missing backend capabilities remain
visible; this is not all-client or all-feature equivalence.

Compared with [run #8](https://github.com/csbxd/fingerprint-bridge/actions/runs/35632578610),
independent TLS matches rose from 0 to 8, whole-case matches from 0 to 4, and
independent HTTP remains 64/72. The extra paired columns provide causal evidence
about B without changing the original independent comparison.

[Archived 72-row summary](TLS-BACKEND-MATRIX.json) was transcribed from the linked
Actions rendered summary; full packet/ClientHello/runtime evidence remains in
that run's artifacts. TCP results do not cover cross-OS kernels, arbitrary network
paths, TCP behavior beyond SYN, HTTP/3, browsers, resumption or every TLS feature.
