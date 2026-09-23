# Direct-baseline instability validation

Validated source: `af28b4731dd4a6db264bb5e1614f95dba8b0318d`  
GitHub Actions: run `35802831047` (`#63`)

## Diagnostic increment

The 72-cell aggregate report now classifies direct1/direct2 instability without
changing any verdict or comparison rule. The classification is informational:
every affected cell remains `inconclusive-baseline`, and the strict gate still
fails.

Across both native architectures and all four distributions, the 24 unstable
cells split consistently:

| Direct-baseline difference | Cells |
|---|---:|
| Rust TLS extension-order permutation | 16 |
| Go HTTP/2 request-header/HPACK byte ordering | 8 |

The Rust cases contain the same extension multiset but emit it in a different
order on separate direct connections, which also changes the derived JA3
string and digest. The Go HTTP/2 cases change header order and therefore HPACK
bytes between separate direct connections. Neither difference is caused by B.

For all 24 cells, the same-connection comparison across B still matches. This
does not turn them into passes because the independent direct baseline remains
unstable.

## Guardrails

Two regression tests prove that diagnostic classification does not alter the
strict verdict. No field was added to an ignore list, no client default was
changed, and missing or unstable evidence remains non-passing.

Both x86_64 and ARM64 regression jobs passed. Each ran 64 Rust tests, 38 Python
test methods, 18 hybrid-group cases, and six compressed-point cases.

The complete matrix remains 24 matches, 24 stable mismatches, and 24 unstable
baselines. The remaining stable TLS mismatch is still point format `2`
(`ansiX962_compressed_char2`) in 24 Python/Node cells.

Machine-readable counts and artifact identities are recorded in
`test-results/BASELINE-INSTABILITY-MATRIX-63.json`.
