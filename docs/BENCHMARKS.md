# Benchmark methodology and snapshot

Run the statistically sampled suite with:

```text
cargo bench -p vole-act --bench protocol
```

The suite uses Criterion with flat sampling, a one-second warm-up, ten samples,
and a three-second measurement window. It separately measures client proving,
issuer proof verification plus MAYO preimage sampling, end-to-end operations,
and canonical wire codecs. Issuer microbenchmarks use a benchmark-only store
that returns the inserted nullifier record without retaining it; this ensures
every iteration measures verification and signing rather than the exact-retry
fast path.

The following snapshot was collected on 2026-07-19 (post-optimization; see
`docs/IMPLEMENTATION.md`) on an Apple M4 Pro (14 cores), macOS 26.5, with
`rustc 1.99.0-nightly`, via `examples/profile_matrix.rs` (medians of 15).

| Operation (ms) | Compact | Balanced | Low latency |
|---|---:|---:|---:|
| Issue, client prove | 8.78 | 7.81 | 7.73 |
| Issue, issuer verify-and-sign | 3.96 | 2.90 | 2.89 |
| Spend (direct), client prove | 20.17 | 18.68 | 18.85 |
| Spend (direct), issuer verify-and-sign | 7.98 | 6.49 | 6.46 |
| Spend (deferred), client prove | 28.35 | 26.61 | 26.87 |
| Spend (deferred), issuer verify-and-sign | 10.31 | 8.32 | 8.30 |
| Deferred settlement, issuer verify-and-sign | 8.04 | 6.52 | 6.42 |
| Issue, end-to-end | 13.88 | 11.62 | 11.50 |
| Spend (direct), end-to-end | 29.49 | 26.40 | 26.46 |

| Wire size (bytes) | Compact | Balanced | Low latency |
|---|---:|---:|---:|
| Token (either format) | 283 | 283 | 283 |
| Issue request | 29,750 | 55,286 | 106,358 |
| Spend request (direct input) | 52,990 | 101,726 | 199,198 |
| Spend request (deferred input) | 72,574 | 140,894 | 277,534 |
| Issue / spend response | 171 / 179 | 171 / 179 | 171 / 179 |
| Public key (expanded map) | 106,319 | 106,319 | 106,319 |

Numbers are machine-specific single-operation latencies on an idle machine,
not sustained concurrent throughput.
