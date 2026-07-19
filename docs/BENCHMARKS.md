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

The following snapshot was collected on 2026-07-19 on an Apple M4 Pro
(14 cores), macOS 26.5, with `rustc 1.99.0-nightly` and optimized benchmark
builds. Ranges are Criterion confidence intervals and are machine-specific.

| Operation | Compact | Balanced | Low latency |
|---|---:|---:|---:|
| Issue, client prove | 26.229–26.304 ms | 17.215–17.308 ms | 16.713–16.759 ms |
| Direct input, client prove | 52.781–53.233 ms | 38.488–38.616 ms | 37.634–37.793 ms |
| Deferred input, client prove | 72.634–72.965 ms | 53.845–54.261 ms | 52.890–53.151 ms |

Balanced issuer-side intervals were:

| Operation | Time |
|---|---:|
| Issue verify + sign | 10.222–10.267 ms |
| Direct-input spend verify + sign | 21.874–21.937 ms |
| Deferred-input spend verify + sign | 29.678–29.767 ms |
| Deferred-return settlement verify + sign | 21.896–21.998 ms |
| Issue, end to end | 28.353–28.622 ms |
| Direct-input direct spend, end to end | 61.261–61.472 ms |
| Deferred-input direct spend, end to end | 84.127–84.347 ms |
| Direct-input deferred-return spend, end to end | 61.169–62.297 ms |

Balanced wire measurements were 3.641–3.651 µs to encode a direct request,
6.375–6.427 µs to decode it, 1.038–1.052 ms to decode and authenticate a
deferred token, and 32.015–32.148 ms to decode an expanded public key and
derive all cached circuit terms.

The default remains Balanced: LowLatency saves only a few percent while nearly
doubling proof size; Compact substantially reduces communication but expands
many more GGM leaves and is materially slower.
