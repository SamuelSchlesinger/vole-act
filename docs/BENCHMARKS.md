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

## Signer-salted common-wrapper experiment (2026-07-21)

The wire-v2 experiment makes every input prove the common salted wrapper. The
sampled Criterion run measured these central estimates:

Environment: MacBook Pro `Mac16,8`, Apple M4 Pro (14 cores), 48 GiB RAM,
macOS 26.5.2 (`25F84`), `aarch64-apple-darwin`,
`rustc 1.99.0-nightly (d0babd8b6 2026-07-15)`, LLVM 22.1.8, Criterion 0.5.1.
The command was `cargo bench -p vole-act --bench protocol`. Exact Criterion
mean point estimates and 95% confidence intervals are committed in
`research/mayo-assumption-review/design-options/data/criterion-2026-07-21.json`.
That export also preserves the exact measured executable's SHA-256 digest,
the stored-baseline change estimates, and a source-patch fingerprint. The
source fingerprint is SHA-256 over the `git diff --binary` from base commit
`e7cec9fd658c443f2d02e06f98012b358fa2da5f`, with this ordered path scope:
root `Cargo.toml`, `Cargo.lock`; `crates/vole-act/Cargo.toml`,
`benches/protocol.rs`, and all non-test Rust source files changed by this
work; then `crates/voleith/Cargo.toml` and its changed Rust source files.
Post-measurement edits before the export was committed were confined to docs,
tests, and Rust comments and did not change benchmark-compiled behavior.

| Client prove (ms) | Compact | Balanced | Low latency |
|---|---:|---:|---:|
| Issue | 10.04 | 8.59 | 8.61 |
| Spend (direct input) | 31.17 | 28.96 | 28.99 |
| Spend (deferred input) | 31.30 | 28.58 | 29.42 |

For Balanced, issuer verify-and-sign was 3.37 ms for issue, 9.36 ms for a
direct input, 9.22 ms for a deferred input, and 9.26 ms for deferred-return
settlement. Direct, deferred-input, and deferred-return end-to-end Criterion
mean central estimates were 40.74, 39.25, and 39.00 ms respectively.

Criterion's stored-baseline comparison reported a 49–53% direct-input prover
regression across the three profiles, a 44% Balanced direct-input issuer
regression, and a 49% Balanced direct end-to-end regression. Deferred-input
timings did not regress in that comparison. The exact payload comparison is
less machine-sensitive:

| Proof payload (bytes) | Before: direct | Before: deferred | Common wrapper: both |
|---|---:|---:|---:|
| Compact | 52,688 | 72,272 | 72,784 |
| Balanced | 101,232 | 140,400 | 141,424 |
| Low latency | 198,320 | 276,656 | 278,704 |

Thus the direct-input bandwidth cost is about 38–41%, while an old deferred
input grows by only 0.7%. Direct and deferred proofs are now byte-for-byte the
same size for each profile.

| Current wire size (bytes) | Compact | Balanced | Low latency |
|---|---:|---:|---:|
| Token (either marker) | 315 | 315 | 315 |
| Issue request | 29,750 | 55,286 | 106,358 |
| Spend request (either input) | 73,086 | 141,918 | 279,582 |
| Issue / spend response | 203 / 211 | 203 / 211 | 203 / 211 |
| Public key (expanded map) | 106,319 | 106,319 | 106,319 |

The extra 32 response/token bytes are the signer salt. The small proof growth
over the old deferred relation comes from carrying that salt as hidden witness
rather than reusing the public context as wrapper input.

## Historical pre-wrapper snapshot (2026-07-19)

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
