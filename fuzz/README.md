# Fuzzing VOLE-ACT

The fuzz package separates cheap structural coverage from expensive real
protocol executions, so parser throughput does not hide arithmetic and state
machine coverage.

| Target | Main invariants |
|---|---|
| `wire_decode` | All public decoders are panic-free, successful decodes are canonical, and ACT type tags are unambiguous |
| `proof_verify` | Valid-adjacent proof mutations are canonical or rejected, modified proofs do not verify, and statements remain transcript-bound |
| `protocol_artifacts` | Valid and mutated issue/spend/pending/token encodings remain uniquely typed across both credential kinds and settlement modes |
| `corner_cases` | GF(16)/GF(2^128) laws, reduction carries, bit padding, GGM boundaries, VOLE reconstruction, invalid geometry, and MAYO input dimensions |
| `protocol_state` | Full-width balances, issue/spend/deferred transitions, over-spends, invalid returns, exact retries, cross-mode nullifier conflicts, and recovery codecs |

Install `cargo-fuzz`, then run from the repository root:

```text
cargo fuzz run wire_decode -- -max_total_time=60 -max_len=1048576 -dict=fuzz/dictionaries/wire.dict
cargo fuzz run proof_verify -- -max_total_time=60 -max_len=2048
cargo fuzz run protocol_artifacts -- -max_total_time=60 -max_len=2048
cargo fuzz run corner_cases -- -max_total_time=300 -max_len=256
cargo fuzz run protocol_state -- -max_total_time=600 -max_len=64
```

ASan is enabled by default. The first four targets build valid fixtures once
or work without cryptographic setup. `protocol_state` intentionally performs
real issuance, proof generation, verification, preimage sampling, and token
authentication per input, so roughly one execution per second under ASan can
be normal on a laptop.

Generated corpora and crash artifacts are ignored. A confirmed failure should
be minimized, fixed, and promoted to a deterministic unit test before the
temporary artifact is removed. The initial campaign found an invalid-parameter
allocation attack in `split_delta`; `vole::tests::invalid_public_parameters_fail_without_panicking`
is the permanent regression.
