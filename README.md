# VOLE-ACT

VOLE-ACT is a research implementation of a post-quantum candidate for
anonymous credit tokens.
It combines a MAYO trapdoor map with a VOLE-in-the-head proof of token
possession, exact balance arithmetic, a one-time nullifier, and a fresh hidden
balance commitment.

Every credential authenticates a signer-salted hash of its hidden balance
commitment and return amount. An ordinary spend uses return zero; a separately
typed extension lets the issuer supply a bounded return after the client fixes
its proved request and before signer-salt generation. Both input formats
therefore use the same three-hidden-SHAKE relation.

This is a cryptographic research prototype. It has not received an independent
audit, its custom proof composition does not yet have a complete reduction, and
it is not ready to protect real value.

## Quick start

```rust
use mayo::Mayo2;
use rand::rngs::OsRng;
use vole_act::Issuer;

let mut rng = OsRng;
let mut issuer = Issuer::<Mayo2>::generate(b"example/credits/epoch-1", &mut rng);
let public = issuer.public_key().clone();

let (pending, request) = public.prepare_issue(100, &mut rng)?;
let response = issuer.issue(&request, 100, &mut rng)?;
let token = pending.finish(&public, &request, &response)?;

// Direct -> direct: charge 25.
let (pending, request) = token.prepare_spend(&public, 25, &mut rng)?;
let response = issuer.spend(&request, &mut rng)?;
let token = pending.finish(&public, &request, &response)?;
assert_eq!(token.balance(), 75);

// Direct -> deferred: reserve 35, then let the issuer supply return 10.
let (pending, request) = token
    .prepare_spend_with_deferred_return(&public, 35, &mut rng)?;
let response = issuer.spend_with_deferred_return(&request, 10, &mut rng)?;
let token = pending.finish(&public, &request, &response)?;
assert_eq!(token.balance(), 50);

// An ordinary spend folds the old return into the balance and normalizes.
let (pending, request) = token.prepare_spend(&public, 10, &mut rng)?;
let response = issuer.spend(&request, &mut rng)?;
let token = pending.finish(&public, &request, &response)?;
assert_eq!(token.balance(), 40);
# Ok::<(), vole_act::Error>(())
```

The four legal transitions are:

| Input | `spend` | `spend_with_deferred_return` |
|---|---|---|
| Direct | Direct | Deferred return |
| Deferred return | Direct | Deferred return |

Request, response, pending-state, and token encodings carry explicit version,
MAYO-parameter, input-kind, and settlement tags. The Rust types and canonical
wire decoders reject unmodified artifacts carrying the wrong tag. The header
tag is not independently authenticated by the codec, however: retagged bodies
with identical layouts can parse. Proof statements and request digests provide
the end-to-end mode binding. Zero-return token and response aliases are
intentional and fiscally inert because they have the same authenticated target,
effective balance, and nullifier lineage.

## Persistence

The default issuer uses `MemoryNullifierStore`, which is useful for examples
and tests but is not crash-safe. Production integration must implement
`NullifierStore::insert_if_absent` as one linearizable database operation that
returns the durably stored winning retry record. The issuer signs first but
does not return that signature unless the corresponding nullifier record is
durable. Restoring an older store snapshot resurrects spent tokens and is a
protocol failure, so backups and failover also need monotonic/rollback-safe
recovery.

Multi-replica security requires losing salted credentials to stay out of
responses, logs, telemetry, and audit tables. The crate tests atomic
winner/replay behavior. Because first arrival may correlate with a variable
number of sampler attempts, the current paper-level reduction requires
response-oblivious winner selection. Merely counting every candidate does not
yet simulate that timing trace; without such scheduling, a separate
race-leakage lemma remains open.

Issuer restoration therefore has no empty-store shortcut:

```text
Issuer::from_key_bytes_with_store(key_bytes, recovered_durable_store)
```

Canonical encodings are available through `to_bytes`/`from_bytes` for public
keys, issuer keys, proofs, issue/spend messages, client pending states, tokens,
and retry records. Token, pending-state, response, and issuer-key encodings are
secret material and need authenticated encryption at rest.

Issuance is deliberately stateless in this crate. A service must bind
authorization, durable charging, idempotency, and first response publication
into one logical transaction. An ambiguous retry under the same external
idempotency key must replay the recorded response without signing or charging
again. Blindly retrying `Issuer::issue` creates another valid salted
authenticator; over the same base opening it remains an alternative for one
nullifier lineage, not another spendable credit.

## Security boundary

- The issuer chooses a fresh 256-bit salt only after accepting a request and
  signs `SHAKE256(commitment || return || salt)`. In the random-oracle model,
  this restores the ordinary MAYO proof shape: signing points can be
  programmed from public-map samples, and an unsigned output is handled by
  the usual OV plus Multi-Target Whipped MQ assumptions rather than a
  specialized adaptive one-more-preimage assumption. A paper-level game plan
  for that adaptation is recorded under
  `research/mayo-assumption-review/reduction/`; completing, formalizing, and
  independently reviewing it remains an explicit proof obligation.
- The local MAYO sampler follows Algorithm 7's 256-attempt cap. The published
  rank-failure bound averages over key generation and a fresh attempt; by
  itself it does not justify raising that bound to the 256th power for one
  reused key. A per-key tail/completeness argument remains part of the exact
  wrapper proof obligation.
- Four-round Keccak groups have degree 16. The generalized assertion check has
  statistical error at most `17 / 2^128` before computational commitment and
  Fiat-Shamir terms—about 123.9 bits, not a literal 128-bit bound.
- Input-kind tags remain public protocol metadata, but direct and deferred
  inputs now have the same circuit/proof size; proof length no longer reveals
  which credential representation was presented.
- The issuer-side MAYO solver uses a fixed-schedule masked elimination routine,
  and long-lived secret state is zeroized on drop. The complete prover has not
  undergone a constant-time audit.
- MAYO's NIST category labels do not transfer to this composition. MAYO1 and
  MAYO2 are both category-1 candidate parameter sets; VOLE-ACT itself has no
  NIST classification.

See [the construction](docs/DESIGN.md) for the formal protocol and
[the adversarial review](docs/SECURITY.md) for attack attempts, concrete
bounds, fixed findings, and unresolved blockers.

## Validation

```text
cargo test --workspace --locked
cargo clippy --workspace --all-targets --all-features -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps
cargo deny check
cargo bench -p vole-act --bench protocol
cargo test --release -p vole-act benchmark_profiles -- --ignored --nocapture
```

The Criterion suite is the reproducible performance harness. The ignored test
is a quick one-sample profile snapshot useful while iterating.

## Fuzzing

Five `cargo-fuzz` targets cover raw and valid-adjacent wire inputs, proof
verification, typed artifact separation, generic algebra/parameter corner
cases, and the complete protocol state machine. See [fuzz/README.md](fuzz/README.md)
for target invariants and campaign budgets.
