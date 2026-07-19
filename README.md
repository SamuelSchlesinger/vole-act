# VOLE-ACT

VOLE-ACT is a research implementation of post-quantum anonymous credit tokens.
It combines a MAYO trapdoor map with a VOLE-in-the-head proof of token
possession, exact balance arithmetic, a one-time nullifier, and a fresh hidden
balance commitment.

The core operation is deliberately cheap: an ordinary spend consumes either
credential format and returns a direct credential. A separately typed
extension lets the issuer choose a bounded return after verifying the proof;
that extension returns a deferred-return credential and pays for one additional
hidden SHAKE evaluation when the credential is next presented.

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

// Direct -> deferred: reserve 35, then return 10 after verification.
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
wire decoders both reject cross-mode use.

## Persistence

The default issuer uses `MemoryNullifierStore`, which is useful for examples
and tests but is not crash-safe. Production integration must implement
`NullifierStore::insert_if_absent` as one linearizable database operation that
returns the durably stored winning retry record. The issuer signs first but
does not return that signature unless the corresponding nullifier record is
durable. Restoring an older store snapshot resurrects spent tokens and is a
protocol failure, so backups and failover also need monotonic/rollback-safe
recovery.

Issuer restoration therefore has no empty-store shortcut:

```text
Issuer::from_key_bytes_with_store(key_bytes, recovered_durable_store)
```

Canonical encodings are available through `to_bytes`/`from_bytes` for public
keys, issuer keys, proofs, issue/spend messages, client pending states, tokens,
and retry records. Token, pending-state, response, and issuer-key encodings are
secret material and need authenticated encryption at rest.

## Security boundary

- The MAYO component is used as a trapdoor preimage relation on externally
  chosen targets. Fiscal soundness therefore needs a one-more-preimage
  assumption for the MAYO map; ordinary MAYO EUF-CMA security is not the right
  assumption.
- Four-round Keccak groups have degree 16. The generalized assertion check has
  statistical error at most `17 / 2^128` before computational commitment and
  Fiat-Shamir terms—about 123.9 bits, not a literal 128-bit bound.
- Optional deferred returns reveal their mode through proof shape and size and
  can partition the anonymity set.
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
