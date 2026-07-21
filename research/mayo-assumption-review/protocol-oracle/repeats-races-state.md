# Repeats, failures, races, and state scope

[Back to the protocol-oracle index](index.md)

## Repeat matrix

The final MAYO target is `Y(C,t,zeta)`, not `C`. That one substitution changes
the repeat analysis.

| Situation | New salt / `SPre`? | Client-visible result |
|---|---|---|
| Exact issuance request repeated after acceptance | Yes / yes. | A fresh `(zeta,Y,signature)` on each successful call, except negligible collision events. |
| Different valid issuance proofs for the same `(b,C)` | Yes / yes. | The proof bytes do not key any cache; every accepted call receives a fresh salted target. |
| Exact ordinary-spend request after durable success | No / no. | Stored `(signature,zeta)` is replayed exactly. |
| Exact deferred request after durable success, with any newly supplied return | No / no. | Stored `(return,signature,zeta)` is replayed exactly. |
| Different request bytes under an already consumed nullifier | No / no in the sequential case. | `NullifierAlreadySpent` (or a mode mismatch error for a same-digest record of the other typed mode). |
| Distinct accepted nullifiers producing the same base `C'` and return | Yes / yes for each. | Normally different salts, targets, and signatures. They may still describe one output lineage if `C'` came from the same opening. |
| Invalid issue/spend proof | No / no. | Rejected before signer RNG is touched. |
| First deferred call with `return > maximum_spend` | No / no. | Rejected before proof verification and signing. |

The source order supporting the matrix is
[`issuer.rs:148-239`](../../../crates/vole-act/src/protocol/issuer.rs#L148-L239).
Exact retry records carry the salt as well as the signature and optional return
([`store.rs:35-54`](../../../crates/vole-act/src/protocol/store.rs#L35-L54),
[`store.rs:100-164`](../../../crates/vole-act/src/protocol/store.rs#L100-L164)).

“Fresh” here means the issuer draws a uniform 256-bit salt from a healthy,
non-reused caller-supplied CSPRNG. A repeated salt does not automatically imply
a repeated target if `C` or `t` changed; conversely, different wrapper inputs
can collide in the truncated SHAKE output. The reduction must charge these as
salt-guessing/collision or random-oracle collision events rather than call them
impossible.

## Why issuance resampling is now different

Issuance remains intentionally stateless. The same request can therefore
produce arbitrarily many valid credentials. In the old bare-target design this
meant arbitrarily many `SPre(sk,C)` samples on one adversary-fixed target. In
the present design it means one sample for each independently salted target:

```text
same C, accepted twice
  -> zeta_1, zeta_2
  -> Y(C,0,zeta_1), Y(C,0,zeta_2)
  -> normally two different ordinary MAYO targets
```

The implementation test establishes the concrete first two arrows and verifies
both resulting preimages
([`protocol/tests.rs`](../../../crates/vole-act/src/protocol/tests.rs)).
No target-refusal table or issuance cache is needed for this property. Repeated
issuance still has fiscal authorization semantics outside the crate, and all
responses over the same opening retain one future nullifier.

## Concurrency

The `NullifierStore` contract models replicas sharing one durable database.
`insert_if_absent` must be linearizable and return the durably stored winner;
the issuer returns nothing before that operation succeeds
([`store.rs:167-185`](../../../crates/vole-act/src/protocol/store.rs#L167-L185)).
If two replicas both observe `Store[N] = empty`, signing can occur on both
before either insertion wins.

For the reduction to normalize that execution to one visible signing sample,
the store/scheduler must not choose a winner by inspecting candidate bytes or
other secret-dependent response properties, and losing candidates must remain
confidential from callers, logs, telemetry, audit tables, and operators.
Arrival order can otherwise depend on the variable number of internal sampler
attempts. Merely counting and coupling every computed candidate does not
simulate which one becomes the visible first-arrival winner. The candidate
proof therefore requires response-oblivious winner selection to normalize the
execution to one visible sample; without it, a separate race/timing leakage
lemma remains open. `Q_try` still counts all sampler invocations for the
bounded-sampler failure term.

### Same ordinary request

Each replica verifies, independently samples `zeta_i`, computes a generally
different `Y(C',0,zeta_i)`, and obtains `sigma_i`. One complete
`(digest,direct,sigma_i,zeta_i)` record wins. Both callers receive the winning
signature and salt; the losing salt, target, and preimage are withheld
([`issuer.rs:190-203`](../../../crates/vole-act/src/protocol/issuer.rs#L190-L203),
[`issuer.rs:241-257`](../../../crates/vole-act/src/protocol/issuer.rs#L241-L257)).

This corrects a subtle old description: concurrent replicas no longer sample
two preimages of the *same* target merely because their requests are identical.
They sample two salted target/preimage candidates and publish only the durable
winner.

### Different requests under the same nullifier

Both replicas may verify and sign their respective fresh salted targets. One
record wins; the other caller compares the returned winning digest with its own
and gets `NullifierAlreadySpent`. Its candidate remains secret
([`issuer.rs:195-204`](../../../crates/vole-act/src/protocol/issuer.rs#L195-L204),
[`issuer.rs:241-279`](../../../crates/vole-act/src/protocol/issuer.rs#L241-L279)).

### Same deferred request, different return choices

The request digest is the same because the issuer's return is out of band.
Each replica chooses a salt and signs its own `Y(C',t_i,zeta_i)`. The durable
record fixes one `(t_i,sigma_i,zeta_i)` triple, which both callers receive; the
losing triple is withheld. This is why an exact retry's current return argument
cannot override the stored return.

The deterministic integration test forces two restored replicas through the
empty lookup concurrently and checks all three cases above: byte-identical
winner replay for an ordinary request, one success plus one double-spend error
for conflicting requests, and one byte-identical deferred winner despite
different proposed returns
([`tests.rs`](../../../crates/vole-act/src/protocol/tests.rs)).

### Concurrent issuance

`issue` has no store boundary. Concurrent accepted calls with independent RNGs
return all of their independently salted credentials
([`issuer.rs:148-179`](../../../crates/vole-act/src/protocol/issuer.rs#L148-L179)).
Unlike a spend race, there is no losing candidate because issuance consumes no
input nullifier.

## Three discarded computations

These events have different proof-model consequences:

1. **Internal MAYO retry.** `SPre` rejects an unsuitable sampled linear system
   and tries again; no valid preimage exists yet.
2. **Valid losing race candidate.** A replica has a valid salted preimage but
   returns the stored winner instead.
3. **Valid candidate followed by storage failure.** The issuer propagates a
   storage error and releases no response.

Only successful returned responses belong to the adversary-visible protocol
oracle. A constant-time/leakage model may still need to account for every
trapdoor computation. Likewise, a compromised database or log that exposes a
losing candidate would violate the oracle reconstructed here.

## State scope and lifetime

The store key is only the 256-bit input nullifier. Its value records an exact
typed request digest and the winning response; it has no output-target index
([`store.rs:12-16`](../../../crates/vole-act/src/protocol/store.rs#L12-L16),
[`store.rs:175-185`](../../../crates/vole-act/src/protocol/store.rs#L175-L185)).
The common signer salt removes the earlier motivation for a global
one-response-per-target table. The security-critical state rule that remains is
monotonic nullifier retention: for as long as a token under a trapdoor remains
spendable, restoration and failover must preserve every consumed nullifier
([`issuer.rs:80-117`](../../../crates/vole-act/src/protocol/issuer.rs#L80-L117)).

The context includes the application key-epoch label and actual MAYO public
map, but the library does not implement epoch rotation or garbage collection
([`public_key.rs:40-58`](../../../crates/vole-act/src/protocol/public_key.rs#L40-L58),
[`spend.rs:626-644`](../../../crates/vole-act/src/protocol/spend.rs#L626-L644)).
The deployment must determine when an old key can no longer receive spend
requests before its nullifier state can be retired.

## Wire and transcript transition

Salt is now canonical state, not ephemeral metadata: it appears in issue
responses, spend responses, tokens, and retry records, and client completion
authenticates it. These artifacts use wire version 2
([`issue.rs:180-202`](../../../crates/vole-act/src/protocol/issue.rs#L180-L202),
[`spend.rs:375-417`](../../../crates/vole-act/src/protocol/spend.rs#L375-L417),
[`wire.rs:1-10`](../../../crates/vole-act/src/wire.rs#L1-L10)). Context,
statement, and request-digest domains moved to version 5. Old serialized
artifacts and old proofs are deliberately not accepted as current artifacts;
this is a protocol transition, not a backward-compatible implementation detail.

[Next: independent lineages](lineage-accounting.md)
