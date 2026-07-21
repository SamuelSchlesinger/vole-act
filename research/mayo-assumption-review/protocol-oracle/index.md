# The exact signer-salted VOLE-ACT oracle

[Back to the corpus index](../index.md)

This branch records what the current Rust worktree actually asks the MAYO
trapdoor to do. It is intentionally narrower than the security reduction: the
goal here is to get the protocol oracle, retry boundary, and accounting objects
exactly right before deciding which MAYO problem supports them.

## Bottom line

The implementation no longer asks MAYO to invert the client-provided
credential commitment. Every successful issuance or new spend response uses a
common signer-salted target

```text
C(ctx,k,b,rho) = first 4m bits of
                 SHAKE256("VOLE-ACT/credential/v2" || ctx || k || enc64(b) || rho)

Y(C,t,zeta)    = first 4m bits of
                 SHAKE256("VOLE-ACT/signed/v3" || pack16(C) || enc64(t) || zeta)
```

where `zeta` is a uniform 256-bit salt sampled by the issuer *after* the
request proof verifies. Direct settlement uses `t = 0`; deferred settlement
uses the issuer-selected return. The code for the wrapper is
[`circuit.rs:139-168`](../../../crates/vole-act/src/circuit.rs#L139-L168), and
the proof-before-salt ordering is literal in all three issuer paths
([`issuer.rs:148-179`](../../../crates/vole-act/src/protocol/issuer.rs#L148-L179),
[`issuer.rs:182-239`](../../../crates/vole-act/src/protocol/issuer.rs#L182-L239),
[`issuer.rs:291-302`](../../../crates/vole-act/src/protocol/issuer.rs#L291-L302)).

That distinction is the intellectual center of the change:

```text
old shape:  client chooses proved C  ----> issuer inverts C
new shape:  client chooses proved C
            issuer accepts proof
            issuer samples zeta
            issuer computes Y(C,t,zeta) -> issuer inverts Y
```

The proof still matters. It certifies that the base commitment `C` has the
right credential opening and balance. It does not and cannot certify the final
`Y`, because `zeta` does not exist until after verification; instead, the
issuer computes `Y` itself from the proved `C`, its bounded return decision,
and its own salt. This is the mechanism intended to put the fiscal argument
back on the ordinary MAYO route: except for salt guessing/collision and
random-oracle collision events, each newly accepted operation reaches a fresh
hash point chosen only after the adversary has fixed the request. The intended
argument is documented in
[DESIGN fiscal soundness](../../../docs/DESIGN.md#71-fiscal-soundness-sketch) and its still-open
reduction obligation in
[SECURITY B2](../../../docs/SECURITY.md#b2-the-ordinary-mayo-reduction-is-incomplete-for-the-exact-protocol-high).

This is stronger than merely saying “we prove Keccak anyway.” Proving that `C`
is a hash output restricts the client's language of commitments, but by itself
does not stop an exact request from asking the signer to sample again on the
same `C`. The signer salt is what changes every accepted non-retry call into a
new final MAYO target. Under the earlier bare-target behavior, using a
one-more-style problem was therefore a defensible conservative response to the
oracle the code exposed; it was not established as mathematically necessary.
Under the present salted behavior, retaining that specialized problem as the
claimed foundation would be unnecessary unless the ordinary-MAYO proof attempt
fails for some other reason.

## The three calls

| Call | What the proof fixes | What is signed after acceptance | Repeat rule |
|---|---|---|---|
| Issuance | Public base commitment `C` and externally authorized balance `b` | Fresh `Y(C,0,zeta)` | No issuance cache: another accepted call samples another `zeta`, hence normally another target and preimage. |
| Ordinary spend | Input ownership/arithmetic/nullifier and fresh base commitment `C'` | Fresh `Y(C',0,zeta)` | An exact durable retry replays the stored `(zeta,signature)`; a new accepted nullifier gets a new salt. |
| Deferred-return spend | The same facts, with a maximum public deduction | Fresh `Y(C',t',zeta)` after the issuer checks `t' <= spend` | An exact durable retry replays the stored `(t',zeta,signature)`, even if its caller now proposes another return. |

The issue circuit proves only the opening of `C`
([`circuit.rs:507-518`](../../../crates/vole-act/src/circuit.rs#L507-L518)). The
spend circuit proves the old salted wrapper relation, derives the old
nullifier, enforces the balance equations, and proves the fresh `C'` opening
([`circuit.rs:610-691`](../../../crates/vole-act/src/circuit.rs#L610-L691)).
Client completion independently evaluates the returned MAYO preimage on the
returned salt and expected return
([`issue.rs:64-93`](../../../crates/vole-act/src/protocol/issue.rs#L64-L93),
[`spend.rs:556-623`](../../../crates/vole-act/src/protocol/spend.rs#L556-L623)).

## What state does and does not do

The only issuer protocol state is a nullifier-keyed retry store. A successful
spend durably records the exact request digest and the entire winning response,
including salt; an exact retry returns that record, while a different request
under the same nullifier is rejected
([`store.rs:35-54`](../../../crates/vole-act/src/protocol/store.rs#L35-L54),
[`store.rs:167-185`](../../../crates/vole-act/src/protocol/store.rs#L167-L185)).
There is no target cache and none is required to make repeated accepted calls
land on fresh targets: that property now comes from the signer salt. Issuance
remains stateless and deliberately returns a newly salted credential on every
successful invocation.

Salt multiplicity and credit multiplicity must not be conflated. The nullifier
is derived from the base credential opening, not from `zeta`, `Y`, the MAYO
preimage, the return, or the local marker. Multiple salted credentials over one
opening are alternative authentications of one consumable lineage, not balances
to be added together
([`circuit.rs:170-190`](../../../crates/vole-act/src/circuit.rs#L170-L190)).

## Format and type boundaries

All credential kinds now share the same cryptographic wrapper. Direct
credentials additionally require `t = 0`; deferred credentials permit a hidden
top-up. Rust markers prevent accidental interchange; Fiat–Shamir statement and
request-digest tags provide end-to-end binding. Wire IDs reject unmodified
wrong-type artifacts but can be header-retagged when body layouts coincide.
A zero-return credential still satisfies the common relation under either
local marker
([`markers.rs:10-80`](../../../crates/vole-act/src/protocol/markers.rs#L10-L80),
[`protocol/tests.rs`](../../../crates/vole-act/src/protocol/tests.rs)).

The transition is intentionally incompatible with old artifacts:

- canonical wire envelope: `v2`, carrying salts in responses, tokens, and
  retry records ([`wire.rs:1-10`](../../../crates/vole-act/src/wire.rs#L1-L10));
- context, issue/spend statement, and spend-request-digest domains: `v5`
  ([`protocol/mod.rs:33-34`](../../../crates/vole-act/src/protocol/mod.rs#L33-L34),
  [`spend.rs:626-703`](../../../crates/vole-act/src/protocol/spend.rs#L626-L703));
- base credential hash: `credential/v2`; common signed wrapper: `signed/v3`
  ([`circuit.rs:17-24`](../../../crates/vole-act/src/circuit.rs#L17-L24)).

## Detailed audit

- [Implemented oracle, call by call](implemented-oracles.md)
- [Repeats, failures, races, and state scope](repeats-races-state.md)
- [What an independent credit lineage actually is](lineage-accounting.md)
- [Transition audit: unsalted snapshot to salted worktree](head-vs-working-tree.md)

## Assumption-review boundary

The current code implements the protocol change needed for the proposed
ordinary-MAYO route. It does **not** itself prove the route. A complete argument
still has to simulate accepted salted signatures, account for exact retries and
withheld race losers, adapt MAYO's game sequence to this wrapper and rejection
sampler, extract the hidden relations, and treat the QROM. Accordingly the
accurate claim today is:

> The signer-salted construction is designed to avoid the specialized
> one-more-preimage assumption and rely on ordinary MAYO hardness, but the exact
> stateful-protocol reduction currently exists only as an incomplete paper-level
> [game plan](../reduction/index.md), not a completed or reviewed theorem.
