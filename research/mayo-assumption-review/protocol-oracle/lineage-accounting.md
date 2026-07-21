# What an independent credit lineage actually is

[Back to the protocol-oracle index](index.md)

## Four objects, four jobs

The easiest way to avoid counting mistakes is to name the objects separately:

| Object | Derived from | What it does |
|---|---|---|
| Base commitment `C` | `(ctx,key,base_balance,nonce)` | Hides and binds the base credential opening. |
| Signed target `Y` | `(C,topup,salt)` | Is the actual MAYO public-map target. |
| MAYO preimage `sigma` | Trapdoor sampling for `Y` | Authenticates that signed target. |
| Nullifier `N` | The suffix of the same credential stream as `C` | Names the one consumable lineage. |

A token stores all the data needed to reconstruct these relations: context,
MAYO preimage, base opening, top-up, and signer salt
([`spend.rs:6-19`](../../../crates/vole-act/src/protocol/spend.rs#L6-L19)). Token
authentication recomputes `C`, checks the kind's top-up rule, computes
`Y(C,topup,salt)`, and evaluates `sigma`
([`public_key.rs:144-160`](../../../crates/vole-act/src/protocol/public_key.rs#L144-L160)).

The nullifier is independent of `topup`, `salt`, `Y`, `sigma`, and the local
credential marker. It is bits immediately following `C` in the XOF stream of
the base opening
([`circuit.rs:101-130`](../../../crates/vole-act/src/circuit.rs#L101-L130),
[`circuit.rs:170-190`](../../../crates/vole-act/src/circuit.rs#L170-L190)).

## Equivalence-class accounting

For fiscal accounting, group all valid token alternatives with the same
nullifier into one class. The class is independently spendable once, because
its first accepted spend durably consumes that nullifier. Its capacity is the
maximum valid effective balance among its alternatives, not the sum.

```text
same opening, different salts
    -> generally different Y and sigma
    -> same N
    -> one lineage

same opening and salt/target, different MAYO preimages
    -> same N
    -> one lineage

same opening, different topups or local kinds
    -> possibly different effective balances and Y values
    -> same N
    -> mutually exclusive alternatives in one lineage
```

This is why repeated issuance is simultaneously:

- many issuer responses;
- normally many final MAYO targets under the new salt rule; but
- only one future spend lineage when all responses use the same opening.

The repeated-issuance test checks the first two points
([`protocol/tests.rs`](../../../crates/vole-act/src/protocol/tests.rs));
the nullifier derivation proves the third. A signature variant is a
cryptanalytic sample, not a second pot of money.

## Direct and deferred markers

All credentials use the same `signed/v3` relation. A direct token must have
`topup = 0`; a deferred token may have any non-overflowing top-up
([`protocol/mod.rs:80-96`](../../../crates/vole-act/src/protocol/mod.rs#L80-L96)).
Therefore a zero-return credential is cryptographically valid under either
local marker if one manually reconstructs the other Rust value. This is
intentional and tested
([`protocol/tests.rs`](../../../crates/vole-act/src/protocol/tests.rs)).

That does not erase type separation at the protocol boundary. Credential-kind
and settlement tags are absorbed into spend statements and canonical wire
headers. Header-retagged identical-layout bodies may parse because the codec
tag is not independently authenticated; re-tagged request proofs fail, and
cross-mode retries do not match the durable request digest/response kind
([`spend.rs:656-703`](../../../crates/vole-act/src/protocol/spend.rs#L656-L703),
[`protocol/tests.rs`](../../../crates/vole-act/src/protocol/tests.rs)).
Markers identify typed artifacts and proof statements; wire IDs reject
unmodified wrong-type bytes but are not authenticators. They do not define
disjoint cryptographic ranges.

## Repeated issuance versus repeated spend

An accepted issuance call is an external authorization event. The crate proves
credential well-formedness and returns a fresh salted signature, but it does
not implement charging, deduplicate a business request, or decide whether the
same issuance should be billed twice. If an application retries issuance after
an ambiguous network failure, it needs its own authorization/idempotency rule.
At the cryptographic layer, the responses over one opening are still one
lineage.

A spend is different. Its input nullifier is the durable idempotency key. The
first successful transaction fixes the output response; exact retransmission
replays it and a conflicting request cannot create another descendant
([`issuer.rs:182-279`](../../../crates/vole-act/src/protocol/issuer.rs#L182-L279),
[`store.rs:167-185`](../../../crates/vole-act/src/protocol/store.rs#L167-L185)).
The surrounding redemption service must couple any real-world delivery of
value to the same transaction boundary; that service is outside this crate.

## The genuinely bad branching events

Signer-salt multiplicity is not a fiscal fork. Independent value requires
different consumable nullifiers. Two hash failures are therefore qualitatively
different:

1. **Credential-prefix double opening.** Two distinct openings yield the same
   base prefix `C` but different suffix nullifiers. One valid signed wrapper
   over `C` can then authenticate two independently consumable lineages. This
   is a collision/double-opening event in the credential hash relation.
2. **Nullifier collision.** Two otherwise independent openings have the same
   suffix `N`. The store permits only one to spend; this is a liveness/value-loss
   event, not inflation.

Wrapper collisions also remain cryptographically relevant: distinct
`(C,topup,salt)` tuples might yield the same truncated `Y`, allowing a preimage
to authenticate more than one wrapper input. Domain separation and 256-bit
salt make the intended ROM analysis clean; they do not make mathematical hash
ranges injective.

## What the MAYO reduction counts

The three ledgers are now:

```text
MAYO exposure:       every returned salted target/preimage pair
fiscal authorization: every accepted externally authorized issuance
credit lineages:     equivalence classes under the same consumable nullifier
```

Under the old bare-target implementation, repeated accepted calls could add
MAYO exposure without adding a new target, which motivated a same-target
multi-sample/one-more-style model. Under the current implementation, each new
accepted response includes an issuer salt and therefore normally contributes a
new target/preimage pair; exact spend retries contribute neither, and race
losers are withheld. This is the oracle shape the ordinary-MAYO reduction must
simulate.

That observation is a design argument, not the missing theorem. The eventual
proof must still show how the ordinary MAYO games cover the protocol's salted
wrapper, extraction failures, random-oracle programming, collisions,
concurrency, and QROM queries
([SECURITY B2](../../../docs/SECURITY.md#b2-the-ordinary-mayo-reduction-is-incomplete-for-the-exact-protocol-high)).

[Back to the protocol-oracle index](index.md)
