# A protocol-level decision test derived from the papers

This document does not claim a completed reduction for VOLE-ACT.  It extracts a
checklist from the two PoMFRIT constructions and applies it to the implemented
signer-salted common wrapper.

## Step 1: Write the issuer's exact oracle

Ignore names such as "sign," "credential," and "commitment."  Write the
accepted request and response as a mathematical relation.

### Ordinary-signature-shaped oracle

```text
request:  a message M (possibly hidden behind a proved relation)
response: a signature (salt,s) satisfying
          P*(s) = HashToField(M,salt).
```

This is structurally the Section-5 route.  A reduction may choose `s`, compute
`P*(s)`, and program the random oracle at a fresh hash input, as in the MAYO
EUF-CMA proof [baum26][baum26] [mayo-r2][mayo-r2].

### Direct-target-shaped oracle

```text
request:  t in the codomain of P*
response: s satisfying P*(s)=t.
```

This is structurally the Section-6 route even if the requester separately proves
that `t` is related to some hash.  Unless that relation lets the simulator
control/program the exact target-setting hash point in the ordinary-signature
way, the issuer is still answering inversion queries from the reduction's point
of view [baum26][baum26].

## Step 2: Locate the hash topologically

Ask which of the following the proof actually checks:

1. `P*(s) = H(encoded credential || signer salt)`;
2. `P*(s) = t` and separately `t = H(encoded credential)`;
3. `P*(s) = H(public data) + hidden mask`;
4. `P*(s) = t` while a different commitment or nullifier is a Keccak output.

Cases 1 and 2 may support an ordinary hash-and-sign reduction if the simulator
can treat the equality as one programmable random-oracle edge and all freshness
conditions hold.  Case 3 is exactly PoMFRIT's optimized pattern: it contains a
hash but still uses the one-more assumption.  Case 4 supplies no relevant
hash-to-target protection at all.

The difference between cases 1 and 2 is often only circuit modularity.  The
security question is whether the issuer accepts only targets arising from a
fresh, domain-separated hash input that the reduction can associate with the
signed message---not whether the source code calls Keccak in the same function.

## Step 3: Check the counting object

PoMFRIT Section 5 counts **distinct signed commitments** and extracts an
ordinary EUF-CMA forgery.  Section 6 counts **distinct random targets** and
extracts a one-more inversion win [baum26][baum26].

For an external protocol, state exactly what `Q+1` successful outputs after `Q`
issuer operations imply:

- `Q+1` distinct messages with valid MAYO signatures;
- `Q+1` distinct hash inputs;
- `Q+1` distinct MAYO targets;
- or merely `Q+1` spend transcripts, some of which may reuse the same hidden
  message, target, or preimage.

Without this injectivity step, neither PoMFRIT reduction transfers directly.

## Step 4: Check repeat behavior

The Round-2 MAYO API supports two materially different modes
[mayo-r2][mayo-r2]:

- `R=0`: the key/message pair deterministically fixes salt and the remaining
  signing coins;
- fresh `R`: repeat messages generate fresh salts and fresh hash targets.

An external oracle that returns a newly sampled preimage of the same fixed
target on every retry matches neither behavior automatically.  A reduction must
show how to simulate that distribution, or the protocol must make the response
idempotent, or the message-to-target derivation must include fresh signer input.

This repeat issue is not what motivates Definition 3.1 in PoMFRIT Section 6:
the paper already needs the one-more assumption because the optimized issuer
exposes target inversion below the hash-and-sign layer.  But repeat behavior can
still prevent a proposed Section-5-style reduction for a different protocol.

### Implemented repeat behavior

VOLE-ACT now resolves this issue by changing target formation rather than by
canonicalizing `SPre` on a bare target:

```text
accepted message descriptor: M = (C, return)
issuer action:               zeta <- uniform {0,1}^256
target:                      H_sig(M || zeta)
response:                    (zeta, SPre(sk,target))
```

Repeated authorized issuance of the same `M` uses a newly sampled salt and a
new target.  A durably accepted spend is different: an exact retry returns the
stored salt/preimage pair and makes no second `SPre` call
([`issuer.rs:148-180`](../../../crates/vole-act/src/protocol/issuer.rs#L148-L180),
[`issuer.rs:182-238`](../../../crates/vole-act/src/protocol/issuer.rs#L182-L238),
[`store.rs:167-180`](../../../crates/vole-act/src/protocol/store.rs#L167-L180)).
This is the repeat topology needed by the ordinary-MAYO simulation, subject to
salt prediction/collision and honest-RNG terms.  It is not Algorithm 7's exact
salt derivation [mayo-r2][mayo-r2].

## Step 5: Inventory every non-MAYO assumption

Replacing one-more resistance with ordinary MAYO security does not leave a
single assumption.  A Section-5-shaped argument still needs, at minimum:

- the OV and MTWMQ assumptions underlying MAYO's EUF-CMA theorem;
- the ROM programming and quantitative freshness/restart bounds of that
  theorem;
- a per-key signing-query budget compatible with the rejection-sampling loss,
  or a separate argument beyond the Round-2 theorem (for MAYO2 the source's
  constant-factor range is fewer than about `2^19` signatures per key);
- binding/injectivity sufficient to map distinct protocol outputs to distinct
  signed messages;
- knowledge extraction for hidden openings and preimages;
- collision resistance or random-oracle collision bounds for all encodings;
- protocol-state guarantees needed to count authorized issuer operations.

The first two items are in the MAYO specification, and the commitment/NIZK
shape is in PoMFRIT [mayo-r2][mayo-r2] [baum26][baum26].  The remaining items
must be proved for the external protocol.

## Decision table

| Observed protocol fact | Direction suggested by sources |
|---|---|
| Issuer runs ordinary MAYO signing on a uniquely encoded message | Start from PoMFRIT Section 5 / MAYO EUF-CMA |
| Proof checks the ordinary MAYO verifier, including target hash | Strong Section-5 evidence |
| Issuer accepts a codomain target and runs `SPre` directly | Section-6 / one-more-shaped oracle |
| Circuit has Keccak, but not on the edge that sets `P*(s)` | Does not support the colleague's conclusion |
| Target is `H(public data)+hidden random mask` | Exactly PoMFRIT Section 6 despite the hash |
| Same fixed target can return multiple fresh preimages | Additional simulation gap; resolve separately |
| `Q+1` outputs do not imply a new message or a new target | Counting reduction incomplete |
| Issuer samples a uniform salt after proof acceptance and signs `H(M||salt)` | Ordinary-MAYO proof direction; adapted wrapper theorem still required |
| Exact spend retry replays `(salt,s)` | Compatible with one programmed signing point |
| Same authorized issuance repeated with a new salt | A new signing query and target, not same-target resampling |

## Derived conclusion

The colleague's statement is best reformulated as follows:

> If the protocol already proves an ordinary, properly encoded MAYO
> hash-and-sign verification relation, including the hash that fixes the MAYO
> target, then PoMFRIT's optimized one-more assumption is not automatically
> needed.  One should attempt a reduction to ordinary MAYO EUF-CMA instead.

The implemented wrapper now meets that design criterion at the oracle-topology
level: the target-setting Keccak includes unpredictable issuer input and is
recomputed in the credential proof.  The colleague was therefore right about
the direction in which the protocol should move.  What remains is not a reason
to restore the one-more premise; it is the work of proving the exact one-hash
wrapper, including oracle, extraction, injectivity, sampler, state, and model
transitions.  Until those are discharged, “based on ordinary MAYO” is an
intended conditional foundation rather than a completed reduction.

[Back to paper analysis](index.md)

[baum26]: ../sources.md#baum26
[mayo-r2]: ../sources.md#mayo-r2
