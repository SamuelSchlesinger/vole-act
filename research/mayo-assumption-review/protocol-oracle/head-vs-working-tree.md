# Transition audit: unsalted snapshot to signer-salted worktree

[Back to the protocol-oracle index](index.md)

This file keeps its historical filename so existing corpus links remain valid.
It no longer treats committed `HEAD` as the protocol authority: the active Rust
worktree implements the signer-salted common wrapper, and this audit records
the semantic transition as observed on 2026-07-21.

## The superseded snapshot

The earlier corpus snapshot reconstructed three different signing behaviors:

- issuance inverted the bare client commitment `C`;
- ordinary spend inverted the bare fresh commitment `C'`;
- deferred-return spend alone inverted a wrapper of `(ctx,C',return)`.

Because issuance had no retry cache, the same accepted request could expose
multiple randomized MAYO preimages of one adversary-fixed `C`. Distinct spend
nullifiers could likewise request multiple samples on one chosen `C'`. The
specialized one-more-preimage assumption was a conservative way to model that
implemented oracle, while the documents correctly left open whether a tighter
ordinary-MAYO simulation could eliminate it.

Those statements are now historical only. In particular, any earlier page in
this corpus saying “the code has no signer salt,” “direct signs `C`,” “an
identical race signs one target twice,” or “target idempotence is the remaining
implementation fix” is obsolete with respect to the current worktree.

## The implemented transition

The current worktree makes five coupled changes:

1. **One common final target.** Every credential authenticates
   `Signed(C,t,zeta)` under the `VOLE-ACT/signed/v3` domain. Direct uses `t=0`;
   deferred uses the issuer-selected return
   ([`circuit.rs:139-168`](../../../crates/vole-act/src/circuit.rs#L139-L168),
   [`protocol/mod.rs:87-96`](../../../crates/vole-act/src/protocol/mod.rs#L87-L96)).
2. **Salt after proof acceptance.** Issuance and both spend paths verify first,
   then draw 32 uniform bytes, derive the target, and call `SPre`
   ([`issuer.rs:148-239`](../../../crates/vole-act/src/protocol/issuer.rs#L148-L239),
   [`issuer.rs:291-302`](../../../crates/vole-act/src/protocol/issuer.rs#L291-L302)).
3. **Salt is authenticated state.** Responses, tokens, spend witnesses, and
   retry records carry the salt; clients and circuits recompute the wrapper
   ([`issue.rs:64-93`](../../../crates/vole-act/src/protocol/issue.rs#L64-L93),
   [`spend.rs:6-19`](../../../crates/vole-act/src/protocol/spend.rs#L6-L19),
   [`circuit.rs:531-607`](../../../crates/vole-act/src/circuit.rs#L531-L607),
   [`store.rs:35-54`](../../../crates/vole-act/src/protocol/store.rs#L35-L54)).
4. **Retries replay the complete winner.** Exact spend retries reuse the stored
   signature, salt, and deferred return. Concurrent losing salted candidates
   are not returned
   ([`issuer.rs:241-279`](../../../crates/vole-act/src/protocol/issuer.rs#L241-L279),
   [`store.rs:167-185`](../../../crates/vole-act/src/protocol/store.rs#L167-L185)).
5. **Artifacts are version-separated.** Wire version 2 carries the new fields;
   context, issue/spend statements, and request digests use version 5 domains.
   Old tokens, responses, pending state, retry rows, and proofs are not current
   artifacts
   ([`wire.rs:1-10`](../../../crates/vole-act/src/wire.rs#L1-L10),
   [`protocol/mod.rs:33-53`](../../../crates/vole-act/src/protocol/mod.rs#L33-L53),
   [`spend.rs:626-703`](../../../crates/vole-act/src/protocol/spend.rs#L626-L703)).

The direct input circuit now includes the same salted-wrapper SHAKE evaluation
as the deferred input circuit and constrains its top-up bits to zero. The two
modes therefore have the same circuit/proof shape, while typed statement and
wire markers remain visible
([`circuit.rs:610-691`](../../../crates/vole-act/src/circuit.rs#L610-L691),
[`protocol/tests.rs`](../../../crates/vole-act/src/protocol/tests.rs)).

## What changed in the assumption discussion

The old concern was not merely that `C` belonged to a client-proved Keccak
language. It was that the trapdoor repeatedly answered on a target fixed before
signer randomness. The new wrapper changes the chronology:

```text
adversary fixes (proved C, typed request)
        -> verifier accepts
        -> signer samples zeta
        -> fresh wrapper point Y(C,t,zeta)
        -> trapdoor returns one preimage of Y
```

That chronology is the reason the design now aims at the ordinary MAYO proof
sequence rather than the specialized `(n,q)` one-more-preimage game the
colleague called Definition 8. It also explains
why simply deleting the old assumption from prose, without implementing the
salt timing and retry persistence, would have been the wrong change.

The implementation has crossed that design gate. The proof gate remains open:
the exact wrapper is not the standardized MAYO signing encoding, and no full
ROM/QROM reduction currently covers the stateful protocol, sampler rejection,
proof extraction, retry records, and concurrency. The source-level review calls
this out explicitly
([DESIGN fiscal soundness](../../../docs/DESIGN.md#71-fiscal-soundness-sketch),
[SECURITY open ordinary-MAYO reduction](../../../docs/SECURITY.md#b2-the-ordinary-mayo-reduction-is-incomplete-for-the-exact-protocol-high)).

## Migration and deployment consequences

This transition is pre-release and intentionally non-compatible. A deployment
must not mix old and new artifacts or attempt to infer a missing salt. In
particular:

- generate compatible issuer/public-key material so all parties agree on the
  `context/v5` derivation; any old-key migration needs an explicit external
  procedure because this crate does not decode the old wire format;
- reject wire-v1 artifacts rather than silently interpreting them as v2;
- store and replay the full v2 retry record, including the signer salt;
- keep old nullifier state attached to any old key for as long as old tokens
  can still be spent, or retire that key and token population atomically; and
- treat application-level issuance idempotency as a separate authorization
  concern: authorization, durable charging, and response publication need one
  external idempotency key because cryptographic issuance resamples deliberately.

| Layer | Current value | Legacy behavior |
|---|---|---|
| Outer protocol wire | `2` | wire-v1 rejected for every artifact family |
| Context/statements/request digest | `v5` | earlier keys/transcripts incompatible |
| Signed wrapper | `signed/v3` | signer salt required |
| Credential and mode markers | `v2` | earlier relations incompatible |
| Embedded VOLE proof codec | `1` | independently versioned inside wire-v2 |

## Audit disposition

The protocol-oracle pages in this directory now describe the salted worktree,
not the earlier commit comparison. The dated historical value of the old audit
is the diagnosis it preserved: Keccak membership alone did not imply target
freshness, and a security-assumption edit was not justified until the signer
controlled fresh entropy after proof acceptance. The current code implements
that missing mechanism. A paper-level ordinary-MAYO game plan is now written in
the [reduction corpus](../reduction/index.md); the remaining Error/Gap is that
its theorem, extraction, sampler, fixed-Keccak, and QROM steps are incomplete
and not independently validated, not that an unsalted oracle remains in the
Rust paths.

[Back to the protocol-oracle index](index.md)
