# Plain MAYO versus one-more preimage security in VOLE-ACT

## 2026-07-21 signer-salted implementation revision

This corpus was originally completed against VOLE-ACT's bare-target issuer.
The worktree now implements the signer-salted common wrapper identified by that
review. This revision has:

- [x] replaced the obsolete issuer-oracle inventory with the implemented
  salt-after-verification, exact-retry, and race semantics;
- [x] turned the candidate wrapper notes into the strongest precise classical
  ideal-XOF proof plan presently supported by the MAYO Round-2 games;
- [x] audited salt freshness, sampler coupling, the 256-attempt cap, OV,
  MTWMQ, and fiscal-accounting losses against primary sources and Rust code;
- [x] updated design recommendations, performance figures, version boundaries,
  and implementation anchors;
- [x] rerun hierarchy, link, bibliography, and quantitative validation; and
- [x] recorded the remaining proof gaps as limitations rather than silently
  claiming that ordinary MAYO already proves the exact protocol.

## Executive conclusion

The colleague's architectural diagnosis was right. PoMFRIT's
`(n,q)` one-more-preimage assumption is used by its optimized construction,
which exposes target inversion below MAYO's hash-and-sign layer. Its more
conservative construction proves ordinary MAYO verification and starts from
MAYO EUF-CMA [baum26][baum26].

The old VOLE-ACT code did expose the difficult oracle: it passed a
client-fixed commitment directly to `SPre` and could return independently
sampled preimages on repeated accepted calls. Merely proving that commitment's
Keccak opening did not give a simulator a fresh point at which to program a
public-map image. The one-more premise was therefore an honest conservative
description of the old implementation, even though it was never proved
necessary.

The current worktree changes that chronology. After a request proof verifies,
the issuer samples a uniform 256-bit salt `zeta` and signs

```text
SHAKE256(
  "VOLE-ACT/signed/v3" || pack16(C) || LE64(return) || zeta
)[0:4m].
```

Direct credentials use return zero; deferred credentials use the
issuer-selected return. Both later prove the same wrapper relation. Exact
successful spend retries replay the durable salt/signature pair, while
concurrent race losers are never released. The old same-target simulation
obstruction is therefore gone except on explicitly charged salt-prequery or
collision events.

That gives a credible **classical ideal-XOF proof route** to the ordinary MAYO
assumption package: simulate signing by choosing a public preimage, program its
image at the fresh salted point, make the OV hop, and use an unsigned wrapper
forgery to solve Multi-Target Whipped MQ [mayo-r2][mayo-r2]. It is an adapted
proof, not a verbatim invocation of Round-2 `MAYO.Sign` or PoMFRIT Theorem 5.1.

The implementation and narrative are now aligned on this status:

> The specialized one-more assumption is no longer the intended premise for
> the implemented signer-salted oracle. Ordinary MAYO's OV-plus-MTWMQ package
> is the intended conditional foundation, but the exact wrapper reduction,
> stateful extraction, local sampler theorem, fixed-Keccak bridge, and QROM
> treatment remain incomplete.

## The first-principles chain

1. **Fiscal accounting.** Group token alternatives by their consumable
   nullifier. Over-redemption yields an authenticated semantic descriptor
   which was not authorized by issuance or an earlier output, after removing
   proof, hash, arithmetic, authorization, and state failures.
2. **Unsigned wrapper message.** Outside a collision in the credential prefix,
   that orphan descriptor gives a valid signature on a message `(C,return)`
   which the issuer never signed. A new salt or preimage on an already signed
   message is only another authenticator for the same nullifier lineage.
3. **Fresh programming point.** The message is fixed before the issuer chooses
   `zeta`. Except when the adversary prequeried or repeated that 256-bit suffix,
   the simulator may program the target hash after choosing a public preimage.
4. **MAYO coupling.** Replacing trapdoor sampling with uniform public sampling
   pays the published `(1-Q_cpl B)^-1` factor for `Q_cpl B < 1`.
   Under response-oblivious scheduling `Q_cpl=Q_s` counts visible winners.
   Without that premise, a separate retry-timing/race lemma is still missing;
   merely substituting `Q_try` is insufficient.
   For MAYO2,
   `B ~= 2^-19.907`, so the published constant-factor regime is below roughly
   `2^19` fresh responses per generated key.
5. **OV and MTWMQ.** The OV hybrid replaces the structured map by a random one;
   an unprogrammed signed-v3 query becomes an MTWMQ target, and the unsigned
   wrapper preimage solves it except for an unqueried-target guess.
6. **Model boundary.** This argument programs an ideal XOF. The implementation
   proves a fixed Keccak-f[1600] circuit, and the proof system itself uses
   Fiat-Shamir. A fixed-Keccak instantiation and QROM extraction are separate
   claims.

## Newly exposed sampler gap

The local `SPre`, like Round-2 Algorithm 7, gives up after 256 failed rank
samples. If `p_K` is the one-attempt failure probability for a fixed generated
key, one call exhausts with probability `p_K^256`. But Round-2 Lemma 1 averages
over key generation and vinegar sampling:

```text
E_K[p_K] <= B.
```

It does not establish `p_K <= B` for every key. Consequently the cited lemma
does not justify `B^256`; it gives only the loose
`E_K[p_K^256] <= B`, and hence a union bound `Q_try B` over a hard maximum of
sampler invocations, each containing at most 256 internal rank attempts.
This is not evidence of a practical failure. It is a genuine completeness and
reduction gap requiring a higher-moment/bad-key-tail theorem, a justified
setup-time validation strategy, or another sampler treatment.

## Research map

- [Paper and definition analysis](paper-analysis/index.md) separates
  PoMFRIT's conservative and optimized constructions and reconstructs the
  exact ordinary-MAYO assumption package.
- [Implemented protocol oracle](protocol-oracle/index.md) records issuance,
  spend, salt timing, exact retries, races, lineages, and the wire-v2/context-v5
  transition.
- [Reduction for the implemented wrapper](reduction/index.md) contains the
  fiscal lift, classical-ROM simulator, distribution/loss ledger, full game
  sequence, and conditional theorem boundary.
- [Design recommendation and measured cost](design-options/index.md) compares
  the implemented wrapper with literal `MAYO.Sign`, target canonicalization,
  issuer challenges, and the retired bare-target design.
- [Random-oracle versus concrete Keccak](design-options/oracle-model.md)
  separates the ideal XOF, ideal permutation, fixed circuit, and QROM layers.
- [Master bibliography](sources.md) contains the primary sources and numbering
  notes.

## Status ledger

| Claim | Status after this revision |
|---|---|
| PoMFRIT's specialized one-more premise belongs to its optimized direct-target construction | Established from Sections 5 and 6 |
| The current issuer ever passes bare `C` directly to `SPre` | **False**; every accepted response uses `signed/v3` with post-verification issuer salt |
| Exact spend retries or identical races expose multiple fresh signatures | **False**; retries replay and all successful race callers receive the durable winner |
| Repeated issuance normally creates new salted targets | Implemented and tested; issuance authorization remains external |
| Direct and deferred input proofs have equal payload | Implemented, tested, and benchmarked for all built-in profiles |
| Fiscal over-redemption yields an unsigned wrapper message | Paper-level argument, conditional on the named extraction/state/hash failures |
| The wrapper has a classical ideal-XOF route to OV plus MTWMQ | Detailed paper-level game plan; not a completed theorem |
| Round-2 Theorem 1 proves the exact wrapper verbatim | **False**; encoding, salt derivation, sampling coins, state, and proof composition differ |
| The local 256-attempt failure is bounded by `B^256` | **Not established**; the published lemma is average over generated keys |
| The proof already covers fixed Keccak or quantum oracle queries | **False**; both bridges remain open |
| The implementation is production ready | **False**; exact reductions and independent cryptographic review remain release blockers |

## Reproducible checks

- [`design-options/data/compare_current_profiles.py`](design-options/data/compare_current_profiles.py)
  validates derived ranges and deltas from the committed benchmark snapshot;
  it does not independently rerun Criterion.
- [`design-options/data/mayo_rejection_bound.py`](design-options/data/mayo_rejection_bound.py)
  computes the Round-2 restart bound for every parameter set.
- [`reduction/data/mayo2_rejection_bound.py`](reduction/data/mayo2_rejection_bound.py)
  checks the MAYO2 bound and representative coupling factors.
- [`reduction/data/salted_wrapper_loss.py`](reduction/data/salted_wrapper_loss.py)
  reproduces representative salt, collision, sampler, and cap terms without
  making the invalid `B^256` inference.
- [`data/check_corpus.py`](data/check_corpus.py) checks reachability, local
  Markdown links, and bibliography anchors.

The implementation, main draft, design, security review, benchmark record, and
this research corpus were revised together. The remaining gaps are stated as
open obligations, not hidden behind the phrase "plain MAYO."

[baum26]: sources.md#baum26
[mayo-r2]: sources.md#mayo-r2
