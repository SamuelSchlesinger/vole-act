# MAYO assumptions, target hashing, and salt semantics

## 1. "Plain MAYO hardness" is not one unqualified assumption

The current MAYO Round-2 specification, Section 5.1, defines two computational
problems [mayo-r2][mayo-r2]:

1. **OV problem (Definition 1).** Distinguish a uniformly random quadratic map
   from one sampled with a hidden oil subspace on which it vanishes.
2. **Multi-Target Whipped MQ (Definition 2).** Given a random quadratic map,
   the fixed whipping matrices, and access to an unbounded sequence of random
   codomain targets, invert one of those targets under the whipped public map.

Section 5.2, Theorem 1 reduces MAYO EUF-CMA security in the random-oracle model
to both problems, subject to an explicit signing-restart bound `Qs * B < 1` and
additive terms for hash collisions, salt prediction/pre-query events, and
secret-seed guessing [mayo-r2][mayo-r2].

Accordingly:

- Calling Whipped MQ "the plain MAYO problem" is understandable shorthand for
  the preimage-hardness leg.
- Calling it the *entire* security assumption of MAYO omits the OV
  indistinguishability leg and the ROM/proof-loss conditions.
- The Round-2 definition is already **multi-target**, but it supplies only
  random targets and no trapdoor inversion oracle.  "Multi-target" must not be
  confused with "one-more."

The original SAC paper has the same two-part structure but uses older
definitions: UOV is Definition 4, Whipped MQ is Definition 5, and Theorem 7
reduces EUF-CMA to UOV and Whipped MQ [beullens22][beullens22].  In that version
the per-message hash also derives the whipping coefficients.  The Round-2
scheme fixes the whipping matrices and formulates Multi-Target Whipped MQ.
This version evolution explains some otherwise confusing definition-number
and terminology mismatches in PoMFRIT.

### The rejection-sampling bound is a real theorem boundary

Theorem 1's multiplicative term is `(1-Qs*B)^-1`, where `Qs` is the number of
signing queries and

```text
B = q^(k-(n-o))/(q-1) + q^(m-ko)/(q-1)
```

is the joint-key-and-vinegar rank-failure bound used in the theorem.  Section
5.3 attributes the resulting loss to a small amount of information-theoretic
leakage from rejection sampling [mayo-r2][mayo-r2].

The specification draws three distinct lines:

- If `Qs*B < 1/2`, the reduction loses only a constant factor and the leakage
  is proved not to degrade security much.
- If `Qs*B > 1`, the proof gives no guarantee.
- The authors nevertheless expect MAYO to remain secure with unboundedly many
  signatures and report no known attack exploiting the leakage.

For MAYO1, MAYO3, and MAYO5, it estimates `B` at about `2^-12`, yielding the
constant-factor range of fewer than about `2^11` signatures.  For MAYO2 it
estimates `B` at about `2^-20`, yielding fewer than about `2^19` signatures per
key [mayo-r2][mayo-r2], Section 5.3 (printed p. 29).

This is an unusually important proved-versus-believed distinction for a
high-volume issuer.  A statement such as "reduce to ordinary MAYO EUF-CMA"
inherits this per-key query limitation unless a different proof, parameter set,
or explicit operational key-rotation policy resolves it.  The absence of a
known attack beyond the bound must not be reported as theorem-level coverage.

There is a separate completeness subtlety. Lemma 1 chooses the oil space,
structured public map, and vinegar sample jointly. If `p_K` is the one-attempt
rank-failure probability after fixing one generated key `K`, the source yields
`E_K[p_K] <= B`; it does not yield the uniform statement `p_K <= B`. Therefore
the 256 independent attempts in Algorithm 7 fail with `p_K^256` for a fixed
key, but `B^256` is not a justified average bound. From Lemma 1 alone one has
only the loose `E_K[p_K^256] <= B`. A stronger per-key tail result would be
needed for the astronomically small cap-failure claim one might otherwise make.

## 2. Exact Round-2 signing semantics

Round-2 Algorithm 7 does not merely compute `t=H(M)` [mayo-r2][mayo-r2].  It
does the following:

```text
M_digest <- SHAKE256(M)
R        <- 0 or fresh random bytes               // optional randomization
salt     <- SHAKE256(M_digest || R || seed_sk)
t        <- DecodeVec(SHAKE256(M_digest || salt))
V        <- SHAKE256(M_digest || salt || seed_sk || ctr)
s        <- trapdoor solution of P*(s)=t
signature = EncodeVec(s) || salt.
```

Verification (Algorithm 8) parses the salt, recomputes `M_digest` and `t`, and
checks that the public whipped-map evaluation on `s` equals `t`
[mayo-r2][mayo-r2].

Consequences:

- With `R=0`, signing is deterministic for a fixed key and message (assuming
  the specified deterministic derivations).
- With fresh `R`, repeated signing of the same message ordinarily produces a
  fresh salt and therefore a fresh hash target.
- Neither mode is the same interface as repeatedly sampling fresh independent
  preimages of one externally supplied fixed target.
- The salt is part of the signature and part of the target derivation; it is
  not the hidden witness whose relation must necessarily be proved in every
  wrapper protocol.

These points are direct readings of Algorithms 7 and 8.  Whether a wrapper can
omit, externalize, or determinize these steps while retaining a particular
security theorem is a separate reduction question.

### The implemented wrapper is a deliberate one-hash adaptation

VOLE-ACT now implements

```text
zeta <- uniform {0,1}^256
Y    <- SHAKE256(
          "VOLE-ACT/signed/v3" || pack16(C) || enc64(return) || zeta
        )[0:4m]
sigma <- SPre(sk,Y; caller RNG)
```

after proof verification.  The response/token carries `zeta`, and every later
credential proof recomputes `Y` before checking `P*(sigma)=Y`
([`circuit.rs:139-168`](../../../crates/vole-act/src/circuit.rs#L139-L168),
[`circuit.rs:655-674`](../../../crates/vole-act/src/circuit.rs#L655-L674),
[`issuer.rs:291-301`](../../../crates/vole-act/src/protocol/issuer.rs#L291-L301)).

This retains Algorithm 7's crucial proof direction—program a target-hash point
which the adversary could not predict before the signer chose its salt—but not
its exact syntax.  The comparison is:

| Step | Round-2 `MAYO.Sign` | Implemented VOLE-ACT wrapper |
|---|---|---|
| Message preprocessing | `M_digest=SHAKE256(M)` | Base `C` was separately proved as a credential hash |
| Salt | `SHAKE256(M_digest||R||seed_sk)` | Independent uniform 32-byte issuer salt |
| Target | `SHAKE256(M_digest||salt)` | One domain-separated hash of `pack16(C)||enc64(return)||zeta` |
| Sampling coins | Derived from digest, salt, secret seed, counter | Supplied by the caller's cryptographic RNG |
| Signature object | `EncodeVec(s)||salt` | Protocol response/token carries bare field vector plus `zeta` |

Accordingly, the following pieces are **inherited as a template** from Theorem
1: fresh-point programming, the OV transition, MTWMQ extraction, and the need
to pay salt-prequery/collision and sampler-rejection terms.  The following are
**adapted obligations**: the exact 256-bit uniform-salt bound, one-hash encoding,
local random sampler distribution, and stateful retry accounting.  The
classical-ROM theorem for that adaptation is still open; Algorithm 7/8 cannot
be cited as if the wrapper were byte-for-byte standard MAYO
[mayo-r2][mayo-r2].

## 3. What the papers say about whether salt is necessary

There is a real source-level tension that should not be papered over.

PoMFRIT footnote 3 says that MAYO's random salt is included only as a
countermeasure against side-channel and fault-injection attacks, is unnecessary
for security, and can be omitted in its blind-signature design
[baum26][baum26].

The current Round-2 MAYO specification gives a more qualified account.  Section
5.3 says the salt length controls a term corresponding to the event that the
adversary queried the target hash input before the signer emitted the
signature.  It says no attack is known even if salt is removed, but nevertheless
chooses salt lengths that make the proof term small; it then adds that salt also
provides fault-injection and side-channel protection [mayo-r2][mayo-r2].

Therefore the strongest statement justified by both sources is:

> The MAYO authors report no known attack caused merely by salt removal, and
> PoMFRIT intentionally analyzes a simplified saltless wrapper, but the current
> official Round-2 EUF-CMA bound itself contains salt-dependent terms.

It would be an overstatement to cite the Round-2 theorem as a verbatim proof of
the saltless PoMFRIT simplification without explaining this gap.  PoMFRIT takes
ordinary MAYO EUF-CMA as the Section-5 primitive-level premise and provides a
proof sketch at that abstraction layer; its footnote, rather than a new detailed
saltless-MAYO reduction, is the support it gives for omission.

## 4. Signature sampling versus public-map inversion

The ordinary MAYO proof simulates signing queries by sampling a domain point
`s`, computing `P*(s)`, and programming the target hash at a fresh salted input.
Round-2 Section 5.2, Lemma 2 and its game sequence make this simulation
explicit [mayo-r2][mayo-r2].  The full-rank/restart analysis is what lets the
real trapdoor-sampled signature distribution be replaced by this public
sampling strategy up to a quantified loss.

This is the deep reason the hash matters in the conservative design: it gives
the reduction a fresh programmable place at which to install `P*(s)`.  A direct
target inversion API removes that freedom.  The reduction is then handed `t`
and must return an `s` satisfying `P*(s)=t`; evaluating the public map on a
chosen `s` no longer answers the query.  PoMFRIT's one-more assumption supplies
exactly the missing inversion-oracle capability.

This argument is about the direction of simulation:

```text
ordinary hash-and-sign simulation:
    choose s -> compute t=P*(s) -> program H(message,salt)=t

direct-target API:
    receive t -> must compute s with P*(s)=t
```

Merely proving that some hash was computed does not restore the first direction.
The hash must sit at the programmable target-setting point, and its input must
be fresh under the proof's game hops.

## 5. Status ledger

| Claim | Status |
|---|---|
| MAYO EUF-CMA reduces to OV + MTWMQ with the stated ROM losses | **Proved conditionally**, Round-2 Theorem 1 |
| The Round-2 reduction stays within a constant factor for MAYO2 below about `2^19` signatures per key | **Stated quantitative theorem consequence**, Section 5.3 |
| MAYO remains secure for unbounded signatures | **Authors' expectation**, explicitly beyond what the proof guarantees |
| MTWMQ is hard at proposed parameters | **Conjectured** and supported by cryptanalysis, not proved from a standard problem |
| One-more resistance follows from MTWMQ | **Not proved** in the cited sources |
| Salt removal has no practical attack | **Authors report no known attack**; not an impossibility theorem |
| Salt is absent from every relevant security proof | **False** for the current Round-2 proof, which has salt-dependent terms |
| A fresh hash input lets the ROM simulator program `P*(s)` | **Proved technique** in MAYO's EUF-CMA game sequence |
| The same technique automatically applies to a concrete external protocol | **Inference requiring a protocol-specific reduction** |
| VOLE-ACT now places a uniform issuer salt in the target-setting hash | **Implemented and tested**; same simulation direction as MAYO |
| Round-2 Theorem 1 proves the exact VOLE-ACT wrapper | **False**; syntax, salt derivation, sampling, state, and proof composition differ |
| OV plus MTWMQ is the intended primitive foundation for the wrapper | **Plausible conditional route**; adapted classical-ROM theorem remains open |
| The 256-attempt cap fails with probability at most `B^256` | **Not established**; Lemma 1 gives an average over generated keys, not a uniform per-key bound |

[Back to paper analysis](index.md)

[mayo-r2]: ../sources.md#mayo-r2
[beullens22]: ../sources.md#beullens22
[baum26]: ../sources.md#baum26
