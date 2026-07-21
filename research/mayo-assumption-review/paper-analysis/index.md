# What PoMFRIT actually says about plain and one-more MAYO

## Bottom line

The colleague's central distinction is correct, but the phrase "if you are
proving Keccak anyway" needs to be made considerably more precise.

PoMFRIT contains two genuinely different constructions:

1. Section 5, **Blind Signatures from Plain MAYO**, asks the issuer to run the
   ordinary MAYO signing algorithm on a commitment.  The final proof establishes
   knowledge of an opening of that commitment and a valid ordinary MAYO
   signature.  Theorem 5.1 reduces one-more unforgeability of the blind
   signature to ordinary MAYO EUF-CMA security, commitment binding, and NIZK
   extraction.  It does **not** invoke PoMFRIT's one-more-preimage assumption
   [baum26][baum26].
2. Section 6, **Blind Signatures from One-More-MAYO**, removes the hash-to-target
   step from MAYO verification.  The issuer applies the trapdoor preimage
   sampler directly to a field target `t = H(mu, pi1) + r`, and the final proof
   establishes `T*(s) = H(mu, pi1) + r`.  Theorem 6.1 explicitly assumes the
   `(n,q)` one-more-preimage property of Definition 3.1 [baum26][baum26].

Thus Definition 3.1 is an assumption for the optimized, direct-target
construction, not a prerequisite for PoMFRIT's conservative construction.
The ePrint landing page identifies this paper as ePrint 2026/109. The checked
USENIX Security 2026 prepublication numbers the relevant game **Definition
3.1**; the colleague called it Definition 8, so use the semantic name and see
the [source and numbering note](#source-and-numbering-note).

The important test is not merely whether some Keccak computation occurs.  The
test is whether a hash-to-MAYO-target edge remains in the proved relation:

```text
plain route:
    hidden message/opening -> commitment -> MAYO hash-to-target -> T*(s)

optimized route:
    public H(message, pi1) + hidden committed mask r -> target -> T*(s)
                                                     (no target hash here)
```

In the optimized route there is still a hash `H(mu, pi1)`.  PoMFRIT calls the
route "hash-free MAYO" because it eliminates the hash *between the value being
signed and the MAYO target*, and because the remaining hash is computed on
public data rather than proved inside the NIZK.  The mere presence of that
remaining hash does not turn the direct preimage oracle back into an ordinary
signature oracle [baum26][baum26].

## Dependency map

| Layer | Exact primary-source result | Security basis stated by source | Status |
|---|---|---|---|
| Plain PoMFRIT | Section 5, Algorithm 1, Theorem 5.1 | Ordinary MAYO EUF-CMA, commitment binding/hiding, NIZK properties | **Proved as a reduction sketch** in PoMFRIT |
| Optimized PoMFRIT | Section 6, Algorithm 2, Theorem 6.1 | Definition 3.1 `(n,q)` one-more preimage resistance, plus NIZK/RO properties | **Proved conditionally** on the new assumption |
| Ordinary MAYO | MAYO Round-2 specification, Section 5.2, Theorem 1 | OV indistinguishability and Multi-Target Whipped MQ in the ROM, with explicit failure/loss terms | **Proved conditionally and only in the theorem's query range** |
| `(1,0)` PoMFRIT OMPR | PoMFRIT Section 3.3 calls this the ordinary Whipped MQ preimage leg | Structured `TrapGen` key, one random target, no inversion calls | **Defined/conjectured; random-map WMQ additionally needs the OV transition** |
| General one-more MAYO | PoMFRIT Definition 3.1 and Appendix A | Produce `q+1` preimages for distinct random challenge targets after at most `q` trapdoor-inversion queries | **New conjectured assumption**, not reduced to plain Whipped MQ |

"The plain MAYO problem" is therefore imprecise shorthand.  Ordinary MAYO's
published EUF-CMA reduction has two computational legs: the OV problem for
distinguishing/recovering the hidden oil-space structure, and the Multi-Target
Whipped MQ problem for inversion of the public whipped map.  PoMFRIT's Table 1
reflects this by listing `UOV/WMQ` for its conservative variants and
`UOV/One-More-WMQ` for its optimized variants [baum26][baum26]
[mayo-r2][mayo-r2].

The query range is not a cosmetic footnote.  Round-2 Section 5.3's advantage
bound loses the multiplicative factor `(1-Qs*B)^-1`—equivalently, the
simulator retains a success factor `(1-Qs*B)`—where `B` is the
joint-key-and-vinegar rank-restart bound used in the signing game.  For MAYO2
it estimates `B` at about `2^-20`, so the source
claims only a constant-factor leakage loss for fewer than about `2^19`
signatures per key.  Once `Qs*B > 1`, it explicitly says the proof gives no
guarantee.  The authors *expect* security even for unboundedly many signatures
and report no attack exploiting the leakage, but that is belief and
cryptanalytic evidence, not the theorem [mayo-r2][mayo-r2].

## What "proving Keccak" must mean

The following is a source-grounded inference, not a theorem stated for
VOLE-ACT in PoMFRIT:

> If an external protocol's proof establishes an ordinary MAYO verification
> relation on a well-defined signed message---including the hash-to-target
> operation---then the PoMFRIT Section-5 proof pattern is the relevant starting
> point, and PoMFRIT Definition 3.1 should not be imported merely because the
> protocol uses the MAYO trapdoor.

Four qualifications prevent this from becoming the false slogan "any Keccak
anywhere implies plain MAYO":

1. The proved Keccak output must be the target equated with `T*(s)`, or must be
   part of an ordinary MAYO verifier that derives that target.  A different
   commitment hash elsewhere in the circuit is irrelevant to this distinction.
2. The value hashed must have an unambiguous role as the signed message.  The
   reduction must map each successful protocol credential to a valid ordinary
   MAYO signature on a message.
3. The issuer interface and retry semantics must be simulatable by the chosen
   MAYO signing algorithm.  In particular, salts, deterministic versus
   randomized signing, and repeated requests cannot be silently discarded.
4. The source proofs are ROM proofs.  A Keccak circuit in an implementation is
   not, by itself, a proof that concrete Keccak may be programmed as a random
   oracle, and none of the cited results supplies a VOLE-ACT-specific QROM
   reduction.

These qualifications are why the colleague's architectural point is strong but
does not by itself complete the reduction for another protocol.

## Applying the distinction to the implemented signer-salted wrapper

The working implementation now passes the topological test above.  It no
longer asks `SPre` to invert the client-fixed base commitment `C`.  After the
issuance or spend proof verifies, the issuer samples a uniform 256-bit salt
`zeta` and signs

```text
Y = SHAKE256(
      "VOLE-ACT/signed/v3" || pack16(C) || enc64(return) || zeta
    )[0:4m].
```

The response is `(zeta,sigma)` with `P*(sigma)=Y`; a later spend circuit proves
the base-commitment opening, recomputes this exact salted target, and checks the
MAYO equation.  Direct credentials use return zero, so both credential kinds
now have the same signed relation
([`circuit.rs:139-168`](../../../crates/vole-act/src/circuit.rs#L139-L168),
[`circuit.rs:655-674`](../../../crates/vole-act/src/circuit.rs#L655-L674),
[`issuer.rs:148-180`](../../../crates/vole-act/src/protocol/issuer.rs#L148-L180),
[`issuer.rs:291-301`](../../../crates/vole-act/src/protocol/issuer.rs#L291-L301)).

This changes the assumption diagnosis:

- **Inherited composite proof shape:** PoMFRIT Section 5 supplies the
  message/signature extraction layer, while the Round-2 MAYO proof supplies the
  lower-level classical-ROM simulation which chooses `sigma`, computes
  `P*(sigma)`, and programs the target hash at a salt point which was
  unpredictable before issuer action [baum26][baum26] [mayo-r2][mayo-r2].
- **Adapted, not inherited theorem:** VOLE-ACT uses one direct
  message-plus-uniform-salt hash.  Round-2 Algorithm 7 instead hashes the
  message to a digest, derives its salt from that digest, `R`, and `seed_sk`,
  then hashes digest-plus-salt.  Theorem 1 therefore supplies a proof template
  and assumption package, not a verbatim theorem for these bytes
  [mayo-r2][mayo-r2].
- **No longer the old one-more interface:** repeated authorized issuance of
  one `C` samples a new salt and hence a new target except on a charged
  salt/hash collision.  Exact successful spend retries replay their stored
  salt and preimage.  The implemented public interface does not return fresh
  preimages of one requester-fixed target.
- **Still open:** the adapted classical-ROM game sequence, local `SPre`
  distribution and 256-attempt cap, adaptive extraction for the stateful
  protocol, fixed-Keccak/ideal-XOF bridge, and QROM proof are not discharged by
  PoMFRIT or the MAYO specification.

Thus the colleague's proposed direction is now reflected in the code, but the
correct security sentence is conditional: the intended foundation is ordinary
MAYO's OV-plus-MTWMQ package through an adapted salted-wrapper reduction, not
PoMFRIT's one-more-preimage premise and not yet a completed theorem.

## A subtlety that matters: random targets do not collapse one-more to plain

PoMFRIT's optimized issuer target is statistically hidden by the NIZK-committed
mask `r`.  The proof of Theorem 6.1 therefore embeds random challenge targets
from Definition 3.1.  This does **not** make plain inversion sufficient: the
adversary is also given up to `q` calls to the trapdoor preimage sampler and must
then account for `q+1` distinct targets.  Plain Whipped MQ is only the no-oracle
special case `(1,0)` [baum26][baum26]. That case still samples a structured
`TrapGen` key; identifying it with random-map WMQ suppresses the separate OV
hybrid used in MAYO's foundational proof.

Appendix A explicitly identifies the extra capability: the one-more adversary
can obtain preimages for outputs through the preimage oracle, unlike an ordinary
MAYO forger whose targets come through the hash-and-sign interface.  The
appendix reports two unsuccessful attack ideas, but it also gives a
multicollision-based separation showing that the oracle capability is genuinely
different and concludes that a new assumption is needed for that proof.  This
is evidence for plausibility, not a reduction of one-more resistance to plain
Whipped MQ [baum26][baum26].

## Source and numbering note

The ePrint page for 2026/109 and the USENIX prepublication have the same title
and authors [baum26][baum26]. The checked USENIX
prepublication labels the one-more game **Definition 3.1**. The colleague called
it "Definition 8," plausibly using alternate manuscript or publication
numbering; this review did not independently retrieve the current ePrint PDF.
The semantic identifier `(n,q)` one-more-preimage resistance is therefore safer
than a bare definition number.

There is a second numbering wrinkle: PoMFRIT says its `(1,0)` case is the
Whipped MQ problem of its reference `[11, Definition 4]`, while the accessible
SAC 2021 paper numbers **UOV** as Definition 4 and **Whipped MQ** as Definition
5 [beullens22][beullens22].  The current Round-2 specification instead calls
its evolved multi-target version Definition 2 [mayo-r2][mayo-r2].  These are
bibliographic/version issues, not different conclusions about the assumption
hierarchy.

## Detailed documents

- [Exact construction and theorem comparison](plain-vs-one-more.md)
- [MAYO assumptions, hash-to-target, and salt semantics](mayo-foundations.md)
- [A protocol-level decision test derived from the papers](translation-test.md)

[Back to the corpus index](../index.md)

[baum26]: ../sources.md#baum26
[mayo-r2]: ../sources.md#mayo-r2
[beullens22]: ../sources.md#beullens22
