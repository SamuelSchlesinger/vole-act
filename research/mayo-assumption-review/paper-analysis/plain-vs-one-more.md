# Exact comparison of PoMFRIT's two constructions

## 1. The conservative construction is an ordinary-signature wrapper

PoMFRIT Section 5 defines, for message `mu`, commitment randomness `r`, and an
ordinary MAYO signature `sig`, a circuit which accepts exactly when

```text
MAYO.Ver(pk, Com(cpk, mu, r), sig) = 1.
```

Algorithm 1 then has the following security-relevant topology:

```text
User:   com <- Com(cpk, mu, r)
Signer: sig <- MAYO.Sig(sk, com)
User:   prove knowledge of (r, sig) satisfying MAYO.Ver(...)=1
```

The signer never exposes `SPre(sk,t)` as a direct field-target oracle.  It
exposes the ordinary message-level signature algorithm `MAYO.Sig(sk,com)`
[baum26][baum26], Section 5, Algorithm 1, lines 3-13.

### What Theorem 5.1 establishes

Theorem 5.1 states correctness, blindness, and one-more unforgeability for
Algorithm 1.  Its unforgeability sketch extracts a commitment opening and an
ordinary MAYO signature from every accepted blind signature.  If an adversary
uses at most `Q` issuer interactions but outputs `Q+1` valid blind signatures on
distinct messages, commitment binding makes the extracted commitments distinct
(except if binding is broken).  At least one extracted commitment was therefore
not submitted to the signer's `Sig2` oracle, giving an ordinary MAYO EUF-CMA
forgery [baum26][baum26], Theorem 5.1 and its unforgeability proof.

This is a pigeonhole reduction at the **message/signature layer**:

```text
Q calls to MAYO.Sig on commitments
          +
Q+1 extracted valid MAYO message/signature pairs
          ->
one new signed commitment
          ->
MAYO EUF-CMA forgery.
```

**Proved versus assumed:** PoMFRIT proves this implication as a proof sketch,
conditional on binding/hiding of the commitment, the stated NIZK properties,
and ordinary MAYO EUF-CMA security.  Theorem 5.1 does not independently prove
the computational assumptions underlying MAYO.

## 2. The optimized construction exposes target inversion

PoMFRIT Section 6 replaces the ordinary commitment and ordinary MAYO signature
call with the following structure:

```text
User first proof stage:  (pi1, r, st) <- P1(C)
Public hash:             h <- H(mu, pi1)
Issuer target:           t <- h + r
Signer:                  s <- MAYO.SPre(sk, pk, t)
Final relation:          T*(s) = h + r.
```

This is Algorithm 2, lines 3-19.  The final circuit `C_(h,pk)` receives `(r,s)`
and checks `T*(s)=h+r`; it does not check `T*(s)=Hash(message encoding)` through
the ordinary MAYO verifier [baum26][baum26], Section 6.

Two points are easy to miss:

- The construction still hashes `(mu,pi1)`.  The optimization is not literally
  hashless; the remaining hash has public input and is outside the expensive
  proved relation.
- The mask `r` is not arbitrary after seeing `h`: it comes from the first NIZK
  stage and is hidden/uniform under PoMFRIT's NIZK definition.  Consequently
  `t=h+r` can be used to embed a random target in the reduction.

### Why Theorem 6.1 uses the one-more game

Theorem 6.1 explicitly assumes Definition 3.1.  Its reduction takes the random
targets supplied by the one-more challenger and associates them with the
adversary's random-oracle queries.  When the adversary requests issuer action,
the reduction spends one preimage-sampler query.  From `Q+1` final forgeries it
extracts `Q+1` preimages of distinct challenge targets, thereby winning the
one-more game after at most `Q` sampler calls [baum26][baum26], Theorem 6.1.

The reduction is therefore at the **target/preimage layer**:

```text
Q calls to SPre on challenge targets
          +
Q+1 extracted valid target/preimage pairs
          ->
win the (n,Q)-one-more preimage game.
```

There is no missing ordinary MAYO message whose signature is automatically an
EUF-CMA forgery.  The signer's API was deliberately moved below the MAYO
hash-and-sign layer.

## 3. Exact relationship between the hardness notions

PoMFRIT Definition 3.1 samples a key pair and `n` independent random codomain
targets, gives the adversary the public key and those targets plus oracle access
to the trapdoor preimage sampler, limits that oracle to `q` calls, and declares
success only if the adversary produces valid preimages for `q+1` **distinct**
challenge-target indices [baum26][baum26], Definition 3.1.

PoMFRIT immediately calls ordinary Whipped MQ the `(1,0)` special case. At the
level of its own `TrapGen`-key experiment, the ladder is:

```text
structured-key random-target preimage resistance
    = one target, zero inversion-oracle calls, one required preimage
    = (1,0)-OMPR

general OMPR
    = many random targets, up to q inversion-oracle calls,
      q+1 distinct required preimages.
```

The first game being a special case of the second does not prove that hardness
of the first implies hardness of the second.  Appendix A explicitly treats the
general game as a new assumption.  It reports no attack from requesting a
preimage of zero and no threatening attack from modest multicollisions, but it
also notes a separation in available multicollision size and concludes that a
new assumption is needed for the proof [baum26][baum26], Appendix A.

This shorthand must not erase the public-key distribution. PoMFRIT's game
samples `(sk,pk) <- TrapGen`, whereas Round-2 MTWMQ samples a uniform random
quadratic map. MAYO's OV hybrid is the separate bridge from the structured key
to that random-map problem.

**Conjectured, not proved:** General one-more resistance of the MAYO trapdoor.

**Proved conditionally:** Theorem 6.1's blind-signature security assuming that
general property.

**Inferred:** A protocol retaining ordinary hash-and-sign semantics should be
analyzed using the Section-5 reduction shape rather than automatically assuming
Definition 3.1.

## 4. Comparison table

| Question | Section 5 plain MAYO | Section 6 one-more MAYO |
|---|---|---|
| What does signer receive? | Commitment as an ordinary MAYO message | Field target `t=h+r` |
| Signer call | `MAYO.Sig(sk,com)` | `MAYO.SPre(sk,pk,t)` |
| Final proved relation | Ordinary `MAYO.Ver` plus commitment opening | `T*(s)=h+r` |
| Target-setting hash inside relation? | Yes, through ordinary MAYO verification | No |
| Hash remaining elsewhere? | Commitment hash and MAYO target hash | Public `H(mu,pi1)` |
| Extracted security object | Message/signature pair | Target/preimage pair |
| Main unforgeability basis | MAYO EUF-CMA | Definition 3.1 one-more preimage resistance |
| Computational assumptions listed in Table 1 | UOV/WMQ | UOV/One-More-WMQ |

## 5. Where the implemented VOLE-ACT wrapper sits

The implemented interface is neither column verbatim, but it now has the
security-relevant topology of the left column.  For the message descriptor
`M=(C,return)`, its signature object is `(zeta,sigma)` and its verification
equation is

```text
P*(sigma) = SHAKE256(
  "VOLE-ACT/signed/v3" || pack16(C) || enc64(return) || zeta
)[0:4m].
```

The issuer chooses `zeta` uniformly only after it accepts the request
([`issuer.rs:148-180`](../../../crates/vole-act/src/protocol/issuer.rs#L148-L180),
[`issuer.rs:195-238`](../../../crates/vole-act/src/protocol/issuer.rs#L195-L238),
[`issuer.rs:291-301`](../../../crates/vole-act/src/protocol/issuer.rs#L291-L301)).
The spend relation recomputes both the hidden base commitment and the salted
target before asserting `P*(sigma)=target`
([`circuit.rs:655-674`](../../../crates/vole-act/src/circuit.rs#L655-L674)).

That makes the following classification precise:

| Property | Implemented wrapper | Status relative to sources |
|---|---|---|
| Signer gets a message-level descriptor before fixing the target | Yes: public `C`, then public/issuer-chosen return, then hidden-until-response salt | Same simulation direction as Section 5 |
| Target-setting hash is verified in the later proof | Yes | Same topological role as ordinary MAYO verification |
| Requester chooses an already-fixed target sent directly to `SPre` | No | Section-6 one-more interface has been removed |
| Syntax equals Round-2 Algorithms 7/8 | No | Requires an adapted proof, not a citation shortcut |
| Primitive foundation expected after adaptation | OV plus MTWMQ, ROM losses, and sampler coupling | Inherited assumption package; transfer still open |

PoMFRIT Theorem 5.1 cannot simply be instantiated because VOLE-ACT is not its
commitment-and-NIZK blind-signature construction, and Round-2 Theorem 1 cannot
simply be instantiated because the wrapper is not `MAYO.Sign`.  What transfers
is a composite proof architecture: PoMFRIT's message/signature extraction idea
followed by MAYO's fresh salted programming and OV/MTWMQ games
[baum26][baum26] [mayo-r2][mayo-r2].

[Back to paper analysis](index.md)

[baum26]: ../sources.md#baum26
[mayo-r2]: ../sources.md#mayo-r2
