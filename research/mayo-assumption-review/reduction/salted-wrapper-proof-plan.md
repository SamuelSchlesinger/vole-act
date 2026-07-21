# Classical ideal-XOF reduction for the implemented salted wrapper

This is the strongest proof plan presently justified for the implemented
protocol. It gives an exact game sequence and loss ledger, but it is still a
paper-level classical ideal-XOF argument. It is not a finished theorem for the
local proof system, fixed Keccak-f[1600], or quantum queries.

## 1. Exact implemented primitive

Fix one MAYO parameter set, expanded public map `P*`, and protocol context. A
base commitment `C in GF(16)^m` already binds the context through the
credential-v2 XOF. The wrapper message is exactly

```text
M(C,t) = "VOLE-ACT/signed/v3" || pack16(C) || LE64(t).
```

It omits a repeated context and public-key hash. The implementation's reason is
concrete: the base commitment already binds `context`, while the shorter v3
encoding leaves room for the 32-byte salt inside one SHAKE256 rate block even
for MAYO5. For a fixed parameter set, `pack16(C)` and `LE64(t)` have fixed
lengths, so the encoding is injective. Cross-context or cross-key use relies on
the credential-prefix binding explained in the fiscal lemma.

After verifying an issuance or spend proof, and after choosing a deferred
return `t`, the issuer runs

```text
zeta <- uniform {0,1}^256
y    <- Hsig(M(C,t) || zeta)[0:4m]
s    <- SPre(sk,y)
return (s,zeta,t).
```

Direct issuance and fixed spends use `t=0`. The token stores `s,zeta,t`; its
next spend proof verifies the base opening, nullifier, effective balance, and
`P*(s)=Hsig(M(C,t)||zeta)`.

This is not Round-2 `MAYO.Sign`. It has no preliminary message digest and
samples the transmitted salt directly from the caller-supplied RNG rather than
deriving it from `seed_sk` and optional `R`. The MAYO proof is a template, not
a theorem which applies verbatim.

## 2. Query and event counts

Use the following separate counts.

- `Q_s`: fresh response pairs visible to the adversary: every successful
  issuance response plus one winning stored response for each newly consumed
  spend nullifier. Replays of an existing pair do not increment `Q_s`.
- `Q_try`: an a priori hard experiment-level maximum on calls reaching
  `sign_token_target`, including issuance calls, spend race losers, attempts
  followed by storage failure, and calls returning observable
  `PreimageSamplingFailed`. Each call is one sampler invocation containing at
  most 256 internal rank attempts. This count governs the bounded-sampler term.
- `Q_h`: adversarial queries to the signed-v3 ideal-XOF domain.
- `Q_cred`: total distinct credential-v2 ideal-XOF inputs across adversarial
  grinding, honest protocol calls, reduction-generated values, and extracted
  accepted proofs.
- `Q_cpl`: the sampler-coupling count, equal to `Q_s` under the required
  response-oblivious winner-selection premise. Without that premise, simply
  setting `Q_cpl=Q_try` is not known to simulate the retry-count/timing trace;
  a separate race-leakage lemma is required.

The store makes the distinction operationally important. An exact successful
spend retry returns the stored `(s,zeta,t)` before proof verification or
signing. Concurrent same-digest calls may compute several candidates, but the
linearizable `insert_if_absent` returns one durable winner to every successful
caller. A conflicting digest receives an error. A losing candidate, or a
candidate followed by storage failure, is not released. Issuance has no such
store: each successful authorized call is one new visible response.

Conditioned on no `SPre` failure and no storage violation, invisible race
candidates can be erased from the adversary's view only if rejected candidates
remain confidential and winner selection is oblivious to candidate contents,
internal retry count, and secret-dependent completion behavior. Under that
premise the winning pair is an honest fresh sample and all repeats replay it,
so the sampler hybrid sets `Q_cpl=Q_s` while the code-failure term counts
`Q_try`. Without the premise, the reduction is incomplete: counting all
candidates does not by itself simulate winner identity when sampler time is
visible through first arrival.

## 3. Primitive game sequence

### Game 0: real wrapper in the classical ideal-XOF model

Generate the structured local MAYO key. Run the exact verification, salt,
sampler, retry, and winner semantics above, treating the domain-separated
SHAKE calls as one prefix-consistent ideal XOF and the caller RNG as an
independent uniform source.

The RNG qualification is substantive: the Rust API accepts caller-supplied
`CryptoRngCore` values. Independence across calls and replicas is a deployment
premise, not a type-system guarantee.

### Game 1: remove bounded-sampler and state failures

Replace the 256-attempt local `SPre` with its ideal unbounded rejection-sampler
semantics and normalize the observable store behavior to one winner per
nullifier. Charge storage rollback/publication failures separately.

Let `p_K` be the rank-failure probability of one fresh vinegar attempt for a
fixed generated key `K`. Independent RNG attempts make one local call exhaust
with probability `p_K^256`. Round-2 Lemma 1 chooses `O` uniformly, then `P`
uniformly from `MQ(O)`, and also chooses the vinegar tuple uniformly; it gives
the average statement

```text
E_K[p_K] <= B,
B = q^(k-(n-o))/(q-1) + q^(m-ko)/(q-1).
```

It is not a uniform per-key bound: the zero public map is an immediate
counterexample to such an interpretation. Therefore the cited lemma alone
justifies only

```text
delta_cap <= Q_try * E_K[p_K^256] <= Q_try * B,
```

not `Q_try*B^256` [mayo-r2][mayo-r2]. A much smaller cap term needs a
higher-moment, bad-key-tail,
or per-key result not present in the specification. This bound is conservative
and can dominate concrete claims; it is an unresolved code-level proof issue,
not evidence of a practical failure rate.

The local code otherwise mirrors Algorithm 7's algebra: each attempt samples
fresh vinegar vectors and a uniform solution seed `r`, rejects unless the
`m x ko` system has full row rank, and uses `sample_solution`. For full-rank
`A`, the nonpivot coordinates remain uniform and the pivot coordinates are the
unique affine completion, so the result is uniform in the solution fiber.
Turning that observation and the implementation's elimination code into a
code-level lemma remains an obligation.

### Game 2: require fresh salted signing points

Abort when a fresh visible response would use an input `M||zeta` which the
adversary queried earlier, or which was already used by an earlier response on
the same `M`. For independent uniform 256-bit salts,

```text
delta_salt
  <= Q_s*Q_h/2^256 + Q_s*(Q_s-1)/(2*2^256).
```

The first term is salt prequery; the second is same-message salt repetition.
Repeating a salt on a different fixed-length `M` is harmless because it is a
different XOF input. Exact stored retries are replays, not fresh response
events, and incur neither term again.

### Game 3: public-sampling signer

At each fresh salted signing point, choose

```text
s <- uniform GF(q)^(kn),
y := P*(s),
Hsig(M||zeta) := y,
```

and return `(s,zeta)`. Freshness from Game 2 makes the programming consistent.
The Round-2 Game-3-to-Game-5 coupling shows that the joint real distribution
`(uniform y, SPre(sk,y))` agrees with this public-sampling distribution when
the corresponding vinegar is good. A union bound over the `Q_cpl` coupled
candidates retains probability at least

```text
1 - Q_cpl*B.
```

Thus the multiplicative advantage loss is `(1-Q_cpl*B)^-1`, under the explicit
condition `Q_cpl*B<1` [mayo-r2][mayo-r2]. Unlike the old unsalted
credential-target simulator, no
offline credential grinding point is changed to `P*(s)`; only fresh response
points are programmed. This is the precise reason the count is `Q_s`, not
`Q_h` or the former `Q_prog`, under the response-oblivious winner-selection
premise.

### Game 4: OV hybrid

Replace the structured public quadratic map with a uniformly random quadratic
map using the OV assumption. The implementation exposes expanded whipped
forms and derives `context` from their hash, so a finished hop must show that
the OV challenger can be encoded into exactly those public forms and that the
resulting context and all statements are distributed as claimed. This is a
separate hop; it cannot be hidden inside “plain Whipped MQ.”

### Game 5: MTWMQ extraction

In the random-map game, answer each previously unprogrammed signed-v3 target
query with the next random target supplied by the MTWMQ instance. Continue to
answer credential-v2, proof-transcript, context, request-digest, and other
domains as independent portions of the global domain-separated ideal XOF.

If the adversary forges `(M,zeta,s)` for a message `M` never sent to the
wrapper signer, then `M||zeta` is not a programmed signing point. Except with
the `q^-m` probability of producing a valid result without first querying that
point, it names an MTWMQ target and `s` is its preimage.

No separate wrapper-output collision abort is required for this extraction.
If an unprogrammed random target happens to equal a programmed signing target,
reusing the known signing preimage directly solves that MTWMQ target. What
must be injective is the **input/message** mapping used by the fiscal lift, not
the random oracle's codomain.

## 4. Fiscal lift

The reduction maintains the [nullifier-class ledger](fiscal-to-fresh-target.md)
online. Its straight-line extractor runs immediately after each spend proof is
accepted and before the issuer signs the current output. At the first orphan
semantic descriptor `tau=(u,t)`, after proof, arithmetic, authorization, RNG,
and state failures are removed, it sets

```text
M = "VOLE-ACT/signed/v3" || pack16(C(u)) || LE64(t).
```

If this exact `M` was signed earlier, either the same semantic descriptor was
authorized, contradicting orphanhood, or another credential opening produced
the same `C`. Charge the latter to a credential-prefix collision. Therefore
the reduction outputs the extracted `(M,zeta,s)` and halts before the current
output or any later call can submit `M` to the signer. It is therefore an
ordinary EUF-CMA forgery for the wrapper.
Alternate salts on an already signed `M` do not create credit and are not used
as forgeries.

For uniform `4m`-bit credential prefixes, a conservative classical collision
term over the global `Q_cred` distinct inputs is

```text
delta_cred_coll <= Q_cred*(Q_cred-1)/(2*2^(4m)).
```

`Q_cred` includes adversarial offline grinding, so the bound is not limited to
accepted or extracted openings. Any accepted proof whose hidden credential
input was never queried to the
ideal XOF adds the corresponding `2^(-4m)` guessing term. Exact accounting
depends on the adaptive extractor interface.

## 5. Schematic advantage statement

Let `epsilon_fisc` be fiscal advantage and collect proof-extraction,
authorization, arithmetic, parser, RNG, store, and ideal-XOF-model failures in
`delta_protocol`. Let `Adv_OV` and `Adv_MTWMQ` refer to the exact parameter set
and query-bounded reductions. The intended classical bound has the shape

```text
epsilon_fisc
 <= delta_protocol
  + delta_cap
  + delta_salt
  + delta_cred_coll
  + delta_unqueried
  + (Adv_OV + Adv_MTWMQ) / (1 - Q_cpl*B),
```

where `Q_cpl*B<1` and `Q_cpl=Q_s` under response-oblivious winner selection.
This is schematic until the extractor, expanded-key OV hop,
and local sampler coupling are proved, but every displayed term now has a
specific event and query counter. The numerical MAYO2 and salt calculations
are reproduced by
[`data/salted_wrapper_loss.py`](data/salted_wrapper_loss.py).

## 6. What is proved, assumed, and open

- **Established from code:** exact v3 bytes, salt timing, common wrapper for
  both token forms, response encodings, and nullifier-keyed winner/replay
  semantics.
- **Established from Round-2:** the ideal sampler coupling, formula for `B`,
  its native signing-query loss boundary, and OV/MTWMQ proof architecture.
- **Paper-level here:** mapping the local protocol to `Q_cpl=Q_s` under
  response-oblivious race erasure, fiscal-to-unsigned-message accounting, and
  the wrapper's adapted classical-ROM games.
- **Still required:** adaptive shared-oracle extraction for the local proof,
  exact expanded-key OV encoding, a code-level `sample_solution` proof, a
  useful bound for the 256-attempt cap under one reused key, and exact query
  counts.
- **Not claimed:** a QROM proof or a reduction for the fixed Keccak circuit.

[Back to the reduction index](index.md)

[mayo-r2]: ../sources.md#mayo-r2
