# Classical-ROM simulator for the implemented issuer

The signer-salted implementation removes the old simulator's same-target
obstruction. This document gives the concrete table algorithm and explains
which real executions count as fresh signing samples.

## 1. Oracle tables

Model SHAKE256 as one prefix-consistent ideal XOF with injectively separated
domains. The important tables are:

```text
Cred[input]  = C || N || ...
Signed[M || zeta] = (y, optional_known_preimage)
Store[nullifier]  = (request_digest, response_kind, s, zeta, optional_t)
```

The exact signed message is

```text
M = "VOLE-ACT/signed/v3" || pack16(C) || LE64(t).
```

It contains neither `context` nor the MAYO-key hash a second time. `C` is the
first `4m` credential-v2 bits and thereby binds the derived context. The proof
must charge a credential-prefix collision before using that transitive binding.

Other SHAKE roles—proof transcript, vector commitments, context derivation,
request digest, and public-key hash—occupy distinct encoded domains. A formal
oracle-aided relation must preserve the credential stream's prefix consistency
between `C` and the later 256 nullifier bits.

## 2. Public-sampling response algorithm

After a request proof verifies, the simulator knows public `C`; for deferred
settlement it also fixes public `t`. It answers a fresh response event as:

```text
M := EncodeSignedV3(C,t)
zeta <- uniform {0,1}^256
if Signed already contains M||zeta: abort SaltFresh
s <- uniform GF(q)^(kn)
y := P*(s)
program Hsig(M||zeta)[0:4m] := y
return (s,zeta,t)
```

The adversary may choose and prehash arbitrarily many `C,t` values, but cannot
predict the later 256-bit suffix except with the salt-prequery probability.
Thus only response points are programmed as public-map images. Every other
signed-v3 query remains an honest random target and, after the OV hop, can be
supplied directly by the MTWMQ challenger.

The real-to-simulated response distribution is not exact. The Round-2 coupling
conditions on the sampled vinegar map having full rank and pays the factor
`(1-Q_s B)^-1` under response-oblivious winner selection. See
[distribution and losses](distribution-and-losses.md).

## 3. Exact issuance, retry, and race accounting

### Issuance

`Issuer::issue` has no retry store and takes `&self`. Every successful accepted
call samples a new salt and calls `SPre`; it contributes one fresh visible
response to `Q_s`. Repeating the identical authorized request is another
response event. The surrounding service must count or deduplicate payment
authorization independently; the library does not do so [issuer-issue].

### Successful spend replay

Before proof verification or signing, each spend looks up the consumed input
nullifier. A matching stored request digest and response kind returns the
stored `(s,zeta,t)`. It neither queries a new salted point nor increments
`Q_s`. A conflicting digest or settlement kind is rejected [issuer-spend]
[store].

For deferred settlement, `t` is out-of-band and absent from the request digest.
After one response wins, every exact request retry returns the winner's stored
`t,s,zeta`, even if the caller supplies a different new return value.

### Concurrent candidates

Across replicas, several calls can observe an empty nullifier and compute
candidates before `insert_if_absent`. The atomic store returns the durable
winner. For a same-digest race, all successful callers receive that winner;
for a conflicting request, the loser receives an error. Losing candidate salts
and preimages are erased and never released.

Conditioned on sampler success, loser confidentiality, and winner selection
that is oblivious to candidate bytes and secret-dependent completion behavior,
this visible behavior is distributionally one fresh winner followed by
replays. Under that premise the simulator need not manufacture invisible
candidates. Merely paying coupling loss for every candidate does not simulate
winner identity when first arrival correlates with the variable number of
sampler attempts; without the premise a separate race-leakage game is needed.
We therefore use:

```text
Q_s   = fresh visible winning response pairs,
Q_try = an a priori hard experiment-level maximum on calls reaching salt
        generation and SPre, each of which makes at most 256 rank attempts.
```

`Q_s` enters salt freshness and, under the response-oblivious race premise,
the public-sampling coupling. `Q_try` enters the conservative code-cap failure
term. A storage error releases
no response and contributes no fresh signature, though its preceding sampler
invocation is included in `Q_try`. `PreimageSamplingFailed` is observable, so
the experiment must enforce the hard cap rather than derive it from expected
adversary running time.

## 4. MTWMQ challenge extraction

After the public-sampling and OV games, answer each unprogrammed signed-v3
query with the next random MTWMQ target. Suppose the fiscal extractor returns
an orphan semantic descriptor `(u,t)` with signature `(zeta,s)`.

Outside a credential-prefix collision, `M(C(u),t)` was never signed. Hence its
point `M||zeta` was not programmed by the response simulator. If the adversary
queried it, the table identifies an MTWMQ target and `P*(s)` equals that target.
If it did not query, validity costs the `q^-m` random-target guessing term.

An output collision between this target and a programmed signing target does
not break extraction: the same `s` is then already a solution to the random
MTWMQ target. Input freshness, not codomain uniqueness, is decisive.

## 5. Why the old obstruction is gone

The pre-wrapper implementation accepted a client-fixed target and returned
fresh `SPre` samples on repeats. A simulator which planted one preimage could
not reproduce a second independent trapdoor sample. In the implemented v3
wrapper, independently accepted calls choose independent signer salts and
therefore fresh hash inputs except on `SaltFresh`. Exact spend retries replay
one stored pair.

This removes the specific need for an inversion oracle in the simulation. It
does not by itself complete security: the sampler coupling, fiscal lift,
adaptive extraction, expanded-key OV hop, concrete-Keccak bridge, and local
failure terms remain explicit obligations.

[Back to the reduction index](index.md)

[issuer-issue]: ../../../crates/vole-act/src/protocol/issuer.rs#L148
[issuer-spend]: ../../../crates/vole-act/src/protocol/issuer.rs#L182
[issuer-deferred]: ../../../crates/vole-act/src/protocol/issuer.rs#L206
[store]: ../../../crates/vole-act/src/protocol/store.rs#L167

[mayo-r2]: ../sources.md#mayo-r2
