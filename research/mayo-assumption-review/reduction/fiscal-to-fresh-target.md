# From fiscal over-redemption to an unsigned wrapper message

This document isolates the combinatorial part of the implemented salted
protocol. It does not simulate the signer. Its output is an ordinary wrapper
forgery candidate: a valid signature on a semantic message which the issuer
never signed.

## 1. Base and wrapper descriptors

Fix one protocol context and MAYO public key. For

```text
u = (key, base_balance, nonce),
```

the credential XOF has the exact implemented input

```text
"VOLE-ACT/credential/v2" || context || key
    || LE64(base_balance) || nonce.
```

Its first `4m` bits encode the base commitment `C(u)` in GF(16)^m; the next
256 bits are the nullifier `N(u)`. A semantic token descriptor is

```text
tau = (u,t),
```

where `t=0` is the normalized direct value and is also a permitted deferred
return; a deferred return may be any value allowed by the settlement bound.
The local Rust marker is therefore not part of this semantic descriptor. Its
effective balance is `base_balance+t`. The message authenticated by the
implemented wrapper is exactly

```text
M(tau) = "VOLE-ACT/signed/v3" || pack16(C(u)) || LE64(t).
```

The v3 message deliberately does **not** repeat `context` or the MAYO-key hash.
The base commitment already binds `context`, and `context` is derived from the
MAYO public-key hash, application context, parameter set, and proof profile.
Omitting the repeated context keeps even the MAYO5 message, including its
32-byte salt, inside one SHAKE256 rate block. This transitive binding is valid
only outside a collision in the credential-prefix map
([`circuit.rs:17-24`](../../../crates/vole-act/src/circuit.rs#L17-L24),
[`circuit.rs:101-168`](../../../crates/vole-act/src/circuit.rs#L101-L168)).

For issuer salt `zeta in {0,1}^256`, define

```text
Y(tau,zeta) = Hsig(M(tau) || zeta)[0:4m].
```

A token is authenticated by `(zeta,s)` when `P*(s)=Y(tau,zeta)`. The spend
circuit proves the base opening and nullifier, the exact balance equations,
the common salted-wrapper equation for the old token, and an opening of the
fresh public commitment. The issuance circuit proves an opening of its public
base commitment before the issuer chooses `zeta` and signs the wrapper.

## 2. Signatures are not capabilities

For fixed `tau=(u,t)`, different salts and MAYO preimages are alternate
authenticators for the same semantic token. They all lead to `N(u)`. More
generally, all `(u,t')` share `N(u)`, even though their effective balances and
wrapper messages differ. The nullifier store permits at most one accepted
spend from this entire **nullifier-equivalence class**.

Consequently:

- repeated authorized issuance over the same opening may return fresh salted
  signatures but never creates a second lineage; the external system must
  authorize each new issuance operation, while an ambiguous retry under the
  same idempotency key must replay rather than re-sign or re-charge; only a
  distinct nullifier opening creates a distinct lineage;
- alternate signatures on one already authorized message do not constitute a
  fiscal forgery; and
- the reduction must find an unsigned semantic message `M(tau)`, not merely a
  new salt or a new preimage for an already signed message.

This is why ordinary EUF-CMA, rather than strong unforgeability, is the right
primitive notion for the salted wrapper.

## 3. Conservation over nullifier classes

Assume extraction supplies a valid witness for every accepted issuance and
spend proof. A capability occurrence is one exact authorized semantic
descriptor `tau=(u,t)`. Group occurrences by the store key `N(u)`. A class is
live exactly while that nullifier is absent from the durable store. For each
live class, define its capacity as the maximum effective balance among its live
authorized alternatives; alternatives in one class—including the zero-return
marker aliases—are mutually exclusive and must not be summed.

- An accepted issuance authorizes `(u,0)` with capacity contribution `b`.
- An accepted fixed spend consumes an input of balance `B`, redeems `s`, and
  authorizes a fresh `(u',0)` of balance `B-s`.
- An accepted deferred-return spend consumes an input of balance `B`, redeems
  `s-t`, and authorizes `(u',t)` of balance `B-s+t`.

The event-by-event potential argument is:

1. Authorizing a root or output of balance `v` raises its destination class's
   capacity by at most `v`, since `max(old,v)-old <= v`.
2. Spending an authorized alternative of balance `B` retires its input class,
   whose capacity is at least `B`. The circuit proves
   `redeemed + output_balance = B`; adding the output raises its destination
   capacity by at most `output_balance`.
3. If an output's destination nullifier is already consumed—including when it
   equals the current input nullifier—the output is operationally dead and does
   not enter the live sum. Retire the input class at the store linearization
   point before adding any still-live destination class.

Induction over the store's linearization order gives

```text
cumulative redemption + sum(live nullifier-class capacities)
    <= sum(externally authorized issuance balances),
```

provided every consumed exact semantic descriptor was authorized by an
issuance or earlier accepted output.

## 4. Earliest orphan and message freshness

If redemption exceeds authorized issuance, some accepted spend consumes an
**orphan semantic descriptor** `tau=(u,t)` which was not authorized by any
issuance or earlier accepted output. The reduction maintains the authorization
ledger online. Its straight-line extractor runs at the proof-verification
boundary and returns `u,t,zeta,s` before the issuer signs the current output.
At the first orphan it halts immediately, before calling `sign_token_target`
for that spend and before any later adversarial call, with

```text
P*(s) = Hsig(M(tau) || zeta)[0:4m].
```

If `M(tau)` was previously signed, then either:

1. the previous signing event authorized the same `u,t`, contradicting that
   `tau` is an orphan; or
2. a different base opening `u'` produced the same `C`, hence the same
   `M=(C,t)`, which is a credential-prefix collision.

Thus, outside the base-prefix collision event, the orphan yields a valid
wrapper signature on a message never submitted to the wrapper signer before
the reduction halts. Immediate halting makes this an EUF-CMA forgery: the
current output and later calls cannot retroactively submit `M(tau)`. A new
salt on an already signed `M` is deliberately not counted as a fiscal forgery.

No separate wrapper-output-collision exclusion is needed for this
unsigned-message conclusion. If an unsigned salted input hits the target of a
signed point, the reused preimage is still a valid signature on an unsigned
message. In the later random-map game it is also a solution to that random
MTWMQ target. The primitive reduction handles this event rather than aborting
the fiscal lift.

## 5. Required bad-event exclusions

The argument is conditional on all of the following.

- **Adaptive shared-oracle extraction.** Each accepted proof yields the old
  semantic descriptor, salt, MAYO preimage, nullifier, balances, and fresh
  commitment opening in one adaptive execution. Extraction is straight-line
  and online at proof acceptance, before the current output is signed, so the
  reduction can halt on the first orphan.
- **Faithful relation and encoding.** Extracted values satisfy the fixed
  credential-v2 and signed-v3 byte encodings, common wrapper equation, and
  exact 64-bit arithmetic checked by the implementation.
- **Linearizable, non-rollback state.** Nullifier consumption, publication of
  the winning response, and external redemption form one durable logical
  event. Losing race candidates are not released or logged, and winner
  selection is response-oblivious. Without that premise, including all
  candidates in the primitive coupling still does not simulate a
  first-arrival retry-count or timing trace; a separate race-leakage lemma is
  required.
- **External issuance accounting.** Authorization, durable charging, and
  client-visible response publication form one service-level event keyed by an
  external idempotency identifier. Ambiguous delivery replays that durable
  result; it must not call stateless `Issuer::issue` again. The library itself
  supplies no issuance-idempotency store.
- **No credential-prefix collision.** This supplies message injectivity from
  an extracted semantic opening to the public base commitment.
- **No unmodeled parser, request-digest, arithmetic, RNG, or storage failure.**

Ordinary nullifier equality is exactly the store's class identity. A genuine
suffix collision between otherwise different credential openings merges two
classes and normally rejects the later spend, causing denial of service rather
than inflation. Excluding that hash-collision event keeps the semantic-opening
accounting simple.

## 6. Exact conclusion

After the named proof, hash, arithmetic, authorization, RNG, and state failures
are removed, fiscal over-redemption yields one valid salted-wrapper signature
on one message the issuer never signed. This conclusion needs no one-more
counting. Turning that primitive forgery into OV or MTWMQ advantage is the
subject of the [salted-wrapper game sequence](salted-wrapper-proof-plan.md).

[Back to the reduction index](index.md)

[spend-circuit]: ../../../crates/vole-act/src/circuit.rs#L613
[issue-circuit]: ../../../crates/vole-act/src/circuit.rs#L504
