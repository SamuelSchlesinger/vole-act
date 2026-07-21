# Implemented oracle, call by call

[Back to the protocol-oracle index](index.md)

## Setup fixes the signing universe

An `Issuer` owns one MAYO trapdoor, the corresponding public protocol key, and
one nullifier/retry store
([`issuer.rs:8-13`](../../../crates/vole-act/src/protocol/issuer.rs#L8-L13)). Its
32-byte context is

```text
SHAKE256(
  "VOLE-ACT/context/v5" || len(application_context) || application_context ||
  mayo_public_key_hash || parameter_name || enc64(64) || enc64(tau) || enc64(k)
)
```

so it binds the caller's deployment/asset/key-epoch label, MAYO map, parameter
set, balance width, and VOLE profile
([`spend.rs:626-644`](../../../crates/vole-act/src/protocol/spend.rs#L626-L644)).
Restoring a trapdoor requires an explicit nullifier store because the key bytes
intentionally omit spent records
([`issuer.rs:80-117`](../../../crates/vole-act/src/protocol/issuer.rs#L80-L117)).

Two hash objects must be kept separate throughout the audit:

```text
base commitment: C = Cred(ctx,k,b,rho)
MAYO target:     Y = Signed(C,t,zeta)
```

The proof establishes facts about `C`; the MAYO signature authenticates `Y`.
The wrapper deliberately omits a second copy of `ctx`, because `C` binds it
outside a credential-prefix collision, and its 129-byte MAYO5 message remains
below one SHAKE256 rate block
([`circuit.rs:17-24`](../../../crates/vole-act/src/circuit.rs#L17-L24),
[`circuit.rs:699-704`](../../../crates/vole-act/src/circuit.rs#L699-L704)).

## Issuance

An honest client samples `key` and `nonce`, computes `C`, and proves knowledge
of that opening at the public, externally authorized balance. A malicious
client is not forced to sample a fresh opening: the issue circuit checks only
the existence of a satisfying opening
([`public_key.rs:100-141`](../../../crates/vole-act/src/protocol/public_key.rs#L100-L141),
[`circuit.rs:507-518`](../../../crates/vole-act/src/circuit.rs#L507-L518)).

The issuer operation is:

```text
Issue(b, C, pi):
    reject unless len(C) = m
    verify pi for exists (key,nonce): C = Cred(ctx,key,b,nonce)
    zeta <- uniform {0,1}^256
    Y <- Signed(C,0,zeta)
    sigma <- SPre(sk,Y; remaining signer randomness)
    return (sigma,zeta)
```

This exact ordering appears in
[`issuer.rs:148-179`](../../../crates/vole-act/src/protocol/issuer.rs#L148-L179)
and the common helper at
[`issuer.rs:291-302`](../../../crates/vole-act/src/protocol/issuer.rs#L291-L302).
An invalid proof is rejected before any signer RNG byte is consumed; the test
pins that boundary
([`protocol/tests.rs`](../../../crates/vole-act/src/protocol/tests.rs)).

There is no issuance cache or store mutation. Repeating an accepted request
therefore produces a new salt, a new `Y` except on a salt/hash collision, and a
new MAYO preimage. The regression test checks distinct salts and targets and
authenticates both signatures
([`protocol/tests.rs`](../../../crates/vole-act/src/protocol/tests.rs)).
The externally authorized balance remains a method argument; charging and
authorization are outside this library.

## Ordinary spend

The spend proof presents an old credential while hiding its signature, salt,
opening, base balance, and top-up. It checks:

1. `base + topup = effective = fresh_base + spend`, with `topup = 0` for a
   direct input;
2. `C_old = Cred(ctx,key,base,nonce)` and
   `Y_old = Signed(C_old,topup,old_salt)`;
3. the hidden signature maps to `Y_old` under the MAYO public map;
4. the public nullifier is the suffix paired with `C_old`; and
5. the public fresh commitment `C'` has a hidden opening at `fresh_base`.

These are one common three-Keccak circuit shape for direct and deferred inputs
([`circuit.rs:521-607`](../../../crates/vole-act/src/circuit.rs#L521-L607),
[`circuit.rs:610-691`](../../../crates/vole-act/src/circuit.rs#L610-L691)). The
credential-kind marker still changes the constraints (`topup = 0`) and the
Fiat–Shamir statement even though proof payload sizes are equal in the current
test profile
([`protocol/tests.rs`](../../../crates/vole-act/src/protocol/tests.rs)).

The issuer operation is:

```text
Spend(req = (input_kind,fixed,spend,N,C',pi)):
    reject malformed dimensions
    dig <- H_v5(ctx || canonical_v2(req))
    if Store[N] exists:
        return stored (sigma,zeta) iff digest and fixed mode match
        otherwise reject
    verify pi
    zeta <- uniform {0,1}^256
    Y <- Signed(C',0,zeta)
    sigma <- SPre(sk,Y)
    winner <- Store.insert_if_absent(N,(dig,fixed,sigma,zeta))
    return winner iff digest and fixed mode match
    otherwise reject
```

The store lookup, proof, signing, and atomic insertion order is
[`issuer.rs:182-204`](../../../crates/vole-act/src/protocol/issuer.rs#L182-L204).
The fixed-response path replays both signature and salt
([`issuer.rs:241-257`](../../../crates/vole-act/src/protocol/issuer.rs#L241-L257)).
The digest covers the complete canonical typed request, including its proof;
rerandomizing a proof therefore creates a conflicting request, not an exact
retry
([`spend.rs:693-703`](../../../crates/vole-act/src/protocol/spend.rs#L693-L703)).

## Deferred-return spend

The client fixes a maximum deduction, nullifier, fresh base commitment, and
proof before the issuer selects the return. The return is an out-of-band method
argument, not part of the request digest. On the first accepted call:

```text
SpendDeferred(req = (input_kind,deferred,spend,N,C',pi), t):
    reject malformed dimensions
    dig <- H_v5(ctx || canonical_v2(req))
    if Store[N] exists:
        return stored (stored_t,sigma,zeta) iff digest and deferred mode match
        otherwise reject
    reject if t > spend
    verify pi
    zeta <- uniform {0,1}^256
    Y <- Signed(C',t,zeta)
    sigma <- SPre(sk,Y)
    winner <- Store.insert_if_absent(N,(dig,deferred,t,sigma,zeta))
    return winner iff digest and deferred mode match
    otherwise reject
```

The code is
[`issuer.rs:206-239`](../../../crates/vole-act/src/protocol/issuer.rs#L206-L239),
with durable replay at
[`issuer.rs:259-279`](../../../crates/vole-act/src/protocol/issuer.rs#L259-L279).
Because lookup precedes the bound check, an exact retry returns the stored
triple even if the caller supplies a different or now out-of-range `t`. That is
correct: the stored response, not the retry's method argument, is authoritative
after nullifier consumption. The tests explicitly retry `t=7` with `t=0` and
recover the original return, signature, and salt
([`protocol/tests.rs`](../../../crates/vole-act/src/protocol/tests.rs)).

## Response authentication and typed markers

Issue and spend completion recompute `Signed(C,t,zeta)`, evaluate the returned
MAYO preimage, and reject a changed salt, return, commitment, or signature
([`issue.rs:64-93`](../../../crates/vole-act/src/protocol/issue.rs#L64-L93),
[`spend.rs:556-623`](../../../crates/vole-act/src/protocol/spend.rs#L556-L623)).
Tokens retain `signature`, the base opening, `topup`, and `salt`; canonical
encoding includes them
([`spend.rs:6-19`](../../../crates/vole-act/src/protocol/spend.rs#L6-L19),
[`spend.rs:50-96`](../../../crates/vole-act/src/protocol/spend.rs#L50-L96)).
The omitted context/key bytes are bound transitively through the credential
prefix only outside a credential-v2 prefix collision; domain separation alone
does not make that map injective.

Direct and deferred credentials are therefore not different hash relations.
Both use `Signed`; `Direct` enforces zero top-up and `DeferredReturn` permits one
([`protocol/mod.rs:80-96`](../../../crates/vole-act/src/protocol/mod.rs#L80-L96)).
Their markers remain useful at three other layers:

- Rust types prevent accidental artifact interchange;
- credential and settlement tags enter the spend statement and request digest;
- credential and settlement IDs enter the wire envelope.

A zero-return token can satisfy the common credential relation when manually
viewed through either local marker, but copying request bytes under another
marker changes the proof statement and fails verification
([`protocol/tests.rs`](../../../crates/vole-act/src/protocol/tests.rs)).
Ordinary settlement always creates a `Direct` token with return zero; deferred
settlement creates a `DeferredReturn` token and may legitimately choose zero.

## Oracle-visible failures

Malformed dimensions, conflicting stored nullifiers, invalid proofs, and an
over-large first-call deferred return all fail before salt generation and
`SPre`. An internal MAYO sampler failure occurs after the salt has been drawn
but releases no response. On a spend, a valid `(zeta,Y,sigma)` candidate may
also be computed and then withheld because durable insertion fails or another
candidate wins
([`issuer.rs:182-239`](../../../crates/vole-act/src/protocol/issuer.rs#L182-L239),
[`store.rs:167-185`](../../../crates/vole-act/src/protocol/store.rs#L167-L185)).
Only returned responses belong to the protocol adversary's signing view;
side-channel, leakage, and fault models may have to count all secret-key
computations instead.

[Next: repeats, races, and state](repeats-races-state.md)
