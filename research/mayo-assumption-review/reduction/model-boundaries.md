# Model boundaries and conditional salted-wrapper theorem

## 1. Implemented behavior

The current Rust issuer no longer signs the client-fixed base commitment
directly. After accepting an issuance or spend proof, it samples a 32-byte
salt, computes

```text
Hsig("VOLE-ACT/signed/v3" || pack16(C) || LE64(t) || salt)[0:4m],
```

and calls local `mayo::spre` on that target. Direct credentials use `t=0`;
deferred credentials bind the issuer-selected return. Every token and response
carries the salt, and one common spend circuit verifies the salted wrapper
([`issuer.rs:148-301`](../../../crates/vole-act/src/protocol/issuer.rs#L148-L301),
[`circuit.rs:613-674`](../../../crates/vole-act/src/circuit.rs#L613-L674)).

The v3 input omits a repeated context. Its base `C` is the credential-v2 prefix
and binds the derived context; that context binds the expanded MAYO public-key
hash, application context, parameter set, and proof profile. The reduction may
use this transitive binding only after charging credential-prefix collisions
and only for the scoped key/context experiment.

Spend retry records are keyed by the consumed input nullifier and store the
winning signature, salt, settlement kind, and optional return. Exact retries
replay that record. Concurrent losing candidates are not released. Issuance
has no retry store and each successful authorized call is a new salted signing
event.

The local MAYO crate still exposes expanded mathematical keys and a bare
preimage sampler; this wrapper is not the compressed Round-2 signature wire
format or exact Algorithm 7/8 message hash.

## 2. Classical ideal-XOF layer

The proof plan requires one global, prefix-consistent ideal XOF with injective
domain encodings. The simulator actively programs fresh signed-v3 points to
public-map images. It also requires:

1. consistent short and long reads of the credential stream so its commitment
   prefix and nullifier suffix agree;
2. separation of credential, signed-wrapper, Fiat–Shamir, vector-commitment,
   context, public-key-hash, and request-digest inputs;
3. adaptive extraction for proof statements whose hidden witnesses contain
   ideal-XOF queries; and
4. independently uniform issuer RNG bytes for salt and sampler coins.

The last premise is not guaranteed by the API: applications and replicas pass
their own `CryptoRngCore` state.

## 3. Fixed Keccak is a separate instantiation

The checked circuit verifies all fixed Keccak-f[1600] rounds. A reduction
cannot literally replace a fixed `SHAKE256(x)` value by `P*(s)`. Therefore the
classical proof first needs an oracle-aided relation in which the hidden hash
gates call the same ideal XOF seen by the adversary.

Sponge indifferentiability with an ideal permutation is relevant background,
but it does not itself prove that:

- fixed Keccak-f behaves as the required random permutation;
- adaptive programming remains sound inside this proof system;
- extracting hidden oracle inputs from many Fiat–Shamir proofs composes; or
- the resulting statement holds against quantum superposition queries.

The implemented code may be a reasonable heuristic instantiation, but neither
the salted proof plan nor ordinary MAYO's ROM theorem closes this bridge.

## 4. Extraction boundary

Fiscal soundness requires an adaptive shared-oracle extractor for every
accepted session. It must recover:

- issuance: the hidden key and nonce opening public `C` at the authorized
  balance;
- spend input: the old opening, salt, MAYO preimage, kind, return, balance, and
  nullifier;
- spend output: the opening of public fresh `C`; and
- exact integer witnesses for settlement arithmetic.

The extractor must remain valid after the reduction programs signed-v3 points
and across statements depending on earlier responses. Per-proof soundness or
a union bound over isolated rewinds does not establish this. The corpus names
adaptive shared-oracle extraction as an assumption; specifically, it must be
straight-line and online at the proof-verification boundary, before the issuer
signs the current output. This lets the reduction halt immediately on the
first orphan rather than risk that its message is signed later. The corpus
does not infer this extractor from PoMFRIT's different NIZK composition.

## 5. Conditional classical theorem

> **Candidate theorem (paper-level; classical ideal-XOF model).** Fix one
> parameter set, sample `K <- TrapGen` once, derive its context, and initialize
> linearizable issuer state. Probability is over that one key generation, the
> ideal XOF, issuer randomness, proof coins, and the adversary. A theorem for
> every fixed generated key would require an additional per-key premise. Suppose:
>
> 1. the credential-v2 and signed-v3 relations use one prefix-consistent
>    programmable ideal XOF with injective domain encodings;
> 2. issuer RNG outputs independently uniform salts and sampler coins;
> 3. the proof system has a straight-line online adaptive multi-theorem
>    extractor in the programmed shared-oracle execution, invoked after proof
>    acceptance and before current-output signing;
> 4. nullifier consumption, response publication, and external redemption are
>    durable, linearizable, and non-rollback; losing candidates remain secret;
>    winner selection is response-oblivious; and successful issuance is externally authorized and
>    counted in one service-level transaction;
> 5. the local sampler has the Round-2 joint-distribution coupling, with
>    uniform fiber sampling, rank bound `B`, and its 256-attempt failure charged
>    separately;
> 6. the exact expanded public-key distribution admits the OV hybrid and
>    random-map MTWMQ is hard; and
> 7. credential-prefix collisions, salt prequeries/repetitions, unqueried-XOF
>    guesses, parser/arithmetic failures, and store/RNG failures are charged.
>
> Then a fiscal adversary with residual advantage yields either an OV
> distinguisher or an MTWMQ solver, with sampler factor
> `(1-Q_s B)^-1` for `Q_s B<1` under response-oblivious winner selection,
> plus the explicit additive terms in the
> [salted-wrapper proof](salted-wrapper-proof-plan.md).

The theorem is intentionally conditional. In particular, Round-2 Lemma 1 is
an average-over-key rank bound and does not justify replacing the local
256-attempt exhaustion probability by `B^256` under one reused key.

## 6. What changed relative to the old reduction

The old direct-target implementation could return multiple trapdoor samples
for one client-fixed target; a plain challenger could not simulate the second
sample. The signer-salted wrapper removes that interface: each independently
accepted response lands at a fresh signer-chosen XOF input, except on the
charged salt event, while exact spend retries replay.

Accordingly, the implemented protocol now has a credible classical
OV-plus-MTWMQ route. The custom one-more assumption is no longer the natural
primitive premise for the implemented oracle. What remains is proof work, not
the old same-target simulation obstruction.

## 7. Remaining theorem obligations

1. Prove the local uniform-fiber sampler and obtain a useful reused-key bound
   for the 256-attempt cap.
2. Instantiate the OV hop for the actual expanded whipped forms and context
   derivation.
3. State and prove the adaptive shared-oracle extractor for the degree-16
   VOLE-in-the-head proof.
4. Give exact global query counts for credential collisions, salt freshness,
   and unqueried hidden inputs.
5. Specify the ideal-XOF/oracle-circuit theorem and separately justify any
   fixed-Keccak or QROM claim.
6. Bind deployment authorization and redemption to the nullifier store's
   durable transaction boundary, and state the RNG trust requirement.

[Back to the reduction index](index.md)

[mayo-lib]: ../../../crates/mayo/src/lib.rs#L27
[keccak-circuit]: ../../../crates/vole-act/src/circuit.rs#L423

[baum26]: ../sources.md#baum26
[fips202]: ../sources.md#fips202
