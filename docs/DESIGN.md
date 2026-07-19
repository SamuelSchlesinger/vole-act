# VOLE-ACT: Post-Quantum Anonymous Credit Tokens

**Protocol version:** 4
**Wire version:** 1
**Status:** research prototype; implemented and tested, but neither proven nor
independently audited.

## 1. Model and objective

There is one issuer and any number of clients. The issuer grants a public
number of credits to a client. A client may later redeem some credits without
revealing which issuance or earlier redemption produced its token. Each
accepted redemption consumes a one-time nullifier and returns a fresh token.

Credits from different issuer keys, application domains, assets, key epochs,
MAYO parameter sets, VOLE profiles, or protocol versions are separate systems.
All of these choices are bound into a 256-bit context `ctx`.

This construction is descended from the Katz–Schlesinger anonymous-credit
design, but replaces its group signatures and Sigma proofs with a MAYO
trapdoor relation and a VOLE-in-the-head argument. The optional
deferred-return operation covers the one case that cannot be represented as an
ordinary spend: the issuer chooses the final return only after the client has
committed to its fresh balance.

### 1.1 Parties and trust

- A malicious client may try to create value, spend the same token twice,
  change a return, or mix protocol modes.
- A malicious issuer may try to link a presentation to the transaction that
  created its token, selectively fail, or return malformed credentials.
- The deployment must provide authenticated transport, issuance authorization,
  rate limits, a cryptographic RNG, and durable nullifier storage. These are
  outside the proof circuit.
- Availability, traffic-analysis resistance, compromise recovery, and hiding
  public spend amounts are not goals of this layer.

## 2. Syntax

An instance has algorithms and protocols

```text
Setup, Issue, Spend, SpendWithDeferredReturn, VerifyToken.
```

- `Setup(app, profile)` generates an issuer trapdoor `sk`, public key `pk`,
  and context `ctx`.
- `Issue(b)` is run with a public 64-bit balance `b`. It returns a direct token
  of effective balance `b`.
- `Spend(s, token)` is run with public `s ≤ balance(token)`. It consumes the
  input nullifier and returns a direct token of balance
  `balance(token) - s`.
- `SpendWithDeferredReturn(s, token)` first proves the same maximum deduction
  `s`. After verification, the issuer chooses `t'` with `0 ≤ t' ≤ s`; the
  operation consumes the input nullifier and returns a deferred-return token
  of balance `balance(token) - s + t'`.
- `VerifyToken` is local client-side authentication of a decoded token. Tokens
  are never sent as presentations; only a zero-knowledge spend request is.

A return known before proof generation is just a smaller net spend. The
deferred-return operation exists precisely because `t'` is not yet known when
the fresh commitment is fixed.

### 2.1 Correctness

Consider an experiment that generates one issuer and lets an environment build
a directed acyclic graph of honest tokens. A root is produced by `Issue(b)`.
Every later node is produced by spending an earlier, not-yet-spent node. Set a
failure flag if any honest operation rejects; any client authentication check
fails; a spend output has a balance other than the equation above; or two
distinct accepted input nodes yield the same nullifier. Exact retransmission
of one request is not a new node and must return the stored response.

The scheme is correct if the failure probability is negligible. The
implementation tests all four credential transitions, exact retries, `0`, and
the full `u64` boundary.

### 2.2 Fiscal accounting

For an accepted ordinary spend, define redeemed value as `s`. For an accepted
deferred-return spend, define it as `s - t'`. The intended fiscal invariant is

```text
sum(effective balances of independently spendable live tokens)
  + sum(redeemed value)
  ≤ sum(externally authorized issuance value).
```

The qualifier “independently spendable” excludes duplicate encodings of the
same opening and nullifier. A formal reduction for the complete implementation
has not been established; Section 7 states the assumptions under which the
invariant is expected to hold.

## 3. Building blocks and notation

Let `P : GF(16)^(kn) -> GF(16)^m` be the whipped MAYO public map and let
`SPre(sk, y)` sample a preimage `sigma` such that `P(sigma) = y`. This library
uses the mathematical trapdoor map, not MAYO's message-hashing signature API.

Let `H` denote SHAKE256 with a fixed, prefix-free domain and fixed input
encoding. `enc64` is little-endian unsigned encoding. `pack16` places the first
GF(16) element in the low nibble. All dimensions and vector boundaries in
Fiat–Shamir are length framed.

The zero-knowledge layer commits witness bits using VOLE correlations over
`GF(2^128)` and checks Boolean, quadratic, and polynomial relations with a
generalized QuickSilver assertion. The public relation is deterministic and is
executed by counting, prover, and verifier backends with identical allocation
order.

## 4. Credential formats

The client samples a 256-bit nullifier key `k` and a 256-bit hiding nonce
`rho`. For base balance `b`, define one XOF stream:

```text
X = SHAKE256(
      "VOLE-ACT/credential/v2" || ctx || k || enc64(b) || rho
    )

C(k,b,rho) = first 4m bits of X, parsed as GF(16)^m
N(k,b,rho) = next 256 bits of X
```

The target and nullifier are disjoint portions of one permutation output. This
saves a complete hidden SHAKE evaluation while treating the unrevealed suffix
as pseudorandom after the issuer has seen the prefix.

### 4.1 Direct credential

```text
P(sigma) = C(k,b,rho)
effective balance = b
private state = (sigma, k, b, rho)
```

Presenting a direct credential requires two hidden SHAKE evaluations: the old
credential stream and the fresh credential stream.

### 4.2 Deferred-return credential

For an issuer-selected return `t`, define

```text
D(ctx,C,t) = first 4m bits of SHAKE256(
  "VOLE-ACT/deferred/v2" || ctx || pack16(C) || enc64(t)
)

P(sigma) = D(ctx, C(k,b,rho), t)
effective balance = b + t
private state = (sigma, k, b, rho, t)
```

The addition is exact and non-wrapping. `C`, `b`, and `t` remain hidden during
presentation. The nested target costs one additional hidden SHAKE.

The wrapper is essential. Signing an algebraically adjustable value such as
`H(k||b) + r` would let a holder reopen one signature to unrelated attributes.
Here the return is a canonical hash input and cannot be changed without a
target collision or a new MAYO preimage.

## 5. Construction

### 5.1 Setup

The issuer runs MAYO trapdoor generation, expands the public quadratic forms,
and computes

```text
ctx = SHAKE256(
  "VOLE-ACT/context/v4" ||
  frame(app) || H(expanded MAYO public map) || MAYO id ||
  balance width || VOLE tau || VOLE k
)[0..256].
```

The application context should name the deployment, asset, and key epoch. A
profile change creates a different credential system even when the MAYO key is
unchanged.

### 5.2 Issue

To issue public balance `b`:

1. The client samples `(k,rho)`, computes `C = C(k,b,rho)`, and proves that `C`
   is the output of the credential hash for public `(ctx,b)` and hidden
   `(k,rho)`.
2. After verifying the proof and external authorization, the issuer samples
   `sigma <- SPre(sk,C)` and returns `sigma`.
3. The client checks `P(sigma) = C` and stores a direct token.

External authorization must itself be one-time. Replaying a payment or grant
with a fresh commitment legitimately asks the cryptographic issuer for another
root token.

### 5.3 Ordinary spend

The client chooses fresh `(k',rho')` and hidden base balance `b'`, then sends
public

```text
(s, N, C', proof), where C' = C(k',b',rho').
```

For a direct input, the proof relation is

```text
P(sigma) = C(k,b,rho)
N = N(k,b,rho)
b' + s = b
C' = C(k',b',rho').
```

For a deferred-return input, it is

```text
P(sigma) = D(ctx, C(k,b,rho), t)
N = N(k,b,rho)
b + t = e
b' + s = e
C' = C(k',b',rho').
```

All additions are exact 64-bit integer relations with a zero final carry. The
issuer verifies the typed statement, produces `sigma' <- SPre(sk,C')`, and
atomically associates the exact request digest and response with `N`. The
client verifies `P(sigma') = C'` and stores a direct token.

Thus an ordinary spend of a deferred-return token folds the old return into
`b'` and restores the cheaper credential format.

### 5.4 Spend with deferred return

The client proves the same input-possession, nullifier, fresh-commitment, and
maximum-deduction relation, but the settlement tag is
`deferred-return-spend/v1`. Only after successful verification does the issuer
choose `t' ≤ s` and sample

```text
sigma' <- SPre(sk, D(ctx,C',t')).
```

The response is `(t',sigma')`. The client checks the public bound, reconstructs
the target, verifies the preimage, and stores a deferred-return token with
effective balance `b' + t'`.

The proof cost is determined by the input credential. Creating a deferred
credential from a direct input still proves only two hashes. The third hash is
paid when that credential is next presented.

### 5.5 Typed state machine

| Input credential | `spend` output | deferred-return output |
|---|---|---|
| Direct | Direct | Deferred return |
| Deferred return | Direct | Deferred return |

Credential kinds and settlement modes have separate sealed Rust markers.
Every statement, request digest, and wire envelope also includes both tags.
Consequently, type erasure or byte-level retagging does not create an implicit
conversion. A consumed nullifier reused under another tag is a conflicting
retry.

`MayoParams` is likewise sealed to the four checked round-2 tuples. A new
tuple is a protocol revision, not a downstream type implementation: it needs
an irreducible-polynomial check, message/rate and circuit-degree bounds, a wire
identifier, performance limits, and renewed cryptanalysis.

### 5.6 Exact retry and crash semantics

For each nullifier, the issuer stores

```text
(request_digest, response_kind, signature, optional_return).
```

`request_digest` covers context, MAYO parameters, input credential kind,
settlement mode, public spend, nullifier, fresh commitment, and every proof
field. An identical retry returns the durable winner. A different digest is a
double-spend attempt.

`NullifierStore::insert_if_absent` is the protocol's persistence boundary. It
must atomically insert by unique nullifier and return whichever row is durably
stored. The issuer never returns a newly sampled signature before this
operation succeeds. Issuer-key restoration requires an explicit recovered
store; the API provides no empty-store restoration shortcut. Rolling that
store back to an older snapshot is equivalent to deleting nullifiers and
violates the protocol contract.

## 6. Circuit and proof system

### 6.1 Bit discipline

Every client secret enters as committed bits. GF(16) values are public-linear
combinations of four bits under the canonical embedding into `GF(2^128)`.
Integer addition uses ripple-carry equations:

```text
z_i = a_i xor b_i xor carry_i
carry_(i+1) = a_i b_i + carry_i(a_i + b_i)
carry_0 = carry_64 = 0.
```

The 64 carry equations share product terms and are folded by verifier
randomness. Arithmetic never treats GF(16) addition as integer addition.

### 6.2 Keccak degree management

Keccak's chi layer doubles algebraic degree. A full 24-round symbolic
evaluation would therefore be unusable. The circuit evaluates four rounds at
a time:

```text
degree 1 -> 2 -> 4 -> 8 -> 16 -> committed 1,600-bit checkpoint.
```

Each checkpoint is a fresh bit commitment constrained equal to the computed
state. The next group starts from degree one. Six checkpoints cover all 24
rounds, so degree never exceeds 16. This is an actual degree reset, not merely
truncation or reduction of a growing polynomial.

### 6.3 VOLE layout and transcript

For witness length `ell`, maximum degree `d`, and `lambda = 128`, VOLE commits

```text
ell_hat = ell + d*lambda
```

bits. The first `ell` carry the witness; `(d-1)lambda` bits mask QuickSilver
coefficients; the final `lambda` bits mask the wide consistency hash.

Every proof carries a fresh `2*lambda`-bit salt (FAEST's salt width), bound
into every tree PRG/hash call and diversified per tree, so multi-instance
attacks on the `lambda`-bit seeds get no batching advantage.

Transcript order is:

```text
statement, dimensions, salt, tree commitments, corrections, witness d
  -> alpha
wide consistency values
  -> chi
QuickSilver coefficients
  -> Delta
all-but-one tree openings.
```

The global `Delta` is unavailable when the prover fixes the proof polynomial.
A 128-bit column-wise universal hash checks that all small VOLE instances share
one `u`; a single small-field scalar check would permit attacks against an
individual `k`-bit chunk.

### 6.4 Concrete assertion error

For a nonzero degree-`d` assertion polynomial over `GF(2^128)`, the extended
assertion analysis gives error at most

```text
(d + 1) / 2^128.
```

At `d = 16`, this is `17/2^128`, or approximately `2^-123.91`. Calling
`tau*k = 128` a literal 128-bit statistical soundness bound would therefore be
incorrect. Computational vector-commitment security, consistency hashing,
Fiat–Shamir in the ROM/QROM, and composition losses are additional terms. No
complete concrete bound has been proved for this implementation.

## 7. Security argument and assumptions

The following are conditional claims, not a theorem about the code.

### 7.1 Fiscal soundness sketch

Suppose an accepted spend proof can be extracted. Its witness contains one
valid input preimage, one opening that derives the revealed nullifier, one
opening of the fresh commitment, and exact balance equations. A direct spend
therefore preserves

```text
old balance = fresh balance + redeemed value.
```

A deferred settlement gives `t' ≤ s`, hence

```text
old effective balance
  = b' + s
  = (b' + t') + (s - t').
```

The durable store prevents the extracted input lineage from being consumed
twice. Producing more independently spendable output lineages than authorized
issuer responses would then require one of:

1. an accepted false proof or extraction failure;
2. two relevant openings of a credential hash target;
3. a collision or domain-confusion failure in transcript/request hashing;
4. a new MAYO preimage beyond the issuer's authorized preimage samples; or
5. a violation of the atomic nullifier-store contract.

Because the issuer samples preimages of targets supplied by protocol
transcripts, item 4 is a **one-more preimage** assumption for the whipped MAYO
map on hash-distributed/adaptively selected targets. Ordinary MAYO signature
EUF-CMA security does not directly imply this property. PoMFRIT makes the same
distinction in its blind-signature analysis.

### 7.2 Anonymity sketch

In the random-oracle model, fresh `rho` makes every visible credential target
pseudorandom, and the unrevealed suffix nullifier remains pseudorandom after
the prefix is exposed. The spend proof hides the old target, signature,
balance, return, key, nonce, and fresh opening. A simulator for the proof plus
random-oracle programming should therefore replace a real presentation with a
simulated one, subject to public metadata.

This does not hide the issuer, context, public spend or maximum charge, timing,
network identity, request length, input credential mode, or whether a retry
occurred. Those values can dominate practical linkability.

### 7.3 Mode leakage

Direct and deferred inputs have different circuit sizes. Optional use therefore
partitions the anonymity set when deferred returns are rare. A deployment that
needs mode hiding should choose one format uniformly for an asset/epoch or use
the always-wrapped format and accept the third hidden hash.

### 7.4 Assumptions and non-claims

The intended argument relies on:

- SHAKE256 as a domain-separated random oracle/PRG and collision-resistant
  commitment hash;
- hiding, binding, and correlation robustness of the GGM all-but-one vector
  commitment and VOLE conversion;
- knowledge soundness and zero knowledge of the degree-16 VOLE proof after
  Fiat–Shamir;
- one-more preimage resistance of the whipped MAYO trapdoor map in the target
  distribution induced here;
- honest cryptographic randomness and atomic durable nullifier storage.

The implementation does **not** inherit a NIST category from MAYO, does not
claim a complete QROM reduction, and has not been checked for fault attacks or
complete constant-time behavior. The issuer-side linear solver is
fixed-schedule and secret state is zeroized, but those measures are not a
side-channel certification.

## 8. Canonical encodings and API boundary

Wire version 1 begins every artifact with `VACT || version`, followed by an
artifact identifier, MAYO parameter identifier, credential-kind identifier,
and settlement identifier. Decoders reject wrong types, wrong parameters,
truncation, nonzero nibble padding, impossible lengths, oversized input, and
trailing bytes. Proof component counts are capped by protocol maxima before
allocation. The maximum outer artifact size is 32 MiB; the maximum embedded
proof is 16 MiB.

Canonical codecs cover:

- expanded MAYO public and secret keys;
- issuer public keys and issuer-key recovery material;
- VOLE proofs;
- issue and both spend request/response families;
- direct and deferred client tokens;
- pending issue/spend crash-recovery state; and
- durable retry records.

Expanded MAYO keys are a VOLE-ACT mathematical format. They are intentionally
not advertised as byte-compatible with the official seed-compressed MAYO
signature API. Secret encodings require authenticated encryption and rollback
protection outside this library.

## 9. Parameters and performance

This repository pins the MAYO round-2 mathematical parameter table. MAYO1 and
MAYO2 both target NIST security category 1; the number is a parameter-set name,
not a category. MAYO1 has the smaller compressed public key, while MAYO2 has a
substantially shorter preimage (`kn = 324` rather than `860`), which is useful
inside the proof.

MAYO advanced to NIST's third additional-signature evaluation round in May
2026, but it is not standardized. Moreover, VOLE-ACT uses its trapdoor in a
different composition and has no NIST classification.

All built-in VOLE profiles use `tau*k = 128`:

| Profile | `tau` | `k` | Direct-input proof | Deferred-input proof |
|---|---:|---:|---:|---:|
| Compact | 16 | 8 | 52,688 bytes | 72,272 bytes |
| Balanced (default) | 32 | 4 | 101,232 bytes | 140,400 bytes |
| Low latency | 64 | 2 | 198,320 bytes | 276,656 bytes |

Compact minimizes communication but expands 4,096 leaves. Balanced expands
512. Low latency expands 256 but sends many more correction bits. Run
`cargo bench -p vole-act --bench protocol` for statistically sampled profile,
issuer, end-to-end, and wire-codec timings. The ignored release test remains a
quick one-sample snapshot.

## 10. Implementation map

| Crate | Responsibility |
|---|---|
| `binary-fields` | GF(16), GF(2^128), canonical embedding, PMULL/PCLMUL acceleration |
| `vector-commit` | salted GGM all-but-one vector commitments |
| `voleith` | VOLE conversion, consistency check, generalized QuickSilver, Fiat–Shamir, proof codec |
| `mayo` | round-2 mathematical TrapGen/SPre/Eval, fixed-schedule solver, expanded-key codecs |
| `vole-act` | Keccak circuits, exact balances, typed protocol, wire codecs, durable-store boundary |

## 11. References

- Katz and Schlesinger, local reference implementation:
  `../anonymous-credit-tokens/docs/design.tex`.
- Baum, Beckmann, Beullens, Mukherjee, and Rechberger,
  [Concretely Efficient Blind Signatures Based on VOLE-in-the-Head Proofs and
  the MAYO Trapdoor](https://eprint.iacr.org/2026/109).
- FAEST team, [FAEST algorithm specification](https://faest.info/faest-spec-v1.0.pdf).
- Baum et al., [One Tree to Rule Them All](https://eprint.iacr.org/2024/490.pdf).
- MAYO team, [MAYO round-2 specification](https://pqmayo.org/assets/specs/mayo-round2.pdf).
- NIST, [IR 8610: status report on the second additional-signature round](https://csrc.nist.gov/pubs/ir/8610/final).

The separate [security review](SECURITY.md) records the concrete adversarial
campaign and the remaining release blockers.
