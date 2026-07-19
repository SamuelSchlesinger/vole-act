# VOLE-ACT: Post-Quantum Anonymous Credit Tokens

**Status:** living design document — the source of truth for the construction as built.

## 1. Goal

Port the Katz–Schlesinger Anonymous Credit Tokens scheme (BBS signatures over
Ristretto; see `github.com/SamuelSchlesinger/anonymous-credit-tokens`) to plausibly
post-quantum assumptions, using **VOLE-in-the-Head (VOLEitH) NIZKs** and the **MAYO
trapdoor** in the style of the PoMFRIT blind-signature paper
(Baum–Beckmann–Beullens–Mukherjee–Rechberger; `pq-blind-signatures.pdf`).

Functionality preserved from the reference scheme:

- **Issue**: issuer grants a token carrying a balance `c`.
- **Spend**: client spends `s ≤ c` anonymously, revealing only a one-time
  nullifier, and receives a fresh token for the change `c' = c − s` in the same
  round trip.
- **Double-spend prevention**: each token's nullifier can be consumed once.
- **Fiscal soundness**: clients cannot create value.
- **Unlinkability**: the issuer cannot link a spend to the issuance (or prior
  spend) that created the token — now against quantum adversaries too.

## 2. Token design

A token is a MAYO signature on a *binding hash commitment* to its attributes:

```
target = H_cred( ctx ‖ k ‖ enc_L(c) ‖ ρ )  ∈ F₁₆^m        T*(σ) = target
```

- `k`   — nullifier key (256 bits, client-chosen, secret until spent)
- `c`   — balance, an L-bit unsigned integer, canonical fixed-width encoding
- `ρ`   — high-entropy commitment nonce (256 bits): hiding + unlinkability
- `ctx` — domain context: issuer public key hash, asset id, protocol version,
  key epoch, balance width L. Bound into every hash.
- `H_cred` — SHAKE256 with domain separation, output exactly 4·m bits parsed as
  m nibbles (the MAYO codomain; "hash-free MAYO": no second hash layer).

Client stores `(σ, k, c, ρ)`. The nullifier revealed at spend time is
`null = H_null(ctx ‖ k)` (domain-separated from `H_cred`).

### 2.1 Two pitfalls this design avoids (do not regress!)

1. **No attribute may sit outside the hash.** An encoding like
   `target = H(k‖c) + r` with client-held `r` is *perfectly equivocable*: given
   any signed target `t`, any `(k̂, ĉ)` opens it via `r̂ = t − H(k̂‖ĉ)` — one
   signature becomes a token of arbitrary balance. Everything binds inside one
   hash; hiding comes from the in-hash nonce `ρ`.
2. **Balance arithmetic is Boolean, never F₁₆ arithmetic.** F₁₆ has
   characteristic 2 (`2 = 0`), so `Σ 2ⁱ·bᵢ` and field subtraction do not
   implement integers. Balances live as L-bit strings; `c = c' + s` is proven
   with a degree-2 ripple-carry adder; bit-ness is `bᵢ² = bᵢ`.

## 3. Protocol

### 3.1 Issue(c), c public

1. Client picks `k, ρ`; computes `target₀ = H_cred(ctx‖k‖c‖ρ)`; sends `target₀`
   plus a VOLEitH NIZK proving knowledge of `(k, ρ)` such that `target₀` is
   well-formed **for the public `c`**.
2. Issuer verifies the proof against `(ctx, c, target₀)`, then signs:
   `σ₀ = SPre(sk, target₀)`; returns `σ₀`.
3. Client checks `T*(σ₀) = target₀`; stores token `(σ₀, k, c, ρ)`.

The external authorization for the issuance (payment etc.) must be one-time —
replaying it with fresh targets would mint multiple root tokens.

### 3.2 Spend(s): c-token → (c−s)-token, one round trip

Client → issuer: public `(s, null, target')` and **one** VOLEitH NIZK proving,
with all public values bound into Fiat–Shamir:

1. `T*(σ) = H_cred(ctx‖k‖c‖ρ)` — possession of a valid token (MAYO Eval
   in-circuit, degree 2; H_cred in-circuit via the Keccak permutation).
2. `null = H_null(ctx‖k)` — nullifier correctly derived.
3. `c = c' + s` as L-bit integers (Boolean adder) and `c' ∈ [0, 2^L)`;
   optionally `c' ≤ B` via comparator if a tighter bound is configured.
4. `target' = H_cred(ctx‖k'‖c'‖ρ')` — the fresh target commits to the change
   balance `c'` and fresh `(k', ρ')`.

Issuer: verify proof → check `null` unseen → **atomically** record
`(null, s, target', σ')` and sign `σ' = SPre(sk, target')` → return `σ'`.
Identical retries return the stored record; conflicting retries reject.

Client: check `T*(σ') = target'`; store `(σ', k', c', ρ')`.

Because the issuer verifies a *complete binding proof before signing*, the
two-stage blind-signature dance of PoMFRIT (π₁/π₂, `H(μ,π₁)`) is unnecessary:
spend = one NIZK show + one plain `SPre`. Blindness of the new token comes from
the zero-knowledge property plus the hidden `ρ'`.

### 3.3 Security sketch

- **Fiscal soundness**: token-lineage argument. Straight-line extraction from
  each accepted proof yields openings `(k, c, ρ)`/`(k', c', ρ')` with
  `c = c' + s`. A valid token not descending from an authorized issuance yields
  either a MAYO forgery (new preimage), an `H_cred` collision, or a nullifier
  reuse. Target assumption: standard MAYO EUF-CMA (the reduction extracts the
  message before its signing-oracle query); the weaker fallback is PoMFRIT's
  one-more-preimage assumption.
- **Unlinkability**: `target` is a uniform RO output thanks to `ρ` and is never
  revealed after issuance (always shown in ZK); `null` is domain-separated from
  everything the issuer ever saw; proofs are zero-knowledge; `σ` and `target`
  appear only as hidden witnesses at spend time.

## 4. Architecture

Cargo workspace, dependencies flow strictly downward:

| Crate | Contents |
|---|---|
| `crates/binary-fields` | GF(16) = F₂[x]/(x⁴+x+1) (MAYO), GF(2¹²⁸) = F₂[x]/(x¹²⁸+x⁷+x²+x+1) (VOLE tags), canonical embedding GF(16) ↪ GF(2¹²⁸) |
| `crates/vector-commit` | GGM-tree all-but-one vector commitments (seed trees, SHAKE256 PRG/commitments, salted + domain-separated) |
| `crates/voleith` | VOLE correlation from VCs (ConvertToVOLE), the `[[a]]` polynomial-commitment layer (lift/linear/cmul/drmul/assert), QuickSilver-style circuit satisfaction, Fiat–Shamir |
| `crates/mayo` | MAYO TrapGen / SPre / Eval, generic over parameter sets (MAYO₁/₃/₅) |
| `crates/vole-act` | ACT circuits (Keccak-f in-circuit, MAYO verify, Boolean adder/range) + Issue/Spend protocol + public API mirroring the reference crate |

## 5. Parameters (first instantiation)

- λ = 128: VOLE tag field GF(2¹²⁸), τ = 16 repetitions × depth-8 GGM trees
  (N = 256 leaves), matching the FAEST-128f-style regime.
- MAYO₁ parameters (q = 16); exact `(n, m, o, k)` pinned against the MAYO
  round-2 spec when `crates/mayo` is built.
- L = 64-bit balances initially; L and the MAYO level stay generic.
- Base witnesses are committed as **bits** (F₂-VOLEs); F₁₆ values are formed
  by public-constant linear combinations via the embedding.

## 6. Roadmap

- **M1** `binary-fields` + `vector-commit` (tested, this milestone)
- **M2** `voleith` NIZK core, validated on toy circuits
- **M3** `mayo` against the official spec + test vectors
- **M4** ACT circuits + protocol + end-to-end tests
- **Later**: degree-16 Keccak round optimization (≈4× proof-size cut),
  hardware carry-less multiply (PMULL/PCLMULQDQ), RainHash as a pluggable
  alternative to SHAKE256, τ/parameter tuning, benches vs. the paper's numbers.
