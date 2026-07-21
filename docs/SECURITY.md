# VOLE-ACT Adversarial Security Review

**Review date:** 2026-07-21

**Scope:** the complete workspace and the uncommitted protocol/API worktree at
the time of this review

**Conclusion:** no practical forgery or value-creation attack was found, but
the construction is not ready for production. The signer-salted common target
is intended to replace the specialized one-more MAYO assumption with the
ordinary MAYO proof foundation (OV plus Multi-Target Whipped MQ) in the
random-oracle model. A paper-level wrapper reduction plan is now written, but
the principal blockers are still the absence of completed, formal, and
independently reviewed reductions for the exact signer-salted MAYO wrapper,
degree-16 VOLE argument, and stateful protocol composition.

“No attack found” is not a proof that the scheme cannot be cracked. This file
records what was actually examined, what was fixed, which generic attacks set
the concrete ceiling, and what remains outside the evidence.

## 1. Method

The review used five complementary approaches:

1. **Protocol derivation.** Re-derived the fiscal invariant, anonymity claim,
   deferred-return equations, signer-salt timing, retry semantics, hash
   domains, and type state machine from the code rather than trusting prior
   prose.
2. **Primitive cross-check.** Compared all MAYO parameter tuples, field-tail
   polynomials, and whipped pair ordering against the current official MAYO C
   implementation. Compared the VOLE/QuickSilver flow against FAEST, One Tree
   to Rule Them All, and PoMFRIT.
3. **Malicious-proof tests.** Used the internal unchecked prover to construct
   proofs of false linear, quadratic-system, and polynomial statements for
   every supported degree 1 through 16. Mutated every proof component and
   sampled 96 byte-level wire mutations.
4. **State/API attacks.** Tried mode retagging, direct/deferred response
   substitution, top-up changes, cross-context use, replay conflicts, crash
   before persistence, integer overflow, non-canonical encodings, truncation,
   trailing data, oversized lengths, and parameter confusion.
5. **Implementation audit.** Reviewed secret-dependent control flow,
   zeroization, parser allocation bounds, hardware field arithmetic, unsafe
   blocks, dependency advisories/licenses/sources, release tests, clippy, and
   rustdoc.

The campaign is deterministic and reproducible through the test suite. It is
not a replacement for coverage-guided fuzzing, formal verification, a QROM
proof, fault injection, power analysis, or an independent audit.

## 2. Security envelope

The strongest defensible statement is conditional:

> If SHAKE256 behaves as the required domain-separated random oracle/PRG; the
> all-but-one vector commitment and custom VOLE consistency check are secure;
> the generalized degree-16 QuickSilver argument is knowledge-sound and zero
> knowledge after Fiat–Shamir with straight-line online extraction at proof
> acceptance before current-output signing; the ordinary MAYO OV and
> Multi-Target Whipped MQ assumptions support the fresh random-oracle targets
> created by the signer-salted wrapper; randomness is sound; and nullifier
> records are durably linearizable with confidential race losers and
> response-oblivious winner selection; external issuance is atomically
> authorized, charged, idempotently recorded, and first published,
> then accepted protocol transitions preserve the fiscal invariant and hide
> their input lineage up to public metadata.

Several clauses are plausible and borrowed from reviewed designs, but the
exact composition implemented here has no published theorem.

## 3. Concrete ceilings

### 3.1 Proof assertion error

The Keccak checkpoint relation has degree 16 over `GF(2^128)`. The extended
assertion error is bounded by

```text
(16 + 1) / 2^128 = 17 / 2^128 ~= 2^-123.91.
```

This corrects the tempting but inaccurate claim that `tau*k = 128` alone gives
a literal 128-bit statistical proof bound. Vector-commitment, consistency,
Fiat–Shamir, and composition terms must also be included in a complete bound.

### 3.2 Credential double-opening

For MAYO2, a credential target has `m = 64` nibbles, hence 256 bits. A generic
collision in

```text
C(k,b,rho)
```

gives two openings of one signed target. With distinct suffix nullifiers, the
same credential can then be presented twice. Thus fiscal soundness cannot
exceed the collision resistance of that 256-bit prefix: about `2^128` classical
hash evaluations. A full-scale BHT-style quantum collision search has query
complexity about `2^(256/3) = 2^85.3`, with a demanding memory/access model.

This is not a shortcut specific to the code; it is the generic binding limit
of a 256-bit credential commitment. MAYO1 has a 312-bit target: classically its
`2^156` collision cost is above the degree-16 proof bound, while the ideal BHT
query exponent is about `312/3 = 104`, below it. NIST treats collision search
as a different benchmark from category-1 AES-128 key search, so classical,
ideal-query, and concrete resource estimates must not be collapsed into one
“NIST level.”

The same output width bounds the common signed wrapper. Direct and deferred
credentials intentionally use the same wrapper; direct is exactly the
zero-return case. Credential-kind tags separate protocol statements and wire
artifacts, not the underlying zero-return authentication relation.

### 3.3 Other generic bounds

- Nullifiers, contexts, request digests, and transcript chaining values are
  256 bits.
- Tree commitments and hidden-leaf commitments are 256 bits; seeds are 128
  bits.
- The global VOLE field challenge is 128 bits.
- MAYO2's algebraic security estimates come from the MAYO submission. Applying
  the plain inversion problem to this stateful composition still requires the
  signer-salt/random-oracle reduction sketched in the design document.

## 4. Attack campaign

| Attack | Attempt and observation | Result |
|---|---|---|
| Unbounded Keccak degree | Traced every chi multiplication and checkpoint allocation. | Degree resets after each constrained four-round group; maximum is 16. |
| Fake checkpoint | Checkpoint bits are fresh commitments, then each is constrained equal to the computed state before reuse. False degree-16 witnesses were generated through the unchecked prover. | Rejected. |
| Polynomial truncation | Audited low-to-high coefficient alignment, omitted leading/error coefficient, degree shifts, mask groups, and final evaluation. Tested every degree 1–16. | No acceptance found; degree 17 is rejected. |
| Linear-constraint bypass | Re-tested the historical `assert_zero` failure mode with malicious witnesses. | Rejected; current homogenized check leaves a nonzero `Delta^2` term. |
| Quadratic-system cancellation | Tested witnesses satisfying one equation but not another and audited the independent fold coefficients before batching. | Rejected in all trials; residual field-probability term remains. |
| Learn `Delta` before fixing proof | Reconstructed transcript order. QuickSilver coefficients are absorbed before `Delta`; openings follow `Delta`. | Ordering is sound at source level. |
| Inconsistent small VOLEs | Mutated correction vectors and audited the 128-column wide hash and final random challenge. | Mutations rejected. The custom wide-hash proof still needs independent analysis. |
| Isolate one `k`-bit chunk | Compared the old scalar-check failure mode with the current column-wise `GF(2^128)` check. | The obvious `2^-k` attack is removed. |
| Tree opening equivocation | Mutated roots, siblings, hidden commitments, salts, and challenge-dependent openings. | Commitment verification rejected each mutation. |
| Fiat–Shamir splice | Changed public input, circuit parameter, context, spend, nullifier, fresh commitment, input kind, and settlement kind. | Rejected. |
| Proof/wire malleability | Flipped sampled bytes throughout a valid canonical proof. A mutation either failed parsing or failed verification. | No surviving mutation. |
| Direct/deferred response swap | Tried compile-time substitution, header retagging, retry under another settlement tag, and viewing direct zero-return artifacts as deferred. | Retagged identical-layout bodies can parse; the codec tag is not an authenticator. Proof statements and request digests reject inconsistent end-to-end use, while zero-return token/response aliases are intentionally fiscally inert. |
| Change deferred return | Modified the returned amount without changing its MAYO preimage. | Client authentication rejected it. |
| Return more than maximum | Used `t' > s`, including `u64` boundaries. | Issuer and client reject; no wrapping addition is accepted. |
| Arithmetic wraparound | Tested full refund at `u64::MAX`, over-spend, and zero final carry. | Exact Boolean equations preserve the integer relation. |
| Same token, two signatures | MAYO can have many preimages of one target, but the nullifier is derived from the target opening, not the signature. | Alternate signatures do not create a second spend lineage. |
| Same signature, two openings | Generic credential-prefix collision described in Section 3.2. | Real generic attack at the advertised collision bound; no cheaper construction-specific attack found. |
| Nested-hash malleability | Considered algebraic adjustment of `(C,t)` and zero-return reinterpretation. | No algebraic adjustment was found: the wrapper binds both. Domain separation does not make hash ranges mathematically disjoint, so generic collision/preimage attacks still apply. |
| Crash after response | The old in-memory-only API could not express the required database transaction. | Fixed: no response is returned before atomic durable insertion succeeds. |
| Multi-replica race | Two replicas may sign the same request concurrently. | Store returns the unique durable winner, and losing candidates must never reach callers, logs, telemetry, or operators. The current reduction additionally assumes response-oblivious winner selection; first-arrival timing needs a new lemma. |
| Restore key with empty or stale spent set | This would resurrect every token whose nullifier is missing from the restored snapshot. | Empty-store restoration is removed; monotonic, rollback-safe backup/failover remains a deployment requirement. |
| Parser allocation bomb | Attacked length/count fields and trailing data. | Proof counts are capped by protocol maxima; proof and outer sizes are capped at 16/32 MiB. |
| Non-canonical encoding | Added high nibble padding, wrong parameter/type tags, truncation, and trailing bytes. | Rejected. |
| Largest-parameter wrapper | Checked the common salted wrapper length against the circuit's one-block SHAKE absorber for every MAYO set. | The v3 domain omits the already-committed context and leaves the largest message 129 < 136 bytes. |
| Secret-dependent MAYO pivots | Original solver searched and indexed secret pivot positions. | Fixed with full-scan masked Gauss–Jordan elimination; only success/retry is revealed. |
| Secret remnants and logs | Long-lived keys, tokens, pending states, responses, retry records, witnesses, and solver intermediates were dropped normally; derived `Debug` output exposed response preimages. | Best-effort zeroization and redacted secret-bearing `Debug` implementations added. Stack/register copies and compiler behavior remain outside a formal guarantee. |
| Dependency compromise | Ran current `cargo-audit` data and configured `cargo-deny`. | Advisories, bans, licenses, and sources pass as of the review date. |

## 5. Findings fixed during review

### F1. Crash-safe nullifier consumption was not representable (high)

An in-memory map was correct only within one process. A deployment could send a
signature and crash before persisting the nullifier, allowing the same input to
be spent again after restart.

The new `NullifierStore` contract requires a linearizable
`insert_if_absent(nullifier, candidate) -> durable_winner`. The issuer samples a
signature, executes that operation, and only returns the stored winner. Key
restoration requires the recovered store explicitly. A failure-injection test
confirms that a storage error never releases the newly sampled credential. A
production store must select the winner by its documented linearization rule
and keep losing candidates out of logs and other observable systems; this is a
deployment premise, not something the trait can enforce. Because normal
first-arrival ordering can correlate with the variable number of sampler
attempts, merely counting all computed candidates is not enough to simulate
the visible winner. The paper-level candidate theorem therefore assumes
response-oblivious scheduling; deployments using ordinary first-arrival races
leave a separate timing/race proof gap.

A deterministic two-replica test forces both callers past an empty lookup. It
checks that identical requests and deferred requests with different proposed
returns receive one byte-identical durable winner, while conflicting requests
under the same nullifier produce exactly one success and one double-spend
error. Direct and deferred persistence-failure paths both release no response.

### F2. MAYO signing had secret-dependent pivot control flow (high)

The original Gaussian elimination used `.find`, conditional row swaps, and
secret pivot columns as indices. Repeated signing timings could reveal
information about the oil-space trapdoor.

The replacement scans all rows and columns on a public schedule, selects and
swaps pivot material with masks, performs Gauss–Jordan elimination without
secret indices, and zeroizes intermediate matrices. `vec_mul` and extension
field shifts were also made branch-free for secret inputs; generic matrix
multiplication no longer skips zero secret entries, and temporary matrices
zeroize on drop. This is a source-
level hardening, not a machine-code or physical side-channel certification.

### F3. No canonical persistence/network format existed (medium)

Ad hoc serialization would have undermined mode separation and enabled parser
DoS. Versioned canonical codecs now cover every network and crash-recovery
artifact. Expanded secret keys deterministically reconstruct their public map,
preventing public/secret mismatch on restore.

### F4. The proof bound and MAYO assumption were overstated (medium)

Documentation previously spoke loosely of 128-bit proof security and MAYO
forgery resistance. It now records the `17/2^128` assertion term. The earlier
specialized one-more-preimage assumption was subsequently removed by F8.

### F5. MAYO5 deferred tokens crossed a circuit message boundary (medium)

The first deferred-return domain string made the MAYO5 wrapper 144 bytes,
while the hidden SHAKE circuit accepts one rate block. Direct-to-deferred
settlement could create such a token, but its next presentation would fail.
The versioned wrapper domain was shortened enough that the largest supported
message was 131 bytes. F8's salted common wrapper is 129 bytes, and the
regression test continues to pin the bound below SHAKE256's 136-byte rate.

### F6. Secret heap temporaries escaped zeroization (medium)

A second review pass found `Vec`-typed secrets freed without wiping, outside
the `Mat`/struct zeroization added in F2:

- in `spre`, the `O·x_i` products (whose freed-heap copies, combined with the
  public oil block `x_i`, give linear equations on the oil space), the
  `v_i^T L_a` rows, the vinegar quadratic values, and the system-matrix
  column staging buffers;
- the secret-key nibble staging buffer on `SecretKey::from_bytes` error
  paths;
- on the prover side, the GGM tree levels, root seeds, per-tree `u` vectors,
  tag planes, `u`/tags on early-error paths, recorded QuickSilver constraint
  data, mask VOLEs, and raw per-constraint coefficients.

All of these are now wrapped in `Zeroizing` or wiped by `Drop`
implementations (`AllButOneVc`, `ProverVole`, `ProverBackend`). Circuit-level
expression temporaries inside the Keccak evaluation remain best-effort (see
B4): wiping every intermediate polynomial buffer would multiply prover
allocations, and stack/register copies are outside a source-level guarantee
anyway.

### F7. Format-hardening pass (low)

Four low-severity items were fixed together, all changing the draft wire or
transcript format in place (nothing had shipped):

- the per-proof salt widened from 128 to 256 bits (FAEST's `2λ` width), so
  multi-instance attacks on the 128-bit tree seeds get no batching
  advantage;
- `challenge_bytes` now binds its output length and uses a domain tag
  distinct from the challenge XOF, removing a prefix-collision footgun;
- wire and proof decoders parse the version byte separately from the magic
  and return a distinguishable `UnsupportedVersion` error;
- the application context is bounded (4 KiB) at key generation and both key
  decoders, so every constructible issuer key round-trips through its own
  codec; `BitVec` bounds checks are hard asserts in release builds; and a
  known-answer test pins the exact embedding constant β (its three property
  tests could not distinguish the four conjugate roots).

The canonical integration test mutates every outer artifact family—keys,
issue/spend requests and responses, pending states, both token forms, and retry
records—to wire v1 and checks explicit rejection. The embedded VOLE proof codec
remains separately versioned at proof format 1.

### F8. Signer-salted common credential target (security/design)

The previous direct credential asked the MAYO trapdoor to invert the bare
client commitment, while a deferred credential used a separate wrapper. Its
fiscal argument therefore named an adaptive one-more-preimage assumption close
to the one used by PoMFRIT's optimized construction. The colleague called that
game Definition 8; the independently checked USENIX prepublication labels the
semantic `(n,q)` one-more-preimage game Definition 3.1. Definition numbers are
version-dependent, so the semantic name is authoritative here.

Every accepted issuance or fresh-output request now receives an independent
uniform 256-bit issuer salt. Both credential kinds authenticate
`SHAKE256(commitment || return || salt)`; direct uses return zero. The salt is
chosen after proof verification, exact spend retries persist and replay the
same salt/signature pair, and response/token/retry encodings carry it. This
gives the reduction a fresh programmable random-oracle point and is intended
to reduce extra output creation through the ordinary MAYO OV/MTWMQ game
sequence. It also makes direct and deferred input proofs the same size. The
wire/context/statement versions were bumped because old credentials are
incompatible.

The all-profile characterization harness now asserts, rather than merely
prints, equal direct/deferred proof payload and request sizes for Compact,
Balanced, and LowLatency, plus the exact token and response sizes recorded in
`BENCHMARKS.md`.

## 6. Unresolved blockers

### B1. No reduction for the exact VOLE proof (high)

The implementation combines a custom wide consistency hash, degree-16
polynomial assertions, equation-system folding, multiple masking regions, and
Fiat–Shamir domains. Each idea has a recognizable antecedent, but their exact
composition is not the standardized FAEST proof. The most valuable next step
is a line-by-line proof or a refactor onto a published, reviewed proof core.

### B2. The ordinary-MAYO reduction is incomplete for the exact protocol (high)

The F8 wrapper appears to remove the need for PoMFRIT's specialized
one-more-preimage definition: the issuer, not the requester, chooses the salt
after request acceptance, so the wrapped target is a fresh random-oracle
value. The paper-level reduction plan under
`research/mayo-assumption-review/reduction/` simulates accepted signatures by programming
public-map images at fresh salted points, then applies the ordinary MAYO OV
and Multi-Target Whipped MQ hops to an unsigned output. It is not yet a
completed or formal theorem: sampler rejection, adaptive hidden-witness
extraction online before current-output signing, race scheduling and loser confidentiality, exact expanded-key OV
modeling, fixed Keccak, and the QROM still require proof and independent
review. Until then, describe ordinary MAYO as the intended foundation, not as
a proved theorem for this implementation.

The 256-attempt sampler cap needs separate treatment. MAYO Round-2 Lemma 1
averages rank failure over key generation and a fresh vinegar sample. Writing
`p_key` for the conditional failure probability of one attempt under a reused
key, the source gives `E[p_key] <= B`; it does not give the per-key bound needed
to infer `p_key^256 <= B^256`. The implementation has not exhibited an
exhaustion failure, but a stronger tail/completeness lemma or a justified
key-validation strategy is required before claiming an astronomically small
cap-failure term.

### B3. No independent interoperability oracle (medium)

Parameters, field polynomials, pair ordering, key relations, and solver
behavior were checked against the official MAYO source. Local expanded-key
round trips and derived-public-key tests pass. The library does not implement
the official seed-compressed MAYO key/signature wire format, so official KATs
cannot yet serve as an end-to-end byte oracle.

### B4. Complete constant-time behavior is unverified (medium)

Issuer signing was hardened, and the solver's one-bit masks now pass through
`core::hint::black_box` so the optimizer cannot trivially re-derive branches
from them — but no dudect, ctgrind, compiler-level audit, power analysis, or
fault campaign was run, and `black_box` is best-effort, not a guarantee. The
client-side prover still has secret-dependent source branches in satisfaction
bookkeeping and VOLE mask construction, and its circuit-level expression
temporaries are not zeroized (F6). This matters if a client proves in a
hostile co-tenant or device environment.

### B5. Fault and randomness robustness is incomplete (medium)

All privacy and soundness arguments require a healthy CSPRNG. There is no
continuous RNG test, hedged randomness, fault-detection recomputation of MAYO
preimages, or hardened hardware-key boundary. The client verifies every issuer
preimage, which catches accidental signing faults but not all leakage attacks.

### B6. Metadata and explicit mode tags (design limitation)

The issuer sees public spend/maximum charge, time, request size, context, input
credential kind, and retry behavior. Direct and deferred proofs now have equal
size, but typed statement and wire tags still reveal the selected mode. Hiding
that last bit would require an API/statement revision, not another credential
hash.

### B7. Resource amplification remains deployment-sensitive (low/medium)

Canonical parsers cap bytes and vector counts, but a syntactically valid proof
still triggers expensive tree expansion and circuit verification. Services
need request-body limits matching the selected profile, authentication or
admission control where appropriate, concurrency limits, and timeouts.

## 7. Release gates

Real-value deployment should require all of the following:

1. an independent cryptographic review of the exact transcript and proof
   equations;
2. a written ROM/QROM fiscal-soundness and anonymity argument for the
   signer-salted target and its adaptation of the ordinary MAYO OV/MTWMQ
   proof;
3. end-to-end interoperability vectors or a second independent implementation;
4. coverage-guided fuzzing of all canonical decoders and verifier entrypoints;
5. compiler-level timing tests and a fault/side-channel plan for issuer keys;
6. a transactional database implementation tested across crashes and
   concurrent replicas;
7. deployment policy for mode leakage, key epochs, maximum body size, retries,
   RNG health, and encrypted rollback-resistant client state; and
8. a fresh review after any domain, parameter, hash, codec, or circuit change.

## 8. Reproduction

```text
cargo test --workspace --locked
cargo clippy --workspace --all-targets --all-features -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps
cargo audit --no-fetch
cargo deny check
cargo bench -p vole-act --bench protocol
cargo test --release -p vole-act benchmark_profiles -- --ignored --nocapture
cargo fuzz run wire_decode -- -max_total_time=60 -dict=fuzz/dictionaries/wire.dict
cargo fuzz run proof_verify -- -max_total_time=60
cargo fuzz run protocol_artifacts -- -max_total_time=60
cargo fuzz run corner_cases -- -max_total_time=300
cargo fuzz run protocol_state -- -max_total_time=600
```

The attack-oriented regression tests include unchecked false-statement proofs,
all degrees 1–16, proof-component tampering, sampled wire mutation, type/mode
confusion, exact retry, persistence failure, full-width arithmetic, and key/
state codec recovery.

The first coverage-guided campaign also found and fixed an allocation denial
of service in the public `split_delta` helper: invalid attacker-sized `tau`
previously reached `Vec::collect` before parameter validation. Invalid geometry
now returns no chunks, and proving/verifying continue to return
`InvalidParameters`. This does not remove the need for continuous fuzzing or
independent adversarial review.

## 9. Primary references

- Baum et al., [PoMFRIT](https://eprint.iacr.org/2026/109).
- FAEST team, [algorithm specification](https://faest.info/faest-spec-v1.0.pdf).
- Baum et al., [One Tree to Rule Them All](https://eprint.iacr.org/2024/490.pdf).
- MAYO team, [round-2 specification](https://pqmayo.org/assets/specs/mayo-round2.pdf)
  and [reference implementation](https://github.com/PQCMayo/MAYO-C).
- NIST, [IR 8610](https://csrc.nist.gov/pubs/ir/8610/final) and
  [post-quantum security categories](https://csrc.nist.gov/Projects/Post-Quantum-Cryptography/Post-Quantum-Cryptography-Standardization/Evaluation-Criteria/Security-%28Evaluation-Criteria%29).
- Brassard, Høyer, and Tapp,
  [Quantum Algorithm for the Collision Problem](https://arxiv.org/abs/quant-ph/9705002).
