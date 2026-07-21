# Implemented signer-salted wrapper and remaining alternatives

## Current conclusion

VOLE-ACT has implemented the design change which the first review identified
as the best proof direction.  The issuer no longer applies `SPre` to the bare,
client-fixed credential commitment.  After accepting a request it samples a
uniform 256-bit salt, hashes the commitment, return amount, and salt into a new
MAYO target, and returns the salt with the preimage.  Both direct and deferred
credentials prove this same salted wrapper.

This removes the specific same-target simulation obstruction which made the
old public oracle naturally one-more-shaped.  It does **not** finish the
security proof.  The implemented wrapper has the same fresh-point programming
direction as ordinary MAYO, but is not Round-2 `MAYO.Sign`; its exact
classical-ROM reduction, local sampler coupling, stateful lifting, fixed-Keccak
bridge, and QROM treatment remain open.

See [the oracle-model boundary](oracle-model.md) for why a programmable ideal
XOF and the checked Keccak circuit must still be kept distinct.

## 1. Exact implemented construction

For the already-proved base commitment `C`, issuer-selected return `t` (`0` for
direct credentials), and fresh issuer salt `zeta`, define

```text
S(C,t,zeta) = SHAKE256(
  "VOLE-ACT/signed/v3" || pack16(C) || enc64(t) || zeta
)[0:4m].
```

After proof verification the issuer executes

```text
zeta  <- uniform {0,1}^256
Y     <- S(C,t,zeta)
sigma <- SPre(sk,Y; caller RNG)
return (zeta,sigma[,t]).
```

The implementation is visible directly in
[`circuit.rs:139-168`](../../../crates/vole-act/src/circuit.rs#L139-L168) and
[`issuer.rs:291-301`](../../../crates/vole-act/src/protocol/issuer.rs#L291-L301).
The spend circuit treats `zeta` as hidden witness, recomputes the wrapper, and
asserts `P*(sigma)=Y`
([`circuit.rs:531-560`](../../../crates/vole-act/src/circuit.rs#L531-L560),
[`circuit.rs:655-674`](../../../crates/vole-act/src/circuit.rs#L655-L674)).
The domain omits a repeated context because `C` binds `ctx` outside a
credential-prefix collision; the largest supported encoding is 129 bytes,
within one 136-byte SHAKE256 rate block
([`circuit.rs:17-24`](../../../crates/vole-act/src/circuit.rs#L17-L24),
[`circuit.rs:700-705`](../../../crates/vole-act/src/circuit.rs#L700-L705)).

The response/token/retry formats carry the 32-byte salt.  An exact successful
spend retry returns the durable stored `(zeta,sigma,t)`; it does not sample a
second salt or call `SPre` again
([`issuer.rs:182-238`](../../../crates/vole-act/src/protocol/issuer.rs#L182-L238),
[`store.rs:87-164`](../../../crates/vole-act/src/protocol/store.rs#L87-L164)).
Issuance has no retry cache: each separately accepted/authorized issuance is a
new signing event and samples a new salt
([`issuer.rs:148-180`](../../../crates/vole-act/src/protocol/issuer.rs#L148-L180)).

## 2. What changed intellectually

The old and new simulation directions are different:

```text
old bare-target interface:
    client fixes C -> issuer must solve P*(sigma)=C

implemented salted interface:
    client fixes C; direct fixes t=0 or deferred issuer supplies t after request
    message descriptor (C,t) is now fixed
    issuer chooses unpredictable zeta
    simulator may choose sigma -> program H_sig(C,t,zeta)=P*(sigma).
```

PoMFRIT Section 6 exposes the first kind of target inversion and therefore uses
its new one-more-preimage assumption.  PoMFRIT Section 5 retains ordinary MAYO
hash-and-sign verification and reduces to MAYO EUF-CMA.  Round-2 MAYO simulates
signing by programming fresh salted target-hash points, then reduces a forgery
through OV and Multi-Target Whipped MQ [baum26][baum26]
[mayo-r2][mayo-r2].

The implemented wrapper now has the second direction.  The salt is revealed
with the response, but a classical adversary must have guessed its 256 bits to
query the exact target-hash point beforehand.  A natural adapted game charges a
term on the order of

```text
(Q_h + Q_s) * Q_s / 2^256
```

for prequeries and repeated signing points.  At a fresh point the simulator can
sample `sigma`, compute `P*(sigma)`, program the hash, and return the pair.  This
is an adaptation of MAYO's technique, not a theorem quoted verbatim.

## 3. Security-dependency ledger

| Claim or component | Status | Why |
|---|---|---|
| Uniform 32-byte salt is sampled after accepted verification | **Implemented** | Issuer helper fills the salt before hashing and `SPre` |
| Salt, return, and commitment are authenticated by one wrapper | **Implemented and tested** | Native verification and spend circuit recompute the target |
| Direct and deferred credentials share one relation | **Implemented** | Direct constrains return to zero; proof payload sizes are identical |
| Fresh salted programming is a valid proof technique | **Inherited technique** | MAYO Round-2 Lemma 2 uses this direction; PoMFRIT Section 5 contributes the message/signature extraction layer |
| Primitive assumptions are OV plus MTWMQ | **Intended conditional foundation** | These are the Round-2 assumptions, themselves conjectured |
| Salt-prequery term is approximately `(Q_h+Q_s)Q_s/2^256` | **Adapted game bound** | Uniform salt differs from Algorithm 7's secret-seed derivation |
| Sampler loss counts online signing responses, not offline grinding | **Conditional adapted result** | `Q_s` needs response-oblivious scheduling; otherwise a retry-timing/race lemma is missing |
| Round-2 Theorem 1 proves this wrapper verbatim | **False** | Message hashing, salt derivation, signing coins, encodings, and protocol state differ |
| PoMFRIT one-more preimage is still the intended premise | **No** | The requester no longer supplies the final target inverted by `SPre` |
| Fiscal soundness follows from primitive EUF-CMA | **Paper-level plan** | Extraction and nullifier-class accounting must lift a fiscal win to an unsigned wrapper message |
| Fixed Keccak and QROM follow from the classical ROM game | **Open** | Programming and adaptive extraction require separate bridges |

The Round-2 rejection bound remains a real quantitative boundary.  For MAYO2,
`B` is approximately `2^-19.907`; the published proof's constant-factor regime
is below about `2^19` signing samples per key, and the theorem becomes vacuous
once the applicable coupling count satisfies `Q_cpl B >= 1`. The authors
expect security beyond that range and report no
attack, but that expectation is not theorem-level coverage
[mayo-r2][mayo-r2].  The local `SPre` uses caller randomness and a 256-attempt
cap, so its exact distribution and failure probability still need a code-level
argument. In particular, Lemma 1 gives `E_K[p_K] <= B` over generated keys,
not a uniform per-key bound; it therefore does not justify replacing the cap
failure `p_K^256` by `B^256`
([`scheme.rs:509-622`](../../../crates/mayo/src/scheme.rs#L509-L622)).

## 4. Design comparison after implementation

| Variant | Assumption/proof route | Circuit and wire cost | State/round cost | Present judgment |
|---|---|---|---|---|
| **Implemented uniform-salt one-hash wrapper** | Adapted classical-ROM route to OV + MTWMQ | Three hidden hashes in every spend; 32-byte salt in token/response; common proof shape | Existing nullifier retry record stores salt; no extra round | Best current design; exact reduction remains a blocker |
| Literal Round-2 `MAYO.Sign`/Verify | Published primitive theorem can be invoked most directly | Likely message-digest plus digest/salt hash in addition to base commitment; unmeasured | No target index; Algorithm-7 key/coin derivations | Cleanest citation target, but materially more circuit machinery |
| Canonical response per bare target | Straight-line ROM route may use OV + MTWMQ | Historical cheaper direct relation | Durable target index across issuance and spends | Avoids wrapper hash but the presented proof's sampler loss counts programmed hash queries, including grinding |
| Old fresh `SPre` on bare target | Custom adaptive one-more assumption | Historical direct/deferred split | Old nullifier store only | Obsolete; stronger assumption and unresolved same-target auxiliary samples |
| Issuer challenge inside base commitment | Fresh-point programming | Could avoid outer hash | Extra round and durable one-use challenge semantics | No advantage over the implemented noninteractive wrapper |
| Deterministic secret `SPre` coins | New PRF/deterministic-sampling argument | Could avoid outer hash | No target table | Adds fault, side-channel, and proof obligations without a clear benefit |

The one-hash wrapper is intentionally not called “standard MAYO.”  Round-2
Algorithm 7 computes `M_digest=SHAKE256(M)`, derives salt from
`M_digest||R||seed_sk`, derives the target from `M_digest||salt`, and derives
sampling coins from additional secret-seeded SHAKE calls.  VOLE-ACT instead
uses an independent uniform issuer salt, one target hash, and the local
RNG-driven `SPre` [mayo-r2][mayo-r2].

## 5. Measured cost of the implemented wrapper

The current 2026-07-21 Criterion snapshot is no longer a proxy: it measures the
wire-v2 common wrapper itself
([benchmark snapshot](../../../docs/BENCHMARKS.md#signer-salted-common-wrapper-experiment-2026-07-21)).

| Client proving time (ms) | Compact | Balanced | Low latency |
|---|---:|---:|---:|
| Issue | 10.04 | 8.59 | 8.61 |
| Spend, direct input | 31.17 | 28.96 | 28.99 |
| Spend, deferred input | 31.30 | 28.58 | 29.42 |

Thus current issue proving spans 8.59–10.04 ms and spend proving spans
28.58–31.30 ms across profiles.  In Balanced, issuer verify-and-sign spans
9.22–9.36 ms across the three spend paths, and the measured spend end-to-end
central estimates span 39.00–40.74 ms.  These are machine-specific sampled
latencies, not sustained throughput.

| Common-wrapper proof payload (bytes) | Compact | Balanced | Low latency |
|---|---:|---:|---:|
| Direct or deferred input | 72,784 | 141,424 | 278,704 |

| Current wire artifact (bytes) | Compact | Balanced | Low latency |
|---|---:|---:|---:|
| Token, either marker | 315 | 315 | 315 |
| Issue request | 29,750 | 55,286 | 106,358 |
| Spend request, either input | 73,086 | 141,918 | 279,582 |
| Issue / spend response | 203 / 211 | 203 / 211 | 203 / 211 |

Relative to the historical pre-wrapper payload, the direct-input proof grows
about 38–41%, while the already-wrapped deferred proof grows about 0.7%.
Direct and deferred proofs are now byte-for-byte equal for a fixed profile.
Criterion's stored-baseline comparison measured a 49–53% direct-input prover
regression; deferred-input timing did not regress in that comparison.  Tokens
and responses grow by exactly 32 bytes for the signer salt.  The reproducible
arithmetic is in
[`data/compare_current_profiles.py`](data/compare_current_profiles.py), which
reads the committed
[`current_wrapper_snapshot.json`](data/current_wrapper_snapshot.json). This is
an arithmetic snapshot, not an independent Criterion rerun. The exact raw mean
estimates, 95% confidence intervals, command, host, and toolchain are preserved
in [`criterion-2026-07-21.json`](data/criterion-2026-07-21.json).

## 6. Remaining engineering and proof obligations

1. Complete and independently review the paper-level primitive wrapper
   EUF-CMA game sequence, including the uniform-salt prequery/collision terms,
   the local sampler distribution, and its formal query bounds.
2. Formalize and review the paper-level lift from an accepted fiscal forgery to
   an unsigned wrapper message using
   adaptive proof extraction, credential-prefix collision bounds, and the
   nullifier-class ledger.
3. State an operational per-key signing budget and prove a stronger per-key
   sampler tail/completeness bound (or a justified key-validation strategy) for
   high-volume issuers.
4. Prove the spend-race normalization under explicit store premises. The
   implementation may compute a losing candidate before `insert_if_absent`;
   winner selection must be response-oblivious, and rejected candidates must
   remain confidential from callers, logs, telemetry, and operators.
5. Prove only the classical ideal-XOF statement presently supported.  Treat
   fixed Keccak/ideal-permutation instantiation and QROM extraction as separate
   claims.
6. Validate honest, non-reused cryptographic RNG state across issuer calls and
   replicas; salt freshness and independent `SPre` coins depend on it.

## 7. Recommendation

Keep the implemented common wrapper and update the security narrative around
it.  The old custom one-more assumption should be retained only as historical
analysis of the obsolete bare-target interface, not as the intended foundation
of the current protocol.  The live claim should instead be:

> In a classical ideal-XOF model, the signer-salted wrapper is intended to
> reduce to the ordinary MAYO assumption package—OV plus MTWMQ—through an
> adapted fresh-point programming argument.  That wrapper-specific reduction,
> the stateful fiscal lifting, the local sampler coupling, and the concrete/QROM
> bridges remain incomplete.

No further protocol change is justified by the papers alone.  The next useful
artifact is the completed reduction and its review, not another target-format
revision.

[Back to the corpus index](../index.md)

[mayo-r2]: ../sources.md#mayo-r2
[baum26]: ../sources.md#baum26
