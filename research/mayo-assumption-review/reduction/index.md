# Reduction for the implemented signer-salted wrapper

## Bottom line

The implementation has crossed the important architectural boundary identified
by the earlier review. It no longer sends a client-fixed credential target
directly to `SPre`. After accepting a proof, the issuer chooses a uniform
256-bit salt and signs the fresh point

```text
SHAKE256("VOLE-ACT/signed/v3" || pack16(C) || LE64(t) || salt)[0:4m].
```

That timing restores the public-sampling direction used by MAYO's ordinary
signature proof: choose `s`, compute `P*(s)`, and program the fresh salted
point. Exact spend retries replay the stored salt/signature pair; concurrent
race losers do not expose their candidates. The previous same-target
simulation obstruction is therefore gone except on the explicitly charged
salt-repetition/prequery event.

The strongest defensible result is still conditional. In a **classical
ideal-XOF model**, a paper-level game sequence now leads from fiscal forgery to
an unsigned wrapper message, then through the MAYO public-sampling coupling,
OV hybrid, and MTWMQ extraction. Its sampler loss is
`(1-Q_s B)^-1` under a response-oblivious race premise. Without that premise,
merely counting all `Q_try` candidates does not simulate the visible winner's
retry-timing distribution. It requires adaptive extraction, exact
expanded-key modeling, durable state,
honest independent issuer RNG, and a code-level sampler argument. It is not a
finished theorem for fixed Keccak or the QROM.

## Exact chain

1. **Fiscal orphan.** Nullifier-class conservation turns over-redemption into
   an authenticated semantic descriptor `(u,t)` not authorized by issuance or
   an earlier output.
2. **Unsigned message.** Outside a credential-prefix collision, its exact v3
   message `M=(domain,pack16(C(u)),LE64(t))` was never signed. Salt and MAYO
   preimage are authenticators, not separate credit lineages.
3. **Salt freshness.** Because the issuer samples salt after acceptance, its
   target point is fresh except for prequery or same-message salt repetition.
4. **Public-sampling coupling.** The simulator chooses uniform `s` and programs
   `Hsig(M||salt)=P*(s)`. Under response-oblivious scheduling the Round-2
   factor counts visible winners in `Q_s`. Without it, a separate race-leakage
   lemma is required. Offline hash grinding is not counted.
5. **OV.** Replace the structured public map by a random quadratic map, using
   the exact expanded encoding and derived context.
6. **MTWMQ.** Every unprogrammed v3 query is a random challenge target. The
   unsigned forgery solves one of them, except for an unqueried-target guess.

## Documents

- [Fiscal over-redemption to an unsigned wrapper
  message](fiscal-to-fresh-target.md) proves the nullifier-class accounting
  shape and the message-injectivity step.
- [Classical-ROM issuer simulator](classical-rom-simulator.md) specifies the
  table algorithm and exact issuance/retry/race counts.
- [Sampling distribution and losses](distribution-and-losses.md) reconstructs
  the MAYO coupling, salt terms, and local 256-attempt caveat.
- [Full salted-wrapper game sequence](salted-wrapper-proof-plan.md) composes
  real wrapper, salt freshness, public sampling, OV, MTWMQ, and fiscal lift.
- [Model boundaries and conditional theorem](model-boundaries.md) separates
  the paper-level ideal-XOF claim from fixed Keccak, extraction, and QROM.

## Oracle-semantics comparison

| Semantics | Plain OV+MTWMQ route | Status |
|---|---|---|
| Historical client-fixed target with fresh repeated `SPre` | Simulator lacks a second same-target trapdoor sample | Superseded implementation; custom one-more assumption was honest for that interface |
| Historical canonical response per client-fixed target | Straight-line route, but its sampler hybrid can count offline target queries | Comparison only; not implemented |
| Implemented uniform signer salt and common v3 wrapper | Fresh programmable point; `Q_s` sampler count under response-oblivious races | Leading conditional classical-ROM reduction |
| Literal Round-2 `MAYO.Sign` | Published theorem applies at the primitive layer | Not implemented; different digest, salt derivation, and wire format |

## Critical quantitative boundary

For MAYO2,

```text
B = 1.0172526041666667e-6 ~= 2^-19.907.
```

Under response-oblivious winner selection, `Q_cpl=Q_s` and the coupling theorem
requires `Q_s B<1`; at `2^19` visible responses its factor is about 2.14. The
local sampler also stops after 256 attempts. The
published rank lemma averages over the generated key and does **not** imply a
per-key exhaustion bound `B^256`; the presently justified generic bound is
only `Q_try*B`, where `Q_try` is a hard experiment-level maximum on sampler
invocations, each containing at most 256 internal rank attempts. Improving
that cap term is the clearest newly exposed
code-level proof gap.

## Honest conclusion

The custom one-more-preimage assumption appears unnecessary for the
**implemented signer-salted oracle** in the classical ideal-XOF proof plan.
That is an architectural and proof-strategy conclusion, not yet an end-to-end
security theorem. Production claims must wait for the named sampler,
extraction, state, OV-encoding, and model-instantiation obligations.

[Back to the corpus index](../index.md)

[baum26]: ../sources.md#baum26
[mayo-r2]: ../sources.md#mayo-r2
