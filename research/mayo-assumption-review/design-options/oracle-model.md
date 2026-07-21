# Random-oracle programming versus the concrete Keccak circuit

## 1. Three different objects

Security discussions here easily slide among three non-identical objects:

1. an **ideal random oracle**, whose outputs a reduction may lazily choose and
   sometimes program;
2. a **sponge built from an ideal random permutation**, for which
   indifferentiability theorems provide a black-box bridge to a random oracle;
3. the **fixed Keccak-f[1600] permutation** expanded into VOLE-ACT's Boolean
   proof circuit.

The classical sponge theorem proves indifferentiability when the sponge's
underlying transformation or permutation is random [bert08][bert08]. A 2025
result supplies a quantum indifferentiability theorem for the sponge, with a
loose polynomial/query bound [alagic25][alagic25]. Neither theorem proves that
the particular fixed Keccak permutation is random; using Keccak instantiates
the ideal-permutation step by a cryptographic design assumption.

## 2. Why programming appears in the plain-MAYO route

The direction needed to simulate hash-and-sign is

```text
choose s -> compute y=P(s) -> arrange that H(message)=y.
```

Coron's Full-Domain-Hash analysis is a canonical example of partitioning
random-oracle queries so the simulator can answer signing queries while a
forgery lands on a challenge point [coron00][coron00]. MAYO's own proof uses a
salted fresh hash point and a PSS-style sequence of games instead
[mayo-r2][mayo-r2].

The old VOLE-ACT interface signed the credential-XOF prefix which the client had
already computed.  Its straightforward simulation therefore had to decide at
every client credential query whether to answer with a public-map image or a
challenge target.  That historical route incurred sampler loss on programmed
offline grinding queries.

The implementation now separates the client commitment from the signed target:

```text
C = H_cred(ctx,key,balance,nonce)
zeta <- uniform issuer salt after request acceptance
Y = H_sig("VOLE-ACT/signed/v3" || pack16(C) || return || zeta).
```

The signer simulation programs only the second edge.  Except when the
adversary guessed `zeta`, `H_sig` has not been queried at this input when the
issuer acts.  The credential query stays honestly random and is used for
binding/extraction, not to simulate `SPre`. Under response-oblivious winner
selection the sampler count is the number of non-replayed visible signing
points `Q_s`, rather than the number of offline credential queries. Without
that scheduling premise, a separate retry-timing/race lemma is required. The
argument is the same shape as
MAYO's salted game sequence, but the one-hash wrapper requires its own proof
[mayo-r2][mayo-r2]
([`circuit.rs:139-168`](../../../crates/vole-act/src/circuit.rs#L139-L168),
[`issuer.rs:291-301`](../../../crates/vole-act/src/protocol/issuer.rs#L291-L301)).

## 3. Why the proof circuit makes the abstraction visible

The implemented issuance and spend arguments constrain every relevant
Keccak-f round. A true random oracle has no small fixed Boolean circuit that a
VOLE proof can execute; conversely, a fixed concrete circuit cannot literally
be reprogrammed at one input. Thus a formal theorem about the implementation
cannot simultaneously say both of the following without an explicit bridge:

```text
the proof relation evaluates this fixed Keccak circuit;
the reduction chooses the output of that hash query.
```

A possible research model would define an oracle-aided relation using an ideal
XOF or an ideal-permutation gate, prove the protocol in that model, and then
argue that the concrete Keccak circuit heuristically instantiates the gate.
Sponge indifferentiability is relevant to the second step but does not by
itself provide a theorem for this exact NIZK composition, especially when the
proof system commits to hidden intermediate permutation states.

The current draft labels SHAKE's ideal-XOF treatment a heuristic bridge.  The
implemented salted wrapper makes the required programming point clean, but it
does not make a fixed Keccak evaluation literally programmable.  Its 129-byte
maximum wrapper fits one SHAKE256 rate block, which simplifies the circuit but
does not change this model distinction
([`circuit.rs:17-24`](../../../crates/vole-act/src/circuit.rs#L17-L24),
[`circuit.rs:700-705`](../../../crates/vole-act/src/circuit.rs#L700-L705)).

## 4. Classical versus quantum claims

In a classical ROM proof, the reduction can observe the adversary's discrete
oracle queries, maintain a table, partition them, and program selected fresh
entries. This still requires a protocol-specific proof and an extractor for
the NIZK witnesses.

In the QROM, the adversary may query a superposition of inputs, so “the salted
point was not queried unless the salt was guessed, then program it” is not
automatically a valid classical step. Quantum
indifferentiability of the sponge addresses the domain-extension construction,
not automatically the adaptive programming and Fiat-Shamir extraction needed
here [alagic25][alagic25]. A VOLE-ACT claim based on the present analysis should
therefore remain explicitly classical-ROM unless a dedicated QROM proof is
written.

## 5. Honest statement today

The strongest defensible formulation is:

> The implemented uniform-salt wrapper has the fresh target-hash topology
> needed for an adapted classical ideal-XOF reduction to ordinary MAYO's OV and
> MTWMQ assumptions.  The wrapper-specific game sequence, stateful extraction
> and accounting, local sampler coupling, fixed SHAKE/Keccak instantiation, and
> QROM proof remain incomplete.

That is weaker than "the code is proved secure from plain MAYO," but much more
informative than simply retaining a new one-more assumption without exploring
the hash-and-sign route.

[Back to design alternatives](index.md)

[bert08]: ../sources.md#bert08
[alagic25]: ../sources.md#alagic25
[coron00]: ../sources.md#coron00
[mayo-r2]: ../sources.md#mayo-r2
