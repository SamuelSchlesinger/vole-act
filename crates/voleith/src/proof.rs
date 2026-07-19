//! The non-interactive proof: orchestration of VOLE commitment, the
//! consistency check, the batched QuickSilver check, and Fiat–Shamir.
//!
//! ## Coordinate layout (ℓ̂ = ℓ + 2λ)
//!
//! | range            | use                                   |
//! |------------------|---------------------------------------|
//! | `[0, ℓ)`         | witness bits                          |
//! | `[ℓ, ℓ+λ)`       | QuickSilver mask (`u*`, `v*`)         |
//! | `[ℓ+λ, ℓ+2λ)`    | consistency-check mask (`m_u`, `m_v`) |
//!
//! ## Transcript order
//!
//! `public ∥ dims ∥ salt ∥ coms ∥ corrections ∥ d` → challenge `α`
//! (consistency coefficients) → `(ũ, ṽ)` → challenge `χ` (QuickSilver
//! coefficients) → `(U, W)` → challenge `Δ` → tree openings.
//!
//! The u-corrections are absorbed *before* `α` is derived (so any
//! chunk-inconsistency is fixed before the check coefficients are known),
//! and everything binding the witness is absorbed before `Δ`.
//!
//! ## Checks performed by the verifier
//!
//! 1. Vector-commitment openings against the τ tree commitments at `Δⱼ`.
//! 2. Consistency: `Σₜ αₜ·Kₜ + K_m = ṽ + ũ·Δ` over the u-stage keys —
//!    forces all repetitions to share one `u` (up to the masked coords).
//! 3. QuickSilver: `Σᵢ χᵢ·Bᵢ + Q* = W + U·Δ` over the witness-stage keys —
//!    forces every circuit constraint.

use crate::VoleithError;
use crate::backend::{
    Circuit, CountingBackend, ProverBackend, ProverConstraint, VerifierBackend, VerifierConstraint,
};
use crate::bits::BitVec;
use crate::transcript::Transcript;
use crate::vole::{Params, ProverVole, reconstruct_keys, split_delta};
use binary_fields::{BinaryField, GF2p128};
use rand_core::CryptoRngCore;
use sha3::digest::XofReader;
use vector_commit::{Seed, VcCommitment, VcOpening};

const PROTOCOL_LABEL: &[u8] = b"VOLE-ACT/voleith/v1";

/// A non-interactive VOLE-in-the-head proof.
#[derive(Clone, Debug)]
pub struct Proof {
    /// Per-proof salt for all PRG/hash domain separation.
    pub salt: [u8; 16],
    /// Per-tree vector commitments.
    pub coms: Vec<VcCommitment>,
    /// u-corrections `c⁽ʲ⁾` for trees `2..τ`.
    pub corrections: Vec<BitVec>,
    /// Witness bit corrections `d_t = u_t ⊕ w_t`.
    pub d: BitVec,
    /// Consistency check: masked coefficient-hash of `u`.
    pub u_tilde: GF2p128,
    /// Consistency check: masked coefficient-hash of the tags.
    pub v_tilde: GF2p128,
    /// QuickSilver: masked `Σ χᵢ·A₁⁽ⁱ⁾`.
    pub qs_u: GF2p128,
    /// QuickSilver: masked `Σ χᵢ·A₀⁽ⁱ⁾`.
    pub qs_w: GF2p128,
    /// All-but-one openings of the τ trees.
    pub openings: Vec<VcOpening>,
}

/// Read one field element from a challenge stream.
fn next_elem(reader: &mut impl XofReader) -> GF2p128 {
    let mut buf = [0u8; 16];
    reader.read(&mut buf);
    GF2p128::from_bytes(buf)
}

/// Absorb the proof prologue (everything up to the first challenge) into the
/// transcript, identically on both sides.
#[allow(clippy::too_many_arguments)]
fn absorb_prologue(
    tr: &mut Transcript,
    public_input: &[u8],
    params: &Params,
    num_witness_bits: usize,
    salt: &[u8; 16],
    coms: &[VcCommitment],
    corrections: &[BitVec],
    d: &BitVec,
) {
    tr.absorb(b"public", public_input);
    let mut dims = Vec::new();
    dims.extend_from_slice(&(params.tau as u64).to_le_bytes());
    dims.extend_from_slice(&(params.k as u64).to_le_bytes());
    dims.extend_from_slice(&(num_witness_bits as u64).to_le_bytes());
    tr.absorb(b"dims", &dims);
    tr.absorb(b"salt", salt);
    for com in coms {
        tr.absorb(b"com", &com.0);
    }
    for c in corrections {
        tr.absorb(b"correction", c.as_bytes());
    }
    tr.absorb(b"witness-d", d.as_bytes());
}

/// Compute the consistency-check hashes over coordinates `[0, ℓ+λ)` with
/// XOF-derived coefficients, plus the `X^b`-combined mask coordinates.
///
/// Returns the masked `(hash of u, hash of tags/keys)` pair — on the prover
/// side pass `Some(u)` to get both; on the verifier side pass `None` and use
/// the returned "tag" slot as the key-side combination.
fn consistency_combine(
    alpha: &mut impl XofReader,
    l: usize,
    lambda: usize,
    u: Option<&BitVec>,
    elems: &[GF2p128],
) -> (GF2p128, GF2p128) {
    let mut u_acc = GF2p128::ZERO;
    let mut e_acc = GF2p128::ZERO;
    for (t, elem) in elems.iter().enumerate().take(l + lambda) {
        let a = next_elem(alpha);
        if let Some(u) = u
            && u.get(t)
        {
            u_acc += a;
        }
        e_acc += a * *elem;
    }
    // Mask coordinates [ℓ+λ, ℓ+2λ) enter with fixed coefficients X^b.
    for b in 0..lambda {
        let t = l + lambda + b;
        let xb = GF2p128::new(1u128 << b);
        if let Some(u) = u
            && u.get(t)
        {
            u_acc += xb;
        }
        e_acc += xb * elems[t];
    }
    (u_acc, e_acc)
}

/// Combine the QuickSilver mask coordinates `[ℓ, ℓ+λ)` into a single
/// `F₂^λ`-valued VOLE: value `Σ X^b·u_b`, tag/key `Σ X^b·elem_b`.
fn qs_mask_combine(
    l: usize,
    lambda: usize,
    u: Option<&BitVec>,
    elems: &[GF2p128],
) -> (GF2p128, GF2p128) {
    let mut u_acc = GF2p128::ZERO;
    let mut e_acc = GF2p128::ZERO;
    for b in 0..lambda {
        let t = l + b;
        let xb = GF2p128::new(1u128 << b);
        if let Some(u) = u
            && u.get(t)
        {
            u_acc += xb;
        }
        e_acc += xb * elems[t];
    }
    (u_acc, e_acc)
}

/// Produce a proof that `circuit` is satisfied by `witness`.
///
/// `public_input` binds any public statement data (it is absorbed first).
/// The witness is the ordered list of bits the circuit's `witness_bit` calls
/// consume. Returns [`VoleithError::Unsatisfiable`] when the witness does not
/// satisfy the circuit.
pub fn prove<C: Circuit>(
    params: &Params,
    public_input: &[u8],
    circuit: &C,
    witness: &[bool],
    rng: &mut impl CryptoRngCore,
) -> Result<Proof, VoleithError> {
    prove_impl(params, public_input, circuit, witness, rng, true)
}

/// Core prover. When `enforce_satisfied` is false the satisfiability check is
/// skipped and a (necessarily-rejected) proof is produced anyway — used only
/// by soundness tests that must construct malicious proofs directly.
pub(crate) fn prove_impl<C: Circuit>(
    params: &Params,
    public_input: &[u8],
    circuit: &C,
    witness: &[bool],
    rng: &mut impl CryptoRngCore,
    enforce_satisfied: bool,
) -> Result<Proof, VoleithError> {
    params.validate()?;
    let lambda = params.lambda();

    // Size the circuit.
    let mut counter = CountingBackend::default();
    circuit.build(&mut counter)?;
    let l = counter.witness_bits;
    if l == 0 {
        return Err(VoleithError::InvalidParameters);
    }
    if witness.len() != l {
        return Err(VoleithError::WitnessMismatch);
    }
    let l_hat = l + 2 * lambda;

    // Commit the VOLE correlations.
    let mut salt = [0u8; 16];
    rng.fill_bytes(&mut salt);
    let mut roots: Vec<Seed> = vec![[0u8; 16]; params.tau];
    for r in roots.iter_mut() {
        rng.fill_bytes(r);
    }
    let vole = ProverVole::commit(&roots, &salt, l_hat, params)
        .map_err(|_| VoleithError::InvalidParameters)?;

    // Run the circuit: collects d corrections and constraint coefficients.
    let mut backend = ProverBackend::new(witness, &vole.u, &vole.tags);
    circuit.build(&mut backend)?;
    if backend.bits_used() != l {
        return Err(VoleithError::WitnessMismatch);
    }
    if enforce_satisfied && !backend.satisfied {
        return Err(VoleithError::Unsatisfiable);
    }
    let mut d = BitVec::zero(l);
    for (t, bit) in backend.d.iter().enumerate() {
        d.set(t, *bit);
    }

    // Fiat-Shamir.
    let mut tr = Transcript::new(PROTOCOL_LABEL);
    absorb_prologue(
        &mut tr,
        public_input,
        params,
        l,
        &salt,
        &vole.coms,
        &vole.corrections,
        &d,
    );

    // Consistency check.
    let mut alpha = tr.challenge_xof(b"alpha");
    let (u_tilde, v_tilde) = consistency_combine(&mut alpha, l, lambda, Some(&vole.u), &vole.tags);
    let mut consist = Vec::with_capacity(32);
    consist.extend_from_slice(&u_tilde.to_bytes());
    consist.extend_from_slice(&v_tilde.to_bytes());
    tr.absorb(b"consistency", &consist);

    // QuickSilver batch. Quadratic systems draw their fold coefficients
    // from the same challenge stream, in emission order, before their χ.
    let mut chi = tr.challenge_xof(b"chi");
    let (qs_mask_u, qs_mask_v) = qs_mask_combine(l, lambda, Some(&vole.u), &vole.tags);
    let mut qs_w = qs_mask_v;
    let mut qs_u = qs_mask_u;
    for constraint in &backend.constraints {
        let (a0, a1) = match constraint {
            ProverConstraint::Simple(a0, a1) => (*a0, *a1),
            ProverConstraint::System(sys) => {
                let phis: Vec<GF2p128> = (0..sys.num_equations())
                    .map(|_| next_elem(&mut chi))
                    .collect();
                let (a0, a1, sat) = sys.fold(&phis);
                if !sat {
                    return Err(VoleithError::Unsatisfiable);
                }
                (a0, a1)
            }
        };
        let x = next_elem(&mut chi);
        qs_w += x * a0;
        qs_u += x * a1;
    }
    let mut qs_bytes = Vec::with_capacity(32);
    qs_bytes.extend_from_slice(&qs_u.to_bytes());
    qs_bytes.extend_from_slice(&qs_w.to_bytes());
    tr.absorb(b"quicksilver", &qs_bytes);

    // Final challenge and openings.
    let mut chall3 = [0u8; 16];
    tr.challenge_bytes(b"delta", &mut chall3);
    let (_delta, chunks) = split_delta(&chall3, params);
    let openings = vole
        .open(&chunks)
        .map_err(|_| VoleithError::InvalidParameters)?;

    Ok(Proof {
        salt,
        coms: vole.coms,
        corrections: vole.corrections,
        d,
        u_tilde,
        v_tilde,
        qs_u,
        qs_w,
        openings,
    })
}

/// Verify a proof against a circuit and public input.
pub fn verify<C: Circuit>(
    params: &Params,
    public_input: &[u8],
    circuit: &C,
    proof: &Proof,
) -> Result<(), VoleithError> {
    params.validate()?;
    let lambda = params.lambda();

    // Size the circuit and validate proof shape.
    let mut counter = CountingBackend::default();
    circuit.build(&mut counter)?;
    let l = counter.witness_bits;
    if l == 0 {
        return Err(VoleithError::InvalidParameters);
    }
    let l_hat = l + 2 * lambda;
    if proof.d.len() != l
        || proof.coms.len() != params.tau
        || proof.corrections.len() != params.tau - 1
        || proof.openings.len() != params.tau
        || proof.corrections.iter().any(|c| c.len() != l_hat)
    {
        return Err(VoleithError::InvalidProof);
    }

    // Replay the transcript.
    let mut tr = Transcript::new(PROTOCOL_LABEL);
    absorb_prologue(
        &mut tr,
        public_input,
        params,
        l,
        &proof.salt,
        &proof.coms,
        &proof.corrections,
        &proof.d,
    );
    let mut alpha = tr.challenge_xof(b"alpha");
    let mut consist = Vec::with_capacity(32);
    consist.extend_from_slice(&proof.u_tilde.to_bytes());
    consist.extend_from_slice(&proof.v_tilde.to_bytes());
    tr.absorb(b"consistency", &consist);
    let mut chi = tr.challenge_xof(b"chi");
    let mut qs_bytes = Vec::with_capacity(32);
    qs_bytes.extend_from_slice(&proof.qs_u.to_bytes());
    qs_bytes.extend_from_slice(&proof.qs_w.to_bytes());
    tr.absorb(b"quicksilver", &qs_bytes);
    let mut chall3 = [0u8; 16];
    tr.challenge_bytes(b"delta", &mut chall3);
    let (delta, chunks) = split_delta(&chall3, params);

    // Reconstruct the u-stage keys from the openings.
    let keys = reconstruct_keys(
        &proof.salt,
        l_hat,
        params,
        &proof.coms,
        &proof.corrections,
        &chunks,
        &proof.openings,
    )
    .map_err(|_| VoleithError::InvalidProof)?;

    // Consistency check: Σ αₜ·Kₜ + K_mask == ṽ + ũ·Δ.
    let (_, key_combined) = consistency_combine(&mut alpha, l, lambda, None, &keys);
    if key_combined != proof.v_tilde + proof.u_tilde * delta {
        return Err(VoleithError::InvalidProof);
    }

    // Witness-stage keys: K'_t = K_t + d_t·Δ.
    let wkeys: Vec<GF2p128> = keys
        .iter()
        .take(l)
        .enumerate()
        .map(|(t, &k)| if proof.d.get(t) { k + delta } else { k })
        .collect();

    // Run the circuit over keys.
    let mut backend = VerifierBackend::new(&wkeys, delta);
    circuit.build(&mut backend)?;
    if backend.bits_used() != l {
        return Err(VoleithError::WitnessMismatch);
    }

    // QuickSilver check: Σ χᵢ·Bᵢ + Q* == W + U·Δ.
    let (_, qs_mask_key) = qs_mask_combine(l, lambda, None, &keys);
    let mut acc = qs_mask_key;
    for check in &backend.checks {
        let b = match check {
            VerifierConstraint::Simple(b) => *b,
            VerifierConstraint::System(sys) => {
                let phis: Vec<GF2p128> = (0..sys.num_equations())
                    .map(|_| next_elem(&mut chi))
                    .collect();
                sys.fold(&phis, delta)
            }
        };
        let x = next_elem(&mut chi);
        acc += x * b;
    }
    if acc != proof.qs_w + proof.qs_u * delta {
        return Err(VoleithError::InvalidProof);
    }

    Ok(())
}

#[cfg(test)]
mod soundness_tests {
    use super::*;
    use crate::backend::Backend;
    use crate::vole::PARAMS_128;
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    /// A circuit that asserts a single witness bit is zero. With a witness
    /// bit of 1 the statement is false; an honest prover would refuse, but a
    /// malicious one (via `prove_impl(.., false)`) still emits a proof — the
    /// verifier MUST reject it. This is the regression test for the
    /// `assert_zero`-not-enforced bug (Codex S5).
    struct AssertBitZero;

    impl Circuit for AssertBitZero {
        fn build<B: Backend>(&self, backend: &mut B) -> Result<(), VoleithError> {
            let b = backend.witness_bit()?;
            backend.assert_zero(&b);
            Ok(())
        }
    }

    #[test]
    fn false_linear_assertion_is_rejected() {
        let mut rng = StdRng::seed_from_u64(100);
        // Honest witness (bit = 0) verifies.
        let ok = prove_impl(&PARAMS_128, b"az", &AssertBitZero, &[false], &mut rng, true).unwrap();
        verify(&PARAMS_128, b"az", &AssertBitZero, &ok).unwrap();

        // Malicious proof over a false statement (bit = 1) must be rejected
        // by the verifier, across many transcripts (no lucky Δ).
        for seed in 0..40u64 {
            let mut rng = StdRng::seed_from_u64(1000 + seed);
            let bad =
                prove_impl(&PARAMS_128, b"az", &AssertBitZero, &[true], &mut rng, false).unwrap();
            assert_eq!(
                verify(&PARAMS_128, b"az", &AssertBitZero, &bad),
                Err(VoleithError::InvalidProof),
                "false assert_zero accepted at seed {seed}"
            );
        }
    }
}
