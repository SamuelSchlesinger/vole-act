//! VOLE correlation generation from all-but-one vector commitments.
//!
//! Per repetition `j ∈ [τ]`, a depth-`k` GGM tree commits `N = 2^k` seeds;
//! each seed `i` expands to a vector `r_i ∈ F₂^ℓ̂`. The prover computes
//!
//! - `u⁽ʲ⁾ = Σᵢ rᵢ` — the committed random vector, and
//! - tag planes `v_b⁽ʲ⁾ = Σᵢ bit_b(i)·rᵢ` for `b ∈ [k]`,
//!
//! while the verifier — knowing every leaf except `Δⱼ` — computes key planes
//! from `qₜ = Σ_{i≠Δ}(i ⊕ Δ)·rᵢ[t]`. Because the `i = Δ` term of
//! `Σᵢ(i ⊕ Δ)·rᵢ[t]` is zero, `qₜ = vₜ + Δⱼ·uₜ` — a VOLE correlation over
//! `F₂^k` — *without* the verifier ever seeing leaf `Δⱼ`.
//!
//! Public corrections `c⁽ʲ⁾ = u⁽¹⁾ ⊕ u⁽ʲ⁾` re-base every repetition onto the
//! shared `u = u⁽¹⁾`; concatenating the τ chunk tags/keys per coordinate then
//! yields a single VOLE over `F₂^λ` (λ = τ·k): `Kₜ = Vₜ + uₜ·Δ`, where the
//! field element `Δ` has `Δⱼ` in bit positions `[jk, jk+k)`.

use crate::bits::BitVec;
use binary_fields::{BinaryField, GF2p128};
use sha3::Shake256;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use vector_commit::{AllButOneVc, Seed, VcCommitment, VcError, VcOpening};

/// VOLE-in-the-head parameters. `λ = tau · k` must equal 128.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Params {
    /// Number of GGM-tree repetitions.
    pub tau: usize,
    /// Tree depth; each repetition has `2^k` leaves.
    pub k: usize,
}

/// λ = 128 with τ = 16 trees of depth 8 (256 leaves each).
pub const PARAMS_128: Params = Params { tau: 16, k: 8 };

impl Params {
    /// The security parameter λ = τ·k in bits.
    #[must_use]
    pub const fn lambda(&self) -> usize {
        self.tau * self.k
    }

    /// Leaves per tree.
    #[must_use]
    pub const fn leaves(&self) -> usize {
        1 << self.k
    }
}

/// Derive the salt for tree `j`'s internal vector-commitment hashing.
fn tree_salt(salt: &[u8; 16], j: usize) -> [u8; 16] {
    let mut h = Shake256::default();
    h.update(b"VOLE-ACT/voleith/v1/tree-salt");
    h.update(salt);
    h.update(&(j as u64).to_le_bytes());
    let mut out = [0u8; 16];
    h.finalize_xof().read(&mut out);
    out
}

/// Expand leaf `i` of tree `j` into its ℓ̂-bit VOLE contribution.
fn expand_leaf(salt: &[u8; 16], j: usize, i: usize, seed: &Seed, l_hat: usize) -> BitVec {
    let mut h = Shake256::default();
    h.update(b"VOLE-ACT/voleith/v1/leaf-expand");
    h.update(salt);
    h.update(&(j as u64).to_le_bytes());
    h.update(&(i as u64).to_le_bytes());
    h.update(seed);
    let mut reader = h.finalize_xof();
    BitVec::from_xof(&mut reader, l_hat)
}

/// Assemble per-coordinate `F₂^λ` elements from τ·k bit planes.
///
/// `planes[j][b]` holds bit `jk + b` of every coordinate's field element.
fn assemble(planes: &[Vec<BitVec>], params: &Params, l_hat: usize) -> Vec<GF2p128> {
    let mut out = vec![GF2p128::ZERO; l_hat];
    for (j, tree_planes) in planes.iter().enumerate() {
        for (b, plane) in tree_planes.iter().enumerate() {
            let pos = (j * params.k + b) as u32;
            for (t, elem) in out.iter_mut().enumerate() {
                if plane.get(t) {
                    *elem += GF2p128::new(1u128 << pos);
                }
            }
        }
    }
    out
}

/// Prover-side VOLE state: the committed random vector `u`, per-coordinate
/// tags `V`, tree commitments, and public corrections.
pub struct ProverVole {
    /// The shared committed random bit vector (`u = u⁽¹⁾`), length ℓ̂.
    pub u: BitVec,
    /// Per-coordinate tags `Vₜ ∈ F₂^λ`, length ℓ̂.
    pub tags: Vec<GF2p128>,
    /// Per-tree commitments (published).
    pub coms: Vec<VcCommitment>,
    /// Corrections `c⁽ʲ⁾ = u⁽¹⁾ ⊕ u⁽ʲ⁾` for `j = 2..τ` (published).
    pub corrections: Vec<BitVec>,
    trees: Vec<AllButOneVc>,
}

impl ProverVole {
    /// Commit to ℓ̂ VOLE correlations across τ trees.
    pub fn commit(
        root_seeds: &[Seed],
        salt: &[u8; 16],
        l_hat: usize,
        params: &Params,
    ) -> Result<Self, VcError> {
        assert_eq!(params.lambda(), 128, "only λ = 128 is supported");
        assert_eq!(root_seeds.len(), params.tau);

        let mut trees = Vec::with_capacity(params.tau);
        let mut coms = Vec::with_capacity(params.tau);
        let mut us: Vec<BitVec> = Vec::with_capacity(params.tau);
        let mut planes: Vec<Vec<BitVec>> = Vec::with_capacity(params.tau);

        for (j, root) in root_seeds.iter().enumerate() {
            let (vc, com) = AllButOneVc::commit(*root, tree_salt(salt, j), params.k as u32)?;
            let mut u_j = BitVec::zero(l_hat);
            let mut planes_j = vec![BitVec::zero(l_hat); params.k];
            for (i, leaf) in vc.leaves().iter().enumerate() {
                let r_i = expand_leaf(salt, j, i, leaf, l_hat);
                u_j.xor_assign(&r_i);
                for (b, plane) in planes_j.iter_mut().enumerate() {
                    if (i >> b) & 1 == 1 {
                        plane.xor_assign(&r_i);
                    }
                }
            }
            trees.push(vc);
            coms.push(com);
            us.push(u_j);
            planes.push(planes_j);
        }

        let u = us[0].clone();
        let corrections = us[1..]
            .iter()
            .map(|u_j| {
                let mut c = u.clone();
                c.xor_assign(u_j);
                c
            })
            .collect();
        let tags = assemble(&planes, params, l_hat);

        Ok(ProverVole {
            u,
            tags,
            coms,
            corrections,
            trees,
        })
    }

    /// Open every tree at all leaves except the challenge indices `deltas`.
    pub fn open(&self, deltas: &[usize]) -> Result<Vec<VcOpening>, VcError> {
        assert_eq!(deltas.len(), self.trees.len());
        self.trees
            .iter()
            .zip(deltas.iter())
            .map(|(t, &d)| t.open_all_but_one(d))
            .collect()
    }
}

/// Verifier-side reconstruction: recompute per-coordinate keys `Kₜ ∈ F₂^λ`
/// (u-stage: after corrections, before witness adjustments) from the tree
/// openings and challenge indices.
pub fn reconstruct_keys(
    salt: &[u8; 16],
    l_hat: usize,
    params: &Params,
    coms: &[VcCommitment],
    corrections: &[BitVec],
    deltas: &[usize],
    openings: &[VcOpening],
) -> Result<Vec<GF2p128>, VcError> {
    assert_eq!(params.lambda(), 128, "only λ = 128 is supported");
    if coms.len() != params.tau
        || corrections.len() != params.tau - 1
        || deltas.len() != params.tau
        || openings.len() != params.tau
    {
        return Err(VcError::InvalidOpening);
    }
    if corrections.iter().any(|c| c.len() != l_hat) {
        return Err(VcError::InvalidOpening);
    }

    let mut planes: Vec<Vec<BitVec>> = Vec::with_capacity(params.tau);
    for j in 0..params.tau {
        let delta = deltas[j];
        let leaves = AllButOneVc::verify(
            &coms[j],
            tree_salt(salt, j),
            params.k as u32,
            delta,
            &openings[j],
        )?;
        let mut planes_j = vec![BitVec::zero(l_hat); params.k];
        for (i, leaf) in leaves.iter().enumerate() {
            let Some(seed) = leaf else { continue };
            let r_i = expand_leaf(salt, j, i, seed, l_hat);
            let e = i ^ delta;
            for (b, plane) in planes_j.iter_mut().enumerate() {
                if (e >> b) & 1 == 1 {
                    plane.xor_assign(&r_i);
                }
            }
        }
        // Apply the u-correction: q'ₜ = qₜ + Δⱼ·c⁽ʲ⁾ₜ, i.e. XOR the
        // correction bits into every plane where Δⱼ has a set bit.
        if j > 0 {
            let c = &corrections[j - 1];
            for (b, plane) in planes_j.iter_mut().enumerate() {
                if (delta >> b) & 1 == 1 {
                    plane.xor_assign(c);
                }
            }
        }
        planes.push(planes_j);
    }
    Ok(assemble(&planes, params, l_hat))
}

/// Interpret a λ-bit challenge as the field element `Δ` and its τ chunk
/// indices `Δⱼ` (bits `[jk, jk+k)`).
#[must_use]
pub fn split_delta(chall: &[u8; 16], params: &Params) -> (GF2p128, Vec<usize>) {
    let delta = GF2p128::from_bytes(*chall);
    let bits = u128::from_le_bytes(*chall);
    let mask = (1u128 << params.k) - 1;
    let chunks = (0..params.tau)
        .map(|j| ((bits >> (j * params.k)) & mask) as usize)
        .collect();
    (delta, chunks)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The fundamental invariant: for every coordinate `t`,
    /// `Kₜ = Vₜ + uₜ·Δ`. This single test validates the leaf expansion,
    /// plane computation, correction application, chunk assembly, and
    /// Δ-splitting conventions all agree between prover and verifier.
    #[test]
    fn vole_correlation_invariant() {
        let params = PARAMS_128;
        let l_hat = 300;
        let salt = [7u8; 16];
        let roots: Vec<Seed> = (0..params.tau)
            .map(|j| core::array::from_fn(|i| (j * 31 + i) as u8))
            .collect();
        let prover = ProverVole::commit(&roots, &salt, l_hat, &params).unwrap();

        // An arbitrary challenge (would be Fiat-Shamir in the NIZK).
        let chall: [u8; 16] = core::array::from_fn(|i| 0xA5u8.wrapping_mul(i as u8 + 3));
        let (delta, chunks) = split_delta(&chall, &params);

        let openings = prover.open(&chunks).unwrap();
        let keys = reconstruct_keys(
            &salt,
            l_hat,
            &params,
            &prover.coms,
            &prover.corrections,
            &chunks,
            &openings,
        )
        .unwrap();

        for (t, key) in keys.iter().enumerate() {
            let expected = if prover.u.get(t) {
                prover.tags[t] + delta
            } else {
                prover.tags[t]
            };
            assert_eq!(*key, expected, "VOLE relation failed at coordinate {t}");
        }
    }

    #[test]
    fn tampered_correction_changes_keys() {
        let params = PARAMS_128;
        let l_hat = 64;
        let salt = [1u8; 16];
        let roots: Vec<Seed> = (0..params.tau)
            .map(|j| core::array::from_fn(|i| (j * 17 + i * 3) as u8))
            .collect();
        let prover = ProverVole::commit(&roots, &salt, l_hat, &params).unwrap();
        let chall = [0x5Au8; 16];
        let (delta, chunks) = split_delta(&chall, &params);
        let openings = prover.open(&chunks).unwrap();

        let mut bad_corrections = prover.corrections.clone();
        let flipped = !bad_corrections[0].get(3);
        bad_corrections[0].set(3, flipped);
        let keys = reconstruct_keys(
            &salt,
            l_hat,
            &params,
            &prover.coms,
            &bad_corrections,
            &chunks,
            &openings,
        )
        .unwrap();
        // The tampered coordinate's key must break the correlation whenever
        // the affected chunk index is nonzero.
        if chunks[1] != 0 {
            let expected = if prover.u.get(3) {
                prover.tags[3] + delta
            } else {
                prover.tags[3]
            };
            assert_ne!(keys[3], expected);
        }
    }
}
