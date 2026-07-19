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
use rayon::prelude::*;
use sha3::Shake256;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use vector_commit::{AllButOneVc, SALT_LEN, Salt, Seed, VcCommitment, VcError, VcOpening};
use zeroize::Zeroize;

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

/// Balanced λ = 128 point with τ = 32 trees of depth 4. This expands 512
/// leaves rather than 4096 while keeping correction data moderate.
pub const PARAMS_128_BALANCED: Params = Params { tau: 32, k: 4 };

/// Lowest-latency built-in λ = 128 point with τ = 64 trees of depth 2.
/// This expands only 256 leaves, at the cost of approximately twice the
/// correction data of [`PARAMS_128_BALANCED`].
pub const PARAMS_128_FAST: Params = Params { tau: 64, k: 2 };

impl Params {
    /// The security parameter λ = τ·k in bits.
    #[must_use]
    pub const fn lambda(&self) -> usize {
        self.tau.saturating_mul(self.k)
    }

    /// Leaves per tree, or zero when `k` is not representable as a `usize`
    /// shift (such a parameter set is rejected by proving and verification).
    #[must_use]
    pub const fn leaves(&self) -> usize {
        if self.k >= usize::BITS as usize {
            0
        } else {
            1 << self.k
        }
    }

    /// Reject unsupported parameters *before* any cryptographic work, so
    /// attacker-supplied dimensions cannot trigger panics (out-of-range
    /// shifts) instead of clean errors. Only λ = 128 is supported, with a
    /// per-tree chunk that fits the field's bit width.
    pub(crate) fn validate(&self) -> Result<(), crate::VoleithError> {
        let ok =
            self.tau >= 1 && self.k >= 1 && self.k <= 24 && self.tau <= 128 && self.lambda() == 128;
        ok.then_some(())
            .ok_or(crate::VoleithError::InvalidParameters)
    }
}

/// Derive the salt for tree `j`'s internal vector-commitment hashing.
fn tree_salt(salt: &[u8; SALT_LEN], j: usize) -> Salt {
    let mut h = Shake256::default();
    h.update(b"VOLE-ACT/voleith/v1/tree-salt");
    h.update(salt);
    h.update(&(j as u64).to_le_bytes());
    let mut out = [0u8; SALT_LEN];
    h.finalize_xof().read(&mut out);
    out
}

/// Expand leaf `i` of tree `j` into its ℓ̂-bit VOLE contribution.
fn expand_leaf(salt: &[u8; SALT_LEN], j: usize, i: usize, seed: &Seed, l_hat: usize) -> BitVec {
    let mut h = Shake256::default();
    h.update(b"VOLE-ACT/voleith/v1/leaf-expand");
    h.update(salt);
    h.update(&(j as u64).to_le_bytes());
    h.update(&(i as u64).to_le_bytes());
    h.update(seed);
    let mut reader = h.finalize_xof();
    BitVec::from_xof(&mut reader, l_hat)
}

/// Streaming accumulator turning the leaf expansions `r_0 … r_{2^k−1}` into
/// `u = Σᵢ rᵢ` and `planes[b] = Σ_{i: bit_b(i)=1} rᵢ` using pairwise subtree
/// sums (a binary-counter walk): ~2 vector XORs per leaf instead of the
/// definitional `1 + k/2`. This is an exact XOR reassociation — every leaf
/// contributes to exactly the same outputs — with `O(k)` working vectors.
///
/// `pending[l]` holds the sum of a completed even-position subtree at level
/// `l`, awaiting its odd sibling; when the sibling's sum arrives it is (a)
/// XORed into `planes[l]` (odd position at level `l` ⟺ bit `l` of the leaf
/// index is set for every leaf in that subtree) and (b) merged upward.
/// All state is wiped on drop, covering panic paths on the prover side.
struct PlaneAccumulator {
    k: usize,
    planes: Vec<BitVec>,
    pending: Vec<Option<BitVec>>,
    count: usize,
}

impl PlaneAccumulator {
    fn new(k: usize, l_hat: usize) -> Self {
        PlaneAccumulator {
            k,
            planes: vec![BitVec::zero(l_hat); k],
            pending: (0..=k).map(|_| None).collect(),
            count: 0,
        }
    }

    /// Feed the next leaf expansion, in index order.
    fn push(&mut self, r: BitVec) {
        let mut cur = r;
        let mut level = 0;
        while let Some(left) = self.pending[level].take() {
            // `cur` is the completed odd-position subtree sum at `level`.
            self.planes[level].xor_assign(&cur);
            cur.xor_assign(&left);
            level += 1;
        }
        self.pending[level] = Some(cur);
        self.count += 1;
    }

    /// After exactly `2^k` pushes: `(u, planes)`.
    fn finish(mut self) -> (BitVec, Vec<BitVec>) {
        assert_eq!(self.count, 1usize << self.k, "accumulator not full");
        let u = self.pending[self.k]
            .take()
            .expect("2^k pushes fill the top level");
        (u, core::mem::take(&mut self.planes))
    }
}

impl Drop for PlaneAccumulator {
    fn drop(&mut self) {
        // Partial sums are as secret as the VOLE itself (prover side).
        self.planes.zeroize();
        for slot in self.pending.iter_mut().flatten() {
            slot.zeroize();
        }
    }
}

/// Assemble per-coordinate `F₂^λ` elements from τ·k bit planes.
///
/// `planes[j][b]` holds bit `jk + b` of every coordinate's field element.
/// Implemented as a word-level 128×64 bit-matrix transpose per 64-coordinate
/// block: identical output to the definitional per-bit loop (each
/// (coordinate, bit-position) pair contributes exactly once), with no
/// data-dependent branches on the secret plane bits.
fn assemble(planes: &[Vec<BitVec>], params: &Params, l_hat: usize) -> Vec<GF2p128> {
    // Both callers run `params.validate()` first (τ·k = λ = 128) and build
    // exactly τ inner vectors of k planes; the shape asserts pin the
    // `pos = j·k + b` mapping the flattened order must reproduce.
    assert_eq!(planes.len(), params.tau);
    assert!(
        planes
            .iter()
            .all(|tree_planes| tree_planes.len() == params.k)
    );
    let flat: Vec<&BitVec> = planes.iter().flatten().collect();
    assert_eq!(flat.len(), 128);

    let mut out = vec![GF2p128::ZERO; l_hat];
    for (w, block) in out.chunks_mut(64).enumerate() {
        let mut lo = [0u64; 64];
        let mut hi = [0u64; 64];
        for (pos, plane) in flat.iter().enumerate() {
            let word = plane.word64(w);
            if pos < 64 {
                lo[pos] = word;
            } else {
                hi[pos - 64] = word;
            }
        }
        crate::bits::transpose64(&mut lo);
        crate::bits::transpose64(&mut hi);
        for (i, elem) in block.iter_mut().enumerate() {
            *elem = GF2p128::new(lo[i] as u128 | ((hi[i] as u128) << 64));
        }
    }
    out
}

/// Prover-side VOLE state: the committed random vector `u`, per-coordinate
/// tags `V`, tree commitments, and public corrections.
///
/// `u` and the tags are wiped on drop (the trees wipe their own seeds), so
/// early-error paths in the prover do not leave VOLE secrets in freed heap
/// memory. The commitments and corrections are published and are not wiped.
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

impl Drop for ProverVole {
    fn drop(&mut self) {
        self.u.zeroize();
        self.tags.zeroize();
    }
}

impl zeroize::ZeroizeOnDrop for ProverVole {}

impl ProverVole {
    /// Commit to ℓ̂ VOLE correlations across τ trees.
    pub fn commit(
        root_seeds: &[Seed],
        salt: &[u8; SALT_LEN],
        l_hat: usize,
        params: &Params,
    ) -> Result<Self, VcError> {
        if params.validate().is_err() || root_seeds.len() != params.tau {
            return Err(VcError::InvalidParameters);
        }

        // The τ trees are independent; expand them in parallel and collect
        // in index order, so the assembled outputs (and hence the transcript)
        // are identical to the sequential walk.
        let per_tree: Result<Vec<_>, VcError> = (0..params.tau)
            .into_par_iter()
            .map(|j| {
                let (vc, com) =
                    AllButOneVc::commit(root_seeds[j], tree_salt(salt, j), params.k as u32)?;
                let mut acc = PlaneAccumulator::new(params.k, l_hat);
                for (i, leaf) in vc.leaves().iter().enumerate() {
                    acc.push(expand_leaf(salt, j, i, leaf, l_hat));
                }
                let (u_j, planes_j) = acc.finish();
                Ok((vc, com, u_j, planes_j))
            })
            .collect();

        let mut trees = Vec::with_capacity(params.tau);
        let mut coms = Vec::with_capacity(params.tau);
        let mut us: Vec<BitVec> = Vec::with_capacity(params.tau);
        let mut planes: Vec<Vec<BitVec>> = Vec::with_capacity(params.tau);
        for (vc, com, u_j, planes_j) in per_tree? {
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
        // The per-tree vectors and tag planes are as secret as the VOLE
        // itself; wipe them now that `u`/`corrections`/`tags` are assembled.
        us.zeroize();
        planes.zeroize();

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
        if deltas.len() != self.trees.len() {
            return Err(VcError::InvalidParameters);
        }
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
    salt: &[u8; SALT_LEN],
    l_hat: usize,
    params: &Params,
    coms: &[VcCommitment],
    corrections: &[BitVec],
    deltas: &[usize],
    openings: &[VcOpening],
) -> Result<Vec<GF2p128>, VcError> {
    if params.validate().is_err() {
        return Err(VcError::InvalidParameters);
    }
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

    // The τ trees reconstruct independently; parallel with in-order collect,
    // identical outputs to the sequential walk. The accumulator walks leaves
    // in `e = i ⊕ Δ` order (the hole i = Δ becomes the zero vector at e = 0),
    // which computes exactly `planes[b] = Σ_{bit_b(e)=1} r_{e⊕Δ}` — the same
    // sums as the definitional per-leaf loop; the SHAKE leaf expansions are
    // position-keyed and order-independent.
    let n = params.leaves();
    let planes: Result<Vec<Vec<BitVec>>, VcError> = (0..params.tau)
        .into_par_iter()
        .map(|j| {
            let delta = deltas[j];
            let leaves = AllButOneVc::verify(
                &coms[j],
                tree_salt(salt, j),
                params.k as u32,
                delta,
                &openings[j],
            )?;
            let mut acc = PlaneAccumulator::new(params.k, l_hat);
            for e in 0..n {
                if e == 0 {
                    acc.push(BitVec::zero(l_hat));
                } else {
                    let i = e ^ delta;
                    let seed = leaves[i]
                        .as_ref()
                        .expect("verify() hides exactly the challenged leaf");
                    acc.push(expand_leaf(salt, j, i, seed, l_hat));
                }
            }
            let (_, mut planes_j) = acc.finish();
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
            Ok(planes_j)
        })
        .collect();
    Ok(assemble(&planes?, params, l_hat))
}

/// Interpret a λ-bit challenge as the field element `Δ` and its τ chunk
/// indices `Δⱼ` (bits `[jk, jk+k)`). Invalid parameter geometry returns the
/// field element together with an empty chunk list, without allocating from
/// attacker-controlled dimensions; proving and verification reject the same
/// geometry with [`crate::VoleithError::InvalidParameters`].
#[must_use]
pub fn split_delta(chall: &[u8; 16], params: &Params) -> (GF2p128, Vec<usize>) {
    let delta = GF2p128::from_bytes(*chall);
    if params.validate().is_err() {
        return (delta, Vec::new());
    }
    let bits = u128::from_le_bytes(*chall);
    let mask = (1u128 << params.k) - 1;
    let chunks = (0..params.tau)
        .map(|j| {
            j.checked_mul(params.k)
                .and_then(|offset| u32::try_from(offset).ok())
                .and_then(|offset| bits.checked_shr(offset))
                .map_or(0, |shifted| (shifted & mask) as usize)
        })
        .collect();
    (delta, chunks)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The definitional per-bit implementation of [`assemble`], kept as the
    /// test oracle for the word-transpose fast path.
    fn assemble_reference(planes: &[Vec<BitVec>], params: &Params, l_hat: usize) -> Vec<GF2p128> {
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

    #[test]
    fn plane_accumulator_matches_definitional_loop() {
        // The binary-counter accumulator must equal the per-leaf loop
        // `u ^= r_i; planes[b] ^= r_i when bit_b(i)` for every k and for
        // ragged vector lengths.
        for k in 1..=8usize {
            let l_hat = 213;
            let n = 1usize << k;
            let mut state = 0x5EED_0000_0000_0000u64 | k as u64;
            let mut next = || {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state
            };
            let leaves: Vec<BitVec> = (0..n)
                .map(|_| {
                    let mut v = BitVec::zero(l_hat);
                    for t in 0..l_hat {
                        v.set(t, next() & 1 == 1);
                    }
                    v
                })
                .collect();

            let mut u_ref = BitVec::zero(l_hat);
            let mut planes_ref = vec![BitVec::zero(l_hat); k];
            for (i, r) in leaves.iter().enumerate() {
                u_ref.xor_assign(r);
                for (b, plane) in planes_ref.iter_mut().enumerate() {
                    if (i >> b) & 1 == 1 {
                        plane.xor_assign(r);
                    }
                }
            }

            let mut acc = PlaneAccumulator::new(k, l_hat);
            for r in leaves {
                acc.push(r);
            }
            let (u, planes) = acc.finish();
            assert_eq!(u, u_ref, "u mismatch at k={k}");
            assert_eq!(planes, planes_ref, "planes mismatch at k={k}");
        }
    }

    #[test]
    fn assemble_matches_reference() {
        // Cover word-aligned and ragged lengths, and every validate()-legal
        // parameter point (τ·k = 128 with k ≤ 24), not only the shipped
        // profiles — the plane partition differs at the extremes.
        for params in [
            PARAMS_128,
            PARAMS_128_BALANCED,
            PARAMS_128_FAST,
            Params { tau: 128, k: 1 },
            Params { tau: 8, k: 16 },
        ] {
            for l_hat in [1usize, 63, 64, 65, 300, 512, 1000] {
                let mut state = 0x1234_5678_9ABC_DEF0u64 ^ (params.tau as u64) << 32;
                let mut next = || {
                    // Deterministic xorshift; test-only data generator.
                    state ^= state << 13;
                    state ^= state >> 7;
                    state ^= state << 17;
                    state
                };
                let planes: Vec<Vec<BitVec>> = (0..params.tau)
                    .map(|_| {
                        (0..params.k)
                            .map(|_| {
                                let mut plane = BitVec::zero(l_hat);
                                for t in 0..l_hat {
                                    plane.set(t, next() & 1 == 1);
                                }
                                plane
                            })
                            .collect()
                    })
                    .collect();
                assert_eq!(
                    assemble(&planes, &params, l_hat),
                    assemble_reference(&planes, &params, l_hat),
                    "tau={} k={} l_hat={}",
                    params.tau,
                    params.k,
                    l_hat
                );
            }
        }
    }

    /// The fundamental invariant: for every coordinate `t`,
    /// `Kₜ = Vₜ + uₜ·Δ`. This single test validates the leaf expansion,
    /// plane computation, correction application, chunk assembly, and
    /// Δ-splitting conventions all agree between prover and verifier.
    #[test]
    fn vole_correlation_invariant() {
        let params = PARAMS_128;
        let l_hat = 300;
        let salt = [7u8; 32];
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
        let salt = [1u8; 32];
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

    #[test]
    fn invalid_public_parameters_fail_without_panicking() {
        let invalid = Params { tau: 1, k: 128 };
        assert_eq!(invalid.leaves(), 0);
        assert_eq!(
            ProverVole::commit(&[[0u8; 16]], &[0u8; 32], 8, &invalid).err(),
            Some(VcError::InvalidParameters)
        );
        let (_, chunks) = split_delta(&[0u8; 16], &invalid);
        assert!(chunks.is_empty());

        let overflowing = Params {
            tau: usize::MAX,
            k: usize::MAX,
        };
        assert_eq!(overflowing.lambda(), usize::MAX);
        assert_eq!(overflowing.leaves(), 0);
        let (_, chunks) = split_delta(&[0u8; 16], &overflowing);
        assert!(chunks.is_empty());

        let allocation_attack = Params {
            tau: u32::MAX as usize,
            k: 24,
        };
        let (_, chunks) = split_delta(&[0u8; 16], &allocation_attack);
        assert!(chunks.is_empty());
    }
}
