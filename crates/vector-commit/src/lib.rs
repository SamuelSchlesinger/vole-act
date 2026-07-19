//! All-but-one vector commitments from GGM seed trees.
//!
//! This is the primitive at the bottom of VOLE-in-the-head: the prover commits
//! to `N = 2^depth` pseudorandom seeds by publishing a single hash; later it
//! can *open every leaf except one* of the verifier's choosing, by revealing
//! the `depth` sibling seeds along the path to the hidden leaf. The verifier
//! recomputes all other leaves and checks the commitment hash. The hidden
//! leaf's seed stays pseudorandom — that unopened seed is what turns into the
//! VOLE correlation secret.
//!
//! Construction (GGM): a root seed is expanded down a binary tree with a
//! length-doubling PRG; leaf `i`'s commitment is a hash of its seed. All PRG
//! and hash calls are SHAKE256 with explicit domain-separation tags and are
//! salted, and every call binds the tree position (level, index), following
//! the hardening in FAEST / "One Tree to Rule Them All".
//!
//! This crate implements a single tree; batching τ trees (and sharing one
//! commitment hash across them) lives in the `voleith` crate.

use sha3::Shake256;
use sha3::digest::{ExtendableOutput, Update, XofReader};

/// Length in bytes of a tree seed (λ = 128).
pub const SEED_LEN: usize = 16;
/// Length in bytes of a leaf/root commitment hash (2λ = 256 bits).
pub const COM_LEN: usize = 32;

/// Maximum supported tree depth (2^24 leaves is already far beyond any
/// parameter set we target; this bounds allocation).
pub const MAX_DEPTH: u32 = 24;

/// Domain-separation tags for every hash/PRG use in this crate.
mod tags {
    pub const EXPAND: &[u8] = b"VOLE-ACT/vc/v1/expand";
    pub const LEAF_COM: &[u8] = b"VOLE-ACT/vc/v1/leaf-com";
    pub const ROOT: &[u8] = b"VOLE-ACT/vc/v1/root";
}

/// A seed: the value committed at each leaf.
pub type Seed = [u8; SEED_LEN];

/// Errors returned by [`AllButOneVc::verify`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VcError {
    /// The opening does not match the commitment (wrong length, wrong hidden
    /// index, or tampered data).
    InvalidOpening,
    /// Parameters out of range (depth 0 or above [`MAX_DEPTH`], index out of
    /// bounds).
    InvalidParameters,
}

impl core::fmt::Display for VcError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            VcError::InvalidOpening => write!(f, "vector commitment opening is invalid"),
            VcError::InvalidParameters => write!(f, "vector commitment parameters are invalid"),
        }
    }
}

impl std::error::Error for VcError {}

/// The public commitment: a single hash binding all `2^depth` leaves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VcCommitment(pub [u8; COM_LEN]);

/// An all-but-one opening: everything the verifier needs to recompute every
/// leaf seed *except* the hidden one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VcOpening {
    /// Sibling seeds along the root→hidden-leaf path, one per level,
    /// top (level 1) to bottom (level `depth`).
    pub siblings: Vec<Seed>,
    /// The hidden leaf's commitment hash (needed to recompute the root hash).
    pub hidden_com: [u8; COM_LEN],
}

/// Prover state: the fully expanded tree.
pub struct AllButOneVc {
    depth: u32,
    /// `levels[l]` holds the `2^l` node seeds at level `l`; `levels[0]` is the
    /// root, `levels[depth]` are the leaves.
    levels: Vec<Vec<Seed>>,
    /// Per-leaf commitment hashes.
    leaf_coms: Vec<[u8; COM_LEN]>,
}

/// Length-doubling PRG: expand a node seed into its two children.
fn expand_node(salt: &[u8; SEED_LEN], level: u32, index: u64, seed: &Seed) -> (Seed, Seed) {
    let mut h = Shake256::default();
    h.update(tags::EXPAND);
    h.update(salt);
    h.update(&level.to_le_bytes());
    h.update(&index.to_le_bytes());
    h.update(seed);
    let mut out = [0u8; 2 * SEED_LEN];
    h.finalize_xof().read(&mut out);
    let mut left = [0u8; SEED_LEN];
    let mut right = [0u8; SEED_LEN];
    left.copy_from_slice(&out[..SEED_LEN]);
    right.copy_from_slice(&out[SEED_LEN..]);
    (left, right)
}

/// Commitment hash for a single leaf seed.
fn leaf_com(salt: &[u8; SEED_LEN], index: u64, seed: &Seed) -> [u8; COM_LEN] {
    let mut h = Shake256::default();
    h.update(tags::LEAF_COM);
    h.update(salt);
    h.update(&index.to_le_bytes());
    h.update(seed);
    let mut out = [0u8; COM_LEN];
    h.finalize_xof().read(&mut out);
    out
}

/// The root commitment hash over all leaf commitments.
fn root_hash(salt: &[u8; SEED_LEN], depth: u32, coms: &[[u8; COM_LEN]]) -> [u8; COM_LEN] {
    let mut h = Shake256::default();
    h.update(tags::ROOT);
    h.update(salt);
    h.update(&depth.to_le_bytes());
    for c in coms {
        h.update(c);
    }
    let mut out = [0u8; COM_LEN];
    h.finalize_xof().read(&mut out);
    out
}

impl AllButOneVc {
    /// Expand `root_seed` into a full depth-`depth` GGM tree and commit.
    ///
    /// `salt` must be fresh per proof (derived from the transcript); it
    /// domain-separates all PRG/hash calls against multi-instance attacks.
    pub fn commit(
        root_seed: Seed,
        salt: [u8; SEED_LEN],
        depth: u32,
    ) -> Result<(Self, VcCommitment), VcError> {
        if depth == 0 || depth > MAX_DEPTH {
            return Err(VcError::InvalidParameters);
        }
        let mut levels: Vec<Vec<Seed>> = Vec::with_capacity(depth as usize + 1);
        levels.push(vec![root_seed]);
        for level in 0..depth {
            let cur = &levels[level as usize];
            let mut next = Vec::with_capacity(cur.len() * 2);
            for (i, seed) in cur.iter().enumerate() {
                let (l, r) = expand_node(&salt, level, i as u64, seed);
                next.push(l);
                next.push(r);
            }
            levels.push(next);
        }
        let leaves = &levels[depth as usize];
        let leaf_coms: Vec<[u8; COM_LEN]> = leaves
            .iter()
            .enumerate()
            .map(|(i, s)| leaf_com(&salt, i as u64, s))
            .collect();
        let com = VcCommitment(root_hash(&salt, depth, &leaf_coms));
        Ok((
            AllButOneVc {
                depth,
                levels,
                leaf_coms,
            },
            com,
        ))
    }

    /// Number of leaves, `2^depth`.
    #[must_use]
    pub fn num_leaves(&self) -> usize {
        1usize << self.depth
    }

    /// The leaf seeds (prover side).
    #[must_use]
    pub fn leaves(&self) -> &[Seed] {
        &self.levels[self.depth as usize]
    }

    /// Open all leaves except `hide`.
    pub fn open_all_but_one(&self, hide: usize) -> Result<VcOpening, VcError> {
        if hide >= self.num_leaves() {
            return Err(VcError::InvalidParameters);
        }
        let mut siblings = Vec::with_capacity(self.depth as usize);
        for level in 1..=self.depth {
            let path_index = hide >> (self.depth - level);
            let sibling = path_index ^ 1;
            siblings.push(self.levels[level as usize][sibling]);
        }
        Ok(VcOpening {
            siblings,
            hidden_com: self.leaf_coms[hide],
        })
    }

    /// Verify an all-but-one opening against a commitment.
    ///
    /// On success, returns the recomputed leaf seeds, with `None` at the
    /// hidden position `hide` and `Some(seed)` everywhere else.
    pub fn verify(
        com: &VcCommitment,
        salt: [u8; SEED_LEN],
        depth: u32,
        hide: usize,
        opening: &VcOpening,
    ) -> Result<Vec<Option<Seed>>, VcError> {
        if depth == 0 || depth > MAX_DEPTH {
            return Err(VcError::InvalidParameters);
        }
        let n = 1usize << depth;
        if hide >= n {
            return Err(VcError::InvalidParameters);
        }
        if opening.siblings.len() != depth as usize {
            return Err(VcError::InvalidOpening);
        }

        let mut leaves: Vec<Option<Seed>> = vec![None; n];
        for (level, sibling_seed) in (1..=depth).zip(opening.siblings.iter()) {
            let path_index = hide >> (depth - level);
            let sibling = path_index ^ 1;
            // Expand the sibling subtree down to its leaves.
            let mut frontier: Vec<(usize, Seed)> = vec![(sibling, *sibling_seed)];
            for l in level..depth {
                let mut next = Vec::with_capacity(frontier.len() * 2);
                for (idx, seed) in frontier {
                    let (left, right) = expand_node(&salt, l, idx as u64, &seed);
                    next.push((idx * 2, left));
                    next.push((idx * 2 + 1, right));
                }
                frontier = next;
            }
            for (idx, seed) in frontier {
                leaves[idx] = Some(seed);
            }
        }

        // Recompute the root hash from the leaf commitments.
        let coms: Vec<[u8; COM_LEN]> = leaves
            .iter()
            .enumerate()
            .map(|(i, leaf)| match leaf {
                Some(seed) => leaf_com(&salt, i as u64, seed),
                None => opening.hidden_com,
            })
            .collect();
        if root_hash(&salt, depth, &coms) != com.0 {
            return Err(VcError::InvalidOpening);
        }
        Ok(leaves)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_seed(tag: u8) -> Seed {
        core::array::from_fn(|i| tag.wrapping_add(i as u8))
    }

    #[test]
    fn roundtrip_all_depths_and_positions() {
        for depth in 1..=6u32 {
            let (vc, com) = AllButOneVc::commit(test_seed(1), test_seed(2), depth).unwrap();
            let n = vc.num_leaves();
            assert_eq!(n, 1 << depth);
            for hide in 0..n {
                let opening = vc.open_all_but_one(hide).unwrap();
                let leaves =
                    AllButOneVc::verify(&com, test_seed(2), depth, hide, &opening).unwrap();
                assert_eq!(leaves.len(), n);
                for (i, leaf) in leaves.iter().enumerate() {
                    if i == hide {
                        assert!(leaf.is_none(), "hidden leaf must not be recovered");
                    } else {
                        assert_eq!(leaf.as_ref(), Some(&vc.leaves()[i]), "leaf {i}");
                    }
                }
            }
        }
    }

    #[test]
    fn deterministic_commitment() {
        let (_, com1) = AllButOneVc::commit(test_seed(7), test_seed(9), 5).unwrap();
        let (_, com2) = AllButOneVc::commit(test_seed(7), test_seed(9), 5).unwrap();
        assert_eq!(com1, com2);
        // Different salt or seed changes the commitment.
        let (_, com3) = AllButOneVc::commit(test_seed(7), test_seed(10), 5).unwrap();
        let (_, com4) = AllButOneVc::commit(test_seed(8), test_seed(9), 5).unwrap();
        assert_ne!(com1, com3);
        assert_ne!(com1, com4);
    }

    #[test]
    fn tampered_openings_are_rejected() {
        let depth = 5u32;
        let salt = test_seed(3);
        let (vc, com) = AllButOneVc::commit(test_seed(1), salt, depth).unwrap();
        let hide = 13;
        let opening = vc.open_all_but_one(hide).unwrap();

        // Baseline verifies.
        assert!(AllButOneVc::verify(&com, salt, depth, hide, &opening).is_ok());

        // Flip one bit in each sibling seed.
        for i in 0..opening.siblings.len() {
            let mut bad = opening.clone();
            bad.siblings[i][0] ^= 1;
            assert_eq!(
                AllButOneVc::verify(&com, salt, depth, hide, &bad),
                Err(VcError::InvalidOpening),
                "tampered sibling {i} must be rejected"
            );
        }

        // Tamper with the hidden commitment.
        let mut bad = opening.clone();
        bad.hidden_com[0] ^= 1;
        assert_eq!(
            AllButOneVc::verify(&com, salt, depth, hide, &bad),
            Err(VcError::InvalidOpening)
        );

        // Wrong hidden index.
        assert_eq!(
            AllButOneVc::verify(&com, salt, depth, hide + 1, &opening),
            Err(VcError::InvalidOpening)
        );

        // Wrong salt.
        assert_eq!(
            AllButOneVc::verify(&com, test_seed(4), depth, hide, &opening),
            Err(VcError::InvalidOpening)
        );

        // Truncated opening.
        let mut bad = opening.clone();
        bad.siblings.pop();
        assert_eq!(
            AllButOneVc::verify(&com, salt, depth, hide, &bad),
            Err(VcError::InvalidOpening)
        );
    }

    #[test]
    fn parameter_validation() {
        assert!(AllButOneVc::commit(test_seed(0), test_seed(0), 0).is_err());
        assert!(AllButOneVc::commit(test_seed(0), test_seed(0), MAX_DEPTH + 1).is_err());
        let (vc, com) = AllButOneVc::commit(test_seed(0), test_seed(0), 3).unwrap();
        assert!(vc.open_all_but_one(8).is_err());
        let opening = vc.open_all_but_one(0).unwrap();
        assert!(AllButOneVc::verify(&com, test_seed(0), 3, 8, &opening).is_err());
    }
}
