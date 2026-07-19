//! The canonical field embedding `GF(16) ↪ GF(2¹²⁸)`.
//!
//! Since `4 | 128`, `GF(2¹²⁸)` contains a unique copy of `GF(16)`: the 15
//! elements of multiplicative order dividing 15, plus zero. The embedding is
//! determined by choosing a root `β ∈ GF(2¹²⁸)` of GF(16)'s defining
//! polynomial `x⁴ + x + 1` and mapping `x ↦ β`.
//!
//! `β` is computed deterministically (no hardcoded magic constant to trust):
//! take the small element `g = x`, raise it to `(2¹²⁸ − 1)/15` to land in the
//! order-15 subgroup, verify the order is exactly 15, and test which primitive
//! quartic it satisfies. If `h` is a root of the *other* primitive quartic
//! (`x⁴ + x³ + 1`), then `h⁷` is a root of `x⁴ + x + 1` (the conjugacy classes
//! of primitive elements are `{1,2,4,8}` and `{7,11,13,14}` as exponents, and
//! `7·{7,11,13,14} ≡ {4,2,1,8} mod 15`). Both prover and verifier recompute
//! the same `β`, and unit tests pin its value and the homomorphism laws.

use crate::{BinaryField, GF2p128, GF16};
use std::sync::OnceLock;

/// `(2¹²⁸ − 1)/15`: fifteen times this is the full group order.
/// In hex this is 32 nibbles of `0x1` (since `15 · 0x11…1 = 0xFF…F`).
const COFACTOR_EXP: u128 = 0x1111_1111_1111_1111_1111_1111_1111_1111;

/// Compute the canonical root `β` of `x⁴ + x + 1` in `GF(2¹²⁸)`.
fn compute_beta() -> GF2p128 {
    // Candidate base elements, tried in order; the first that lands on an
    // element of order exactly 15 decides β deterministically.
    for g in [2u128, 3, 4, 5, 6, 7] {
        let h = GF2p128::new(g).pow(COFACTOR_EXP);
        // Order must be exactly 15 (not 1, 3, or 5).
        if h == GF2p128::ONE || h.pow(3) == GF2p128::ONE || h.pow(5) == GF2p128::ONE {
            continue;
        }
        // h is a primitive element of the GF(16) subfield, so it satisfies
        // one of the two primitive quartics; h or h^7 satisfies x^4 + x + 1.
        for c in [h, h.pow(7)] {
            if c.square().square() + c + GF2p128::ONE == GF2p128::ZERO {
                return c;
            }
        }
        unreachable!("order-15 element must be a root of a primitive quartic");
    }
    unreachable!("some small element must generate the order-15 subgroup");
}

/// The embedding table: image of each of the 16 elements of GF(16).
fn embed_table() -> &'static [GF2p128; 16] {
    static TABLE: OnceLock<[GF2p128; 16]> = OnceLock::new();
    TABLE.get_or_init(|| {
        let b1 = compute_beta();
        let b2 = b1.square();
        let b3 = b2 * b1;
        let basis = [GF2p128::ONE, b1, b2, b3];
        core::array::from_fn(|i| {
            let mut acc = GF2p128::ZERO;
            for (bit, base) in basis.iter().enumerate() {
                if (i >> bit) & 1 == 1 {
                    acc += *base;
                }
            }
            acc
        })
    })
}

/// The canonical field embedding `GF(16) ↪ GF(2¹²⁸)`.
///
/// This is a ring homomorphism: `embed(a·b) = embed(a)·embed(b)` and
/// `embed(a+b) = embed(a)+embed(b)` (tested exhaustively). Used to lift
/// F₁₆-valued witnesses into the VOLE tag field.
///
/// Note: the table lookup is indexed by the nibble value. For the VOLE layer
/// this is used on *public constants* (basis images combined linearly), so
/// secret-indexed lookups do not arise there; treat direct secret-dependent
/// use with care until a constant-time variant is provided.
#[must_use]
pub fn embed_gf16(a: GF16) -> GF2p128 {
    embed_table()[a.to_u8() as usize]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn beta_satisfies_defining_polynomial() {
        let b = embed_gf16(GF16::new(0b0010)); // image of x
        assert_eq!(
            b.square().square() + b + GF2p128::ONE,
            GF2p128::ZERO,
            "β⁴ + β + 1 = 0"
        );
        assert_ne!(b, GF2p128::ZERO);
        // β has multiplicative order exactly 15.
        assert_eq!(b.pow(15), GF2p128::ONE);
        assert_ne!(b.pow(3), GF2p128::ONE);
        assert_ne!(b.pow(5), GF2p128::ONE);
    }

    /// Pins the exact canonical β. All four conjugate roots β, β², β⁴, β⁸ of
    /// `x⁴ + x + 1` satisfy every *property* test in this module; only this
    /// known-answer constant distinguishes them. If a refactor of
    /// [`compute_beta`] changes this value, every serialized proof becomes
    /// incompatible across versions — that is a protocol break, not a
    /// harmless cleanup.
    #[test]
    fn beta_known_answer() {
        assert_eq!(
            embed_gf16(GF16::new(0b0010)).to_u128(),
            0x8b49_8493_3933_4e30_987a_355c_bf0c_842b,
        );
    }

    #[test]
    fn embedding_is_deterministic_and_injective() {
        let images: Vec<GF2p128> = (0..16).map(|i| embed_gf16(GF16::new(i))).collect();
        for i in 0..16 {
            for j in 0..i {
                assert_ne!(images[i], images[j], "embedding must be injective");
            }
            // Recomputing gives the same image.
            assert_eq!(embed_gf16(GF16::new(i as u8)), images[i]);
        }
    }

    #[test]
    fn embedding_preserves_structure_exhaustive() {
        assert_eq!(embed_gf16(GF16::ZERO), GF2p128::ZERO);
        assert_eq!(embed_gf16(GF16::ONE), GF2p128::ONE);
        for a in (0..16).map(GF16::new) {
            for b in (0..16).map(GF16::new) {
                assert_eq!(
                    embed_gf16(a + b),
                    embed_gf16(a) + embed_gf16(b),
                    "additive homomorphism at ({a:?}, {b:?})"
                );
                assert_eq!(
                    embed_gf16(a * b),
                    embed_gf16(a) * embed_gf16(b),
                    "multiplicative homomorphism at ({a:?}, {b:?})"
                );
            }
            // Images lie in the GF(16) subfield: a^16 = a.
            assert_eq!(embed_gf16(a).pow(16), embed_gf16(a));
        }
    }
}
