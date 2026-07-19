//! `GF(16) = F₂[x]/(x⁴ + x + 1)` — the field MAYO's multivariate system lives in.

use crate::BinaryField;
use core::fmt;
use core::iter::{Product, Sum};
use core::ops::{Add, AddAssign, Mul, MulAssign, Sub, SubAssign};
use rand_core::CryptoRngCore;
use zeroize::Zeroize;

/// An element of `GF(16) = F₂[x]/(x⁴ + x + 1)`.
///
/// The element `a₀ + a₁x + a₂x² + a₃x³` is stored as the nibble
/// `a₃a₂a₁a₀` in the low four bits of a byte. The high four bits are always
/// zero (an invariant maintained by every constructor).
#[derive(Clone, Copy, PartialEq, Eq, Default, Hash, PartialOrd, Ord)]
#[repr(transparent)]
pub struct GF16(u8);

impl Zeroize for GF16 {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl GF16 {
    /// The reduction polynomial `x⁴ + x + 1` as a bit pattern.
    const MODULUS: u16 = 0b1_0011;

    /// Construct an element from the low four bits of `v` (high bits ignored).
    #[must_use]
    pub const fn new(v: u8) -> Self {
        GF16(v & 0x0F)
    }

    /// The canonical nibble representation (always `< 16`).
    #[must_use]
    pub const fn to_u8(self) -> u8 {
        self.0
    }

    /// View a slice of elements as their canonical nibble bytes.
    ///
    /// Each element occupies one byte with the high four bits zero (a
    /// constructor invariant), so the byte view is exactly the packed-lane
    /// format the [`packed`] module operates on.
    #[must_use]
    pub fn slice_as_bytes(elems: &[GF16]) -> &[u8] {
        // SAFETY: `GF16` is `#[repr(transparent)]` over `u8`.
        unsafe { core::slice::from_raw_parts(elems.as_ptr().cast::<u8>(), elems.len()) }
    }

    /// Carry-less 4×4-bit multiply followed by reduction mod `x⁴ + x + 1`.
    ///
    /// Branch-free: fixed iteration counts, mask-based conditionals.
    const fn mul_internal(a: u8, b: u8) -> u8 {
        let a = a as u16;
        // Carry-less product: at most 7 bits.
        let mut p: u16 = 0;
        let mut i = 0;
        while i < 4 {
            let mask = 0u16.wrapping_sub(((b >> i) & 1) as u16);
            p ^= (a << i) & mask;
            i += 1;
        }
        // Reduce bits 6..=4.
        let mut j = 6;
        while j >= 4 {
            let mask = 0u16.wrapping_sub((p >> j) & 1);
            p ^= (Self::MODULUS << (j - 4)) & mask;
            j -= 1;
        }
        (p & 0x0F) as u8
    }
}

impl BinaryField for GF16 {
    const ZERO: Self = GF16(0);
    const ONE: Self = GF16(1);
    const BITS: usize = 4;

    /// Inverse via `a⁻¹ = a¹⁴ = a²·a⁴·a⁸` (Fermat), with `inv(0) = 0`.
    fn inv(self) -> Self {
        let a2 = self.square();
        let a4 = a2.square();
        let a8 = a4.square();
        a2 * a4 * a8
    }

    fn random(rng: &mut impl CryptoRngCore) -> Self {
        GF16::new(rng.next_u32() as u8)
    }
}

impl Add for GF16 {
    type Output = Self;
    // In characteristic 2, addition of polynomial coefficients is XOR.
    #[allow(clippy::suspicious_arithmetic_impl)]
    fn add(self, rhs: Self) -> Self {
        GF16(self.0 ^ rhs.0)
    }
}

impl Sub for GF16 {
    type Output = Self;
    // In characteristic 2, subtraction coincides with addition.
    #[allow(clippy::suspicious_arithmetic_impl)]
    fn sub(self, rhs: Self) -> Self {
        self + rhs
    }
}

impl Mul for GF16 {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self {
        GF16(Self::mul_internal(self.0, rhs.0))
    }
}

impl AddAssign for GF16 {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl SubAssign for GF16 {
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

impl MulAssign for GF16 {
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs;
    }
}

impl Sum for GF16 {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::ZERO, |a, b| a + b)
    }
}

impl Product for GF16 {
    fn product<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::ONE, |a, b| a * b)
    }
}

impl fmt::Debug for GF16 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "GF16({:#x})", self.0)
    }
}

impl From<GF16> for u8 {
    fn from(v: GF16) -> u8 {
        v.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all() -> impl Iterator<Item = GF16> {
        (0u8..16).map(GF16::new)
    }

    #[test]
    fn new_masks_high_bits() {
        assert_eq!(GF16::new(0xAB), GF16::new(0x0B));
        assert_eq!(GF16::new(0xF7).to_u8(), 0x7);
    }

    #[test]
    fn addition_is_xor_and_self_inverse() {
        for a in all() {
            for b in all() {
                assert_eq!(a + b, b + a);
                assert_eq!((a + b) + b, a, "adding twice cancels");
                assert_eq!(a - b, a + b, "char 2: sub == add");
            }
            assert_eq!(a + GF16::ZERO, a);
        }
    }

    #[test]
    fn multiplication_axioms_exhaustive() {
        for a in all() {
            assert_eq!(a * GF16::ONE, a);
            assert_eq!(a * GF16::ZERO, GF16::ZERO);
            for b in all() {
                assert_eq!(a * b, b * a, "commutativity");
                for c in all() {
                    assert_eq!((a * b) * c, a * (b * c), "associativity");
                    assert_eq!(a * (b + c), a * b + a * c, "distributivity");
                }
            }
        }
    }

    #[test]
    fn known_products() {
        let x = GF16::new(0b0010);
        // x * x^3 = x^4 = x + 1
        assert_eq!(x * GF16::new(0b1000), GF16::new(0b0011));
        // x^3 * x^3 = x^6 = x^3 + x^2  (x^6 = x^2 * x^4 = x^2(x+1))
        assert_eq!(GF16::new(0b1000) * GF16::new(0b1000), GF16::new(0b1100));
    }

    #[test]
    fn inverses_exhaustive() {
        assert_eq!(GF16::ZERO.inv(), GF16::ZERO, "inv(0) = 0 convention");
        for a in all().skip(1) {
            assert_eq!(a * a.inv(), GF16::ONE, "a * a^-1 = 1 for a = {a:?}");
        }
    }

    #[test]
    fn frobenius_and_field_size() {
        for a in all() {
            for b in all() {
                // (a+b)^2 = a^2 + b^2 in characteristic 2.
                assert_eq!((a + b).square(), a.square() + b.square());
            }
            // a^16 = a for all a in GF(16).
            assert_eq!(a.pow(16), a);
        }
    }

    #[test]
    fn multiplicative_group_order() {
        // x is a generator: x has order 15 (x^4+x+1 is primitive).
        let x = GF16::new(0b0010);
        assert_eq!(x.pow(15), GF16::ONE);
        assert_ne!(x.pow(3), GF16::ONE);
        assert_ne!(x.pow(5), GF16::ONE);
    }
}

/// Eight-lane packed GF(16) arithmetic: one element per byte of a `u64`
/// (low nibble, high nibble zero — the same canonical layout as [`GF16`]'s
/// byte view, so `u64::from_le_bytes` over [`GF16::slice_as_bytes`] chunks
/// yields lanes directly).
///
/// Like the scalar path these routines are branch-free with
/// secret-independent memory access: lane selection uses full-word masks
/// derived by constant multiplications, never lookup tables, so the
/// constant-time posture of [`GF16`] multiplication is preserved exactly.
pub mod packed {
    use super::GF16;

    /// One set bit in each byte lane.
    const LANE_LSB: u64 = 0x0101_0101_0101_0101;

    /// Reduce per-lane carry-less products of degree ≤ 6 mod `x⁴ + x + 1`.
    ///
    /// Lane values stay within their byte throughout: inputs occupy bits
    /// 0..=6 of each lane and the folded modulus contributions
    /// (`0b1_0011 << (j-4)` for `j = 6, 5, 4`) reach at most bit 6.
    #[inline]
    fn reduce(mut p: u64) -> u64 {
        let hits6 = (p >> 6) & LANE_LSB;
        p ^= hits6.wrapping_mul(0b1_0011 << 2);
        let hits5 = (p >> 5) & LANE_LSB;
        p ^= hits5.wrapping_mul(0b1_0011 << 1);
        let hits4 = (p >> 4) & LANE_LSB;
        p ^= hits4.wrapping_mul(0b1_0011);
        p
    }

    /// Multiply every lane of `word` by the scalar `s`.
    ///
    /// Identical to applying `GF16::mul` lane-by-lane (the carry-less
    /// product of a nibble by a nibble has degree ≤ 6, so `word << i` for
    /// `i ≤ 3` never crosses a lane boundary).
    #[must_use]
    #[inline]
    pub fn mul_scalar8(word: u64, s: GF16) -> u64 {
        let s = s.to_u8();
        let mut p = 0u64;
        let mut i = 0;
        while i < 4 {
            let mask = 0u64.wrapping_sub(u64::from((s >> i) & 1));
            p ^= (word << i) & mask;
            i += 1;
        }
        reduce(p)
    }

    /// Lane-wise product of two packed words.
    ///
    /// The per-lane selector `((b >> i) & LANE_LSB) * 0xFF` broadcasts bit
    /// `i` of each lane of `b` to a full byte mask; the multiplication
    /// cannot carry across lanes because each multiplicand byte is 0 or 1.
    #[must_use]
    #[inline]
    pub fn mul_lanes8(a: u64, b: u64) -> u64 {
        let mut p = 0u64;
        let mut i = 0;
        while i < 4 {
            let sel = ((b >> i) & LANE_LSB).wrapping_mul(0xFF);
            p ^= (a << i) & sel;
            i += 1;
        }
        reduce(p)
    }

    /// XOR-fold the eight lanes into a single element (the GF(16) sum of
    /// the lanes, since addition is XOR).
    #[must_use]
    #[inline]
    pub fn fold8(mut w: u64) -> GF16 {
        w ^= w >> 32;
        w ^= w >> 16;
        w ^= w >> 8;
        GF16::new(w as u8)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::BinaryField;

        /// Every (a, b) nibble pair, in every lane position, against the
        /// scalar multiplier — exhaustive over the full function domain.
        #[test]
        fn packed_matches_scalar_exhaustively() {
            for a in 0..16u8 {
                for b in 0..16u8 {
                    let expected = (GF16::new(a) * GF16::new(b)).to_u8();
                    for lane in 0..8 {
                        let wa = u64::from(a) << (8 * lane);
                        let wb = u64::from(b) << (8 * lane);
                        assert_eq!(
                            mul_scalar8(wa, GF16::new(b)),
                            u64::from(expected) << (8 * lane),
                            "mul_scalar8 a={a} b={b} lane={lane}"
                        );
                        assert_eq!(
                            mul_lanes8(wa, wb),
                            u64::from(expected) << (8 * lane),
                            "mul_lanes8 a={a} b={b} lane={lane}"
                        );
                    }
                }
            }
        }

        /// Dense words: all lanes at once, cross-checked lane-by-lane.
        #[test]
        fn packed_dense_words() {
            let mut state = 0x1357_9BDF_2468_ACE0u64;
            let mut next = || {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state
            };
            for _ in 0..200 {
                let a = next() & 0x0F0F_0F0F_0F0F_0F0F;
                let b = next() & 0x0F0F_0F0F_0F0F_0F0F;
                let s = GF16::new((next() & 0xF) as u8);
                let scalar = mul_scalar8(a, s);
                let lanes = mul_lanes8(a, b);
                let mut fold_expected = GF16::ZERO;
                for lane in 0..8 {
                    let la = GF16::new((a >> (8 * lane)) as u8);
                    let lb = GF16::new((b >> (8 * lane)) as u8);
                    assert_eq!(
                        GF16::new((scalar >> (8 * lane)) as u8),
                        la * s,
                        "scalar lane {lane}"
                    );
                    assert_eq!(
                        GF16::new((lanes >> (8 * lane)) as u8),
                        la * lb,
                        "pairwise lane {lane}"
                    );
                    fold_expected += la;
                }
                assert_eq!(fold8(a), fold_expected);
            }
        }

        #[test]
        fn slice_as_bytes_is_canonical() {
            let elems: Vec<GF16> = (0..16).map(GF16::new).collect();
            let bytes = GF16::slice_as_bytes(&elems);
            for (i, byte) in bytes.iter().enumerate() {
                assert_eq!(*byte, i as u8);
            }
        }
    }
}
