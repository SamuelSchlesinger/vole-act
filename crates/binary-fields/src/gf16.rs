//! `GF(16) = F₂[x]/(x⁴ + x + 1)` — the field MAYO's multivariate system lives in.

use crate::BinaryField;
use core::fmt;
use core::iter::{Product, Sum};
use core::ops::{Add, AddAssign, Mul, MulAssign, Sub, SubAssign};
use rand_core::CryptoRngCore;

/// An element of `GF(16) = F₂[x]/(x⁴ + x + 1)`.
///
/// The element `a₀ + a₁x + a₂x² + a₃x³` is stored as the nibble
/// `a₃a₂a₁a₀` in the low four bits of a byte. The high four bits are always
/// zero (an invariant maintained by every constructor).
#[derive(Clone, Copy, PartialEq, Eq, Default, Hash, PartialOrd, Ord)]
pub struct GF16(u8);

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
