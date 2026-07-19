//! `GF(2¹²⁸) = F₂[x]/(x¹²⁸ + x⁷ + x² + x + 1)` — the VOLE tag field.

use crate::BinaryField;
use core::fmt;
use core::iter::{Product, Sum};
use core::ops::{Add, AddAssign, Mul, MulAssign, Sub, SubAssign};
use rand_core::CryptoRngCore;

/// An element of `GF(2¹²⁸) = F₂[x]/(x¹²⁸ + x⁷ + x² + x + 1)`.
///
/// The element `Σ aᵢxⁱ` is stored as a `u128` with bit `i` holding `aᵢ`
/// (bit 0 = constant term). This is the same reduction polynomial used by
/// FAEST's `F₂₁₂₈` and by GHASH (in non-reflected bit order).
#[derive(Clone, Copy, PartialEq, Eq, Default, Hash)]
pub struct GF2p128(u128);

impl GF2p128 {
    /// Low bits of the reduction polynomial: `x⁷ + x² + x + 1`.
    const POLY_LOW: u128 = 0x87;

    /// Construct from the canonical `u128` bit representation.
    #[must_use]
    pub const fn new(v: u128) -> Self {
        GF2p128(v)
    }

    /// The canonical `u128` bit representation.
    #[must_use]
    pub const fn to_u128(self) -> u128 {
        self.0
    }

    /// Canonical little-endian byte serialization.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; 16] {
        self.0.to_le_bytes()
    }

    /// Deserialize from canonical little-endian bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        GF2p128(u128::from_le_bytes(bytes))
    }

    /// Multiply by `x` (a single reduction step). Branch-free.
    #[inline]
    const fn mul_x(v: u128) -> u128 {
        let carry = 0u128.wrapping_sub(v >> 127);
        (v << 1) ^ (carry & Self::POLY_LOW)
    }
}

impl BinaryField for GF2p128 {
    const ZERO: Self = GF2p128(0);
    const ONE: Self = GF2p128(1);
    const BITS: usize = 128;

    /// Inverse via Fermat: `a⁻¹ = a^(2¹²⁸ − 2)`, with `inv(0) = 0`.
    fn inv(self) -> Self {
        // 2^128 - 2 == u128::MAX - 1.
        self.pow(u128::MAX - 1)
    }

    fn random(rng: &mut impl CryptoRngCore) -> Self {
        let mut bytes = [0u8; 16];
        rng.fill_bytes(&mut bytes);
        Self::from_bytes(bytes)
    }
}

impl Add for GF2p128 {
    type Output = Self;
    // In characteristic 2, addition of polynomial coefficients is XOR.
    #[allow(clippy::suspicious_arithmetic_impl)]
    fn add(self, rhs: Self) -> Self {
        GF2p128(self.0 ^ rhs.0)
    }
}

impl Sub for GF2p128 {
    type Output = Self;
    // In characteristic 2, subtraction coincides with addition.
    #[allow(clippy::suspicious_arithmetic_impl)]
    fn sub(self, rhs: Self) -> Self {
        self + rhs
    }
}

impl Mul for GF2p128 {
    type Output = Self;

    /// Russian-peasant carry-less multiply with interleaved reduction.
    ///
    /// Fixed 128 iterations, mask-based conditionals: branch-free on secret
    /// operands. (Hardware carry-less multiply is a deferred optimization;
    /// see the crate docs.)
    fn mul(self, rhs: Self) -> Self {
        let mut acc: u128 = 0;
        let mut a = self.0;
        let b = rhs.0;
        let mut i = 0;
        while i < 128 {
            let mask = 0u128.wrapping_sub((b >> i) & 1);
            acc ^= a & mask;
            a = Self::mul_x(a);
            i += 1;
        }
        GF2p128(acc)
    }
}

impl AddAssign for GF2p128 {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl SubAssign for GF2p128 {
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

impl MulAssign for GF2p128 {
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs;
    }
}

impl Sum for GF2p128 {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::ZERO, |a, b| a + b)
    }
}

impl Product for GF2p128 {
    fn product<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::ONE, |a, b| a * b)
    }
}

impl fmt::Debug for GF2p128 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "GF2p128({:#034x})", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const X: GF2p128 = GF2p128::new(2);

    #[test]
    fn reduction_known_answers() {
        // x^127 * x = x^128 = x^7 + x^2 + x + 1.
        assert_eq!(GF2p128::new(1 << 127) * X, GF2p128::new(0x87));
        // Squaring x seven times gives x^(2^7) = x^128 as well.
        let mut v = X;
        for _ in 0..7 {
            v = v.square();
        }
        assert_eq!(v, GF2p128::new(0x87));
        // x * x = x^2.
        assert_eq!(X * X, GF2p128::new(4));
    }

    #[test]
    fn identities() {
        let a = GF2p128::new(0xDEAD_BEEF_0123_4567_89AB_CDEF_FEDC_BA98);
        assert_eq!(a * GF2p128::ONE, a);
        assert_eq!(a * GF2p128::ZERO, GF2p128::ZERO);
        assert_eq!(a + GF2p128::ZERO, a);
        assert_eq!(a + a, GF2p128::ZERO);
    }

    #[test]
    fn inv_zero_is_zero() {
        assert_eq!(GF2p128::ZERO.inv(), GF2p128::ZERO);
        assert_eq!(GF2p128::ONE.inv(), GF2p128::ONE);
    }

    #[test]
    fn bytes_roundtrip() {
        let a = GF2p128::new(0x0123_4567_89AB_CDEF_0011_2233_4455_6677);
        assert_eq!(GF2p128::from_bytes(a.to_bytes()), a);
    }

    proptest! {
        #[test]
        fn commutativity(a: u128, b: u128) {
            let (a, b) = (GF2p128::new(a), GF2p128::new(b));
            prop_assert_eq!(a * b, b * a);
            prop_assert_eq!(a + b, b + a);
        }

        #[test]
        fn associativity(a: u128, b: u128, c: u128) {
            let (a, b, c) = (GF2p128::new(a), GF2p128::new(b), GF2p128::new(c));
            prop_assert_eq!((a * b) * c, a * (b * c));
            prop_assert_eq!((a + b) + c, a + (b + c));
        }

        #[test]
        fn distributivity(a: u128, b: u128, c: u128) {
            let (a, b, c) = (GF2p128::new(a), GF2p128::new(b), GF2p128::new(c));
            prop_assert_eq!(a * (b + c), a * b + a * c);
        }

        #[test]
        fn inverses(a: u128) {
            prop_assume!(a != 0);
            let a = GF2p128::new(a);
            prop_assert_eq!(a * a.inv(), GF2p128::ONE);
        }

        #[test]
        fn frobenius_is_additive(a: u128, b: u128) {
            let (a, b) = (GF2p128::new(a), GF2p128::new(b));
            prop_assert_eq!((a + b).square(), a.square() + b.square());
        }

        #[test]
        fn frobenius_order_divides_128(a: u128) {
            // Applying the Frobenius x -> x^2 128 times is the identity on
            // GF(2^128): a strong end-to-end check of the reduction logic.
            let a = GF2p128::new(a);
            let mut v = a;
            for _ in 0..128 {
                v = v.square();
            }
            prop_assert_eq!(v, a);
        }
    }
}
