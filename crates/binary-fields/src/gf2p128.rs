//! `GF(2¹²⁸) = F₂[x]/(x¹²⁸ + x⁷ + x² + x + 1)` — the VOLE tag field.

use crate::BinaryField;
use core::fmt;
use core::iter::{Product, Sum};
use core::ops::{Add, AddAssign, Mul, MulAssign, Sub, SubAssign};
use rand_core::CryptoRngCore;
use zeroize::Zeroize;

/// An element of `GF(2¹²⁸) = F₂[x]/(x¹²⁸ + x⁷ + x² + x + 1)`.
///
/// The element `Σ aᵢxⁱ` is stored as a `u128` with bit `i` holding `aᵢ`
/// (bit 0 = constant term). This is the same reduction polynomial used by
/// FAEST's `F₂₁₂₈` and by GHASH (in non-reflected bit order).
#[derive(Clone, Copy, PartialEq, Eq, Default, Hash)]
pub struct GF2p128(u128);

impl Zeroize for GF2p128 {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

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

    /// Portable constant-time multiplication used on targets without a
    /// carry-less multiply instruction and as the test oracle for fast paths.
    #[inline]
    fn mul_portable(a: u128, b: u128) -> u128 {
        let mut acc = 0;
        let mut shifted = a;
        let mut i = 0;
        while i < 128 {
            let mask = 0u128.wrapping_sub((b >> i) & 1);
            acc ^= shifted & mask;
            shifted = Self::mul_x(shifted);
            i += 1;
        }
        acc
    }

    /// Reduce a 256-bit carry-less product modulo
    /// `x^128 + x^7 + x^2 + x + 1`.
    #[inline]
    fn reduce_product(low: u128, high: u128) -> u128 {
        // Fold `high*x^128` with x^128 = r, r = 0x87. Multiplication by r
        // can overflow by at most seven bits, which are folded once more.
        let folded = high ^ (high << 1) ^ (high << 2) ^ (high << 7);
        let overflow = (high >> 127) ^ (high >> 126) ^ (high >> 121);
        let folded_overflow = overflow ^ (overflow << 1) ^ (overflow << 2) ^ (overflow << 7);
        low ^ folded ^ folded_overflow
    }

    #[inline]
    fn reduce_karatsuba(p0: u128, p1: u128, middle: u128) -> u128 {
        let low = (p0 as u64 as u128) | (((p0 >> 64) ^ (middle as u64 as u128)) << 64);
        let high = ((middle >> 64) ^ (p1 as u64 as u128)) | ((p1 >> 64) << 64);
        Self::reduce_product(low, high)
    }

    /// Three PMULL instructions with Karatsuba produce the unreduced 256-bit
    /// polynomial product.
    #[cfg(target_arch = "aarch64")]
    #[target_feature(enable = "aes")]
    unsafe fn mul_pmull(a: u128, b: u128) -> u128 {
        use core::arch::aarch64::vmull_p64;

        let a0 = a as u64;
        let a1 = (a >> 64) as u64;
        let b0 = b as u64;
        let b1 = (b >> 64) as u64;
        let p0 = vmull_p64(a0, b0);
        let p1 = vmull_p64(a1, b1);
        let middle = vmull_p64(a0 ^ a1, b0 ^ b1) ^ p0 ^ p1;
        Self::reduce_karatsuba(p0, p1, middle)
    }

    /// Three PCLMULQDQ instructions with Karatsuba, for x86-64 hosts.
    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "pclmulqdq")]
    unsafe fn mul_pclmul(a: u128, b: u128) -> u128 {
        use core::arch::x86_64::{__m128i, _mm_clmulepi64_si128};

        // SAFETY: `u128` and `__m128i` are both 128-bit bit containers. Lane
        // zero receives the low-order polynomial coefficients on little-endian
        // x86-64.
        let av: __m128i = unsafe { core::mem::transmute(a) };
        let bv: __m128i = unsafe { core::mem::transmute(b) };
        let p0v = _mm_clmulepi64_si128::<0x00>(av, bv);
        let p1v = _mm_clmulepi64_si128::<0x11>(av, bv);
        let ax = (a as u64) ^ ((a >> 64) as u64);
        let bx = (b as u64) ^ ((b >> 64) as u64);
        let axv: __m128i = unsafe { core::mem::transmute(ax as u128) };
        let bxv: __m128i = unsafe { core::mem::transmute(bx as u128) };
        let middle_v = _mm_clmulepi64_si128::<0x00>(axv, bxv);
        let p0: u128 = unsafe { core::mem::transmute(p0v) };
        let p1: u128 = unsafe { core::mem::transmute(p1v) };
        let middle_product: u128 = unsafe { core::mem::transmute(middle_v) };
        let middle = middle_product ^ p0 ^ p1;
        Self::reduce_karatsuba(p0, p1, middle)
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

    /// Carry-less multiplication with hardware acceleration when available.
    /// The portable fallback has a fixed 128-iteration, branch-free schedule.
    #[inline]
    fn mul(self, rhs: Self) -> Self {
        #[cfg(target_arch = "aarch64")]
        if std::arch::is_aarch64_feature_detected!("aes") {
            // SAFETY: the runtime feature check gates the PMULL target feature.
            return GF2p128(unsafe { Self::mul_pmull(self.0, rhs.0) });
        }
        #[cfg(target_arch = "x86_64")]
        if std::arch::is_x86_feature_detected!("pclmulqdq") {
            // SAFETY: the runtime feature check gates PCLMULQDQ.
            return GF2p128(unsafe { Self::mul_pclmul(self.0, rhs.0) });
        }
        GF2p128(Self::mul_portable(self.0, rhs.0))
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
        #[cfg(target_arch = "aarch64")]
        fn pmull_matches_portable(a: u128, b: u128) {
            if std::arch::is_aarch64_feature_detected!("aes") {
                // SAFETY: guarded by the target-feature check.
                let fast = unsafe { GF2p128::mul_pmull(a, b) };
                prop_assert_eq!(fast, GF2p128::mul_portable(a, b));
            }
        }

        #[test]
        #[cfg(target_arch = "x86_64")]
        fn pclmul_matches_portable(a: u128, b: u128) {
            if std::arch::is_x86_feature_detected!("pclmulqdq") {
                // SAFETY: guarded by the target-feature check.
                let fast = unsafe { GF2p128::mul_pclmul(a, b) };
                prop_assert_eq!(fast, GF2p128::mul_portable(a, b));
            }
        }

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
