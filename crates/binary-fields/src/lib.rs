//! Binary field arithmetic for VOLE-in-the-head proofs and the MAYO trapdoor.
//!
//! This crate provides the two fields the VOLE-ACT stack is built on, plus the
//! canonical embedding between them:
//!
//! - [`GF16`]: the MAYO field `F₂[x]/(x⁴+x+1)`, elements stored as nibbles.
//! - [`GF2p128`]: the VOLE tag field `F₂[x]/(x¹²⁸+x⁷+x²+x+1)` (the polynomial
//!   used by FAEST and by GCM's GHASH, in non-reflected bit order).
//! - [`embed_gf16`]: the field homomorphism `GF(16) ↪ GF(2¹²⁸)` used to lift
//!   committed F₁₆ values into the tag field.
//!
//! All field arithmetic is branch-free on secret data and uses no
//! secret-indexed lookup tables. The one exception in this crate is
//! [`embed_gf16`], whose 16-entry table is indexed by its input nibble: it is
//! intended for *public* values (basis constants, public coefficients) and
//! must not be called on secret data until a constant-time variant exists —
//! see its documentation. GF(2¹²⁸) multiplication uses PMULL on AArch64 and
//! PCLMULQDQ on x86-64 when available, with a fixed-iteration portable
//! fallback.

mod embed;
mod gf16;
mod gf2p128;

pub use embed::embed_gf16;
pub use gf2p128::GF2p128;
pub use gf16::GF16;

use core::fmt::Debug;
use core::ops::{Add, AddAssign, Mul, MulAssign, Sub, SubAssign};
use rand_core::CryptoRngCore;

/// A binary (characteristic-2) finite field.
///
/// Addition and subtraction coincide (both are XOR); [`Sub`] is provided so
/// generic code can be written naturally.
pub trait BinaryField:
    'static
    + Copy
    + Clone
    + Debug
    + Default
    + Eq
    + Add<Output = Self>
    + AddAssign
    + Sub<Output = Self>
    + SubAssign
    + Mul<Output = Self>
    + MulAssign
{
    /// The additive identity.
    const ZERO: Self;
    /// The multiplicative identity.
    const ONE: Self;
    /// Number of bits in the field's canonical representation.
    const BITS: usize;

    /// Squaring (the Frobenius endomorphism in characteristic 2).
    #[must_use]
    fn square(self) -> Self {
        self * self
    }

    /// Multiplicative inverse, with the convention `inv(0) = 0`.
    ///
    /// Callers that must distinguish the zero case (e.g. Gaussian elimination
    /// pivoting) should test for zero explicitly.
    #[must_use]
    fn inv(self) -> Self;

    /// Exponentiation by a public exponent (square-and-multiply; the exponent
    /// is *not* treated as secret).
    #[must_use]
    fn pow(self, mut e: u128) -> Self {
        let mut acc = Self::ONE;
        let mut base = self;
        while e != 0 {
            if e & 1 == 1 {
                acc *= base;
            }
            base = base.square();
            e >>= 1;
        }
        acc
    }

    /// Sample a uniformly random field element.
    fn random(rng: &mut impl CryptoRngCore) -> Self;
}
