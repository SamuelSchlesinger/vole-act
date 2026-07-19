//! MAYO parameter sets (round-2 specification, Table 2.1).

mod sealed {
    pub trait MayoParams {}
}

/// A supported MAYO round-2 parameter set.
///
/// The irreducible polynomial `f(z) = z^M + Σ (c_d)·z^d` over `F₁₆` defines
/// the extension field whose multiplication-by-`z` matrix is the `E` matrix;
/// `F_TAIL` lists the nonzero tail coefficients `(d, c_d)` with `c_d` encoded
/// as a nibble (bit `i` = coefficient of `xⁱ` in `F₁₆ = F₂[x]/(x⁴+x+1)`).
///
/// This trait is sealed. New tuples require field-polynomial validation,
/// circuit/message bounds, wire identifiers, and a fresh security analysis;
/// treating them as ordinary downstream implementations would be unsafe.
pub trait MayoParams: sealed::MayoParams + 'static + Copy + Send + Sync {
    /// Stable one-byte identifier used by the canonical expanded-key codec.
    const WIRE_ID: u8;
    /// Number of variables of the base map.
    const N: usize;
    /// Number of polynomials (codomain dimension).
    const M: usize;
    /// Oil-space dimension.
    const O: usize;
    /// Whipping parameter (number of copies).
    const K: usize;
    /// Nonzero tail coefficients of `f(z)` as `(degree, nibble)` pairs.
    const F_TAIL: &'static [(usize, u8)];

    /// Vinegar dimension `N − O`.
    const V: usize = Self::N - Self::O;
    /// Whipped input length `K·N`.
    const KN: usize = Self::K * Self::N;
    /// A short human-readable name.
    const NAME: &'static str;
}

/// MAYO₁ — targets NIST security category 1, `(n,m,o,k) = (86,78,8,10)`,
/// `f₇₈ = z⁷⁸+z²+z+x³`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mayo1;

impl sealed::MayoParams for Mayo1 {}

impl MayoParams for Mayo1 {
    const WIRE_ID: u8 = 1;
    const N: usize = 86;
    const M: usize = 78;
    const O: usize = 8;
    const K: usize = 10;
    const F_TAIL: &'static [(usize, u8)] = &[(2, 0x1), (1, 0x1), (0, 0x8)];
    const NAME: &'static str = "MAYO1";
}

/// MAYO₂ — targets NIST security category 1, `(n,m,o,k) = (81,64,17,4)`,
/// `f₆₄ = z⁶⁴+x³z³+xz²+x³`. Compared with MAYO₁, this is the level-1
/// trade-off with a larger public key and substantially shorter signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mayo2;

impl sealed::MayoParams for Mayo2 {}

impl MayoParams for Mayo2 {
    const WIRE_ID: u8 = 2;
    const N: usize = 81;
    const M: usize = 64;
    const O: usize = 17;
    const K: usize = 4;
    const F_TAIL: &'static [(usize, u8)] = &[(3, 0x8), (2, 0x2), (0, 0x8)];
    const NAME: &'static str = "MAYO2";
}

/// MAYO₃ — targets NIST security category 3, `(n,m,o,k) = (118,108,10,11)`,
/// `f₁₀₈ = z¹⁰⁸+(x²+x+1)z³+z²+x³`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mayo3;

impl sealed::MayoParams for Mayo3 {}

impl MayoParams for Mayo3 {
    const WIRE_ID: u8 = 3;
    const N: usize = 118;
    const M: usize = 108;
    const O: usize = 10;
    const K: usize = 11;
    const F_TAIL: &'static [(usize, u8)] = &[(3, 0x7), (2, 0x1), (0, 0x8)];
    const NAME: &'static str = "MAYO3";
}

/// MAYO₅ — targets NIST security category 5, `(n,m,o,k) = (154,142,12,12)`,
/// `f₁₄₂ = z¹⁴²+z³+x³z²+x²`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mayo5;

impl sealed::MayoParams for Mayo5 {}

impl MayoParams for Mayo5 {
    const WIRE_ID: u8 = 5;
    const N: usize = 154;
    const M: usize = 142;
    const O: usize = 12;
    const K: usize = 12;
    const F_TAIL: &'static [(usize, u8)] = &[(3, 0x1), (2, 0x8), (0, 0x4)];
    const NAME: &'static str = "MAYO5";
}
