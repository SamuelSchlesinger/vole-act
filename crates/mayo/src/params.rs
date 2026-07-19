//! MAYO parameter sets (round-2 specification, Table 2.1).

/// A MAYO parameter set.
///
/// The irreducible polynomial `f(z) = z^M + Σ (c_d)·z^d` over `F₁₆` defines
/// the extension field whose multiplication-by-`z` matrix is the `E` matrix;
/// `F_TAIL` lists the nonzero tail coefficients `(d, c_d)` with `c_d` encoded
/// as a nibble (bit `i` = coefficient of `xⁱ` in `F₁₆ = F₂[x]/(x⁴+x+1)`).
pub trait MayoParams: 'static + Copy + Send + Sync {
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

/// MAYO₁ — NIST level 1, `(n,m,o,k) = (86,78,8,10)`, `f₇₈ = z⁷⁸+z²+z+x³`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mayo1;

impl MayoParams for Mayo1 {
    const N: usize = 86;
    const M: usize = 78;
    const O: usize = 8;
    const K: usize = 10;
    const F_TAIL: &'static [(usize, u8)] = &[(2, 0x1), (1, 0x1), (0, 0x8)];
    const NAME: &'static str = "MAYO1";
}

/// MAYO₂ — NIST level 1, `(n,m,o,k) = (81,64,17,4)`, `f₆₄ = z⁶⁴+x³z³+xz²+x³`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mayo2;

impl MayoParams for Mayo2 {
    const N: usize = 81;
    const M: usize = 64;
    const O: usize = 17;
    const K: usize = 4;
    const F_TAIL: &'static [(usize, u8)] = &[(3, 0x8), (2, 0x2), (0, 0x8)];
    const NAME: &'static str = "MAYO2";
}

/// MAYO₃ — NIST level 3, `(n,m,o,k) = (118,108,10,11)`,
/// `f₁₀₈ = z¹⁰⁸+(x²+x+1)z³+z²+x³`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mayo3;

impl MayoParams for Mayo3 {
    const N: usize = 118;
    const M: usize = 108;
    const O: usize = 10;
    const K: usize = 11;
    const F_TAIL: &'static [(usize, u8)] = &[(3, 0x7), (2, 0x1), (0, 0x8)];
    const NAME: &'static str = "MAYO3";
}

/// MAYO₅ — NIST level 5, `(n,m,o,k) = (154,142,12,12)`,
/// `f₁₄₂ = z¹⁴²+z³+x³z²+x²`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mayo5;

impl MayoParams for Mayo5 {
    const N: usize = 154;
    const M: usize = 142;
    const O: usize = 12;
    const K: usize = 12;
    const F_TAIL: &'static [(usize, u8)] = &[(3, 0x1), (2, 0x8), (0, 0x4)];
    const NAME: &'static str = "MAYO5";
}
