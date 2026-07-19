//! Dense row-major matrices over GF(16) — just enough linear algebra for
//! MAYO (products, transposes, `Upper`, Gaussian elimination).
//!
//! The product kernels (`mul`, `mul_vec`, `vec_mul`, `quad_form`) run on
//! eight-lane packed words ([`binary_fields::gf16_packed`]): branch-free,
//! no secret-indexed lookups, bit-identical to the definitional scalar
//! loops (which remain in the test module as oracles).

use binary_fields::{BinaryField, GF16, gf16_packed as packed};
use rand_core::CryptoRngCore;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Read one packed 8-lane word from canonical GF(16) bytes, zero-padded.
#[inline]
fn word_at(bytes: &[u8], start: usize) -> u64 {
    let end = (start + 8).min(bytes.len());
    let mut buf = [0u8; 8];
    buf[..end - start].copy_from_slice(&bytes[start..end]);
    u64::from_le_bytes(buf)
}

/// `dst ^= scalar · src`, lane-wise over equal-length GF(16) slices.
pub(crate) fn packed_axpy(dst: &mut [GF16], scalar: GF16, src: &[GF16]) {
    assert_eq!(dst.len(), src.len());
    let dst_bytes = GF16::slice_as_bytes_mut(dst);
    let src_bytes = GF16::slice_as_bytes(src);
    let (dst_words, dst_tail) = dst_bytes.as_chunks_mut::<8>();
    let (src_words, src_tail) = src_bytes.as_chunks::<8>();
    for (d, s) in dst_words.iter_mut().zip(src_words.iter()) {
        let w = u64::from_le_bytes(*d) ^ packed::mul_scalar8(u64::from_le_bytes(*s), scalar);
        *d = w.to_le_bytes();
    }
    for (d, s) in dst_tail.iter_mut().zip(src_tail.iter()) {
        *d ^= (GF16::new(*s) * scalar).to_u8();
    }
}

/// A dense row-major matrix over `GF(16)`.
#[derive(Clone, PartialEq, Eq)]
pub struct Mat {
    rows: usize,
    cols: usize,
    data: Vec<GF16>,
}

impl Zeroize for Mat {
    fn zeroize(&mut self) {
        self.data.zeroize();
    }
}

impl Drop for Mat {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl ZeroizeOnDrop for Mat {}

impl Mat {
    pub(crate) fn from_data(rows: usize, cols: usize, data: Vec<GF16>) -> Option<Self> {
        (data.len() == rows.checked_mul(cols)?).then_some(Self { rows, cols, data })
    }

    /// A zero matrix.
    #[must_use]
    pub fn zero(rows: usize, cols: usize) -> Self {
        Mat {
            rows,
            cols,
            data: vec![GF16::ZERO; rows * cols],
        }
    }

    /// A uniformly random matrix.
    pub fn random(rows: usize, cols: usize, rng: &mut impl CryptoRngCore) -> Self {
        let mut m = Mat::zero(rows, cols);
        for e in m.data.iter_mut() {
            *e = GF16::random(rng);
        }
        m
    }

    /// A uniformly random upper-triangular square matrix (entries below the
    /// diagonal are zero).
    pub fn random_upper(dim: usize, rng: &mut impl CryptoRngCore) -> Self {
        let mut m = Mat::zero(dim, dim);
        for r in 0..dim {
            for c in r..dim {
                m[(r, c)] = GF16::random(rng);
            }
        }
        m
    }

    /// Number of rows.
    #[must_use]
    pub fn rows(&self) -> usize {
        self.rows
    }

    /// Number of columns.
    #[must_use]
    pub fn cols(&self) -> usize {
        self.cols
    }

    /// The entries in row-major order (row `r` occupies
    /// `[r·cols, (r+1)·cols)`).
    #[must_use]
    pub fn entries(&self) -> &[GF16] {
        &self.data
    }

    /// Row `r` as a slice.
    pub(crate) fn row(&self, r: usize) -> &[GF16] {
        &self.data[r * self.cols..(r + 1) * self.cols]
    }

    /// Row `r` as a mutable slice.
    pub(crate) fn row_mut(&mut self, r: usize) -> &mut [GF16] {
        &mut self.data[r * self.cols..(r + 1) * self.cols]
    }

    /// Matrix product `self · rhs`.
    #[must_use]
    pub fn mul(&self, rhs: &Mat) -> Mat {
        assert_eq!(self.cols, rhs.rows);
        let mut out = Mat::zero(self.rows, rhs.cols);
        let rhs_bytes = GF16::slice_as_bytes(&rhs.data);
        let words = rhs.cols.div_ceil(8);
        // Row accumulator in packed lanes; holds key-derived secrets during
        // key expansion, so it is wiped on drop.
        let mut acc = Zeroizing::new(vec![0u64; words.max(1)]);
        for r in 0..self.rows {
            acc.fill(0);
            for i in 0..self.cols {
                let a = self[(r, i)];
                let row_base = i * rhs.cols;
                for (w, slot) in acc.iter_mut().enumerate() {
                    *slot ^= packed::mul_scalar8(word_at(rhs_bytes, row_base + 8 * w), a);
                }
            }
            for c in 0..rhs.cols {
                out[(r, c)] = GF16::new((acc[c / 8] >> (8 * (c % 8))) as u8);
            }
        }
        out
    }

    /// Transpose.
    #[must_use]
    pub fn transpose(&self) -> Mat {
        let mut out = Mat::zero(self.cols, self.rows);
        for r in 0..self.rows {
            for c in 0..self.cols {
                out[(c, r)] = self[(r, c)];
            }
        }
        out
    }

    /// Entry-wise sum.
    #[must_use]
    pub fn add(&self, rhs: &Mat) -> Mat {
        assert_eq!((self.rows, self.cols), (rhs.rows, rhs.cols));
        let mut out = self.clone();
        for (a, b) in out.data.iter_mut().zip(rhs.data.iter()) {
            *a += *b;
        }
        out
    }

    /// `Upper(M)`: the upper-triangular matrix with `U_ii = M_ii` and
    /// `U_ij = M_ij + M_ji` for `i < j` (spec §2.1.2).
    #[must_use]
    pub fn upper(&self) -> Mat {
        assert_eq!(self.rows, self.cols);
        let mut out = Mat::zero(self.rows, self.cols);
        for r in 0..self.rows {
            out[(r, r)] = self[(r, r)];
            for c in (r + 1)..self.cols {
                out[(r, c)] = self[(r, c)] + self[(c, r)];
            }
        }
        out
    }

    /// `vᵀ·M`: row-vector times matrix, as a vector of length `cols`.
    ///
    /// Packed row-axpy: each row is scaled by its (possibly secret) scalar
    /// eight lanes at a time. Lanes beyond `cols` in the final word never
    /// reach the unpacked output.
    #[must_use]
    pub fn vec_mul(&self, v: &[GF16]) -> Vec<GF16> {
        assert_eq!(v.len(), self.rows);
        let bytes = GF16::slice_as_bytes(&self.data);
        let words = self.cols.div_ceil(8);
        let mut acc = Zeroizing::new(vec![0u64; words.max(1)]);
        for (r, &vr) in v.iter().enumerate() {
            let row_base = r * self.cols;
            for (w, slot) in acc.iter_mut().enumerate() {
                *slot ^= packed::mul_scalar8(word_at(bytes, row_base + 8 * w), vr);
            }
        }
        let mut out = vec![GF16::ZERO; self.cols];
        for (c, elem) in out.iter_mut().enumerate() {
            *elem = GF16::new((acc[c / 8] >> (8 * (c % 8))) as u8);
        }
        out
    }

    /// The quadratic form `vᵀ · M · v`.
    #[must_use]
    pub fn quad_form(&self, v: &[GF16]) -> GF16 {
        assert_eq!(self.rows, self.cols);
        assert_eq!(v.len(), self.rows);
        let mv = self.mul_vec(v);
        v.iter()
            .zip(mv.iter())
            .fold(GF16::ZERO, |acc, (a, b)| acc + *a * *b)
    }

    /// `M·v`: matrix times column vector, as a vector of length `rows`.
    ///
    /// Packed dot products: eight lane-wise nibble multiplies per word,
    /// XOR-folded to the row sum. `word_at` zero-pads past the end of the
    /// data, and zero lanes contribute zero to the fold, so ragged widths
    /// need no special casing beyond padding `v`.
    #[must_use]
    pub fn mul_vec(&self, v: &[GF16]) -> Vec<GF16> {
        assert_eq!(v.len(), self.cols);
        let bytes = GF16::slice_as_bytes(&self.data);
        let v_bytes = GF16::slice_as_bytes(v);
        let words = self.cols.div_ceil(8);
        let mut out = vec![GF16::ZERO; self.rows];
        for (r, elem) in out.iter_mut().enumerate() {
            let row_base = r * self.cols;
            let mut acc = 0u64;
            for w in 0..words {
                // The row word may run into the next row's bytes on ragged
                // widths; mask to the true row length so those lanes are
                // zero before the fold.
                let mut row_word = word_at(bytes, row_base + 8 * w);
                let remaining = self.cols - 8 * w;
                if remaining < 8 {
                    row_word &= (1u64 << (8 * remaining)) - 1;
                }
                acc ^= packed::mul_lanes8(row_word, word_at(v_bytes, 8 * w));
            }
            *elem = packed::fold8(acc);
        }
        out
    }
}

impl core::ops::Index<(usize, usize)> for Mat {
    type Output = GF16;
    fn index(&self, (r, c): (usize, usize)) -> &GF16 {
        &self.data[r * self.cols + c]
    }
}

impl core::ops::IndexMut<(usize, usize)> for Mat {
    fn index_mut(&mut self, (r, c): (usize, usize)) -> &mut GF16 {
        &mut self.data[r * self.cols + c]
    }
}

impl core::fmt::Debug for Mat {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Mat({}x{})", self.rows, self.cols)
    }
}

/// Solve `A·x = y` for a uniformly random solution, per spec Algorithm 2
/// (`SampleSolution`).
///
/// Elimination uses a fixed public loop schedule, scans every possible pivot
/// row, and applies masked row selection. Pivot positions never become array
/// indices or branch conditions. The final full-rank result is allowed to
/// select success versus retry, as in the official MAYO implementation.
/// Returns `None` when `A` does not have full row rank.
#[must_use]
pub fn sample_solution(a: &Mat, y: &[GF16], r: &[GF16]) -> Option<Vec<GF16>> {
    let m = a.rows();
    let cols = a.cols();
    assert_eq!(y.len(), m);
    assert_eq!(r.len(), cols);

    // x ← r; y' ← y − A·r.
    let mut ar = a.mul_vec(r);
    let mut aug = Mat::zero(m, cols + 1);
    for row in 0..m {
        for column in 0..cols {
            aug[(row, column)] = a[(row, column)];
        }
        aug[(row, cols)] = y[row] + ar[row];
    }

    // Mask helpers return one-bit values. Matrix dimensions are public and
    // far below the top bit of usize, so wrapping-subtraction comparison is
    // unambiguous on every supported target. Each result passes through
    // `black_box` so the optimizer cannot prove the value is 0/1 and
    // re-derive a branch from it; this is a best-effort barrier, not a
    // machine-code guarantee (see SECURITY.md B4).
    let ct_is_zero = |value: usize| -> u8 {
        core::hint::black_box((((value | value.wrapping_neg()) >> (usize::BITS - 1)) ^ 1) as u8)
    };
    let ct_eq = |left: usize, right: usize| -> u8 { ct_is_zero(left ^ right) };
    let ct_lt = |left: usize, right: usize| -> u8 {
        core::hint::black_box((left.wrapping_sub(right) >> (usize::BITS - 1)) as u8)
    };
    let gf_nonzero = |value: GF16| -> u8 {
        let value = value.to_u8() as usize;
        1 ^ ct_is_zero(value)
    };

    // Fixed-schedule Gauss-Jordan elimination. `pivot_row` and the arrays
    // derived from it are secret data, but are used only through full scans.
    let mut pivot_row = 0;
    let mut pivot_rows = vec![0usize; cols];
    let mut pivot_columns = vec![0u8; cols];
    let mut selected = vec![GF16::ZERO; cols + 1];
    let mut normalized = vec![GF16::ZERO; cols + 1];

    for pivot_column in 0..cols {
        selected.fill(GF16::ZERO);
        let mut found = 0u8;
        for row in 0..m {
            let at_or_below = 1 ^ ct_lt(row, pivot_row);
            let is_target = ct_eq(row, pivot_row);
            let take_lower =
                at_or_below & (is_target ^ 1) & gf_nonzero(aug[(row, pivot_column)]) & (found ^ 1);
            // Always include the current target row. If its pivot is zero,
            // XOR in the first usable lower row. Subsequent elimination then
            // moves the old target row into that source row, preserving rank
            // without a secret-indexed swap.
            let include = is_target | take_lower;
            let mask = 0u8.wrapping_sub(include);
            for column in 0..=cols {
                selected[column] += GF16::new(aug[(row, column)].to_u8() & mask);
            }
            found |= at_or_below & gf_nonzero(aug[(row, pivot_column)]);
        }

        let inverse = selected[pivot_column].inv();
        for column in 0..=cols {
            normalized[column] = inverse * selected[column];
        }

        pivot_rows[pivot_column] = pivot_row;
        pivot_columns[pivot_column] = found;

        // Put the normalized row at secret index `pivot_row` via a full scan.
        for row in 0..m {
            let write = found & ct_eq(row, pivot_row);
            let write_mask = 0u8.wrapping_sub(write);
            let keep_mask = !write_mask;
            for column in 0..=cols {
                let old = aug[(row, column)].to_u8();
                let new = normalized[column].to_u8();
                aug[(row, column)] = GF16::new((old & keep_mask) | (new & write_mask));
            }
        }

        // Eliminate this pivot column from every other row. All row and
        // column accesses are public; only field values are masked.
        for row in 0..m {
            let eliminate = found & (1 ^ ct_eq(row, pivot_row));
            let mask = 0u8.wrapping_sub(eliminate);
            let factor = GF16::new(aug[(row, pivot_column)].to_u8() & mask);
            for column in 0..=cols {
                aug[(row, column)] += factor * normalized[column];
            }
        }
        pivot_row += found as usize;
    }

    // Revealing whether this sample needs a retry is permitted by MAYO.
    if pivot_row != m {
        ar.zeroize();
        aug.zeroize();
        pivot_rows.zeroize();
        pivot_columns.zeroize();
        selected.zeroize();
        normalized.zeroize();
        return None;
    }

    // Free correction variables are zero. For every pivot column, scan all
    // rows to select the final RREF right-hand side without indexing by its
    // secret pivot row.
    let mut x: Vec<GF16> = r.to_vec();
    for column in 0..cols {
        let mut correction = 0u8;
        for row in 0..m {
            let mask = 0u8.wrapping_sub(ct_eq(row, pivot_rows[column]));
            correction ^= aug[(row, cols)].to_u8() & mask;
        }
        correction &= 0u8.wrapping_sub(pivot_columns[column]);
        x[column] += GF16::new(correction);
    }
    ar.zeroize();
    aug.zeroize();
    pivot_rows.zeroize();
    pivot_columns.zeroize();
    selected.zeroize();
    normalized.zeroize();
    Some(x)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    /// Definitional scalar implementations, kept as oracles for the packed
    /// kernels.
    fn mul_reference(a: &Mat, rhs: &Mat) -> Mat {
        let mut out = Mat::zero(a.rows, rhs.cols);
        for r in 0..a.rows {
            for i in 0..a.cols {
                let s = a[(r, i)];
                for c in 0..rhs.cols {
                    out[(r, c)] += s * rhs[(i, c)];
                }
            }
        }
        out
    }

    fn mul_vec_reference(m: &Mat, v: &[GF16]) -> Vec<GF16> {
        let mut out = vec![GF16::ZERO; m.rows];
        for (r, elem) in out.iter_mut().enumerate() {
            for c in 0..m.cols {
                *elem += m[(r, c)] * v[c];
            }
        }
        out
    }

    fn vec_mul_reference(m: &Mat, v: &[GF16]) -> Vec<GF16> {
        let mut out = vec![GF16::ZERO; m.cols];
        for (r, &vr) in v.iter().enumerate() {
            for (c, elem) in out.iter_mut().enumerate() {
                *elem += vr * m[(r, c)];
            }
        }
        out
    }

    #[test]
    fn packed_kernels_match_reference() {
        let mut rng = StdRng::seed_from_u64(0x9A17);
        // Ragged and word-aligned shapes, including MAYO2's own (64, 81, 17).
        for (rows, mid, cols) in [
            (1, 1, 1),
            (3, 5, 7),
            (8, 8, 8),
            (9, 16, 17),
            (17, 64, 17),
            (64, 81, 17),
            (64, 64, 64),
        ] {
            let a = Mat::random(rows, mid, &mut rng);
            let b = Mat::random(mid, cols, &mut rng);
            assert_eq!(a.mul(&b), mul_reference(&a, &b), "{rows}x{mid}x{cols}");

            let v_mid: Vec<GF16> = (0..mid).map(|_| GF16::random(&mut rng)).collect();
            assert_eq!(
                a.mul_vec(&v_mid),
                mul_vec_reference(&a, &v_mid),
                "mul_vec {rows}x{mid}"
            );

            let v_rows: Vec<GF16> = (0..rows).map(|_| GF16::random(&mut rng)).collect();
            assert_eq!(
                a.vec_mul(&v_rows),
                vec_mul_reference(&a, &v_rows),
                "vec_mul {rows}x{mid}"
            );
        }
    }

    #[test]
    fn upper_symmetrizes() {
        let mut rng = StdRng::seed_from_u64(1);
        let m = Mat::random(5, 5, &mut rng);
        let u = m.upper();
        // For all vectors v: vᵀ·M·v == vᵀ·Upper(M)·v.
        for _ in 0..20 {
            let v: Vec<GF16> = (0..5).map(|_| GF16::random(&mut rng)).collect();
            let quad = |mat: &Mat| {
                let mv = mat.mul_vec(&v);
                v.iter()
                    .zip(mv.iter())
                    .fold(GF16::ZERO, |acc, (a, b)| acc + *a * *b)
            };
            assert_eq!(quad(&m), quad(&u));
        }
    }

    #[test]
    fn sample_solution_solves() {
        let mut rng = StdRng::seed_from_u64(2);
        let mut successes = 0;
        for trial in 0..50 {
            let m = 6;
            let cols = 10;
            let a = Mat::random(m, cols, &mut rng);
            let y: Vec<GF16> = (0..m).map(|_| GF16::random(&mut rng)).collect();
            let r: Vec<GF16> = (0..cols).map(|_| GF16::random(&mut rng)).collect();
            if let Some(x) = sample_solution(&a, &y, &r) {
                assert_eq!(a.mul_vec(&x), y, "trial {trial}: A·x must equal y");
                successes += 1;
            }
        }
        assert!(successes >= 48, "unexpected full-rank rate: {successes}/50");
    }

    #[test]
    fn sample_solution_detects_rank_deficiency() {
        let mut rng = StdRng::seed_from_u64(3);
        // A matrix with a duplicated row cannot have full row rank.
        let mut a = Mat::random(4, 8, &mut rng);
        for c in 0..8 {
            let v = a[(0, c)];
            a[(1, c)] = v;
        }
        let y: Vec<GF16> = (0..4).map(|_| GF16::random(&mut rng)).collect();
        let r: Vec<GF16> = (0..8).map(|_| GF16::random(&mut rng)).collect();
        // With random y, row 2 = row 1 forces inconsistency w.p. 15/16; a
        // consistent duplicate still leaves rank ≤ 3 < 4.
        assert!(sample_solution(&a, &y, &r).is_none());
    }
}
