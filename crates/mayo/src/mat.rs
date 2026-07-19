//! Dense row-major matrices over GF(16) — just enough linear algebra for
//! MAYO (products, transposes, `Upper`, Gaussian elimination).

use binary_fields::{BinaryField, GF16};
use rand_core::CryptoRngCore;

/// A dense row-major matrix over `GF(16)`.
#[derive(Clone, PartialEq, Eq)]
pub struct Mat {
    rows: usize,
    cols: usize,
    data: Vec<GF16>,
}

impl Mat {
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

    /// Matrix product `self · rhs`.
    #[must_use]
    pub fn mul(&self, rhs: &Mat) -> Mat {
        assert_eq!(self.cols, rhs.rows);
        let mut out = Mat::zero(self.rows, rhs.cols);
        for r in 0..self.rows {
            for i in 0..self.cols {
                let a = self[(r, i)];
                if a == GF16::ZERO {
                    continue;
                }
                for c in 0..rhs.cols {
                    out[(r, c)] += a * rhs[(i, c)];
                }
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
    #[must_use]
    pub fn vec_mul(&self, v: &[GF16]) -> Vec<GF16> {
        assert_eq!(v.len(), self.rows);
        let mut out = vec![GF16::ZERO; self.cols];
        for (r, &vr) in v.iter().enumerate() {
            if vr == GF16::ZERO {
                continue;
            }
            for c in 0..self.cols {
                out[c] += vr * self[(r, c)];
            }
        }
        out
    }

    /// `M·v`: matrix times column vector, as a vector of length `rows`.
    #[must_use]
    pub fn mul_vec(&self, v: &[GF16]) -> Vec<GF16> {
        assert_eq!(v.len(), self.cols);
        let mut out = vec![GF16::ZERO; self.rows];
        for r in 0..self.rows {
            let mut acc = GF16::ZERO;
            for c in 0..self.cols {
                acc += self[(r, c)] * v[c];
            }
            out[r] = acc;
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
/// (`SampleSolution`): randomize with `r`, reduce `(A|y)` to echelon form,
/// fail if `A` has rank < rows, then back-substitute.
///
/// Returns `None` when `A` does not have full row rank.
#[must_use]
pub fn sample_solution(a: &Mat, y: &[GF16], r: &[GF16]) -> Option<Vec<GF16>> {
    let m = a.rows();
    let cols = a.cols();
    assert_eq!(y.len(), m);
    assert_eq!(r.len(), cols);

    // x ← r; y' ← y − A·r.
    let ar = a.mul_vec(r);
    let mut aug = Mat::zero(m, cols + 1);
    for rr in 0..m {
        for cc in 0..cols {
            aug[(rr, cc)] = a[(rr, cc)];
        }
        aug[(rr, cols)] = y[rr] + ar[rr];
    }

    // Echelon form with leading ones (spec Algorithm 1).
    let mut pivot_row = 0;
    let mut pivot_col = 0;
    let mut pivots = Vec::with_capacity(m);
    while pivot_row < m && pivot_col < cols + 1 {
        let Some(next) = (pivot_row..m).find(|&rr| aug[(rr, pivot_col)] != GF16::ZERO) else {
            pivot_col += 1;
            continue;
        };
        // Swap rows.
        if next != pivot_row {
            for cc in 0..=cols {
                let tmp = aug[(pivot_row, cc)];
                aug[(pivot_row, cc)] = aug[(next, cc)];
                aug[(next, cc)] = tmp;
            }
        }
        // Normalize the pivot row.
        let inv = aug[(pivot_row, pivot_col)].inv();
        for cc in 0..=cols {
            aug[(pivot_row, cc)] = inv * aug[(pivot_row, cc)];
        }
        // Eliminate below.
        for rr in (pivot_row + 1)..m {
            let f = aug[(rr, pivot_col)];
            if f != GF16::ZERO {
                for cc in 0..=cols {
                    let sub = f * aug[(pivot_row, cc)];
                    aug[(rr, cc)] += sub;
                }
            }
        }
        pivots.push(pivot_col);
        pivot_row += 1;
        pivot_col += 1;
    }

    // Full row rank means every row got a pivot inside A (not the y column).
    if pivot_row < m || pivots.iter().any(|&c| c >= cols) {
        return None;
    }

    // Back-substitution: x_c ← x_c + y_r; y ← y − y_r·A[:,c].
    let mut x: Vec<GF16> = r.to_vec();
    let mut rhs: Vec<GF16> = (0..m).map(|rr| aug[(rr, cols)]).collect();
    for rr in (0..m).rev() {
        let c = pivots[rr];
        let yr = rhs[rr];
        x[c] += yr;
        // Update earlier rows' rhs to account for x_c's new value.
        for up in 0..rr {
            rhs[up] += yr * aug[(up, c)];
        }
    }
    Some(x)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand::rngs::StdRng;

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
        for trial in 0..50 {
            let m = 6;
            let cols = 10;
            let a = Mat::random(m, cols, &mut rng);
            let y: Vec<GF16> = (0..m).map(|_| GF16::random(&mut rng)).collect();
            let r: Vec<GF16> = (0..cols).map(|_| GF16::random(&mut rng)).collect();
            if let Some(x) = sample_solution(&a, &y, &r) {
                assert_eq!(a.mul_vec(&x), y, "trial {trial}: A·x must equal y");
            }
        }
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
