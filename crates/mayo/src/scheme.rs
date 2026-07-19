//! TrapGen / Eval / SPre — the MAYO trapdoor function.

use crate::mat::{Mat, sample_solution};
use crate::params::MayoParams;
use binary_fields::{BinaryField, GF16};
use core::marker::PhantomData;
use rand_core::CryptoRngCore;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Errors from the MAYO algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MayoError {
    /// Preimage sampling failed repeatedly (astronomically unlikely with
    /// honest keys; indicates a corrupted secret key).
    PreimageSamplingFailed,
    /// An input had the wrong length.
    InvalidLength,
    /// A canonical expanded-key encoding was malformed, non-canonical, or
    /// carried a different MAYO parameter-set identifier.
    InvalidEncoding,
}

impl core::fmt::Display for MayoError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            MayoError::PreimageSamplingFailed => write!(f, "preimage sampling failed"),
            MayoError::InvalidLength => write!(f, "input has invalid length"),
            MayoError::InvalidEncoding => write!(f, "invalid MAYO key encoding"),
        }
    }
}

impl std::error::Error for MayoError {}

/// A MAYO public key: the matrices `{P⁽¹⁾_a, P⁽²⁾_a, P⁽³⁾_a}` describing the
/// quadratic map `P`.
pub struct PublicKey<P: MayoParams> {
    pub(crate) p1: Vec<Mat>,
    pub(crate) p2: Vec<Mat>,
    pub(crate) p3: Vec<Mat>,
    _params: PhantomData<P>,
}

/// A MAYO secret key: the oil-space matrix `O` plus the `{P⁽¹⁾_a}` and the
/// derived `{L_a}` needed for preimage sampling.
pub struct SecretKey<P: MayoParams> {
    o: Mat,
    p1: Vec<Mat>,
    l: Vec<Mat>,
    _params: PhantomData<P>,
}

impl<P: MayoParams> Drop for SecretKey<P> {
    fn drop(&mut self) {
        self.o.zeroize();
        self.p1.zeroize();
        self.l.zeroize();
    }
}

impl<P: MayoParams> ZeroizeOnDrop for SecretKey<P> {}

const PUBLIC_KEY_MAGIC: &[u8; 5] = b"MYPK\x01";
const SECRET_KEY_MAGIC: &[u8; 5] = b"MYSK\x01";

fn push_nibble(out: &mut Vec<u8>, index: usize, value: GF16) {
    if index.is_multiple_of(2) {
        out.push(value.to_u8());
    } else {
        *out.last_mut().expect("odd nibble has preceding byte") |= value.to_u8() << 4;
    }
}

fn append_matrix(out: &mut Vec<u8>, nibble_index: &mut usize, matrix: &Mat, upper: bool) {
    for row in 0..matrix.rows() {
        let start = if upper { row } else { 0 };
        for column in start..matrix.cols() {
            push_nibble(out, *nibble_index, matrix[(row, column)]);
            *nibble_index += 1;
        }
    }
}

struct NibbleReader<'a> {
    bytes: &'a [u8],
    count: usize,
    next: usize,
}

impl<'a> NibbleReader<'a> {
    fn new(bytes: &'a [u8], count: usize) -> Result<Self, MayoError> {
        let expected = count.checked_add(1).ok_or(MayoError::InvalidEncoding)? / 2;
        if bytes.len() != expected
            || (count % 2 == 1 && bytes.last().is_some_and(|b| b & 0xf0 != 0))
        {
            return Err(MayoError::InvalidEncoding);
        }
        Ok(Self {
            bytes,
            count,
            next: 0,
        })
    }

    fn nibble(&mut self) -> Result<GF16, MayoError> {
        if self.next >= self.count {
            return Err(MayoError::InvalidEncoding);
        }
        let byte = self.bytes[self.next / 2];
        let value = if self.next.is_multiple_of(2) {
            byte & 0x0f
        } else {
            byte >> 4
        };
        self.next += 1;
        Ok(GF16::new(value))
    }

    fn matrix(&mut self, rows: usize, cols: usize, upper: bool) -> Result<Mat, MayoError> {
        let len = rows.checked_mul(cols).ok_or(MayoError::InvalidEncoding)?;
        // Wrap the staging buffer so partially decoded (possibly secret-key)
        // nibbles are wiped even when a later `nibble()` call fails.
        let mut data = Zeroizing::new(vec![GF16::ZERO; len]);
        for row in 0..rows {
            let start = if upper { row } else { 0 };
            for column in start..cols {
                data[row * cols + column] = self.nibble()?;
            }
        }
        Mat::from_data(rows, cols, data.to_vec()).ok_or(MayoError::InvalidEncoding)
    }

    fn finish(self) -> Result<(), MayoError> {
        (self.next == self.count)
            .then_some(())
            .ok_or(MayoError::InvalidEncoding)
    }
}

const fn upper_entries(dimension: usize) -> usize {
    dimension * (dimension + 1) / 2
}

/// Key generation (spec Algorithm 4, math level).
///
/// Samples the oil matrix `O` and the random public matrices, then derives
/// `P⁽³⁾_a = Upper(Oᵀ P⁽¹⁾_a O + Oᵀ P⁽²⁾_a)` (so that `P` vanishes on the oil
/// space) and `L_a = (P⁽¹⁾_a + P⁽¹⁾_aᵀ)O + P⁽²⁾_a`.
pub fn trapgen<P: MayoParams>(rng: &mut impl CryptoRngCore) -> (SecretKey<P>, PublicKey<P>) {
    let v = P::V;
    let o_mat = Mat::random(v, P::O, rng);
    let ot = o_mat.transpose();

    let mut p1 = Vec::with_capacity(P::M);
    let mut p2 = Vec::with_capacity(P::M);
    let mut p3 = Vec::with_capacity(P::M);
    let mut l = Vec::with_capacity(P::M);
    for _ in 0..P::M {
        let p1_a = Mat::random_upper(v, rng);
        let p2_a = Mat::random(v, P::O, rng);
        // P3_a = Upper(O^T P1_a O + O^T P2_a)  (char 2: − = +).
        let p3_a = ot.mul(&p1_a.mul(&o_mat)).add(&ot.mul(&p2_a)).upper();
        // L_a = (P1_a + P1_a^T) O + P2_a.
        let l_a = p1_a.add(&p1_a.transpose()).mul(&o_mat).add(&p2_a);
        p1.push(p1_a);
        p2.push(p2_a);
        p3.push(p3_a);
        l.push(l_a);
    }

    (
        SecretKey {
            o: o_mat,
            p1: p1.clone(),
            l,
            _params: PhantomData,
        },
        PublicKey {
            p1,
            p2,
            p3,
            _params: PhantomData,
        },
    )
}

impl<P: MayoParams> PublicKey<P> {
    /// Encode the expanded public quadratic map canonically.
    ///
    /// This is a stable, versioned mathematical-key format. It deliberately
    /// does not claim interoperability with MAYO's seed-compressed signature
    /// API: VOLE-ACT consumes the expanded trapdoor map directly.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let nibble_count = P::M * (upper_entries(P::V) + P::V * P::O + upper_entries(P::O));
        let mut body = Vec::with_capacity(nibble_count.div_ceil(2));
        let mut index = 0;
        for equation in 0..P::M {
            append_matrix(&mut body, &mut index, &self.p1[equation], true);
            append_matrix(&mut body, &mut index, &self.p2[equation], false);
            append_matrix(&mut body, &mut index, &self.p3[equation], true);
        }
        debug_assert_eq!(index, nibble_count);
        let mut out = Vec::with_capacity(PUBLIC_KEY_MAGIC.len() + 1 + body.len());
        out.extend_from_slice(PUBLIC_KEY_MAGIC);
        out.push(P::WIRE_ID);
        out.extend_from_slice(&body);
        body.zeroize();
        out
    }

    /// Decode a canonical expanded public quadratic map.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, MayoError> {
        if bytes.len() < PUBLIC_KEY_MAGIC.len() + 1
            || &bytes[..PUBLIC_KEY_MAGIC.len()] != PUBLIC_KEY_MAGIC
            || bytes[PUBLIC_KEY_MAGIC.len()] != P::WIRE_ID
        {
            return Err(MayoError::InvalidEncoding);
        }
        let nibble_count = P::M
            .checked_mul(
                upper_entries(P::V)
                    .checked_add(P::V * P::O)
                    .and_then(|n| n.checked_add(upper_entries(P::O)))
                    .ok_or(MayoError::InvalidEncoding)?,
            )
            .ok_or(MayoError::InvalidEncoding)?;
        let mut reader = NibbleReader::new(&bytes[PUBLIC_KEY_MAGIC.len() + 1..], nibble_count)?;
        let mut p1 = Vec::with_capacity(P::M);
        let mut p2 = Vec::with_capacity(P::M);
        let mut p3 = Vec::with_capacity(P::M);
        for _ in 0..P::M {
            p1.push(reader.matrix(P::V, P::V, true)?);
            p2.push(reader.matrix(P::V, P::O, false)?);
            p3.push(reader.matrix(P::O, P::O, true)?);
        }
        reader.finish()?;
        Ok(Self {
            p1,
            p2,
            p3,
            _params: PhantomData,
        })
    }
}

impl<P: MayoParams> SecretKey<P> {
    /// Reconstruct the public map determined by this expanded trapdoor.
    ///
    /// Storing only `(O, P1, L)` prevents a serialized issuer key from
    /// carrying a mismatched public key. In characteristic two,
    /// `P2 = L + (P1 + P1^T) O`; `P3` then follows from the MAYO key relation.
    #[must_use]
    pub fn public_key(&self) -> PublicKey<P> {
        let ot = self.o.transpose();
        let mut p2 = Vec::with_capacity(P::M);
        let mut p3 = Vec::with_capacity(P::M);
        for equation in 0..P::M {
            let symmetric_o = self.p1[equation]
                .add(&self.p1[equation].transpose())
                .mul(&self.o);
            let p2_equation = self.l[equation].add(&symmetric_o);
            let p3_equation = ot
                .mul(&self.p1[equation].mul(&self.o))
                .add(&ot.mul(&p2_equation))
                .upper();
            p2.push(p2_equation);
            p3.push(p3_equation);
        }
        PublicKey {
            p1: self.p1.clone(),
            p2,
            p3,
            _params: PhantomData,
        }
    }

    /// Encode the expanded issuer trapdoor canonically.
    ///
    /// The returned bytes are secret key material and must be protected at
    /// rest. The format stores `(O, P1, L)` and derives the public map during
    /// decoding, so no attacker-controlled public/secret mismatch is possible.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let nibble_count = P::V * P::O + P::M * (upper_entries(P::V) + P::V * P::O);
        let mut body = Vec::with_capacity(nibble_count.div_ceil(2));
        let mut index = 0;
        append_matrix(&mut body, &mut index, &self.o, false);
        for equation in 0..P::M {
            append_matrix(&mut body, &mut index, &self.p1[equation], true);
            append_matrix(&mut body, &mut index, &self.l[equation], false);
        }
        debug_assert_eq!(index, nibble_count);
        let mut out = Vec::with_capacity(SECRET_KEY_MAGIC.len() + 1 + body.len());
        out.extend_from_slice(SECRET_KEY_MAGIC);
        out.push(P::WIRE_ID);
        out.extend_from_slice(&body);
        body.zeroize();
        out
    }

    /// Decode a canonical expanded issuer trapdoor.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, MayoError> {
        if bytes.len() < SECRET_KEY_MAGIC.len() + 1
            || &bytes[..SECRET_KEY_MAGIC.len()] != SECRET_KEY_MAGIC
            || bytes[SECRET_KEY_MAGIC.len()] != P::WIRE_ID
        {
            return Err(MayoError::InvalidEncoding);
        }
        let per_equation = upper_entries(P::V)
            .checked_add(P::V * P::O)
            .ok_or(MayoError::InvalidEncoding)?;
        let nibble_count = (P::V * P::O)
            .checked_add(
                P::M.checked_mul(per_equation)
                    .ok_or(MayoError::InvalidEncoding)?,
            )
            .ok_or(MayoError::InvalidEncoding)?;
        let mut reader = NibbleReader::new(&bytes[SECRET_KEY_MAGIC.len() + 1..], nibble_count)?;
        let o = reader.matrix(P::V, P::O, false)?;
        let mut p1 = Vec::with_capacity(P::M);
        let mut l = Vec::with_capacity(P::M);
        for _ in 0..P::M {
            p1.push(reader.matrix(P::V, P::V, true)?);
            l.push(reader.matrix(P::V, P::O, false)?);
        }
        reader.finish()?;
        Ok(Self {
            o,
            p1,
            l,
            _params: PhantomData,
        })
    }
}

/// Multiply an `F₁₆^M`-vector (viewed as a polynomial in `F₁₆[z]/f(z)`) by
/// `z^shift` — the `E^ℓ` matrix action of the spec.
fn mul_z_pow<P: MayoParams>(u: &[GF16], shift: usize) -> Vec<GF16> {
    let m = P::M;
    let mut out = u.to_vec();
    for _ in 0..shift {
        let top = out[m - 1];
        // Shift up: z·(Σ c_i z^i); z^m ≡ tail(z) mod f.
        for i in (1..m).rev() {
            out[i] = out[i - 1];
        }
        out[0] = GF16::ZERO;
        for &(d, coeff) in P::F_TAIL {
            out[d] += top * GF16::new(coeff);
        }
    }
    out
}

/// Evaluate the whipped map `P*(s)` for `s ∈ F₁₆^{K·N}` (spec Algorithm 8,
/// lines 20–26). MAYO verification is `eval(pk, s) == t`.
pub fn eval<P: MayoParams>(pk: &PublicKey<P>, s: &[GF16]) -> Result<Vec<GF16>, MayoError> {
    if s.len() != P::KN {
        return Err(MayoError::InvalidLength);
    }
    let (n, v, k, m) = (P::N, P::V, P::K, P::M);
    let blocks: Vec<&[GF16]> = (0..k).map(|i| &s[i * n..(i + 1) * n]).collect();

    // Precompute w[a][j] = (P1_a P2_a; 0 P3_a) · s_j, blockwise.
    let w: Vec<Vec<Vec<GF16>>> = (0..m)
        .map(|a| {
            blocks
                .iter()
                .map(|s_j| {
                    let (s_v, s_o) = s_j.split_at(v);
                    let mut top = pk.p1[a].mul_vec(s_v);
                    let top2 = pk.p2[a].mul_vec(s_o);
                    for (x, y) in top.iter_mut().zip(top2.iter()) {
                        *x += *y;
                    }
                    top.extend(pk.p3[a].mul_vec(s_o));
                    top
                })
                .collect()
        })
        .collect();

    let dot = |x: &[GF16], y: &[GF16]| {
        x.iter()
            .zip(y.iter())
            .fold(GF16::ZERO, |acc, (a, b)| acc + *a * *b)
    };

    let mut y = vec![GF16::ZERO; m];
    let mut ell = 0;
    for i in 0..k {
        for j in (i..k).rev() {
            let mut u = vec![GF16::ZERO; m];
            for (a, u_a) in u.iter_mut().enumerate() {
                *u_a = if i == j {
                    dot(blocks[i], &w[a][i])
                } else {
                    dot(blocks[i], &w[a][j]) + dot(blocks[j], &w[a][i])
                };
            }
            let shifted = mul_z_pow::<P>(&u, ell);
            for (y_b, u_b) in y.iter_mut().zip(shifted.iter()) {
                *y_b += *u_b;
            }
            ell += 1;
        }
    }
    Ok(y)
}

impl<P: MayoParams> PublicKey<P> {
    /// The full `n × n` matrix `M_b = ((P1_b, P2_b), (0, P3_b))` for
    /// equation `b`, whose quadratic form is the base map: `s_i^T M_b s_i`.
    fn full_matrix(&self, b: usize) -> Mat {
        let (n, v, o) = (P::N, P::V, P::O);
        let mut m = Mat::zero(n, n);
        for r in 0..v {
            for c in 0..v {
                m[(r, c)] = self.p1[b][(r, c)];
            }
            for c in 0..o {
                m[(r, v + c)] = self.p2[b][(r, c)];
            }
        }
        for r in 0..o {
            for c in 0..o {
                m[(v + r, v + c)] = self.p3[b][(r, c)];
            }
        }
        m
    }

    /// The `m` whipped quadratic forms `G_a ∈ F₁₆^{kn×kn}` (upper triangular)
    /// with `eval(pk, s)_a = sᵀ G_a s` — the representation the VOLE-ACT
    /// circuit proves against.
    ///
    /// Cost is `O(m·(kn)²)` space; intended for the smaller parameter sets
    /// (e.g. MAYO₂, `kn = 324`). Larger sets want a structured, non-
    /// materialized QuickSilver check (a documented future optimization).
    #[must_use]
    pub fn whipped_forms(&self) -> Vec<Mat> {
        let (n, k, m, kn) = (P::N, P::K, P::M, P::KN);
        // E^ℓ as an m×m matrix: column b is z^ℓ · z^b reduced mod f.
        let e_pow = |ell: usize| -> Vec<Vec<GF16>> {
            (0..m)
                .map(|b| {
                    let mut unit = vec![GF16::ZERO; m];
                    unit[b] = GF16::ONE;
                    mul_z_pow::<P>(&unit, ell)
                })
                .collect()
        };
        let full: Vec<Mat> = (0..m).map(|b| self.full_matrix(b)).collect();
        // Symmetrized copies `Mb + Mbᵀ`, so every block placement below is a
        // row-contiguous scalar-multiply-accumulate over packed lanes. The
        // symmetric matrix has a zero diagonal (characteristic 2), so the
        // diagonal-block case takes its diagonal from `Mb` directly.
        let sym: Vec<Mat> = full.iter().map(|mb| mb.add(&mb.transpose())).collect();

        let mut g = vec![Mat::zero(kn, kn); m];
        let mut ell = 0;
        for i in 0..k {
            for j in (i..k).rev() {
                let e_cols = e_pow(ell); // e_cols[b][a] = [E^ℓ]_{a,b}
                for b in 0..m {
                    let (mb, sym_b) = (&full[b], &sym[b]);
                    // Base placement: block (i,j) of the kn×kn form.
                    let (ri0, cj0) = (i * n, j * n);
                    for a in 0..m {
                        let coeff = e_cols[b][a];
                        if coeff == GF16::ZERO {
                            continue;
                        }
                        let ga = &mut g[a];
                        if i == j {
                            // sᵢᵀ Mb sᵢ → place Upper(coeff·Mb) on the diagonal
                            // block: strict upper part from `sym`, diagonal
                            // from `Mb`.
                            for r in 0..n {
                                let ga_row = ga.row_mut(ri0 + r);
                                ga_row[ri0 + r] += coeff * mb[(r, r)];
                                crate::mat::packed_axpy(
                                    &mut ga_row[ri0 + r + 1..ri0 + n],
                                    coeff,
                                    &sym_b.row(r)[r + 1..n],
                                );
                            }
                        } else {
                            // sᵢᵀ Mb sⱼ + sⱼᵀ Mb sᵢ = sᵢᵀ(Mb+Mbᵀ)sⱼ → off-diagonal
                            // block (i<j, so already upper-triangular).
                            for r in 0..n {
                                crate::mat::packed_axpy(
                                    &mut ga.row_mut(ri0 + r)[cj0..cj0 + n],
                                    coeff,
                                    sym_b.row(r),
                                );
                            }
                        }
                    }
                }
                ell += 1;
            }
        }
        g
    }
}

/// Sample a preimage `s` with `P*(s) = t` using the oil-space trapdoor
/// (spec Algorithm 7, lines 13–45, with RNG-supplied randomness instead of
/// seed-derived counters).
pub fn spre<P: MayoParams>(
    sk: &SecretKey<P>,
    t: &[GF16],
    rng: &mut impl CryptoRngCore,
) -> Result<Vec<GF16>, MayoError> {
    if t.len() != P::M {
        return Err(MayoError::InvalidLength);
    }
    let (n, v, o, k, m) = (P::N, P::V, P::O, P::K, P::M);

    for _attempt in 0..256 {
        // Fresh vinegar values and system randomness.
        let mut vinegar: Vec<Vec<GF16>> = (0..k)
            .map(|_| (0..v).map(|_| GF16::random(rng)).collect())
            .collect();
        let mut r: Vec<GF16> = (0..k * o).map(|_| GF16::random(rng)).collect();

        // M_i ∈ F^{m×o} with M_i[a,:] = v_iᵀ L_a. The row temporaries are
        // vinegar-dependent secrets and must not linger in freed heap memory.
        let mut m_mats: Vec<Mat> = (0..k)
            .map(|i| {
                let mut mi = Mat::zero(m, o);
                for a in 0..m {
                    let row = Zeroizing::new(sk.l[a].vec_mul(&vinegar[i]));
                    for c in 0..o {
                        mi[(a, c)] = row[c];
                    }
                }
                mi
            })
            .collect();

        // Precompute w[a][j] = P1_a · v_j for the vinegar quadratic forms.
        let mut w: Vec<Vec<Vec<GF16>>> = (0..m)
            .map(|a| (0..k).map(|j| sk.p1[a].mul_vec(&vinegar[j])).collect())
            .collect();
        let dot = |x: &[GF16], y: &[GF16]| {
            x.iter()
                .zip(y.iter())
                .fold(GF16::ZERO, |acc, (a, b)| acc + *a * *b)
        };

        // Build the linear system A·x = y.
        let mut a_mat = Mat::zero(m, k * o);
        let mut y: Vec<GF16> = t.to_vec();
        let mut ell = 0;
        for i in 0..k {
            for j in (i..k).rev() {
                // Vinegar-only contribution, moved to the RHS. Both the raw
                // and shifted vinegar quadratic values are secrets.
                let mut u = Zeroizing::new(vec![GF16::ZERO; m]);
                for (a, u_a) in u.iter_mut().enumerate() {
                    *u_a = if i == j {
                        dot(&vinegar[i], &w[a][i])
                    } else {
                        dot(&vinegar[i], &w[a][j]) + dot(&vinegar[j], &w[a][i])
                    };
                }
                let shifted = Zeroizing::new(mul_z_pow::<P>(&u, ell));
                for (y_b, u_b) in y.iter_mut().zip(shifted.iter()) {
                    *y_b += *u_b;
                }

                // Linear-in-oil contribution: A gains E^ℓ·M blocks.
                add_shifted_block::<P>(&mut a_mat, &m_mats[j], i * o, ell);
                if i != j {
                    add_shifted_block::<P>(&mut a_mat, &m_mats[i], j * o, ell);
                }
                ell += 1;
            }
        }

        let Some(mut x) = sample_solution(&a_mat, &y, &r) else {
            vinegar.zeroize();
            r.zeroize();
            m_mats.zeroize();
            w.zeroize();
            a_mat.zeroize();
            y.zeroize();
            continue;
        };

        // Assemble s: s_i = (v_i + O·x_i) ‖ x_i. `O·x_i` must be wiped:
        // the oil block x_i is public in the emitted preimage, so a freed
        // heap copy of `O·x_i` would yield linear equations on `O` itself.
        let mut s = vec![GF16::ZERO; P::KN];
        for i in 0..k {
            let x_i = &x[i * o..(i + 1) * o];
            let ox = Zeroizing::new(sk.o.mul_vec(x_i));
            for (idx, val) in vinegar[i]
                .iter()
                .zip(ox.iter())
                .map(|(a, b)| *a + *b)
                .enumerate()
            {
                s[i * n + idx] = val;
            }
            for (idx, val) in x_i.iter().enumerate() {
                s[i * n + v + idx] = *val;
            }
        }
        vinegar.zeroize();
        r.zeroize();
        m_mats.zeroize();
        w.zeroize();
        a_mat.zeroize();
        y.zeroize();
        x.zeroize();
        return Ok(s);
    }
    Err(MayoError::PreimageSamplingFailed)
}

/// `A[:, col..col+o] += E^ℓ · M` — shift each column of `M` (an `F₁₆^m`
/// polynomial) by `z^ℓ` and add it into the block of `A` starting at `col`.
fn add_shifted_block<P: MayoParams>(a: &mut Mat, m_mat: &Mat, col: usize, ell: usize) {
    let m = P::M;
    let o = P::O;
    for c in 0..o {
        // Columns of the secret system matrix; wipe both staging buffers.
        let column = Zeroizing::new((0..m).map(|r| m_mat[(r, c)]).collect::<Vec<GF16>>());
        let shifted = Zeroizing::new(mul_z_pow::<P>(&column, ell));
        for (r, val) in shifted.iter().enumerate() {
            a[(r, col + c)] += *val;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::{Mayo1, Mayo2};
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    fn random_target<P: MayoParams>(rng: &mut impl CryptoRngCore) -> Vec<GF16> {
        (0..P::M).map(|_| GF16::random(rng)).collect()
    }

    fn preimage_roundtrip<P: MayoParams>(seed: u64, iterations: usize) {
        let mut rng = StdRng::seed_from_u64(seed);
        let (sk, pk) = trapgen::<P>(&mut rng);
        for i in 0..iterations {
            let t = random_target::<P>(&mut rng);
            let s = spre(&sk, &t, &mut rng).expect("preimage sampling");
            assert_eq!(s.len(), P::KN);
            let evaluated = eval(&pk, &s).expect("eval");
            assert_eq!(evaluated, t, "{} iteration {i}: P*(s) != t", P::NAME);
        }
    }

    #[test]
    fn mayo1_preimage_roundtrip() {
        preimage_roundtrip::<Mayo1>(11, 3);
    }

    #[test]
    fn mayo2_preimage_roundtrip() {
        preimage_roundtrip::<Mayo2>(12, 3);
    }

    #[test]
    fn oil_space_vanishes() {
        // P* evaluates to zero on the whipped oil space
        // {(O·x₁‖x₁, …, O·x_k‖x_k)} — the defining trapdoor property.
        let mut rng = StdRng::seed_from_u64(13);
        let (sk, pk) = trapgen::<Mayo1>(&mut rng);
        let (n, v, o, k) = (Mayo1::N, Mayo1::V, Mayo1::O, Mayo1::K);
        let mut s = vec![GF16::ZERO; Mayo1::KN];
        for i in 0..k {
            let x_i: Vec<GF16> = (0..o).map(|_| GF16::random(&mut rng)).collect();
            let ox = sk.o.mul_vec(&x_i);
            for (idx, val) in ox.iter().enumerate() {
                s[i * n + idx] = *val;
            }
            for (idx, val) in x_i.iter().enumerate() {
                s[i * n + v + idx] = *val;
            }
        }
        let y = eval(&pk, &s).unwrap();
        assert!(
            y.iter().all(|c| *c == GF16::ZERO),
            "P* must vanish on the whipped oil space"
        );
    }

    #[test]
    fn tampered_signature_rejected() {
        let mut rng = StdRng::seed_from_u64(14);
        let (sk, pk) = trapgen::<Mayo1>(&mut rng);
        let t = random_target::<Mayo1>(&mut rng);
        let mut s = spre(&sk, &t, &mut rng).unwrap();
        s[7] += GF16::ONE;
        assert_ne!(eval(&pk, &s).unwrap(), t);
    }

    fn whipped_forms_match_eval<P: MayoParams>(seed: u64) {
        let mut rng = StdRng::seed_from_u64(seed);
        let (_sk, pk) = trapgen::<P>(&mut rng);
        let forms = pk.whipped_forms();
        assert_eq!(forms.len(), P::M);
        for _ in 0..3 {
            let s: Vec<GF16> = (0..P::KN).map(|_| GF16::random(&mut rng)).collect();
            let evaluated = eval(&pk, &s).unwrap();
            for (a, g_a) in forms.iter().enumerate() {
                assert_eq!(
                    g_a.quad_form(&s),
                    evaluated[a],
                    "{} equation {a}: sᵀG_a s != eval_a",
                    P::NAME
                );
            }
        }
    }

    #[test]
    fn whipped_forms_match_eval_mayo2() {
        whipped_forms_match_eval::<Mayo2>(30);
    }

    #[test]
    fn whipped_forms_match_eval_mayo1() {
        whipped_forms_match_eval::<Mayo1>(31);
    }

    #[test]
    fn eval_rejects_wrong_lengths() {
        let mut rng = StdRng::seed_from_u64(15);
        let (sk, pk) = trapgen::<Mayo1>(&mut rng);
        assert_eq!(
            eval(&pk, &[GF16::ZERO; 5]).unwrap_err(),
            MayoError::InvalidLength
        );
        assert_eq!(
            spre(&sk, &[GF16::ZERO; 5], &mut rng).unwrap_err(),
            MayoError::InvalidLength
        );
    }

    #[test]
    fn expanded_key_codecs_are_canonical_and_consistent() {
        let mut rng = StdRng::seed_from_u64(0xC0DE_CAFE);
        let (secret, public) = trapgen::<Mayo2>(&mut rng);

        let public_bytes = public.to_bytes();
        let decoded_public = PublicKey::<Mayo2>::from_bytes(&public_bytes).unwrap();
        assert_eq!(decoded_public.to_bytes(), public_bytes);

        let secret_bytes = secret.to_bytes();
        let decoded_secret = SecretKey::<Mayo2>::from_bytes(&secret_bytes).unwrap();
        assert_eq!(decoded_secret.to_bytes(), secret_bytes);
        let derived_public = decoded_secret.public_key();
        assert_eq!(derived_public.to_bytes(), public_bytes);

        let target = random_target::<Mayo2>(&mut rng);
        let preimage = spre(&decoded_secret, &target, &mut rng).unwrap();
        assert_eq!(eval(&derived_public, &preimage).unwrap(), target);

        for encoded in [&public_bytes, &secret_bytes] {
            let mut trailing = encoded.clone();
            trailing.push(0);
            if encoded.starts_with(PUBLIC_KEY_MAGIC) {
                assert_eq!(
                    PublicKey::<Mayo2>::from_bytes(&trailing).err(),
                    Some(MayoError::InvalidEncoding)
                );
            } else {
                assert_eq!(
                    SecretKey::<Mayo2>::from_bytes(&trailing).err(),
                    Some(MayoError::InvalidEncoding)
                );
            }
        }

        let mut wrong_parameter = public_bytes;
        wrong_parameter[PUBLIC_KEY_MAGIC.len()] = Mayo1::WIRE_ID;
        assert_eq!(
            PublicKey::<Mayo2>::from_bytes(&wrong_parameter).err(),
            Some(MayoError::InvalidEncoding)
        );
    }
}
