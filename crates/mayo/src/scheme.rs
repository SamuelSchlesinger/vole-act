//! TrapGen / Eval / SPre — the MAYO trapdoor function.

use crate::mat::{Mat, sample_solution};
use crate::params::MayoParams;
use binary_fields::{BinaryField, GF16};
use core::marker::PhantomData;
use rand_core::CryptoRngCore;

/// Errors from the MAYO algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MayoError {
    /// Preimage sampling failed repeatedly (astronomically unlikely with
    /// honest keys; indicates a corrupted secret key).
    PreimageSamplingFailed,
    /// An input had the wrong length.
    InvalidLength,
}

impl core::fmt::Display for MayoError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            MayoError::PreimageSamplingFailed => write!(f, "preimage sampling failed"),
            MayoError::InvalidLength => write!(f, "input has invalid length"),
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
        if top != GF16::ZERO {
            for &(d, coeff) in P::F_TAIL {
                out[d] += top * GF16::new(coeff);
            }
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
        let vinegar: Vec<Vec<GF16>> = (0..k)
            .map(|_| (0..v).map(|_| GF16::random(rng)).collect())
            .collect();
        let r: Vec<GF16> = (0..k * o).map(|_| GF16::random(rng)).collect();

        // M_i ∈ F^{m×o} with M_i[a,:] = v_iᵀ L_a.
        let m_mats: Vec<Mat> = (0..k)
            .map(|i| {
                let mut mi = Mat::zero(m, o);
                for a in 0..m {
                    let row = sk.l[a].vec_mul(&vinegar[i]);
                    for c in 0..o {
                        mi[(a, c)] = row[c];
                    }
                }
                mi
            })
            .collect();

        // Precompute w[a][j] = P1_a · v_j for the vinegar quadratic forms.
        let w: Vec<Vec<Vec<GF16>>> = (0..m)
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
                // Vinegar-only contribution, moved to the RHS.
                let mut u = vec![GF16::ZERO; m];
                for (a, u_a) in u.iter_mut().enumerate() {
                    *u_a = if i == j {
                        dot(&vinegar[i], &w[a][i])
                    } else {
                        dot(&vinegar[i], &w[a][j]) + dot(&vinegar[j], &w[a][i])
                    };
                }
                let shifted = mul_z_pow::<P>(&u, ell);
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

        let Some(x) = sample_solution(&a_mat, &y, &r) else {
            continue;
        };

        // Assemble s: s_i = (v_i + O·x_i) ‖ x_i.
        let mut s = vec![GF16::ZERO; P::KN];
        for i in 0..k {
            let x_i = &x[i * o..(i + 1) * o];
            let ox = sk.o.mul_vec(x_i);
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
        let column: Vec<GF16> = (0..m).map(|r| m_mat[(r, c)]).collect();
        let shifted = mul_z_pow::<P>(&column, ell);
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
}
