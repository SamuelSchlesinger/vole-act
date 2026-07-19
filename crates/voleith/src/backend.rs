//! Circuit backends: one generic circuit description, executed by the prover
//! (over values + tags), the verifier (over keys), and a counter (to size the
//! VOLE up front).
//!
//! A *wire* is a linearly-homomorphic commitment to an `F₂^λ` element. The
//! only committed inputs are witness **bits**; richer values (F₁₆ elements,
//! bytes, field elements) are formed as public linear combinations of bit
//! wires — which cost nothing. Constraints are:
//!
//! - `assert_mul(a, b, c)`: `a·b = c` (the QuickSilver degree-2 relation);
//! - `assert_zero(a)`: `a = 0` (a degree-1 relation, batched the same way).
//!
//! Prover-side wires carry `(value, tag)`; verifier-side wires carry the key.
//! The invariant `key = tag + value·Δ` is preserved by every operation, and
//! each constraint contributes one χ-weighted term to a single batched check.

use crate::VoleithError;
use binary_fields::{BinaryField, GF2p128, GF16, embed_gf16};

/// Build the 16-entry lookup table `nib ↦ φ·embed(nib)` for one fold
/// coefficient, so that folding a GF(16)-coefficient equation system costs
/// one table lookup + XOR per (term, equation) instead of a field multiply.
fn fold_table(phi: GF2p128) -> [GF2p128; 16] {
    core::array::from_fn(|nib| phi * embed_gf16(GF16::new(nib as u8)))
}

/// Fold per-term GF(16) coefficient vectors with the tables of all
/// equations: `c_t = Σ_e φ_e·embed(coeffs_t[e])`.
fn fold_coeff(tables: &[[GF2p128; 16]], coeffs: &[GF16]) -> GF2p128 {
    let mut acc = GF2p128::ZERO;
    for (table, &c) in tables.iter().zip(coeffs.iter()) {
        acc += table[c.to_u8() as usize];
    }
    acc
}

/// A circuit whose satisfiability is proven. Implementations must be
/// deterministic: both parties execute `build` and the sequence of
/// `witness_bit` / constraint calls must be identical.
pub trait Circuit {
    /// Build the circuit against a backend.
    fn build<B: Backend>(&self, backend: &mut B) -> Result<(), VoleithError>;
}

/// One product term of a quadratic system: contributes
/// `embed(coeffs[e])·a·b` to equation `e` of the system.
pub struct QuadTerm<W> {
    /// Left factor.
    pub a: W,
    /// Right factor.
    pub b: W,
    /// Per-equation GF(16) coefficients (`coeffs.len()` = number of
    /// equations in the system).
    pub coeffs: Vec<GF16>,
}

/// The interface circuits are written against.
pub trait Backend {
    /// A linearly-homomorphic commitment to an `F₂^λ` element.
    type Wire: Clone;

    /// Allocate the next witness bit.
    fn witness_bit(&mut self) -> Result<Self::Wire, VoleithError>;

    /// A public constant wire.
    fn constant(&mut self, c: GF2p128) -> Self::Wire;

    /// Wire addition (no communication).
    fn add(&mut self, a: &Self::Wire, b: &Self::Wire) -> Self::Wire;

    /// Multiplication by a public constant (no communication).
    fn scale(&mut self, c: GF2p128, a: &Self::Wire) -> Self::Wire;

    /// Constrain `a = 0`.
    fn assert_zero(&mut self, a: &Self::Wire);

    /// Constrain `a·b = c`.
    fn assert_mul(&mut self, a: &Self::Wire, b: &Self::Wire, c: &Self::Wire);

    /// Constrain a *system* of quadratic equations over shared product
    /// terms: for every equation `e < linear.len()`,
    ///
    /// ```text
    /// Σ_t embed(terms[t].coeffs[e]) · terms[t].a · terms[t].b + linear[e] = 0.
    /// ```
    ///
    /// The equations are folded into a single degree-2 check using
    /// verifier randomness sampled at challenge time (an unsatisfied
    /// equation survives the fold with probability 2^−λ). This is the
    /// economical way to express large multivariate-quadratic systems such
    /// as the MAYO verification equations, whose product terms are shared
    /// across all equations.
    ///
    /// Every `terms[t].coeffs` must have length `linear.len()`.
    fn assert_quad_system(&mut self, terms: Vec<QuadTerm<Self::Wire>>, linear: Vec<Self::Wire>);
}

/// Prover wire: the actual value and its VOLE tag.
#[derive(Clone, Debug)]
pub struct ProverWire {
    pub(crate) value: GF2p128,
    pub(crate) tag: GF2p128,
}

/// A recorded prover-side constraint.
pub enum ProverConstraint {
    /// A single degree-≤2 relation with QuickSilver coefficients
    /// `(A₀, A₁)`, satisfied exactly by the witness.
    Simple(GF2p128, GF2p128),
    /// A deferred quadratic system, folded with challenge randomness.
    System(ProverQuadSystem),
}

/// Prover-side stored quadratic system (values and tags of every term).
pub struct ProverQuadSystem {
    /// Per term: `(value_a, tag_a, value_b, tag_b, coeffs)`.
    terms: Vec<(GF2p128, GF2p128, GF2p128, GF2p128, Vec<GF16>)>,
    /// Per equation: `(value, tag)` of the linear wire.
    linear: Vec<(GF2p128, GF2p128)>,
}

impl ProverQuadSystem {
    /// Number of equations (fold coefficients to draw).
    #[must_use]
    pub fn num_equations(&self) -> usize {
        self.linear.len()
    }

    /// Fold the system with challenge coefficients `phis` into a single
    /// QuickSilver `(A₀, A₁)` pair; also returns whether the folded
    /// equation holds for the witness (false detects an unsatisfied system
    /// except with probability 2^−λ).
    #[must_use]
    pub fn fold(&self, phis: &[GF2p128]) -> (GF2p128, GF2p128, bool) {
        assert_eq!(phis.len(), self.linear.len());
        let tables: Vec<[GF2p128; 16]> = phis.iter().map(|&p| fold_table(p)).collect();
        let mut a0 = GF2p128::ZERO;
        let mut a1 = GF2p128::ZERO;
        let mut value = GF2p128::ZERO;
        for (va, ta, vb, tb, coeffs) in &self.terms {
            let c = fold_coeff(&tables, coeffs);
            a0 += c * (*ta * *tb);
            a1 += c * (*va * *tb + *vb * *ta);
            value += c * (*va * *vb);
        }
        for (phi, (vl, tl)) in phis.iter().zip(self.linear.iter()) {
            a1 += *phi * *tl;
            value += *phi * *vl;
        }
        (a0, a1, value == GF2p128::ZERO)
    }
}

/// Prover backend: consumes witness bits and VOLE correlations in order,
/// records the public bit corrections `d` and the per-constraint QuickSilver
/// data.
pub struct ProverBackend<'a> {
    witness: &'a [bool],
    u: &'a crate::bits::BitVec,
    tags: &'a [GF2p128],
    next: usize,
    /// Public corrections `d_t = u_t ⊕ w_t`, published in the proof.
    pub d: Vec<bool>,
    /// Recorded constraints, in emission order.
    pub constraints: Vec<ProverConstraint>,
    /// Whether every *simple* constraint holds for the provided witness
    /// (quadratic systems are checked at fold time).
    pub satisfied: bool,
}

impl<'a> ProverBackend<'a> {
    /// Create a prover backend over the witness bits and the first
    /// `witness.len()` VOLE coordinates.
    pub fn new(witness: &'a [bool], u: &'a crate::bits::BitVec, tags: &'a [GF2p128]) -> Self {
        ProverBackend {
            witness,
            u,
            tags,
            next: 0,
            d: Vec::with_capacity(witness.len()),
            constraints: Vec::new(),
            satisfied: true,
        }
    }

    /// Number of witness bits consumed.
    #[must_use]
    pub fn bits_used(&self) -> usize {
        self.next
    }
}

impl Backend for ProverBackend<'_> {
    type Wire = ProverWire;

    fn witness_bit(&mut self) -> Result<ProverWire, VoleithError> {
        let t = self.next;
        if t >= self.witness.len() {
            return Err(VoleithError::WitnessMismatch);
        }
        self.next += 1;
        let w = self.witness[t];
        self.d.push(self.u.get(t) ^ w);
        Ok(ProverWire {
            value: if w { GF2p128::ONE } else { GF2p128::ZERO },
            tag: self.tags[t],
        })
    }

    fn constant(&mut self, c: GF2p128) -> ProverWire {
        ProverWire {
            value: c,
            tag: GF2p128::ZERO,
        }
    }

    fn add(&mut self, a: &ProverWire, b: &ProverWire) -> ProverWire {
        ProverWire {
            value: a.value + b.value,
            tag: a.tag + b.tag,
        }
    }

    fn scale(&mut self, c: GF2p128, a: &ProverWire) -> ProverWire {
        ProverWire {
            value: c * a.value,
            tag: c * a.tag,
        }
    }

    fn assert_zero(&mut self, a: &ProverWire) {
        // Homogenize to degree 2 (as `a·1 = 0`) so the check is not a
        // tautology: verifier computes B = Δ·k_a = tag_a·Δ + value_a·Δ², so
        // (A₀, A₁) = (0, tag_a). A nonzero value leaves an unmatched Δ² term.
        self.constraints
            .push(ProverConstraint::Simple(GF2p128::ZERO, a.tag));
        if a.value != GF2p128::ZERO {
            self.satisfied = false;
        }
    }

    fn assert_mul(&mut self, a: &ProverWire, b: &ProverWire, c: &ProverWire) {
        // key_a·key_b + Δ·key_c
        //   = tag_a·tag_b + (a·tag_b + b·tag_a + tag_c)·Δ + (ab + c)·Δ².
        // For a satisfied constraint the Δ² coefficient vanishes.
        let a0 = a.tag * b.tag;
        let a1 = a.value * b.tag + b.value * a.tag + c.tag;
        self.constraints.push(ProverConstraint::Simple(a0, a1));
        if a.value * b.value != c.value {
            self.satisfied = false;
        }
    }

    fn assert_quad_system(&mut self, terms: Vec<QuadTerm<ProverWire>>, linear: Vec<ProverWire>) {
        let n_eqs = linear.len();
        let stored = terms
            .into_iter()
            .map(|t| {
                assert_eq!(t.coeffs.len(), n_eqs, "coefficient vector length");
                (t.a.value, t.a.tag, t.b.value, t.b.tag, t.coeffs)
            })
            .collect();
        self.constraints
            .push(ProverConstraint::System(ProverQuadSystem {
                terms: stored,
                linear: linear.into_iter().map(|w| (w.value, w.tag)).collect(),
            }));
    }
}

/// A recorded verifier-side constraint.
pub enum VerifierConstraint {
    /// A single check value `B = A₀ + A₁·Δ (+ error·Δ²)`.
    Simple(GF2p128),
    /// A deferred quadratic system over keys.
    System(VerifierQuadSystem),
}

/// Verifier-side stored quadratic system (keys of every term).
pub struct VerifierQuadSystem {
    /// Per term: `(key_a, key_b, coeffs)`.
    terms: Vec<(GF2p128, GF2p128, Vec<GF16>)>,
    /// Per equation: key of the linear wire.
    linear: Vec<GF2p128>,
}

impl VerifierQuadSystem {
    /// Number of equations (fold coefficients to draw).
    #[must_use]
    pub fn num_equations(&self) -> usize {
        self.linear.len()
    }

    /// Fold the system with challenge coefficients into its check value
    /// `B = Σ_t c_t·k_a·k_b + Δ·Σ_e φ_e·k_lin`.
    #[must_use]
    pub fn fold(&self, phis: &[GF2p128], delta: GF2p128) -> GF2p128 {
        assert_eq!(phis.len(), self.linear.len());
        let tables: Vec<[GF2p128; 16]> = phis.iter().map(|&p| fold_table(p)).collect();
        let mut b = GF2p128::ZERO;
        for (ka, kb, coeffs) in &self.terms {
            let c = fold_coeff(&tables, coeffs);
            b += c * (*ka * *kb);
        }
        let mut lin = GF2p128::ZERO;
        for (phi, kl) in phis.iter().zip(self.linear.iter()) {
            lin += *phi * *kl;
        }
        b + delta * lin
    }
}

/// Verifier backend: consumes witness keys in order and records the
/// per-constraint check data.
pub struct VerifierBackend<'a> {
    keys: &'a [GF2p128],
    delta: GF2p128,
    next: usize,
    /// Recorded constraints, in emission order.
    pub checks: Vec<VerifierConstraint>,
}

impl<'a> VerifierBackend<'a> {
    /// Create a verifier backend over the witness-stage keys (already
    /// adjusted by the public corrections `d`).
    pub fn new(keys: &'a [GF2p128], delta: GF2p128) -> Self {
        VerifierBackend {
            keys,
            delta,
            next: 0,
            checks: Vec::new(),
        }
    }

    /// Number of witness bits consumed.
    #[must_use]
    pub fn bits_used(&self) -> usize {
        self.next
    }
}

/// Verifier wire: the key.
#[derive(Clone, Debug)]
pub struct VerifierWire {
    key: GF2p128,
}

impl Backend for VerifierBackend<'_> {
    type Wire = VerifierWire;

    fn witness_bit(&mut self) -> Result<VerifierWire, VoleithError> {
        let t = self.next;
        if t >= self.keys.len() {
            return Err(VoleithError::WitnessMismatch);
        }
        self.next += 1;
        Ok(VerifierWire { key: self.keys[t] })
    }

    fn constant(&mut self, c: GF2p128) -> VerifierWire {
        VerifierWire {
            key: c * self.delta,
        }
    }

    fn add(&mut self, a: &VerifierWire, b: &VerifierWire) -> VerifierWire {
        VerifierWire { key: a.key + b.key }
    }

    fn scale(&mut self, c: GF2p128, a: &VerifierWire) -> VerifierWire {
        VerifierWire { key: c * a.key }
    }

    fn assert_zero(&mut self, a: &VerifierWire) {
        // Matches the prover's degree-2 homogenization: B = Δ·k_a.
        self.checks
            .push(VerifierConstraint::Simple(self.delta * a.key));
    }

    fn assert_mul(&mut self, a: &VerifierWire, b: &VerifierWire, c: &VerifierWire) {
        self.checks.push(VerifierConstraint::Simple(
            a.key * b.key + self.delta * c.key,
        ));
    }

    fn assert_quad_system(
        &mut self,
        terms: Vec<QuadTerm<VerifierWire>>,
        linear: Vec<VerifierWire>,
    ) {
        let n_eqs = linear.len();
        let stored = terms
            .into_iter()
            .map(|t| {
                assert_eq!(t.coeffs.len(), n_eqs, "coefficient vector length");
                (t.a.key, t.b.key, t.coeffs)
            })
            .collect();
        self.checks
            .push(VerifierConstraint::System(VerifierQuadSystem {
                terms: stored,
                linear: linear.into_iter().map(|w| w.key).collect(),
            }));
    }
}

/// Counting backend: sizes the circuit (witness bits, constraints) without
/// any cryptography.
#[derive(Default)]
pub struct CountingBackend {
    /// Number of witness bits allocated.
    pub witness_bits: usize,
    /// Number of constraints recorded.
    pub constraints: usize,
}

impl Backend for CountingBackend {
    type Wire = ();

    fn witness_bit(&mut self) -> Result<(), VoleithError> {
        self.witness_bits += 1;
        Ok(())
    }

    fn constant(&mut self, _c: GF2p128) {}

    fn add(&mut self, _a: &(), _b: &()) {}

    fn scale(&mut self, _c: GF2p128, _a: &()) {}

    fn assert_zero(&mut self, _a: &()) {
        self.constraints += 1;
    }

    fn assert_mul(&mut self, _a: &(), _b: &(), _c: &()) {
        self.constraints += 1;
    }

    fn assert_quad_system(&mut self, _terms: Vec<QuadTerm<()>>, _linear: Vec<()>) {
        self.constraints += 1;
    }
}
