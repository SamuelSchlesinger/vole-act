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
use zeroize::Zeroize;

/// Maximum polynomial degree accepted by proving and verification. Shared
/// with `proof.rs`, which rejects any circuit whose counted degree exceeds
/// it before either cryptographic backend runs.
pub(crate) const MAX_DEGREE: usize = 16;

/// Inline, fixed-capacity polynomial coefficient list (low-to-high order).
///
/// The circuit hot path creates millions of short coefficient vectors per
/// proof; keeping them inline (capacity `MAX_DEGREE + 1`, the largest size
/// `prove`/`verify` accept) removes per-expression heap allocation and lets
/// constraint zeroization run as one linear sweep.
#[derive(Clone, Copy, Debug)]
pub struct PolyCoeffs {
    len: u8,
    slots: [GF2p128; MAX_DEGREE + 1],
}

impl PolyCoeffs {
    const CAPACITY: usize = MAX_DEGREE + 1;

    fn zeroed(len: usize) -> Self {
        debug_assert!(len <= Self::CAPACITY);
        PolyCoeffs {
            len: len as u8,
            slots: [GF2p128::ZERO; Self::CAPACITY],
        }
    }

    /// The coefficients, low-to-high.
    #[must_use]
    pub fn as_slice(&self) -> &[GF2p128] {
        &self.slots[..self.len as usize]
    }

    /// Number of coefficients (degree + 1).
    #[must_use]
    pub fn len(&self) -> usize {
        self.len as usize
    }

    /// Whether the list is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl Zeroize for PolyCoeffs {
    fn zeroize(&mut self) {
        // Per-field volatile stores, matching the zeroize crate's guarantee.
        // (Measured: a whole-struct `zeroize_flat_type` wipe is *slower* here —
        // LLVM lowers large volatile aggregate writes poorly.)
        self.slots.zeroize();
        self.len.zeroize();
    }
}

/// Build the 16-entry lookup table `nib ↦ φ·embed(nib)` for one fold
/// coefficient, so that folding a GF(16)-coefficient equation system costs
/// one table lookup + XOR per (term, equation) instead of a field multiply.
fn fold_table(phi: GF2p128) -> [GF2p128; 16] {
    core::array::from_fn(|nib| phi * embed_gf16(GF16::new(nib as u8)))
}

/// Fold per-term GF(16) coefficient vectors with the tables of all
/// equations: `c_t = Σ_e φ_e·embed(coeffs_t[e])`.
///
/// Four independent accumulators break the serial XOR dependency chain so
/// the table loads pipeline; XOR is associative and commutative, so the
/// regrouped sum is bit-identical to the definitional left fold.
fn fold_coeff(tables: &[[GF2p128; 16]], coeffs: &[GF16]) -> GF2p128 {
    // Equal lengths are enforced when the system is stored; the chunked
    // walk below is only pairwise-equivalent to a plain zip under it.
    debug_assert_eq!(tables.len(), coeffs.len());
    let (table_chunks, table_rest) = tables.as_chunks::<4>();
    let (coeff_chunks, coeff_rest) = coeffs.as_chunks::<4>();
    let mut acc = [GF2p128::ZERO; 4];
    for (t4, c4) in table_chunks.iter().zip(coeff_chunks.iter()) {
        acc[0] += t4[0][c4[0].to_u8() as usize];
        acc[1] += t4[1][c4[1].to_u8() as usize];
        acc[2] += t4[2][c4[2].to_u8() as usize];
        acc[3] += t4[3][c4[3].to_u8() as usize];
    }
    for (table, &c) in table_rest.iter().zip(coeff_rest.iter()) {
        acc[0] += table[c.to_u8() as usize];
    }
    (acc[0] + acc[1]) + (acc[2] + acc[3])
}

/// A circuit whose satisfiability is proven. Implementations must be
/// deterministic: both parties execute `build` and the sequence of
/// `witness_bit` / constraint calls must be identical.
pub trait Circuit {
    /// Build the circuit against a backend.
    fn build<B: Backend>(&self, backend: &mut B) -> Result<(), VoleithError>;
}

/// Per-equation GF(16) coefficients of one quadratic term, viewed inside a
/// shared reference-counted buffer.
///
/// Coefficient tables are *public* data — expanded public-key material and
/// public selector constants — so one arena is shared by every term of a
/// system (and across proof runs) instead of allocating per term, and the
/// coefficients are deliberately excluded from constraint zeroization.
#[derive(Clone)]
pub struct SharedCoeffs {
    buf: std::sync::Arc<[GF16]>,
    start: usize,
    len: usize,
}

impl SharedCoeffs {
    /// View `buf[start..start + len]`; `None` when out of bounds.
    #[must_use]
    pub fn new(buf: std::sync::Arc<[GF16]>, start: usize, len: usize) -> Option<Self> {
        (start.checked_add(len)? <= buf.len()).then_some(SharedCoeffs { buf, start, len })
    }

    /// A whole-buffer view of an owned coefficient vector.
    #[must_use]
    pub fn from_vec(coeffs: Vec<GF16>) -> Self {
        let len = coeffs.len();
        SharedCoeffs {
            buf: coeffs.into(),
            start: 0,
            len,
        }
    }

    /// The coefficients.
    #[must_use]
    pub fn as_slice(&self) -> &[GF16] {
        &self.buf[self.start..self.start + self.len]
    }

    /// Number of coefficients.
    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether the view is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
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
    pub coeffs: SharedCoeffs,
}

/// The interface circuits are written against.
pub trait Backend {
    /// A linearly-homomorphic commitment to an `F₂^λ` element.
    type Wire: Clone;
    /// A bounded-degree polynomial expression in committed wires. Its leading
    /// coefficient is the value of the represented circuit expression.
    type Expr: Clone;

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

    /// Lift a degree-1 committed wire into the polynomial-expression layer.
    fn wire_expr(&mut self, wire: &Self::Wire) -> Self::Expr;

    /// Add two expressions, aligning their leading (value) coefficients.
    fn expr_add(&mut self, a: &Self::Expr, b: &Self::Expr) -> Self::Expr;

    /// Multiply two expressions. Degrees add.
    fn expr_mul(&mut self, a: &Self::Expr, b: &Self::Expr) -> Self::Expr;

    /// Assert that an expression's leading/value coefficient is zero.
    fn assert_expr_zero(&mut self, expression: &Self::Expr);
}

/// Prover wire: the actual value and its VOLE tag.
#[derive(Clone, Debug)]
pub struct ProverWire {
    pub(crate) value: GF2p128,
    pub(crate) tag: GF2p128,
}

/// A recorded prover-side constraint.
///
/// `Polynomial` dominates both the count (one per asserted circuit
/// expression) and the size; keeping its coefficients inline — rather than
/// boxed — is a deliberate trade of enum width for the removal of one heap
/// allocation, pointer chase, and separate zeroization per constraint.
#[allow(clippy::large_enum_variant)]
pub enum ProverConstraint {
    /// A single degree-≤2 relation with QuickSilver coefficients
    /// `(A₀, A₁)`, satisfied exactly by the witness.
    Simple(GF2p128, GF2p128),
    /// A deferred quadratic system, folded with challenge randomness.
    System(ProverQuadSystem),
    /// A fully materialized polynomial whose leading coefficient must vanish.
    Polynomial(PolyCoeffs),
}

impl Zeroize for ProverConstraint {
    fn zeroize(&mut self) {
        match self {
            ProverConstraint::Simple(a0, a1) => {
                a0.zeroize();
                a1.zeroize();
            }
            ProverConstraint::System(system) => system.zeroize(),
            ProverConstraint::Polynomial(coefficients) => coefficients.zeroize(),
        }
    }
}

/// Prover-side polynomial expression, coefficients in low-to-high order.
///
/// Stored inline (no heap allocation): the expression layer runs millions of
/// times per proof. Degrees above `MAX_DEGREE` are unsupported — `prove`
/// and `verify` reject such circuits via the counting pass before either
/// cryptographic backend runs.
#[derive(Clone, Copy, Debug)]
pub struct ProverExpr {
    coefficients: PolyCoeffs,
}

/// Prover-side stored quadratic system (values and tags of every term).
pub struct ProverQuadSystem {
    /// Per term: `(value_a, tag_a, value_b, tag_b, coeffs)`.
    terms: Vec<(GF2p128, GF2p128, GF2p128, GF2p128, SharedCoeffs)>,
    /// Per equation: `(value, tag)` of the linear wire.
    linear: Vec<(GF2p128, GF2p128)>,
}

impl Zeroize for ProverQuadSystem {
    fn zeroize(&mut self) {
        // The coefficient views are shared *public* data (public-key material
        // and public selectors) and are intentionally not wiped; the secret
        // witness values and VOLE tags are.
        for (value_a, tag_a, value_b, tag_b, _coeffs) in self.terms.iter_mut() {
            value_a.zeroize();
            tag_a.zeroize();
            value_b.zeroize();
            tag_b.zeroize();
        }
        for (value, tag) in self.linear.iter_mut() {
            value.zeroize();
            tag.zeroize();
        }
    }
}

impl ProverQuadSystem {
    /// Number of equations (fold coefficients to draw).
    #[must_use]
    pub fn num_equations(&self) -> usize {
        self.linear.len()
    }

    /// Fold the system with challenge coefficients `phis` into a single
    /// QuickSilver `(A₀, A₁)` pair; also returns whether the folded
    /// equation's leading/error coefficient (zero for a satisfied fold).
    #[must_use]
    pub fn fold(&self, phis: &[GF2p128]) -> (GF2p128, GF2p128, GF2p128) {
        assert_eq!(phis.len(), self.linear.len());
        let tables: Vec<[GF2p128; 16]> = phis.iter().map(|&p| fold_table(p)).collect();
        let mut a0 = GF2p128::ZERO;
        let mut a1 = GF2p128::ZERO;
        let mut value = GF2p128::ZERO;
        for (va, ta, vb, tb, coeffs) in &self.terms {
            let c = fold_coeff(&tables, coeffs.as_slice());
            a0 += c * (*ta * *tb);
            a1 += c * (*va * *tb + *vb * *ta);
            value += c * (*va * *vb);
        }
        for (phi, (vl, tl)) in phis.iter().zip(self.linear.iter()) {
            a1 += *phi * *tl;
            value += *phi * *vl;
        }
        (a0, a1, value)
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

impl Drop for ProverBackend<'_> {
    fn drop(&mut self) {
        // Recorded constraints hold raw witness values and VOLE tags (the
        // published QuickSilver coefficients are the χ-masked combinations,
        // not these). Wipe them on every exit path from the prover.
        self.constraints.zeroize();
    }
}

impl<'a> ProverBackend<'a> {
    /// Create a prover backend over the witness bits and the first
    /// `witness.len()` VOLE coordinates.
    ///
    /// `constraint_capacity` must be the constraint count reported by the
    /// [`CountingBackend`] pass over the same circuit. Reserving it up front
    /// guarantees the constraint vector never reallocates while it holds
    /// secrets: constraint coefficients are stored inline, so a growth
    /// reallocation would copy them into a new buffer and free the old one
    /// unwiped, out of reach of the drop-time zeroization.
    pub fn new(
        witness: &'a [bool],
        u: &'a crate::bits::BitVec,
        tags: &'a [GF2p128],
        constraint_capacity: usize,
    ) -> Self {
        ProverBackend {
            witness,
            u,
            tags,
            next: 0,
            d: Vec::with_capacity(witness.len()),
            constraints: Vec::with_capacity(constraint_capacity),
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
    type Expr = ProverExpr;

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

    fn wire_expr(&mut self, wire: &ProverWire) -> ProverExpr {
        let mut coefficients = PolyCoeffs::zeroed(2);
        coefficients.slots[0] = wire.tag;
        coefficients.slots[1] = wire.value;
        ProverExpr { coefficients }
    }

    fn expr_add(&mut self, a: &ProverExpr, b: &ProverExpr) -> ProverExpr {
        let len = a.coefficients.len().max(b.coefficients.len());
        let mut coefficients = PolyCoeffs::zeroed(len);
        let a_shift = len - a.coefficients.len();
        let b_shift = len - b.coefficients.len();
        for (index, coefficient) in a.coefficients.as_slice().iter().enumerate() {
            coefficients.slots[a_shift + index] += *coefficient;
        }
        for (index, coefficient) in b.coefficients.as_slice().iter().enumerate() {
            coefficients.slots[b_shift + index] += *coefficient;
        }
        ProverExpr { coefficients }
    }

    fn expr_mul(&mut self, a: &ProverExpr, b: &ProverExpr) -> ProverExpr {
        let len = a.coefficients.len() + b.coefficients.len() - 1;
        assert!(
            len <= PolyCoeffs::CAPACITY,
            "expression degree exceeds MAX_DEGREE ({MAX_DEGREE})"
        );
        let mut coefficients = PolyCoeffs::zeroed(len);
        for (i, left) in a.coefficients.as_slice().iter().enumerate() {
            for (j, right) in b.coefficients.as_slice().iter().enumerate() {
                coefficients.slots[i + j] += *left * *right;
            }
        }
        ProverExpr { coefficients }
    }

    fn assert_expr_zero(&mut self, expression: &ProverExpr) {
        if expression.coefficients.as_slice().last() != Some(&GF2p128::ZERO) {
            self.satisfied = false;
        }
        self.constraints
            .push(ProverConstraint::Polynomial(expression.coefficients));
    }
}

/// A recorded verifier-side constraint.
pub enum VerifierConstraint {
    /// A single check value `B = A₀ + A₁·Δ (+ error·Δ²)`.
    Simple(GF2p128),
    /// A deferred quadratic system over keys.
    System(VerifierQuadSystem),
    /// Evaluation at `Δ` together with the polynomial degree.
    Polynomial(GF2p128, usize),
}

/// Verifier-side stored quadratic system (keys of every term).
pub struct VerifierQuadSystem {
    /// Per term: `(key_a, key_b, coeffs)`.
    terms: Vec<(GF2p128, GF2p128, SharedCoeffs)>,
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
            let c = fold_coeff(&tables, coeffs.as_slice());
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
    /// `delta_pows[i] = Δ^i`, precomputed for the expression layer's degree
    /// alignments (a table lookup instead of a `pow` per operation).
    delta_pows: [GF2p128; MAX_DEGREE + 1],
    next: usize,
    /// Recorded constraints, in emission order.
    pub checks: Vec<VerifierConstraint>,
}

impl<'a> VerifierBackend<'a> {
    /// Create a verifier backend over the witness-stage keys (already
    /// adjusted by the public corrections `d`).
    pub fn new(keys: &'a [GF2p128], delta: GF2p128) -> Self {
        let mut delta_pows = [GF2p128::ONE; MAX_DEGREE + 1];
        for i in 1..delta_pows.len() {
            delta_pows[i] = delta_pows[i - 1] * delta;
        }
        VerifierBackend {
            keys,
            delta,
            delta_pows,
            next: 0,
            checks: Vec::new(),
        }
    }

    /// `Δ^exponent`; identical to `delta.pow(exponent)`, via the table for
    /// the in-range exponents the expression layer produces.
    fn delta_pow(&self, exponent: usize) -> GF2p128 {
        self.delta_pows
            .get(exponent)
            .copied()
            .unwrap_or_else(|| self.delta.pow(exponent as u128))
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

/// Verifier-side polynomial expression: only its evaluation at `Δ` and
/// its degree are needed.
#[derive(Clone, Debug)]
pub struct VerifierExpr {
    evaluation: GF2p128,
    degree: usize,
}

impl Backend for VerifierBackend<'_> {
    type Wire = VerifierWire;
    type Expr = VerifierExpr;

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

    fn wire_expr(&mut self, wire: &VerifierWire) -> VerifierExpr {
        VerifierExpr {
            evaluation: wire.key,
            degree: 1,
        }
    }

    fn expr_add(&mut self, a: &VerifierExpr, b: &VerifierExpr) -> VerifierExpr {
        let degree = a.degree.max(b.degree);
        VerifierExpr {
            evaluation: a.evaluation * self.delta_pow(degree - a.degree)
                + b.evaluation * self.delta_pow(degree - b.degree),
            degree,
        }
    }

    fn expr_mul(&mut self, a: &VerifierExpr, b: &VerifierExpr) -> VerifierExpr {
        VerifierExpr {
            evaluation: a.evaluation * b.evaluation,
            degree: a.degree + b.degree,
        }
    }

    fn assert_expr_zero(&mut self, expression: &VerifierExpr) {
        self.checks.push(VerifierConstraint::Polynomial(
            expression.evaluation,
            expression.degree,
        ));
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
    /// Maximum asserted polynomial degree.
    pub max_degree: usize,
    /// Maximum degree of any *constructed* expression, asserted or not.
    /// Proving and verification reject circuits whose built degree exceeds
    /// `MAX_DEGREE` before either cryptographic backend runs, so the
    /// inline-array expression storage can never overflow. This does not
    /// affect `max_degree` and therefore does not change VOLE sizing or the
    /// transcript of any accepted circuit.
    pub max_built_degree: usize,
}

impl Backend for CountingBackend {
    type Wire = ();
    type Expr = usize;

    fn witness_bit(&mut self) -> Result<(), VoleithError> {
        self.witness_bits += 1;
        Ok(())
    }

    fn constant(&mut self, _c: GF2p128) {}

    fn add(&mut self, _a: &(), _b: &()) {}

    fn scale(&mut self, _c: GF2p128, _a: &()) {}

    fn assert_zero(&mut self, _a: &()) {
        self.constraints += 1;
        self.max_degree = self.max_degree.max(2);
    }

    fn assert_mul(&mut self, _a: &(), _b: &(), _c: &()) {
        self.constraints += 1;
        self.max_degree = self.max_degree.max(2);
    }

    fn assert_quad_system(&mut self, _terms: Vec<QuadTerm<()>>, _linear: Vec<()>) {
        self.constraints += 1;
        self.max_degree = self.max_degree.max(2);
    }

    fn wire_expr(&mut self, _wire: &()) -> usize {
        1
    }

    fn expr_add(&mut self, a: &usize, b: &usize) -> usize {
        (*a).max(*b)
    }

    fn expr_mul(&mut self, a: &usize, b: &usize) -> usize {
        // Saturating: a runaway product chain must pin at the ceiling (and be
        // rejected by the built-degree check), never wrap back into range.
        let degree = a.saturating_add(*b);
        self.max_built_degree = self.max_built_degree.max(degree);
        degree
    }

    fn assert_expr_zero(&mut self, expression: &usize) {
        self.constraints += 1;
        self.max_degree = self.max_degree.max(*expression);
    }
}
