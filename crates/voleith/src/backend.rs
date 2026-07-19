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
use binary_fields::{BinaryField, GF2p128};

/// A circuit whose satisfiability is proven. Implementations must be
/// deterministic: both parties execute `build` and the sequence of
/// `witness_bit` / constraint calls must be identical.
pub trait Circuit {
    /// Build the circuit against a backend.
    fn build<B: Backend>(&self, backend: &mut B) -> Result<(), VoleithError>;
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
}

/// Prover wire: the actual value and its VOLE tag.
#[derive(Clone, Debug)]
pub struct ProverWire {
    pub(crate) value: GF2p128,
    pub(crate) tag: GF2p128,
}

/// Prover backend: consumes witness bits and VOLE correlations in order,
/// records the public bit corrections `d` and the per-constraint coefficient
/// pairs `(A₀, A₁)` of the QuickSilver polynomial `A₀ + A₁·Δ`.
pub struct ProverBackend<'a> {
    witness: &'a [bool],
    u: &'a crate::bits::BitVec,
    tags: &'a [GF2p128],
    next: usize,
    /// Public corrections `d_t = u_t ⊕ w_t`, published in the proof.
    pub d: Vec<bool>,
    /// Per-constraint `(A₀, A₁)` pairs.
    pub constraints: Vec<(GF2p128, GF2p128)>,
    /// Whether every constraint actually holds for the provided witness.
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
        // key_a = tag_a + value_a·Δ, so B = A₀ + A₁·Δ with A₀ = tag, A₁ = value.
        self.constraints.push((a.tag, a.value));
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
        self.constraints.push((a0, a1));
        if a.value * b.value != c.value {
            self.satisfied = false;
        }
    }
}

/// Verifier backend: consumes witness keys in order and records the
/// per-constraint check values `B = A₀ + A₁·Δ (+ error·Δ²)`.
pub struct VerifierBackend<'a> {
    keys: &'a [GF2p128],
    delta: GF2p128,
    next: usize,
    /// Per-constraint check values.
    pub checks: Vec<GF2p128>,
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
        self.checks.push(a.key);
    }

    fn assert_mul(&mut self, a: &VerifierWire, b: &VerifierWire, c: &VerifierWire) {
        self.checks.push(a.key * b.key + self.delta * c.key);
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
}
