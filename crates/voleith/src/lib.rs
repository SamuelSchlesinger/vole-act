//! VOLE-in-the-head zero-knowledge proofs.
//!
//! A non-interactive zero-knowledge proof system for Boolean/arithmetic
//! circuits over committed bits, in the style of FAEST / Baum et al.'s
//! VOLEitH with a generalized QuickSilver-style polynomial check:
//!
//! 1. τ GGM trees ([`vector-commit`](vector_commit)) commit pseudorandom
//!    seeds; all-but-one openings yield **VOLE correlations**
//!    `K_t = V_t + u_t·Δ` over `F₂^λ` ([`vole`]).
//! 2. Committed witness bits support free linear operations, quadratic systems,
//!    and χ-batched polynomial constraints through degree 16 ([`backend`]).
//! 3. Fiat–Shamir ([`transcript`]) makes the whole thing non-interactive;
//!    a coefficient-hash **consistency check** binds all τ repetitions to a
//!    single committed `u` ([`proof`] documents the exact flow).
//!
//! Circuits implement [`Circuit`] once and are executed by the prover,
//! verifier, and a counting backend, guaranteeing all parties agree on wire
//! ordering. See `docs/DESIGN.md` at the workspace root for the surrounding
//! ACT scheme.

pub mod backend;
pub mod bits;
pub mod proof;
pub mod transcript;
pub mod vole;

pub use backend::{Backend, Circuit, CountingBackend, ProverBackend, QuadTerm, VerifierBackend};
pub use proof::{MAX_PROOF_WIRE_BYTES, Proof, ProofDecodeError, prove, verify};
pub use vole::{PARAMS_128, PARAMS_128_BALANCED, PARAMS_128_FAST, Params};

/// Errors from proving or verifying.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VoleithError {
    /// The witness does not satisfy the circuit (prover-side).
    Unsatisfiable,
    /// The proof failed verification.
    InvalidProof,
    /// The witness length does not match the circuit's allocation order.
    WitnessMismatch,
    /// Parameters out of supported range.
    InvalidParameters,
}

impl core::fmt::Display for VoleithError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            VoleithError::Unsatisfiable => write!(f, "witness does not satisfy the circuit"),
            VoleithError::InvalidProof => write!(f, "proof verification failed"),
            VoleithError::WitnessMismatch => write!(f, "witness length mismatch"),
            VoleithError::InvalidParameters => write!(f, "invalid parameters"),
        }
    }
}

impl std::error::Error for VoleithError {}
