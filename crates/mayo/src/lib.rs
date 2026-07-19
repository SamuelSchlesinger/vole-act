//! The MAYO trapdoor function over GF(16).
//!
//! MAYO (Beullens; a NIST additional-signature candidate, with this crate
//! pinned to its round-2 specification) is a "whipped" Oil-and-Vinegar
//! trapdoor: the public key is a multivariate quadratic map
//! `P : F₁₆ⁿ → F₁₆^m` vanishing on a secret o-dimensional oil space, and the
//! whipped map
//!
//! ```text
//! P*(s₁,…,s_k) = Σᵢ E^ℓ·P(sᵢ) + Σ_{i<j} E^ℓ·P'(sᵢ,sⱼ)  :  F₁₆^{kn} → F₁₆^m
//! ```
//!
//! (with `E` the multiplication-by-`z` matrix in `F₁₆[z]/f(z)` and `ℓ` the
//! pair index) vanishes on the k-fold oil space, which is large enough to
//! sample preimages for any target.
//!
//! This crate exposes the three algorithms the VOLE-ACT scheme needs, in the
//! trapdoor-function shape used by the PoMFRIT blind-signature paper:
//!
//! - [`trapgen`]: key generation (`Algorithm 4`, math level).
//! - [`eval`]: the whipped-map evaluation `P*(s)` (`Algorithm 8`, lines
//!   20–26) — MAYO verification is `eval(pk, s) == t`.
//! - [`spre`]: preimage sampling `s` with `P*(s) = t` using the oil-space
//!   trapdoor (`Algorithm 7`, lines 13–45).
//!
//! Matrix shapes, the whipping iteration order, the `E`-matrix accumulation,
//! and `SampleSolution` follow the MAYO round-2 specification exactly.
//! Deliberate deviations (documented, none security-relevant for VOLE-ACT):
//!
//! - Keys are sampled from a caller-provided RNG at the math level; the
//!   spec's compressed-key formats (AES-128-CTR seed expansion, nibble
//!   packing) are not implemented, so NIST KATs do not apply.
//! - No message hashing or salts: VOLE-ACT signs *targets* `t ∈ F₁₆^m`
//!   directly ("hash-free MAYO" in PoMFRIT's terminology); deriving targets
//!   is the caller's job.

mod mat;
mod params;
mod scheme;

pub use mat::Mat;
pub use params::{Mayo1, Mayo2, Mayo3, Mayo5, MayoParams};
pub use scheme::{MayoError, PublicKey, SecretKey, eval, spre, trapgen};
