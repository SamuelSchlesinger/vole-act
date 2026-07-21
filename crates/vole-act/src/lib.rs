//! # vole-act
//!
//! Post-quantum anonymous credit tokens from VOLE-in-the-head proofs and the
//! MAYO trapdoor.
//!
//! See `docs/DESIGN.md` at the workspace root for the construction. Every
//! token is a MAYO preimage of a signer-salted hash binding a hidden-balance
//! commitment and return amount. Direct tokens use return zero; the optional
//! deferred-return extension carries a bounded issuer-selected return, which
//! may be zero. Both
//! paths use three hidden SHAKE evaluations and prove token possession, exact
//! balance arithmetic, a one-time nullifier, and well-formedness of a fresh
//! commitment.
//!
//! ```no_run
//! # fn main() -> Result<(), vole_act::Error> {
//! use mayo::Mayo2;
//! use rand::rngs::OsRng;
//! use vole_act::Issuer;
//!
//! let mut rng = OsRng;
//! let mut issuer = Issuer::<Mayo2>::generate(b"credits/epoch-1", &mut rng);
//! let public = issuer.public_key().clone();
//!
//! let (pending, request) = public.prepare_issue(100, &mut rng)?;
//! let response = issuer.issue(&request, 100, &mut rng)?;
//! let token = pending.finish(&public, &request, &response)?;
//!
//! // The ordinary path creates another direct token.
//! let (pending, request) = token.prepare_spend(&public, 25, &mut rng)?;
//! let response = issuer.spend(&request, &mut rng)?;
//! let token = pending.finish(&public, &request, &response)?;
//!
//! // The extension lets the issuer supply a return after the proved request.
//! let (pending, request) =
//!     token.prepare_spend_with_deferred_return(&public, 20, &mut rng)?;
//! let response = issuer.spend_with_deferred_return(&request, 7, &mut rng)?;
//! let token = pending.finish(&public, &request, &response)?;
//! assert_eq!(token.balance(), 62);
//! # Ok(())
//! # }
//! ```
//!
//! The two settlement artifact families are deliberately incompatible:
//!
//! ```compile_fail
//! use mayo::MayoParams;
//! use vole_act::{
//!     CredentialKind, DeferredReturnSpendResponse, PendingSpend, PublicKey,
//!     SpendRequest,
//! };
//!
//! fn cannot_finish_with_the_other_mode<P: MayoParams, K: CredentialKind>(
//!     pending: PendingSpend<P, K>,
//!     public: &PublicKey<P>,
//!     request: &SpendRequest<P, K>,
//!     response: &DeferredReturnSpendResponse<P, K>,
//! ) {
//!     let _ = pending.finish(public, request, response);
//! }
//! ```
//!
//! The scheme layers (bottom-up): `binary-fields` → `vector-commit` →
//! `voleith` → `mayo` → this crate.

mod circuit;
pub mod keccak;
mod protocol;
mod wire;

pub use protocol::{
    CredentialKind, DeferredReturn, DeferredReturnSpendRequest, DeferredReturnSpendResponse,
    DeferredReturnToken, Direct, DirectToken, Error, IssueRequest, IssueResponse, Issuer,
    MAX_APPLICATION_CONTEXT_BYTES, MemoryNullifierStore, NullifierStore,
    PendingDeferredReturnSpend, PendingIssue, PendingSpend, PerformanceProfile,
    PreparedDeferredReturnSpend, PreparedSpend, PublicKey, RetryRecord, RetryResponse,
    SpendRequest, SpendResponse, Token,
};
pub use wire::{MAX_WIRE_BYTES, WireError};
