//! # vole-act
//!
//! Post-quantum anonymous credit tokens from VOLE-in-the-head proofs and the
//! MAYO trapdoor.
//!
//! **Under construction.** See `docs/DESIGN.md` at the workspace root for the
//! construction this crate is building toward: tokens are MAYO signatures on
//! binding hash commitments `H_cred(ctx ‖ k ‖ c ‖ ρ)`, spent by revealing a
//! nullifier `H_null(ctx ‖ k)` alongside a VOLE-in-the-head proof of token
//! possession, balance arithmetic, and well-formedness of the refund target.
//!
//! The scheme layers (bottom-up): `binary-fields` → `vector-commit` →
//! `voleith` → `mayo` → this crate.

pub mod keccak;
