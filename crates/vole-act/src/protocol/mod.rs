//! Stateful Issue and Spend protocol for post-quantum anonymous credits.
//!
//! Every issued credential authenticates a signer-salted wrapper around its
//! hidden-balance commitment and return amount. Direct credentials use a zero
//! return; the deferred-return extension lets an issuer choose a bounded
//! return after the client fixes its proved spend request and before signer
//! salt generation. This common wrapper keeps the
//! security argument on fresh, uniformly salted MAYO targets.
//!
//! The issuer type includes an in-memory nullifier/retry store so its default
//! spend operations have the atomic semantics required by the construction:
//! a nullifier is recorded together with the exact typed request and response,
//! identical retries return the stored response, and conflicting retries are
//! rejected. Deployments that move this record into a database must preserve
//! the same transaction boundary.

use crate::circuit::{
    InputCredentialKind, IssueCircuit, MayoTermTable, SALT_BYTES, SpendCircuit, SpendSecrets,
    credential_target, derive_nullifier, mayo_terms_and_hash, signed_token_target,
};
use crate::wire::{self, Decoder, WireError};
use binary_fields::GF16;
use mayo::{Mayo1, MayoParams, PublicKey as MayoPublicKey, SecretKey as MayoSecretKey};
use rand_core::CryptoRngCore;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use std::collections::HashMap;
use std::marker::PhantomData;
use std::sync::Arc;
use voleith::{
    PARAMS_128, PARAMS_128_BALANCED, PARAMS_128_FAST, Params, Proof, VoleithError, prove, verify,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

const ISSUE_STATEMENT: &[u8] = b"VOLE-ACT/issue-statement/v5";
const SPEND_STATEMENT: &[u8] = b"VOLE-ACT/spend-statement/v5";

/// Maximum accepted application-context length in bytes.
///
/// The application context is a short deployment/asset/key-epoch label. The
/// bound keeps every encodable issuer key and public key decodable by its own
/// decoder (no round-trip asymmetry against [`MAX_WIRE_BYTES`](crate::MAX_WIRE_BYTES))
/// and is enforced at key generation and at both key decoders.
pub const MAX_APPLICATION_CONTEXT_BYTES: usize = 4096;

const WIRE_PUBLIC_KEY: u8 = 1;
const WIRE_ISSUER_KEY: u8 = 2;
const WIRE_ISSUE_REQUEST: u8 = 3;
const WIRE_ISSUE_RESPONSE: u8 = 4;
const WIRE_PENDING_ISSUE: u8 = 5;
const WIRE_TOKEN: u8 = 6;
const WIRE_SPEND_REQUEST: u8 = 7;
const WIRE_SPEND_RESPONSE: u8 = 8;
const WIRE_PENDING_SPEND: u8 = 9;
const WIRE_RETRY_RECORD: u8 = 10;

mod issue;
mod issuer;
mod markers;
mod public_key;
mod spend;
mod store;

pub use issue::{IssueRequest, IssueResponse, PendingIssue};
pub use issuer::Issuer;
pub use markers::{
    CredentialKind, DeferredReturn, DeferredReturnSpend, Direct, Error, FixedSpend,
    PerformanceProfile, SettlementMode,
};
pub use public_key::PublicKey;
pub use spend::*;
pub use store::{MemoryNullifierStore, NullifierStore, RetryRecord, RetryResponse};

fn input_kind<K: CredentialKind>() -> InputCredentialKind {
    if K::HAS_TOPUP {
        InputCredentialKind::DeferredReturn
    } else {
        InputCredentialKind::Direct
    }
}

fn effective_balance<K: CredentialKind>(base_balance: u64, topup: u64) -> Option<u64> {
    if !K::HAS_TOPUP && topup != 0 {
        return None;
    }
    base_balance.checked_add(topup)
}

fn signing_target<P: MayoParams, K: CredentialKind>(
    commitment: &[GF16],
    topup: u64,
    salt: &[u8; SALT_BYTES],
) -> Option<Vec<GF16>> {
    if !K::HAS_TOPUP && topup != 0 {
        return None;
    }
    Some(signed_token_target::<P>(commitment, topup, salt))
}

#[cfg(test)]
mod tests;
