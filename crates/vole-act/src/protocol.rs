//! Stateful Issue and Spend protocol for post-quantum anonymous credits.
//!
//! The core protocol issues direct credentials and keeps ordinary spends on
//! the two-hash path. The deferred-return extension lets an issuer choose a
//! bounded return after verifying a spend; its output credential wraps the
//! fresh commitment and return amount in one additional signed hash.
//!
//! The issuer type includes an in-memory nullifier/retry store so its default
//! spend operations have the atomic semantics required by the construction:
//! a nullifier is recorded together with the exact typed request and response,
//! identical retries return the stored response, and conflicting retries are
//! rejected. Deployments that move this record into a database must preserve
//! the same transaction boundary.

use crate::circuit::{
    InputCredentialKind, IssueCircuit, MayoTerm, SpendCircuit, SpendSecrets, credential_target,
    derive_nullifier, mayo_terms_and_hash, signed_token_target,
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

const ISSUE_STATEMENT: &[u8] = b"VOLE-ACT/issue-statement/v4";
const SPEND_STATEMENT: &[u8] = b"VOLE-ACT/spend-statement/v4";

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

mod sealed {
    pub trait CredentialKind {}
    pub trait SettlementMode {}
}

/// A closed credential-format marker.
///
/// This trait is sealed because adding a format requires new domains, circuit
/// equations, retry semantics, and security analysis. It is an implementation
/// abstraction, not an open cryptographic plug-in interface.
pub trait CredentialKind:
    sealed::CredentialKind + Copy + core::fmt::Debug + Send + Sync + 'static
{
    #[doc(hidden)]
    const TAG: &'static [u8];
    #[doc(hidden)]
    const HAS_TOPUP: bool;
    #[doc(hidden)]
    const WIRE_ID: u8;
}

/// A credential signed directly on its hidden-balance commitment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Direct;

impl sealed::CredentialKind for Direct {}
impl CredentialKind for Direct {
    const TAG: &'static [u8] = b"direct-credential/v1";
    const HAS_TOPUP: bool = false;
    const WIRE_ID: u8 = 1;
}

/// A credential whose signed target binds a hidden commitment and deferred
/// issuer-selected return amount.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeferredReturn;

impl sealed::CredentialKind for DeferredReturn {}
impl CredentialKind for DeferredReturn {
    const TAG: &'static [u8] = b"deferred-return-credential/v1";
    const HAS_TOPUP: bool = true;
    const WIRE_ID: u8 = 2;
}

/// A closed marker for the output settlement selected before proving.
#[doc(hidden)]
pub trait SettlementMode:
    sealed::SettlementMode + Copy + core::fmt::Debug + Send + Sync + 'static
{
    #[doc(hidden)]
    const TAG: &'static [u8];
    #[doc(hidden)]
    const WIRE_ID: u8;
}

/// Ordinary spend settlement: sign the fresh commitment directly.
#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FixedSpend;

impl sealed::SettlementMode for FixedSpend {}
impl SettlementMode for FixedSpend {
    const TAG: &'static [u8] = b"fixed-spend/v1";
    const WIRE_ID: u8 = 1;
}

/// Deferred-return settlement: sign the fresh commitment and a later issuer
/// choice through the nested target hash.
#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeferredReturnSpend;

impl sealed::SettlementMode for DeferredReturnSpend {}
impl SettlementMode for DeferredReturnSpend {
    const TAG: &'static [u8] = b"deferred-return-spend/v1";
    const WIRE_ID: u8 = 2;
}

/// Errors from the ACT protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// A spend exceeds the token balance.
    InsufficientBalance,
    /// A request has malformed dimensions or does not match its pending state.
    InvalidRequest,
    /// The issuer-selected return amount exceeds the maximum spend.
    InvalidReturnAmount,
    /// A VOLE-in-the-head proof did not verify.
    InvalidProof,
    /// A returned MAYO preimage does not authenticate the expected target.
    InvalidSignature,
    /// The nullifier was already used by a different typed request.
    NullifierAlreadySpent,
    /// MAYO preimage sampling failed.
    SigningFailed,
    /// The durable nullifier/retry store could not complete its operation.
    StorageFailure,
    /// A token or pending operation belongs to a different issuer context.
    WrongContext,
}

/// VOLE tree geometry, trading prover latency against request size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PerformanceProfile {
    /// Smallest proofs, but substantially more seed-tree expansion.
    Compact,
    /// A middle point between proof size and prover latency.
    Balanced,
    /// Minimum built-in prover latency, with roughly twice the correction
    /// payload of `Balanced` for large circuits.
    LowLatency,
}

impl PerformanceProfile {
    const fn params(self) -> Params {
        match self {
            Self::Compact => PARAMS_128,
            Self::Balanced => PARAMS_128_BALANCED,
            Self::LowLatency => PARAMS_128_FAST,
        }
    }

    const fn wire_id(self) -> u8 {
        match self {
            Self::Compact => 1,
            Self::Balanced => 2,
            Self::LowLatency => 3,
        }
    }

    fn from_wire_id(id: u8) -> Result<Self, WireError> {
        match id {
            1 => Ok(Self::Compact),
            2 => Ok(Self::Balanced),
            3 => Ok(Self::LowLatency),
            _ => Err(WireError::InvalidEncoding),
        }
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::InsufficientBalance => write!(f, "spend exceeds token balance"),
            Error::InvalidRequest => write!(f, "invalid ACT request"),
            Error::InvalidReturnAmount => write!(f, "return amount exceeds maximum spend"),
            Error::InvalidProof => write!(f, "invalid ACT proof"),
            Error::InvalidSignature => write!(f, "invalid MAYO signature"),
            Error::NullifierAlreadySpent => write!(f, "nullifier already spent"),
            Error::SigningFailed => write!(f, "MAYO preimage sampling failed"),
            Error::StorageFailure => write!(f, "nullifier store operation failed"),
            Error::WrongContext => write!(f, "issuer context mismatch"),
        }
    }
}

impl std::error::Error for Error {}

fn proof_error(_: VoleithError) -> Error {
    Error::InvalidProof
}

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
    context: &[u8; 32],
    commitment: &[GF16],
    topup: u64,
) -> Option<Vec<GF16>> {
    if !K::HAS_TOPUP && topup != 0 {
        return None;
    }
    Some(if K::HAS_TOPUP {
        signed_token_target::<P>(context, commitment, topup)
    } else {
        commitment.to_vec()
    })
}

struct PublicInner<P: MayoParams> {
    mayo: MayoPublicKey<P>,
    terms: Vec<MayoTerm>,
    context: [u8; 32],
    profile: PerformanceProfile,
    application_context: Vec<u8>,
}

/// Issuer public key and precomputed MAYO circuit representation.
///
/// Cloning this type is cheap: the large public key and quadratic term table
/// are reference-counted.
pub struct PublicKey<P: MayoParams = Mayo1> {
    inner: Arc<PublicInner<P>>,
}

impl<P: MayoParams> Clone for PublicKey<P> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<P: MayoParams> core::fmt::Debug for PublicKey<P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PublicKey")
            .field("parameter_set", &P::NAME)
            .field("context", &self.inner.context)
            .finish_non_exhaustive()
    }
}

impl<P: MayoParams> PublicKey<P> {
    /// The 32-byte protocol context binding this issuer, application domain,
    /// parameter set, protocol version, and 64-bit balance width.
    #[must_use]
    pub fn context(&self) -> [u8; 32] {
        self.inner.context
    }

    /// VOLE performance profile bound into this issuer's protocol context.
    #[must_use]
    pub fn performance_profile(&self) -> PerformanceProfile {
        self.inner.profile
    }

    /// Application/asset/key-epoch domain bound into this public key.
    #[must_use]
    pub fn application_context(&self) -> &[u8] {
        &self.inner.application_context
    }

    /// Encode this public key and its protocol context canonically.
    ///
    /// The embedded MAYO map is the expanded mathematical key rather than
    /// MAYO's seed-compressed signature-API format.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mayo = self.inner.mayo.to_bytes();
        let mut out = Vec::with_capacity(16 + self.inner.application_context.len() + mayo.len());
        wire::header(&mut out, WIRE_PUBLIC_KEY, P::WIRE_ID, 0, 0);
        out.push(self.inner.profile.wire_id());
        wire::put_bytes(&mut out, &self.inner.application_context);
        wire::put_bytes(&mut out, &mayo);
        out
    }

    /// Decode a canonical public key, recomputing all derived circuit terms
    /// and the issuer context from the advertised application domain.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, WireError> {
        let mut decoder = Decoder::new(bytes, WIRE_PUBLIC_KEY, P::WIRE_ID, 0, 0)?;
        let profile = PerformanceProfile::from_wire_id(decoder.u8()?)?;
        let application_context = decoder.bytes()?.to_vec();
        let mayo = MayoPublicKey::<P>::from_bytes(decoder.bytes()?)
            .map_err(|_| WireError::InvalidEncoding)?;
        decoder.finish()?;
        let (terms, public_key_hash) = mayo_terms_and_hash(&mayo);
        let context = derive_context::<P>(&application_context, &public_key_hash, profile);
        Ok(Self {
            inner: Arc::new(PublicInner {
                mayo,
                terms,
                context,
                profile,
                application_context,
            }),
        })
    }

    /// Start an issuance request for the public `balance`.
    pub fn prepare_issue(
        &self,
        balance: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(PendingIssue<P>, IssueRequest<P>), Error> {
        let mut key = [0u8; 32];
        let mut nonce = [0u8; 32];
        rng.fill_bytes(&mut key);
        rng.fill_bytes(&mut nonce);
        let commitment = credential_target::<P>(&self.inner.context, &key, balance, &nonce);
        let circuit = IssueCircuit::<P> {
            context: self.inner.context,
            balance,
            target: commitment.clone(),
            params: PhantomData,
        };
        let mut witness = circuit.witness(&key, &nonce);
        let statement = issue_statement::<P>(&self.inner.context, balance, &commitment);
        let proof_result = prove(
            &self.inner.profile.params(),
            &statement,
            &circuit,
            &witness,
            rng,
        );
        witness.zeroize();
        let proof = proof_result.map_err(proof_error)?;
        let request = IssueRequest {
            commitment: commitment.clone(),
            proof,
            params: PhantomData,
        };
        let pending = PendingIssue {
            context: self.inner.context,
            key,
            balance,
            nonce,
            commitment,
            params: PhantomData,
        };
        Ok((pending, request))
    }

    /// Verify either supported token kind against this issuer.
    pub fn verify_token<K: CredentialKind>(&self, token: &Token<P, K>) -> Result<(), Error> {
        if token.context != self.inner.context {
            return Err(Error::WrongContext);
        }
        effective_balance::<K>(token.base_balance, token.topup).ok_or(Error::InvalidSignature)?;
        let commitment =
            credential_target::<P>(&token.context, &token.key, token.base_balance, &token.nonce);
        let target = signing_target::<P, K>(&token.context, &commitment, token.topup)
            .ok_or(Error::InvalidSignature)?;
        let evaluated =
            mayo::eval(&self.inner.mayo, &token.signature).map_err(|_| Error::InvalidSignature)?;
        if evaluated != target {
            return Err(Error::InvalidSignature);
        }
        Ok(())
    }
}

/// Persisted response for one consumed nullifier.
///
/// The record is intentionally independent of the calling Rust request type:
/// its request digest commits the input credential and settlement tags, while
/// `response` records which signature target won the atomic insertion race.
#[derive(Clone, PartialEq, Eq)]
pub struct RetryRecord<P: MayoParams = Mayo1> {
    request_digest: [u8; 32],
    response: RetryResponse,
    params: PhantomData<P>,
}

impl<P: MayoParams> Drop for RetryRecord<P> {
    fn drop(&mut self) {
        self.request_digest.zeroize();
    }
}

impl<P: MayoParams> ZeroizeOnDrop for RetryRecord<P> {}

impl<P: MayoParams> core::fmt::Debug for RetryRecord<P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RetryRecord")
            .field("parameter_set", &P::NAME)
            .field("response", &self.response)
            .finish_non_exhaustive()
    }
}

/// Response payload durably paired with a consumed nullifier.
#[derive(Clone, PartialEq, Eq)]
pub enum RetryResponse {
    /// A direct fresh-commitment signature.
    Direct {
        /// MAYO preimage returned to the client.
        signature: Vec<GF16>,
    },
    /// A nested fresh-commitment/return signature.
    DeferredReturn {
        /// MAYO preimage returned to the client.
        signature: Vec<GF16>,
        /// Issuer-selected return bound into the signed target.
        return_amount: u64,
    },
}

impl Drop for RetryResponse {
    fn drop(&mut self) {
        match self {
            Self::Direct { signature } => signature.zeroize(),
            Self::DeferredReturn {
                signature,
                return_amount,
            } => {
                signature.zeroize();
                return_amount.zeroize();
            }
        }
    }
}

impl ZeroizeOnDrop for RetryResponse {}

impl core::fmt::Debug for RetryResponse {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Direct { .. } => f.write_str("RetryResponse::Direct { .. }"),
            Self::DeferredReturn { .. } => f.write_str("RetryResponse::DeferredReturn { .. }"),
        }
    }
}

impl<P: MayoParams> RetryRecord<P> {
    /// Digest of the exact typed request that consumed the nullifier.
    #[must_use]
    pub fn request_digest(&self) -> [u8; 32] {
        self.request_digest
    }

    /// Stored response payload.
    #[must_use]
    pub fn response(&self) -> &RetryResponse {
        &self.response
    }

    /// Encode this database record canonically.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let (settlement, signature, return_amount) = match &self.response {
            RetryResponse::Direct { signature } => (FixedSpend::WIRE_ID, signature, 0),
            RetryResponse::DeferredReturn {
                signature,
                return_amount,
            } => (DeferredReturnSpend::WIRE_ID, signature, *return_amount),
        };
        let mut out = Vec::with_capacity(56 + signature.len().div_ceil(2));
        wire::header(&mut out, WIRE_RETRY_RECORD, P::WIRE_ID, 0, settlement);
        out.extend_from_slice(&self.request_digest);
        out.extend_from_slice(&wire::pack_nibbles(signature));
        out.extend_from_slice(&return_amount.to_le_bytes());
        out
    }

    /// Decode a canonical database record.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, WireError> {
        let direct = Decoder::new(bytes, WIRE_RETRY_RECORD, P::WIRE_ID, 0, FixedSpend::WIRE_ID);
        let (mut decoder, deferred) = match direct {
            Ok(decoder) => (decoder, false),
            Err(WireError::WrongArtifact) => (
                Decoder::new(
                    bytes,
                    WIRE_RETRY_RECORD,
                    P::WIRE_ID,
                    0,
                    DeferredReturnSpend::WIRE_ID,
                )?,
                true,
            ),
            Err(error) => return Err(error),
        };
        let request_digest = decoder.array()?;
        let signature = decoder.nibbles(P::KN)?;
        let return_amount = decoder.u64()?;
        decoder.finish()?;
        if !deferred && return_amount != 0 {
            return Err(WireError::InvalidEncoding);
        }
        let response = if deferred {
            RetryResponse::DeferredReturn {
                signature,
                return_amount,
            }
        } else {
            RetryResponse::Direct { signature }
        };
        Ok(Self {
            request_digest,
            response,
            params: PhantomData,
        })
    }
}

/// Atomic persistence required for nullifier consumption and exact retries.
///
/// `insert_if_absent` must be one linearizable operation. It returns the
/// record that is durably stored after the operation: `candidate` if this
/// caller inserted first, or the pre-existing winner otherwise. A database
/// implementation should use a unique nullifier key and return the winning
/// row from the same transaction. Returning a response before this operation
/// is durable can create value after a crash and violates the protocol.
pub trait NullifierStore<P: MayoParams>: Send {
    /// Look up a previously consumed nullifier.
    fn get(&self, nullifier: &[u8; 32]) -> Result<Option<RetryRecord<P>>, Error>;

    /// Atomically insert `candidate` if absent and return the durable winner.
    fn insert_if_absent(
        &mut self,
        nullifier: [u8; 32],
        candidate: RetryRecord<P>,
    ) -> Result<RetryRecord<P>, Error>;
}

/// Process-local reference nullifier store.
///
/// It has correct retry semantics within one process but is not crash-safe.
/// Production issuers should supply a durable [`NullifierStore`].
pub struct MemoryNullifierStore<P: MayoParams = Mayo1> {
    records: HashMap<[u8; 32], RetryRecord<P>>,
}

impl<P: MayoParams> Default for MemoryNullifierStore<P> {
    fn default() -> Self {
        Self {
            records: HashMap::new(),
        }
    }
}

impl<P: MayoParams> NullifierStore<P> for MemoryNullifierStore<P> {
    fn get(&self, nullifier: &[u8; 32]) -> Result<Option<RetryRecord<P>>, Error> {
        Ok(self.records.get(nullifier).cloned())
    }

    fn insert_if_absent(
        &mut self,
        nullifier: [u8; 32],
        candidate: RetryRecord<P>,
    ) -> Result<RetryRecord<P>, Error> {
        use std::collections::hash_map::Entry;
        Ok(match self.records.entry(nullifier) {
            Entry::Vacant(entry) => entry.insert(candidate).clone(),
            Entry::Occupied(entry) => entry.get().clone(),
        })
    }
}

/// Stateful issuer with its MAYO trapdoor and nullifier/retry store.
pub struct Issuer<P: MayoParams = Mayo1, S: NullifierStore<P> = MemoryNullifierStore<P>> {
    secret: MayoSecretKey<P>,
    public: PublicKey<P>,
    spent: S,
}

impl<P: MayoParams> Issuer<P, MemoryNullifierStore<P>> {
    /// Generate a fresh issuer. `application_context` should identify the
    /// deployment, asset, and key epoch; it is hashed into every credential.
    pub fn generate(application_context: &[u8], rng: &mut impl CryptoRngCore) -> Self {
        Self::generate_with_profile(application_context, PerformanceProfile::Balanced, rng)
    }

    /// Generate an issuer with an explicit proof size/latency profile.
    pub fn generate_with_profile(
        application_context: &[u8],
        profile: PerformanceProfile,
        rng: &mut impl CryptoRngCore,
    ) -> Self {
        Self::generate_with_store(
            application_context,
            profile,
            MemoryNullifierStore::default(),
            rng,
        )
    }

    /// Number of consumed nullifiers in the built-in process-local store.
    #[must_use]
    pub fn spent_count(&self) -> usize {
        self.spent.records.len()
    }
}

impl<P: MayoParams, Store: NullifierStore<P>> Issuer<P, Store> {
    /// Generate a fresh issuer backed by an explicit nullifier store.
    pub fn generate_with_store(
        application_context: &[u8],
        profile: PerformanceProfile,
        spent: Store,
        rng: &mut impl CryptoRngCore,
    ) -> Self {
        let (secret, mayo) = mayo::trapgen::<P>(rng);
        let (terms, public_key_hash) = mayo_terms_and_hash(&mayo);
        let context = derive_context::<P>(application_context, &public_key_hash, profile);
        Self {
            secret,
            public: PublicKey {
                inner: Arc::new(PublicInner {
                    mayo,
                    terms,
                    context,
                    profile,
                    application_context: application_context.to_vec(),
                }),
            },
            spent,
        }
    }

    /// Restore an issuer key using an explicitly supplied nullifier store.
    ///
    /// Requiring the store at restoration is deliberate: silently restoring
    /// a key with an empty nullifier set would make every pre-crash token
    /// spendable again.
    pub fn from_key_bytes_with_store(bytes: &[u8], spent: Store) -> Result<Self, WireError> {
        let mut decoder = Decoder::new(bytes, WIRE_ISSUER_KEY, P::WIRE_ID, 0, 0)?;
        let profile = PerformanceProfile::from_wire_id(decoder.u8()?)?;
        let application_context = decoder.bytes()?.to_vec();
        let secret = MayoSecretKey::<P>::from_bytes(decoder.bytes()?)
            .map_err(|_| WireError::InvalidEncoding)?;
        decoder.finish()?;
        let mayo = secret.public_key();
        let (terms, public_key_hash) = mayo_terms_and_hash(&mayo);
        let context = derive_context::<P>(&application_context, &public_key_hash, profile);
        Ok(Self {
            secret,
            public: PublicKey {
                inner: Arc::new(PublicInner {
                    mayo,
                    terms,
                    context,
                    profile,
                    application_context,
                }),
            },
            spent,
        })
    }

    /// Encode the issuer trapdoor and public protocol context canonically.
    ///
    /// These bytes are the issuer's master secret. They intentionally omit
    /// nullifier records; back up the durable store at the same consistency
    /// boundary and always restore with [`Issuer::from_key_bytes_with_store`].
    #[must_use]
    pub fn key_bytes(&self) -> Vec<u8> {
        let mut secret = self.secret.to_bytes();
        let mut out =
            Vec::with_capacity(16 + self.public.inner.application_context.len() + secret.len());
        wire::header(&mut out, WIRE_ISSUER_KEY, P::WIRE_ID, 0, 0);
        out.push(self.public.inner.profile.wire_id());
        wire::put_bytes(&mut out, &self.public.inner.application_context);
        wire::put_bytes(&mut out, &secret);
        secret.zeroize();
        out
    }

    /// Borrow the configured nullifier store.
    #[must_use]
    pub fn store(&self) -> &Store {
        &self.spent
    }

    /// Mutably borrow the configured nullifier store.
    pub fn store_mut(&mut self) -> &mut Store {
        &mut self.spent
    }

    /// Borrow the issuer public key.
    #[must_use]
    pub fn public_key(&self) -> &PublicKey<P> {
        &self.public
    }

    /// Verify an issuance request for the externally authorized public
    /// `balance`, then sign its direct credential commitment.
    pub fn issue(
        &self,
        request: &IssueRequest<P>,
        balance: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<IssueResponse<P>, Error> {
        if request.commitment.len() != P::M {
            return Err(Error::InvalidRequest);
        }
        let circuit = IssueCircuit::<P> {
            context: self.public.inner.context,
            balance,
            target: request.commitment.clone(),
            params: PhantomData,
        };
        let statement =
            issue_statement::<P>(&self.public.inner.context, balance, &request.commitment);
        verify(
            &self.public.inner.profile.params(),
            &statement,
            &circuit,
            &request.proof,
        )
        .map_err(proof_error)?;
        let signature =
            mayo::spre(&self.secret, &request.commitment, rng).map_err(|_| Error::SigningFailed)?;
        Ok(IssueResponse {
            signature,
            params: PhantomData,
        })
    }

    /// Verify and process an ordinary spend, signing the fresh commitment
    /// directly. Exact retries return the original response.
    pub fn spend<K: CredentialKind>(
        &mut self,
        request: &SpendRequest<P, K>,
        rng: &mut impl CryptoRngCore,
    ) -> Result<SpendResponse<P, K>, Error> {
        self.validate_request_dimensions(request)?;
        let digest = spend_request_digest(&self.public.inner.context, request);
        if let Some(stored) = self.spent.get(&request.nullifier)? {
            return Self::fixed_response(stored, digest);
        }

        self.verify_spend_request(request)?;
        let signature = mayo::spre(&self.secret, &request.fresh_commitment, rng)
            .map_err(|_| Error::SigningFailed)?;
        let candidate = RetryRecord {
            request_digest: digest,
            response: RetryResponse::Direct { signature },
            params: PhantomData,
        };
        let stored = self.spent.insert_if_absent(request.nullifier, candidate)?;
        Self::fixed_response(stored, digest)
    }

    /// Verify and process a deferred-return spend. After proof verification,
    /// the issuer may return `return_amount <= request.maximum_spend()` to the
    /// fresh token. Exact retries return the originally stored amount and
    /// signature even if the caller supplies a different amount.
    pub fn spend_with_deferred_return<K: CredentialKind>(
        &mut self,
        request: &DeferredReturnSpendRequest<P, K>,
        return_amount: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<DeferredReturnSpendResponse<P, K>, Error> {
        self.validate_request_dimensions(request)?;
        let digest = spend_request_digest(&self.public.inner.context, request);
        if let Some(stored) = self.spent.get(&request.nullifier)? {
            return Self::deferred_response(stored, digest);
        }
        if return_amount > request.spend {
            return Err(Error::InvalidReturnAmount);
        }

        self.verify_spend_request(request)?;
        let target = signed_token_target::<P>(
            &self.public.inner.context,
            &request.fresh_commitment,
            return_amount,
        );
        let signature = mayo::spre(&self.secret, &target, rng).map_err(|_| Error::SigningFailed)?;
        let candidate = RetryRecord {
            request_digest: digest,
            response: RetryResponse::DeferredReturn {
                signature,
                return_amount,
            },
            params: PhantomData,
        };
        let stored = self.spent.insert_if_absent(request.nullifier, candidate)?;
        Self::deferred_response(stored, digest)
    }

    fn fixed_response<K: CredentialKind>(
        stored: RetryRecord<P>,
        digest: [u8; 32],
    ) -> Result<SpendResponse<P, K>, Error> {
        if stored.request_digest != digest {
            return Err(Error::NullifierAlreadySpent);
        }
        match &stored.response {
            RetryResponse::Direct { signature } => Ok(TypedSpendResponse {
                signature: signature.clone(),
                return_amount: 0,
                params: PhantomData,
            }),
            RetryResponse::DeferredReturn { .. } => Err(Error::InvalidRequest),
        }
    }

    fn deferred_response<K: CredentialKind>(
        stored: RetryRecord<P>,
        digest: [u8; 32],
    ) -> Result<DeferredReturnSpendResponse<P, K>, Error> {
        if stored.request_digest != digest {
            return Err(Error::NullifierAlreadySpent);
        }
        match &stored.response {
            RetryResponse::DeferredReturn {
                signature,
                return_amount,
            } => Ok(TypedSpendResponse {
                signature: signature.clone(),
                return_amount: *return_amount,
                params: PhantomData,
            }),
            RetryResponse::Direct { .. } => Err(Error::InvalidRequest),
        }
    }

    fn validate_request_dimensions<K: CredentialKind, S: SettlementMode>(
        &self,
        request: &TypedSpendRequest<P, K, S>,
    ) -> Result<(), Error> {
        if request.fresh_commitment.len() != P::M {
            return Err(Error::InvalidRequest);
        }
        Ok(())
    }

    fn verify_spend_request<K: CredentialKind, S: SettlementMode>(
        &self,
        request: &TypedSpendRequest<P, K, S>,
    ) -> Result<(), Error> {
        let circuit = SpendCircuit::<P> {
            terms: &self.public.inner.terms,
            context: self.public.inner.context,
            spend: request.spend,
            nullifier: request.nullifier,
            fresh_commitment: request.fresh_commitment.clone(),
            input_kind: input_kind::<K>(),
            params: PhantomData,
        };
        let statement = spend_statement::<P, K, S>(
            &self.public.inner.context,
            request.spend,
            &request.nullifier,
            &request.fresh_commitment,
        );
        verify(
            &self.public.inner.profile.params(),
            &statement,
            &circuit,
            &request.proof,
        )
        .map_err(proof_error)
    }
}

/// Client-side state retained while an issuance request is in flight.
pub struct PendingIssue<P: MayoParams = Mayo1> {
    context: [u8; 32],
    key: [u8; 32],
    balance: u64,
    nonce: [u8; 32],
    commitment: Vec<GF16>,
    params: PhantomData<P>,
}

impl<P: MayoParams> Drop for PendingIssue<P> {
    fn drop(&mut self) {
        self.context.zeroize();
        self.key.zeroize();
        self.balance.zeroize();
        self.nonce.zeroize();
        self.commitment.zeroize();
    }
}

impl<P: MayoParams> ZeroizeOnDrop for PendingIssue<P> {}

impl<P: MayoParams> PendingIssue<P> {
    /// Encode this crash-recovery state canonically.
    ///
    /// It contains token-opening secrets and must be protected at rest.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(128);
        wire::header(&mut out, WIRE_PENDING_ISSUE, P::WIRE_ID, 0, 0);
        out.extend_from_slice(&self.context);
        out.extend_from_slice(&self.key);
        out.extend_from_slice(&self.balance.to_le_bytes());
        out.extend_from_slice(&self.nonce);
        out
    }

    /// Restore canonical issuance state for this public key.
    pub fn from_bytes(public: &PublicKey<P>, bytes: &[u8]) -> Result<Self, WireError> {
        let mut decoder = Decoder::new(bytes, WIRE_PENDING_ISSUE, P::WIRE_ID, 0, 0)?;
        let context = decoder.array()?;
        let key = decoder.array()?;
        let balance = decoder.u64()?;
        let nonce = decoder.array()?;
        decoder.finish()?;
        if context != public.inner.context {
            return Err(WireError::WrongArtifact);
        }
        let commitment = credential_target::<P>(&context, &key, balance, &nonce);
        Ok(Self {
            context,
            key,
            balance,
            nonce,
            commitment,
            params: PhantomData,
        })
    }

    /// Validate the issuer response and construct a direct token.
    pub fn finish(
        self,
        public: &PublicKey<P>,
        request: &IssueRequest<P>,
        response: &IssueResponse<P>,
    ) -> Result<DirectToken<P>, Error> {
        if self.context != public.inner.context {
            return Err(Error::WrongContext);
        }
        if request.commitment != self.commitment {
            return Err(Error::InvalidRequest);
        }
        let evaluated = mayo::eval(&public.inner.mayo, &response.signature)
            .map_err(|_| Error::InvalidSignature)?;
        if evaluated != self.commitment {
            return Err(Error::InvalidSignature);
        }
        Ok(Token {
            context: self.context,
            signature: response.signature.clone(),
            key: self.key,
            base_balance: self.balance,
            nonce: self.nonce,
            topup: 0,
            params: PhantomData,
        })
    }
}

/// Issuance request sent from client to issuer.
#[derive(Clone, Debug)]
pub struct IssueRequest<P: MayoParams = Mayo1> {
    commitment: Vec<GF16>,
    proof: Proof,
    params: PhantomData<P>,
}

impl<P: MayoParams> IssueRequest<P> {
    /// Fresh hidden-balance commitment to sign after proof verification.
    #[must_use]
    pub fn commitment(&self) -> &[GF16] {
        &self.commitment
    }

    /// The well-formedness proof.
    #[must_use]
    pub fn proof(&self) -> &Proof {
        &self.proof
    }

    /// Encode this issuance request canonically.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let proof = self.proof.to_bytes();
        let mut out = Vec::with_capacity(16 + self.commitment.len().div_ceil(2) + proof.len());
        wire::header(&mut out, WIRE_ISSUE_REQUEST, P::WIRE_ID, 0, 0);
        out.extend_from_slice(&wire::pack_nibbles(&self.commitment));
        wire::put_bytes(&mut out, &proof);
        out
    }

    /// Decode a canonical issuance request.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, WireError> {
        let mut decoder = Decoder::new(bytes, WIRE_ISSUE_REQUEST, P::WIRE_ID, 0, 0)?;
        let commitment = decoder.nibbles(P::M)?;
        let proof = Proof::from_bytes(decoder.bytes()?).map_err(|error| match error {
            voleith::ProofDecodeError::TooLarge => WireError::TooLarge,
            voleith::ProofDecodeError::InvalidEncoding => WireError::InvalidEncoding,
        })?;
        decoder.finish()?;
        Ok(Self {
            commitment,
            proof,
            params: PhantomData,
        })
    }
}

/// Issuer response completing issuance.
pub struct IssueResponse<P: MayoParams = Mayo1> {
    signature: Vec<GF16>,
    params: PhantomData<P>,
}

impl<P: MayoParams> Drop for IssueResponse<P> {
    fn drop(&mut self) {
        self.signature.zeroize();
    }
}

impl<P: MayoParams> ZeroizeOnDrop for IssueResponse<P> {}

impl<P: MayoParams> core::fmt::Debug for IssueResponse<P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IssueResponse")
            .field("parameter_set", &P::NAME)
            .finish_non_exhaustive()
    }
}

impl<P: MayoParams> Clone for IssueResponse<P> {
    fn clone(&self) -> Self {
        Self {
            signature: self.signature.clone(),
            params: PhantomData,
        }
    }
}

impl<P: MayoParams> IssueResponse<P> {
    /// Encode this issuance response canonically.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(16 + self.signature.len().div_ceil(2));
        wire::header(&mut out, WIRE_ISSUE_RESPONSE, P::WIRE_ID, 0, 0);
        out.extend_from_slice(&wire::pack_nibbles(&self.signature));
        out
    }

    /// Decode a canonical issuance response.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, WireError> {
        let mut decoder = Decoder::new(bytes, WIRE_ISSUE_RESPONSE, P::WIRE_ID, 0, 0)?;
        let signature = decoder.nibbles(P::KN)?;
        decoder.finish()?;
        Ok(Self {
            signature,
            params: PhantomData,
        })
    }
}

/// A client-held anonymous credit token.
///
/// `K` is either [`Direct`] (the default/core format) or [`DeferredReturn`].
/// The marker is part of every request and response type, preventing artifacts
/// for the two credential formats from being mixed accidentally.
pub struct Token<P: MayoParams = Mayo1, K: CredentialKind = Direct> {
    context: [u8; 32],
    signature: Vec<GF16>,
    key: [u8; 32],
    base_balance: u64,
    nonce: [u8; 32],
    topup: u64,
    params: PhantomData<(P, K)>,
}

impl<P: MayoParams, K: CredentialKind> Drop for Token<P, K> {
    fn drop(&mut self) {
        self.context.zeroize();
        self.signature.zeroize();
        self.key.zeroize();
        self.base_balance.zeroize();
        self.nonce.zeroize();
        self.topup.zeroize();
    }
}

impl<P: MayoParams, K: CredentialKind> ZeroizeOnDrop for Token<P, K> {}

/// Core token format signed directly on its hidden-balance commitment.
pub type DirectToken<P = Mayo1> = Token<P, Direct>;

/// Extension token format carrying a hidden issuer-selected return.
pub type DeferredReturnToken<P = Mayo1> = Token<P, DeferredReturn>;

impl<P: MayoParams, K: CredentialKind> Token<P, K> {
    /// Current private effective balance.
    #[must_use]
    pub fn balance(&self) -> u64 {
        effective_balance::<K>(self.base_balance, self.topup)
            .expect("verified token balances cannot overflow")
    }

    /// Encode this client-held token canonically.
    ///
    /// The encoding contains the signature, nullifier key, balance, and
    /// hiding nonce. It is secret local state, not a presentation message.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(128 + self.signature.len().div_ceil(2));
        wire::header(&mut out, WIRE_TOKEN, P::WIRE_ID, K::WIRE_ID, 0);
        out.extend_from_slice(&self.context);
        out.extend_from_slice(&wire::pack_nibbles(&self.signature));
        out.extend_from_slice(&self.key);
        out.extend_from_slice(&self.base_balance.to_le_bytes());
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.topup.to_le_bytes());
        out
    }

    /// Decode and authenticate client-held token state.
    pub fn from_bytes(public: &PublicKey<P>, bytes: &[u8]) -> Result<Self, WireError> {
        let mut decoder = Decoder::new(bytes, WIRE_TOKEN, P::WIRE_ID, K::WIRE_ID, 0)?;
        let context = decoder.array()?;
        let signature = decoder.nibbles(P::KN)?;
        let key = decoder.array()?;
        let base_balance = decoder.u64()?;
        let nonce = decoder.array()?;
        let topup = decoder.u64()?;
        decoder.finish()?;
        if context != public.inner.context || (!K::HAS_TOPUP && topup != 0) {
            return Err(WireError::WrongArtifact);
        }
        let token = Self {
            context,
            signature,
            key,
            base_balance,
            nonce,
            topup,
            params: PhantomData,
        };
        public
            .verify_token(&token)
            .map_err(|_| WireError::InvalidCredential)?;
        Ok(token)
    }

    /// Prepare an ordinary spend. Its response always creates a direct token,
    /// folding any old deferred return into the fresh balance.
    pub fn prepare_spend(
        &self,
        public: &PublicKey<P>,
        amount: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<PreparedSpend<P, K>, Error> {
        self.prepare_typed_spend::<FixedSpend>(public, amount, rng)
    }

    /// Prepare a spend whose final return is chosen by the issuer only after
    /// proof verification. The response creates a deferred-return token.
    pub fn prepare_spend_with_deferred_return(
        &self,
        public: &PublicKey<P>,
        maximum_spend: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<PreparedDeferredReturnSpend<P, K>, Error> {
        self.prepare_typed_spend::<DeferredReturnSpend>(public, maximum_spend, rng)
    }

    fn prepare_typed_spend<S: SettlementMode>(
        &self,
        public: &PublicKey<P>,
        spend: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<PreparedTypedSpend<P, K, S>, Error> {
        if self.context != public.inner.context {
            return Err(Error::WrongContext);
        }
        public.verify_token(self)?;
        let balance = self.balance();
        if spend > balance {
            return Err(Error::InsufficientBalance);
        }

        let fresh_base_balance = balance - spend;
        let mut fresh_key = [0u8; 32];
        let mut fresh_nonce = [0u8; 32];
        rng.fill_bytes(&mut fresh_key);
        rng.fill_bytes(&mut fresh_nonce);
        let fresh_commitment =
            credential_target::<P>(&self.context, &fresh_key, fresh_base_balance, &fresh_nonce);
        let nullifier =
            derive_nullifier::<P>(&self.context, &self.key, self.base_balance, &self.nonce);
        let circuit = SpendCircuit::<P> {
            terms: &public.inner.terms,
            context: self.context,
            spend,
            nullifier,
            fresh_commitment: fresh_commitment.clone(),
            input_kind: input_kind::<K>(),
            params: PhantomData,
        };
        let secrets = SpendSecrets {
            signature: &self.signature,
            key: &self.key,
            base_balance: self.base_balance,
            nonce: &self.nonce,
            topup: self.topup,
            fresh_key: &fresh_key,
            fresh_base_balance,
            fresh_nonce: &fresh_nonce,
        };
        let mut witness = circuit.witness(&secrets);
        let statement =
            spend_statement::<P, K, S>(&self.context, spend, &nullifier, &fresh_commitment);
        let proof_result = prove(
            &public.inner.profile.params(),
            &statement,
            &circuit,
            &witness,
            rng,
        );
        witness.zeroize();
        let proof = proof_result.map_err(proof_error)?;
        let request = TypedSpendRequest {
            spend,
            nullifier,
            fresh_commitment: fresh_commitment.clone(),
            proof,
            params: PhantomData,
        };
        let request_digest = spend_request_digest(&self.context, &request);
        let pending = TypedPendingSpend {
            context: self.context,
            fresh_key,
            fresh_base_balance,
            fresh_nonce,
            fresh_commitment,
            request_digest,
            params: PhantomData,
        };
        Ok((pending, request))
    }
}

/// Typed spend request. Public aliases select a fixed or deferred-return
/// settlement mode; callers should normally use [`SpendRequest`] or
/// [`DeferredReturnSpendRequest`].
#[doc(hidden)]
#[derive(Clone, Debug)]
pub struct TypedSpendRequest<
    P: MayoParams = Mayo1,
    K: CredentialKind = Direct,
    S: SettlementMode = FixedSpend,
> {
    spend: u64,
    nullifier: [u8; 32],
    fresh_commitment: Vec<GF16>,
    proof: Proof,
    params: PhantomData<(P, K, S)>,
}

/// Request for an ordinary spend that produces a direct token.
pub type SpendRequest<P = Mayo1, K = Direct> = TypedSpendRequest<P, K, FixedSpend>;

/// Request for a spend whose issuer-selected return is deferred until after
/// proof verification.
pub type DeferredReturnSpendRequest<P = Mayo1, K = Direct> =
    TypedSpendRequest<P, K, DeferredReturnSpend>;

impl<P: MayoParams, K: CredentialKind, S: SettlementMode> TypedSpendRequest<P, K, S> {
    /// Encode this typed spend request canonically.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let proof = self.proof.to_bytes();
        let mut out =
            Vec::with_capacity(64 + self.fresh_commitment.len().div_ceil(2) + proof.len());
        wire::header(
            &mut out,
            WIRE_SPEND_REQUEST,
            P::WIRE_ID,
            K::WIRE_ID,
            S::WIRE_ID,
        );
        out.extend_from_slice(&self.spend.to_le_bytes());
        out.extend_from_slice(&self.nullifier);
        out.extend_from_slice(&wire::pack_nibbles(&self.fresh_commitment));
        wire::put_bytes(&mut out, &proof);
        out
    }

    /// Decode a canonical request of exactly this input-credential and
    /// settlement type.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, WireError> {
        let mut decoder = Decoder::new(
            bytes,
            WIRE_SPEND_REQUEST,
            P::WIRE_ID,
            K::WIRE_ID,
            S::WIRE_ID,
        )?;
        let spend = decoder.u64()?;
        let nullifier = decoder.array()?;
        let fresh_commitment = decoder.nibbles(P::M)?;
        let proof = Proof::from_bytes(decoder.bytes()?).map_err(|error| match error {
            voleith::ProofDecodeError::TooLarge => WireError::TooLarge,
            voleith::ProofDecodeError::InvalidEncoding => WireError::InvalidEncoding,
        })?;
        decoder.finish()?;
        Ok(Self {
            spend,
            nullifier,
            fresh_commitment,
            proof,
            params: PhantomData,
        })
    }
}

impl<P: MayoParams, K: CredentialKind> TypedSpendRequest<P, K, FixedSpend> {
    /// Public amount deducted from the token.
    #[must_use]
    pub fn amount(&self) -> u64 {
        self.spend
    }

    /// One-time nullifier to consume atomically.
    #[must_use]
    pub fn nullifier(&self) -> [u8; 32] {
        self.nullifier
    }

    /// Fresh direct-token commitment.
    #[must_use]
    pub fn fresh_commitment(&self) -> &[GF16] {
        &self.fresh_commitment
    }

    /// Complete possession, arithmetic, nullifier, and refresh proof.
    #[must_use]
    pub fn proof(&self) -> &Proof {
        &self.proof
    }
}

impl<P: MayoParams, K: CredentialKind> TypedSpendRequest<P, K, DeferredReturnSpend> {
    /// Maximum public deduction before the issuer chooses a return.
    #[must_use]
    pub fn maximum_spend(&self) -> u64 {
        self.spend
    }

    /// One-time nullifier to consume atomically.
    #[must_use]
    pub fn nullifier(&self) -> [u8; 32] {
        self.nullifier
    }

    /// Fresh base commitment to wrap with the issuer-selected return.
    #[must_use]
    pub fn fresh_commitment(&self) -> &[GF16] {
        &self.fresh_commitment
    }

    /// Complete possession, arithmetic, nullifier, and refresh proof.
    #[must_use]
    pub fn proof(&self) -> &Proof {
        &self.proof
    }
}

/// Typed issuer response. Public aliases keep ordinary and deferred-return
/// responses non-interchangeable at compile time.
#[doc(hidden)]
pub struct TypedSpendResponse<
    P: MayoParams = Mayo1,
    K: CredentialKind = Direct,
    S: SettlementMode = FixedSpend,
> {
    signature: Vec<GF16>,
    return_amount: u64,
    params: PhantomData<(P, K, S)>,
}

impl<P: MayoParams, K: CredentialKind, S: SettlementMode> Drop for TypedSpendResponse<P, K, S> {
    fn drop(&mut self) {
        self.signature.zeroize();
        self.return_amount.zeroize();
    }
}

impl<P: MayoParams, K: CredentialKind, S: SettlementMode> ZeroizeOnDrop
    for TypedSpendResponse<P, K, S>
{
}

impl<P: MayoParams, K: CredentialKind, S: SettlementMode> core::fmt::Debug
    for TypedSpendResponse<P, K, S>
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SpendResponse")
            .field("parameter_set", &P::NAME)
            .field("input_kind", &core::any::type_name::<K>())
            .field("settlement", &core::any::type_name::<S>())
            .finish_non_exhaustive()
    }
}

impl<P: MayoParams, K: CredentialKind, S: SettlementMode> Clone for TypedSpendResponse<P, K, S> {
    fn clone(&self) -> Self {
        Self {
            signature: self.signature.clone(),
            return_amount: self.return_amount,
            params: PhantomData,
        }
    }
}

impl<P: MayoParams, K: CredentialKind, S: SettlementMode> TypedSpendResponse<P, K, S> {
    /// Encode this typed spend response canonically.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(24 + self.signature.len().div_ceil(2));
        wire::header(
            &mut out,
            WIRE_SPEND_RESPONSE,
            P::WIRE_ID,
            K::WIRE_ID,
            S::WIRE_ID,
        );
        out.extend_from_slice(&wire::pack_nibbles(&self.signature));
        out.extend_from_slice(&self.return_amount.to_le_bytes());
        out
    }

    /// Decode a canonical response of exactly this input-credential and
    /// settlement type.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, WireError> {
        let mut decoder = Decoder::new(
            bytes,
            WIRE_SPEND_RESPONSE,
            P::WIRE_ID,
            K::WIRE_ID,
            S::WIRE_ID,
        )?;
        let signature = decoder.nibbles(P::KN)?;
        let return_amount = decoder.u64()?;
        decoder.finish()?;
        if S::WIRE_ID == FixedSpend::WIRE_ID && return_amount != 0 {
            return Err(WireError::InvalidEncoding);
        }
        Ok(Self {
            signature,
            return_amount,
            params: PhantomData,
        })
    }
}

/// Issuer response completing an ordinary spend.
pub type SpendResponse<P = Mayo1, K = Direct> = TypedSpendResponse<P, K, FixedSpend>;

/// Issuer response completing a deferred-return spend.
pub type DeferredReturnSpendResponse<P = Mayo1, K = Direct> =
    TypedSpendResponse<P, K, DeferredReturnSpend>;

impl<P: MayoParams, K: CredentialKind> TypedSpendResponse<P, K, DeferredReturnSpend> {
    /// Issuer-selected amount returned to the new token.
    #[must_use]
    pub fn return_amount(&self) -> u64 {
        self.return_amount
    }
}

/// Typed client-side state retained while a spend is in flight.
#[doc(hidden)]
pub struct TypedPendingSpend<
    P: MayoParams = Mayo1,
    K: CredentialKind = Direct,
    S: SettlementMode = FixedSpend,
> {
    context: [u8; 32],
    fresh_key: [u8; 32],
    fresh_base_balance: u64,
    fresh_nonce: [u8; 32],
    fresh_commitment: Vec<GF16>,
    request_digest: [u8; 32],
    params: PhantomData<(P, K, S)>,
}

impl<P: MayoParams, K: CredentialKind, S: SettlementMode> Drop for TypedPendingSpend<P, K, S> {
    fn drop(&mut self) {
        self.context.zeroize();
        self.fresh_key.zeroize();
        self.fresh_base_balance.zeroize();
        self.fresh_nonce.zeroize();
        self.fresh_commitment.zeroize();
        self.request_digest.zeroize();
    }
}

impl<P: MayoParams, K: CredentialKind, S: SettlementMode> ZeroizeOnDrop
    for TypedPendingSpend<P, K, S>
{
}

/// Pending ordinary spend; finishes only with its matching request/response.
pub type PendingSpend<P = Mayo1, K = Direct> = TypedPendingSpend<P, K, FixedSpend>;

/// Pending deferred-return spend; finishes only with its matching typed
/// request/response.
pub type PendingDeferredReturnSpend<P = Mayo1, K = Direct> =
    TypedPendingSpend<P, K, DeferredReturnSpend>;

type PreparedTypedSpend<P, K, S> = (TypedPendingSpend<P, K, S>, TypedSpendRequest<P, K, S>);

/// Pending state and request produced by [`Token::prepare_spend`].
pub type PreparedSpend<P = Mayo1, K = Direct> = (PendingSpend<P, K>, SpendRequest<P, K>);

/// Pending state and request produced by
/// [`Token::prepare_spend_with_deferred_return`].
pub type PreparedDeferredReturnSpend<P = Mayo1, K = Direct> = (
    PendingDeferredReturnSpend<P, K>,
    DeferredReturnSpendRequest<P, K>,
);

impl<P: MayoParams, K: CredentialKind, S: SettlementMode> TypedPendingSpend<P, K, S> {
    /// Encode this crash-recovery state canonically.
    ///
    /// It contains the fresh token opening and must be protected at rest.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(160);
        wire::header(
            &mut out,
            WIRE_PENDING_SPEND,
            P::WIRE_ID,
            K::WIRE_ID,
            S::WIRE_ID,
        );
        out.extend_from_slice(&self.context);
        out.extend_from_slice(&self.fresh_key);
        out.extend_from_slice(&self.fresh_base_balance.to_le_bytes());
        out.extend_from_slice(&self.fresh_nonce);
        out.extend_from_slice(&self.request_digest);
        out
    }

    /// Restore canonical pending-spend state for this public key.
    pub fn from_bytes(public: &PublicKey<P>, bytes: &[u8]) -> Result<Self, WireError> {
        let mut decoder = Decoder::new(
            bytes,
            WIRE_PENDING_SPEND,
            P::WIRE_ID,
            K::WIRE_ID,
            S::WIRE_ID,
        )?;
        let context = decoder.array()?;
        let fresh_key = decoder.array()?;
        let fresh_base_balance = decoder.u64()?;
        let fresh_nonce = decoder.array()?;
        let request_digest = decoder.array()?;
        decoder.finish()?;
        if context != public.inner.context {
            return Err(WireError::WrongArtifact);
        }
        let fresh_commitment =
            credential_target::<P>(&context, &fresh_key, fresh_base_balance, &fresh_nonce);
        Ok(Self {
            context,
            fresh_key,
            fresh_base_balance,
            fresh_nonce,
            fresh_commitment,
            request_digest,
            params: PhantomData,
        })
    }

    fn validate_request(
        &self,
        public: &PublicKey<P>,
        request: &TypedSpendRequest<P, K, S>,
    ) -> Result<(), Error> {
        if self.context != public.inner.context {
            return Err(Error::WrongContext);
        }
        if spend_request_digest(&self.context, request) != self.request_digest
            || request.fresh_commitment != self.fresh_commitment
        {
            return Err(Error::InvalidRequest);
        }
        Ok(())
    }
}

impl<P: MayoParams, K: CredentialKind> TypedPendingSpend<P, K, FixedSpend> {
    /// Validate the exact ordinary-spend artifacts and construct a direct
    /// change token.
    pub fn finish(
        self,
        public: &PublicKey<P>,
        request: &SpendRequest<P, K>,
        response: &SpendResponse<P, K>,
    ) -> Result<DirectToken<P>, Error> {
        self.validate_request(public, request)?;
        let evaluated = mayo::eval(&public.inner.mayo, &response.signature)
            .map_err(|_| Error::InvalidSignature)?;
        if evaluated != self.fresh_commitment {
            return Err(Error::InvalidSignature);
        }
        Ok(Token {
            context: self.context,
            signature: response.signature.clone(),
            key: self.fresh_key,
            base_balance: self.fresh_base_balance,
            nonce: self.fresh_nonce,
            topup: 0,
            params: PhantomData,
        })
    }
}

impl<P: MayoParams, K: CredentialKind> TypedPendingSpend<P, K, DeferredReturnSpend> {
    /// Validate the exact deferred-return artifacts and construct a
    /// deferred-return token.
    pub fn finish(
        self,
        public: &PublicKey<P>,
        request: &DeferredReturnSpendRequest<P, K>,
        response: &DeferredReturnSpendResponse<P, K>,
    ) -> Result<DeferredReturnToken<P>, Error> {
        self.validate_request(public, request)?;
        if response.return_amount > request.spend
            || self
                .fresh_base_balance
                .checked_add(response.return_amount)
                .is_none()
        {
            return Err(Error::InvalidReturnAmount);
        }
        let target = signed_token_target::<P>(
            &self.context,
            &self.fresh_commitment,
            response.return_amount,
        );
        let evaluated = mayo::eval(&public.inner.mayo, &response.signature)
            .map_err(|_| Error::InvalidSignature)?;
        if evaluated != target {
            return Err(Error::InvalidSignature);
        }
        Ok(Token {
            context: self.context,
            signature: response.signature.clone(),
            key: self.fresh_key,
            base_balance: self.fresh_base_balance,
            nonce: self.fresh_nonce,
            topup: response.return_amount,
            params: PhantomData,
        })
    }
}

fn derive_context<P: MayoParams>(
    application_context: &[u8],
    public_key_hash: &[u8; 32],
    profile: PerformanceProfile,
) -> [u8; 32] {
    let mut h = sha3::Shake256::default();
    h.update(b"VOLE-ACT/context/v4");
    h.update(&(application_context.len() as u64).to_le_bytes());
    h.update(application_context);
    h.update(public_key_hash);
    h.update(P::NAME.as_bytes());
    h.update(&64u64.to_le_bytes());
    let vole = profile.params();
    h.update(&(vole.tau as u64).to_le_bytes());
    h.update(&(vole.k as u64).to_le_bytes());
    let mut out = [0u8; 32];
    h.finalize_xof().read(&mut out);
    out
}

fn encode_target(target: &[GF16], out: &mut Vec<u8>) {
    out.extend_from_slice(&(target.len() as u64).to_le_bytes());
    out.extend(target.iter().map(|element| element.to_u8()));
}

fn encode_bytes(bytes: &[u8], out: &mut Vec<u8>) {
    out.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    out.extend_from_slice(bytes);
}

fn issue_statement<P: MayoParams>(
    context: &[u8; 32],
    balance: u64,
    commitment: &[GF16],
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(ISSUE_STATEMENT);
    encode_bytes(P::NAME.as_bytes(), &mut out);
    out.extend_from_slice(context);
    out.extend_from_slice(&balance.to_le_bytes());
    encode_target(commitment, &mut out);
    out
}

fn spend_statement<P: MayoParams, K: CredentialKind, S: SettlementMode>(
    context: &[u8; 32],
    spend: u64,
    nullifier: &[u8; 32],
    fresh_commitment: &[GF16],
) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(SPEND_STATEMENT);
    encode_bytes(P::NAME.as_bytes(), &mut out);
    encode_bytes(K::TAG, &mut out);
    encode_bytes(S::TAG, &mut out);
    out.extend_from_slice(context);
    out.extend_from_slice(&spend.to_le_bytes());
    out.extend_from_slice(nullifier);
    encode_target(fresh_commitment, &mut out);
    out
}

fn hash_framed(h: &mut sha3::Shake256, bytes: &[u8]) {
    h.update(&(bytes.len() as u64).to_le_bytes());
    h.update(bytes);
}

fn spend_request_digest<P: MayoParams, K: CredentialKind, S: SettlementMode>(
    context: &[u8; 32],
    request: &TypedSpendRequest<P, K, S>,
) -> [u8; 32] {
    let mut h = sha3::Shake256::default();
    h.update(b"VOLE-ACT/spend-request-digest/v4");
    h.update(context);
    hash_framed(&mut h, &request.to_bytes());
    let mut out = [0u8; 32];
    h.finalize_xof().read(&mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use mayo::Mayo2;
    use rand::SeedableRng;
    use rand::rngs::StdRng;
    use std::time::Instant;

    fn issue_token(
        issuer: &Issuer<Mayo2>,
        public: &PublicKey<Mayo2>,
        balance: u64,
        rng: &mut StdRng,
    ) -> DirectToken<Mayo2> {
        let (pending, request) = public.prepare_issue(balance, rng).unwrap();
        let response = issuer.issue(&request, balance, rng).unwrap();
        pending.finish(public, &request, &response).unwrap()
    }

    fn wire_fingerprint(bytes: &[u8]) -> [u8; 32] {
        let mut hash = sha3::Shake256::default();
        hash.update(b"VOLE-ACT/test-vector-fingerprint/v1");
        hash.update(&(bytes.len() as u64).to_le_bytes());
        hash.update(bytes);
        let mut fingerprint = [0u8; 32];
        hash.finalize_xof().read(&mut fingerprint);
        fingerprint
    }

    #[test]
    fn deterministic_mayo2_wire_vector() {
        let mut rng = StdRng::seed_from_u64(0x5645_4354_4F52_0001);
        let mut issuer = Issuer::<Mayo2>::generate_with_profile(
            b"test-vector/credits/epoch-1",
            PerformanceProfile::Balanced,
            &mut rng,
        );
        let public = issuer.public_key().clone();
        let (pending_issue, issue_request) = public.prepare_issue(90, &mut rng).unwrap();
        let issue_response = issuer.issue(&issue_request, 90, &mut rng).unwrap();
        let token = pending_issue
            .finish(&public, &issue_request, &issue_response)
            .unwrap();
        let (pending_spend, spend_request) = token.prepare_spend(&public, 17, &mut rng).unwrap();
        let spend_response = issuer.spend(&spend_request, &mut rng).unwrap();
        let output = pending_spend
            .finish(&public, &spend_request, &spend_response)
            .unwrap();

        let fingerprints = [
            public.to_bytes(),
            issue_request.to_bytes(),
            issue_response.to_bytes(),
            token.to_bytes(),
            spend_request.to_bytes(),
            spend_response.to_bytes(),
            output.to_bytes(),
        ]
        .map(|bytes| wire_fingerprint(&bytes));

        assert_eq!(
            fingerprints,
            [
                [
                    0x03, 0xa1, 0x10, 0xe2, 0x05, 0x36, 0x8b, 0xb2, 0xf2, 0x0d, 0x3e, 0x8e, 0x7e,
                    0xbb, 0xb5, 0x77, 0xaf, 0xca, 0x54, 0x68, 0x91, 0x67, 0x43, 0xd0, 0x7d, 0x8b,
                    0x43, 0xcd, 0xb1, 0xc2, 0xd1, 0xb1,
                ],
                [
                    0xe0, 0x98, 0xf7, 0xac, 0x1e, 0x83, 0x04, 0xb7, 0x6e, 0xc5, 0x77, 0x8b, 0x84,
                    0x85, 0xed, 0xc1, 0x91, 0x08, 0xa1, 0x94, 0x11, 0xf5, 0x62, 0x6c, 0x5e, 0x50,
                    0x20, 0x01, 0x7f, 0x2a, 0xec, 0x45,
                ],
                [
                    0x0a, 0x65, 0x43, 0xa7, 0x18, 0xc0, 0x0e, 0xef, 0x56, 0x7c, 0x44, 0xf3, 0xfc,
                    0xbf, 0xf5, 0x1b, 0xde, 0x8e, 0xe6, 0xaf, 0x1c, 0x5f, 0x10, 0xf3, 0x1e, 0xcc,
                    0xd5, 0x93, 0x7e, 0xc7, 0xe9, 0x41,
                ],
                [
                    0x2e, 0x58, 0x4c, 0x2b, 0x7f, 0xea, 0x29, 0x90, 0x05, 0xfd, 0x57, 0xe5, 0x97,
                    0x7d, 0xf2, 0x0e, 0xb9, 0x52, 0xf9, 0x1a, 0xd9, 0xae, 0xf0, 0x4e, 0x1a, 0x7f,
                    0x35, 0x5c, 0x14, 0x58, 0xdd, 0xb0,
                ],
                [
                    0x65, 0xa2, 0x75, 0xf6, 0xad, 0xec, 0xcc, 0x6b, 0xed, 0x9d, 0xd4, 0x37, 0xe9,
                    0x11, 0xbd, 0xa7, 0xb7, 0x9c, 0xf7, 0x0f, 0xb2, 0xac, 0xdb, 0x6d, 0x94, 0x61,
                    0x5f, 0x8b, 0x4e, 0x59, 0x25, 0x2c,
                ],
                [
                    0x14, 0x95, 0x68, 0x80, 0x84, 0xa7, 0xf5, 0x6e, 0xc7, 0x30, 0x1e, 0x73, 0x92,
                    0xbb, 0x16, 0x43, 0x93, 0x89, 0x55, 0xd5, 0x51, 0xe2, 0xf0, 0xf7, 0xe5, 0x54,
                    0x0d, 0x5f, 0x10, 0x3a, 0x6d, 0xe5,
                ],
                [
                    0x75, 0xa4, 0xe9, 0x5a, 0xbf, 0x62, 0x1d, 0xba, 0x65, 0x6f, 0x8d, 0xfe, 0x05,
                    0x4f, 0xe6, 0xbf, 0xd8, 0x3b, 0xbd, 0xf7, 0xf5, 0x25, 0x9e, 0x2c, 0x8e, 0x0a,
                    0xb0, 0x27, 0x9e, 0x27, 0x37, 0x14,
                ],
            ]
        );
    }

    #[test]
    fn all_four_typed_spend_transitions_and_retries() {
        let mut rng = StdRng::seed_from_u64(0xAC7);
        let mut issuer = Issuer::<Mayo2>::generate(b"example/credits/epoch-1", &mut rng);
        let public = issuer.public_key().clone();
        let token: DirectToken<Mayo2> = issue_token(&issuer, &public, 100, &mut rng);
        public.verify_token(&token).unwrap();
        assert_eq!(
            token.prepare_spend(&public, 101, &mut rng).err(),
            Some(Error::InsufficientBalance)
        );

        // Direct -> direct.
        let (pending, request) = token.prepare_spend(&public, 10, &mut rng).unwrap();
        let response = issuer.spend(&request, &mut rng).unwrap();
        let retry = issuer.spend(&request, &mut rng).unwrap();
        assert_eq!(retry.signature, response.signature);
        let token: DirectToken<Mayo2> = pending.finish(&public, &request, &response).unwrap();
        assert_eq!(token.balance(), 90);

        // Direct -> deferred return.
        let (pending, request) = token
            .prepare_spend_with_deferred_return(&public, 20, &mut rng)
            .unwrap();
        let response = issuer
            .spend_with_deferred_return(&request, 7, &mut rng)
            .unwrap();
        assert_eq!(response.return_amount(), 7);
        let retry = issuer
            .spend_with_deferred_return(&request, 0, &mut rng)
            .unwrap();
        assert_eq!(retry.return_amount(), 7);
        assert_eq!(retry.signature, response.signature);
        let token: DeferredReturnToken<Mayo2> =
            pending.finish(&public, &request, &response).unwrap();
        assert_eq!(token.balance(), 77);

        // Deferred return -> deferred return.
        let (pending, request) = token
            .prepare_spend_with_deferred_return(&public, 10, &mut rng)
            .unwrap();
        let response = issuer
            .spend_with_deferred_return(&request, 4, &mut rng)
            .unwrap();
        let token: DeferredReturnToken<Mayo2> =
            pending.finish(&public, &request, &response).unwrap();
        assert_eq!(token.balance(), 71);

        // Deferred return -> direct, normalizing the old top-up.
        let (pending, request) = token.prepare_spend(&public, 11, &mut rng).unwrap();
        let response = issuer.spend(&request, &mut rng).unwrap();
        let token: DirectToken<Mayo2> = pending.finish(&public, &request, &response).unwrap();
        assert_eq!(token.balance(), 60);
        public.verify_token(&token).unwrap();
        assert_eq!(issuer.spent_count(), 4);
    }

    #[test]
    fn statements_bind_public_values_context_and_modes() {
        let mut rng = StdRng::seed_from_u64(0xB1AD);
        let mut issuer = Issuer::<Mayo2>::generate(b"binding-test/issuer-a", &mut rng);
        let public = issuer.public_key().clone();

        let (pending_issue, issue_request) = public.prepare_issue(100, &mut rng).unwrap();
        assert_eq!(
            issuer.issue(&issue_request, 99, &mut rng).unwrap_err(),
            Error::InvalidProof
        );
        let issue_response = issuer.issue(&issue_request, 100, &mut rng).unwrap();
        let token = pending_issue
            .finish(&public, &issue_request, &issue_response)
            .unwrap();

        let (_pending, request) = token.prepare_spend(&public, 35, &mut rng).unwrap();
        let mut wrong_spend = request.clone();
        wrong_spend.spend += 1;
        assert_eq!(
            issuer.spend(&wrong_spend, &mut rng).unwrap_err(),
            Error::InvalidProof
        );
        let mut wrong_nullifier = request.clone();
        wrong_nullifier.nullifier[0] ^= 1;
        assert_eq!(
            issuer.spend(&wrong_nullifier, &mut rng).unwrap_err(),
            Error::InvalidProof
        );
        let mut wrong_commitment = request.clone();
        wrong_commitment.fresh_commitment[0] += GF16::new(1);
        assert_eq!(
            issuer.spend(&wrong_commitment, &mut rng).unwrap_err(),
            Error::InvalidProof
        );

        // Re-tagging the input credential kind also changes the statement and
        // circuit shape, even when all serialized request fields are copied.
        let wrong_input_kind = TypedSpendRequest::<Mayo2, DeferredReturn, FixedSpend> {
            spend: request.spend,
            nullifier: request.nullifier,
            fresh_commitment: request.fresh_commitment.clone(),
            proof: request.proof.clone(),
            params: PhantomData,
        };
        assert_eq!(
            issuer.spend(&wrong_input_kind, &mut rng).unwrap_err(),
            Error::InvalidProof
        );

        // Re-tagging an ordinary request as deferred return does not verify:
        // the mode is bound into Fiat-Shamir independently of Rust's types.
        let wrong_mode = TypedSpendRequest::<Mayo2, Direct, DeferredReturnSpend> {
            spend: request.spend,
            nullifier: request.nullifier,
            fresh_commitment: request.fresh_commitment.clone(),
            proof: request.proof.clone(),
            params: PhantomData,
        };
        assert_eq!(
            issuer
                .spend_with_deferred_return(&wrong_mode, 0, &mut rng)
                .unwrap_err(),
            Error::InvalidProof
        );
        assert_eq!(issuer.spent_count(), 0);

        let (_pending, deferred_request) = token
            .prepare_spend_with_deferred_return(&public, 35, &mut rng)
            .unwrap();
        assert_eq!(
            issuer
                .spend_with_deferred_return(&deferred_request, 36, &mut rng)
                .unwrap_err(),
            Error::InvalidReturnAmount
        );
        assert_eq!(issuer.spent_count(), 0);

        let other = Issuer::<Mayo2>::generate(b"binding-test/issuer-b", &mut rng);
        assert_eq!(
            token.prepare_spend(other.public_key(), 1, &mut rng).err(),
            Some(Error::WrongContext)
        );
    }

    #[test]
    fn cross_mode_retry_and_signature_reinterpretation_are_rejected() {
        let mut rng = StdRng::seed_from_u64(0x70_7A);
        let mut issuer = Issuer::<Mayo2>::generate(b"mode-separation", &mut rng);
        let public = issuer.public_key().clone();
        let token = issue_token(&issuer, &public, 50, &mut rng);

        // A direct signature cannot be reinterpreted as a deferred-return
        // signature, even with a zero top-up.
        let retagged = Token::<Mayo2, DeferredReturn> {
            context: token.context,
            signature: token.signature.clone(),
            key: token.key,
            base_balance: token.base_balance,
            nonce: token.nonce,
            topup: 0,
            params: PhantomData,
        };
        assert_eq!(
            public.verify_token(&retagged).unwrap_err(),
            Error::InvalidSignature
        );

        let (_pending, request) = token.prepare_spend(&public, 20, &mut rng).unwrap();
        let response = issuer.spend(&request, &mut rng).unwrap();

        let cross_mode = TypedSpendRequest::<Mayo2, Direct, DeferredReturnSpend> {
            spend: request.spend,
            nullifier: request.nullifier,
            fresh_commitment: request.fresh_commitment.clone(),
            proof: request.proof.clone(),
            params: PhantomData,
        };
        assert_eq!(
            issuer
                .spend_with_deferred_return(&cross_mode, 0, &mut rng)
                .unwrap_err(),
            Error::NullifierAlreadySpent
        );

        let wrapper_target =
            signed_token_target::<Mayo2>(&public.inner.context, &request.fresh_commitment, 0);
        let evaluated = mayo::eval(&public.inner.mayo, &response.signature).unwrap();
        assert_eq!(evaluated, request.fresh_commitment);
        assert_ne!(evaluated, wrapper_target);
    }

    #[test]
    fn deferred_return_amount_is_signature_bound() {
        let mut rng = StdRng::seed_from_u64(0xD3FE_22ED);
        let mut issuer = Issuer::<Mayo2>::generate(b"return-binding", &mut rng);
        let public = issuer.public_key().clone();
        let token = issue_token(&issuer, &public, 50, &mut rng);

        let (pending, request) = token
            .prepare_spend_with_deferred_return(&public, 20, &mut rng)
            .unwrap();
        let mut response = issuer
            .spend_with_deferred_return(&request, 7, &mut rng)
            .unwrap();
        response.return_amount = 8;
        assert_eq!(
            pending.finish(&public, &request, &response).err(),
            Some(Error::InvalidSignature)
        );
    }

    #[test]
    fn full_u64_refund_is_exact_and_can_be_normalized() {
        let mut rng = StdRng::seed_from_u64(0xF011_0064);
        let mut issuer = Issuer::<Mayo2>::generate(b"full-refund-boundary", &mut rng);
        let public = issuer.public_key().clone();
        let token = issue_token(&issuer, &public, u64::MAX, &mut rng);

        let (pending, request) = token
            .prepare_spend_with_deferred_return(&public, u64::MAX, &mut rng)
            .unwrap();
        let response = issuer
            .spend_with_deferred_return(&request, u64::MAX, &mut rng)
            .unwrap();
        let token = pending.finish(&public, &request, &response).unwrap();
        assert_eq!(token.balance(), u64::MAX);

        let (pending, request) = token.prepare_spend(&public, u64::MAX, &mut rng).unwrap();
        let response = issuer.spend(&request, &mut rng).unwrap();
        let token: DirectToken<Mayo2> = pending.finish(&public, &request, &response).unwrap();
        assert_eq!(token.balance(), 0);
        public.verify_token(&token).unwrap();
    }

    #[test]
    fn canonical_wire_roundtrips_and_preserves_type_separation() {
        let mut rng = StdRng::seed_from_u64(0x5749_5245);
        let mut issuer = Issuer::<Mayo2>::generate(b"wire/credits/epoch-9", &mut rng);
        let public_bytes = issuer.public_key().to_bytes();
        let public = PublicKey::<Mayo2>::from_bytes(&public_bytes).unwrap();
        assert_eq!(public.to_bytes(), public_bytes);
        assert_eq!(public.context(), issuer.public_key().context());
        assert_eq!(
            PublicKey::<Mayo1>::from_bytes(&public_bytes).err(),
            Some(WireError::WrongParameterSet)
        );

        let key_bytes = issuer.key_bytes();
        let restored =
            Issuer::<Mayo2>::from_key_bytes_with_store(&key_bytes, MemoryNullifierStore::default())
                .unwrap();
        assert_eq!(restored.public_key().to_bytes(), public_bytes);
        assert_eq!(restored.key_bytes(), key_bytes);

        let (pending_issue, issue_request) = public.prepare_issue(90, &mut rng).unwrap();
        let pending_issue =
            PendingIssue::<Mayo2>::from_bytes(&public, &pending_issue.to_bytes()).unwrap();
        let issue_request = IssueRequest::<Mayo2>::from_bytes(&issue_request.to_bytes()).unwrap();
        let issue_response = issuer.issue(&issue_request, 90, &mut rng).unwrap();
        let issue_response =
            IssueResponse::<Mayo2>::from_bytes(&issue_response.to_bytes()).unwrap();
        let token = pending_issue
            .finish(&public, &issue_request, &issue_response)
            .unwrap();
        let token_bytes = token.to_bytes();
        let token = DirectToken::<Mayo2>::from_bytes(&public, &token_bytes).unwrap();
        let mut direct_with_topup = token_bytes;
        *direct_with_topup.last_mut().unwrap() = 1;
        assert_eq!(
            DirectToken::<Mayo2>::from_bytes(&public, &direct_with_topup).err(),
            Some(WireError::WrongArtifact)
        );

        let (pending, request) = token.prepare_spend(&public, 20, &mut rng).unwrap();
        let pending_bytes = pending.to_bytes();
        let request_bytes = request.to_bytes();
        let pending = PendingSpend::<Mayo2, Direct>::from_bytes(&public, &pending_bytes).unwrap();
        let request = SpendRequest::<Mayo2, Direct>::from_bytes(&request_bytes).unwrap();
        let response = issuer.spend(&request, &mut rng).unwrap();
        let response = SpendResponse::<Mayo2, Direct>::from_bytes(&response.to_bytes()).unwrap();
        let token = pending.finish(&public, &request, &response).unwrap();
        assert_eq!(token.balance(), 70);

        let record = issuer.store().get(&request.nullifier()).unwrap().unwrap();
        assert_eq!(
            RetryRecord::<Mayo2>::from_bytes(&record.to_bytes()).unwrap(),
            record
        );

        let (pending, deferred_request) = token
            .prepare_spend_with_deferred_return(&public, 30, &mut rng)
            .unwrap();
        let deferred_bytes = deferred_request.to_bytes();
        assert_eq!(
            SpendRequest::<Mayo2, Direct>::from_bytes(&deferred_bytes).unwrap_err(),
            WireError::WrongArtifact
        );
        let deferred_request =
            DeferredReturnSpendRequest::<Mayo2, Direct>::from_bytes(&deferred_bytes).unwrap();
        let response = issuer
            .spend_with_deferred_return(&deferred_request, 11, &mut rng)
            .unwrap();
        let response_bytes = response.to_bytes();
        assert_eq!(
            SpendResponse::<Mayo2, Direct>::from_bytes(&response_bytes).unwrap_err(),
            WireError::WrongArtifact
        );
        let response =
            DeferredReturnSpendResponse::<Mayo2, Direct>::from_bytes(&response_bytes).unwrap();
        let pending =
            PendingDeferredReturnSpend::<Mayo2, Direct>::from_bytes(&public, &pending.to_bytes())
                .unwrap();
        let deferred = pending
            .finish(&public, &deferred_request, &response)
            .unwrap();
        let deferred_bytes = deferred.to_bytes();
        assert_eq!(
            DirectToken::<Mayo2>::from_bytes(&public, &deferred_bytes).err(),
            Some(WireError::WrongArtifact)
        );
        let deferred = DeferredReturnToken::<Mayo2>::from_bytes(&public, &deferred_bytes).unwrap();
        assert_eq!(deferred.balance(), 51);

        let mut trailing = public_bytes.clone();
        trailing.push(0);
        assert!(PublicKey::<Mayo2>::from_bytes(&trailing).is_err());
        let mut trailing = key_bytes.clone();
        trailing.push(0);
        assert!(
            Issuer::<Mayo2>::from_key_bytes_with_store(&trailing, MemoryNullifierStore::default(),)
                .is_err()
        );
        let mut trailing = request_bytes.clone();
        trailing.push(0);
        assert!(SpendRequest::<Mayo2, Direct>::from_bytes(&trailing).is_err());
        let mut trailing = pending_bytes.clone();
        trailing.push(0);
        assert!(PendingSpend::<Mayo2, Direct>::from_bytes(&public, &trailing).is_err());
        let mut trailing = deferred_bytes;
        trailing.push(0);
        assert!(DeferredReturnToken::<Mayo2>::from_bytes(&public, &trailing).is_err());
    }

    struct FailingStore;

    impl NullifierStore<Mayo2> for FailingStore {
        fn get(&self, _nullifier: &[u8; 32]) -> Result<Option<RetryRecord<Mayo2>>, Error> {
            Ok(None)
        }

        fn insert_if_absent(
            &mut self,
            _nullifier: [u8; 32],
            _candidate: RetryRecord<Mayo2>,
        ) -> Result<RetryRecord<Mayo2>, Error> {
            Err(Error::StorageFailure)
        }
    }

    #[test]
    fn issuer_never_returns_a_signature_before_nullifier_persistence() {
        let mut rng = StdRng::seed_from_u64(0x00D0_A81E);
        let mut issuer = Issuer::<Mayo2, FailingStore>::generate_with_store(
            b"durability/failure",
            PerformanceProfile::Balanced,
            FailingStore,
            &mut rng,
        );
        let public = issuer.public_key().clone();
        let (pending, request) = public.prepare_issue(20, &mut rng).unwrap();
        let response = issuer.issue(&request, 20, &mut rng).unwrap();
        let token = pending.finish(&public, &request, &response).unwrap();
        let (_pending, request) = token.prepare_spend(&public, 5, &mut rng).unwrap();
        assert_eq!(
            issuer.spend(&request, &mut rng).unwrap_err(),
            Error::StorageFailure
        );
    }

    #[test]
    #[ignore = "performance characterization; run with --release -- --ignored --nocapture"]
    fn benchmark_profiles() {
        for profile in [
            PerformanceProfile::Compact,
            PerformanceProfile::Balanced,
            PerformanceProfile::LowLatency,
        ] {
            let mut rng = StdRng::seed_from_u64(0xAC7);
            let mut issuer = Issuer::<Mayo2>::generate_with_profile(
                b"benchmark/credits/epoch-1",
                profile,
                &mut rng,
            );
            let public = issuer.public_key().clone();

            let start = Instant::now();
            let (pending_issue, issue_request) = public.prepare_issue(100, &mut rng).unwrap();
            let issue_prove = start.elapsed();
            let start = Instant::now();
            let issue_response = issuer.issue(&issue_request, 100, &mut rng).unwrap();
            let issue_verify_sign = start.elapsed();
            let token = pending_issue
                .finish(&public, &issue_request, &issue_response)
                .unwrap();

            let start = Instant::now();
            let (pending_direct, direct_request) =
                token.prepare_spend(&public, 20, &mut rng).unwrap();
            let direct_prove = start.elapsed();
            let start = Instant::now();
            let direct_response = issuer.spend(&direct_request, &mut rng).unwrap();
            let direct_verify_sign = start.elapsed();
            let direct_token = pending_direct
                .finish(&public, &direct_request, &direct_response)
                .unwrap();

            let (pending_defer, defer_request) = direct_token
                .prepare_spend_with_deferred_return(&public, 20, &mut rng)
                .unwrap();
            let defer_response = issuer
                .spend_with_deferred_return(&defer_request, 5, &mut rng)
                .unwrap();
            let deferred_token = pending_defer
                .finish(&public, &defer_request, &defer_response)
                .unwrap();

            let start = Instant::now();
            let (_pending_redeem, redeem_request) =
                deferred_token.prepare_spend(&public, 10, &mut rng).unwrap();
            let deferred_input_prove = start.elapsed();
            let start = Instant::now();
            issuer.spend(&redeem_request, &mut rng).unwrap();
            let deferred_input_verify_sign = start.elapsed();

            eprintln!(
                "{profile:?}: issue prove={issue_prove:?}, verify+sign={issue_verify_sign:?}, payload={} bytes; direct-input spend prove={direct_prove:?}, verify+sign={direct_verify_sign:?}, payload={} bytes; deferred-input spend prove={deferred_input_prove:?}, verify+sign={deferred_input_verify_sign:?}, payload={} bytes",
                issue_request.proof.payload_len(),
                direct_request.proof.payload_len(),
                redeem_request.proof.payload_len(),
            );
        }
    }
}
