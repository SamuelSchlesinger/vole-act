//! Tokens, spend requests/responses, pending spends, and request digests.

use super::markers::proof_error;
use super::*;

/// A client-held anonymous credit token.
///
/// `K` is either [`Direct`] (the default/core format) or [`DeferredReturn`].
/// The marker is part of every request and response type, preventing artifacts
/// for the two credential formats from being mixed accidentally.
pub struct Token<P: MayoParams = Mayo1, K: CredentialKind = Direct> {
    pub(super) context: [u8; 32],
    pub(super) signature: Vec<GF16>,
    pub(super) key: [u8; 32],
    pub(super) base_balance: u64,
    pub(super) nonce: [u8; 32],
    pub(super) topup: u64,
    pub(super) salt: [u8; SALT_BYTES],
    pub(super) params: PhantomData<(P, K)>,
}

impl<P: MayoParams, K: CredentialKind> Drop for Token<P, K> {
    fn drop(&mut self) {
        self.context.zeroize();
        self.signature.zeroize();
        self.key.zeroize();
        self.base_balance.zeroize();
        self.nonce.zeroize();
        self.topup.zeroize();
        self.salt.zeroize();
    }
}

impl<P: MayoParams, K: CredentialKind> ZeroizeOnDrop for Token<P, K> {}

/// Core token format with a zero return in the common salted wrapper.
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
    /// The encoding contains the signature, signer salt, nullifier key,
    /// balance, and hiding nonce. It is secret local state, not a
    /// presentation message.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(128 + self.signature.len().div_ceil(2) + SALT_BYTES);
        wire::header(&mut out, WIRE_TOKEN, P::WIRE_ID, K::WIRE_ID, 0);
        out.extend_from_slice(&self.context);
        out.extend_from_slice(&wire::pack_nibbles(&self.signature));
        out.extend_from_slice(&self.key);
        out.extend_from_slice(&self.base_balance.to_le_bytes());
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.topup.to_le_bytes());
        out.extend_from_slice(&self.salt);
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
        let salt = decoder.array()?;
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
            salt,
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

    /// Prepare a spend whose final return is supplied by the issuer after the
    /// client fixes this proved request and before signer-salt generation. The
    /// response creates a deferred-return token.
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
            salt: &self.salt,
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
    pub(super) spend: u64,
    pub(super) nullifier: [u8; 32],
    pub(super) fresh_commitment: Vec<GF16>,
    pub(super) proof: Proof,
    pub(super) params: PhantomData<(P, K, S)>,
}

/// Request for an ordinary spend that produces a direct token.
pub type SpendRequest<P = Mayo1, K = Direct> = TypedSpendRequest<P, K, FixedSpend>;

/// Request for a spend whose issuer-selected return is supplied after the
/// client fixes the proved request and before signer-salt generation.
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
            voleith::ProofDecodeError::UnsupportedVersion => WireError::UnsupportedVersion,
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
    pub(super) signature: Vec<GF16>,
    pub(super) return_amount: u64,
    pub(super) salt: [u8; SALT_BYTES],
    pub(super) params: PhantomData<(P, K, S)>,
}

impl<P: MayoParams, K: CredentialKind, S: SettlementMode> Drop for TypedSpendResponse<P, K, S> {
    fn drop(&mut self) {
        self.signature.zeroize();
        self.return_amount.zeroize();
        self.salt.zeroize();
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
            salt: self.salt,
            params: PhantomData,
        }
    }
}

impl<P: MayoParams, K: CredentialKind, S: SettlementMode> TypedSpendResponse<P, K, S> {
    /// Encode this typed spend response canonically.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(24 + self.signature.len().div_ceil(2) + SALT_BYTES);
        wire::header(
            &mut out,
            WIRE_SPEND_RESPONSE,
            P::WIRE_ID,
            K::WIRE_ID,
            S::WIRE_ID,
        );
        out.extend_from_slice(&wire::pack_nibbles(&self.signature));
        out.extend_from_slice(&self.return_amount.to_le_bytes());
        out.extend_from_slice(&self.salt);
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
        let salt = decoder.array()?;
        decoder.finish()?;
        if S::WIRE_ID == FixedSpend::WIRE_ID && return_amount != 0 {
            return Err(WireError::InvalidEncoding);
        }
        Ok(Self {
            signature,
            return_amount,
            salt,
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
        let target = signed_token_target::<P>(&self.fresh_commitment, 0, &response.salt);
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
            topup: 0,
            salt: response.salt,
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
            &self.fresh_commitment,
            response.return_amount,
            &response.salt,
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
            salt: response.salt,
            params: PhantomData,
        })
    }
}

pub(super) fn derive_context<P: MayoParams>(
    application_context: &[u8],
    public_key_hash: &[u8; 32],
    profile: PerformanceProfile,
) -> [u8; 32] {
    let mut h = sha3::Shake256::default();
    h.update(b"VOLE-ACT/context/v5");
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

pub(super) fn issue_statement<P: MayoParams>(
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

pub(super) fn spend_statement<P: MayoParams, K: CredentialKind, S: SettlementMode>(
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

pub(super) fn spend_request_digest<P: MayoParams, K: CredentialKind, S: SettlementMode>(
    context: &[u8; 32],
    request: &TypedSpendRequest<P, K, S>,
) -> [u8; 32] {
    let mut h = sha3::Shake256::default();
    h.update(b"VOLE-ACT/spend-request-digest/v5");
    h.update(context);
    hash_framed(&mut h, &request.to_bytes());
    let mut out = [0u8; 32];
    h.finalize_xof().read(&mut out);
    out
}
