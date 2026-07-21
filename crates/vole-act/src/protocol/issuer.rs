//! The issuer: proof verification, MAYO preimage sampling, and settlement.

use super::markers::proof_error;
use super::public_key::PublicInner;
use super::spend::{issue_statement, spend_request_digest, spend_statement};
use super::*;

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
    ///
    /// # Panics
    ///
    /// Panics when `application_context` exceeds
    /// [`MAX_APPLICATION_CONTEXT_BYTES`]: an oversized label is a
    /// configuration error, caught here rather than as an unencodable or
    /// undecodable key later.
    pub fn generate_with_store(
        application_context: &[u8],
        profile: PerformanceProfile,
        spent: Store,
        rng: &mut impl CryptoRngCore,
    ) -> Self {
        assert!(
            application_context.len() <= MAX_APPLICATION_CONTEXT_BYTES,
            "application context exceeds MAX_APPLICATION_CONTEXT_BYTES"
        );
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
        if application_context.len() > MAX_APPLICATION_CONTEXT_BYTES {
            return Err(WireError::InvalidEncoding);
        }
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
    /// `balance`, then sign a uniformly salted wrapper around its commitment.
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
        let (signature, salt) = self.sign_token_target(&request.commitment, 0, rng)?;
        Ok(IssueResponse {
            signature,
            salt,
            params: PhantomData,
        })
    }

    /// Verify and process an ordinary spend, signing the common salted wrapper
    /// with a zero return. Exact retries return the original salt and response.
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
        let (signature, salt) = self.sign_token_target(&request.fresh_commitment, 0, rng)?;
        let candidate = RetryRecord {
            request_digest: digest,
            response: RetryResponse::Direct { signature, salt },
            params: PhantomData,
        };
        let stored = self.spent.insert_if_absent(request.nullifier, candidate)?;
        Self::fixed_response(stored, digest)
    }

    /// Verify and process a deferred-return spend. On a first call, the issuer
    /// supplies `return_amount <= request.maximum_spend()` before verification;
    /// the bound is checked before the proof, while signing happens only after
    /// verification succeeds. Exact retries return the originally stored amount
    /// and signature before considering a newly supplied amount.
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
        let (signature, salt) =
            self.sign_token_target(&request.fresh_commitment, return_amount, rng)?;
        let candidate = RetryRecord {
            request_digest: digest,
            response: RetryResponse::DeferredReturn {
                signature,
                return_amount,
                salt,
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
            RetryResponse::Direct { signature, salt } => Ok(TypedSpendResponse {
                signature: signature.clone(),
                return_amount: 0,
                salt: *salt,
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
                salt,
            } => Ok(TypedSpendResponse {
                signature: signature.clone(),
                return_amount: *return_amount,
                salt: *salt,
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

    fn sign_token_target(
        &self,
        commitment: &[GF16],
        topup: u64,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Vec<GF16>, [u8; SALT_BYTES]), Error> {
        let mut salt = [0u8; SALT_BYTES];
        rng.fill_bytes(&mut salt);
        let target = signed_token_target::<P>(commitment, topup, &salt);
        let signature = mayo::spre(&self.secret, &target, rng).map_err(|_| Error::SigningFailed)?;
        Ok((signature, salt))
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
