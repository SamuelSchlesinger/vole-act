//! The issuer public key and its derived circuit terms and context.

use super::markers::proof_error;
use super::spend::issue_statement;
use super::*;

pub(super) struct PublicInner<P: MayoParams> {
    pub(super) mayo: MayoPublicKey<P>,
    pub(super) terms: MayoTermTable,
    pub(super) context: [u8; 32],
    pub(super) profile: PerformanceProfile,
    pub(super) application_context: Vec<u8>,
}

/// Issuer public key and precomputed MAYO circuit representation.
///
/// Cloning this type is cheap: the large public key and quadratic term table
/// are reference-counted.
pub struct PublicKey<P: MayoParams = Mayo1> {
    pub(super) inner: Arc<PublicInner<P>>,
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
        if application_context.len() > MAX_APPLICATION_CONTEXT_BYTES {
            return Err(WireError::InvalidEncoding);
        }
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
