//! Client-side issuance: pending state, requests, and responses.

use super::*;

/// Client-side state retained while an issuance request is in flight.
pub struct PendingIssue<P: MayoParams = Mayo1> {
    pub(super) context: [u8; 32],
    pub(super) key: [u8; 32],
    pub(super) balance: u64,
    pub(super) nonce: [u8; 32],
    pub(super) commitment: Vec<GF16>,
    pub(super) params: PhantomData<P>,
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
    pub(super) commitment: Vec<GF16>,
    pub(super) proof: Proof,
    pub(super) params: PhantomData<P>,
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
            voleith::ProofDecodeError::UnsupportedVersion => WireError::UnsupportedVersion,
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
    pub(super) signature: Vec<GF16>,
    pub(super) params: PhantomData<P>,
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
