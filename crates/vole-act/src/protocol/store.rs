//! Nullifier/retry records and the store abstraction with atomic retry semantics.

use super::*;

/// Persisted response for one consumed nullifier.
///
/// The record is intentionally independent of the calling Rust request type:
/// its request digest commits the input credential and settlement tags, while
/// `response` records which signature target won the atomic insertion race.
#[derive(Clone, PartialEq, Eq)]

pub struct RetryRecord<P: MayoParams = Mayo1> {
    pub(super) request_digest: [u8; 32],
    pub(super) response: RetryResponse,
    pub(super) params: PhantomData<P>,
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
    /// A zero-return signature under the common salted wrapper.
    Direct {
        /// MAYO preimage returned to the client.
        signature: Vec<GF16>,
        /// Uniform signer salt bound into the signed target.
        salt: [u8; SALT_BYTES],
    },
    /// A fresh-commitment/return signature under the common salted wrapper.
    DeferredReturn {
        /// MAYO preimage returned to the client.
        signature: Vec<GF16>,
        /// Issuer-selected return bound into the signed target.
        return_amount: u64,
        /// Uniform signer salt bound into the signed target.
        salt: [u8; SALT_BYTES],
    },
}

impl Drop for RetryResponse {
    fn drop(&mut self) {
        match self {
            Self::Direct { signature, salt } => {
                signature.zeroize();
                salt.zeroize();
            }
            Self::DeferredReturn {
                signature,
                return_amount,
                salt,
            } => {
                signature.zeroize();
                return_amount.zeroize();
                salt.zeroize();
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
        let (settlement, signature, return_amount, salt) = match &self.response {
            RetryResponse::Direct { signature, salt } => (FixedSpend::WIRE_ID, signature, 0, salt),
            RetryResponse::DeferredReturn {
                signature,
                return_amount,
                salt,
            } => (
                DeferredReturnSpend::WIRE_ID,
                signature,
                *return_amount,
                salt,
            ),
        };
        let mut out = Vec::with_capacity(56 + signature.len().div_ceil(2) + SALT_BYTES);
        wire::header(&mut out, WIRE_RETRY_RECORD, P::WIRE_ID, 0, settlement);
        out.extend_from_slice(&self.request_digest);
        out.extend_from_slice(&wire::pack_nibbles(signature));
        out.extend_from_slice(&return_amount.to_le_bytes());
        out.extend_from_slice(salt);
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
        let salt = decoder.array()?;
        decoder.finish()?;
        if !deferred && return_amount != 0 {
            return Err(WireError::InvalidEncoding);
        }
        let response = if deferred {
            RetryResponse::DeferredReturn {
                signature,
                return_amount,
                salt,
            }
        } else {
            RetryResponse::Direct { signature, salt }
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
/// Winner selection must depend only on the store's linearization order, not
/// on candidate contents. Rejected candidates contain secret salts and MAYO
/// preimages and must not be exposed through logs, telemetry, audit tables, or
/// any response path. The candidate security theorem additionally needs winner
/// scheduling independent of candidate-production timing (or external
/// election/serialization before signing); ordinary first-arrival races leave
/// a separate leakage proof obligation even when the store never inspects
/// candidate bytes.
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
    pub(super) records: HashMap<[u8; 32], RetryRecord<P>>,
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
