//! Sealed credential-kind and settlement-mode markers, errors, and VOLE profiles.

use super::*;

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

/// A credential with zero return under the common salted wrapper.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Direct;

impl sealed::CredentialKind for Direct {}
impl CredentialKind for Direct {
    const TAG: &'static [u8] = b"direct-credential/v2";
    const HAS_TOPUP: bool = false;
    const WIRE_ID: u8 = 1;
}

/// A credential whose common salted target binds a hidden commitment and
/// deferred issuer-selected return amount.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeferredReturn;

impl sealed::CredentialKind for DeferredReturn {}
impl CredentialKind for DeferredReturn {
    const TAG: &'static [u8] = b"deferred-return-credential/v2";
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

/// Ordinary spend settlement: sign the common salted wrapper with zero return.
#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FixedSpend;

impl sealed::SettlementMode for FixedSpend {}
impl SettlementMode for FixedSpend {
    const TAG: &'static [u8] = b"fixed-spend/v2";
    const WIRE_ID: u8 = 1;
}

/// Deferred-return settlement: sign the fresh commitment and a later issuer
/// choice through the common salted target hash.
#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeferredReturnSpend;

impl sealed::SettlementMode for DeferredReturnSpend {}
impl SettlementMode for DeferredReturnSpend {
    const TAG: &'static [u8] = b"deferred-return-spend/v2";
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
    pub(super) const fn params(self) -> Params {
        match self {
            Self::Compact => PARAMS_128,
            Self::Balanced => PARAMS_128_BALANCED,
            Self::LowLatency => PARAMS_128_FAST,
        }
    }

    pub(super) const fn wire_id(self) -> u8 {
        match self {
            Self::Compact => 1,
            Self::Balanced => 2,
            Self::LowLatency => 3,
        }
    }

    pub(super) fn from_wire_id(id: u8) -> Result<Self, WireError> {
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

pub(super) fn proof_error(_: VoleithError) -> Error {
    Error::InvalidProof
}
