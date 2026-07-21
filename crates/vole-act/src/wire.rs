//! Canonical protocol encodings.
//!
//! Every artifact begins with a versioned envelope and explicit parameter,
//! credential-kind, and settlement identifiers. Decoders reject trailing
//! bytes, non-canonical nibble padding, oversized inputs, and unmodified
//! wrong-type tags. Envelope identifiers are typed discriminants, not
//! authenticators: retagged identical-layout bodies may parse, while proof
//! statements, request digests, and token semantics provide end-to-end binding.

use binary_fields::GF16;

pub(crate) const MAGIC: &[u8; 4] = b"VACT";
pub(crate) const WIRE_VERSION: u8 = 2;

/// Largest individual VOLE-ACT artifact accepted by a canonical decoder.
pub const MAX_WIRE_BYTES: usize = 32 * 1024 * 1024;

/// Failure to decode or authenticate a canonical protocol artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireError {
    /// The byte string is truncated, has impossible lengths, has nonzero
    /// nibble padding, or contains trailing data.
    InvalidEncoding,
    /// The envelope describes a different request, response, state, or token
    /// kind than the decoder requested.
    WrongArtifact,
    /// The envelope names a different MAYO parameter set.
    WrongParameterSet,
    /// The artifact exceeds [`MAX_WIRE_BYTES`].
    TooLarge,
    /// A decoded local token failed cryptographic authentication.
    InvalidCredential,
    /// The artifact is a VOLE-ACT encoding, but from a wire-format version
    /// this library does not implement.
    UnsupportedVersion,
}

impl core::fmt::Display for WireError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidEncoding => write!(f, "invalid canonical VOLE-ACT encoding"),
            Self::WrongArtifact => write!(f, "wrong VOLE-ACT artifact type"),
            Self::WrongParameterSet => write!(f, "wrong MAYO parameter set"),
            Self::TooLarge => write!(f, "VOLE-ACT artifact exceeds the configured limit"),
            Self::InvalidCredential => write!(f, "decoded credential is not authentic"),
            Self::UnsupportedVersion => write!(f, "unsupported VOLE-ACT wire-format version"),
        }
    }
}

impl std::error::Error for WireError {}

pub(crate) fn header(
    out: &mut Vec<u8>,
    artifact: u8,
    parameter_set: u8,
    credential_kind: u8,
    settlement: u8,
) {
    out.extend_from_slice(MAGIC);
    out.push(WIRE_VERSION);
    out.extend_from_slice(&[artifact, parameter_set, credential_kind, settlement]);
}

pub(crate) fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    let len = u32::try_from(bytes.len()).expect("wire component exceeds u32 length");
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(bytes);
}

pub(crate) fn pack_nibbles(values: &[GF16]) -> Vec<u8> {
    let mut out = Vec::with_capacity(values.len().div_ceil(2));
    for (index, value) in values.iter().enumerate() {
        if index.is_multiple_of(2) {
            out.push(value.to_u8());
        } else {
            *out.last_mut().expect("odd nibble follows an even nibble") |= value.to_u8() << 4;
        }
    }
    out
}

pub(crate) struct Decoder<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> Decoder<'a> {
    pub(crate) fn new(
        input: &'a [u8],
        artifact: u8,
        parameter_set: u8,
        credential_kind: u8,
        settlement: u8,
    ) -> Result<Self, WireError> {
        if input.len() > MAX_WIRE_BYTES {
            return Err(WireError::TooLarge);
        }
        let mut decoder = Self { input, offset: 0 };
        if decoder.take(MAGIC.len())? != MAGIC {
            return Err(WireError::InvalidEncoding);
        }
        if decoder.u8()? != WIRE_VERSION {
            return Err(WireError::UnsupportedVersion);
        }
        let actual = decoder.array::<4>()?;
        if actual != [artifact, parameter_set, credential_kind, settlement] {
            if actual[1] != parameter_set {
                return Err(WireError::WrongParameterSet);
            }
            return Err(WireError::WrongArtifact);
        }
        Ok(decoder)
    }

    pub(crate) fn take(&mut self, len: usize) -> Result<&'a [u8], WireError> {
        let end = self
            .offset
            .checked_add(len)
            .filter(|end| *end <= self.input.len())
            .ok_or(WireError::InvalidEncoding)?;
        let output = &self.input[self.offset..end];
        self.offset = end;
        Ok(output)
    }

    pub(crate) fn array<const N: usize>(&mut self) -> Result<[u8; N], WireError> {
        self.take(N)?
            .try_into()
            .map_err(|_| WireError::InvalidEncoding)
    }

    pub(crate) fn u8(&mut self) -> Result<u8, WireError> {
        Ok(self.array::<1>()?[0])
    }

    pub(crate) fn u32(&mut self) -> Result<u32, WireError> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    pub(crate) fn u64(&mut self) -> Result<u64, WireError> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    pub(crate) fn bytes(&mut self) -> Result<&'a [u8], WireError> {
        let len = usize::try_from(self.u32()?).map_err(|_| WireError::InvalidEncoding)?;
        self.take(len)
    }

    pub(crate) fn nibbles(&mut self, count: usize) -> Result<Vec<GF16>, WireError> {
        let byte_len = count.checked_add(1).ok_or(WireError::InvalidEncoding)? / 2;
        let bytes = self.take(byte_len)?;
        if count % 2 == 1 && bytes.last().is_some_and(|byte| byte & 0xf0 != 0) {
            return Err(WireError::InvalidEncoding);
        }
        Ok((0..count)
            .map(|index| {
                let byte = bytes[index / 2];
                GF16::new(if index.is_multiple_of(2) {
                    byte & 0x0f
                } else {
                    byte >> 4
                })
            })
            .collect())
    }

    pub(crate) fn finish(self) -> Result<(), WireError> {
        if self.offset == self.input.len() {
            Ok(())
        } else {
            Err(WireError::InvalidEncoding)
        }
    }
}
