//! A minimal bit-vector utility used for VOLE coordinate vectors.

use sha3::digest::XofReader;
use zeroize::Zeroize;

/// A fixed-length bit vector, stored little-endian within bytes
/// (bit `t` is `bytes[t/8] >> (t%8) & 1`). Trailing bits of the final byte
/// are always zero, so `as_bytes` is a canonical encoding.
#[derive(Clone, PartialEq, Eq)]
pub struct BitVec {
    len: usize,
    bytes: Vec<u8>,
}

impl BitVec {
    /// A zeroed bit vector of length `len`.
    #[must_use]
    pub fn zero(len: usize) -> Self {
        BitVec {
            len,
            bytes: vec![0u8; len.div_ceil(8)],
        }
    }

    /// Fill a bit vector of length `len` from an extendable-output reader.
    pub fn from_xof(reader: &mut impl XofReader, len: usize) -> Self {
        let mut bytes = vec![0u8; len.div_ceil(8)];
        reader.read(&mut bytes);
        let mut bv = BitVec { len, bytes };
        bv.mask_tail();
        bv
    }

    /// Construct from raw little-endian bytes; returns `None` when the byte
    /// length or trailing-bit padding is not canonical for `len`.
    #[must_use]
    pub fn from_bytes(bytes: Vec<u8>, len: usize) -> Option<Self> {
        if bytes.len() != len.div_ceil(8) {
            return None;
        }
        let bv = BitVec { len, bytes };
        let mut canon = bv.clone();
        canon.mask_tail();
        (canon == bv).then_some(bv)
    }

    /// Zero any bits beyond `len` in the final byte.
    fn mask_tail(&mut self) {
        let used = self.len % 8;
        if used != 0
            && let Some(last) = self.bytes.last_mut()
        {
            *last &= (1u8 << used) - 1;
        }
    }

    /// Number of bits.
    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether the vector has zero length.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Read bit `t`.
    ///
    /// # Panics
    ///
    /// Panics when `t >= self.len()`, in release builds too: a silent
    /// out-of-range read would return a padding bit and break the canonical
    /// encoding invariant the transcript depends on.
    #[must_use]
    pub fn get(&self, t: usize) -> bool {
        assert!(t < self.len);
        (self.bytes[t / 8] >> (t % 8)) & 1 == 1
    }

    /// Set bit `t`.
    ///
    /// # Panics
    ///
    /// Panics when `t >= self.len()`, in release builds too: a silent
    /// out-of-range write could set a padding bit, producing a non-canonical
    /// `as_bytes()` that diverges from what a decoder would accept.
    pub fn set(&mut self, t: usize, v: bool) {
        assert!(t < self.len);
        let mask = 1u8 << (t % 8);
        if v {
            self.bytes[t / 8] |= mask;
        } else {
            self.bytes[t / 8] &= !mask;
        }
    }

    /// XOR another equal-length bit vector into this one.
    ///
    /// # Panics
    ///
    /// Panics when the lengths differ, in release builds too: silently
    /// truncating to the shorter vector would corrupt VOLE coordinates.
    pub fn xor_assign(&mut self, other: &BitVec) {
        assert_eq!(self.len, other.len);
        for (a, b) in self.bytes.iter_mut().zip(other.bytes.iter()) {
            *a ^= b;
        }
    }

    /// The canonical little-endian byte encoding.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl Zeroize for BitVec {
    fn zeroize(&mut self) {
        self.bytes.zeroize();
    }
}

impl core::fmt::Debug for BitVec {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "BitVec(len={})", self.len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_get_xor() {
        let mut a = BitVec::zero(19);
        a.set(0, true);
        a.set(18, true);
        assert!(a.get(0) && a.get(18) && !a.get(9));
        let mut b = BitVec::zero(19);
        b.set(18, true);
        b.set(9, true);
        a.xor_assign(&b);
        assert!(a.get(0) && !a.get(18) && a.get(9));
    }

    #[test]
    fn canonical_bytes() {
        let mut a = BitVec::zero(9);
        a.set(8, true);
        assert_eq!(a.as_bytes(), &[0x00, 0x01]);
        assert!(BitVec::from_bytes(vec![0x00, 0x01], 9).is_some());
        // Non-canonical: padding bit set.
        assert!(BitVec::from_bytes(vec![0x00, 0x02], 9).is_none());
        // Wrong length.
        assert!(BitVec::from_bytes(vec![0x00], 9).is_none());
    }
}
