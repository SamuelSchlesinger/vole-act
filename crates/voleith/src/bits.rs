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

    /// Read the `w`-th 64-bit little-endian word (bits `[64w, 64w+64)`),
    /// zero-padded past the end of the vector.
    #[must_use]
    pub(crate) fn word64(&self, w: usize) -> u64 {
        let start = (w * 8).min(self.bytes.len());
        let end = (start + 8).min(self.bytes.len());
        let mut buf = [0u8; 8];
        buf[..end - start].copy_from_slice(&self.bytes[start..end]);
        u64::from_le_bytes(buf)
    }
}

/// Transpose a 128×128 bit matrix given as 128 `u128` rows (bit `i`,
/// LSB-first, is column `i`): `out[c]` bit `r` equals `rows[r]` bit `c`.
/// Built from four 64×64 tile transposes; branch-free and secret-independent.
pub(crate) fn transpose128(rows: &[u128; 128]) -> [u128; 128] {
    let mut tile_a = [0u64; 64]; // rows 0..64,   columns 0..64
    let mut tile_b = [0u64; 64]; // rows 0..64,   columns 64..128
    let mut tile_c = [0u64; 64]; // rows 64..128, columns 0..64
    let mut tile_d = [0u64; 64]; // rows 64..128, columns 64..128
    for i in 0..64 {
        tile_a[i] = rows[i] as u64;
        tile_b[i] = (rows[i] >> 64) as u64;
        tile_c[i] = rows[64 + i] as u64;
        tile_d[i] = (rows[64 + i] >> 64) as u64;
    }
    transpose64(&mut tile_a);
    transpose64(&mut tile_b);
    transpose64(&mut tile_c);
    transpose64(&mut tile_d);
    core::array::from_fn(|c| {
        if c < 64 {
            tile_a[c] as u128 | ((tile_c[c] as u128) << 64)
        } else {
            tile_b[c - 64] as u128 | ((tile_d[c - 64] as u128) << 64)
        }
    })
}

/// In-place transpose of a 64×64 bit matrix: bit `i` (LSB-first) of row `k`
/// moves to bit `k` of row `i`. Branch-free and secret-independent: the
/// access pattern and operation count depend only on the (public) dimensions.
pub(crate) fn transpose64(a: &mut [u64; 64]) {
    let mut j = 32usize;
    let mut m = 0x0000_0000_FFFF_FFFFu64;
    while j != 0 {
        let mut k = 0usize;
        while k < 64 {
            let t = ((a[k] >> j) ^ a[k + j]) & m;
            a[k] ^= t << j;
            a[k + j] ^= t;
            k = (k + j + 1) & !j;
        }
        j >>= 1;
        m ^= m << j;
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
    fn transpose64_is_transpose() {
        // Deterministic pseudo-random matrix; check the defining property
        // bit-by-bit and the involution A^TT = A.
        let mut state = 0x0123_4567_89AB_CDEFu64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let original: [u64; 64] = core::array::from_fn(|_| next());
        let mut t = original;
        transpose64(&mut t);
        for (row, row_word) in t.iter().enumerate() {
            for column in 0..64 {
                assert_eq!(
                    (row_word >> column) & 1,
                    (original[column] >> row) & 1,
                    "transpose bit ({row}, {column})"
                );
            }
        }
        transpose64(&mut t);
        assert_eq!(t, original);
    }

    #[test]
    fn transpose128_is_transpose() {
        let mut state = 0xFEED_FACE_CAFE_BEEFu64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let rows: [u128; 128] = core::array::from_fn(|_| next() as u128 | ((next() as u128) << 64));
        let t = transpose128(&rows);
        for (column, t_word) in t.iter().enumerate() {
            for (row, row_word) in rows.iter().enumerate() {
                assert_eq!(
                    (t_word >> row) & 1,
                    (row_word >> column) & 1,
                    "transpose bit ({row}, {column})"
                );
            }
        }
        let back = transpose128(&t);
        assert_eq!(back, rows);
    }

    #[test]
    fn word64_reads_and_pads() {
        let mut v = BitVec::zero(70);
        v.set(0, true);
        v.set(63, true);
        v.set(69, true);
        assert_eq!(v.word64(0), 1u64 | (1u64 << 63));
        assert_eq!(v.word64(1), 1u64 << 5);
        assert_eq!(v.word64(2), 0);
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
