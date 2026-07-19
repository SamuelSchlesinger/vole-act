//! Native `Keccak-f[1600]` and the SHAKE256 sponge, with round-by-round
//! access.
//!
//! The ACT circuits prove SHAKE256 evaluations *inside* the NIZK, which
//! requires (a) a bit-level view of every permutation round to generate the
//! witness (the intermediate round states), and (b) an exactly matching
//! native implementation for everything computed in the clear. The `sha3`
//! crate exposes neither, so this module implements `Keccak-f[1600]` directly;
//! its output is tested against `sha3` to rule out divergence.
//!
//! State layout: 25 lanes `A[x + 5y]` of 64 bits each, lane bit `z` = bit
//! `64·(x + 5y) + z` of the 1600-bit state, matching FIPS 202's mapping of
//! the sponge's byte string into lanes (lane (x,y) little-endian).

/// Number of rounds in `Keccak-f[1600]`.
pub const ROUNDS: usize = 24;

/// The SHAKE256 rate in bytes (1088 bits).
pub const RATE_BYTES: usize = 136;

/// Round constants (ι step).
pub const RC: [u64; ROUNDS] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808a,
    0x8000000080008000,
    0x000000000000808b,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008a,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000a,
    0x000000008000808b,
    0x800000000000008b,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800a,
    0x800000008000000a,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
];

/// Rotation offsets for the ρ step, indexed `[x + 5y]`.
pub const RHO: [u32; 25] = [
    0, 1, 62, 28, 27, //
    36, 44, 6, 55, 20, //
    3, 10, 43, 25, 39, //
    41, 45, 15, 21, 8, //
    18, 2, 61, 56, 14,
];

/// A Keccak state: 25 little-endian 64-bit lanes.
pub type State = [u64; 25];

/// One round of `Keccak-f[1600]`.
#[must_use]
pub fn round(a: &State, rc: u64) -> State {
    // θ: column parities.
    let mut c = [0u64; 5];
    for (x, cx) in c.iter_mut().enumerate() {
        *cx = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
    }
    let mut d = [0u64; 5];
    for x in 0..5 {
        d[x] = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
    }
    let mut b = [0u64; 25];
    for y in 0..5 {
        for x in 0..5 {
            b[x + 5 * y] = a[x + 5 * y] ^ d[x];
        }
    }
    // ρ and π: rotate lanes, then permute lane positions:
    // B'[y, 2x+3y] = rot(B[x, y]).
    let mut p = [0u64; 25];
    for y in 0..5 {
        for x in 0..5 {
            let idx = x + 5 * y;
            let nx = y;
            let ny = (2 * x + 3 * y) % 5;
            p[nx + 5 * ny] = b[idx].rotate_left(RHO[idx]);
        }
    }
    // χ (the only nonlinear step, degree 2) and ι.
    let mut out = [0u64; 25];
    for y in 0..5 {
        for x in 0..5 {
            out[x + 5 * y] = p[x + 5 * y] ^ (!p[(x + 1) % 5 + 5 * y] & p[(x + 2) % 5 + 5 * y]);
        }
    }
    out[0] ^= rc;
    out
}

/// The full `Keccak-f[1600]` permutation.
#[must_use]
pub fn keccak_f(mut a: State) -> State {
    for rc in RC {
        a = round(&a, rc);
    }
    a
}

/// XOR a rate-sized block (136 bytes) into the state.
pub fn absorb_block(state: &mut State, block: &[u8; RATE_BYTES]) {
    // 136 = 17 lanes × 8 bytes; the trailing 0 bytes of the last u64 chunk
    // are handled by iterating whole lanes only.
    for (i, chunk) in block.chunks(8).enumerate().take(RATE_BYTES / 8) {
        let mut lane = [0u8; 8];
        lane.copy_from_slice(chunk);
        state[i] ^= u64::from_le_bytes(lane);
    }
}

/// Read `out.len() ≤ RATE_BYTES` bytes from the state (one squeeze).
pub fn squeeze_block(state: &State, out: &mut [u8]) {
    assert!(out.len() <= RATE_BYTES);
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = (state[i / 8] >> (8 * (i % 8))) as u8;
    }
}

/// Pad a message shorter than one rate block into a single final block
/// (SHAKE256 domain byte `0x1F`, final bit `0x80`).
///
/// # Panics
///
/// Panics when `msg` does not fit in one padded block (`len ≥ RATE_BYTES`).
#[must_use]
pub fn pad_single_block(msg: &[u8]) -> [u8; RATE_BYTES] {
    assert!(
        msg.len() < RATE_BYTES,
        "message must fit in one padded rate block"
    );
    let mut block = [0u8; RATE_BYTES];
    block[..msg.len()].copy_from_slice(msg);
    block[msg.len()] ^= 0x1F;
    block[RATE_BYTES - 1] ^= 0x80;
    block
}

/// SHAKE256 for arbitrary-length input and output, built from the pieces
/// above (used only in tests and small helpers; hot paths use the pieces
/// directly).
#[must_use]
pub fn shake256(msg: &[u8], out_len: usize) -> Vec<u8> {
    let mut state: State = [0; 25];
    // Absorb all full blocks, then the padded final block.
    let (blocks, remainder) = msg.as_chunks::<RATE_BYTES>();
    for block in blocks {
        absorb_block(&mut state, block);
        state = keccak_f(state);
    }
    let block = pad_single_block(remainder);
    absorb_block(&mut state, &block);
    state = keccak_f(state);
    // Squeeze.
    let mut out = vec![0u8; out_len];
    for piece in out.chunks_mut(RATE_BYTES) {
        squeeze_block(&state, piece);
        if piece.len() == RATE_BYTES {
            state = keccak_f(state);
        }
    }
    out
}

/// Bit `i` of the state (bit-endianness used by the circuits).
#[must_use]
pub fn state_bit(state: &State, i: usize) -> bool {
    (state[i / 64] >> (i % 64)) & 1 == 1
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha3::digest::{ExtendableOutput, Update, XofReader};

    fn reference_shake256(msg: &[u8], out_len: usize) -> Vec<u8> {
        let mut h = sha3::Shake256::default();
        h.update(msg);
        let mut out = vec![0u8; out_len];
        h.finalize_xof().read(&mut out);
        out
    }

    #[test]
    fn matches_sha3_crate() {
        for (msg_len, out_len) in [
            (0usize, 32usize),
            (1, 64),
            (17, 136),
            (135, 137),
            (136, 32),
            (200, 500),
            (1000, 39),
        ] {
            let msg: Vec<u8> = (0..msg_len).map(|i| (i * 7 + 3) as u8).collect();
            assert_eq!(
                shake256(&msg, out_len),
                reference_shake256(&msg, out_len),
                "mismatch at msg_len={msg_len}, out_len={out_len}"
            );
        }
    }

    #[test]
    fn state_bit_layout() {
        let mut state: State = [0; 25];
        state[3] = 1 << 17;
        assert!(state_bit(&state, 3 * 64 + 17));
        assert!(!state_bit(&state, 3 * 64 + 16));
    }
}
