//! Fiat–Shamir transcript over SHAKE256.
//!
//! A simple hash-chain transcript: every absorbed message updates a 32-byte
//! running state (with length framing and labels, so message boundaries are
//! unambiguous), and every challenge both derives output from the state and
//! ratchets it (so later challenges depend on earlier ones).

use sha3::Shake256;
use sha3::digest::{ExtendableOutput, Update, XofReader};

/// A Fiat–Shamir transcript.
pub struct Transcript {
    state: [u8; 32],
}

fn shake(parts: &[&[u8]], out: &mut [u8]) {
    let mut h = Shake256::default();
    for p in parts {
        h.update(p);
    }
    h.finalize_xof().read(out);
}

impl Transcript {
    /// Start a transcript for the given protocol label.
    #[must_use]
    pub fn new(protocol: &'static [u8]) -> Self {
        let mut state = [0u8; 32];
        shake(&[b"VOLE-ACT/fs/v1/init", protocol], &mut state);
        Transcript { state }
    }

    /// Absorb a labeled message.
    pub fn absorb(&mut self, label: &'static [u8], data: &[u8]) {
        let mut next = [0u8; 32];
        shake(
            &[
                b"VOLE-ACT/fs/v1/absorb",
                &self.state,
                &(label.len() as u64).to_le_bytes(),
                label,
                &(data.len() as u64).to_le_bytes(),
                data,
            ],
            &mut next,
        );
        self.state = next;
    }

    /// Derive `out.len()` challenge bytes and ratchet the state.
    pub fn challenge_bytes(&mut self, label: &'static [u8], out: &mut [u8]) {
        shake(&[b"VOLE-ACT/fs/v1/challenge", &self.state, label], out);
        self.ratchet(label);
    }

    /// Derive an unbounded challenge stream (XOF) and ratchet the state.
    ///
    /// Both parties must read the stream identically (same order, same
    /// lengths) for their challenges to agree.
    pub fn challenge_xof(&mut self, label: &'static [u8]) -> impl XofReader + use<> {
        let mut h = Shake256::default();
        h.update(b"VOLE-ACT/fs/v1/challenge");
        h.update(&self.state);
        h.update(label);
        let reader = h.finalize_xof();
        self.ratchet(label);
        reader
    }

    fn ratchet(&mut self, label: &'static [u8]) {
        let mut next = [0u8; 32];
        shake(&[b"VOLE-ACT/fs/v1/ratchet", &self.state, label], &mut next);
        self.state = next;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_and_order_sensitive() {
        let run = |msgs: &[(&'static [u8], &[u8])]| {
            let mut t = Transcript::new(b"test");
            for (l, d) in msgs {
                t.absorb(l, d);
            }
            let mut out = [0u8; 16];
            t.challenge_bytes(b"c", &mut out);
            out
        };
        let a = run(&[(b"x", b"1"), (b"y", b"2")]);
        let b = run(&[(b"x", b"1"), (b"y", b"2")]);
        let c = run(&[(b"y", b"2"), (b"x", b"1")]);
        let d = run(&[(b"x", b"12"), (b"y", b"")]);
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_ne!(a, d);
    }

    #[test]
    fn challenges_ratchet() {
        let mut t = Transcript::new(b"test");
        t.absorb(b"m", b"data");
        let mut c1 = [0u8; 16];
        t.challenge_bytes(b"c", &mut c1);
        let mut c2 = [0u8; 16];
        t.challenge_bytes(b"c", &mut c2);
        assert_ne!(c1, c2, "same label twice must give fresh challenges");
    }
}
