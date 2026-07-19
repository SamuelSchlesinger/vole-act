//! The non-interactive proof: orchestration of VOLE commitment, the
//! consistency check, the batched QuickSilver check, and Fiat–Shamir.
//!
//! ## Coordinate layout (ℓ̂ = ℓ + dλ)
//!
//! | range            | use                                   |
//! |------------------|---------------------------------------|
//! | `[0, ℓ)`         | witness bits                          |
//! | `[ℓ, ℓ+(d−1)λ)` | `d−1` QuickSilver polynomial masks |
//! | `[ℓ+(d−1)λ, ℓ+dλ)` | wide-consistency-hash mask       |
//!
//! ## Transcript order
//!
//! `public ∥ dims ∥ salt ∥ coms ∥ corrections ∥ d` → challenge `α`
//! (consistency coefficients) → `(ũ, ṽ)` → challenge `χ` (QuickSilver
//! coefficients) → `(U, W)` → challenge `Δ` → tree openings.
//!
//! The u-corrections are absorbed *before* `α` is derived (so any
//! chunk-inconsistency is fixed before the check coefficients are known),
//! and everything binding the witness is absorbed before `Δ`.
//!
//! ## Checks performed by the verifier
//!
//! 1. Vector-commitment openings against the τ tree commitments at `Δⱼ`.
//! 2. Consistency: a 128-bit, column-wise linear universal hash preserves
//!    `Q̃ = Ṽ + ũ·Δ` — forcing all small-VOLE repetitions to share
//!    one `u`. A scalar field hash is not sufficient here: a prover could
//!    otherwise target one `k`-bit challenge chunk with probability `2⁻ᵏ`.
//! 3. QuickSilver: `Σᵢ χᵢ·Bᵢ + Q* = W + U·Δ` over the witness-stage keys —
//!    forces every circuit constraint.

use crate::VoleithError;
use crate::backend::{
    Circuit, CountingBackend, ProverBackend, ProverConstraint, VerifierBackend, VerifierConstraint,
};
use crate::bits::BitVec;
use crate::transcript::Transcript;
use crate::vole::{Params, ProverVole, reconstruct_keys, split_delta};
use binary_fields::{BinaryField, GF2p128};
use rand_core::CryptoRngCore;
use sha3::digest::XofReader;
use vector_commit::{MAX_DEPTH, SALT_LEN, Seed, VcCommitment, VcOpening};
use zeroize::{Zeroize, Zeroizing};

const PROTOCOL_LABEL: &[u8] = b"VOLE-ACT/voleith/v1";
pub(crate) use crate::backend::MAX_DEGREE;
const PROOF_WIRE_MAGIC: &[u8; 4] = b"VITH";
const PROOF_WIRE_VERSION: u8 = 1;

/// Maximum canonical proof encoding accepted by [`Proof::from_bytes`].
///
/// The shipped ACT circuits are below 300 KiB.  The larger ceiling leaves
/// room for other circuits while preventing attacker-controlled length fields
/// from causing unbounded allocation before proof-shape validation.
pub const MAX_PROOF_WIRE_BYTES: usize = 16 * 1024 * 1024;

/// Failure to decode a canonical VOLE-in-the-head proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofDecodeError {
    /// The input is truncated, has a wrong type tag, contains a
    /// non-canonical bit vector, has impossible lengths, or has trailing data.
    InvalidEncoding,
    /// The encoded proof exceeds [`MAX_PROOF_WIRE_BYTES`].
    TooLarge,
    /// The artifact is a VOLE-in-the-head proof, but from a format version
    /// this library does not implement.
    UnsupportedVersion,
}

impl core::fmt::Display for ProofDecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidEncoding => write!(f, "invalid canonical proof encoding"),
            Self::TooLarge => write!(f, "proof encoding exceeds the configured limit"),
            Self::UnsupportedVersion => write!(f, "unsupported proof format version"),
        }
    }
}

impl std::error::Error for ProofDecodeError {}

/// A non-interactive VOLE-in-the-head proof.
#[derive(Clone, Debug)]
pub struct Proof {
    /// Per-proof salt for all PRG/hash domain separation (2λ bits, as in
    /// FAEST, so multi-instance seed-guessing attacks get no batching help).
    pub salt: [u8; SALT_LEN],
    /// Per-tree vector commitments.
    pub coms: Vec<VcCommitment>,
    /// u-corrections `c⁽ʲ⁾` for trees `2..τ`.
    pub corrections: Vec<BitVec>,
    /// Witness bit corrections `d_t = u_t ⊕ w_t`.
    pub d: BitVec,
    /// Consistency check: masked coefficient-hash of `u`.
    pub u_tilde: GF2p128,
    /// Consistency check: the 128 rows of the column-wise hash of the tag
    /// matrix. Each field element packs one 128-bit output row.
    pub v_tilde: Vec<GF2p128>,
    /// Masked coefficients of the batched QuickSilver polynomial, in
    /// low-to-high order. Its length is the circuit's maximum degree.
    pub qs_coefficients: Vec<GF2p128>,
    /// All-but-one openings of the τ trees.
    pub openings: Vec<VcOpening>,
}

impl Proof {
    /// Size of the proof's fixed-layout cryptographic payload in bytes.
    ///
    /// This counts every field, bit vector, seed, and commitment exactly once,
    /// but not container length prefixes a particular wire codec may add.
    #[must_use]
    pub fn payload_len(&self) -> usize {
        SALT_LEN
            + self.coms.len() * 32
            + self
                .corrections
                .iter()
                .map(|correction| correction.as_bytes().len())
                .sum::<usize>()
            + self.d.as_bytes().len()
            + 16
            + self.v_tilde.len() * 16
            + self.qs_coefficients.len() * 16
            + self
                .openings
                .iter()
                .map(|opening| opening.siblings.len() * 16 + 32)
                .sum::<usize>()
    }

    /// Encode this proof in the canonical, versioned wire format.
    ///
    /// Integer lengths are little-endian. Bit vectors carry their logical bit
    /// length and must have zero unused high bits; decoding rejects trailing
    /// bytes and all alternate encodings of the same proof.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.payload_len() + 128);
        out.extend_from_slice(PROOF_WIRE_MAGIC);
        out.push(PROOF_WIRE_VERSION);
        out.extend_from_slice(&self.salt);

        put_len(&mut out, self.coms.len());
        for commitment in &self.coms {
            out.extend_from_slice(&commitment.0);
        }

        put_len(&mut out, self.corrections.len());
        for correction in &self.corrections {
            put_bits(&mut out, correction);
        }
        put_bits(&mut out, &self.d);
        out.extend_from_slice(&self.u_tilde.to_bytes());

        put_len(&mut out, self.v_tilde.len());
        for row in &self.v_tilde {
            out.extend_from_slice(&row.to_bytes());
        }

        put_len(&mut out, self.qs_coefficients.len());
        for coefficient in &self.qs_coefficients {
            out.extend_from_slice(&coefficient.to_bytes());
        }

        put_len(&mut out, self.openings.len());
        for opening in &self.openings {
            put_len(&mut out, opening.siblings.len());
            for sibling in &opening.siblings {
                out.extend_from_slice(sibling);
            }
            out.extend_from_slice(&opening.hidden_com);
        }
        out
    }

    /// Decode a proof from the canonical, versioned wire format.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ProofDecodeError> {
        if bytes.len() > MAX_PROOF_WIRE_BYTES {
            return Err(ProofDecodeError::TooLarge);
        }
        let mut decoder = ProofDecoder::new(bytes);
        decoder.expect(PROOF_WIRE_MAGIC)?;
        if decoder.array::<1>()?[0] != PROOF_WIRE_VERSION {
            return Err(ProofDecodeError::UnsupportedVersion);
        }
        let salt = decoder.array()?;

        let com_count = decoder.count(32, 128)?;
        let mut coms = Vec::with_capacity(com_count);
        for _ in 0..com_count {
            coms.push(VcCommitment(decoder.array()?));
        }

        let correction_count = decoder.count(8, 127)?;
        let mut corrections = Vec::with_capacity(correction_count);
        for _ in 0..correction_count {
            corrections.push(decoder.bits()?);
        }
        let d = decoder.bits()?;
        let u_tilde = GF2p128::from_bytes(decoder.array()?);

        let v_count = decoder.count(16, 128)?;
        let mut v_tilde = Vec::with_capacity(v_count);
        for _ in 0..v_count {
            v_tilde.push(GF2p128::from_bytes(decoder.array()?));
        }

        let coefficient_count = decoder.count(16, MAX_DEGREE)?;
        let mut qs_coefficients = Vec::with_capacity(coefficient_count);
        for _ in 0..coefficient_count {
            qs_coefficients.push(GF2p128::from_bytes(decoder.array()?));
        }

        let opening_count = decoder.count(36, 128)?;
        let mut openings = Vec::with_capacity(opening_count);
        for _ in 0..opening_count {
            let sibling_count = decoder.count(16, MAX_DEPTH as usize)?;
            let mut siblings = Vec::with_capacity(sibling_count);
            for _ in 0..sibling_count {
                siblings.push(decoder.array()?);
            }
            openings.push(VcOpening {
                siblings,
                hidden_com: decoder.array()?,
            });
        }
        decoder.finish()?;
        Ok(Self {
            salt,
            coms,
            corrections,
            d,
            u_tilde,
            v_tilde,
            qs_coefficients,
            openings,
        })
    }
}

fn put_len(out: &mut Vec<u8>, len: usize) {
    let len = u32::try_from(len).expect("in-memory proof component exceeds wire format");
    out.extend_from_slice(&len.to_le_bytes());
}

fn put_bits(out: &mut Vec<u8>, bits: &BitVec) {
    let len = u64::try_from(bits.len()).expect("bit vector length exceeds wire format");
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(bits.as_bytes());
}

struct ProofDecoder<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> ProofDecoder<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, offset: 0 }
    }

    fn remaining(&self) -> usize {
        self.input.len() - self.offset
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], ProofDecodeError> {
        let end = self
            .offset
            .checked_add(len)
            .filter(|end| *end <= self.input.len())
            .ok_or(ProofDecodeError::InvalidEncoding)?;
        let out = &self.input[self.offset..end];
        self.offset = end;
        Ok(out)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], ProofDecodeError> {
        self.take(N)?
            .try_into()
            .map_err(|_| ProofDecodeError::InvalidEncoding)
    }

    fn expect(&mut self, expected: &[u8]) -> Result<(), ProofDecodeError> {
        if self.take(expected.len())? == expected {
            Ok(())
        } else {
            Err(ProofDecodeError::InvalidEncoding)
        }
    }

    fn u32(&mut self) -> Result<u32, ProofDecodeError> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, ProofDecodeError> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    fn count(
        &mut self,
        minimum_item_bytes: usize,
        absolute_maximum: usize,
    ) -> Result<usize, ProofDecodeError> {
        let count = usize::try_from(self.u32()?).map_err(|_| ProofDecodeError::InvalidEncoding)?;
        let maximum = self.remaining() / minimum_item_bytes.max(1);
        if count > maximum || count > absolute_maximum {
            return Err(ProofDecodeError::InvalidEncoding);
        }
        Ok(count)
    }

    fn bits(&mut self) -> Result<BitVec, ProofDecodeError> {
        let bit_len =
            usize::try_from(self.u64()?).map_err(|_| ProofDecodeError::InvalidEncoding)?;
        let byte_len = bit_len
            .checked_add(7)
            .ok_or(ProofDecodeError::InvalidEncoding)?
            / 8;
        let bytes = self.take(byte_len)?.to_vec();
        BitVec::from_bytes(bytes, bit_len).ok_or(ProofDecodeError::InvalidEncoding)
    }

    fn finish(self) -> Result<(), ProofDecodeError> {
        if self.offset == self.input.len() {
            Ok(())
        } else {
            Err(ProofDecodeError::InvalidEncoding)
        }
    }
}

/// Read one field element from a challenge stream.
fn next_elem(reader: &mut impl XofReader) -> GF2p128 {
    let mut buf = [0u8; 16];
    reader.read(&mut buf);
    GF2p128::from_bytes(buf)
}

/// Absorb the proof prologue (everything up to the first challenge) into the
/// transcript, identically on both sides.
#[allow(clippy::too_many_arguments)]
fn absorb_prologue(
    tr: &mut Transcript,
    public_input: &[u8],
    params: &Params,
    num_witness_bits: usize,
    max_degree: usize,
    salt: &[u8; SALT_LEN],
    coms: &[VcCommitment],
    corrections: &[BitVec],
    d: &BitVec,
) {
    tr.absorb(b"public", public_input);
    let mut dims = Vec::new();
    dims.extend_from_slice(&(params.tau as u64).to_le_bytes());
    dims.extend_from_slice(&(params.k as u64).to_le_bytes());
    dims.extend_from_slice(&(num_witness_bits as u64).to_le_bytes());
    dims.extend_from_slice(&(max_degree as u64).to_le_bytes());
    tr.absorb(b"dims", &dims);
    tr.absorb(b"salt", salt);
    for com in coms {
        tr.absorb(b"com", &com.0);
    }
    for c in corrections {
        tr.absorb(b"correction", c.as_bytes());
    }
    tr.absorb(b"witness-d", d.as_bytes());
}

/// Key for the wide linear universal hash used by the VOLE consistency
/// check. For input `(x₀, x₁)` with `x₁` exactly 128 bits, the hash is
///
/// `r₀·P_s(x₀) + r₁·P_t(x₀) + x₁`.
///
/// `P_s` and `P_t` parse 128-bit chunks of `x₀` as coefficients and
/// evaluate the resulting polynomial at independent random field points.
/// The two evaluations make the probability that a nonzero input reaches
/// `(0,0)` negligible; conditioned on either being nonzero, the random
/// linear combination is uniform in `F₂¹²⁸`. The final identity block makes
/// the hash perfectly hiding when `x₁` is uniform.
#[derive(Clone, Copy)]
struct WideHashKey {
    r0: GF2p128,
    r1: GF2p128,
    s: GF2p128,
    t: GF2p128,
}

impl WideHashKey {
    fn draw(reader: &mut impl XofReader) -> Self {
        Self {
            r0: next_elem(reader),
            r1: next_elem(reader),
            s: next_elem(reader),
            t: next_elem(reader),
        }
    }
}

/// Evaluate the wide hash on one bit-vector column.
///
/// The `x0` chunks start at multiples of 128 bits, so each is two aligned
/// 64-bit words of the vector (masked to the chunk's logical length —
/// identical to the definitional bit-by-bit gather).
fn wide_hash_bits(key: WideHashKey, input: &BitVec) -> GF2p128 {
    debug_assert!(input.len() >= 128);
    let x0_len = input.len() - 128;
    let mut hs = GF2p128::ZERO;
    let mut ht = GF2p128::ZERO;
    for base in (0..x0_len).step_by(128) {
        let take = (x0_len - base).min(128);
        let word = base / 64;
        let mut chunk = input.word64(word) as u128 | ((input.word64(word + 1) as u128) << 64);
        if take < 128 {
            chunk &= (1u128 << take) - 1;
        }
        let chunk = GF2p128::new(chunk);
        hs = hs * key.s + chunk;
        ht = ht * key.t + chunk;
    }
    let mut mask = 0u128;
    for bit in 0..128 {
        mask |= (input.get(x0_len + bit) as u128) << bit;
    }
    key.r0 * hs + key.r1 * ht + GF2p128::new(mask)
}

/// Apply the same wide hash to every column of an `input.len() × 128`
/// bit matrix whose rows are packed as field elements. The result uses the
/// same row-packed representation and therefore has exactly 128 elements.
///
/// The per-block column gather and the final row packing are 128×128 bit
/// transposes, done word-level; the arithmetic is unchanged.
fn wide_hash_rows(key: WideHashKey, input: &[GF2p128]) -> Vec<GF2p128> {
    debug_assert!(input.len() >= 128);
    let x0_len = input.len() - 128;
    let mut hs = [GF2p128::ZERO; 128];
    let mut ht = [GF2p128::ZERO; 128];

    for base in (0..x0_len).step_by(128) {
        let take = (x0_len - base).min(128);
        let mut rows = [0u128; 128];
        for (row, elem) in input[base..base + take].iter().enumerate() {
            rows[row] = elem.to_u128();
        }
        let columns = crate::bits::transpose128(&rows);
        for column in 0..128 {
            let chunk = GF2p128::new(columns[column]);
            hs[column] = hs[column] * key.s + chunk;
            ht[column] = ht[column] * key.t + chunk;
        }
    }

    let mixed: [u128; 128] =
        core::array::from_fn(|column| (key.r0 * hs[column] + key.r1 * ht[column]).to_u128());
    let packed_rows = crate::bits::transpose128(&mixed);
    let mut out = vec![GF2p128::ZERO; 128];
    for (row, packed) in out.iter_mut().enumerate() {
        *packed = GF2p128::new(packed_rows[row]) + input[x0_len + row];
    }
    out
}

/// Combine each of the QuickSilver mask coordinate groups into one
/// `F₂^λ`-valued VOLE: value `Σ X^b·u_b`, tag/key `Σ X^b·elem_b`.
fn qs_mask_groups(
    l: usize,
    lambda: usize,
    groups: usize,
    u: Option<&BitVec>,
    elems: &[GF2p128],
) -> Vec<(GF2p128, GF2p128)> {
    (0..groups)
        .map(|group| {
            let mut u_acc = GF2p128::ZERO;
            let mut e_acc = GF2p128::ZERO;
            for b in 0..lambda {
                let coordinate = l + group * lambda + b;
                let xb = GF2p128::new(1u128 << b);
                if let Some(u) = u
                    && u.get(coordinate)
                {
                    u_acc += xb;
                }
                e_acc += xb * elems[coordinate];
            }
            (u_acc, e_acc)
        })
        .collect()
}

fn align_and_accumulate(output: &mut [GF2p128], coefficients: &[GF2p128], weight: GF2p128) {
    let shift = output.len() - coefficients.len();
    for (index, coefficient) in coefficients.iter().enumerate() {
        output[shift + index] += weight * *coefficient;
    }
}

fn evaluate_polynomial(coefficients: &[GF2p128], point: GF2p128) -> GF2p128 {
    coefficients
        .iter()
        .rev()
        .fold(GF2p128::ZERO, |acc, coefficient| acc * point + *coefficient)
}

fn constraint_degree(constraint: &VerifierConstraint) -> usize {
    match constraint {
        VerifierConstraint::Simple(_) | VerifierConstraint::System(_) => 2,
        VerifierConstraint::Polynomial(_, degree) => *degree,
    }
}

fn verifier_constraint_evaluation(
    constraint: &VerifierConstraint,
    chi: &mut impl XofReader,
    delta: GF2p128,
) -> GF2p128 {
    match constraint {
        VerifierConstraint::Simple(value) => *value,
        VerifierConstraint::System(system) => {
            let phis: Vec<GF2p128> = (0..system.num_equations())
                .map(|_| next_elem(chi))
                .collect();
            system.fold(&phis, delta)
        }
        VerifierConstraint::Polynomial(value, _) => *value,
    }
}

/// Produce a proof that `circuit` is satisfied by `witness`.
///
/// `public_input` binds any public statement data (it is absorbed first).
/// The witness is the ordered list of bits the circuit's `witness_bit` calls
/// consume. Returns [`VoleithError::Unsatisfiable`] when the witness does not
/// satisfy the circuit.
pub fn prove<C: Circuit>(
    params: &Params,
    public_input: &[u8],
    circuit: &C,
    witness: &[bool],
    rng: &mut impl CryptoRngCore,
) -> Result<Proof, VoleithError> {
    prove_impl(params, public_input, circuit, witness, rng, true)
}

/// Core prover. When `enforce_satisfied` is false the satisfiability check is
/// skipped and a (necessarily-rejected) proof is produced anyway — used only
/// by soundness tests that must construct malicious proofs directly.
pub(crate) fn prove_impl<C: Circuit>(
    params: &Params,
    public_input: &[u8],
    circuit: &C,
    witness: &[bool],
    rng: &mut impl CryptoRngCore,
    enforce_satisfied: bool,
) -> Result<Proof, VoleithError> {
    params.validate()?;
    let lambda = params.lambda();

    // Size the circuit. `max_built_degree` covers every expression the
    // circuit constructs (asserted or not), so the inline expression storage
    // in the cryptographic backends can never overflow; only the *asserted*
    // degree sizes the VOLE, keeping the transcript of accepted circuits
    // unchanged.
    let mut counter = CountingBackend::default();
    circuit.build(&mut counter)?;
    let l = counter.witness_bits;
    let max_degree = counter.max_degree.max(2);
    if l == 0 {
        return Err(VoleithError::InvalidParameters);
    }
    if max_degree > MAX_DEGREE || counter.max_built_degree > MAX_DEGREE {
        return Err(VoleithError::InvalidParameters);
    }
    if witness.len() != l {
        return Err(VoleithError::WitnessMismatch);
    }
    let l_hat = l + max_degree * lambda;

    // Commit the VOLE correlations. The root seeds are wiped as soon as the
    // trees are expanded, on the error path too; the tree state and the
    // VOLE secrets wipe themselves on drop.
    let mut salt = [0u8; SALT_LEN];
    rng.fill_bytes(&mut salt);
    let mut roots: Vec<Seed> = vec![[0u8; 16]; params.tau];
    for r in roots.iter_mut() {
        rng.fill_bytes(r);
    }
    let vole_result = ProverVole::commit(&roots, &salt, l_hat, params);
    roots.zeroize();
    let mut vole = vole_result.map_err(|_| VoleithError::InvalidParameters)?;

    // Run the circuit: collects d corrections and constraint coefficients.
    // The constraint capacity from the counting pass guarantees no growth
    // reallocation while the vector holds secret coefficients.
    let mut backend = ProverBackend::new(witness, &vole.u, &vole.tags, counter.constraints);
    circuit.build(&mut backend)?;
    if backend.bits_used() != l || backend.constraints.len() != counter.constraints {
        return Err(VoleithError::WitnessMismatch);
    }
    if enforce_satisfied && !backend.satisfied {
        return Err(VoleithError::Unsatisfiable);
    }
    let mut d = BitVec::zero(l);
    for (t, bit) in backend.d.iter().enumerate() {
        d.set(t, *bit);
    }

    // Fiat-Shamir.
    let mut tr = Transcript::new(PROTOCOL_LABEL);
    absorb_prologue(
        &mut tr,
        public_input,
        params,
        l,
        max_degree,
        &salt,
        &vole.coms,
        &vole.corrections,
        &d,
    );

    // Consistency check.
    let mut alpha = tr.challenge_xof(b"alpha");
    let wide_key = WideHashKey::draw(&mut alpha);
    let u_tilde = wide_hash_bits(wide_key, &vole.u);
    let v_tilde = wide_hash_rows(wide_key, &vole.tags);
    let mut consist = Vec::with_capacity(16 + 16 * lambda);
    consist.extend_from_slice(&u_tilde.to_bytes());
    for row in &v_tilde {
        consist.extend_from_slice(&row.to_bytes());
    }
    tr.absorb(b"consistency", &consist);

    // QuickSilver batch. Quadratic systems draw their fold coefficients
    // from the same challenge stream, in emission order, before their χ.
    // The mask VOLEs and the raw per-constraint coefficients are secrets
    // (only their χ-weighted sums are published); wipe both.
    let mut chi = tr.challenge_xof(b"chi");
    let mut masks = qs_mask_groups(l, lambda, max_degree - 1, Some(&vole.u), &vole.tags);
    let mut qs_coefficients = vec![GF2p128::ZERO; max_degree];
    for (index, (mask_value, mask_tag)) in masks.iter().enumerate() {
        qs_coefficients[index] += *mask_tag;
        qs_coefficients[index + 1] += *mask_value;
    }
    for (mask_value, mask_tag) in masks.iter_mut() {
        mask_value.zeroize();
        mask_tag.zeroize();
    }
    drop(masks);
    // One reused stack scratch buffer for the per-constraint coefficients
    // (secret data; fully wiped on every exit path via `Zeroizing`).
    let mut coefficients = Zeroizing::new([GF2p128::ZERO; MAX_DEGREE + 1]);
    for constraint in &backend.constraints {
        let filled = match constraint {
            ProverConstraint::Simple(a0, a1) => {
                coefficients[0] = *a0;
                coefficients[1] = *a1;
                coefficients[2] = GF2p128::ZERO;
                3
            }
            ProverConstraint::System(sys) => {
                let phis: Vec<GF2p128> = (0..sys.num_equations())
                    .map(|_| next_elem(&mut chi))
                    .collect();
                let (a0, a1, error) = sys.fold(&phis);
                if enforce_satisfied && error != GF2p128::ZERO {
                    return Err(VoleithError::Unsatisfiable);
                }
                coefficients[0] = a0;
                coefficients[1] = a1;
                coefficients[2] = error;
                3
            }
            ProverConstraint::Polynomial(poly) => {
                coefficients[..poly.len()].copy_from_slice(poly.as_slice());
                poly.len()
            }
        };
        let x = next_elem(&mut chi);
        // The leading coefficient is the asserted circuit value. The prover
        // claims it is zero by omitting it; the verifier's evaluation retains
        // it and therefore detects a false claim at the final random point.
        align_and_accumulate(&mut qs_coefficients, &coefficients[..filled - 1], x);
    }
    let mut qs_bytes = Vec::with_capacity(16 * max_degree);
    for coefficient in &qs_coefficients {
        qs_bytes.extend_from_slice(&coefficient.to_bytes());
    }
    tr.absorb(b"quicksilver", &qs_bytes);

    // Final challenge and openings.
    let mut chall3 = [0u8; 16];
    tr.challenge_bytes(b"delta", &mut chall3);
    let (_delta, chunks) = split_delta(&chall3, params);
    let openings = vole
        .open(&chunks)
        .map_err(|_| VoleithError::InvalidParameters)?;

    // `vole` wipes `u` and the tags when it drops below; the published
    // commitments and corrections move into the proof first.
    Ok(Proof {
        salt,
        coms: core::mem::take(&mut vole.coms),
        corrections: core::mem::take(&mut vole.corrections),
        d,
        u_tilde,
        v_tilde,
        qs_coefficients,
        openings,
    })
}

/// Verify a proof against a circuit and public input.
pub fn verify<C: Circuit>(
    params: &Params,
    public_input: &[u8],
    circuit: &C,
    proof: &Proof,
) -> Result<(), VoleithError> {
    params.validate()?;
    let lambda = params.lambda();

    // Size the circuit and validate proof shape. The built-degree bound
    // mirrors the prover exactly, so a circuit is rejected by both sides or
    // by neither.
    let mut counter = CountingBackend::default();
    circuit.build(&mut counter)?;
    let l = counter.witness_bits;
    let max_degree = counter.max_degree.max(2);
    if l == 0 {
        return Err(VoleithError::InvalidParameters);
    }
    if max_degree > MAX_DEGREE || counter.max_built_degree > MAX_DEGREE {
        return Err(VoleithError::InvalidParameters);
    }
    let l_hat = l + max_degree * lambda;
    if proof.d.len() != l
        || proof.coms.len() != params.tau
        || proof.corrections.len() != params.tau - 1
        || proof.openings.len() != params.tau
        || proof.v_tilde.len() != lambda
        || proof.qs_coefficients.len() != max_degree
        || proof.corrections.iter().any(|c| c.len() != l_hat)
    {
        return Err(VoleithError::InvalidProof);
    }

    // Replay the transcript.
    let mut tr = Transcript::new(PROTOCOL_LABEL);
    absorb_prologue(
        &mut tr,
        public_input,
        params,
        l,
        max_degree,
        &proof.salt,
        &proof.coms,
        &proof.corrections,
        &proof.d,
    );
    let mut alpha = tr.challenge_xof(b"alpha");
    let wide_key = WideHashKey::draw(&mut alpha);
    let mut consist = Vec::with_capacity(16 + 16 * lambda);
    consist.extend_from_slice(&proof.u_tilde.to_bytes());
    for row in &proof.v_tilde {
        consist.extend_from_slice(&row.to_bytes());
    }
    tr.absorb(b"consistency", &consist);
    let mut chi = tr.challenge_xof(b"chi");
    let mut qs_bytes = Vec::with_capacity(16 * max_degree);
    for coefficient in &proof.qs_coefficients {
        qs_bytes.extend_from_slice(&coefficient.to_bytes());
    }
    tr.absorb(b"quicksilver", &qs_bytes);
    let mut chall3 = [0u8; 16];
    tr.challenge_bytes(b"delta", &mut chall3);
    let (delta, chunks) = split_delta(&chall3, params);

    // Reconstruct the u-stage keys from the openings.
    let keys = reconstruct_keys(
        &proof.salt,
        l_hat,
        params,
        &proof.coms,
        &proof.corrections,
        &chunks,
        &proof.openings,
    )
    .map_err(|_| VoleithError::InvalidProof)?;

    // Wide consistency check, row by row: Q̃ = Ṽ + ũ·Δ. Applying
    // one 128-bit universal hash column-wise prevents a prover from isolating
    // a malformed correction in a single k-bit challenge chunk.
    let key_tilde = wide_hash_rows(wide_key, &keys);
    let u_bits = proof.u_tilde.to_u128();
    for (row, key_row) in key_tilde.iter().enumerate().take(lambda) {
        let expected = if (u_bits >> row) & 1 == 1 {
            proof.v_tilde[row] + delta
        } else {
            proof.v_tilde[row]
        };
        if *key_row != expected {
            return Err(VoleithError::InvalidProof);
        }
    }

    // Witness-stage keys: K'_t = K_t + d_t·Δ.
    let wkeys: Vec<GF2p128> = keys
        .iter()
        .take(l)
        .enumerate()
        .map(|(t, &k)| if proof.d.get(t) { k + delta } else { k })
        .collect();

    // Run the circuit over keys.
    let mut backend = VerifierBackend::new(&wkeys, delta);
    circuit.build(&mut backend)?;
    if backend.bits_used() != l {
        return Err(VoleithError::WitnessMismatch);
    }

    // Degree-d QuickSilver check. Mask group j contributes `Δʲ·Kⱼ`,
    // pairing its tag with coefficient j and its value with j+1.
    // `Δ^i` is precomputed up to `max_degree`; every degree below is bounded
    // by the counting pass, so the table covers all lookups.
    let mut delta_pows = vec![GF2p128::ONE; max_degree + 1];
    for i in 1..=max_degree {
        delta_pows[i] = delta_pows[i - 1] * delta;
    }
    let mask_keys = qs_mask_groups(l, lambda, max_degree - 1, None, &keys);
    let mut acc = GF2p128::ZERO;
    for (degree, (_, key)) in mask_keys.into_iter().enumerate() {
        acc += key * delta_pows[degree];
    }
    for check in &backend.checks {
        let value = verifier_constraint_evaluation(check, &mut chi, delta);
        let x = next_elem(&mut chi);
        acc += x * value * delta_pows[max_degree - constraint_degree(check)];
    }
    if acc != evaluate_polynomial(&proof.qs_coefficients, delta) {
        return Err(VoleithError::InvalidProof);
    }

    Ok(())
}

#[cfg(test)]
mod soundness_tests {
    use super::*;
    use crate::backend::Backend;
    use crate::vole::PARAMS_128_FAST as PARAMS_128;
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    /// A circuit that asserts a single witness bit is zero. With a witness
    /// bit of 1 the statement is false; an honest prover would refuse, but a
    /// malicious one (via `prove_impl(.., false)`) still emits a proof — the
    /// verifier MUST reject it. This is the regression test for the
    /// `assert_zero`-not-enforced bug (Codex S5).
    struct AssertBitZero;

    impl Circuit for AssertBitZero {
        fn build<B: Backend>(&self, backend: &mut B) -> Result<(), VoleithError> {
            let b = backend.witness_bit()?;
            backend.assert_zero(&b);
            Ok(())
        }
    }

    #[test]
    fn false_linear_assertion_is_rejected() {
        let mut rng = StdRng::seed_from_u64(100);
        // Honest witness (bit = 0) verifies.
        let ok = prove_impl(&PARAMS_128, b"az", &AssertBitZero, &[false], &mut rng, true).unwrap();
        verify(&PARAMS_128, b"az", &AssertBitZero, &ok).unwrap();

        // Malicious proof over a false statement (bit = 1) must be rejected
        // by the verifier, across many transcripts (no lucky Δ).
        for seed in 0..8u64 {
            let mut rng = StdRng::seed_from_u64(1000 + seed);
            let bad =
                prove_impl(&PARAMS_128, b"az", &AssertBitZero, &[true], &mut rng, false).unwrap();
            assert_eq!(
                verify(&PARAMS_128, b"az", &AssertBitZero, &bad),
                Err(VoleithError::InvalidProof),
                "false assert_zero accepted at seed {seed}"
            );
        }
    }

    /// Exercise the exact degree used by the four-round Keccak checkpoints.
    struct DegreeSixteenZero;

    impl Circuit for DegreeSixteenZero {
        fn build<B: Backend>(&self, backend: &mut B) -> Result<(), VoleithError> {
            let bit = backend.witness_bit()?;
            let mut expression = backend.wire_expr(&bit);
            for _ in 0..4 {
                expression = backend.expr_mul(&expression, &expression);
            }
            backend.assert_expr_zero(&expression);
            Ok(())
        }
    }

    #[test]
    fn false_degree_sixteen_assertion_is_rejected() {
        let mut rng = StdRng::seed_from_u64(200);
        let ok = prove_impl(
            &PARAMS_128,
            b"degree-sixteen",
            &DegreeSixteenZero,
            &[false],
            &mut rng,
            true,
        )
        .unwrap();
        assert_eq!(ok.qs_coefficients.len(), 16);
        verify(&PARAMS_128, b"degree-sixteen", &DegreeSixteenZero, &ok).unwrap();

        for seed in 0..8u64 {
            let mut rng = StdRng::seed_from_u64(2000 + seed);
            let bad = prove_impl(
                &PARAMS_128,
                b"degree-sixteen",
                &DegreeSixteenZero,
                &[true],
                &mut rng,
                false,
            )
            .unwrap();
            assert_eq!(
                verify(&PARAMS_128, b"degree-sixteen", &DegreeSixteenZero, &bad,),
                Err(VoleithError::InvalidProof),
                "false degree-16 assertion accepted at seed {seed}"
            );
        }
    }

    /// Builds (and discards) an expression of degree `MAX_DEGREE + 1`
    /// without asserting it, then asserts an innocuous degree-2 relation.
    /// Regression for the inline expression storage: both `prove` and
    /// `verify` must reject this circuit cleanly (never panic), and they
    /// must reject it symmetrically.
    struct DiscardedOverDegree;

    impl Circuit for DiscardedOverDegree {
        fn build<B: Backend>(&self, backend: &mut B) -> Result<(), VoleithError> {
            let bit = backend.witness_bit()?;
            let base = backend.wire_expr(&bit);
            let mut expression = base.clone();
            for _ in 0..MAX_DEGREE {
                expression = backend.expr_mul(&expression, &base);
            }
            drop(expression);
            backend.assert_zero(&bit);
            Ok(())
        }
    }

    #[test]
    fn discarded_over_degree_expression_is_rejected_not_panicked() {
        let mut rng = StdRng::seed_from_u64(0xDD_0001);
        assert_eq!(
            prove_impl(
                &PARAMS_128,
                b"over-degree",
                &DiscardedOverDegree,
                &[false],
                &mut rng,
                true,
            )
            .unwrap_err(),
            VoleithError::InvalidParameters
        );

        // The verifier applies the same bound: an arbitrary well-formed proof
        // against this circuit is rejected as InvalidParameters, matching the
        // prover, before any proof material is inspected.
        let ok = prove_impl(&PARAMS_128, b"az", &AssertBitZero, &[false], &mut rng, true).unwrap();
        assert_eq!(
            verify(&PARAMS_128, b"over-degree", &DiscardedOverDegree, &ok),
            Err(VoleithError::InvalidParameters)
        );
    }

    struct DegreeDZero(usize);

    impl Circuit for DegreeDZero {
        fn build<B: Backend>(&self, backend: &mut B) -> Result<(), VoleithError> {
            let bit = backend.witness_bit()?;
            let base = backend.wire_expr(&bit);
            let mut expression = base.clone();
            for _ in 1..self.0 {
                expression = backend.expr_mul(&expression, &base);
            }
            backend.assert_expr_zero(&expression);
            Ok(())
        }
    }

    #[test]
    fn every_supported_polynomial_degree_rejects_a_false_statement() {
        for degree in 1..=MAX_DEGREE {
            let circuit = DegreeDZero(degree);
            let mut rng = StdRng::seed_from_u64(0xD3_0000 + degree as u64);
            let bad = prove_impl(
                &PARAMS_128,
                b"all-degrees",
                &circuit,
                &[true],
                &mut rng,
                false,
            )
            .unwrap();
            assert_eq!(
                verify(&PARAMS_128, b"all-degrees", &circuit, &bad),
                Err(VoleithError::InvalidProof),
                "false degree-{degree} assertion accepted"
            );
        }

        let mut rng = StdRng::seed_from_u64(0xD3_0011);
        assert_eq!(
            prove_impl(
                &PARAMS_128,
                b"degree-too-large",
                &DegreeDZero(MAX_DEGREE + 1),
                &[false],
                &mut rng,
                true,
            )
            .unwrap_err(),
            VoleithError::InvalidParameters
        );
    }
}
