//! ACT circuit construction and native witness generation.
//!
//! The circuit deliberately mirrors the statement in `docs/DESIGN.md`:
//! MAYO verification and two or three SHAKE256 evaluations are connected to
//! exact 64-bit balance equations. Direct credentials require the old and
//! fresh commitment hashes; deferred-return credentials add a wrapper hash
//! binding the old base commitment and issuer-selected top-up. Every secret
//! scalar is allocated as bits; GF(16) values are obtained only through the
//! canonical embedding into the VOLE tag field.

use crate::keccak::{self, RATE_BYTES, RC, RHO, State};
use binary_fields::{BinaryField, GF2p128, GF16, embed_gf16};
use mayo::{MayoParams, PublicKey as MayoPublicKey};
use std::marker::PhantomData;
use voleith::{Backend, Circuit, QuadTerm, VoleithError};

pub(crate) const CRED_DOMAIN: &[u8] = b"VOLE-ACT/credential/v2";
// Keep the wrapper below one SHAKE256 rate block even for MAYO5's 71-byte
// target: 20 + 32 + 71 + 8 = 131 < 136.  The circuit deliberately handles
// one absorb block so all parameter sets must satisfy this bound.
pub(crate) const DEFERRED_TOKEN_DOMAIN: &[u8] = b"VOLE-ACT/deferred/v2";
pub(crate) const BALANCE_BITS: usize = 64;
const KEY_BYTES: usize = 32;
const NONCE_BYTES: usize = 32;

/// Shape of the credential being presented by a spend circuit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InputCredentialKind {
    Direct,
    DeferredReturn,
}

#[derive(Clone)]
pub(crate) struct MayoTerm {
    pub r: usize,
    pub c: usize,
    pub coeffs: Vec<GF16>,
}

pub(crate) fn mayo_terms_and_hash<P: MayoParams>(
    pk: &MayoPublicKey<P>,
) -> (Vec<MayoTerm>, [u8; 32]) {
    use sha3::digest::{ExtendableOutput, Update, XofReader};

    let forms = pk.whipped_forms();
    let mut h = sha3::Shake256::default();
    h.update(b"VOLE-ACT/mayo-public-key/v1");
    h.update(&(P::N as u64).to_le_bytes());
    h.update(&(P::M as u64).to_le_bytes());
    h.update(&(P::O as u64).to_le_bytes());
    h.update(&(P::K as u64).to_le_bytes());
    for form in &forms {
        // One absorb of the row-major entry bytes per form: the identical
        // byte stream the per-entry loop produced, minus millions of
        // single-byte update calls.
        h.update(GF16::slice_as_bytes(form.entries()));
    }
    let mut public_key_hash = [0u8; 32];
    h.finalize_xof().read(&mut public_key_hash);

    let mut terms = Vec::new();
    let kn = P::KN;
    for r in 0..kn {
        let rows: Vec<&[GF16]> = forms
            .iter()
            .map(|form| &form.entries()[r * kn..(r + 1) * kn])
            .collect();
        for c in r..kn {
            let coeffs: Vec<GF16> = rows.iter().map(|row| row[c]).collect();
            if coeffs.iter().any(|coeff| *coeff != GF16::ZERO) {
                terms.push(MayoTerm { r, c, coeffs });
            }
        }
    }
    (terms, public_key_hash)
}

pub(crate) fn credential_message(
    context: &[u8; 32],
    key: &[u8; KEY_BYTES],
    balance: u64,
    nonce: &[u8; NONCE_BYTES],
) -> Vec<u8> {
    let mut msg = Vec::with_capacity(CRED_DOMAIN.len() + 32 + KEY_BYTES + 8 + NONCE_BYTES);
    msg.extend_from_slice(CRED_DOMAIN);
    msg.extend_from_slice(context);
    msg.extend_from_slice(key);
    msg.extend_from_slice(&balance.to_le_bytes());
    msg.extend_from_slice(nonce);
    debug_assert!(msg.len() < RATE_BYTES);
    msg
}

pub(crate) fn credential_target<P: MayoParams>(
    context: &[u8; 32],
    key: &[u8; KEY_BYTES],
    balance: u64,
    nonce: &[u8; NONCE_BYTES],
) -> Vec<GF16> {
    let bytes = keccak::shake256(
        &credential_message(context, key, balance, nonce),
        P::M.div_ceil(2),
    );
    (0..P::M)
        .map(|i| GF16::new((bytes[i / 2] >> (4 * (i % 2))) & 0x0f))
        .collect()
}

fn pack_gf16(values: &[GF16]) -> Vec<u8> {
    values
        .chunks(2)
        .map(|pair| pair[0].to_u8() | (pair.get(1).map_or(0, |v| v.to_u8()) << 4))
        .collect()
}

pub(crate) fn token_message<P: MayoParams>(
    context: &[u8; 32],
    commitment: &[GF16],
    topup: u64,
) -> Vec<u8> {
    debug_assert_eq!(commitment.len(), P::M);
    let packed = pack_gf16(commitment);
    let mut msg = Vec::with_capacity(DEFERRED_TOKEN_DOMAIN.len() + 32 + packed.len() + 8);
    msg.extend_from_slice(DEFERRED_TOKEN_DOMAIN);
    msg.extend_from_slice(context);
    msg.extend_from_slice(&packed);
    msg.extend_from_slice(&topup.to_le_bytes());
    debug_assert!(msg.len() < RATE_BYTES);
    msg
}

/// MAYO target binding the hidden base commitment and issuer-selected top-up.
pub(crate) fn signed_token_target<P: MayoParams>(
    context: &[u8; 32],
    commitment: &[GF16],
    topup: u64,
) -> Vec<GF16> {
    let bytes = keccak::shake256(
        &token_message::<P>(context, commitment, topup),
        P::M.div_ceil(2),
    );
    (0..P::M)
        .map(|i| GF16::new((bytes[i / 2] >> (4 * (i % 2))) & 0x0f))
        .collect()
}

pub(crate) fn derive_nullifier<P: MayoParams>(
    context: &[u8; 32],
    key: &[u8; KEY_BYTES],
    balance: u64,
    nonce: &[u8; NONCE_BYTES],
) -> [u8; 32] {
    // The credential target and nullifier are disjoint portions of one XOF
    // output. The issuer sees only the prefix at issuance; the suffix remains
    // pseudorandom until the client proves it at spend time. Sharing the
    // permutation removes one complete in-circuit SHAKE evaluation.
    let nullifier_offset = 4 * P::M;
    let output = keccak::shake256(
        &credential_message(context, key, balance, nonce),
        (nullifier_offset + 256).div_ceil(8),
    );
    let mut nullifier = [0u8; 32];
    for bit in 0..256 {
        let source = nullifier_offset + bit;
        nullifier[bit / 8] |= ((output[source / 8] >> (source % 8)) & 1) << (bit % 8);
    }
    nullifier
}

fn bytes_bits(bytes: &[u8]) -> Vec<bool> {
    bytes
        .iter()
        .flat_map(|byte| (0..8).map(move |bit| (byte >> bit) & 1 == 1))
        .collect()
}

fn gf16_bits(values: &[GF16]) -> Vec<bool> {
    values
        .iter()
        .flat_map(|value| (0..4).map(move |bit| (value.to_u8() >> bit) & 1 == 1))
        .collect()
}

fn u64_bits(value: u64) -> Vec<bool> {
    (0..BALANCE_BITS)
        .map(|bit| (value >> bit) & 1 == 1)
        .collect()
}

fn append_keccak_checkpoints(witness: &mut Vec<bool>, msg: &[u8]) {
    let block = keccak::pad_single_block(msg);
    let mut state: State = [0; 25];
    keccak::absorb_block(&mut state, &block);
    for (round_index, rc) in RC.iter().enumerate() {
        state = keccak::round(&state, *rc);
        if (round_index + 1) % 4 == 0 {
            witness.extend((0..1600).map(|bit| keccak::state_bit(&state, bit)));
        }
    }
}

fn alloc_bits<B: Backend>(backend: &mut B, count: usize) -> Result<Vec<B::Wire>, VoleithError> {
    (0..count).map(|_| backend.witness_bit()).collect()
}

fn constant_bit<B: Backend>(backend: &mut B, bit: bool) -> B::Wire {
    backend.constant(if bit { GF2p128::ONE } else { GF2p128::ZERO })
}

fn constant_bytes<B: Backend>(backend: &mut B, bytes: &[u8]) -> Vec<B::Wire> {
    bytes_bits(bytes)
        .into_iter()
        .map(|bit| constant_bit(backend, bit))
        .collect()
}

fn lift_gf16<B: Backend>(backend: &mut B, bits: &[B::Wire]) -> B::Wire {
    debug_assert_eq!(bits.len(), 4);
    let mut acc = backend.constant(GF2p128::ZERO);
    for (bit_index, bit) in bits.iter().enumerate() {
        let basis = embed_gf16(GF16::new(1 << bit_index));
        let term = backend.scale(basis, bit);
        acc = backend.add(&acc, &term);
    }
    acc
}

fn lift_nibbles<B: Backend>(backend: &mut B, bits: &[B::Wire]) -> Vec<B::Wire> {
    debug_assert_eq!(bits.len() % 4, 0);
    bits.chunks(4)
        .map(|nibble| lift_gf16(backend, nibble))
        .collect()
}

fn target_constant_bits<B: Backend>(backend: &mut B, target: &[GF16]) -> Vec<B::Wire> {
    gf16_bits(target)
        .into_iter()
        .map(|bit| constant_bit(backend, bit))
        .collect()
}

fn initial_sponge_state<B: Backend>(backend: &mut B, msg: &[B::Wire]) -> Vec<B::Wire> {
    debug_assert_eq!(msg.len() % 8, 0);
    debug_assert!(msg.len() / 8 < RATE_BYTES);
    let zero = backend.constant(GF2p128::ZERO);
    let one = backend.constant(GF2p128::ONE);
    let mut state = vec![zero; 1600];
    for (dst, src) in state.iter_mut().zip(msg.iter()) {
        *dst = src.clone();
    }
    let msg_byte = msg.len() / 8;
    for bit in 0..8 {
        if (0x1fu8 >> bit) & 1 == 1 {
            state[msg_byte * 8 + bit] = one.clone();
        }
    }
    state[RATE_BYTES * 8 - 1] = one;
    state
}

fn keccak_linear_expr<B: Backend>(backend: &mut B, state: &[B::Expr]) -> Vec<B::Expr> {
    let zero = backend.constant(GF2p128::ZERO);
    let zero = backend.wire_expr(&zero);
    let mut columns = vec![zero.clone(); 5 * 64];
    for x in 0..5 {
        for z in 0..64 {
            let mut parity = zero.clone();
            for y in 0..5 {
                parity = backend.expr_add(&parity, &state[64 * (x + 5 * y) + z]);
            }
            columns[64 * x + z] = parity;
        }
    }

    let mut theta = vec![zero.clone(); 1600];
    for y in 0..5 {
        for x in 0..5 {
            for z in 0..64 {
                let left = &columns[64 * ((x + 4) % 5) + z];
                let right = &columns[64 * ((x + 1) % 5) + ((z + 63) % 64)];
                let d = backend.expr_add(left, right);
                theta[64 * (x + 5 * y) + z] = backend.expr_add(&state[64 * (x + 5 * y) + z], &d);
            }
        }
    }

    theta
}

/// Index map for ρ and π: entry `64·lane + z` names the θ-state position
/// whose bit lands at `(lane, z)` after the rotation and lane permutation
/// (`B'[y, 2x+3y] = rot(B[x, y])`). Reading θ through this map avoids
/// materializing (and copying) the permuted expression vector each round.
fn pi_rho_index() -> [usize; 1600] {
    let mut index = [0usize; 1600];
    for y in 0..5 {
        for x in 0..5 {
            let source_lane = x + 5 * y;
            let target_x = y;
            let target_y = (2 * x + 3 * y) % 5;
            let target_lane = target_x + 5 * target_y;
            for z in 0..64 {
                let source_z = (z + 64 - RHO[source_lane] as usize) % 64;
                index[64 * target_lane + z] = 64 * source_lane + source_z;
            }
        }
    }
    index
}

fn keccak_round_expr<B: Backend>(backend: &mut B, state: &[B::Expr], rc: u64) -> Vec<B::Expr> {
    let theta = keccak_linear_expr(backend, state);
    let pi = pi_rho_index();
    let one = backend.constant(GF2p128::ONE);
    let one = backend.wire_expr(&one);
    let mut output = Vec::with_capacity(1600);
    for bit_index in 0..1600 {
        let lane = bit_index / 64;
        let z = bit_index % 64;
        let x = lane % 5;
        let y = lane / 5;
        let p0 = &theta[pi[64 * (x + 5 * y) + z]];
        let p1 = &theta[pi[64 * ((x + 1) % 5 + 5 * y) + z]];
        let p2 = &theta[pi[64 * ((x + 2) % 5 + 5 * y) + z]];
        let not_p1 = backend.expr_add(&one, p1);
        let product = backend.expr_mul(&not_p1, p2);
        let mut bit = backend.expr_add(p0, &product);
        if lane == 0 && (rc >> z) & 1 == 1 {
            bit = backend.expr_add(&bit, &one);
        }
        output.push(bit);
    }
    output
}

fn shake_degree16<B: Backend>(
    backend: &mut B,
    msg: &[B::Wire],
) -> Result<Vec<B::Wire>, VoleithError> {
    let mut state = initial_sponge_state(backend, msg);
    for group in 0..(RC.len() / 4) {
        let checkpoint = alloc_bits(backend, 1600)?;
        let mut expression: Vec<B::Expr> =
            state.iter().map(|wire| backend.wire_expr(wire)).collect();
        for round in 0..4 {
            expression = keccak_round_expr(backend, &expression, RC[4 * group + round]);
        }
        for (computed, committed) in expression.iter().zip(checkpoint.iter()) {
            let committed = backend.wire_expr(committed);
            let difference = backend.expr_add(computed, &committed);
            backend.assert_expr_zero(&difference);
        }
        state = checkpoint;
    }
    Ok(state)
}

fn shake_hidden_output<B: Backend>(
    backend: &mut B,
    msg: &[B::Wire],
    output_bits: usize,
) -> Result<Vec<B::Wire>, VoleithError> {
    let state = shake_degree16(backend, msg)?;
    Ok(state[..output_bits].to_vec())
}

fn shake_assert_output<B: Backend>(
    backend: &mut B,
    msg: &[B::Wire],
    expected: &[B::Wire],
) -> Result<(), VoleithError> {
    let state = shake_degree16(backend, msg)?;
    for (actual, expected) in state.iter().zip(expected.iter()) {
        let difference = backend.add(actual, expected);
        backend.assert_zero(&difference);
    }
    Ok(())
}

fn credential_wires<B: Backend>(
    backend: &mut B,
    context: &[u8; 32],
    key: &[B::Wire],
    balance: &[B::Wire],
    nonce: &[B::Wire],
) -> Vec<B::Wire> {
    let mut msg = constant_bytes(backend, CRED_DOMAIN);
    msg.extend(constant_bytes(backend, context));
    msg.extend(key.iter().cloned());
    msg.extend(balance.iter().cloned());
    msg.extend(nonce.iter().cloned());
    debug_assert_eq!(msg.len() % 8, 0);
    msg
}

fn token_wires<B: Backend>(
    backend: &mut B,
    context: &[u8; 32],
    commitment: &[B::Wire],
    topup: &[B::Wire],
) -> Vec<B::Wire> {
    debug_assert_eq!(topup.len(), BALANCE_BITS);
    let mut msg = constant_bytes(backend, DEFERRED_TOKEN_DOMAIN);
    msg.extend(constant_bytes(backend, context));
    msg.extend(commitment.iter().cloned());
    while !msg.len().is_multiple_of(8) {
        msg.push(constant_bit(backend, false));
    }
    msg.extend(topup.iter().cloned());
    debug_assert_eq!(msg.len() % 8, 0);
    msg
}

fn assert_u64_sum<B: Backend>(
    backend: &mut B,
    a: &[B::Wire],
    b: &[B::Wire],
    sum: &[B::Wire],
    carries: &[B::Wire],
) {
    debug_assert_eq!(a.len(), BALANCE_BITS);
    debug_assert_eq!(b.len(), BALANCE_BITS);
    debug_assert_eq!(sum.len(), BALANCE_BITS);
    debug_assert_eq!(carries.len(), BALANCE_BITS);
    let zero = backend.constant(GF2p128::ZERO);
    let mut carry_in = zero.clone();
    for bit in 0..BALANCE_BITS {
        let mut equation = backend.add(&a[bit], &b[bit]);
        equation = backend.add(&equation, &carry_in);
        equation = backend.add(&equation, &sum[bit]);
        backend.assert_zero(&equation);
        carry_in = carries[bit].clone();
    }

    // `carry_out = a·b + carry_in·(a+b)`. Fold all 64 quadratic carry
    // equations into one deferred system rather than allocating product wires.
    let mut terms = Vec::with_capacity(3 * BALANCE_BITS);
    let mut carry_in = zero;
    for bit in 0..BALANCE_BITS {
        let mut coefficient = vec![GF16::ZERO; BALANCE_BITS];
        coefficient[bit] = GF16::ONE;
        terms.push(QuadTerm {
            a: a[bit].clone(),
            b: b[bit].clone(),
            coeffs: coefficient.clone(),
        });
        terms.push(QuadTerm {
            a: carry_in.clone(),
            b: a[bit].clone(),
            coeffs: coefficient.clone(),
        });
        terms.push(QuadTerm {
            a: carry_in.clone(),
            b: b[bit].clone(),
            coeffs: coefficient,
        });
        carry_in = carries[bit].clone();
    }
    backend.assert_quad_system(terms, carries.to_vec());
    backend.assert_zero(&carry_in);
}

pub(crate) struct IssueCircuit<P: MayoParams> {
    pub context: [u8; 32],
    pub balance: u64,
    pub target: Vec<GF16>,
    pub params: PhantomData<P>,
}

impl<P: MayoParams> IssueCircuit<P> {
    pub(crate) fn witness(&self, key: &[u8; 32], nonce: &[u8; 32]) -> Vec<bool> {
        let mut witness = bytes_bits(key);
        witness.extend(bytes_bits(nonce));
        append_keccak_checkpoints(
            &mut witness,
            &credential_message(&self.context, key, self.balance, nonce),
        );
        witness
    }
}

impl<P: MayoParams> Circuit for IssueCircuit<P> {
    fn build<B: Backend>(&self, backend: &mut B) -> Result<(), VoleithError> {
        if self.target.len() != P::M {
            return Err(VoleithError::InvalidParameters);
        }
        let key = alloc_bits(backend, KEY_BYTES * 8)?;
        let nonce = alloc_bits(backend, NONCE_BYTES * 8)?;
        let balance = constant_bytes(backend, &self.balance.to_le_bytes());
        let msg = credential_wires(backend, &self.context, &key, &balance, &nonce);
        let target = target_constant_bits(backend, &self.target);
        shake_assert_output(backend, &msg, &target)
    }
}

pub(crate) struct SpendCircuit<'a, P: MayoParams> {
    pub terms: &'a [MayoTerm],
    pub context: [u8; 32],
    pub spend: u64,
    pub nullifier: [u8; 32],
    pub fresh_commitment: Vec<GF16>,
    pub input_kind: InputCredentialKind,
    pub params: PhantomData<P>,
}

pub(crate) struct SpendSecrets<'a> {
    pub signature: &'a [GF16],
    pub key: &'a [u8; 32],
    pub base_balance: u64,
    pub nonce: &'a [u8; 32],
    pub topup: u64,
    pub fresh_key: &'a [u8; 32],
    pub fresh_base_balance: u64,
    pub fresh_nonce: &'a [u8; 32],
}

impl<P: MayoParams> SpendCircuit<'_, P> {
    pub(crate) fn witness(&self, secrets: &SpendSecrets<'_>) -> Vec<bool> {
        let mut witness = gf16_bits(secrets.signature);
        witness.extend(bytes_bits(secrets.key));
        witness.extend(u64_bits(secrets.base_balance));
        witness.extend(bytes_bits(secrets.nonce));
        match self.input_kind {
            InputCredentialKind::Direct => {
                debug_assert_eq!(secrets.topup, 0);
            }
            InputCredentialKind::DeferredReturn => {
                witness.extend(u64_bits(secrets.topup));
                let effective_balance = secrets
                    .base_balance
                    .checked_add(secrets.topup)
                    .expect("a valid token balance cannot overflow");
                witness.extend(u64_bits(effective_balance));
            }
        }
        witness.extend(bytes_bits(secrets.fresh_key));
        witness.extend(u64_bits(secrets.fresh_base_balance));
        witness.extend(bytes_bits(secrets.fresh_nonce));

        if self.input_kind == InputCredentialKind::DeferredReturn {
            let mut carry = 0;
            for bit in 0..BALANCE_BITS {
                let a = (secrets.base_balance >> bit) & 1;
                let b = (secrets.topup >> bit) & 1;
                carry = (a & b) | (carry & (a ^ b));
                witness.push(carry == 1);
            }
        }
        let mut carry = 0;
        for bit in 0..BALANCE_BITS {
            let a = (secrets.fresh_base_balance >> bit) & 1;
            let b = (self.spend >> bit) & 1;
            carry = (a & b) | (carry & (a ^ b));
            witness.push(carry == 1);
        }

        let old_commitment = credential_target::<P>(
            &self.context,
            secrets.key,
            secrets.base_balance,
            secrets.nonce,
        );
        append_keccak_checkpoints(
            &mut witness,
            &credential_message(
                &self.context,
                secrets.key,
                secrets.base_balance,
                secrets.nonce,
            ),
        );
        if self.input_kind == InputCredentialKind::DeferredReturn {
            append_keccak_checkpoints(
                &mut witness,
                &token_message::<P>(&self.context, &old_commitment, secrets.topup),
            );
        }
        append_keccak_checkpoints(
            &mut witness,
            &credential_message(
                &self.context,
                secrets.fresh_key,
                secrets.fresh_base_balance,
                secrets.fresh_nonce,
            ),
        );
        witness
    }
}

impl<P: MayoParams> Circuit for SpendCircuit<'_, P> {
    fn build<B: Backend>(&self, backend: &mut B) -> Result<(), VoleithError> {
        if self.fresh_commitment.len() != P::M
            || (self.input_kind == InputCredentialKind::DeferredReturn
                && DEFERRED_TOKEN_DOMAIN.len() + 32 + P::M.div_ceil(2) + 8 >= RATE_BYTES)
        {
            return Err(VoleithError::InvalidParameters);
        }

        let signature_bits = alloc_bits(backend, 4 * P::KN)?;
        let signature = lift_nibbles(backend, &signature_bits);
        let key = alloc_bits(backend, KEY_BYTES * 8)?;
        let base_balance = alloc_bits(backend, BALANCE_BITS)?;
        let nonce = alloc_bits(backend, NONCE_BYTES * 8)?;
        let (topup, effective_balance) = match self.input_kind {
            InputCredentialKind::Direct => (None, None),
            InputCredentialKind::DeferredReturn => (
                Some(alloc_bits(backend, BALANCE_BITS)?),
                Some(alloc_bits(backend, BALANCE_BITS)?),
            ),
        };
        let fresh_key = alloc_bits(backend, KEY_BYTES * 8)?;
        let fresh_base_balance = alloc_bits(backend, BALANCE_BITS)?;
        let fresh_nonce = alloc_bits(backend, NONCE_BYTES * 8)?;
        let old_carries = match self.input_kind {
            InputCredentialKind::Direct => None,
            InputCredentialKind::DeferredReturn => Some(alloc_bits(backend, BALANCE_BITS)?),
        };
        let fresh_carries = alloc_bits(backend, BALANCE_BITS)?;

        let spend = constant_bytes(backend, &self.spend.to_le_bytes());
        match self.input_kind {
            InputCredentialKind::Direct => {
                // Exact unsigned addition with zero final carry:
                // `fresh_base + spend = old_balance`.
                assert_u64_sum(
                    backend,
                    &fresh_base_balance,
                    &spend,
                    &base_balance,
                    &fresh_carries,
                );
            }
            InputCredentialKind::DeferredReturn => {
                // Both equalities are exact unsigned integer additions with a
                // zero final carry:
                // `base + topup = effective = fresh_base + spend`.
                assert_u64_sum(
                    backend,
                    &base_balance,
                    topup.as_deref().expect("deferred top-up wires"),
                    effective_balance
                        .as_deref()
                        .expect("deferred effective-balance wires"),
                    old_carries.as_deref().expect("deferred carry wires"),
                );
                assert_u64_sum(
                    backend,
                    &fresh_base_balance,
                    &spend,
                    effective_balance
                        .as_deref()
                        .expect("deferred effective-balance wires"),
                    &fresh_carries,
                );
            }
        }

        let old_msg = credential_wires(backend, &self.context, &key, &base_balance, &nonce);
        let old_output = shake_hidden_output(backend, &old_msg, 4 * P::M + 256)?;
        let old_commitment_bits = &old_output[..4 * P::M];

        let signed_target = match self.input_kind {
            InputCredentialKind::Direct => lift_nibbles(backend, old_commitment_bits),
            InputCredentialKind::DeferredReturn => {
                // Deferred-return credentials authenticate a nested hash of
                // the hidden base commitment and hidden issuer-selected
                // top-up.
                let token_msg = token_wires(
                    backend,
                    &self.context,
                    old_commitment_bits,
                    topup.as_deref().expect("deferred top-up wires"),
                );
                let signed_target_bits = shake_hidden_output(backend, &token_msg, 4 * P::M)?;
                lift_nibbles(backend, &signed_target_bits)
            }
        };

        let mayo_terms = self
            .terms
            .iter()
            .map(|term| QuadTerm {
                a: signature[term.r].clone(),
                b: signature[term.c].clone(),
                coeffs: term.coeffs.clone(),
            })
            .collect();
        backend.assert_quad_system(mayo_terms, signed_target);

        let expected_null = constant_bytes(backend, &self.nullifier);
        for (actual, expected) in old_output[4 * P::M..].iter().zip(expected_null.iter()) {
            let difference = backend.add(actual, expected);
            backend.assert_zero(&difference);
        }

        let fresh_msg = credential_wires(
            backend,
            &self.context,
            &fresh_key,
            &fresh_base_balance,
            &fresh_nonce,
        );
        let expected_commitment = target_constant_bits(backend, &self.fresh_commitment);
        shake_assert_output(backend, &fresh_msg, &expected_commitment)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mayo::Mayo5;

    #[test]
    fn largest_deferred_wrapper_fits_one_rate_block() {
        assert!(
            DEFERRED_TOKEN_DOMAIN.len() + 32 + Mayo5::M.div_ceil(2) + 8 < RATE_BYTES,
            "MAYO5 deferred wrapper must fit the circuit's single absorb block"
        );
    }

    #[test]
    fn circuit_keccak_rotation_convention_matches_native() {
        // The public native implementation is already checked against the
        // `sha3` crate. This test protects the less obvious rotate-left bit
        // indexing used by the circuit's rho step.
        let mut input: State = [0; 25];
        for (lane, value) in input.iter_mut().enumerate() {
            *value = (lane as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15);
        }
        let mut theta = [0u64; 25];
        let mut columns = [0u64; 5];
        for x in 0..5 {
            columns[x] = input[x] ^ input[x + 5] ^ input[x + 10] ^ input[x + 15] ^ input[x + 20];
        }
        for y in 0..5 {
            for x in 0..5 {
                theta[x + 5 * y] =
                    input[x + 5 * y] ^ columns[(x + 4) % 5] ^ columns[(x + 1) % 5].rotate_left(1);
            }
        }
        for lane in 0..25 {
            for z in 0..64 {
                let source_z = (z + 64 - RHO[lane] as usize) % 64;
                assert_eq!(
                    (theta[lane].rotate_left(RHO[lane]) >> z) & 1,
                    (theta[lane] >> source_z) & 1
                );
            }
        }
    }
}
