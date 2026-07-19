//! End-to-end tests of the VOLE-in-the-head NIZK on small circuits.

use binary_fields::{BinaryField, GF2p128, GF16, embed_gf16};
use rand::RngCore;
use rand::SeedableRng;
use rand::rngs::StdRng;
use voleith::{Backend, Circuit, PARAMS_128_BALANCED as PARAMS_128, VoleithError, prove, verify};

/// Lift 4 committed bits into an F₁₆-valued wire via the embedding.
fn lift_gf16<B: Backend>(backend: &mut B, bits: &[B::Wire; 4]) -> B::Wire {
    let mut acc = backend.constant(GF2p128::ZERO);
    for (b, bit) in bits.iter().enumerate() {
        let basis = embed_gf16(GF16::new(1 << b));
        let term = backend.scale(basis, bit);
        acc = backend.add(&acc, &term);
    }
    acc
}

/// Prove knowledge of `x ∈ GF(16)` with `x² + x = c` for public `c`.
struct QuadraticCircuit {
    c: GF16,
}

impl Circuit for QuadraticCircuit {
    fn build<B: Backend>(&self, backend: &mut B) -> Result<(), VoleithError> {
        let bits: [B::Wire; 4] = [
            backend.witness_bit()?,
            backend.witness_bit()?,
            backend.witness_bit()?,
            backend.witness_bit()?,
        ];
        // Bit-ness: b·b = b.
        for bit in &bits {
            backend.assert_mul(bit, bit, bit);
        }
        let x = lift_gf16(backend, &bits);
        // x·x = x + c  ⟺  x² + x = c in characteristic 2.
        let c = backend.constant(embed_gf16(self.c));
        let rhs = backend.add(&x, &c);
        backend.assert_mul(&x, &x, &rhs);
        Ok(())
    }
}

fn gf16_bits(x: GF16) -> Vec<bool> {
    (0..4).map(|b| (x.to_u8() >> b) & 1 == 1).collect()
}

#[test]
fn quadratic_completeness() {
    let mut rng = StdRng::seed_from_u64(1);
    for xv in 0..16u8 {
        let x = GF16::new(xv);
        let c = x.square() + x;
        let circuit = QuadraticCircuit { c };
        let witness = gf16_bits(x);
        let proof = prove(&PARAMS_128, b"quadratic", &circuit, &witness, &mut rng).unwrap();
        verify(&PARAMS_128, b"quadratic", &circuit, &proof).unwrap();
    }
}

#[test]
fn quadratic_wrong_witness_is_unsatisfiable() {
    let mut rng = StdRng::seed_from_u64(2);
    let x = GF16::new(0b0110);
    let c = x.square() + x;
    // x+1 is also a root of y²+y = c (the two roots are x and x+1), so use
    // a value that is neither root.
    let bad = x + GF16::new(0b0010);
    assert_ne!(bad.square() + bad, c);
    let circuit = QuadraticCircuit { c };
    let result = prove(
        &PARAMS_128,
        b"quadratic",
        &circuit,
        &gf16_bits(bad),
        &mut rng,
    );
    assert_eq!(result.unwrap_err(), VoleithError::Unsatisfiable);
}

#[test]
fn quadratic_wrong_public_input_rejected() {
    let mut rng = StdRng::seed_from_u64(3);
    let x = GF16::new(0b1011);
    let c = x.square() + x;
    let circuit = QuadraticCircuit { c };
    let proof = prove(&PARAMS_128, b"quadratic", &circuit, &gf16_bits(x), &mut rng).unwrap();
    // Same circuit, different bound public input.
    assert_eq!(
        verify(&PARAMS_128, b"other-context", &circuit, &proof),
        Err(VoleithError::InvalidProof)
    );
    // Different public parameter in the circuit itself.
    let other = QuadraticCircuit { c: c + GF16::ONE };
    assert_eq!(
        verify(&PARAMS_128, b"quadratic", &other, &proof),
        Err(VoleithError::InvalidProof)
    );
}

/// Prove knowledge of secret `a` (n bits) with `a + s = z` as integers, for
/// public `s` and `z` — a ripple-carry adder, the core of the ACT range
/// argument. Carries are witness bits constrained with degree-2 relations.
struct AdderCircuit {
    n: usize,
    s: u64,
    z: u64,
}

impl Circuit for AdderCircuit {
    fn build<B: Backend>(&self, backend: &mut B) -> Result<(), VoleithError> {
        let one = backend.constant(GF2p128::ONE);
        let zero = backend.constant(GF2p128::ZERO);

        // Witness: a's bits, then carries γ_1..γ_n (γ_0 = 0).
        let mut a_bits = Vec::with_capacity(self.n);
        for _ in 0..self.n {
            a_bits.push(backend.witness_bit()?);
        }
        let mut carries = Vec::with_capacity(self.n);
        for _ in 0..self.n {
            carries.push(backend.witness_bit()?);
        }
        for w in a_bits.iter().chain(carries.iter()) {
            backend.assert_mul(w, w, w);
        }

        let mut carry_in = zero;
        for i in 0..self.n {
            let s_i = (self.s >> i) & 1 == 1;
            let z_i = (self.z >> i) & 1 == 1;
            let a_i = &a_bits[i];
            let carry_out = &carries[i];

            // s_i as a wire (public constant 0/1).
            let s_wire = if s_i {
                one.clone()
            } else {
                backend.constant(GF2p128::ZERO)
            };

            // Sum: a_i + s_i + carry_in + z_i = 0.
            let mut sum = backend.add(a_i, &s_wire);
            sum = backend.add(&sum, &carry_in);
            if z_i {
                sum = backend.add(&sum, &one);
            }
            backend.assert_zero(&sum);

            // Carry: γ_{i+1} = a_i·s_i + carry_in·(a_i + s_i).
            // Rearranged for a single mul each: t1 = a_i·s_i is linear
            // (s_i public); t2 = carry_in·(a_i + s_i) needs a mul.
            let t1 = if s_i {
                a_i.clone()
            } else {
                backend.constant(GF2p128::ZERO)
            };
            let a_plus_s = backend.add(a_i, &s_wire);
            // t2 with carry_out: carry_in·(a_i+s_i) = carry_out + t1.
            let t2 = backend.add(carry_out, &t1);
            backend.assert_mul(&carry_in, &a_plus_s, &t2);

            carry_in = carry_out.clone();
        }
        // Final carry must be zero (no overflow: a + s = z exactly in n bits).
        backend.assert_zero(&carry_in);
        Ok(())
    }
}

fn adder_witness(a: u64, s: u64, n: usize) -> Vec<bool> {
    let mut bits = Vec::with_capacity(2 * n);
    for i in 0..n {
        bits.push((a >> i) & 1 == 1);
    }
    let mut carry = 0u64;
    for i in 0..n {
        let ai = (a >> i) & 1;
        let si = (s >> i) & 1;
        carry = (ai & si) | (carry & (ai ^ si));
        bits.push(carry == 1);
    }
    bits
}

#[test]
fn adder_completeness() {
    let mut rng = StdRng::seed_from_u64(4);
    let n = 16;
    for (a, s) in [
        (0u64, 0u64),
        (1, 1),
        (12345, 999),
        (0xFFFE, 1),
        (40000, 25535),
    ] {
        let z = a + s;
        assert!(z < (1 << n));
        let circuit = AdderCircuit { n, s, z };
        let witness = adder_witness(a, s, n);
        let proof = prove(&PARAMS_128, b"adder", &circuit, &witness, &mut rng).unwrap();
        verify(&PARAMS_128, b"adder", &circuit, &proof).unwrap();
    }
}

#[test]
fn adder_wrong_sum_unsatisfiable() {
    let mut rng = StdRng::seed_from_u64(5);
    let n = 16;
    let (a, s) = (500u64, 300u64);
    let circuit = AdderCircuit { n, s, z: a + s + 1 };
    let result = prove(
        &PARAMS_128,
        b"adder",
        &circuit,
        &adder_witness(a, s, n),
        &mut rng,
    );
    assert_eq!(result.unwrap_err(), VoleithError::Unsatisfiable);
}

#[test]
fn tampered_proofs_rejected() {
    let mut rng = StdRng::seed_from_u64(6);
    let x = GF16::new(0b0101);
    let c = x.square() + x;
    let circuit = QuadraticCircuit { c };
    let proof = prove(&PARAMS_128, b"quadratic", &circuit, &gf16_bits(x), &mut rng).unwrap();

    // Tamper with each component and expect rejection.
    {
        let mut p = proof.clone();
        p.qs_coefficients[0] += GF2p128::ONE;
        assert!(verify(&PARAMS_128, b"quadratic", &circuit, &p).is_err());
    }
    {
        let mut p = proof.clone();
        p.qs_coefficients[1] += GF2p128::ONE;
        assert!(verify(&PARAMS_128, b"quadratic", &circuit, &p).is_err());
    }
    {
        let mut p = proof.clone();
        p.u_tilde += GF2p128::ONE;
        assert!(verify(&PARAMS_128, b"quadratic", &circuit, &p).is_err());
    }
    {
        let mut p = proof.clone();
        p.v_tilde[0] += GF2p128::ONE;
        assert!(verify(&PARAMS_128, b"quadratic", &circuit, &p).is_err());
    }
    {
        let mut p = proof.clone();
        let bit = p.d.get(0);
        p.d.set(0, !bit);
        assert!(verify(&PARAMS_128, b"quadratic", &circuit, &p).is_err());
    }
    {
        let mut p = proof.clone();
        let bit = p.corrections[0].get(0);
        p.corrections[0].set(0, !bit);
        assert!(verify(&PARAMS_128, b"quadratic", &circuit, &p).is_err());
    }
    {
        let mut p = proof.clone();
        p.salt[0] ^= 1;
        assert!(verify(&PARAMS_128, b"quadratic", &circuit, &p).is_err());
    }
    {
        let mut p = proof.clone();
        p.openings[3].siblings[2][5] ^= 1;
        assert!(verify(&PARAMS_128, b"quadratic", &circuit, &p).is_err());
    }
    {
        let mut p = proof.clone();
        p.coms[7].0[0] ^= 1;
        assert!(verify(&PARAMS_128, b"quadratic", &circuit, &p).is_err());
    }

    // Untampered still verifies (sanity).
    verify(&PARAMS_128, b"quadratic", &circuit, &proof).unwrap();
}

#[test]
fn proof_wire_codec_is_canonical_and_fail_closed() {
    let mut rng = StdRng::seed_from_u64(0x51_5245);
    let x = GF16::new(9);
    let circuit = QuadraticCircuit { c: x.square() + x };
    let proof = prove(
        &PARAMS_128,
        b"proof-wire",
        &circuit,
        &gf16_bits(x),
        &mut rng,
    )
    .unwrap();
    let encoded = proof.to_bytes();
    let decoded = voleith::Proof::from_bytes(&encoded).unwrap();
    assert_eq!(decoded.to_bytes(), encoded);
    verify(&PARAMS_128, b"proof-wire", &circuit, &decoded).unwrap();

    for cut in [0, 1, 4, encoded.len() / 2, encoded.len() - 1] {
        assert!(voleith::Proof::from_bytes(&encoded[..cut]).is_err());
    }
    let mut trailing = encoded.clone();
    trailing.push(0);
    assert!(voleith::Proof::from_bytes(&trailing).is_err());

    // The first correction's logical bit length begins after magic, version,
    // the 32-byte salt, commitments, and the correction count. Give it an
    // impossible u64 length; the decoder must reject before allocating.
    let mut huge = encoded;
    let first_correction_len = 5 + 32 + 4 + PARAMS_128.tau * 32 + 4;
    huge[first_correction_len..first_correction_len + 8].copy_from_slice(&u64::MAX.to_le_bytes());
    assert!(voleith::Proof::from_bytes(&huge).is_err());
}

#[test]
fn sampled_wire_mutations_never_turn_into_an_accepted_proof() {
    let mut rng = StdRng::seed_from_u64(0xADDE_525A);
    let x = GF16::new(13);
    let circuit = QuadraticCircuit { c: x.square() + x };
    let proof = prove(
        &PARAMS_128,
        b"mutation-campaign",
        &circuit,
        &gf16_bits(x),
        &mut rng,
    )
    .unwrap();
    let encoded = proof.to_bytes();
    let samples = 96usize.min(encoded.len());
    for sample in 0..samples {
        let index = sample * encoded.len() / samples;
        let mut mutated = encoded.clone();
        mutated[index] ^= 1 << (sample % 8);
        if let Ok(decoded) = voleith::Proof::from_bytes(&mutated) {
            assert!(
                verify(&PARAMS_128, b"mutation-campaign", &circuit, &decoded).is_err(),
                "wire mutation at byte {index} survived verification"
            );
        }
    }

    // Parser smoke-fuzzing: arbitrary short inputs must be rejected or parsed
    // without panicking; no parsed garbage may verify this statement.
    for length in 0..256usize {
        let mut garbage = vec![0u8; length];
        rng.fill_bytes(&mut garbage);
        if let Ok(decoded) = voleith::Proof::from_bytes(&garbage) {
            assert!(verify(&PARAMS_128, b"mutation-campaign", &circuit, &decoded).is_err());
        }
    }
}

/// Prove knowledge of x, y ∈ GF(16) satisfying the two-equation system
/// { x·y = p, x² + y = q } via a folded quadratic system (shared terms).
struct SystemCircuit {
    p: GF16,
    q: GF16,
}

impl Circuit for SystemCircuit {
    fn build<B: Backend>(&self, backend: &mut B) -> Result<(), VoleithError> {
        use voleith::QuadTerm;
        let mut xy_bits = Vec::with_capacity(8);
        for _ in 0..8 {
            xy_bits.push(backend.witness_bit()?);
        }
        for bit in &xy_bits {
            backend.assert_mul(bit, bit, bit);
        }
        let x = lift_gf16(
            backend,
            &[
                xy_bits[0].clone(),
                xy_bits[1].clone(),
                xy_bits[2].clone(),
                xy_bits[3].clone(),
            ],
        );
        let y = lift_gf16(
            backend,
            &[
                xy_bits[4].clone(),
                xy_bits[5].clone(),
                xy_bits[6].clone(),
                xy_bits[7].clone(),
            ],
        );
        // Equation 0: x·y + p = 0. Equation 1: x·x + y + q = 0.
        let lin0 = backend.constant(embed_gf16(self.p));
        let yq = backend.constant(embed_gf16(self.q));
        let lin1 = backend.add(&y, &yq);
        backend.assert_quad_system(
            vec![
                QuadTerm {
                    a: x.clone(),
                    b: y,
                    coeffs: vec![GF16::ONE, GF16::ZERO],
                },
                QuadTerm {
                    a: x.clone(),
                    b: x,
                    coeffs: vec![GF16::ZERO, GF16::ONE],
                },
            ],
            vec![lin0, lin1],
        );
        Ok(())
    }
}

#[test]
fn quad_system_completeness_and_soundness() {
    let mut rng = StdRng::seed_from_u64(7);
    for xv in [1u8, 5, 11] {
        for yv in [2u8, 7, 14] {
            let x = GF16::new(xv);
            let y = GF16::new(yv);
            let circuit = SystemCircuit {
                p: x * y,
                q: x.square() + y,
            };
            let mut witness = gf16_bits(x);
            witness.extend(gf16_bits(y));
            let proof = prove(&PARAMS_128, b"system", &circuit, &witness, &mut rng).unwrap();
            verify(&PARAMS_128, b"system", &circuit, &proof).unwrap();

            // A witness satisfying eq 0 but not eq 1 must be caught by the fold.
            let bad = SystemCircuit {
                p: x * y,
                q: x.square() + y + GF16::ONE,
            };
            assert_eq!(
                prove(&PARAMS_128, b"system", &bad, &witness, &mut rng).unwrap_err(),
                VoleithError::Unsatisfiable
            );
            // Cross-verification with mismatched public parameters fails.
            assert!(verify(&PARAMS_128, b"system", &bad, &proof).is_err());
        }
    }
}

/// Exercise the generalized polynomial-expression backend above degree two.
struct DegreeFourCircuit {
    fourth_power: GF16,
}

impl Circuit for DegreeFourCircuit {
    fn build<B: Backend>(&self, backend: &mut B) -> Result<(), VoleithError> {
        let bits: [B::Wire; 4] = [
            backend.witness_bit()?,
            backend.witness_bit()?,
            backend.witness_bit()?,
            backend.witness_bit()?,
        ];
        let x = lift_gf16(backend, &bits);
        let x = backend.wire_expr(&x);
        let square = backend.expr_mul(&x, &x);
        let fourth = backend.expr_mul(&square, &square);
        let constant = backend.constant(embed_gf16(self.fourth_power));
        let constant = backend.wire_expr(&constant);
        let relation = backend.expr_add(&fourth, &constant);
        backend.assert_expr_zero(&relation);
        Ok(())
    }
}

#[test]
fn degree_four_completeness_and_soundness() {
    let mut rng = StdRng::seed_from_u64(8);
    let x = GF16::new(11);
    let circuit = DegreeFourCircuit {
        fourth_power: x.square().square(),
    };
    let witness = gf16_bits(x);
    let proof = prove(&PARAMS_128, b"degree-four", &circuit, &witness, &mut rng).unwrap();
    verify(&PARAMS_128, b"degree-four", &circuit, &proof).unwrap();

    let wrong = DegreeFourCircuit {
        fourth_power: circuit.fourth_power + GF16::ONE,
    };
    assert_eq!(
        prove(&PARAMS_128, b"degree-four", &wrong, &witness, &mut rng).unwrap_err(),
        VoleithError::Unsatisfiable
    );
    assert!(verify(&PARAMS_128, b"degree-four", &wrong, &proof).is_err());
}
