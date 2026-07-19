//! End-to-end tests of the VOLE-in-the-head NIZK on small circuits.

use binary_fields::{BinaryField, GF2p128, GF16, embed_gf16};
use rand::SeedableRng;
use rand::rngs::StdRng;
use voleith::{Backend, Circuit, PARAMS_128, VoleithError, prove, verify};

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
        p.qs_u += GF2p128::ONE;
        assert!(verify(&PARAMS_128, b"quadratic", &circuit, &p).is_err());
    }
    {
        let mut p = proof.clone();
        p.qs_w += GF2p128::ONE;
        assert!(verify(&PARAMS_128, b"quadratic", &circuit, &p).is_err());
    }
    {
        let mut p = proof.clone();
        p.u_tilde += GF2p128::ONE;
        assert!(verify(&PARAMS_128, b"quadratic", &circuit, &p).is_err());
    }
    {
        let mut p = proof.clone();
        p.v_tilde += GF2p128::ONE;
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
