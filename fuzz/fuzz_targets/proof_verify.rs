#![no_main]

mod common;

use binary_fields::{BinaryField, GF2p128};
use libfuzzer_sys::fuzz_target;
use rand::SeedableRng;
use rand::rngs::StdRng;
use std::sync::OnceLock;
use voleith::{Backend, Circuit, PARAMS_128_FAST, Proof, VoleithError, prove, verify};

struct BitCircuit;

impl Circuit for BitCircuit {
    fn build<B: Backend>(&self, backend: &mut B) -> Result<(), VoleithError> {
        let bit = backend.witness_bit()?;
        backend.assert_mul(&bit, &bit, &bit);
        let zero = backend.constant(GF2p128::ZERO);
        let same = backend.add(&bit, &zero);
        backend.assert_mul(&same, &same, &same);
        Ok(())
    }
}

fn valid_proof() -> &'static [u8] {
    static VALID: OnceLock<Vec<u8>> = OnceLock::new();
    VALID
        .get_or_init(|| {
            let mut rng = StdRng::seed_from_u64(0x564f_4c45_4143_5421);
            prove(
                &PARAMS_128_FAST,
                b"vole-act/fuzz/proof",
                &BitCircuit,
                &[true],
                &mut rng,
            )
            .expect("fixed proof fixture must be satisfiable")
            .to_bytes()
        })
        .as_slice()
}

fuzz_target!(|data: &[u8]| {
    let baseline = valid_proof();
    let candidate = common::mutate_valid(baseline, data);

    if let Ok(proof) = Proof::from_bytes(&candidate) {
        assert_eq!(
            proof.to_bytes(),
            candidate,
            "accepted a non-canonical proof"
        );
        let verifies = verify(
            &PARAMS_128_FAST,
            b"vole-act/fuzz/proof",
            &BitCircuit,
            &proof,
        )
        .is_ok();
        if candidate == baseline {
            assert!(verifies, "valid proof fixture stopped verifying");
        } else {
            assert!(!verifies, "modified proof still verified");
        }

        assert!(
            verify(
                &PARAMS_128_FAST,
                b"vole-act/fuzz/wrong-statement",
                &BitCircuit,
                &proof,
            )
            .is_err(),
            "proof was not bound to its public statement"
        );
    }
});
