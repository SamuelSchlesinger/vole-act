#![no_main]

mod common;

use binary_fields::{BinaryField, GF2p128, GF16};
use libfuzzer_sys::fuzz_target;
use mayo::{Mayo2, MayoParams};
use rand::SeedableRng;
use rand::rngs::StdRng;
use std::sync::OnceLock;
use vector_commit::{AllButOneVc, MAX_DEPTH};
use voleith::bits::BitVec;
use voleith::vole::{ProverVole, reconstruct_keys, split_delta};
use voleith::{PARAMS_128, PARAMS_128_BALANCED, PARAMS_128_FAST, Params};

fn mayo_public() -> &'static mayo::PublicKey<Mayo2> {
    static PUBLIC: OnceLock<mayo::PublicKey<Mayo2>> = OnceLock::new();
    PUBLIC.get_or_init(|| {
        let mut rng = StdRng::seed_from_u64(0x434f_524e_4552_4d32);
        let (_, public) = mayo::trapgen::<Mayo2>(&mut rng);
        public
    })
}

fuzz_target!(|data: &[u8]| {
    // Field laws exercise reduction exactly at the high-degree/carry edge.
    let a = GF2p128::new(common::read_u128(data));
    let b = GF2p128::new(common::read_u128(data.get(16..).unwrap_or_default()));
    let c = GF2p128::new(common::read_u128(data.get(32..).unwrap_or_default()));
    assert_eq!(a * b, b * a);
    assert_eq!((a * b) * c, a * (b * c));
    assert_eq!(a * (b + c), a * b + a * c);
    assert_eq!(a.square(), a * a);
    assert_eq!(a + a, GF2p128::ZERO);
    if a != GF2p128::ZERO {
        assert_eq!(a * a.inv(), GF2p128::ONE);
    }

    let x = GF16::new(data.first().copied().unwrap_or(0));
    let y = GF16::new(data.get(1).copied().unwrap_or(0));
    assert_eq!(x * y, y * x);
    assert_eq!(x.square(), x * x);
    if x != GF16::ZERO {
        assert_eq!(x * x.inv(), GF16::ONE);
    }

    // Canonical tail padding and zero-length vectors.
    let bit_len = (common::read_u64(data.get(48..).unwrap_or_default()) % 2049) as usize;
    let byte_len = bit_len.div_ceil(8);
    let mut bytes = vec![0u8; byte_len];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = data.get(56 + index).copied().unwrap_or(index as u8);
    }
    if !bit_len.is_multiple_of(8)
        && let Some(last) = bytes.last_mut()
    {
        *last &= (1u8 << (bit_len % 8)) - 1;
    }
    let bits = BitVec::from_bytes(bytes.clone(), bit_len).expect("masked encoding is canonical");
    assert_eq!(bits.as_bytes(), bytes);
    assert_eq!(bits.len(), bit_len);
    if !bit_len.is_multiple_of(8) {
        let mut noncanonical = bytes;
        *noncanonical.last_mut().unwrap() |= 1u8 << (bit_len % 8);
        assert!(BitVec::from_bytes(noncanonical, bit_len).is_none());
    }

    // GGM boundary depths, positions, salts, and tampered openings.
    let depth = u32::from(data.get(2).copied().unwrap_or(0) % 8 + 1);
    let mut root = [0u8; 16];
    let mut salt = [0u8; 16];
    root.copy_from_slice(&a.to_bytes());
    salt.copy_from_slice(&b.to_bytes());
    let (tree, commitment) = AllButOneVc::commit(root, salt, depth).unwrap();
    let hide = common::read_u64(data.get(64..).unwrap_or_default()) as usize % tree.num_leaves();
    let opening = tree.open_all_but_one(hide).unwrap();
    let leaves = AllButOneVc::verify(&commitment, salt, depth, hide, &opening).unwrap();
    assert_eq!(leaves.len(), tree.num_leaves());
    assert_eq!(leaves.iter().filter(|leaf| leaf.is_none()).count(), 1);
    assert!(leaves[hide].is_none());

    let mut tampered = opening.clone();
    if data.get(3).copied().unwrap_or(0) & 1 == 0 {
        tampered.hidden_com[0] ^= 1;
    } else {
        tampered.siblings[0][0] ^= 1;
    }
    assert!(AllButOneVc::verify(&commitment, salt, depth, hide, &tampered).is_err());
    assert!(AllButOneVc::commit(root, salt, 0).is_err());
    assert!(AllButOneVc::commit(root, salt, MAX_DEPTH + 1).is_err());
    assert!(tree.open_all_but_one(tree.num_leaves()).is_err());

    // Invalid parameter geometry must reject without shifts or allocations;
    // valid geometry gets the full VOLE reconstruction invariant.
    let arbitrary = Params {
        tau: common::read_u64(data.get(72..).unwrap_or_default()) as usize,
        k: common::read_u64(data.get(80..).unwrap_or_default()) as usize,
    };
    let challenge = a.to_bytes();
    let (_, arbitrary_chunks) = split_delta(&challenge, &arbitrary);
    let geometry_is_valid = arbitrary.tau >= 1
        && arbitrary.k >= 1
        && arbitrary.k <= 24
        && arbitrary.tau <= 128
        && arbitrary.lambda() == 128;
    assert_eq!(
        arbitrary_chunks.len(),
        if geometry_is_valid { arbitrary.tau } else { 0 }
    );
    let l_hat = (common::read_u64(data.get(88..).unwrap_or_default()) % 385) as usize;
    let _ = ProverVole::commit(&[], &salt, l_hat, &arbitrary);

    if data.get(4).copied().unwrap_or(0) & 7 == 0 {
        let params = match data.get(5).copied().unwrap_or(0) % 3 {
            0 => PARAMS_128,
            1 => PARAMS_128_BALANCED,
            _ => PARAMS_128_FAST,
        };
        let roots: Vec<[u8; 16]> = (0..params.tau)
            .map(|j| {
                let mut seed = root;
                seed[..8].copy_from_slice(&(j as u64).to_le_bytes());
                seed
            })
            .collect();
        let vole = ProverVole::commit(&roots, &salt, l_hat, &params).unwrap();
        let (delta, deltas) = split_delta(&challenge, &params);
        let openings = vole.open(&deltas).unwrap();
        let keys = reconstruct_keys(
            &salt,
            l_hat,
            &params,
            &vole.coms,
            &vole.corrections,
            &deltas,
            &openings,
        )
        .unwrap();
        assert_eq!(keys.len(), l_hat);
        for (index, key) in keys.iter().enumerate() {
            let expected = vole.tags[index]
                + if vole.u.get(index) {
                    delta
                } else {
                    GF2p128::ZERO
                };
            assert_eq!(*key, expected);
        }
    }

    // MAYO must reject every dimension except exactly KN without indexing or
    // allocation surprises. Values are always reduced to canonical nibbles.
    let mayo_len = common::read_u64(data.get(96..).unwrap_or_default()) as usize % (Mayo2::KN + 3);
    let input: Vec<GF16> = (0..mayo_len)
        .map(|index| GF16::new(data.get(index).copied().unwrap_or(index as u8)))
        .collect();
    assert_eq!(
        mayo::eval(mayo_public(), &input).is_ok(),
        mayo_len == Mayo2::KN
    );
});
