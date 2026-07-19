#![no_main]

mod common;

use libfuzzer_sys::fuzz_target;
use mayo::Mayo2;
use rand::SeedableRng;
use rand::rngs::StdRng;
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use vole_act::{
    CredentialKind, DeferredReturnToken, DirectToken, Error, Issuer, NullifierStore,
    PerformanceProfile, PublicKey, RetryRecord, Token,
};

#[derive(Default)]
struct ResettableStore {
    records: HashMap<[u8; 32], RetryRecord<Mayo2>>,
}

impl ResettableStore {
    fn clear(&mut self) {
        self.records.clear();
    }
}

impl NullifierStore<Mayo2> for ResettableStore {
    fn get(&self, nullifier: &[u8; 32]) -> Result<Option<RetryRecord<Mayo2>>, Error> {
        Ok(self.records.get(nullifier).cloned())
    }

    fn insert_if_absent(
        &mut self,
        nullifier: [u8; 32],
        candidate: RetryRecord<Mayo2>,
    ) -> Result<RetryRecord<Mayo2>, Error> {
        Ok(self.records.entry(nullifier).or_insert(candidate).clone())
    }
}

fn issuer() -> &'static Mutex<Issuer<Mayo2, ResettableStore>> {
    static ISSUER: OnceLock<Mutex<Issuer<Mayo2, ResettableStore>>> = OnceLock::new();
    ISSUER.get_or_init(|| {
        let mut rng = StdRng::seed_from_u64(0x5354_4154_454d_3231);
        Mutex::new(Issuer::generate_with_store(
            b"vole-act/fuzz/state-machine",
            PerformanceProfile::Balanced,
            ResettableStore::default(),
            &mut rng,
        ))
    })
}

fn bounded(raw: u64, maximum: u64) -> u64 {
    (u128::from(raw) % (u128::from(maximum) + 1)) as u64
}

fn final_step<K: CredentialKind>(
    token: Token<Mayo2, K>,
    expected_balance: u64,
    public: &PublicKey<Mayo2>,
    issuer: &mut Issuer<Mayo2, ResettableStore>,
    data: &[u8],
    rng: &mut StdRng,
) {
    assert_eq!(token.balance(), expected_balance);
    public.verify_token(&token).unwrap();

    if expected_balance != u64::MAX {
        assert!(matches!(
            token.prepare_spend(public, expected_balance + 1, rng),
            Err(Error::InsufficientBalance)
        ));
    }

    let spend = bounded(common::read_u64(data), expected_balance);
    let return_amount = bounded(common::read_u64(data.get(8..).unwrap_or_default()), spend);
    let flags = data.get(16).copied().unwrap_or(0);

    if flags & 1 == 0 {
        let (pending, request) = token.prepare_spend(public, spend, rng).unwrap();
        let conflicting = if flags & 2 != 0 {
            Some(
                token
                    .prepare_spend_with_deferred_return(public, spend, rng)
                    .unwrap()
                    .1,
            )
        } else {
            None
        };
        let response = issuer.spend(&request, rng).unwrap();
        let retry = issuer.spend(&request, rng).unwrap();
        assert_eq!(response.to_bytes(), retry.to_bytes());
        if let Some(conflicting) = conflicting {
            assert!(matches!(
                issuer.spend_with_deferred_return(&conflicting, 0, rng),
                Err(Error::NullifierAlreadySpent)
            ));
        }
        let output = pending.finish(public, &request, &response).unwrap();
        let expected = expected_balance - spend;
        assert_eq!(output.balance(), expected);
        let encoded = output.to_bytes();
        let decoded = DirectToken::<Mayo2>::from_bytes(public, &encoded).unwrap();
        assert_eq!(decoded.balance(), expected);
        public.verify_token(&decoded).unwrap();
    } else {
        let (pending, request) = token
            .prepare_spend_with_deferred_return(public, spend, rng)
            .unwrap();
        let conflicting = if flags & 2 != 0 {
            Some(token.prepare_spend(public, spend, rng).unwrap().1)
        } else {
            None
        };
        if spend != u64::MAX {
            assert!(matches!(
                issuer.spend_with_deferred_return(&request, spend + 1, rng),
                Err(Error::InvalidReturnAmount)
            ));
        }
        let response = issuer
            .spend_with_deferred_return(&request, return_amount, rng)
            .unwrap();
        let retry_amount = if return_amount == spend { 0 } else { spend };
        let retry = issuer
            .spend_with_deferred_return(&request, retry_amount, rng)
            .unwrap();
        assert_eq!(response.to_bytes(), retry.to_bytes());
        assert_eq!(response.return_amount(), return_amount);
        if let Some(conflicting) = conflicting {
            assert!(matches!(
                issuer.spend(&conflicting, rng),
                Err(Error::NullifierAlreadySpent)
            ));
        }
        let output = pending.finish(public, &request, &response).unwrap();
        let expected = expected_balance - spend + return_amount;
        assert_eq!(output.balance(), expected);
        let encoded = output.to_bytes();
        let decoded = DeferredReturnToken::<Mayo2>::from_bytes(public, &encoded).unwrap();
        assert_eq!(decoded.balance(), expected);
        public.verify_token(&decoded).unwrap();
    }
}

fuzz_target!(|data: &[u8]| {
    let mut seed = [0u8; 32];
    for (index, byte) in data.iter().enumerate() {
        seed[index % seed.len()] ^= byte.wrapping_add(index as u8);
    }
    let mut rng = StdRng::from_seed(seed);
    let balance = common::read_u64(data);
    let first_spend = bounded(common::read_u64(data.get(8..).unwrap_or_default()), balance);
    let first_return = bounded(
        common::read_u64(data.get(16..).unwrap_or_default()),
        first_spend,
    );
    let flags = data.get(24).copied().unwrap_or(0);

    let mut issuer = issuer().lock().unwrap();
    issuer.store_mut().clear();
    let public = issuer.public_key().clone();

    let (pending, request) = public.prepare_issue(balance, &mut rng).unwrap();
    let response = issuer.issue(&request, balance, &mut rng).unwrap();
    let token = pending.finish(&public, &request, &response).unwrap();
    assert_eq!(token.balance(), balance);

    if flags & 1 == 0 {
        final_step(
            token,
            balance,
            &public,
            &mut issuer,
            data.get(25..).unwrap_or_default(),
            &mut rng,
        );
    } else {
        let (pending, request) = token
            .prepare_spend_with_deferred_return(&public, first_spend, &mut rng)
            .unwrap();
        let response = issuer
            .spend_with_deferred_return(&request, first_return, &mut rng)
            .unwrap();
        let retry = issuer
            .spend_with_deferred_return(&request, first_return.wrapping_add(1), &mut rng)
            .unwrap();
        assert_eq!(response.to_bytes(), retry.to_bytes());
        let token = pending.finish(&public, &request, &response).unwrap();
        let expected = balance - first_spend + first_return;
        assert_eq!(token.balance(), expected);
        final_step(
            token,
            expected,
            &public,
            &mut issuer,
            data.get(25..).unwrap_or_default(),
            &mut rng,
        );
    }
});
