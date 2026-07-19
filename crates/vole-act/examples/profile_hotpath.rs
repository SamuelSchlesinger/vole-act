//! Temporary profiling harness: loops the direct-spend path forever so an
//! external sampler (macOS `sample`) can attribute time. Not part of the API.
#![allow(missing_docs)]

use mayo::Mayo2;
use rand::SeedableRng;
use rand::rngs::StdRng;
use vole_act::{Error, Issuer, NullifierStore, PerformanceProfile, RetryRecord};

#[derive(Default)]
struct NonPersistingStore;

impl NullifierStore<Mayo2> for NonPersistingStore {
    fn get(&self, _nullifier: &[u8; 32]) -> Result<Option<RetryRecord<Mayo2>>, Error> {
        Ok(None)
    }
    fn insert_if_absent(
        &mut self,
        _nullifier: [u8; 32],
        candidate: RetryRecord<Mayo2>,
    ) -> Result<RetryRecord<Mayo2>, Error> {
        Ok(candidate)
    }
}

fn main() {
    let profile = match std::env::args().nth(2).as_deref() {
        Some("compact") => PerformanceProfile::Compact,
        Some("low-latency") => PerformanceProfile::LowLatency,
        _ => PerformanceProfile::Balanced,
    };
    let mut rng = StdRng::seed_from_u64(0xF0F0);
    let mut issuer = Issuer::generate_with_store(
        b"vole-act/profile",
        profile,
        NonPersistingStore,
        &mut rng,
    );
    let public = issuer.public_key().clone();
    let (pending, request) = public.prepare_issue(100, &mut rng).unwrap();
    let response = issuer.issue(&request, 100, &mut rng).unwrap();
    let direct = pending.finish(&public, &request, &response).unwrap();

    let mode = std::env::args().nth(1).unwrap_or_else(|| "both".into());
    let (mut prove_only, mut verify_only) = (false, false);
    match mode.as_str() {
        "prove" => prove_only = true,
        "verify" => verify_only = true,
        _ => {}
    }

    let (_, fixed_request) = direct.prepare_spend(&public, 20, &mut rng).unwrap();
    eprintln!("looping mode={mode}; attach `sample` now");
    loop {
        if verify_only {
            let _ = issuer.spend(&fixed_request, &mut rng).unwrap();
        } else if prove_only {
            let _ = direct.prepare_spend(&public, 20, &mut rng).unwrap();
        } else {
            let (_, request) = direct.prepare_spend(&public, 20, &mut rng).unwrap();
            let _ = issuer.spend(&request, &mut rng).unwrap();
        }
    }
}
