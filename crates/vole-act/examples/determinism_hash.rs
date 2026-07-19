//! Temporary optimization-safety harness: derives every protocol artifact
//! from fixed RNG seeds and prints SHA3-256 hashes of the wire bytes.
//! Optimizations must not change any hash (the protocol is deterministic
//! given the RNG stream), proving transcript compatibility bit-for-bit.
#![allow(missing_docs)]

use mayo::Mayo2;
use rand::SeedableRng;
use rand::rngs::StdRng;
use sha3::{Digest, Sha3_256};
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

fn digest(label: &str, bytes: &[u8]) {
    let mut h = Sha3_256::new();
    h.update(bytes);
    let out = h.finalize();
    let hex: String = out.iter().map(|b| format!("{b:02x}")).collect();
    println!("{label}: {hex}");
}

fn main() {
    for profile in [
        PerformanceProfile::Compact,
        PerformanceProfile::Balanced,
        PerformanceProfile::LowLatency,
    ] {
        let tag = format!("{profile:?}");
        let mut rng = StdRng::seed_from_u64(0xD00D_0001);
        let mut issuer = Issuer::generate_with_store(
            b"vole-act/determinism",
            profile,
            NonPersistingStore,
            &mut rng,
        );
        let public = issuer.public_key().clone();
        digest(&format!("{tag}/public-key"), &public.to_bytes());

        let (pending, issue_request) = public.prepare_issue(100, &mut rng).unwrap();
        digest(&format!("{tag}/issue-request"), &issue_request.to_bytes());
        let response = issuer.issue(&issue_request, 100, &mut rng).unwrap();
        let direct = pending.finish(&public, &issue_request, &response).unwrap();
        digest(&format!("{tag}/direct-token"), &direct.to_bytes());

        let (_, spend_request) = direct.prepare_spend(&public, 20, &mut rng).unwrap();
        digest(&format!("{tag}/spend-request"), &spend_request.to_bytes());
        let spend_response = issuer.spend(&spend_request, &mut rng).unwrap();
        digest(&format!("{tag}/spend-response"), &spend_response.to_bytes());

        let (pending, deferred_request) = direct
            .prepare_spend_with_deferred_return(&public, 20, &mut rng)
            .unwrap();
        digest(
            &format!("{tag}/deferred-request"),
            &deferred_request.to_bytes(),
        );
        let deferred_response = issuer
            .spend_with_deferred_return(&deferred_request, 5, &mut rng)
            .unwrap();
        let deferred = pending
            .finish(&public, &deferred_request, &deferred_response)
            .unwrap();
        digest(&format!("{tag}/deferred-token"), &deferred.to_bytes());

        let (_, deferred_spend) = deferred.prepare_spend(&public, 10, &mut rng).unwrap();
        digest(
            &format!("{tag}/deferred-spend-request"),
            &deferred_spend.to_bytes(),
        );
        let final_response = issuer.spend(&deferred_spend, &mut rng).unwrap();
        digest(
            &format!("{tag}/deferred-spend-response"),
            &final_response.to_bytes(),
        );
    }
}
