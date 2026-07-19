//! Measurement harness: every protocol operation and wire size, for every
//! performance profile. Medians over repeated runs; complements the criterion
//! suite (which covers the balanced profile in depth).
#![allow(missing_docs)]

use mayo::Mayo2;
use rand::SeedableRng;
use rand::rngs::StdRng;
use std::time::Instant;
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

fn median_ms(mut samples: Vec<f64>) -> f64 {
    samples.sort_by(|a, b| a.partial_cmp(b).unwrap());
    samples[samples.len() / 2]
}

fn time<R>(iters: usize, mut f: impl FnMut() -> R) -> f64 {
    let mut samples = Vec::with_capacity(iters);
    for _ in 0..iters {
        let t = Instant::now();
        std::hint::black_box(f());
        samples.push(t.elapsed().as_secs_f64() * 1e3);
    }
    median_ms(samples)
}

fn main() {
    const ITERS: usize = 15;
    println!(
        "{:<38} {:>10} {:>10} {:>12}",
        "operation (ms, median of 15)", "compact", "balanced", "low-latency"
    );
    let mut rows: Vec<(String, Vec<f64>)> = Vec::new();
    let mut sizes: Vec<(String, Vec<usize>)> = Vec::new();

    for profile in [
        PerformanceProfile::Compact,
        PerformanceProfile::Balanced,
        PerformanceProfile::LowLatency,
    ] {
        let mut rng = StdRng::seed_from_u64(0xACC0);
        let mut issuer = Issuer::generate_with_store(
            b"vole-act/profile-matrix",
            profile,
            NonPersistingStore,
            &mut rng,
        );
        let public = issuer.public_key().clone();

        let (pending, issue_request) = public.prepare_issue(100, &mut rng).unwrap();
        let issue_response = issuer.issue(&issue_request, 100, &mut rng).unwrap();
        let direct = pending
            .finish(&public, &issue_request, &issue_response)
            .unwrap();
        let (_, direct_request) = direct.prepare_spend(&public, 20, &mut rng).unwrap();
        let (dpending, deferred_request) = direct
            .prepare_spend_with_deferred_return(&public, 20, &mut rng)
            .unwrap();
        let deferred_response = issuer
            .spend_with_deferred_return(&deferred_request, 5, &mut rng)
            .unwrap();
        let deferred = dpending
            .finish(&public, &deferred_request, &deferred_response)
            .unwrap();
        let (_, deferred_input_request) = deferred.prepare_spend(&public, 10, &mut rng).unwrap();

        let mut add = |name: &str, value: f64| {
            match rows.iter_mut().find(|(n, _)| n == name) {
                Some((_, values)) => values.push(value),
                None => rows.push((name.to_string(), vec![value])),
            };
        };

        add(
            "issue/client-prove",
            time(ITERS, || public.prepare_issue(100, &mut rng).unwrap()),
        );
        add(
            "issue/issuer-verify-and-sign",
            time(ITERS, || {
                issuer.issue(&issue_request, 100, &mut rng).unwrap()
            }),
        );
        add(
            "spend(direct)/client-prove",
            time(ITERS, || {
                direct.prepare_spend(&public, 20, &mut rng).unwrap()
            }),
        );
        add(
            "spend(direct)/issuer-verify-and-sign",
            time(ITERS, || issuer.spend(&direct_request, &mut rng).unwrap()),
        );
        add(
            "spend(deferred)/client-prove",
            time(ITERS, || {
                deferred.prepare_spend(&public, 10, &mut rng).unwrap()
            }),
        );
        add(
            "spend(deferred)/issuer-verify-and-sign",
            time(ITERS, || {
                issuer.spend(&deferred_input_request, &mut rng).unwrap()
            }),
        );
        add(
            "deferred-return/issuer-verify-and-sign",
            time(ITERS, || {
                issuer
                    .spend_with_deferred_return(&deferred_request, 5, &mut rng)
                    .unwrap()
            }),
        );
        add(
            "issue/end-to-end",
            time(ITERS, || {
                let (pending, request) = public.prepare_issue(100, &mut rng).unwrap();
                let response = issuer.issue(&request, 100, &mut rng).unwrap();
                pending.finish(&public, &request, &response).unwrap()
            }),
        );
        add(
            "spend(direct)/end-to-end",
            time(ITERS, || {
                let (pending, request) = direct.prepare_spend(&public, 20, &mut rng).unwrap();
                let response = issuer.spend(&request, &mut rng).unwrap();
                pending.finish(&public, &request, &response).unwrap()
            }),
        );

        let mut add_size = |name: &str, value: usize| {
            match sizes.iter_mut().find(|(n, _)| n == name) {
                Some((_, values)) => values.push(value),
                None => sizes.push((name.to_string(), vec![value])),
            };
        };
        add_size("public key", public.to_bytes().len());
        add_size("direct token", direct.to_bytes().len());
        add_size("deferred-return token", deferred.to_bytes().len());
        add_size("issue request", issue_request.to_bytes().len());
        add_size("issue response", issue_response.to_bytes().len());
        add_size(
            "spend request (direct input)",
            direct_request.to_bytes().len(),
        );
        add_size(
            "spend request (deferred input)",
            deferred_input_request.to_bytes().len(),
        );
        add_size(
            "deferred-return spend request",
            deferred_request.to_bytes().len(),
        );
        add_size("spend response", deferred_response.to_bytes().len());
    }

    for (name, values) in &rows {
        println!(
            "{:<38} {:>9.2}ms {:>9.2}ms {:>11.2}ms",
            name, values[0], values[1], values[2]
        );
    }
    println!();
    println!(
        "{:<38} {:>10} {:>10} {:>12}",
        "wire size (bytes)", "compact", "balanced", "low-latency"
    );
    for (name, values) in &sizes {
        println!(
            "{:<38} {:>10} {:>10} {:>12}",
            name, values[0], values[1], values[2]
        );
    }
}
