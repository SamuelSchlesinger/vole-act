//! Criterion benchmarks for the complete VOLE-ACT protocol stack.
#![allow(missing_docs)]

use criterion::{
    BenchmarkId, Criterion, SamplingMode, Throughput, black_box, criterion_group, criterion_main,
};
use mayo::Mayo2;
use rand::SeedableRng;
use rand::rngs::StdRng;
use std::time::Duration;
use vole_act::{
    DeferredReturn, DeferredReturnSpendRequest, DeferredReturnToken, Direct, DirectToken, Error,
    IssueRequest, Issuer, NullifierStore, PerformanceProfile, PublicKey, RetryRecord, SpendRequest,
};

/// Benchmark-only store that always accepts a candidate but deliberately does
/// not retain it. This lets issuer verification/signing repeatedly measure the
/// full path for one prepared request instead of falling into the retry path.
/// It must never be copied into production code.
#[derive(Default)]
struct NonPersistingBenchmarkStore;

impl NullifierStore<Mayo2> for NonPersistingBenchmarkStore {
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

struct Fixture {
    issuer: Issuer<Mayo2, NonPersistingBenchmarkStore>,
    public: PublicKey<Mayo2>,
    direct: DirectToken<Mayo2>,
    deferred: DeferredReturnToken<Mayo2>,
    issue_request: IssueRequest<Mayo2>,
    direct_request: SpendRequest<Mayo2, Direct>,
    deferred_input_request: SpendRequest<Mayo2, DeferredReturn>,
    deferred_settlement_request: DeferredReturnSpendRequest<Mayo2, Direct>,
}

impl Fixture {
    fn new(profile: PerformanceProfile, seed: u64) -> Self {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut issuer = Issuer::generate_with_store(
            b"vole-act/criterion/protocol-v2",
            profile,
            NonPersistingBenchmarkStore,
            &mut rng,
        );
        let public = issuer.public_key().clone();

        let (pending, issue_request) = public.prepare_issue(100, &mut rng).unwrap();
        let response = issuer.issue(&issue_request, 100, &mut rng).unwrap();
        let direct = pending.finish(&public, &issue_request, &response).unwrap();

        let (_, direct_request) = direct.prepare_spend(&public, 20, &mut rng).unwrap();
        let (pending, deferred_settlement_request) = direct
            .prepare_spend_with_deferred_return(&public, 20, &mut rng)
            .unwrap();
        let response = issuer
            .spend_with_deferred_return(&deferred_settlement_request, 5, &mut rng)
            .unwrap();
        let deferred = pending
            .finish(&public, &deferred_settlement_request, &response)
            .unwrap();
        let (_, deferred_input_request) = deferred.prepare_spend(&public, 10, &mut rng).unwrap();

        Self {
            issuer,
            public,
            direct,
            deferred,
            issue_request,
            direct_request,
            deferred_input_request,
            deferred_settlement_request,
        }
    }
}

fn profile_name(profile: PerformanceProfile) -> &'static str {
    match profile {
        PerformanceProfile::Compact => "compact",
        PerformanceProfile::Balanced => "balanced",
        PerformanceProfile::LowLatency => "low-latency",
    }
}

fn profile_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("profiles");
    group.sampling_mode(SamplingMode::Flat);

    for (index, profile) in [
        PerformanceProfile::Compact,
        PerformanceProfile::Balanced,
        PerformanceProfile::LowLatency,
    ]
    .into_iter()
    .enumerate()
    {
        let label = profile_name(profile);
        let fixture = Fixture::new(profile, 0xB3_0000 + index as u64);
        let mut rng = StdRng::seed_from_u64(0xB3_1000 + index as u64);

        group.bench_with_input(
            BenchmarkId::new("issue/client-prove", label),
            &profile,
            |b, _| {
                b.iter(|| {
                    black_box(
                        fixture
                            .public
                            .prepare_issue(black_box(100), &mut rng)
                            .unwrap(),
                    )
                });
            },
        );
        group.bench_with_input(
            BenchmarkId::new("direct-input/client-prove", label),
            &profile,
            |b, _| {
                b.iter(|| {
                    black_box(
                        fixture
                            .direct
                            .prepare_spend(&fixture.public, black_box(20), &mut rng)
                            .unwrap(),
                    )
                });
            },
        );
        group.bench_with_input(
            BenchmarkId::new("deferred-input/client-prove", label),
            &profile,
            |b, _| {
                b.iter(|| {
                    black_box(
                        fixture
                            .deferred
                            .prepare_spend(&fixture.public, black_box(10), &mut rng)
                            .unwrap(),
                    )
                });
            },
        );
    }
    group.finish();
}

fn balanced_protocol(c: &mut Criterion) {
    let mut fixture = Fixture::new(PerformanceProfile::Balanced, 0xB4_0000);
    let mut rng = StdRng::seed_from_u64(0xB4_1000);
    let mut group = c.benchmark_group("balanced");
    group.sampling_mode(SamplingMode::Flat);

    group.bench_function("issue/issuer-verify-and-sign", |b| {
        b.iter(|| {
            black_box(
                fixture
                    .issuer
                    .issue(black_box(&fixture.issue_request), black_box(100), &mut rng)
                    .unwrap(),
            )
        });
    });
    group.bench_function("direct-input/issuer-verify-and-sign", |b| {
        b.iter(|| {
            black_box(
                fixture
                    .issuer
                    .spend(black_box(&fixture.direct_request), &mut rng)
                    .unwrap(),
            )
        });
    });
    group.bench_function("deferred-input/issuer-verify-and-sign", |b| {
        b.iter(|| {
            black_box(
                fixture
                    .issuer
                    .spend(black_box(&fixture.deferred_input_request), &mut rng)
                    .unwrap(),
            )
        });
    });
    group.bench_function("deferred-return/issuer-verify-and-sign", |b| {
        b.iter(|| {
            black_box(
                fixture
                    .issuer
                    .spend_with_deferred_return(
                        black_box(&fixture.deferred_settlement_request),
                        black_box(5),
                        &mut rng,
                    )
                    .unwrap(),
            )
        });
    });
    group.bench_function("issue/end-to-end", |b| {
        b.iter(|| {
            let (pending, request) = fixture
                .public
                .prepare_issue(black_box(100), &mut rng)
                .unwrap();
            let response = fixture
                .issuer
                .issue(&request, black_box(100), &mut rng)
                .unwrap();
            black_box(
                pending
                    .finish(&fixture.public, &request, &response)
                    .unwrap(),
            )
        });
    });
    group.bench_function("direct/end-to-end", |b| {
        b.iter(|| {
            let (pending, request) = fixture
                .direct
                .prepare_spend(&fixture.public, black_box(20), &mut rng)
                .unwrap();
            let response = fixture.issuer.spend(&request, &mut rng).unwrap();
            black_box(
                pending
                    .finish(&fixture.public, &request, &response)
                    .unwrap(),
            )
        });
    });
    group.bench_function("deferred-input/direct-end-to-end", |b| {
        b.iter(|| {
            let (pending, request) = fixture
                .deferred
                .prepare_spend(&fixture.public, black_box(10), &mut rng)
                .unwrap();
            let response = fixture.issuer.spend(&request, &mut rng).unwrap();
            black_box(
                pending
                    .finish(&fixture.public, &request, &response)
                    .unwrap(),
            )
        });
    });
    group.bench_function("deferred-return/end-to-end", |b| {
        b.iter(|| {
            let (pending, request) = fixture
                .direct
                .prepare_spend_with_deferred_return(&fixture.public, black_box(20), &mut rng)
                .unwrap();
            let response = fixture
                .issuer
                .spend_with_deferred_return(&request, black_box(5), &mut rng)
                .unwrap();
            black_box(
                pending
                    .finish(&fixture.public, &request, &response)
                    .unwrap(),
            )
        });
    });
    group.finish();
}

fn wire_codecs(c: &mut Criterion) {
    let fixture = Fixture::new(PerformanceProfile::Balanced, 0xB5_0000);
    let request_bytes = fixture.direct_request.to_bytes();
    let token_bytes = fixture.deferred.to_bytes();
    let public_bytes = fixture.public.to_bytes();

    let mut group = c.benchmark_group("wire");
    group.sampling_mode(SamplingMode::Flat);

    group.throughput(Throughput::Bytes(request_bytes.len() as u64));
    group.bench_function("direct-request/encode", |b| {
        b.iter(|| black_box(fixture.direct_request.to_bytes()));
    });
    group.bench_function("direct-request/decode", |b| {
        b.iter(|| {
            black_box(SpendRequest::<Mayo2, Direct>::from_bytes(black_box(
                &request_bytes,
            )))
        });
    });

    group.throughput(Throughput::Bytes(token_bytes.len() as u64));
    group.bench_function("deferred-token/decode-and-authenticate", |b| {
        b.iter(|| {
            black_box(DeferredReturnToken::<Mayo2>::from_bytes(
                &fixture.public,
                black_box(&token_bytes),
            ))
        });
    });

    group.throughput(Throughput::Bytes(public_bytes.len() as u64));
    group.bench_function("public-key/decode-and-derive", |b| {
        b.iter(|| black_box(PublicKey::<Mayo2>::from_bytes(black_box(&public_bytes))));
    });
    group.finish();
}

criterion_group! {
    name = benches;
    config = Criterion::default()
        .sample_size(10)
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(3));
    targets = profile_comparison, balanced_protocol, wire_codecs
}
criterion_main!(benches);
