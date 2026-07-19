#![no_main]

mod common;

use libfuzzer_sys::fuzz_target;
use mayo::Mayo2;
use rand::SeedableRng;
use rand::rngs::StdRng;
use std::sync::OnceLock;
use vole_act::{
    DeferredReturn, DeferredReturnSpendRequest, DeferredReturnSpendResponse, DeferredReturnToken,
    Direct, DirectToken, IssueRequest, IssueResponse, Issuer, PendingDeferredReturnSpend,
    PendingIssue, PendingSpend, PublicKey, SpendRequest, SpendResponse,
};

struct Fixture {
    public: PublicKey<Mayo2>,
    artifacts: Vec<Vec<u8>>,
}

fn issue_token(
    issuer: &Issuer<Mayo2>,
    public: &PublicKey<Mayo2>,
    balance: u64,
    rng: &mut StdRng,
    artifacts: &mut Vec<Vec<u8>>,
) -> DirectToken<Mayo2> {
    let (pending, request) = public.prepare_issue(balance, rng).unwrap();
    let pending_bytes = pending.to_bytes();
    let request_bytes = request.to_bytes();
    let response = issuer.issue(&request, balance, rng).unwrap();
    let response_bytes = response.to_bytes();
    let token = pending.finish(public, &request, &response).unwrap();
    artifacts.extend([
        pending_bytes,
        request_bytes,
        response_bytes,
        token.to_bytes(),
    ]);
    token
}

fn fixture() -> &'static Fixture {
    static FIXTURE: OnceLock<Fixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let mut rng = StdRng::seed_from_u64(0x4152_5449_4641_4354);
        let mut issuer = Issuer::<Mayo2>::generate(b"vole-act/fuzz/artifacts", &mut rng);
        let public = issuer.public_key().clone();
        let mut artifacts = vec![public.to_bytes()];

        // Direct input -> direct output.
        let direct = issue_token(&issuer, &public, 100, &mut rng, &mut artifacts);
        let (pending, request) = direct.prepare_spend(&public, 31, &mut rng).unwrap();
        artifacts.push(pending.to_bytes());
        artifacts.push(request.to_bytes());
        let response = issuer.spend(&request, &mut rng).unwrap();
        artifacts.push(response.to_bytes());
        let output = pending.finish(&public, &request, &response).unwrap();
        artifacts.push(output.to_bytes());

        // Direct input -> deferred token -> direct output.
        let direct = issue_token(&issuer, &public, 100, &mut rng, &mut artifacts);
        let (pending, request) = direct
            .prepare_spend_with_deferred_return(&public, 40, &mut rng)
            .unwrap();
        artifacts.push(pending.to_bytes());
        artifacts.push(request.to_bytes());
        let response = issuer
            .spend_with_deferred_return(&request, 17, &mut rng)
            .unwrap();
        artifacts.push(response.to_bytes());
        let deferred = pending.finish(&public, &request, &response).unwrap();
        artifacts.push(deferred.to_bytes());
        let (pending, request) = deferred.prepare_spend(&public, 23, &mut rng).unwrap();
        artifacts.push(pending.to_bytes());
        artifacts.push(request.to_bytes());
        let response = issuer.spend(&request, &mut rng).unwrap();
        artifacts.push(response.to_bytes());
        let output = pending.finish(&public, &request, &response).unwrap();
        artifacts.push(output.to_bytes());

        // Deferred input -> deferred output.
        let direct = issue_token(&issuer, &public, 100, &mut rng, &mut artifacts);
        let (pending, request) = direct
            .prepare_spend_with_deferred_return(&public, 20, &mut rng)
            .unwrap();
        let response = issuer
            .spend_with_deferred_return(&request, 9, &mut rng)
            .unwrap();
        let deferred = pending.finish(&public, &request, &response).unwrap();
        let (pending, request) = deferred
            .prepare_spend_with_deferred_return(&public, 19, &mut rng)
            .unwrap();
        artifacts.push(pending.to_bytes());
        artifacts.push(request.to_bytes());
        let response = issuer
            .spend_with_deferred_return(&request, 3, &mut rng)
            .unwrap();
        artifacts.push(response.to_bytes());
        let output = pending.finish(&public, &request, &response).unwrap();
        artifacts.push(output.to_bytes());

        Fixture { public, artifacts }
    })
}

fuzz_target!(|data: &[u8]| {
    let fixture = fixture();
    let selection = data.first().copied().unwrap_or(0) as usize % fixture.artifacts.len();
    let baseline = &fixture.artifacts[selection];
    let candidate = common::mutate_valid(baseline, data.get(1..).unwrap_or_default());
    let mut successes = 0usize;

    macro_rules! canonical {
        ($decode:expr) => {
            if let Ok(value) = $decode {
                assert_eq!(
                    value.to_bytes(),
                    candidate,
                    "accepted a non-canonical protocol artifact"
                );
                successes += 1;
            }
        };
    }

    canonical!(PublicKey::<Mayo2>::from_bytes(&candidate));
    canonical!(IssueRequest::<Mayo2>::from_bytes(&candidate));
    canonical!(IssueResponse::<Mayo2>::from_bytes(&candidate));
    canonical!(PendingIssue::<Mayo2>::from_bytes(
        &fixture.public,
        &candidate
    ));
    canonical!(DirectToken::<Mayo2>::from_bytes(
        &fixture.public,
        &candidate
    ));
    canonical!(DeferredReturnToken::<Mayo2>::from_bytes(
        &fixture.public,
        &candidate
    ));

    canonical!(SpendRequest::<Mayo2, Direct>::from_bytes(&candidate));
    canonical!(SpendRequest::<Mayo2, DeferredReturn>::from_bytes(
        &candidate
    ));
    canonical!(DeferredReturnSpendRequest::<Mayo2, Direct>::from_bytes(
        &candidate
    ));
    canonical!(DeferredReturnSpendRequest::<Mayo2, DeferredReturn>::from_bytes(&candidate));

    canonical!(SpendResponse::<Mayo2, Direct>::from_bytes(&candidate));
    canonical!(SpendResponse::<Mayo2, DeferredReturn>::from_bytes(
        &candidate
    ));
    canonical!(DeferredReturnSpendResponse::<Mayo2, Direct>::from_bytes(
        &candidate
    ));
    canonical!(DeferredReturnSpendResponse::<Mayo2, DeferredReturn>::from_bytes(&candidate));

    canonical!(PendingSpend::<Mayo2, Direct>::from_bytes(
        &fixture.public,
        &candidate
    ));
    canonical!(PendingSpend::<Mayo2, DeferredReturn>::from_bytes(
        &fixture.public,
        &candidate
    ));
    canonical!(PendingDeferredReturnSpend::<Mayo2, Direct>::from_bytes(
        &fixture.public,
        &candidate,
    ));
    canonical!(
        PendingDeferredReturnSpend::<Mayo2, DeferredReturn>::from_bytes(
            &fixture.public,
            &candidate,
        )
    );

    assert!(
        successes <= 1,
        "one byte string decoded as multiple artifact types"
    );
    if candidate == *baseline {
        assert_eq!(successes, 1, "valid fixture failed its unique decoder");
    }
});
