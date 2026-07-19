#![no_main]

use libfuzzer_sys::fuzz_target;
use mayo::{Mayo2, PublicKey as MayoPublicKey, SecretKey as MayoSecretKey};
use vole_act::{
    DeferredReturn, DeferredReturnSpendRequest, DeferredReturnSpendResponse, Direct, IssueRequest,
    IssueResponse, Issuer, MemoryNullifierStore, PublicKey, RetryRecord, SpendRequest,
    SpendResponse,
};
use voleith::Proof;

fuzz_target!(|data: &[u8]| {
    let mut act_successes = 0usize;

    macro_rules! canonical_act {
        ($decode:expr) => {
            if let Ok(value) = $decode {
                assert_eq!(
                    value.to_bytes(),
                    data,
                    "accepted a non-canonical ACT encoding"
                );
                act_successes += 1;
            }
        };
    }

    canonical_act!(PublicKey::<Mayo2>::from_bytes(data));
    canonical_act!(RetryRecord::<Mayo2>::from_bytes(data));
    canonical_act!(IssueRequest::<Mayo2>::from_bytes(data));
    canonical_act!(IssueResponse::<Mayo2>::from_bytes(data));

    canonical_act!(SpendRequest::<Mayo2, Direct>::from_bytes(data));
    canonical_act!(SpendRequest::<Mayo2, DeferredReturn>::from_bytes(data));
    canonical_act!(DeferredReturnSpendRequest::<Mayo2, Direct>::from_bytes(
        data
    ));
    canonical_act!(DeferredReturnSpendRequest::<Mayo2, DeferredReturn>::from_bytes(data));

    canonical_act!(SpendResponse::<Mayo2, Direct>::from_bytes(data));
    canonical_act!(SpendResponse::<Mayo2, DeferredReturn>::from_bytes(data));
    canonical_act!(DeferredReturnSpendResponse::<Mayo2, Direct>::from_bytes(
        data
    ));
    canonical_act!(DeferredReturnSpendResponse::<Mayo2, DeferredReturn>::from_bytes(data));

    if let Ok(issuer) = Issuer::<Mayo2, MemoryNullifierStore<Mayo2>>::from_key_bytes_with_store(
        data,
        MemoryNullifierStore::default(),
    ) {
        assert_eq!(
            issuer.key_bytes(),
            data,
            "accepted a non-canonical issuer key"
        );
        act_successes += 1;
    }

    // Every outer artifact has a distinct type / credential-kind / settlement
    // tuple. Acceptance by two decoders would defeat that domain separation.
    assert!(act_successes <= 1, "ambiguous ACT wire encoding");

    if let Ok(proof) = Proof::from_bytes(data) {
        assert_eq!(proof.to_bytes(), data, "accepted a non-canonical proof");
    }
    if let Ok(public) = MayoPublicKey::<Mayo2>::from_bytes(data) {
        assert_eq!(
            public.to_bytes(),
            data,
            "accepted a non-canonical MAYO public key"
        );
    }
    if let Ok(secret) = MayoSecretKey::<Mayo2>::from_bytes(data) {
        assert_eq!(
            secret.to_bytes(),
            data,
            "accepted a non-canonical MAYO secret key"
        );
    }
});
