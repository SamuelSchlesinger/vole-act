//! Protocol integration tests (moved verbatim from the former protocol.rs).

use super::*;
use mayo::Mayo2;
use rand::SeedableRng;
use rand::rngs::StdRng;
use std::time::Instant;

fn issue_token(
    issuer: &Issuer<Mayo2>,
    public: &PublicKey<Mayo2>,
    balance: u64,
    rng: &mut StdRng,
) -> DirectToken<Mayo2> {
    let (pending, request) = public.prepare_issue(balance, rng).unwrap();
    let response = issuer.issue(&request, balance, rng).unwrap();
    pending.finish(public, &request, &response).unwrap()
}

fn wire_fingerprint(bytes: &[u8]) -> [u8; 32] {
    let mut hash = sha3::Shake256::default();
    hash.update(b"VOLE-ACT/test-vector-fingerprint/v1");
    hash.update(&(bytes.len() as u64).to_le_bytes());
    hash.update(bytes);
    let mut fingerprint = [0u8; 32];
    hash.finalize_xof().read(&mut fingerprint);
    fingerprint
}

#[test]
fn deterministic_mayo2_wire_vector() {
    let mut rng = StdRng::seed_from_u64(0x5645_4354_4F52_0001);
    let mut issuer = Issuer::<Mayo2>::generate_with_profile(
        b"test-vector/credits/epoch-1",
        PerformanceProfile::Balanced,
        &mut rng,
    );
    let public = issuer.public_key().clone();
    let (pending_issue, issue_request) = public.prepare_issue(90, &mut rng).unwrap();
    let issue_response = issuer.issue(&issue_request, 90, &mut rng).unwrap();
    let token = pending_issue
        .finish(&public, &issue_request, &issue_response)
        .unwrap();
    let (pending_spend, spend_request) = token.prepare_spend(&public, 17, &mut rng).unwrap();
    let spend_response = issuer.spend(&spend_request, &mut rng).unwrap();
    let output = pending_spend
        .finish(&public, &spend_request, &spend_response)
        .unwrap();

    let fingerprints = [
        public.to_bytes(),
        issue_request.to_bytes(),
        issue_response.to_bytes(),
        token.to_bytes(),
        spend_request.to_bytes(),
        spend_response.to_bytes(),
        output.to_bytes(),
    ]
    .map(|bytes| wire_fingerprint(&bytes));

    assert_eq!(
        fingerprints,
        [
            [
                0x03, 0xa1, 0x10, 0xe2, 0x05, 0x36, 0x8b, 0xb2, 0xf2, 0x0d, 0x3e, 0x8e, 0x7e, 0xbb,
                0xb5, 0x77, 0xaf, 0xca, 0x54, 0x68, 0x91, 0x67, 0x43, 0xd0, 0x7d, 0x8b, 0x43, 0xcd,
                0xb1, 0xc2, 0xd1, 0xb1,
            ],
            [
                0xee, 0xc2, 0xb5, 0xca, 0x39, 0xcc, 0x75, 0x14, 0x1e, 0x16, 0xa1, 0xc5, 0xd6, 0x2f,
                0x26, 0xf3, 0xe1, 0x56, 0xf5, 0x7a, 0xef, 0x97, 0x84, 0xc4, 0x16, 0x4e, 0xd0, 0x9f,
                0xc9, 0x11, 0x67, 0xd6,
            ],
            [
                0x89, 0x72, 0x0e, 0xd6, 0x42, 0x34, 0xcb, 0x11, 0xf3, 0x2a, 0xfa, 0xd2, 0x5d, 0xbb,
                0xa3, 0xfd, 0x52, 0xa2, 0x0f, 0xf1, 0x4c, 0x3d, 0x45, 0x86, 0x5a, 0xa7, 0x46, 0xb6,
                0x14, 0x46, 0x82, 0x7b,
            ],
            [
                0x46, 0x24, 0x1d, 0x27, 0xc6, 0x8a, 0x09, 0x7c, 0x8c, 0xdf, 0x8a, 0xab, 0xe9, 0x33,
                0xfa, 0x6b, 0x9f, 0xfc, 0x33, 0x29, 0xcc, 0x8a, 0x56, 0x3f, 0x2f, 0xd5, 0xf5, 0x2f,
                0x24, 0x1b, 0xc6, 0x7d,
            ],
            [
                0x33, 0x28, 0xcb, 0x08, 0x35, 0xaa, 0xd6, 0x77, 0x50, 0xb4, 0x74, 0x74, 0xbd, 0x95,
                0xe4, 0xdd, 0xa4, 0x58, 0xf7, 0xb5, 0xc7, 0x87, 0x01, 0x12, 0x6e, 0x3f, 0xa3, 0x39,
                0x41, 0x49, 0xcc, 0xb9,
            ],
            [
                0xa6, 0x59, 0x59, 0x98, 0xd4, 0x6e, 0x0d, 0x87, 0xc4, 0xd2, 0x77, 0x9e, 0x5d, 0xcd,
                0xee, 0x52, 0xee, 0xcc, 0xbc, 0x30, 0x18, 0x01, 0xa6, 0xcf, 0x82, 0x0f, 0x6e, 0x81,
                0xbf, 0x7d, 0x20, 0x66,
            ],
            [
                0xb8, 0xdf, 0xea, 0x72, 0x2c, 0xed, 0xd2, 0xd6, 0xe1, 0x91, 0x59, 0xf1, 0x3d, 0xb4,
                0xb4, 0x0a, 0x46, 0x18, 0xb9, 0x5e, 0x24, 0xe2, 0x37, 0x5e, 0x51, 0x9a, 0xca, 0x69,
                0xd0, 0x9b, 0x50, 0xab,
            ],
        ]
    );
}

#[test]
fn all_four_typed_spend_transitions_and_retries() {
    let mut rng = StdRng::seed_from_u64(0xAC7);
    let mut issuer = Issuer::<Mayo2>::generate(b"example/credits/epoch-1", &mut rng);
    let public = issuer.public_key().clone();
    let token: DirectToken<Mayo2> = issue_token(&issuer, &public, 100, &mut rng);
    public.verify_token(&token).unwrap();
    assert_eq!(
        token.prepare_spend(&public, 101, &mut rng).err(),
        Some(Error::InsufficientBalance)
    );

    // Direct -> direct.
    let (pending, request) = token.prepare_spend(&public, 10, &mut rng).unwrap();
    let response = issuer.spend(&request, &mut rng).unwrap();
    let retry = issuer.spend(&request, &mut rng).unwrap();
    assert_eq!(retry.signature, response.signature);
    let token: DirectToken<Mayo2> = pending.finish(&public, &request, &response).unwrap();
    assert_eq!(token.balance(), 90);

    // Direct -> deferred return.
    let (pending, request) = token
        .prepare_spend_with_deferred_return(&public, 20, &mut rng)
        .unwrap();
    let response = issuer
        .spend_with_deferred_return(&request, 7, &mut rng)
        .unwrap();
    assert_eq!(response.return_amount(), 7);
    let retry = issuer
        .spend_with_deferred_return(&request, 0, &mut rng)
        .unwrap();
    assert_eq!(retry.return_amount(), 7);
    assert_eq!(retry.signature, response.signature);
    let token: DeferredReturnToken<Mayo2> = pending.finish(&public, &request, &response).unwrap();
    assert_eq!(token.balance(), 77);

    // Deferred return -> deferred return.
    let (pending, request) = token
        .prepare_spend_with_deferred_return(&public, 10, &mut rng)
        .unwrap();
    let response = issuer
        .spend_with_deferred_return(&request, 4, &mut rng)
        .unwrap();
    let token: DeferredReturnToken<Mayo2> = pending.finish(&public, &request, &response).unwrap();
    assert_eq!(token.balance(), 71);

    // Deferred return -> direct, normalizing the old top-up.
    let (pending, request) = token.prepare_spend(&public, 11, &mut rng).unwrap();
    let response = issuer.spend(&request, &mut rng).unwrap();
    let token: DirectToken<Mayo2> = pending.finish(&public, &request, &response).unwrap();
    assert_eq!(token.balance(), 60);
    public.verify_token(&token).unwrap();
    assert_eq!(issuer.spent_count(), 4);
}

#[test]
fn statements_bind_public_values_context_and_modes() {
    let mut rng = StdRng::seed_from_u64(0xB1AD);
    let mut issuer = Issuer::<Mayo2>::generate(b"binding-test/issuer-a", &mut rng);
    let public = issuer.public_key().clone();

    let (pending_issue, issue_request) = public.prepare_issue(100, &mut rng).unwrap();
    assert_eq!(
        issuer.issue(&issue_request, 99, &mut rng).unwrap_err(),
        Error::InvalidProof
    );
    let issue_response = issuer.issue(&issue_request, 100, &mut rng).unwrap();
    let token = pending_issue
        .finish(&public, &issue_request, &issue_response)
        .unwrap();

    let (_pending, request) = token.prepare_spend(&public, 35, &mut rng).unwrap();
    let mut wrong_spend = request.clone();
    wrong_spend.spend += 1;
    assert_eq!(
        issuer.spend(&wrong_spend, &mut rng).unwrap_err(),
        Error::InvalidProof
    );
    let mut wrong_nullifier = request.clone();
    wrong_nullifier.nullifier[0] ^= 1;
    assert_eq!(
        issuer.spend(&wrong_nullifier, &mut rng).unwrap_err(),
        Error::InvalidProof
    );
    let mut wrong_commitment = request.clone();
    wrong_commitment.fresh_commitment[0] += GF16::new(1);
    assert_eq!(
        issuer.spend(&wrong_commitment, &mut rng).unwrap_err(),
        Error::InvalidProof
    );

    // Re-tagging the input credential kind also changes the statement and
    // circuit shape, even when all serialized request fields are copied.
    let wrong_input_kind = TypedSpendRequest::<Mayo2, DeferredReturn, FixedSpend> {
        spend: request.spend,
        nullifier: request.nullifier,
        fresh_commitment: request.fresh_commitment.clone(),
        proof: request.proof.clone(),
        params: PhantomData,
    };
    assert_eq!(
        issuer.spend(&wrong_input_kind, &mut rng).unwrap_err(),
        Error::InvalidProof
    );

    // Re-tagging an ordinary request as deferred return does not verify:
    // the mode is bound into Fiat-Shamir independently of Rust's types.
    let wrong_mode = TypedSpendRequest::<Mayo2, Direct, DeferredReturnSpend> {
        spend: request.spend,
        nullifier: request.nullifier,
        fresh_commitment: request.fresh_commitment.clone(),
        proof: request.proof.clone(),
        params: PhantomData,
    };
    assert_eq!(
        issuer
            .spend_with_deferred_return(&wrong_mode, 0, &mut rng)
            .unwrap_err(),
        Error::InvalidProof
    );
    assert_eq!(issuer.spent_count(), 0);

    let (_pending, deferred_request) = token
        .prepare_spend_with_deferred_return(&public, 35, &mut rng)
        .unwrap();
    assert_eq!(
        issuer
            .spend_with_deferred_return(&deferred_request, 36, &mut rng)
            .unwrap_err(),
        Error::InvalidReturnAmount
    );
    assert_eq!(issuer.spent_count(), 0);

    let other = Issuer::<Mayo2>::generate(b"binding-test/issuer-b", &mut rng);
    assert_eq!(
        token.prepare_spend(other.public_key(), 1, &mut rng).err(),
        Some(Error::WrongContext)
    );
}

#[test]
fn cross_mode_retry_and_signature_reinterpretation_are_rejected() {
    let mut rng = StdRng::seed_from_u64(0x70_7A);
    let mut issuer = Issuer::<Mayo2>::generate(b"mode-separation", &mut rng);
    let public = issuer.public_key().clone();
    let token = issue_token(&issuer, &public, 50, &mut rng);

    // A direct signature cannot be reinterpreted as a deferred-return
    // signature, even with a zero top-up.
    let retagged = Token::<Mayo2, DeferredReturn> {
        context: token.context,
        signature: token.signature.clone(),
        key: token.key,
        base_balance: token.base_balance,
        nonce: token.nonce,
        topup: 0,
        params: PhantomData,
    };
    assert_eq!(
        public.verify_token(&retagged).unwrap_err(),
        Error::InvalidSignature
    );

    let (_pending, request) = token.prepare_spend(&public, 20, &mut rng).unwrap();
    let response = issuer.spend(&request, &mut rng).unwrap();

    let cross_mode = TypedSpendRequest::<Mayo2, Direct, DeferredReturnSpend> {
        spend: request.spend,
        nullifier: request.nullifier,
        fresh_commitment: request.fresh_commitment.clone(),
        proof: request.proof.clone(),
        params: PhantomData,
    };
    assert_eq!(
        issuer
            .spend_with_deferred_return(&cross_mode, 0, &mut rng)
            .unwrap_err(),
        Error::NullifierAlreadySpent
    );

    let wrapper_target =
        signed_token_target::<Mayo2>(&public.inner.context, &request.fresh_commitment, 0);
    let evaluated = mayo::eval(&public.inner.mayo, &response.signature).unwrap();
    assert_eq!(evaluated, request.fresh_commitment);
    assert_ne!(evaluated, wrapper_target);
}

#[test]
fn deferred_return_amount_is_signature_bound() {
    let mut rng = StdRng::seed_from_u64(0xD3FE_22ED);
    let mut issuer = Issuer::<Mayo2>::generate(b"return-binding", &mut rng);
    let public = issuer.public_key().clone();
    let token = issue_token(&issuer, &public, 50, &mut rng);

    let (pending, request) = token
        .prepare_spend_with_deferred_return(&public, 20, &mut rng)
        .unwrap();
    let mut response = issuer
        .spend_with_deferred_return(&request, 7, &mut rng)
        .unwrap();
    response.return_amount = 8;
    assert_eq!(
        pending.finish(&public, &request, &response).err(),
        Some(Error::InvalidSignature)
    );
}

#[test]
fn full_u64_refund_is_exact_and_can_be_normalized() {
    let mut rng = StdRng::seed_from_u64(0xF011_0064);
    let mut issuer = Issuer::<Mayo2>::generate(b"full-refund-boundary", &mut rng);
    let public = issuer.public_key().clone();
    let token = issue_token(&issuer, &public, u64::MAX, &mut rng);

    let (pending, request) = token
        .prepare_spend_with_deferred_return(&public, u64::MAX, &mut rng)
        .unwrap();
    let response = issuer
        .spend_with_deferred_return(&request, u64::MAX, &mut rng)
        .unwrap();
    let token = pending.finish(&public, &request, &response).unwrap();
    assert_eq!(token.balance(), u64::MAX);

    let (pending, request) = token.prepare_spend(&public, u64::MAX, &mut rng).unwrap();
    let response = issuer.spend(&request, &mut rng).unwrap();
    let token: DirectToken<Mayo2> = pending.finish(&public, &request, &response).unwrap();
    assert_eq!(token.balance(), 0);
    public.verify_token(&token).unwrap();
}

#[test]
fn canonical_wire_roundtrips_and_preserves_type_separation() {
    let mut rng = StdRng::seed_from_u64(0x5749_5245);
    let mut issuer = Issuer::<Mayo2>::generate(b"wire/credits/epoch-9", &mut rng);
    let public_bytes = issuer.public_key().to_bytes();
    let public = PublicKey::<Mayo2>::from_bytes(&public_bytes).unwrap();
    assert_eq!(public.to_bytes(), public_bytes);
    assert_eq!(public.context(), issuer.public_key().context());
    assert_eq!(
        PublicKey::<Mayo1>::from_bytes(&public_bytes).err(),
        Some(WireError::WrongParameterSet)
    );

    let key_bytes = issuer.key_bytes();
    let restored =
        Issuer::<Mayo2>::from_key_bytes_with_store(&key_bytes, MemoryNullifierStore::default())
            .unwrap();
    assert_eq!(restored.public_key().to_bytes(), public_bytes);
    assert_eq!(restored.key_bytes(), key_bytes);

    let (pending_issue, issue_request) = public.prepare_issue(90, &mut rng).unwrap();
    let pending_issue =
        PendingIssue::<Mayo2>::from_bytes(&public, &pending_issue.to_bytes()).unwrap();
    let issue_request = IssueRequest::<Mayo2>::from_bytes(&issue_request.to_bytes()).unwrap();
    let issue_response = issuer.issue(&issue_request, 90, &mut rng).unwrap();
    let issue_response = IssueResponse::<Mayo2>::from_bytes(&issue_response.to_bytes()).unwrap();
    let token = pending_issue
        .finish(&public, &issue_request, &issue_response)
        .unwrap();
    let token_bytes = token.to_bytes();
    let token = DirectToken::<Mayo2>::from_bytes(&public, &token_bytes).unwrap();
    let mut direct_with_topup = token_bytes;
    *direct_with_topup.last_mut().unwrap() = 1;
    assert_eq!(
        DirectToken::<Mayo2>::from_bytes(&public, &direct_with_topup).err(),
        Some(WireError::WrongArtifact)
    );

    let (pending, request) = token.prepare_spend(&public, 20, &mut rng).unwrap();
    let pending_bytes = pending.to_bytes();
    let request_bytes = request.to_bytes();
    let pending = PendingSpend::<Mayo2, Direct>::from_bytes(&public, &pending_bytes).unwrap();
    let request = SpendRequest::<Mayo2, Direct>::from_bytes(&request_bytes).unwrap();
    let response = issuer.spend(&request, &mut rng).unwrap();
    let response = SpendResponse::<Mayo2, Direct>::from_bytes(&response.to_bytes()).unwrap();
    let token = pending.finish(&public, &request, &response).unwrap();
    assert_eq!(token.balance(), 70);

    let record = issuer.store().get(&request.nullifier()).unwrap().unwrap();
    assert_eq!(
        RetryRecord::<Mayo2>::from_bytes(&record.to_bytes()).unwrap(),
        record
    );

    let (pending, deferred_request) = token
        .prepare_spend_with_deferred_return(&public, 30, &mut rng)
        .unwrap();
    let deferred_bytes = deferred_request.to_bytes();
    assert_eq!(
        SpendRequest::<Mayo2, Direct>::from_bytes(&deferred_bytes).unwrap_err(),
        WireError::WrongArtifact
    );
    let deferred_request =
        DeferredReturnSpendRequest::<Mayo2, Direct>::from_bytes(&deferred_bytes).unwrap();
    let response = issuer
        .spend_with_deferred_return(&deferred_request, 11, &mut rng)
        .unwrap();
    let response_bytes = response.to_bytes();
    assert_eq!(
        SpendResponse::<Mayo2, Direct>::from_bytes(&response_bytes).unwrap_err(),
        WireError::WrongArtifact
    );
    let response =
        DeferredReturnSpendResponse::<Mayo2, Direct>::from_bytes(&response_bytes).unwrap();
    let pending =
        PendingDeferredReturnSpend::<Mayo2, Direct>::from_bytes(&public, &pending.to_bytes())
            .unwrap();
    let deferred = pending
        .finish(&public, &deferred_request, &response)
        .unwrap();
    let deferred_bytes = deferred.to_bytes();
    assert_eq!(
        DirectToken::<Mayo2>::from_bytes(&public, &deferred_bytes).err(),
        Some(WireError::WrongArtifact)
    );
    let deferred = DeferredReturnToken::<Mayo2>::from_bytes(&public, &deferred_bytes).unwrap();
    assert_eq!(deferred.balance(), 51);

    let mut trailing = public_bytes.clone();
    trailing.push(0);
    assert!(PublicKey::<Mayo2>::from_bytes(&trailing).is_err());
    let mut trailing = key_bytes.clone();
    trailing.push(0);
    assert!(
        Issuer::<Mayo2>::from_key_bytes_with_store(&trailing, MemoryNullifierStore::default(),)
            .is_err()
    );
    let mut trailing = request_bytes.clone();
    trailing.push(0);
    assert!(SpendRequest::<Mayo2, Direct>::from_bytes(&trailing).is_err());
    let mut trailing = pending_bytes.clone();
    trailing.push(0);
    assert!(PendingSpend::<Mayo2, Direct>::from_bytes(&public, &trailing).is_err());
    let mut trailing = deferred_bytes;
    trailing.push(0);
    assert!(DeferredReturnToken::<Mayo2>::from_bytes(&public, &trailing).is_err());
}

struct FailingStore;

impl NullifierStore<Mayo2> for FailingStore {
    fn get(&self, _nullifier: &[u8; 32]) -> Result<Option<RetryRecord<Mayo2>>, Error> {
        Ok(None)
    }

    fn insert_if_absent(
        &mut self,
        _nullifier: [u8; 32],
        _candidate: RetryRecord<Mayo2>,
    ) -> Result<RetryRecord<Mayo2>, Error> {
        Err(Error::StorageFailure)
    }
}

#[test]
fn issuer_never_returns_a_signature_before_nullifier_persistence() {
    let mut rng = StdRng::seed_from_u64(0x00D0_A81E);
    let mut issuer = Issuer::<Mayo2, FailingStore>::generate_with_store(
        b"durability/failure",
        PerformanceProfile::Balanced,
        FailingStore,
        &mut rng,
    );
    let public = issuer.public_key().clone();
    let (pending, request) = public.prepare_issue(20, &mut rng).unwrap();
    let response = issuer.issue(&request, 20, &mut rng).unwrap();
    let token = pending.finish(&public, &request, &response).unwrap();
    let (_pending, request) = token.prepare_spend(&public, 5, &mut rng).unwrap();
    assert_eq!(
        issuer.spend(&request, &mut rng).unwrap_err(),
        Error::StorageFailure
    );
}

#[test]
#[ignore = "performance characterization; run with --release -- --ignored --nocapture"]
fn benchmark_profiles() {
    for profile in [
        PerformanceProfile::Compact,
        PerformanceProfile::Balanced,
        PerformanceProfile::LowLatency,
    ] {
        let mut rng = StdRng::seed_from_u64(0xAC7);
        let mut issuer =
            Issuer::<Mayo2>::generate_with_profile(b"benchmark/credits/epoch-1", profile, &mut rng);
        let public = issuer.public_key().clone();

        let start = Instant::now();
        let (pending_issue, issue_request) = public.prepare_issue(100, &mut rng).unwrap();
        let issue_prove = start.elapsed();
        let start = Instant::now();
        let issue_response = issuer.issue(&issue_request, 100, &mut rng).unwrap();
        let issue_verify_sign = start.elapsed();
        let token = pending_issue
            .finish(&public, &issue_request, &issue_response)
            .unwrap();

        let start = Instant::now();
        let (pending_direct, direct_request) = token.prepare_spend(&public, 20, &mut rng).unwrap();
        let direct_prove = start.elapsed();
        let start = Instant::now();
        let direct_response = issuer.spend(&direct_request, &mut rng).unwrap();
        let direct_verify_sign = start.elapsed();
        let direct_token = pending_direct
            .finish(&public, &direct_request, &direct_response)
            .unwrap();

        let (pending_defer, defer_request) = direct_token
            .prepare_spend_with_deferred_return(&public, 20, &mut rng)
            .unwrap();
        let defer_response = issuer
            .spend_with_deferred_return(&defer_request, 5, &mut rng)
            .unwrap();
        let deferred_token = pending_defer
            .finish(&public, &defer_request, &defer_response)
            .unwrap();

        let start = Instant::now();
        let (_pending_redeem, redeem_request) =
            deferred_token.prepare_spend(&public, 10, &mut rng).unwrap();
        let deferred_input_prove = start.elapsed();
        let start = Instant::now();
        issuer.spend(&redeem_request, &mut rng).unwrap();
        let deferred_input_verify_sign = start.elapsed();

        eprintln!(
            "{profile:?}: issue prove={issue_prove:?}, verify+sign={issue_verify_sign:?}, payload={} bytes; direct-input spend prove={direct_prove:?}, verify+sign={direct_verify_sign:?}, payload={} bytes; deferred-input spend prove={deferred_input_prove:?}, verify+sign={deferred_input_verify_sign:?}, payload={} bytes",
            issue_request.proof.payload_len(),
            direct_request.proof.payload_len(),
            redeem_request.proof.payload_len(),
        );
    }
}
