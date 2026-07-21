//! Protocol integration tests (moved verbatim from the former protocol.rs).

use super::*;
use mayo::Mayo2;
use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};
use std::collections::HashMap;
use std::sync::{Arc, Barrier, Mutex};
use std::thread;
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

fn as_wire_v1(mut bytes: Vec<u8>) -> Vec<u8> {
    assert_eq!(&bytes[..4], b"VACT");
    bytes[4] = 1;
    bytes
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
                0xf1, 0x63, 0xe4, 0xcc, 0x68, 0xcd, 0xfe, 0x2b, 0xdf, 0xff, 0xbb, 0x2b, 0x11, 0xc9,
                0x90, 0x63, 0x9f, 0x78, 0x23, 0xfa, 0x3a, 0x9a, 0xb0, 0x87, 0xf6, 0x33, 0x64, 0xf1,
                0x62, 0x4d, 0xb4, 0xec,
            ],
            [
                0xf2, 0xcc, 0x93, 0x4e, 0x4c, 0xe4, 0xd9, 0x4f, 0x4a, 0xee, 0x10, 0xaa, 0xcb, 0xf3,
                0x7a, 0x78, 0xa3, 0x37, 0x14, 0xe0, 0xb0, 0x83, 0xd7, 0x09, 0x1e, 0x2e, 0xb1, 0x40,
                0x63, 0x14, 0xa6, 0x24,
            ],
            [
                0x18, 0x31, 0x60, 0x28, 0xb5, 0xd6, 0x13, 0xdb, 0x9c, 0xae, 0xb2, 0x4f, 0xeb, 0x1c,
                0x58, 0x2c, 0x28, 0x42, 0x9a, 0x37, 0xc3, 0xb9, 0xe2, 0x92, 0x5a, 0x5f, 0x8e, 0x52,
                0x09, 0xa8, 0x76, 0x0b,
            ],
            [
                0x02, 0xc7, 0x19, 0x1e, 0x6f, 0xa9, 0x05, 0xf1, 0x89, 0x8a, 0x29, 0x2e, 0x36, 0x3e,
                0x8e, 0xa7, 0xf1, 0xa3, 0x5e, 0x45, 0x26, 0xa7, 0x88, 0x4e, 0x9e, 0xb3, 0xad, 0xc1,
                0xf4, 0xd5, 0xa0, 0xd3,
            ],
            [
                0x0b, 0xf3, 0x34, 0xb5, 0xde, 0x57, 0xa2, 0xeb, 0x84, 0x18, 0x80, 0x00, 0x8a, 0xfb,
                0x7c, 0x9f, 0x16, 0x88, 0x22, 0x55, 0x64, 0x9c, 0x0a, 0xa0, 0x50, 0x85, 0xc7, 0x06,
                0x36, 0x8a, 0x0d, 0x09,
            ],
            [
                0xee, 0x70, 0xfe, 0x60, 0x17, 0x3a, 0xac, 0x5f, 0x75, 0x65, 0x92, 0xaa, 0xc2, 0x36,
                0x55, 0xe7, 0x2f, 0x9a, 0x4c, 0x3b, 0x68, 0x4a, 0xb1, 0xb0, 0x49, 0xd2, 0x68, 0x37,
                0x7d, 0xbb, 0xaa, 0xe2,
            ],
            [
                0x9a, 0xf0, 0xc1, 0xd6, 0x79, 0xcc, 0x60, 0x7d, 0x7d, 0xf2, 0xfe, 0x6d, 0x4d, 0x5e,
                0x82, 0x54, 0x9e, 0x67, 0x23, 0x97, 0x7f, 0x24, 0xef, 0xfa, 0x93, 0x0e, 0x0a, 0xbf,
                0x66, 0xcf, 0xa9, 0xf9,
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
    let pending_bytes = pending.to_bytes();
    let direct_payload_len = request.proof.payload_len();
    let response = issuer.spend(&request, &mut rng).unwrap();
    let retry = issuer.spend(&request, &mut rng).unwrap();
    assert_eq!(retry.signature, response.signature);
    assert_eq!(retry.salt, response.salt);
    let mut tampered = response.clone();
    tampered.salt[0] ^= 1;
    let tampered_pending =
        PendingSpend::<Mayo2, Direct>::from_bytes(&public, &pending_bytes).unwrap();
    assert_eq!(
        tampered_pending.finish(&public, &request, &tampered).err(),
        Some(Error::InvalidSignature)
    );
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
    assert_eq!(retry.salt, response.salt);
    let mut retry_rng = StdRng::seed_from_u64(0xDEC0_DED0);
    let mut untouched_retry_rng = retry_rng.clone();
    let out_of_range_retry = issuer
        .spend_with_deferred_return(&request, 21, &mut retry_rng)
        .unwrap();
    assert_eq!(out_of_range_retry.return_amount(), 7);
    assert_eq!(out_of_range_retry.signature, response.signature);
    assert_eq!(out_of_range_retry.salt, response.salt);
    assert_eq!(
        retry_rng.next_u64(),
        untouched_retry_rng.next_u64(),
        "an exact retry must replay before validating a new return or consuming signer randomness"
    );
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
    assert_eq!(request.proof.payload_len(), direct_payload_len);
    let response = issuer.spend(&request, &mut rng).unwrap();
    let token: DirectToken<Mayo2> = pending.finish(&public, &request, &response).unwrap();
    assert_eq!(token.balance(), 60);
    public.verify_token(&token).unwrap();
    assert_eq!(issuer.spent_count(), 4);
}

#[test]
fn signer_salt_randomizes_repeated_issue_targets_and_is_authenticated() {
    let mut rng = StdRng::seed_from_u64(0x005A_17ED);
    let mut issuer = Issuer::<Mayo2>::generate(b"signer-salt", &mut rng);
    let public = issuer.public_key().clone();
    let (pending, request) = public.prepare_issue(50, &mut rng).unwrap();
    let pending_bytes = pending.to_bytes();

    let first = issuer.issue(&request, 50, &mut rng).unwrap();
    let second = issuer.issue(&request, 50, &mut rng).unwrap();
    assert_ne!(first.salt, second.salt);

    let first_target = signed_token_target::<Mayo2>(&request.commitment, 0, &first.salt);
    let second_target = signed_token_target::<Mayo2>(&request.commitment, 0, &second.salt);
    assert_ne!(first_target, second_target);
    assert_eq!(
        mayo::eval(&public.inner.mayo, &first.signature).unwrap(),
        first_target
    );
    assert_eq!(
        mayo::eval(&public.inner.mayo, &second.signature).unwrap(),
        second_target
    );

    let mut tampered = first.clone();
    tampered.salt[0] ^= 1;
    let pending = PendingIssue::from_bytes(&public, &pending_bytes).unwrap();
    assert_eq!(
        pending.finish(&public, &request, &tampered).err(),
        Some(Error::InvalidSignature)
    );
    let pending = PendingIssue::from_bytes(&public, &pending_bytes).unwrap();
    let first_token = pending.finish(&public, &request, &first).unwrap();
    let pending = PendingIssue::from_bytes(&public, &pending_bytes).unwrap();
    let second_token = pending.finish(&public, &request, &second).unwrap();

    let (_first_pending, first_spend) = first_token.prepare_spend(&public, 1, &mut rng).unwrap();
    let (_second_pending, second_spend) = second_token.prepare_spend(&public, 1, &mut rng).unwrap();
    assert_eq!(first_spend.nullifier(), second_spend.nullifier());
    issuer.spend(&first_spend, &mut rng).unwrap();
    assert_eq!(
        issuer.spend(&second_spend, &mut rng).unwrap_err(),
        Error::NullifierAlreadySpent,
        "independently salted authenticators over one opening remain one spendable lineage"
    );
}

#[test]
fn statements_bind_public_values_context_and_modes() {
    let mut rng = StdRng::seed_from_u64(0xB1AD);
    let mut issuer = Issuer::<Mayo2>::generate(b"binding-test/issuer-a", &mut rng);
    let public = issuer.public_key().clone();

    let (pending_issue, issue_request) = public.prepare_issue(100, &mut rng).unwrap();
    let mut invalid_issue_rng = StdRng::seed_from_u64(0x51A7_71A1);
    let mut untouched_issue_rng = invalid_issue_rng.clone();
    assert_eq!(
        issuer
            .issue(&issue_request, 99, &mut invalid_issue_rng)
            .unwrap_err(),
        Error::InvalidProof
    );
    assert_eq!(
        invalid_issue_rng.next_u64(),
        untouched_issue_rng.next_u64(),
        "an invalid issuance proof must be rejected before signer randomness is consumed"
    );
    let issue_response = issuer.issue(&issue_request, 100, &mut rng).unwrap();
    let token = pending_issue
        .finish(&public, &issue_request, &issue_response)
        .unwrap();

    let (_pending, request) = token.prepare_spend(&public, 35, &mut rng).unwrap();
    let mut wrong_spend = request.clone();
    wrong_spend.spend += 1;
    let mut invalid_spend_rng = StdRng::seed_from_u64(0x51A7_5EED);
    let mut untouched_spend_rng = invalid_spend_rng.clone();
    assert_eq!(
        issuer
            .spend(&wrong_spend, &mut invalid_spend_rng)
            .unwrap_err(),
        Error::InvalidProof
    );
    assert_eq!(
        invalid_spend_rng.next_u64(),
        untouched_spend_rng.next_u64(),
        "an invalid spend proof must be rejected before signer randomness is consumed"
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
    let mut invalid_deferred_rng = StdRng::seed_from_u64(0x51A7_DEFE);
    let mut untouched_deferred_rng = invalid_deferred_rng.clone();
    assert_eq!(
        issuer
            .spend_with_deferred_return(&wrong_mode, 0, &mut invalid_deferred_rng)
            .unwrap_err(),
        Error::InvalidProof
    );
    assert_eq!(
        invalid_deferred_rng.next_u64(),
        untouched_deferred_rng.next_u64(),
        "a bounded invalid deferred proof must fail before signer randomness is consumed"
    );
    assert_eq!(issuer.spent_count(), 0);

    let (_pending, deferred_request) = token
        .prepare_spend_with_deferred_return(&public, 35, &mut rng)
        .unwrap();
    let mut over_bound_rng = StdRng::seed_from_u64(0x51A7_B0D0);
    let mut untouched_over_bound_rng = over_bound_rng.clone();
    assert_eq!(
        issuer
            .spend_with_deferred_return(&deferred_request, 36, &mut over_bound_rng)
            .unwrap_err(),
        Error::InvalidReturnAmount
    );
    assert_eq!(
        over_bound_rng.next_u64(),
        untouched_over_bound_rng.next_u64(),
        "an over-bound deferred return must fail before proof verification and signing"
    );
    assert_eq!(issuer.spent_count(), 0);

    let other = Issuer::<Mayo2>::generate(b"binding-test/issuer-b", &mut rng);
    assert_eq!(
        token.prepare_spend(other.public_key(), 1, &mut rng).err(),
        Some(Error::WrongContext)
    );
}

#[test]
fn cross_mode_retry_is_rejected_while_zero_return_credentials_share_a_target_shape() {
    let mut rng = StdRng::seed_from_u64(0x70_7A);
    let mut issuer = Issuer::<Mayo2>::generate(b"mode-separation", &mut rng);
    let public = issuer.public_key().clone();
    let token = issue_token(&issuer, &public, 50, &mut rng);

    // Credential kinds now share one authenticated representation. A zero
    // return can therefore be viewed through either local marker; the marker
    // still separates request statements and wire artifacts.
    let retagged = Token::<Mayo2, DeferredReturn> {
        context: token.context,
        signature: token.signature.clone(),
        key: token.key,
        base_balance: token.base_balance,
        nonce: token.nonce,
        topup: 0,
        salt: token.salt,
        params: PhantomData,
    };
    public.verify_token(&retagged).unwrap();

    let (pending, request) = token.prepare_spend(&public, 20, &mut rng).unwrap();
    let response = issuer.spend(&request, &mut rng).unwrap();

    // Wire tags identify the requested Rust artifact, but do not authenticate
    // identical-layout bodies. These zero-return/header aliases parse; the
    // proof statement, request digest, and semantic nullifier lineage provide
    // the end-to-end boundary.
    let mut retagged_token_bytes = token.to_bytes();
    retagged_token_bytes[7] = DeferredReturn::WIRE_ID;
    let retagged_token =
        DeferredReturnToken::<Mayo2>::from_bytes(&public, &retagged_token_bytes).unwrap();
    assert_eq!(retagged_token.balance(), token.balance());

    let mut retagged_request_bytes = request.to_bytes();
    retagged_request_bytes[8] = DeferredReturnSpend::WIRE_ID;
    DeferredReturnSpendRequest::<Mayo2, Direct>::from_bytes(&retagged_request_bytes).unwrap();

    let mut retagged_pending_bytes = pending.to_bytes();
    retagged_pending_bytes[8] = DeferredReturnSpend::WIRE_ID;
    PendingDeferredReturnSpend::<Mayo2, Direct>::from_bytes(&public, &retagged_pending_bytes)
        .unwrap();

    let mut retagged_response_bytes = response.to_bytes();
    retagged_response_bytes[8] = DeferredReturnSpend::WIRE_ID;
    let retagged_response =
        DeferredReturnSpendResponse::<Mayo2, Direct>::from_bytes(&retagged_response_bytes).unwrap();
    assert_eq!(retagged_response.return_amount(), 0);

    let record = issuer.store().get(&request.nullifier()).unwrap().unwrap();
    let mut retagged_record_bytes = record.to_bytes();
    retagged_record_bytes[8] = DeferredReturnSpend::WIRE_ID;
    let retagged_record = RetryRecord::<Mayo2>::from_bytes(&retagged_record_bytes).unwrap();
    assert!(matches!(
        retagged_record.response(),
        RetryResponse::DeferredReturn {
            return_amount: 0,
            ..
        }
    ));

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

    let wrapper_target = signed_token_target::<Mayo2>(&request.fresh_commitment, 0, &response.salt);
    let evaluated = mayo::eval(&public.inner.mayo, &response.signature).unwrap();
    assert_eq!(evaluated, wrapper_target);
    assert_ne!(evaluated, request.fresh_commitment);
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
    let pending_bytes = pending.to_bytes();
    let response = issuer
        .spend_with_deferred_return(&request, 7, &mut rng)
        .unwrap();
    let mut wrong_amount = response.clone();
    wrong_amount.return_amount = 8;
    let restored =
        PendingDeferredReturnSpend::<Mayo2, Direct>::from_bytes(&public, &pending_bytes).unwrap();
    assert_eq!(
        restored.finish(&public, &request, &wrong_amount).err(),
        Some(Error::InvalidSignature)
    );

    let mut wrong_salt = response.clone();
    wrong_salt.salt[0] ^= 1;
    let restored =
        PendingDeferredReturnSpend::<Mayo2, Direct>::from_bytes(&public, &pending_bytes).unwrap();
    assert_eq!(
        restored.finish(&public, &request, &wrong_salt).err(),
        Some(Error::InvalidSignature)
    );

    pending.finish(&public, &request, &response).unwrap();
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
    assert_eq!(
        PublicKey::<Mayo2>::from_bytes(&as_wire_v1(public_bytes.clone())).unwrap_err(),
        WireError::UnsupportedVersion
    );
    let public = PublicKey::<Mayo2>::from_bytes(&public_bytes).unwrap();
    assert_eq!(public.to_bytes(), public_bytes);
    assert_eq!(public.context(), issuer.public_key().context());
    assert_eq!(
        PublicKey::<Mayo1>::from_bytes(&public_bytes).err(),
        Some(WireError::WrongParameterSet)
    );

    let key_bytes = issuer.key_bytes();
    assert_eq!(
        Issuer::<Mayo2>::from_key_bytes_with_store(
            &as_wire_v1(key_bytes.clone()),
            MemoryNullifierStore::default(),
        )
        .err(),
        Some(WireError::UnsupportedVersion)
    );
    let restored =
        Issuer::<Mayo2>::from_key_bytes_with_store(&key_bytes, MemoryNullifierStore::default())
            .unwrap();
    assert_eq!(restored.public_key().to_bytes(), public_bytes);
    assert_eq!(restored.key_bytes(), key_bytes);

    let (pending_issue, issue_request) = public.prepare_issue(90, &mut rng).unwrap();
    let pending_issue_bytes = pending_issue.to_bytes();
    assert_eq!(
        PendingIssue::<Mayo2>::from_bytes(&public, &as_wire_v1(pending_issue_bytes.clone())).err(),
        Some(WireError::UnsupportedVersion)
    );
    let pending_issue = PendingIssue::<Mayo2>::from_bytes(&public, &pending_issue_bytes).unwrap();
    let issue_request_bytes = issue_request.to_bytes();
    assert_eq!(
        IssueRequest::<Mayo2>::from_bytes(&as_wire_v1(issue_request_bytes.clone())).unwrap_err(),
        WireError::UnsupportedVersion
    );
    let issue_request = IssueRequest::<Mayo2>::from_bytes(&issue_request_bytes).unwrap();
    let issue_response = issuer.issue(&issue_request, 90, &mut rng).unwrap();
    let issue_response_bytes = issue_response.to_bytes();
    assert_eq!(
        IssueResponse::<Mayo2>::from_bytes(&as_wire_v1(issue_response_bytes.clone())).unwrap_err(),
        WireError::UnsupportedVersion
    );
    let issue_response = IssueResponse::<Mayo2>::from_bytes(&issue_response_bytes).unwrap();
    let token = pending_issue
        .finish(&public, &issue_request, &issue_response)
        .unwrap();
    let token_bytes = token.to_bytes();
    assert_eq!(
        DirectToken::<Mayo2>::from_bytes(&public, &as_wire_v1(token_bytes.clone())).err(),
        Some(WireError::UnsupportedVersion)
    );
    let token = DirectToken::<Mayo2>::from_bytes(&public, &token_bytes).unwrap();
    let mut direct_with_topup = token_bytes;
    let topup_offset = direct_with_topup.len() - SALT_BYTES - core::mem::size_of::<u64>();
    direct_with_topup[topup_offset] = 1;
    assert_eq!(
        DirectToken::<Mayo2>::from_bytes(&public, &direct_with_topup).err(),
        Some(WireError::WrongArtifact)
    );
    let mut direct_with_bad_salt = token.to_bytes();
    *direct_with_bad_salt.last_mut().unwrap() ^= 1;
    assert_eq!(
        DirectToken::<Mayo2>::from_bytes(&public, &direct_with_bad_salt).err(),
        Some(WireError::InvalidCredential)
    );

    let (pending, request) = token.prepare_spend(&public, 20, &mut rng).unwrap();
    let pending_bytes = pending.to_bytes();
    let request_bytes = request.to_bytes();
    assert_eq!(
        PendingSpend::<Mayo2, Direct>::from_bytes(&public, &as_wire_v1(pending_bytes.clone()))
            .err(),
        Some(WireError::UnsupportedVersion)
    );
    assert_eq!(
        SpendRequest::<Mayo2, Direct>::from_bytes(&as_wire_v1(request_bytes.clone())).unwrap_err(),
        WireError::UnsupportedVersion
    );
    let pending = PendingSpend::<Mayo2, Direct>::from_bytes(&public, &pending_bytes).unwrap();
    let request = SpendRequest::<Mayo2, Direct>::from_bytes(&request_bytes).unwrap();
    let response = issuer.spend(&request, &mut rng).unwrap();
    let direct_response_bytes = response.to_bytes();
    assert_eq!(
        SpendResponse::<Mayo2, Direct>::from_bytes(&as_wire_v1(direct_response_bytes.clone()))
            .unwrap_err(),
        WireError::UnsupportedVersion
    );
    let response = SpendResponse::<Mayo2, Direct>::from_bytes(&direct_response_bytes).unwrap();
    let token = pending.finish(&public, &request, &response).unwrap();
    assert_eq!(token.balance(), 70);

    let record = issuer.store().get(&request.nullifier()).unwrap().unwrap();
    assert_eq!(
        RetryRecord::<Mayo2>::from_bytes(&as_wire_v1(record.to_bytes())).unwrap_err(),
        WireError::UnsupportedVersion
    );
    assert_eq!(
        RetryRecord::<Mayo2>::from_bytes(&record.to_bytes()).unwrap(),
        record
    );

    let (pending, deferred_request) = token
        .prepare_spend_with_deferred_return(&public, 30, &mut rng)
        .unwrap();
    let deferred_pending_bytes = pending.to_bytes();
    assert_eq!(
        PendingDeferredReturnSpend::<Mayo2, Direct>::from_bytes(
            &public,
            &as_wire_v1(deferred_pending_bytes.clone()),
        )
        .err(),
        Some(WireError::UnsupportedVersion)
    );
    let deferred_bytes = deferred_request.to_bytes();
    assert_eq!(
        DeferredReturnSpendRequest::<Mayo2, Direct>::from_bytes(&as_wire_v1(
            deferred_bytes.clone(),
        ))
        .unwrap_err(),
        WireError::UnsupportedVersion
    );
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
        DeferredReturnSpendResponse::<Mayo2, Direct>::from_bytes(&as_wire_v1(
            response_bytes.clone(),
        ))
        .unwrap_err(),
        WireError::UnsupportedVersion
    );
    assert_eq!(
        SpendResponse::<Mayo2, Direct>::from_bytes(&response_bytes).unwrap_err(),
        WireError::WrongArtifact
    );
    let response =
        DeferredReturnSpendResponse::<Mayo2, Direct>::from_bytes(&response_bytes).unwrap();
    let pending =
        PendingDeferredReturnSpend::<Mayo2, Direct>::from_bytes(&public, &deferred_pending_bytes)
            .unwrap();
    let deferred = pending
        .finish(&public, &deferred_request, &response)
        .unwrap();
    let deferred_bytes = deferred.to_bytes();
    assert_eq!(
        DeferredReturnToken::<Mayo2>::from_bytes(&public, &as_wire_v1(deferred_bytes.clone()),)
            .err(),
        Some(WireError::UnsupportedVersion)
    );
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

#[derive(Clone)]
struct RacingStore {
    records: Arc<Mutex<HashMap<[u8; 32], RetryRecord<Mayo2>>>>,
    simultaneous_gets: Arc<Barrier>,
}

impl NullifierStore<Mayo2> for RacingStore {
    fn get(&self, nullifier: &[u8; 32]) -> Result<Option<RetryRecord<Mayo2>>, Error> {
        let current = self.records.lock().unwrap().get(nullifier).cloned();
        self.simultaneous_gets.wait();
        Ok(current)
    }

    fn insert_if_absent(
        &mut self,
        nullifier: [u8; 32],
        candidate: RetryRecord<Mayo2>,
    ) -> Result<RetryRecord<Mayo2>, Error> {
        use std::collections::hash_map::Entry;
        Ok(match self.records.lock().unwrap().entry(nullifier) {
            Entry::Vacant(entry) => entry.insert(candidate).clone(),
            Entry::Occupied(entry) => entry.get().clone(),
        })
    }
}

fn racing_stores() -> (RacingStore, RacingStore) {
    let records = Arc::new(Mutex::new(HashMap::new()));
    let simultaneous_gets = Arc::new(Barrier::new(2));
    let first = RacingStore {
        records: records.clone(),
        simultaneous_gets: simultaneous_gets.clone(),
    };
    let second = RacingStore {
        records,
        simultaneous_gets,
    };
    (first, second)
}

#[test]
fn multi_replica_races_publish_exactly_one_durable_winner() {
    let mut setup_rng = StdRng::seed_from_u64(0x5A7E_5A7E);
    let issuer = Issuer::<Mayo2>::generate(b"race-semantics", &mut setup_rng);
    let public = issuer.public_key().clone();
    let key_bytes = issuer.key_bytes();

    // Identical direct requests both receive the same durable response.
    let token = issue_token(&issuer, &public, 80, &mut setup_rng);
    let (_pending, request) = token.prepare_spend(&public, 10, &mut setup_rng).unwrap();
    let (store_a, store_b) = racing_stores();
    let mut replica_a =
        Issuer::<Mayo2, RacingStore>::from_key_bytes_with_store(&key_bytes, store_a).unwrap();
    let mut replica_b =
        Issuer::<Mayo2, RacingStore>::from_key_bytes_with_store(&key_bytes, store_b).unwrap();
    let request_b = request.clone();
    let direct_a = thread::spawn(move || {
        let mut rng = StdRng::seed_from_u64(1);
        replica_a
            .spend(&request, &mut rng)
            .map(|value| value.to_bytes())
    });
    let direct_b = thread::spawn(move || {
        let mut rng = StdRng::seed_from_u64(2);
        replica_b
            .spend(&request_b, &mut rng)
            .map(|value| value.to_bytes())
    });
    assert_eq!(
        direct_a.join().unwrap().unwrap(),
        direct_b.join().unwrap().unwrap()
    );

    // Different requests consuming one nullifier produce one success and one
    // conflicting-spend error, regardless of which request wins.
    let token = issue_token(&issuer, &public, 80, &mut setup_rng);
    let (_pending, request_a) = token.prepare_spend(&public, 10, &mut setup_rng).unwrap();
    let (_pending, request_b) = token.prepare_spend(&public, 11, &mut setup_rng).unwrap();
    let (store_a, store_b) = racing_stores();
    let mut replica_a =
        Issuer::<Mayo2, RacingStore>::from_key_bytes_with_store(&key_bytes, store_a).unwrap();
    let mut replica_b =
        Issuer::<Mayo2, RacingStore>::from_key_bytes_with_store(&key_bytes, store_b).unwrap();
    let conflict_a = thread::spawn(move || {
        let mut rng = StdRng::seed_from_u64(3);
        replica_a.spend(&request_a, &mut rng)
    });
    let conflict_b = thread::spawn(move || {
        let mut rng = StdRng::seed_from_u64(4);
        replica_b.spend(&request_b, &mut rng)
    });
    let outcomes = [conflict_a.join().unwrap(), conflict_b.join().unwrap()];
    assert_eq!(outcomes.iter().filter(|outcome| outcome.is_ok()).count(), 1);
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, Err(Error::NullifierAlreadySpent)))
            .count(),
        1
    );

    // The first durable deferred-return candidate fixes both the return and
    // authenticator for every successful racing caller.
    let token = issue_token(&issuer, &public, 80, &mut setup_rng);
    let (_pending, request) = token
        .prepare_spend_with_deferred_return(&public, 20, &mut setup_rng)
        .unwrap();
    let (store_a, store_b) = racing_stores();
    let mut replica_a =
        Issuer::<Mayo2, RacingStore>::from_key_bytes_with_store(&key_bytes, store_a).unwrap();
    let mut replica_b =
        Issuer::<Mayo2, RacingStore>::from_key_bytes_with_store(&key_bytes, store_b).unwrap();
    let request_b = request.clone();
    let deferred_a = thread::spawn(move || {
        let mut rng = StdRng::seed_from_u64(5);
        replica_a
            .spend_with_deferred_return(&request, 0, &mut rng)
            .map(|value| value.to_bytes())
    });
    let deferred_b = thread::spawn(move || {
        let mut rng = StdRng::seed_from_u64(6);
        replica_b
            .spend_with_deferred_return(&request_b, 7, &mut rng)
            .map(|value| value.to_bytes())
    });
    assert_eq!(
        deferred_a.join().unwrap().unwrap(),
        deferred_b.join().unwrap().unwrap()
    );
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

    let (_pending, deferred_request) = token
        .prepare_spend_with_deferred_return(&public, 5, &mut rng)
        .unwrap();
    assert_eq!(
        issuer
            .spend_with_deferred_return(&deferred_request, 2, &mut rng)
            .unwrap_err(),
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
        let (expected_payload, expected_spend_request) = match profile {
            PerformanceProfile::Compact => (72_784, 73_086),
            PerformanceProfile::Balanced => (141_424, 141_918),
            PerformanceProfile::LowLatency => (278_704, 279_582),
        };
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
        let redeem_response = issuer.spend(&redeem_request, &mut rng).unwrap();
        let deferred_input_verify_sign = start.elapsed();

        assert_eq!(direct_request.proof.payload_len(), expected_payload);
        assert_eq!(defer_request.proof.payload_len(), expected_payload);
        assert_eq!(redeem_request.proof.payload_len(), expected_payload);
        assert_eq!(direct_request.to_bytes().len(), expected_spend_request);
        assert_eq!(defer_request.to_bytes().len(), expected_spend_request);
        assert_eq!(redeem_request.to_bytes().len(), expected_spend_request);
        assert_eq!(direct_token.to_bytes().len(), 315);
        assert_eq!(deferred_token.to_bytes().len(), 315);
        assert_eq!(issue_response.to_bytes().len(), 203);
        assert_eq!(direct_response.to_bytes().len(), 211);
        assert_eq!(defer_response.to_bytes().len(), 211);
        assert_eq!(redeem_response.to_bytes().len(), 211);

        eprintln!(
            "{profile:?}: issue prove={issue_prove:?}, verify+sign={issue_verify_sign:?}, payload={} bytes, request={} bytes, response={} bytes; direct-input spend prove={direct_prove:?}, verify+sign={direct_verify_sign:?}, payload={} bytes, request={} bytes, response={} bytes; deferred-input spend prove={deferred_input_prove:?}, verify+sign={deferred_input_verify_sign:?}, payload={} bytes, request={} bytes, response={} bytes; token={} bytes",
            issue_request.proof.payload_len(),
            issue_request.to_bytes().len(),
            issue_response.to_bytes().len(),
            direct_request.proof.payload_len(),
            direct_request.to_bytes().len(),
            direct_response.to_bytes().len(),
            redeem_request.proof.payload_len(),
            redeem_request.to_bytes().len(),
            redeem_response.to_bytes().len(),
            direct_token.to_bytes().len(),
        );
    }
}
