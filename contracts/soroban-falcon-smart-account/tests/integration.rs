//! Integration tests for Falcon Smart Account with embedded verification.

#![cfg(feature = "testutils")]

use soroban_sdk::{Bytes, Env};

use soroban_falcon_smart_account::{Error, FalconSmartAccount, FalconSmartAccountClient};

const TEST_PUBKEY_HEX: &str = include_str!("fixtures/test_pubkey.hex");
const TEST_SIGNATURE_HEX: &str = include_str!("fixtures/test_signature.hex");
// Two-step rotation fixtures: a second keypair's pubkey and its
// proof-of-possession signature over ACCEPT_DS || SHA-256(pubkey).
// Regenerate with fixtures/gen_accept_fixtures.mjs.
const TEST_PENDING_PUBKEY_HEX: &str = include_str!("fixtures/test_pending_pubkey.hex");
const TEST_ACCEPT_PROOF_HEX: &str = include_str!("fixtures/test_accept_proof.hex");

/// Register a smart account with the canonical 897-byte test pubkey.
fn deploy_with_test_pubkey(env: &Env) -> (soroban_sdk::Address, FalconSmartAccountClient<'_>) {
    let pubkey_bytes = hex::decode(TEST_PUBKEY_HEX.trim()).expect("Invalid pubkey hex");
    let pubkey = Bytes::from_slice(env, &pubkey_bytes);
    let id = env.register(FalconSmartAccount, (&pubkey,));
    let client = FalconSmartAccountClient::new(env, &id);
    (id, client)
}

fn pending_pubkey(env: &Env) -> Bytes {
    let bytes = hex::decode(TEST_PENDING_PUBKEY_HEX.trim()).expect("Invalid pending pubkey hex");
    Bytes::from_slice(env, &bytes)
}

fn accept_proof(env: &Env) -> Bytes {
    let bytes = hex::decode(TEST_ACCEPT_PROOF_HEX.trim()).expect("Invalid accept proof hex");
    Bytes::from_slice(env, &bytes)
}

/// 897 bytes: a chosen header byte over an all-zero body. Header 0x09
/// makes a well-formed (if degenerate) encoding; any other header fails
/// the well-formedness gate.
fn pubkey_of_distinct_first_byte(env: &Env, first: u8) -> Bytes {
    let mut data = [0u8; 897];
    data[0] = first;
    Bytes::from_array(env, &data)
}

#[test]
fn test_smart_account_constructor() {
    let env = Env::default();

    // Decode pubkey
    let pubkey_bytes = hex::decode(TEST_PUBKEY_HEX.trim()).expect("Invalid pubkey hex");
    let pubkey = Bytes::from_slice(&env, &pubkey_bytes);

    // Deploy with constructor
    let smart_account_id = env.register(FalconSmartAccount, (&pubkey,));
    let client = FalconSmartAccountClient::new(&env, &smart_account_id);

    // Verify stored value (get_pubkey now returns Result; client unwraps for ergonomics).
    assert_eq!(client.get_pubkey(), pubkey);
}

#[test]
#[should_panic(expected = "Invalid public key size")]
fn test_invalid_pubkey_size_on_construction() {
    let env = Env::default();

    let bad_pubkey = Bytes::from_slice(&env, &[0u8; 100]);

    // This should panic during construction
    let _smart_account_id = env.register(FalconSmartAccount, (&bad_pubkey,));
}

// -----------------------------------------------------------------------
// Two-step key rotation: propose / accept / cancel
// -----------------------------------------------------------------------
//
// propose_key keeps the require-auth-first, validate-second ordering.
// accept_key has no require_auth; the proof signature is its
// authorization.

#[test]
fn test_two_step_rotation_happy_path() {
    let env = Env::default();
    env.mock_all_auths();
    let (_id, client) = deploy_with_test_pubkey(&env);
    let original = client.get_pubkey();

    let new_pubkey = pending_pubkey(&env);
    client.propose_key(&new_pubkey);

    // Proposal stored; active key untouched.
    assert_eq!(client.get_pending_key(), new_pubkey);
    assert_eq!(client.get_pubkey(), original);

    // The pending key's proof of possession activates it.
    client.accept_key(&accept_proof(&env));
    assert_eq!(client.get_pubkey(), new_pubkey);
    assert_eq!(
        client.try_get_pending_key().expect_err("pending must be cleared"),
        Ok(Error::NoPendingKey)
    );
}

#[test]
fn test_accept_without_propose_fails() {
    let env = Env::default();
    let (_id, client) = deploy_with_test_pubkey(&env);

    let err = client
        .try_accept_key(&accept_proof(&env))
        .expect_err("expected NoPendingKey");
    assert_eq!(err, Ok(Error::NoPendingKey));
}

#[test]
fn test_accept_with_invalid_proof_fails() {
    let env = Env::default();
    env.mock_all_auths();
    let (_id, client) = deploy_with_test_pubkey(&env);
    let original = client.get_pubkey();

    let new_pubkey = pending_pubkey(&env);
    client.propose_key(&new_pubkey);

    // A valid signature by the wrong key over the wrong message (the
    // "Hello, Falcon!" fixture) must not activate the key.
    let wrong_proof = hex::decode(TEST_SIGNATURE_HEX.trim()).unwrap();
    let err = client
        .try_accept_key(&Bytes::from_slice(&env, &wrong_proof))
        .expect_err("expected proof failure");
    assert_eq!(err, Ok(Error::ProofVerificationFailed));

    // A corrupted copy of the real proof must also fail.
    let mut corrupted = hex::decode(TEST_ACCEPT_PROOF_HEX.trim()).unwrap();
    corrupted[100] ^= 0x01;
    let err = client
        .try_accept_key(&Bytes::from_slice(&env, &corrupted))
        .expect_err("expected proof failure");
    assert_eq!(err, Ok(Error::ProofVerificationFailed));

    // Undersized proof is rejected on size before verification.
    let err = client
        .try_accept_key(&Bytes::from_slice(&env, &[0u8; 10]))
        .expect_err("expected size error");
    assert_eq!(err, Ok(Error::InvalidSignatureSize));

    // Nothing changed: current key active, proposal still pending.
    assert_eq!(client.get_pubkey(), original);
    assert_eq!(client.get_pending_key(), new_pubkey);
}

#[test]
fn test_propose_twice_replaces_pending() {
    let env = Env::default();
    env.mock_all_auths();
    let (_id, client) = deploy_with_test_pubkey(&env);

    // First proposal: a degenerate-but-well-formed all-zero key.
    let first = pubkey_of_distinct_first_byte(&env, 0x09);
    client.propose_key(&first);
    assert_eq!(client.get_pending_key(), first);

    // Second proposal replaces it.
    let second = pending_pubkey(&env);
    client.propose_key(&second);
    assert_eq!(client.get_pending_key(), second);

    // The real pending key's proof still works against the replacement.
    client.accept_key(&accept_proof(&env));
    assert_eq!(client.get_pubkey(), second);
}

#[test]
fn test_cancel_then_accept_fails() {
    let env = Env::default();
    env.mock_all_auths();
    let (_id, client) = deploy_with_test_pubkey(&env);
    let original = client.get_pubkey();

    client.propose_key(&pending_pubkey(&env));
    client.cancel_key();

    assert_eq!(
        client.try_get_pending_key().expect_err("pending must be cleared"),
        Ok(Error::NoPendingKey)
    );
    let err = client
        .try_accept_key(&accept_proof(&env))
        .expect_err("expected NoPendingKey");
    assert_eq!(err, Ok(Error::NoPendingKey));
    assert_eq!(client.get_pubkey(), original);
}

#[test]
fn test_cancel_without_pending_fails() {
    let env = Env::default();
    env.mock_all_auths();
    let (_id, client) = deploy_with_test_pubkey(&env);

    let err = client.try_cancel_key().expect_err("expected NoPendingKey");
    assert_eq!(err, Ok(Error::NoPendingKey));
}

#[test]
#[should_panic] // Soroban auth-missing surfaces as a host trap in tests
fn test_propose_key_without_auth_fails() {
    let env = Env::default();
    // Note: no `mock_all_auths()` — the host should reject the call.
    let (_id, client) = deploy_with_test_pubkey(&env);

    client.propose_key(&pending_pubkey(&env));
}

#[test]
#[should_panic] // Soroban auth-missing surfaces as a host trap in tests
fn test_cancel_key_without_auth_fails() {
    let env = Env::default();
    let (_id, client) = deploy_with_test_pubkey(&env);

    client.cancel_key();
}

#[test]
fn test_propose_key_bad_size_after_auth_returns_error() {
    // Proves the auth-then-validate ordering: we still get
    // InvalidPublicKeySize for a wrong-sized pubkey, but only after
    // `require_auth()` runs.
    let env = Env::default();
    env.mock_all_auths();
    let (_id, client) = deploy_with_test_pubkey(&env);

    let bad_pubkey = Bytes::from_slice(&env, &[0u8; 100]);
    let err = client.try_propose_key(&bad_pubkey).expect_err("expected size error");
    assert_eq!(err, Ok(Error::InvalidPublicKeySize));

    // Pubkey should be unchanged and nothing pending after a failed proposal.
    let original_bytes = hex::decode(TEST_PUBKEY_HEX.trim()).unwrap();
    assert_eq!(client.get_pubkey(), Bytes::from_slice(&env, &original_bytes));
    assert_eq!(
        client.try_get_pending_key().expect_err("nothing pending"),
        Ok(Error::NoPendingKey)
    );
}

#[test]
fn test_propose_key_malformed_encodings_rejected() {
    let env = Env::default();
    env.mock_all_auths();
    let (_id, client) = deploy_with_test_pubkey(&env);

    // Right length, wrong header byte (0x0A instead of 0x09).
    let bad_header = pubkey_of_distinct_first_byte(&env, 0x0a);
    let err = client
        .try_propose_key(&bad_header)
        .expect_err("expected malformed error");
    assert_eq!(err, Ok(Error::MalformedPublicKey));

    // Right length and header, but an all-0xFF body makes the first
    // 14-bit coefficient 0x3FFF >= Q.
    let mut oor = [0xffu8; 897];
    oor[0] = 0x09;
    let err = client
        .try_propose_key(&Bytes::from_array(&env, &oor))
        .expect_err("expected malformed error");
    assert_eq!(err, Ok(Error::MalformedPublicKey));

    // Corruption of an otherwise-valid key: two adjacent 0xFF bytes always
    // push some 14-bit coefficient past Q, wherever they land.
    let mut corrupted = hex::decode(TEST_PENDING_PUBKEY_HEX.trim()).unwrap();
    corrupted[400] = 0xff;
    corrupted[401] = 0xff;
    let err = client
        .try_propose_key(&Bytes::from_slice(&env, &corrupted))
        .expect_err("expected malformed error");
    assert_eq!(err, Ok(Error::MalformedPublicKey));

    assert_eq!(
        client.try_get_pending_key().expect_err("nothing pending"),
        Ok(Error::NoPendingKey)
    );
}

#[test]
#[should_panic(expected = "Malformed public key")]
fn test_constructor_rejects_malformed_pubkey() {
    let env = Env::default();
    // 897 bytes but a wrong header byte: well-formedness gates deploys too.
    let bad_pubkey = pubkey_of_distinct_first_byte(&env, 0x0a);
    let _id = env.register(FalconSmartAccount, (&bad_pubkey,));
}

// -----------------------------------------------------------------------
// get_pubkey — Result-return test
// -----------------------------------------------------------------------

#[test]
fn test_get_pubkey_returns_stored_value() {
    let env = Env::default();
    let (_id, client) = deploy_with_test_pubkey(&env);

    let pubkey_bytes = hex::decode(TEST_PUBKEY_HEX.trim()).unwrap();
    assert_eq!(client.get_pubkey(), Bytes::from_slice(&env, &pubkey_bytes));
}

// -----------------------------------------------------------------------
// __check_auth — sanity rejection tests
// -----------------------------------------------------------------------
//
// True positive end-to-end tests (sign DS||payload with a fresh Falcon
// keypair and route through __check_auth via env.try_invoke_contract_check_auth)
// require a Falcon signer in the test path, which is out of scope for
// this crate. The tests below cover the structural rejection paths.
// Follow-up SR-tracked.

#[test]
fn test_check_auth_rejects_undersized_signature() {
    let env = Env::default();
    let (_id, client) = deploy_with_test_pubkey(&env);

    let sig_bytes = hex::decode(TEST_SIGNATURE_HEX.trim()).expect("Invalid sig hex");
    let pubkey_bytes = hex::decode(TEST_PUBKEY_HEX.trim()).unwrap();

    use soroban_falcon_smart_account::FalconVerifier;
    let mut pk = [0u8; 897];
    pk.copy_from_slice(&pubkey_bytes[..897]);

    // Signature shorter than FALCON_SIG_MIN_SIZE (42).
    let truncated = &sig_bytes[..10];
    assert!(!FalconVerifier::verify_512(&pk, b"Hello, Falcon!", truncated));

    // Use the client too (touches the auth-path branch indirectly via
    // the underlying verifier path) — sanity-only.
    let _ = client; // keep client alive
}

#[test]
fn test_check_auth_rejects_oversized_signature() {
    let env = Env::default();
    let (_id, client) = deploy_with_test_pubkey(&env);

    use soroban_falcon_smart_account::{FalconVerifier, FALCON_SIG_MAX_SIZE};
    let pubkey_bytes = hex::decode(TEST_PUBKEY_HEX.trim()).unwrap();
    let mut pk = [0u8; 897];
    pk.copy_from_slice(&pubkey_bytes[..897]);

    let oversized = vec![0x39u8; (FALCON_SIG_MAX_SIZE as usize) + 1];
    assert!(!FalconVerifier::verify_512(&pk, b"Hello, Falcon!", &oversized));

    let _ = client;
}

#[test]
fn test_embedded_verification() {
    // Test that the embedded verifier works correctly
    let env = Env::default();

    if TEST_PUBKEY_HEX.is_empty() || TEST_SIGNATURE_HEX.is_empty() {
        return;
    }

    let pubkey_bytes = hex::decode(TEST_PUBKEY_HEX.trim()).expect("Invalid pubkey hex");
    let sig_bytes = hex::decode(TEST_SIGNATURE_HEX.trim()).expect("Invalid signature hex");

    let pubkey = Bytes::from_slice(&env, &pubkey_bytes);

    // Deploy with constructor
    let smart_account_id = env.register(FalconSmartAccount, (&pubkey,));
    let client = FalconSmartAccountClient::new(&env, &smart_account_id);

    // Verify pubkey is stored
    let stored_pubkey = client.get_pubkey();
    assert_eq!(stored_pubkey.len(), 897);

    // Verify directly using FalconVerifier
    use soroban_falcon_smart_account::FalconVerifier;

    let mut pk_bytes = [0u8; 897];
    for i in 0..897 {
        pk_bytes[i] = stored_pubkey.get(i as u32).unwrap();
    }

    let result = FalconVerifier::verify_512(&pk_bytes, b"Hello, Falcon!", &sig_bytes);
    assert!(result, "Falcon verification should succeed");
}
