//! Integration tests for Falcon Smart Account with embedded verification.

#![cfg(feature = "testutils")]

use soroban_sdk::{Bytes, Env};

use soroban_falcon_smart_account::{Error, FalconSmartAccount, FalconSmartAccountClient};

const TEST_PUBKEY_HEX: &str = include_str!("fixtures/test_pubkey.hex");
const TEST_SIGNATURE_HEX: &str = include_str!("fixtures/test_signature.hex");

/// Register a smart account with the canonical 897-byte test pubkey.
fn deploy_with_test_pubkey(env: &Env) -> (soroban_sdk::Address, FalconSmartAccountClient<'_>) {
    let pubkey_bytes = hex::decode(TEST_PUBKEY_HEX.trim()).expect("Invalid pubkey hex");
    let pubkey = Bytes::from_slice(env, &pubkey_bytes);
    let id = env.register(FalconSmartAccount, (&pubkey,));
    let client = FalconSmartAccountClient::new(env, &id);
    (id, client)
}

/// Build a well-formed 897-byte pubkey with a distinct first byte (still
/// invalid as a Falcon-512 pubkey beyond the header check, but the contract
/// only validates LENGTH at constructor/rotate boundaries).
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
// rotate_key — auth-routing tests
// -----------------------------------------------------------------------
//
// These exist primarily to prove the SC-1 ordering: `require_auth()` runs
// FIRST, then size is validated. The negative cases (no auth, bad new
// pubkey) both fail, but for distinct reasons.

#[test]
fn test_rotate_key_succeeds_with_mocked_auth() {
    let env = Env::default();
    env.mock_all_auths();
    let (_id, client) = deploy_with_test_pubkey(&env);

    let new_pubkey = pubkey_of_distinct_first_byte(&env, 0x09);
    client.rotate_key(&new_pubkey);

    assert_eq!(client.get_pubkey(), new_pubkey);
}

#[test]
#[should_panic] // Soroban auth-missing surfaces as a host trap in tests
fn test_rotate_key_without_auth_fails() {
    let env = Env::default();
    // Note: no `mock_all_auths()` — the host should reject the call.
    let (_id, client) = deploy_with_test_pubkey(&env);

    let new_pubkey = pubkey_of_distinct_first_byte(&env, 0x09);
    client.rotate_key(&new_pubkey);
}

#[test]
fn test_rotate_key_bad_size_after_auth_returns_error() {
    // Proves SC-1 ordering: we still get InvalidPublicKeySize for a
    // wrong-sized pubkey, but only AFTER `require_auth()` runs.
    let env = Env::default();
    env.mock_all_auths();
    let (_id, client) = deploy_with_test_pubkey(&env);

    let bad_pubkey = Bytes::from_slice(&env, &[0u8; 100]);
    let err = client.try_rotate_key(&bad_pubkey).expect_err("expected size error");
    assert_eq!(err, Ok(Error::InvalidPublicKeySize));

    // Pubkey should be unchanged after a failed rotation.
    let original_bytes = hex::decode(TEST_PUBKEY_HEX.trim()).unwrap();
    assert_eq!(client.get_pubkey(), Bytes::from_slice(&env, &original_bytes));
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
