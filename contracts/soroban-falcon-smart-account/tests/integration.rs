//! Integration tests for Falcon Smart Account with embedded verification.

#![cfg(feature = "testutils")]

use soroban_sdk::{Bytes, Env};

use soroban_falcon_smart_account::{FalconSmartAccount, FalconSmartAccountClient};

const TEST_PUBKEY_HEX: &str = include_str!("fixtures/test_pubkey.hex");
const TEST_SIGNATURE_HEX: &str = include_str!("fixtures/test_signature.hex");

#[test]
fn test_smart_account_constructor() {
    let env = Env::default();

    // Decode pubkey
    let pubkey_bytes = hex::decode(TEST_PUBKEY_HEX.trim()).expect("Invalid pubkey hex");
    let pubkey = Bytes::from_slice(&env, &pubkey_bytes);

    // Deploy with constructor
    let smart_account_id = env.register(FalconSmartAccount, (&pubkey,));
    let client = FalconSmartAccountClient::new(&env, &smart_account_id);

    // Verify stored value
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
