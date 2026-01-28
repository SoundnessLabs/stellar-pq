//! Integration tests with signature verification.

#![cfg(feature = "testutils")]

use soroban_falcon_verifier::{FalconVerifierContract, FalconVerifierContractClient};
use soroban_sdk::{Bytes, Env};

// Test vector generated using the falcon crate with generate_vectors binary
// Seed: 2a31383f464d545b626970777e858c939aa1a8afb6bdc4cbd2d9e0e7eef5fc030a11181f262d343b424950575e656c73
// Message: "Hello, Falcon!"
// Format: Padded (fixed 666 bytes for Falcon-512)

// Public key (897 bytes) - hex encoded
const TEST_PUBKEY_HEX: &str = include_str!("fixtures/test_pubkey.hex");
const TEST_SIGNATURE_HEX: &str = include_str!("fixtures/test_signature.hex");
const TEST_MESSAGE: &[u8] = b"Hello, Falcon!";

#[test]
fn test_verify_with_generated_signature() {
    // Skip if fixtures don't exist yet
    if TEST_PUBKEY_HEX.is_empty() {
        println!("Skipping test - fixtures not generated yet");
        return;
    }

    let env = Env::default();
    let contract_id = env.register(FalconVerifierContract, ());
    let client = FalconVerifierContractClient::new(&env, &contract_id);

    // Decode hex fixtures
    let pubkey_bytes = hex::decode(TEST_PUBKEY_HEX.trim()).expect("Invalid pubkey hex");
    let sig_bytes = hex::decode(TEST_SIGNATURE_HEX.trim()).expect("Invalid signature hex");

    // Convert to Soroban Bytes
    let pubkey = Bytes::from_slice(&env, &pubkey_bytes);
    let message = Bytes::from_slice(&env, TEST_MESSAGE);
    let signature = Bytes::from_slice(&env, &sig_bytes);

    // Verify
    let result = client.verify(&pubkey, &message, &signature);
    assert!(result, "Signature verification should succeed");

    // Try with wrong message - should fail
    let wrong_message = Bytes::from_slice(&env, b"Wrong message");
    let result = client.verify(&pubkey, &wrong_message, &signature);
    assert!(!result, "Verification with wrong message should fail");
}

#[test]
fn test_verify_invalid_pubkey_size() {
    let env = Env::default();
    let contract_id = env.register(FalconVerifierContract, ());
    let client = FalconVerifierContractClient::new(&env, &contract_id);

    // Wrong size public key
    let pubkey = Bytes::from_slice(&env, &[0u8; 100]);
    let message = Bytes::from_slice(&env, b"test");
    let signature = Bytes::from_slice(&env, &[0u8; 650]);

    let result = client.verify(&pubkey, &message, &signature);
    assert!(!result, "Invalid pubkey size should fail");
}

#[test]
fn test_verify_invalid_signature_size() {
    let env = Env::default();
    let contract_id = env.register(FalconVerifierContract, ());
    let client = FalconVerifierContractClient::new(&env, &contract_id);

    // Valid size public key but too short signature
    let pubkey = Bytes::from_slice(&env, &[9u8; 897]);
    let message = Bytes::from_slice(&env, b"test");
    let signature = Bytes::from_slice(&env, &[0u8; 10]);

    let result = client.verify(&pubkey, &message, &signature);
    assert!(!result, "Too short signature should fail");
}
