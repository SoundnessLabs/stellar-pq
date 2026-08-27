//! NIST Known Answer Tests (KAT) for Falcon-512 verification.
//!
//! This test suite verifies our implementation against the official NIST KAT vectors
//! from the Falcon submission (falcon512-KAT.rsp).
//!
//! # KAT Format
//!
//! The NIST KAT file contains test vectors with:
//! - `pk`: Public key (897 bytes for Falcon-512)
//! - `msg`: Original message
//! - `sm`: Signed message in NIST format
//!
//! ## NIST `sm` Format
//!
//! The signed message `sm` has the following structure:
//! ```text
//! sm = sig_len (2 bytes, big-endian) || nonce (40 bytes) || message || sig_data
//! ```
//!
//! To verify with our implementation, we reconstruct the standard Falcon
//! signature, preserving the original header byte from the KAT:
//! ```text
//! signature = header (0x29 in these NIST vectors) || nonce (40 bytes) || sig_body
//! ```
//!
//! The header low nibble is 9 (logn for Falcon-512). The NIST Round-3 KAT
//! vectors use high nibble 0x2X with a *variable-length* compressed body; the
//! verifier also accepts 0x3X (PQClean / falcon-wasm). See the verifier's
//! module docs for the full format policy.

use soroban_falcon_verifier::FalconVerifier;

/// Parse a NIST KAT response file and extract test vectors.
fn parse_kat_file(content: &str) -> Vec<KatVector> {
    let mut vectors = Vec::new();
    let mut current = KatVector::default();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        if let Some((key, value)) = line.split_once(" = ") {
            match key {
                "count" => {
                    if current.count.is_some() {
                        vectors.push(current);
                        current = KatVector::default();
                    }
                    current.count = Some(value.parse().unwrap());
                }
                "mlen" => current.mlen = Some(value.parse().unwrap()),
                "msg" => current.msg = Some(value.to_string()),
                "pk" => current.pk = Some(value.to_string()),
                "smlen" => current.smlen = Some(value.parse().unwrap()),
                "sm" => current.sm = Some(value.to_string()),
                _ => {}
            }
        }
    }

    // Don't forget the last vector
    if current.count.is_some() {
        vectors.push(current);
    }

    vectors
}

#[derive(Default, Debug)]
struct KatVector {
    count: Option<u32>,
    mlen: Option<usize>,
    msg: Option<String>,
    pk: Option<String>,
    smlen: Option<usize>,
    sm: Option<String>,
}

impl KatVector {
    /// Extract the standard Falcon signature from NIST `sm` format.
    ///
    /// NIST format: sig_len(2) || nonce(40) || message(mlen) || sig_data(sig_len)
    /// where sig_data = header(1) || compressed_body
    ///
    /// Standard Falcon format: header(1) || nonce(40) || compressed_body
    fn extract_falcon_signature(&self) -> Vec<u8> {
        let sm = hex::decode(self.sm.as_ref().unwrap()).unwrap();
        let mlen = self.mlen.unwrap();

        // Parse NIST format
        let sig_len = ((sm[0] as usize) << 8) | (sm[1] as usize);
        let nonce = &sm[2..42];
        let sig_data = &sm[42 + mlen..];

        assert_eq!(sig_data.len(), sig_len, "Signature data length mismatch");

        // sig_data starts with the header byte, followed by the compressed body
        let header = sig_data[0];
        let sig_body = &sig_data[1..];

        // Reconstruct standard Falcon signature:
        // header(1) || nonce(40) || compressed_body
        let mut signature = Vec::with_capacity(1 + 40 + sig_body.len());
        signature.push(header);
        signature.extend_from_slice(nonce);
        signature.extend_from_slice(sig_body);

        signature
    }

    /// Get the public key bytes.
    fn public_key(&self) -> Vec<u8> {
        hex::decode(self.pk.as_ref().unwrap()).unwrap()
    }

    /// Get the message bytes.
    fn message(&self) -> Vec<u8> {
        hex::decode(self.msg.as_ref().unwrap()).unwrap()
    }
}

#[test]
fn test_kat_vectors() {
    // Read KAT file
    let kat_content = include_str!("falcon512-KAT.rsp");
    let vectors = parse_kat_file(kat_content);

    assert_eq!(vectors.len(), 100, "Expected 100 KAT vectors");

    let mut passed = 0;
    let mut failed = 0;

    for vector in &vectors {
        let count = vector.count.unwrap();

        // Skip vectors with missing data
        if vector.pk.is_none() || vector.sm.is_none() || vector.msg.is_none() {
            continue;
        }

        let pk = vector.public_key();
        let msg = vector.message();
        let sig = vector.extract_falcon_signature();


        let result = FalconVerifier::verify_512(&pk, &msg, &sig);

        if result {
            passed += 1;
        } else {
            failed += 1;
            eprintln!("FAILED: KAT vector {}", count);
        }
    }

    println!("KAT Results: {}/{} passed", passed, passed + failed);
    assert_eq!(failed, 0, "Some KAT vectors failed verification");
    assert!(passed > 0, "No KAT vectors were tested");
}

/// Test a single KAT vector in detail for debugging.
#[test]
fn test_kat_vector_0() {
    let kat_content = include_str!("falcon512-KAT.rsp");
    let vectors = parse_kat_file(kat_content);

    let vector = &vectors[0];
    assert_eq!(vector.count, Some(0));

    let pk = vector.public_key();
    let msg = vector.message();
    let sig = vector.extract_falcon_signature();

    // Verify sizes
    assert_eq!(pk.len(), 897, "Public key should be 897 bytes");
    assert_eq!(msg.len(), vector.mlen.unwrap(), "Message length mismatch");

    // Verify signature structure: low nibble = logn = 9; high nibble selects
    // the encoding family. The NIST KAT vectors use 0x2X (variable-length
    // compressed); the verifier also accepts 0x3X. (0x5X CT is out of scope.)
    assert_eq!(
        sig[0] & 0x0F,
        9,
        "Signature header low nibble should be 9 (logn for Falcon-512)"
    );
    let format = sig[0] & 0xF0;
    assert!(
        format == 0x20 || format == 0x30 || format == 0x50,
        "Signature header high nibble should be 0x2X/0x3X (or 0x5X CT)"
    );

    println!("Vector 0:");
    println!("  Public key: {} bytes", pk.len());
    println!("  Message: {} bytes", msg.len());
    println!("  Signature: {} bytes", sig.len());
    println!("  Signature header: 0x{:02x}", sig[0]);
    println!("  Nonce: {}...", hex::encode(&sig[1..11]));

    let result = FalconVerifier::verify_512(&pk, &msg, &sig);
    assert!(result, "KAT vector 0 should verify successfully");
}

/// Test that verification fails with wrong message.
#[test]
fn test_kat_wrong_message() {
    let kat_content = include_str!("falcon512-KAT.rsp");
    let vectors = parse_kat_file(kat_content);

    let vector = &vectors[0];
    let pk = vector.public_key();
    let sig = vector.extract_falcon_signature();

    // Use wrong message
    let wrong_msg = b"This is not the original message";

    let result = FalconVerifier::verify_512(&pk, wrong_msg, &sig);
    assert!(!result, "Verification should fail with wrong message");
}

/// DEC-002 regression: a natural-length signature inflated with arbitrary
/// (non-666) zero padding must be REJECTED, while padding to exactly the
/// 666-byte padded size with a zero tail is ACCEPTED. This closes the
/// unbounded-length malleability the audit flagged (DEC-002).
#[test]
fn test_dec002_arbitrary_padding_rejected() {
    let kat_content = include_str!("falcon512-KAT.rsp");
    let vectors = parse_kat_file(kat_content);
    let vector = &vectors[0];
    let pk = vector.public_key();
    let msg = vector.message();
    let sig = vector.extract_falcon_signature();

    // Sanity: the natural-length signature verifies, and is shorter than the
    // 666-byte padded size (so we have room to test both directions).
    assert!(
        FalconVerifier::verify_512(&pk, &msg, &sig),
        "natural KAT signature should verify"
    );
    assert!(
        sig.len() < 666,
        "KAT vector 0 is expected to be shorter than the padded size"
    );

    // (1) Arbitrary zero padding to a non-666 length must be rejected.
    let mut inflated = sig.clone();
    inflated.extend_from_slice(&[0u8; 4]);
    assert_ne!(inflated.len(), 666);
    assert!(
        !FalconVerifier::verify_512(&pk, &msg, &inflated),
        "DEC-002: arbitrarily zero-padded signature must be rejected"
    );

    // (2) Padding to exactly the 666-byte padded size (zero tail) is allowed.
    let mut padded = sig.clone();
    padded.resize(666, 0u8);
    assert_eq!(padded.len(), 666);
    assert!(
        FalconVerifier::verify_512(&pk, &msg, &padded),
        "exactly-666 zero-padded signature should still verify"
    );

    // (3) A non-zero byte anywhere in the padded tail must be rejected.
    let mut tampered = sig.clone();
    tampered.resize(666, 0u8);
    *tampered.last_mut().unwrap() = 1;
    assert!(
        !FalconVerifier::verify_512(&pk, &msg, &tampered),
        "non-zero padding tail must be rejected"
    );
}

/// Test that verification fails with wrong public key.
#[test]
fn test_kat_wrong_public_key() {
    let kat_content = include_str!("falcon512-KAT.rsp");
    let vectors = parse_kat_file(kat_content);

    // Use signature from vector 0 but public key from vector 1
    let vector0 = &vectors[0];
    let vector1 = &vectors[1];

    let pk = vector1.public_key(); // Wrong public key
    let msg = vector0.message();
    let sig = vector0.extract_falcon_signature();

    let result = FalconVerifier::verify_512(&pk, &msg, &sig);
    assert!(!result, "Verification should fail with wrong public key");
}

/// The contract hashes the message through a fixed-size chunk buffer.
/// Verify KAT vectors whose message lengths land just under, just past,
/// and at several multiples of the chunk size, so the chunked absorption
/// is exercised at its boundaries.
#[cfg(feature = "testutils")]
#[test]
fn test_contract_chunked_message_boundaries() {
    use soroban_falcon_verifier::{FalconVerifierContract, FalconVerifierContractClient};
    use soroban_sdk::{Bytes, Env};

    let kat_content = include_str!("falcon512-KAT.rsp");
    let vectors = parse_kat_file(kat_content);

    let env = Env::default();
    let contract_id = env.register(FalconVerifierContract, ());
    let client = FalconVerifierContractClient::new(&env, &contract_id);

    // mlen = 33·(index+1): 1023 and 1056 straddle the 1024-byte chunk,
    // 3300 spans four chunks.
    for (index, expected_mlen) in [(30usize, 1023usize), (31, 1056), (99, 3300)] {
        let vector = &vectors[index];
        assert_eq!(vector.mlen.unwrap(), expected_mlen, "vector {index}");

        let pk = Bytes::from_slice(&env, &vector.public_key());
        let msg_bytes = vector.message();
        let msg = Bytes::from_slice(&env, &msg_bytes);
        let sig = Bytes::from_slice(&env, &vector.extract_falcon_signature());

        assert!(client.verify(&pk, &msg, &sig), "vector {index} should verify");

        // The same message with its last byte flipped must fail.
        let mut wrong = msg_bytes.clone();
        *wrong.last_mut().unwrap() ^= 1;
        assert!(
            !client.verify(&pk, &Bytes::from_slice(&env, &wrong), &sig),
            "tampered message for vector {index} must fail"
        );
    }
}
