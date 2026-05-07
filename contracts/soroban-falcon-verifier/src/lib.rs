#![no_std]

//! # Falcon-512 Signature Verifier for Soroban
//!
//! Thin Soroban wrapper around `falcon-512-core`. All cryptographic logic
//! lives in the core crate; this file only handles `soroban-sdk` type marshalling.

use soroban_sdk::{contract, contractimpl, Bytes, Env};

pub use falcon_512_core::verify;
pub use falcon_512_core::FalconVerifier;
pub use falcon_512_core::{
    FALCON_512_LOGN, FALCON_512_N, FALCON_512_PUBKEY_SIZE, FALCON_MAX_MESSAGE_SIZE,
    FALCON_SIG_MAX_SIZE, FALCON_SIG_MIN_SIZE, L2_BOUND_512, Q,
};

#[contract]
pub struct FalconVerifierContract;

#[contractimpl]
impl FalconVerifierContract {
    /// Verify a Falcon-512 signature.
    ///
    /// # Arguments
    /// * `public_key` - 897-byte Falcon-512 public key
    /// * `message` - Message that was signed, up to `FALCON_MAX_MESSAGE_SIZE` bytes
    /// * `signature` - Falcon signature (compressed or padded format)
    ///
    /// # Returns
    /// * `true` if the signature is valid, `false` otherwise.
    ///
    /// Returns `false` for any oversized input rather than silently truncating.
    pub fn verify(_env: Env, public_key: Bytes, message: Bytes, signature: Bytes) -> bool {
        if public_key.len() != FALCON_512_PUBKEY_SIZE as u32 {
            return false;
        }
        let sig_len = signature.len();
        if sig_len < FALCON_SIG_MIN_SIZE || sig_len > FALCON_SIG_MAX_SIZE {
            return false;
        }
        let msg_len = message.len();
        if msg_len > FALCON_MAX_MESSAGE_SIZE as u32 {
            return false;
        }

        // Per-byte copies use `let Some(b) = ... else { return false; }`
        // rather than `unwrap()`. Bounds were enforced by the size checks
        // above, so `get()` should always be `Some` here -- but a verify()
        // that returns `false` on malformed input is a strictly safer
        // failure mode than a host trap, and matches the smart-account's
        // panic-free __check_auth pattern.
        let mut pk_bytes = [0u8; FALCON_512_PUBKEY_SIZE];
        for i in 0..FALCON_512_PUBKEY_SIZE {
            let Some(b) = public_key.get(i as u32) else {
                return false;
            };
            pk_bytes[i] = b;
        }

        let sig_len_usize = sig_len as usize;
        let mut sig_bytes = [0u8; FALCON_SIG_MAX_SIZE as usize];
        for i in 0..sig_len_usize {
            let Some(b) = signature.get(i as u32) else {
                return false;
            };
            sig_bytes[i] = b;
        }

        let msg_len_usize = msg_len as usize;
        let mut msg_bytes = [0u8; FALCON_MAX_MESSAGE_SIZE];
        for i in 0..msg_len_usize {
            let Some(b) = message.get(i as u32) else {
                return false;
            };
            msg_bytes[i] = b;
        }

        FalconVerifier::verify_512(
            &pk_bytes,
            &msg_bytes[..msg_len_usize],
            &sig_bytes[..sig_len_usize],
        )
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use soroban_sdk::Env;

    #[test]
    fn test_contract_compiles() {
        let env = Env::default();
        let contract_id = env.register(FalconVerifierContract, ());
        let _client = FalconVerifierContractClient::new(&env, &contract_id);
    }

    #[test]
    fn test_oversized_message_rejected() {
        let env = Env::default();
        let contract_id = env.register(FalconVerifierContract, ());
        let client = FalconVerifierContractClient::new(&env, &contract_id);

        let pubkey = Bytes::from_slice(&env, &[9u8; FALCON_512_PUBKEY_SIZE]);
        let mut sig = [0u8; 666];
        sig[0] = 0x29;
        let signature = Bytes::from_slice(&env, &sig);

        // A message one byte past the cap must be rejected instead of truncated.
        let mut big_msg = [0u8; FALCON_MAX_MESSAGE_SIZE + 1];
        big_msg[0] = 0x01;
        let message = Bytes::from_slice(&env, &big_msg);

        assert!(!client.verify(&pubkey, &message, &signature));
    }
}
