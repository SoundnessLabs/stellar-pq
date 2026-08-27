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

// DRS-1: bound the worst-case verify() stack frame at build time. verify()
// stacks a 16 KiB message buffer + 897 B pubkey + 666 B signature buffer;
// verify_512 then uses several fixed [u16;512]/[i16;512] arrays. Keep the
// entry buffers well under the wasm32 shadow-stack budget (1 MiB default).
const _: () = assert!(
    FALCON_MAX_MESSAGE_SIZE + FALCON_512_PUBKEY_SIZE + (FALCON_SIG_MAX_SIZE as usize) <= 64 * 1024
);

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

        // Bulk host->guest copies (DRS-3 optimization). The length gates above
        // guarantee `public_key.len() == 897`, `sig_len in [42,666]`, and
        // `msg_len <= 16384`, so each destination slice is sized to exactly the
        // source length; `copy_into_slice` only panics on a length mismatch,
        // which cannot occur here. One metered host call each, versus up to
        // ~17.9 KB of individual `get()` dispatches.
        let mut pk_bytes = [0u8; FALCON_512_PUBKEY_SIZE];
        public_key.copy_into_slice(&mut pk_bytes);

        let sig_len_usize = sig_len as usize;
        let mut sig_bytes = [0u8; FALCON_SIG_MAX_SIZE as usize];
        signature.copy_into_slice(&mut sig_bytes[..sig_len_usize]);

        let msg_len_usize = msg_len as usize;
        let mut msg_bytes = [0u8; FALCON_MAX_MESSAGE_SIZE];
        message.copy_into_slice(&mut msg_bytes[..msg_len_usize]);

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
        sig[0] = 0x39;
        let signature = Bytes::from_slice(&env, &sig);

        // A message one byte past the cap must be rejected instead of truncated.
        let mut big_msg = [0u8; FALCON_MAX_MESSAGE_SIZE + 1];
        big_msg[0] = 0x01;
        let message = Bytes::from_slice(&env, &big_msg);

        assert!(!client.verify(&pubkey, &message, &signature));
    }
}
