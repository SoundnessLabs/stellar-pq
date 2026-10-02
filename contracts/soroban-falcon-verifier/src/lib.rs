#![no_std]

//! Falcon-512 signature verifier for Soroban.
//!
//! Thin wrapper around `falcon-512-core`. All crypto lives in the core
//! crate; this file only marshals `soroban-sdk` types.

use soroban_sdk::{contract, contractimpl, Bytes, Env};

pub use falcon_512_core::verify;
pub use falcon_512_core::{Falcon512Verification, FalconVerifier};
pub use falcon_512_core::{
    FALCON_512_LOGN, FALCON_512_N, FALCON_512_PUBKEY_SIZE, FALCON_SIG_MAX_SIZE,
    FALCON_SIG_MIN_SIZE, L2_BOUND_512, Q,
};

/// Host->guest copy granularity for the message. The message is hashed
/// through this buffer, so its length is unbounded while the stack stays
/// small.
const MSG_CHUNK_SIZE: usize = 1024;

// Bound the worst-case verify() frame at build time: one message chunk,
// 897 B pubkey, 752 B signature, plus the core verifier's fixed arrays.
// The wasm32 shadow stack defaults to 1 MiB.
const _: () = assert!(
    MSG_CHUNK_SIZE + FALCON_512_PUBKEY_SIZE + (FALCON_SIG_MAX_SIZE as usize) <= 64 * 1024
);

#[contract]
pub struct FalconVerifierContract;

#[contractimpl]
impl FalconVerifierContract {
    /// Verify a Falcon-512 signature.
    ///
    /// 897-byte key, a message of any length, and a compressed or padded
    /// signature. Returns `false` on any failure.
    pub fn verify(_env: Env, public_key: Bytes, message: Bytes, signature: Bytes) -> bool {
        if public_key.len() != FALCON_512_PUBKEY_SIZE as u32 {
            return false;
        }
        let sig_len = signature.len();
        if sig_len < FALCON_SIG_MIN_SIZE || sig_len > FALCON_SIG_MAX_SIZE {
            return false;
        }

        // Bulk host->guest copies: one metered host call per copy, versus
        // one `get()` dispatch per byte. The gates above make each
        // destination exactly its source length, so this cannot panic.
        let mut pk_bytes = [0u8; FALCON_512_PUBKEY_SIZE];
        public_key.copy_into_slice(&mut pk_bytes);

        let sig_len_usize = sig_len as usize;
        let mut sig_bytes = [0u8; FALCON_SIG_MAX_SIZE as usize];
        signature.copy_into_slice(&mut sig_bytes[..sig_len_usize]);

        let Some(mut verification) =
            Falcon512Verification::new(&pk_bytes, &sig_bytes[..sig_len_usize])
        else {
            return false;
        };

        // Hash the message through a fixed-size chunk buffer; only the
        // concatenation of the chunks matters. A message that fits the
        // buffer is copied with a single host call; a longer one costs one
        // `slice` + one copy per chunk.
        let msg_len = message.len();
        let mut chunk = [0u8; MSG_CHUNK_SIZE];
        if msg_len <= MSG_CHUNK_SIZE as u32 {
            message.copy_into_slice(&mut chunk[..msg_len as usize]);
            verification.absorb_message(&chunk[..msg_len as usize]);
        } else {
            let mut offset = 0u32;
            while offset < msg_len {
                let n = (msg_len - offset).min(MSG_CHUNK_SIZE as u32);
                message
                    .slice(offset..offset + n)
                    .copy_into_slice(&mut chunk[..n as usize]);
                verification.absorb_message(&chunk[..n as usize]);
                offset += n;
            }
        }

        verification.finalize()
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
    fn test_large_message_reaches_verification() {
        let env = Env::default();
        let contract_id = env.register(FalconVerifierContract, ());
        let client = FalconVerifierContractClient::new(&env, &contract_id);

        let pubkey = Bytes::from_slice(&env, &[9u8; FALCON_512_PUBKEY_SIZE]);
        let mut sig = [0u8; 666];
        sig[0] = 0x39;
        let signature = Bytes::from_slice(&env, &sig);

        // A 40 KiB message is hashed chunk by chunk; the call must run the
        // full pipeline without trapping and reject on the signature.
        let big_msg = [0x01u8; 40 * 1024];
        let message = Bytes::from_slice(&env, &big_msg);

        assert!(!client.verify(&pubkey, &message, &signature));
    }
}
