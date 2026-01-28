#![no_std]

//! # Falcon-512 Signature Verifier for Soroban

use soroban_sdk::{contract, contractimpl, Bytes, Env};

mod ntt;
mod verify;

pub use verify::FalconVerifier;

pub const FALCON_512_LOGN: u32 = 9;
pub const FALCON_512_N: usize = 512;
pub const FALCON_512_PUBKEY_SIZE: usize = 897;
/// The prime modulus
pub const Q: u32 = 12289;
/// Squared L2 norm bound for Falcon-512 signatures.
pub const L2_BOUND_512: u32 = 34034726;

#[contract]
pub struct FalconVerifierContract;

#[contractimpl]
impl FalconVerifierContract {
    /// Verify a Falcon-512 signature (compressed format).
    ///
    /// # Arguments
    /// * `public_key` - 897-byte Falcon-512 public key
    /// * `message` - Message that was signed
    /// * `signature` - Falcon signature (compressed format, variable size ~650 bytes)
    ///
    /// # Returns
    /// * `true` if signature is valid, `false` otherwise
    pub fn verify(_env: Env, public_key: Bytes, message: Bytes, signature: Bytes) -> bool {
        if public_key.len() != FALCON_512_PUBKEY_SIZE as u32 {
            return false;
        }
        if signature.len() < 42 || signature.len() > 700 {
            return false;
        }

        let mut pk_bytes = [0u8; FALCON_512_PUBKEY_SIZE];
        for i in 0..FALCON_512_PUBKEY_SIZE {
            pk_bytes[i] = public_key.get(i as u32).unwrap();
        }

        let sig_len = signature.len() as usize;
        let mut sig_bytes = [0u8; 700];
        for i in 0..sig_len {
            sig_bytes[i] = signature.get(i as u32).unwrap();
        }

        let msg_len = message.len() as usize;
        let mut msg_bytes = [0u8; 4096];
        let actual_msg_len = if msg_len > 4096 { 4096 } else { msg_len };
        for i in 0..actual_msg_len {
            msg_bytes[i] = message.get(i as u32).unwrap();
        }

        FalconVerifier::verify_512(
            &pk_bytes,
            &msg_bytes[..actual_msg_len],
            &sig_bytes[..sig_len],
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
}
