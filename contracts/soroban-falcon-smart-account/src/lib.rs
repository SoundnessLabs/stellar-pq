#![no_std]

//! Falcon-512 Smart Account for Soroban.
//!
//! A post-quantum secure smart account implementing `CustomAccountInterface`
//! with embedded Falcon-512 signature verification.
//!
//! The contract is initialized at deployment with a Falcon public key via the
//! constructor. All subsequent transactions are authenticated using Falcon
//! signatures.

use soroban_sdk::{
    auth::{Context, CustomAccountInterface},
    contract, contracterror, contractimpl,
    crypto::Hash,
    symbol_short, Bytes, Env, Symbol, Vec,
};

mod ntt;
pub mod verify;

pub use verify::FalconVerifier;

// Storage key for the Falcon public key
const FALCON_PUBKEY_KEY: Symbol = symbol_short!("F_PUBKEY");

// Falcon-512 constants
pub const FALCON_512_LOGN: u32 = 9;
pub const FALCON_512_N: usize = 512;
pub const FALCON_512_PUBKEY_SIZE: usize = 897;
pub const FALCON_SIG_MIN_SIZE: u32 = 42;
pub const FALCON_SIG_MAX_SIZE: u32 = 700;
/// The prime modulus for Falcon ring arithmetic
pub const Q: u32 = 12289;
/// Squared L2 norm bound for Falcon-512 signatures
pub const L2_BOUND_512: u32 = 34034726;

#[contracterror]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Error {
    InvalidPublicKeySize = 1,
    InvalidSignatureSize = 2,
    VerificationFailed = 3,
}

#[contract]
pub struct FalconSmartAccount;

#[contractimpl]
impl FalconSmartAccount {
    /// Constructor - initializes the smart account with a Falcon-512 public key.
    ///
    /// # Arguments
    /// * `falcon_pubkey` - The 897-byte Falcon-512 public key
    ///
    /// # Panics
    /// Panics if the public key is not exactly 897 bytes.
    pub fn __constructor(env: Env, falcon_pubkey: Bytes) {
        if falcon_pubkey.len() != FALCON_512_PUBKEY_SIZE as u32 {
            panic!("Invalid public key size: expected 897 bytes");
        }

        env.storage()
            .instance()
            .set(&FALCON_PUBKEY_KEY, &falcon_pubkey);
    }

    /// Get the stored Falcon public key.
    ///
    /// # Returns
    /// The 897-byte Falcon-512 public key stored in this account.
    pub fn get_pubkey(env: Env) -> Bytes {
        env.storage()
            .instance()
            .get(&FALCON_PUBKEY_KEY)
            .expect("Public key not set")
    }
}

#[contractimpl]
impl CustomAccountInterface for FalconSmartAccount {
    type Signature = Bytes;
    type Error = Error;

    /// Verify authorization using Falcon-512 post-quantum signature.
    ///
    /// # Arguments
    /// * `signature_payload` - The 32-byte hash of the transaction to verify
    /// * `signature` - The Falcon signature (variable size, 42-700 bytes)
    /// * `_auth_contexts` - Authorization contexts (unused)
    ///
    /// # Returns
    /// * `Ok(())` if the signature is valid
    /// * `Err(Error::InvalidSignatureSize)` if signature size is invalid
    /// * `Err(Error::VerificationFailed)` if signature verification fails
    #[allow(non_snake_case)]
    fn __check_auth(
        env: Env,
        signature_payload: Hash<32>,
        signature: Bytes,
        _auth_contexts: Vec<Context>,
    ) -> Result<(), Error> {
        // Get stored public key
        let pubkey: Bytes = env
            .storage()
            .instance()
            .get(&FALCON_PUBKEY_KEY)
            .expect("Public key not set");

        // Validate signature size
        let sig_len = signature.len();
        if sig_len < FALCON_SIG_MIN_SIZE || sig_len > FALCON_SIG_MAX_SIZE {
            return Err(Error::InvalidSignatureSize);
        }

        let mut pk_bytes = [0u8; FALCON_512_PUBKEY_SIZE];
        for i in 0..FALCON_512_PUBKEY_SIZE {
            pk_bytes[i] = pubkey.get(i as u32).unwrap();
        }

        let sig_len_usize = sig_len as usize;
        let mut sig_bytes = [0u8; 700];
        for i in 0..sig_len_usize {
            sig_bytes[i] = signature.get(i as u32).unwrap();
        }

        let payload_array = signature_payload.to_array();

        let is_valid = FalconVerifier::verify_512(
            &pk_bytes,
            payload_array.as_slice(),
            &sig_bytes[..sig_len_usize],
        );

        if is_valid {
            Ok(())
        } else {
            Err(Error::VerificationFailed)
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use soroban_sdk::Env;

    #[test]
    fn test_constructor_and_get_pubkey() {
        let env = Env::default();

        let mut pubkey_data = [0u8; 897];
        pubkey_data[0] = 9; // Falcon-512 header
        let pubkey = Bytes::from_array(&env, &pubkey_data);

        let contract_id = env.register(FalconSmartAccount, (&pubkey,));
        let client = FalconSmartAccountClient::new(&env, &contract_id);

        assert_eq!(client.get_pubkey(), pubkey);
    }

    #[test]
    #[should_panic(expected = "Invalid public key size")]
    fn test_constructor_invalid_pubkey_size() {
        let env = Env::default();

        let bad_pubkey = Bytes::from_array(&env, &[0u8; 100]);

        let _contract_id = env.register(FalconSmartAccount, (&bad_pubkey,));
    }

    #[test]
    fn test_falcon_verification_integration() {
        let env = Env::default();

        let pubkey_hex = "0902c671f64d92df6c446a63f5061d73fab61be667e74db66752251102a105922a6fe56a7b3a48196bafc22de2275600dfd8b4149842bf0a5f3b7df4e1f6608f5394aae63e918a7bc492426a62e64d1873fb72c020a3c6be3a9295bc29aaf1c351267c6b00ffc2aa003f64fa9133628b2996b4327b7ee6366b9acb4067e30715fcf68273e04880a453eb468eff0a8d563af3235c6cae44984e8ed8911a34222ed6ec3274f8c491893a9f74ab6b1d67daa0083eb666c098acd4745aa208362a8e14b906437c2cc1ca044a5b903724c9066cd662a622cc38165a4d91322e193c48d12b5e20977bdb4816d6c1aa6a8a4118705029de6fd8723d3ca408ea0c296ceba31e903fbbc9dd60b0c1ca74a1a995d3cf449518815ab29f227d257491f758630484e3a6e36c83008069e538e3e65272f0a5440d8e6998e516e1a5390045b986c24975567c8ce8eae5b29916797516c04f69085a0112e9295b8d96e878410e12507ff9ba012c1f352a84be660a467a95321c8947b07440d58ac215b9cc2ee3d2e5c5af1e9044aed41e94305390c5110c27e5ee3a620c898f90671911e58f75c1085551618b5b4443e3e3527955357007d8696bb59e0d625f248f513de19916a093b43ef00b8d8211a3801874c9687b792e9588a59622b748ae5adc1ff98d0040506cd7c720e64123631bdd70628fa2534bf1094d92b82f2d5fb586d715dee362ac6cd33268a3249669c853fde1643222968b072d07be36764962d3c6a0550038bce88219585357616fb63e701f923ae986247850c7c5ad74bd3e8cf342623cabb8e467fe55a1103975f9af1235995ca30bfe8ea9af0619a2995a283e5cd49bae9a9737201d152d253f50e526d55c59ae8675eeca051bbf44f4c9e530cdfca2c0b192cf8f779a85de921e06a48b71ac1170af6c50c16d3328149c5a682ceb18a01f1de6207319d54a5f205ff82d8ae5536a924721e68c83b82d47dbc0854db1d392e055e2702e8a9401e200616d43aa8c25075712b1f0274f097cf51423685a051d35afb9a9d3217e365e95d95bff5a31e8320bc423bc5052d1ec04739005090a8e6f95b53014129aa30b937cf157c6d0bfa77263e3a2d435954e30f790a4ca062e7d17aa2d52a5a4aec83108c12e24fcf97a9119554eadf26b5447b1d0d7e0484b58122a1b68aa15bd3e5db8927b4240785966f5cba8784b752d723a86c13c005ec57fe22bb18afd43d1093d232ac8b09f920d2a8cbec54e56f93edd6dd235a1ef";
        let pubkey_bytes = hex::decode(pubkey_hex).unwrap();
        let pubkey = Bytes::from_slice(&env, &pubkey_bytes);

        let contract_id = env.register(FalconSmartAccount, (&pubkey,));
        let client = FalconSmartAccountClient::new(&env, &contract_id);

        let stored_pubkey = client.get_pubkey();
        assert_eq!(stored_pubkey.len(), 897);

        let mut h = [0u16; FALCON_512_N];
        let mut pk_bytes = [0u8; FALCON_512_PUBKEY_SIZE];
        for i in 0..FALCON_512_PUBKEY_SIZE {
            pk_bytes[i] = stored_pubkey.get(i as u32).unwrap();
        }
        assert!(FalconVerifier::decode_pubkey(&pk_bytes, &mut h));
    }

    #[test]
    fn test_direct_verification() {
        let pubkey_hex = "0902c671f64d92df6c446a63f5061d73fab61be667e74db66752251102a105922a6fe56a7b3a48196bafc22de2275600dfd8b4149842bf0a5f3b7df4e1f6608f5394aae63e918a7bc492426a62e64d1873fb72c020a3c6be3a9295bc29aaf1c351267c6b00ffc2aa003f64fa9133628b2996b4327b7ee6366b9acb4067e30715fcf68273e04880a453eb468eff0a8d563af3235c6cae44984e8ed8911a34222ed6ec3274f8c491893a9f74ab6b1d67daa0083eb666c098acd4745aa208362a8e14b906437c2cc1ca044a5b903724c9066cd662a622cc38165a4d91322e193c48d12b5e20977bdb4816d6c1aa6a8a4118705029de6fd8723d3ca408ea0c296ceba31e903fbbc9dd60b0c1ca74a1a995d3cf449518815ab29f227d257491f758630484e3a6e36c83008069e538e3e65272f0a5440d8e6998e516e1a5390045b986c24975567c8ce8eae5b29916797516c04f69085a0112e9295b8d96e878410e12507ff9ba012c1f352a84be660a467a95321c8947b07440d58ac215b9cc2ee3d2e5c5af1e9044aed41e94305390c5110c27e5ee3a620c898f90671911e58f75c1085551618b5b4443e3e3527955357007d8696bb59e0d625f248f513de19916a093b43ef00b8d8211a3801874c9687b792e9588a59622b748ae5adc1ff98d0040506cd7c720e64123631bdd70628fa2534bf1094d92b82f2d5fb586d715dee362ac6cd33268a3249669c853fde1643222968b072d07be36764962d3c6a0550038bce88219585357616fb63e701f923ae986247850c7c5ad74bd3e8cf342623cabb8e467fe55a1103975f9af1235995ca30bfe8ea9af0619a2995a283e5cd49bae9a9737201d152d253f50e526d55c59ae8675eeca051bbf44f4c9e530cdfca2c0b192cf8f779a85de921e06a48b71ac1170af6c50c16d3328149c5a682ceb18a01f1de6207319d54a5f205ff82d8ae5536a924721e68c83b82d47dbc0854db1d392e055e2702e8a9401e200616d43aa8c25075712b1f0274f097cf51423685a051d35afb9a9d3217e365e95d95bff5a31e8320bc423bc5052d1ec04739005090a8e6f95b53014129aa30b937cf157c6d0bfa77263e3a2d435954e30f790a4ca062e7d17aa2d52a5a4aec83108c12e24fcf97a9119554eadf26b5447b1d0d7e0484b58122a1b68aa15bd3e5db8927b4240785966f5cba8784b752d723a86c13c005ec57fe22bb18afd43d1093d232ac8b09f920d2a8cbec54e56f93edd6dd235a1ef";
        let pubkey = hex::decode(pubkey_hex).unwrap();

        let sig_hex = "399e11dbc7c5328dbdd260d989a2e58c18e698b7ee2c94235312fabbae38c24058d1dd43fe030b3f2583c4e2dcc445a1c76624aa2e2a0527fd6a6398a521b5c6d6391c9caf0729893d087fd672d38c0232e9ff98e313bebbe069e93a371de31f7e6c2905544a210fa3363aa23ce2418803d6b1fee2a275f3e8f2d6585ffa30ac2bf639345d78b1da59a2c1187a3f79190b3b788537993873fb9755bc8dd7723fbbefeaa5fd89a25298609f4f7ec5988292c4a976f833d6f312eaea792e53d9b49b31bd5bd20ee4bef5a887359d5c71e86e4d14c56848d23d65f2dd65775d2a0f47549d6289b1ab4897142aa12d7424ac17c4ce1ba84ea6094f448e0e57c53ea64521596220cdef215ad311b6d57723de37438ebae27d38fae24e81eefc98a88e9ea39d5418a53b9fd4912624ae4f81e219759ecb1759b6bee72de06285432f3c7c310c0b867b5afdff29658f45610854fbdecb1b04524cc0b6d16edccb37dace29db3becd6779ded4caa6f5a277b852d11ad2a46b8d731c6ef694c39bb3772532bc0f99757ab4ce76ae25d646c7dd8eecdee84b3b3040797975ff39782a11b8eb65507fe415c5a39b6862949f6eeb1c53c996f14be765154c9b239230990621e52513b5da72bcfc6a48433cefcb843a1127a2335d559161f9db54eb798bb15c65d4ad073f0d9f52cc6cba122ed824726758226cbe41d340bd495c131f891eecb1837b9df7e66e8695355fd5853e736d4bedc224063f08ac33b6e9bd5e21ad8ec52a2b14e225299399a26287f28c4d8a3567f3a685fa5dfa2f94ac8476b38793b7d4fd711bafb5ebeac3f65e70466a51455cba3946a6688e6cb14ef1386143efc7638f655910f751bd4ecc5168a142495937fb5afb5e84698a35d829ef83a387336c622f1b8b3bab64d9eca1a0000000000000000000000000000";
        let signature = hex::decode(sig_hex).unwrap();

        let message = b"Hello, Falcon!";

        assert!(
            FalconVerifier::verify_512(&pubkey, message, &signature),
            "Direct verification should pass"
        );

        assert!(
            !FalconVerifier::verify_512(&pubkey, b"Wrong message", &signature),
            "Wrong message should fail verification"
        );
    }
}
