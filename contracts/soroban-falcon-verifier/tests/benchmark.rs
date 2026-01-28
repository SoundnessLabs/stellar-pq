//! Gas benchmark for Falcon-512 signature verification.
//!
//! Measures CPU instructions and memory usage for verification operations.

#![cfg(feature = "testutils")]

use soroban_sdk::{Bytes, Env};
use soroban_falcon_verifier::{FalconVerifierContract, FalconVerifierContractClient};

// Test vectors from C FFI bindings
const TEST_PUBKEY_HEX: &str = "0902c671f64d92df6c446a63f5061d73fab61be667e74db66752251102a105922a6fe56a7b3a48196bafc22de2275600dfd8b4149842bf0a5f3b7df4e1f6608f5394aae63e918a7bc492426a62e64d1873fb72c020a3c6be3a9295bc29aaf1c351267c6b00ffc2aa003f64fa9133628b2996b4327b7ee6366b9acb4067e30715fcf68273e04880a453eb468eff0a8d563af3235c6cae44984e8ed8911a34222ed6ec3274f8c491893a9f74ab6b1d67daa0083eb666c098acd4745aa208362a8e14b906437c2cc1ca044a5b903724c9066cd662a622cc38165a4d91322e193c48d12b5e20977bdb4816d6c1aa6a8a4118705029de6fd8723d3ca408ea0c296ceba31e903fbbc9dd60b0c1ca74a1a995d3cf449518815ab29f227d257491f758630484e3a6e36c83008069e538e3e65272f0a5440d8e6998e516e1a5390045b986c24975567c8ce8eae5b29916797516c04f69085a0112e9295b8d96e878410e12507ff9ba012c1f352a84be660a467a95321c8947b07440d58ac215b9cc2ee3d2e5c5af1e9044aed41e94305390c5110c27e5ee3a620c898f90671911e58f75c1085551618b5b4443e3e3527955357007d8696bb59e0d625f248f513de19916a093b43ef00b8d8211a3801874c9687b792e9588a59622b748ae5adc1ff98d0040506cd7c720e64123631bdd70628fa2534bf1094d92b82f2d5fb586d715dee362ac6cd33268a3249669c853fde1643222968b072d07be36764962d3c6a0550038bce88219585357616fb63e701f923ae986247850c7c5ad74bd3e8cf342623cabb8e467fe55a1103975f9af1235995ca30bfe8ea9af0619a2995a283e5cd49bae9a9737201d152d253f50e526d55c59ae8675eeca051bbf44f4c9e530cdfca2c0b192cf8f779a85de921e06a48b71ac1170af6c50c16d3328149c5a682ceb18a01f1de6207319d54a5f205ff82d8ae5536a924721e68c83b82d47dbc0854db1d392e055e2702e8a9401e200616d43aa8c25075712b1f0274f097cf51423685a051d35afb9a9d3217e365e95d95bff5a31e8320bc423bc5052d1ec04739005090a8e6f95b53014129aa30b937cf157c6d0bfa77263e3a2d435954e30f790a4ca062e7d17aa2d52a5a4aec83108c12e24fcf97a9119554eadf26b5447b1d0d7e0484b58122a1b68aa15bd3e5db8927b4240785966f5cba8784b752d723a86c13c005ec57fe22bb18afd43d1093d232ac8b09f920d2a8cbec54e56f93edd6dd235a1ef";

// Padded signature for "Hello, Falcon!" (666 bytes)
const TEST_SIGNATURE_HEX: &str = "399e11dbc7c5328dbdd260d989a2e58c18e698b7ee2c94235312fabbae38c24058d1dd43fe030b3f2583c4e2dcc445a1c76624aa2e2a0527fd6a6398a521b5c6d6391c9caf0729893d087fd672d38c0232e9ff98e313bebbe069e93a371de31f7e6c2905544a210fa3363aa23ce2418803d6b1fee2a275f3e8f2d6585ffa30ac2bf639345d78b1da59a2c1187a3f79190b3b788537993873fb9755bc8dd7723fbbefeaa5fd89a25298609f4f7ec5988292c4a976f833d6f312eaea792e53d9b49b31bd5bd20ee4bef5a887359d5c71e86e4d14c56848d23d65f2dd65775d2a0f47549d6289b1ab4897142aa12d7424ac17c4ce1ba84ea6094f448e0e57c53ea64521596220cdef215ad311b6d57723de37438ebae27d38fae24e81eefc98a88e9ea39d5418a53b9fd4912624ae4f81e219759ecb1759b6bee72de06285432f3c7c310c0b867b5afdff29658f45610854fbdecb1b04524cc0b6d16edccb37dace29db3becd6779ded4caa6f5a277b852d11ad2a46b8d731c6ef694c39bb3772532bc0f99757ab4ce76ae25d646c7dd8eecdee84b3b3040797975ff39782a11b8eb65507fe415c5a39b6862949f6eeb1c53c996f14be765154c9b239230990621e52513b5da72bcfc6a48433cefcb843a1127a2335d559161f9db54eb798bb15c65d4ad073f0d9f52cc6cba122ed824726758226cbe41d340bd495c131f891eecb1837b9df7e66e8695355fd5853e736d4bedc224063f08ac33b6e9bd5e21ad8ec52a2b14e225299399a26287f28c4d8a3567f3a685fa5dfa2f94ac8476b38793b7d4fd711bafb5ebeac3f65e70466a51455cba3946a6688e6cb14ef1386143efc7638f655910f751bd4ecc5168a142495937fb5afb5e84698a35d829ef83a387336c622f1b8b3bab64d9eca1a0000000000000000000000000000";

#[test]
fn benchmark_verify_falcon512() {
    let env = Env::default();
    let contract_id = env.register(FalconVerifierContract, ());
    let client = FalconVerifierContractClient::new(&env, &contract_id);

    // Decode test vectors
    let pubkey_bytes = hex::decode(TEST_PUBKEY_HEX).expect("Invalid pubkey hex");
    let sig_bytes = hex::decode(TEST_SIGNATURE_HEX).expect("Invalid signature hex");

    // Convert to Soroban Bytes
    let pubkey = Bytes::from_slice(&env, &pubkey_bytes);
    let message = Bytes::from_slice(&env, b"Hello, Falcon!");
    let signature = Bytes::from_slice(&env, &sig_bytes);

    // Reset budget tracking
    env.cost_estimate().budget().reset_default();

    // Run verification
    let result = client.verify(&pubkey, &message, &signature);
    assert!(result, "Verification should succeed");

    // Print budget consumption
    let budget = env.cost_estimate().budget();
    println!("\n=== Falcon-512 Verification Gas Benchmark ===");
    println!("Message: \"Hello, Falcon!\" (14 bytes)");
    println!("Signature: {} bytes (padded format)", sig_bytes.len());
    println!("Public key: {} bytes", pubkey_bytes.len());
    println!();

    // Get CPU instructions consumed
    let cpu_insns = budget.cpu_instruction_cost();
    println!("CPU Instructions: {}", cpu_insns);

    // Get memory bytes consumed
    let mem_bytes = budget.memory_bytes_cost();
    println!("Memory Bytes: {}", mem_bytes);

    println!();
    println!("=== Budget Breakdown ===");
    budget.print();

    println!("\n=== End Benchmark ===\n");
}

#[test]
fn benchmark_verify_empty_message() {
    let env = Env::default();
    let contract_id = env.register(FalconVerifierContract, ());
    let client = FalconVerifierContractClient::new(&env, &contract_id);

    // Decode test vectors
    let pubkey_bytes = hex::decode(TEST_PUBKEY_HEX).expect("Invalid pubkey hex");
    // Signature for empty message
    let sig_hex = "399e11dbc7c5328dbdd260d989a2e58c18e698b7ee2c94235312fabbae38c24058d1dd43fe030b3f25bbafe2f1767a33929d6cbe92c46e1666c9e36c314cec389f476cf63a639a984e46fd63e4ec65fae59abb3e4570d016d67b6f52bdff6eef1d24d0a20869518d31667dabbd77b3063317b8ce5fa7b94eab750a929066395fbe54fd8897bfe517e12826813c94d2ad9e384391992d8da2851430ba8c0e9d8d547a7525827f0382a13c4e1aab19e98957810975a0d822992439fc03dcd5f9bcb1971e30d87234ec67462dc6d75b5e9a0db6f53f675e5c522951640d675ed096bdfe8889a4b2686829b21eeec48c35662bac39b8e723edaf71920519dbe357366c3c2a7272f192d21315fc7c7749e993aae132cb29dcd41b197e7997f7652c971824438351984c151d06192177319f9da62be786966e495695c4e82d99cb9fcd66e86a3e84d25c56a2c8ea4fddf2ab9c2c1c53acd597aee372867db08fb4f3b92e569027115a475dfed273599a51ed460d35ca7be3f99c22018da0b9c976e20fce8714d71687dfce50588336aeb6d48f926e81b8e9a5aaa9f2702c3bd5baf3b3a9e28956a2118fab99e8ff2e16b44856c83953e6273ce46655a3460ae996ba4520a7a722be6b1a0628802f9c4822b7a27ee529a419fa9d6a767d643fd1a9eea66bf68efd4f92a5f005d48323150b2e5d9379147218a0bb7853067af0faac2cbd3a879d3f87850935b0056bc703bdc3ae33fb2cff849d4e59af2b44ee76316a572d45155d7aaecaf2b3fbe271de6cb8e7063c9ad53ca428fa6f60b3a510a260fd091c810a605ef652e542c633deb1c0b31a662b61a2c3a00a6f8bbcc8582db5861e45998f6b60142ab4fa6ade67497c6d8f65f5c604e7efab1cc9ca79e38ddaa7b72b01ddd9ef1318f61e00000000000000000000000000000000";
    let sig_bytes = hex::decode(sig_hex).expect("Invalid signature hex");

    // Convert to Soroban Bytes
    let pubkey = Bytes::from_slice(&env, &pubkey_bytes);
    let message = Bytes::from_slice(&env, b"");
    let signature = Bytes::from_slice(&env, &sig_bytes);

    // Reset budget tracking
    env.cost_estimate().budget().reset_default();

    // Run verification
    let result = client.verify(&pubkey, &message, &signature);
    assert!(result, "Verification should succeed");

    // Print budget consumption
    let budget = env.cost_estimate().budget();
    println!("\n=== Falcon-512 Verification (Empty Message) ===");
    println!("Message: \"\" (0 bytes)");
    println!("Signature: {} bytes (padded format)", sig_bytes.len());

    let cpu_insns = budget.cpu_instruction_cost();
    println!("CPU Instructions: {}", cpu_insns);

    let mem_bytes = budget.memory_bytes_cost();
    println!("Memory Bytes: {}", mem_bytes);

    println!("=== End Benchmark ===\n");
}

#[test]
fn benchmark_verify_large_message() {
    let env = Env::default();
    let contract_id = env.register(FalconVerifierContract, ());
    let client = FalconVerifierContractClient::new(&env, &contract_id);

    // Decode test vectors
    let pubkey_bytes = hex::decode(TEST_PUBKEY_HEX).expect("Invalid pubkey hex");
    // Signature for binary data (100 bytes: 0x00..0x63)
    let sig_hex = "399e11dbc7c5328dbdd260d989a2e58c18e698b7ee2c94235312fabbae38c24058d1dd43fe030b3f2584574f5f13cef9416249e48bd1e249b63af2728c4871e45b21a271d0432b256616b63300cce2dce131833da501e2c7eb7455dd03875579e2c89b553ebd2b9274d19a56f2c4093875b8924ebb1e6b13b61d0868dc5e2aa9a0dfbf0a9f8fa915e238586dc289068d3d32d8269a8e715f99e99072b2d3f306dea87cbcca090353a12dcb3672b3ecda9a9fc6dbdae9e8a5254357384fa8cf6b052084d67fae0479d187e3a3e85a24deb948ecfa8ace45f88d7ed2f50aa4b43a4d65d5c161556bc507debbe9fe9a9c85074688658f84e943e5ffa259af6d5e999dc3f369345d82957f1f6dab8f2d8316c48d21628cd61341313124133291c563892262dca51a95a18f6e77c503d78984dc180617694c49e96b0a95b3a9eee16ab89cae13fb5fa62c824bf776a55f9bd8fff777ba24817d9eca896569077aa416fa16f5ba64ef542429d55cfe3b6410a9525e8fe4655774b3648620b7315cb6cd232a15b358beca70e40e01df74a5bcc74f3066a1ad1cf39eb972fa0bec360beeae2a7913ea4e94033369c9264a7259677aa51c23fd0ec617fe96370cff654541a3a2fc51335f2ebe65f1373a2479fb23066bcf9e6b1d2acf0fdd114c5249560e58311c698c03abefa12d570466286b9ca993837e5d6bfcadb14f7498736b5d22f86ed25ddeab3509a1aa39442f51ae9faeac4a81a573abff6b66253cad32dd774244c62ab74e13226f91b314e5b39daa0237bed0ba0a0ecb356cf27f2ac9b483e0f4c4e3a605ee4f7aba4e567674e7fca18e6a268944a82cdaeaec73bde42b9adab7ac5ad2b294778e8da0ba34e97555ce69bbbffbd640a025d5ba449e98286c4350c7346e4f2935adf00e9628f7c00000000000000000000000";
    let sig_bytes = hex::decode(sig_hex).expect("Invalid signature hex");

    // 100-byte binary message
    let msg_bytes: [u8; 100] = core::array::from_fn(|i| i as u8);

    // Convert to Soroban Bytes
    let pubkey = Bytes::from_slice(&env, &pubkey_bytes);
    let message = Bytes::from_slice(&env, &msg_bytes);
    let signature = Bytes::from_slice(&env, &sig_bytes);

    // Reset budget tracking
    env.cost_estimate().budget().reset_default();

    // Run verification
    let result = client.verify(&pubkey, &message, &signature);
    assert!(result, "Verification should succeed");

    // Print budget consumption
    let budget = env.cost_estimate().budget();
    println!("\n=== Falcon-512 Verification (100-byte Message) ===");
    println!("Message: binary 0x00..0x63 (100 bytes)");
    println!("Signature: {} bytes (padded format)", sig_bytes.len());

    let cpu_insns = budget.cpu_instruction_cost();
    println!("CPU Instructions: {}", cpu_insns);

    let mem_bytes = budget.memory_bytes_cost();
    println!("Memory Bytes: {}", mem_bytes);

    println!("=== End Benchmark ===\n");
}

#[test]
fn benchmark_failed_verification() {
    let env = Env::default();
    let contract_id = env.register(FalconVerifierContract, ());
    let client = FalconVerifierContractClient::new(&env, &contract_id);

    // Decode test vectors
    let pubkey_bytes = hex::decode(TEST_PUBKEY_HEX).expect("Invalid pubkey hex");
    let sig_bytes = hex::decode(TEST_SIGNATURE_HEX).expect("Invalid signature hex");

    // Convert to Soroban Bytes - wrong message
    let pubkey = Bytes::from_slice(&env, &pubkey_bytes);
    let message = Bytes::from_slice(&env, b"Wrong message!");
    let signature = Bytes::from_slice(&env, &sig_bytes);

    // Reset budget tracking
    env.cost_estimate().budget().reset_default();

    // Run verification (should fail)
    let result = client.verify(&pubkey, &message, &signature);
    assert!(!result, "Verification should fail");

    // Print budget consumption
    let budget = env.cost_estimate().budget();
    println!("\n=== Falcon-512 Failed Verification ===");
    println!("Message: \"Wrong message!\" (mismatch)");
    println!("Signature: {} bytes (padded format)", sig_bytes.len());

    let cpu_insns = budget.cpu_instruction_cost();
    println!("CPU Instructions: {}", cpu_insns);

    let mem_bytes = budget.memory_bytes_cost();
    println!("Memory Bytes: {}", mem_bytes);

    println!("(Note: Failed verification uses similar resources as successful)");
    println!("=== End Benchmark ===\n");
}
