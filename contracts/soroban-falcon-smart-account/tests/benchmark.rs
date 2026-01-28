//! Gas benchmark for Falcon-512 Smart Account verification.
//!
//! Measures CPU instructions and memory usage for embedded verification.

#![cfg(feature = "testutils")]

use soroban_sdk::{Bytes, Env};
use soroban_falcon_smart_account::{FalconSmartAccount, FalconSmartAccountClient, FalconVerifier};

// Test vectors from C FFI bindings
const TEST_PUBKEY_HEX: &str = "0902c671f64d92df6c446a63f5061d73fab61be667e74db66752251102a105922a6fe56a7b3a48196bafc22de2275600dfd8b4149842bf0a5f3b7df4e1f6608f5394aae63e918a7bc492426a62e64d1873fb72c020a3c6be3a9295bc29aaf1c351267c6b00ffc2aa003f64fa9133628b2996b4327b7ee6366b9acb4067e30715fcf68273e04880a453eb468eff0a8d563af3235c6cae44984e8ed8911a34222ed6ec3274f8c491893a9f74ab6b1d67daa0083eb666c098acd4745aa208362a8e14b906437c2cc1ca044a5b903724c9066cd662a622cc38165a4d91322e193c48d12b5e20977bdb4816d6c1aa6a8a4118705029de6fd8723d3ca408ea0c296ceba31e903fbbc9dd60b0c1ca74a1a995d3cf449518815ab29f227d257491f758630484e3a6e36c83008069e538e3e65272f0a5440d8e6998e516e1a5390045b986c24975567c8ce8eae5b29916797516c04f69085a0112e9295b8d96e878410e12507ff9ba012c1f352a84be660a467a95321c8947b07440d58ac215b9cc2ee3d2e5c5af1e9044aed41e94305390c5110c27e5ee3a620c898f90671911e58f75c1085551618b5b4443e3e3527955357007d8696bb59e0d625f248f513de19916a093b43ef00b8d8211a3801874c9687b792e9588a59622b748ae5adc1ff98d0040506cd7c720e64123631bdd70628fa2534bf1094d92b82f2d5fb586d715dee362ac6cd33268a3249669c853fde1643222968b072d07be36764962d3c6a0550038bce88219585357616fb63e701f923ae986247850c7c5ad74bd3e8cf342623cabb8e467fe55a1103975f9af1235995ca30bfe8ea9af0619a2995a283e5cd49bae9a9737201d152d253f50e526d55c59ae8675eeca051bbf44f4c9e530cdfca2c0b192cf8f779a85de921e06a48b71ac1170af6c50c16d3328149c5a682ceb18a01f1de6207319d54a5f205ff82d8ae5536a924721e68c83b82d47dbc0854db1d392e055e2702e8a9401e200616d43aa8c25075712b1f0274f097cf51423685a051d35afb9a9d3217e365e95d95bff5a31e8320bc423bc5052d1ec04739005090a8e6f95b53014129aa30b937cf157c6d0bfa77263e3a2d435954e30f790a4ca062e7d17aa2d52a5a4aec83108c12e24fcf97a9119554eadf26b5447b1d0d7e0484b58122a1b68aa15bd3e5db8927b4240785966f5cba8784b752d723a86c13c005ec57fe22bb18afd43d1093d232ac8b09f920d2a8cbec54e56f93edd6dd235a1ef";

// Padded signature for "Hello, Falcon!" (666 bytes)
const TEST_SIGNATURE_HEX: &str = "399e11dbc7c5328dbdd260d989a2e58c18e698b7ee2c94235312fabbae38c24058d1dd43fe030b3f2583c4e2dcc445a1c76624aa2e2a0527fd6a6398a521b5c6d6391c9caf0729893d087fd672d38c0232e9ff98e313bebbe069e93a371de31f7e6c2905544a210fa3363aa23ce2418803d6b1fee2a275f3e8f2d6585ffa30ac2bf639345d78b1da59a2c1187a3f79190b3b788537993873fb9755bc8dd7723fbbefeaa5fd89a25298609f4f7ec5988292c4a976f833d6f312eaea792e53d9b49b31bd5bd20ee4bef5a887359d5c71e86e4d14c56848d23d65f2dd65775d2a0f47549d6289b1ab4897142aa12d7424ac17c4ce1ba84ea6094f448e0e57c53ea64521596220cdef215ad311b6d57723de37438ebae27d38fae24e81eefc98a88e9ea39d5418a53b9fd4912624ae4f81e219759ecb1759b6bee72de06285432f3c7c310c0b867b5afdff29658f45610854fbdecb1b04524cc0b6d16edccb37dace29db3becd6779ded4caa6f5a277b852d11ad2a46b8d731c6ef694c39bb3772532bc0f99757ab4ce76ae25d646c7dd8eecdee84b3b3040797975ff39782a11b8eb65507fe415c5a39b6862949f6eeb1c53c996f14be765154c9b239230990621e52513b5da72bcfc6a48433cefcb843a1127a2335d559161f9db54eb798bb15c65d4ad073f0d9f52cc6cba122ed824726758226cbe41d340bd495c131f891eecb1837b9df7e66e8695355fd5853e736d4bedc224063f08ac33b6e9bd5e21ad8ec52a2b14e225299399a26287f28c4d8a3567f3a685fa5dfa2f94ac8476b38793b7d4fd711bafb5ebeac3f65e70466a51455cba3946a6688e6cb14ef1386143efc7638f655910f751bd4ecc5168a142495937fb5afb5e84698a35d829ef83a387336c622f1b8b3bab64d9eca1a0000000000000000000000000000";

#[test]
fn benchmark_smart_account_deployment() {
    let env = Env::default();

    // Decode test vectors
    let pubkey_bytes = hex::decode(TEST_PUBKEY_HEX).expect("Invalid pubkey hex");
    let pubkey = Bytes::from_slice(&env, &pubkey_bytes);

    // Reset budget tracking
    env.cost_estimate().budget().reset_default();

    // Deploy contract with constructor
    let contract_id = env.register(FalconSmartAccount, (&pubkey,));
    let _client = FalconSmartAccountClient::new(&env, &contract_id);

    // Print budget consumption
    let budget = env.cost_estimate().budget();
    println!("\n=== Smart Account Deployment Benchmark ===");
    println!("Public key: {} bytes", pubkey_bytes.len());
    println!();

    let cpu_insns = budget.cpu_instruction_cost();
    println!("CPU Instructions: {}", cpu_insns);

    let mem_bytes = budget.memory_bytes_cost();
    println!("Memory Bytes: {}", mem_bytes);

    println!("=== End Benchmark ===\n");
}

#[test]
fn benchmark_embedded_verification() {
    let env = Env::default();

    // Decode test vectors
    let pubkey_bytes = hex::decode(TEST_PUBKEY_HEX).expect("Invalid pubkey hex");
    let sig_bytes = hex::decode(TEST_SIGNATURE_HEX).expect("Invalid signature hex");

    // Reset budget tracking
    env.cost_estimate().budget().reset_default();

    // Run verification directly (simulating __check_auth)
    let result = FalconVerifier::verify_512(&pubkey_bytes, b"Hello, Falcon!", &sig_bytes);
    assert!(result, "Verification should succeed");

    // Print budget consumption
    let budget = env.cost_estimate().budget();
    println!("\n=== Falcon-512 Embedded Verification Benchmark ===");
    println!("Message: \"Hello, Falcon!\" (14 bytes)");
    println!("Signature: {} bytes (padded format)", sig_bytes.len());
    println!("Public key: {} bytes", pubkey_bytes.len());
    println!();

    let cpu_insns = budget.cpu_instruction_cost();
    println!("CPU Instructions: {}", cpu_insns);

    let mem_bytes = budget.memory_bytes_cost();
    println!("Memory Bytes: {}", mem_bytes);

    println!();
    println!("=== Budget Breakdown ===");
    budget.print();

    println!("\n=== End Benchmark ===\n");
}

#[test]
fn benchmark_32byte_message() {
    let env = Env::default();

    // Decode test vectors
    let pubkey_bytes = hex::decode(TEST_PUBKEY_HEX).expect("Invalid pubkey hex");

    // Signature for a 32-byte hash (typical transaction payload)
    // Using the "Test message for cross-implementation verification" signature
    let sig_hex = "399e11dbc7c5328dbdd260d989a2e58c18e698b7ee2c94235312fabbae38c24058d1dd43fe030b3f2591405b77214f2bd4393a17b9c35ef79a4ce21eda5ef85a912da064952654634e34294e4b2dcfdc11257ad245db17ca89445ec4c3871ada38484bf8a2a96829c16edf3d335bb7e96438bbb42b81a490e849d0fc72b2d13eaa152e2549375acd1f1cd6fa9c934987574ac9d2f58cd4e6e5ce5ad91ecc9218d210f5cf173235b9b8e775fae71fc41560c7ab344fc489803372ea7da65b01b5678655d55e1465f218a0344831e968b78dfa696838c50731346792e306b54d64d28675d2c2c65f46caee820edf265bd8dff8fca8e10a4755797751fd643db8b35e68f7546e1292640af0daab7b641ea1f364e98ada0d85441b4ecdd7c947da6d965bb3e7c9bf469ac4c19c3a3cd949385d38aee31bacb0ed3bd65caad0a6dae9ead699b3bef43b4f33aaf34375d7be1f813ac11b26ca7f8179db36cb587a13e4a4f5382cbe65264d99be82daf8d9e4b6149a49d6c5eb14a76642db163912c7e4c7140d07073995d920eddc667f538ed9ed3851cc8cdda11c7d8d9bbcfe4e62f7d35fa561f2f2522850b9fe6a02a4b046596c8a710580b5843f971edac9547ca3aea815393669b6d952082f6be3245f19a8e3c2b97664c8e919ae9972c59acf6d2d5e6e28cf11654f4a32e764de3b295c372101cafbfaf1bf76651c4e99e1096e12f9747635bfa94098c529a36d85b664e7cfd319170a2ff1641a78ba79497970be9fe47ea3a2e660499e73273378377417f6327359b430d1b7ed38aab2bdea3fab0b9d281e8df529b8cf286cf18c506e6ca1b229f8a81c873486cf23f58105d7ec4aa4a2d255b16d9ac0bc7ad7caa7f53c26edd7d99848b34a360cc25eae5bb1cb8b150731216f742bbc2fe9bd6421b9c4000000000000000000";
    let sig_bytes = hex::decode(sig_hex).expect("Invalid signature hex");
    let message = b"Test message for cross-implementation verification";

    // Reset budget tracking
    env.cost_estimate().budget().reset_default();

    // Run verification
    let result = FalconVerifier::verify_512(&pubkey_bytes, message, &sig_bytes);
    assert!(result, "Verification should succeed");

    // Print budget consumption
    let budget = env.cost_estimate().budget();
    println!("\n=== Falcon-512 Verification (50-byte Message) ===");
    println!("Message: {} bytes", message.len());
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

    // Decode test vectors
    let pubkey_bytes = hex::decode(TEST_PUBKEY_HEX).expect("Invalid pubkey hex");
    let sig_bytes = hex::decode(TEST_SIGNATURE_HEX).expect("Invalid signature hex");

    // Reset budget tracking
    env.cost_estimate().budget().reset_default();

    // Run verification with wrong message (should fail)
    let result = FalconVerifier::verify_512(&pubkey_bytes, b"Wrong message!", &sig_bytes);
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
