# Falcon-512 Verifier for Soroban

> **WARNING: This code has not been audited. Use at your own risk. Do not use in production with real funds until a professional security audit has been completed.**

A pure-Rust implementation of Falcon-512 post-quantum signature verification for [Soroban](https://soroban.stellar.org/) smart contracts.

## Quick Start

### Prerequisites

1. **Rust** (1.70+)

   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   rustup target add wasm32-unknown-unknown
   ```

2. **Stellar CLI**

   ```bash
   cargo install stellar-cli --locked
   ```

3. **Testnet Account**

   ```bash
   stellar keys generate --global alice --network testnet
   stellar keys address alice
   # Fund at https://friendbot.stellar.org/?addr=<YOUR_ADDRESS>
   ```

### Step 1: Generate Falcon Keys and Sign a Message (Off-Chain)

First, create a small Rust project to generate keys and signatures using the `falcon` crate:

```bash
cargo new falcon-signer
cd falcon-signer
```

Add to `Cargo.toml`:

```toml
[dependencies]
falcon = { path = "../falcon" }  # or from crates.io when published
hex = "0.4"
```

Create `src/main.rs`:

```rust
use falcon::{Falcon512, KeyPair, SignatureFormat};

fn main() {
    // Generate a keypair from a seed (use secure random in production!)
    let seed: [u8; 48] = [0x42; 48]; // Replace with secure entropy
    let keypair = KeyPair::<Falcon512>::generate_from_seed(&seed)
        .expect("Failed to generate keypair");

    // Sign a message
    let message = b"Hello, Soroban!";
    let signature = keypair
        .sign_with_seed(message, SignatureFormat::Padded, &seed)
        .expect("Failed to sign");

    // Output hex-encoded values for use with Stellar CLI
    println!("Public Key ({} bytes):", keypair.public_key().as_bytes().len());
    println!("{}", hex::encode(keypair.public_key().as_bytes()));
    println!();
    println!("Message: {:?}", String::from_utf8_lossy(message));
    println!("Message Hex: {}", hex::encode(message));
    println!();
    println!("Signature ({} bytes):", signature.len());
    println!("{}", hex::encode(signature.as_bytes()));
}
```

Run it:

```bash
cargo run
```

Save the output - you'll need the public key and signature hex strings.

### Step 2: Build the Verifier Contract

```bash
cd soroban-falcon-verifier
stellar contract build
```

This creates `target/wasm32-unknown-unknown/release/soroban_falcon_verifier.wasm`.

### Step 3: Deploy to Testnet

Use the deploy script:

```bash
./deploy.sh --network testnet --source alice
```

Or deploy manually:

```bash
stellar contract deploy \
    --wasm target/wasm32-unknown-unknown/release/soroban_falcon_verifier.wasm \
    --source alice \
    --network testnet
```

Save the returned contract ID (e.g., `CCUXVGY7ABTWKKAMOJNUD536D7KVVEPG5DXA7SSALSSB3O7OAU3TL57S`).

For mainnet deployment:

```bash
./deploy.sh --network mainnet --source alice
```

### Step 4: Verify a Signature On-Chain

Using the values from Step 1:

```bash
stellar contract invoke \
    --id <CONTRACT_ID> \
    --source alice \
    --network testnet \
    -- \
    verify \
    --public_key <PUBLIC_KEY_HEX> \
    --message <MESSAGE_HEX> \
    --signature <SIGNATURE_HEX>
```

**Example with test vectors:**

```bash
# Contract deployed on testnet
CONTRACT_ID="CCUXVGY7ABTWKKAMOJNUD536D7KVVEPG5DXA7SSALSSB3O7OAU3TL57S"

# Test vector: "Hello, Falcon!" signed with test keypair
PUBLIC_KEY="0902c671f64d92df6c446a63f5061d73fab61be667e74db66752251102a105922a6fe56a7b3a48196bafc22de2275600dfd8b4149842bf0a5f3b7df4e1f6608f5394aae63e918a7bc492426a62e64d1873fb72c020a3c6be3a9295bc29aaf1c351267c6b00ffc2aa003f64fa9133628b2996b4327b7ee6366b9acb4067e30715fcf68273e04880a453eb468eff0a8d563af3235c6cae44984e8ed8911a34222ed6ec3274f8c491893a9f74ab6b1d67daa0083eb666c098acd4745aa208362a8e14b906437c2cc1ca044a5b903724c9066cd662a622cc38165a4d91322e193c48d12b5e20977bdb4816d6c1aa6a8a4118705029de6fd8723d3ca408ea0c296ceba31e903fbbc9dd60b0c1ca74a1a995d3cf449518815ab29f227d257491f758630484e3a6e36c83008069e538e3e65272f0a5440d8e6998e516e1a5390045b986c24975567c8ce8eae5b29916797516c04f69085a0112e9295b8d96e878410e12507ff9ba012c1f352a84be660a467a95321c8947b07440d58ac215b9cc2ee3d2e5c5af1e9044aed41e94305390c5110c27e5ee3a620c898f90671911e58f75c1085551618b5b4443e3e3527955357007d8696bb59e0d625f248f513de19916a093b43ef00b8d8211a3801874c9687b792e9588a59622b748ae5adc1ff98d0040506cd7c720e64123631bdd70628fa2534bf1094d92b82f2d5fb586d715dee362ac6cd33268a3249669c853fde1643222968b072d07be36764962d3c6a0550038bce88219585357616fb63e701f923ae986247850c7c5ad74bd3e8cf342623cabb8e467fe55a1103975f9af1235995ca30bfe8ea9af0619a2995a283e5cd49bae9a9737201d152d253f50e526d55c59ae8675eeca051bbf44f4c9e530cdfca2c0b192cf8f779a85de921e06a48b71ac1170af6c50c16d3328149c5a682ceb18a01f1de6207319d54a5f205ff82d8ae5536a924721e68c83b82d47dbc0854db1d392e055e2702e8a9401e200616d43aa8c25075712b1f0274f097cf51423685a051d35afb9a9d3217e365e95d95bff5a31e8320bc423bc5052d1ec04739005090a8e6f95b53014129aa30b937cf157c6d0bfa77263e3a2d435954e30f790a4ca062e7d17aa2d52a5a4aec83108c12e24fcf97a9119554eadf26b5447b1d0d7e0484b58122a1b68aa15bd3e5db8927b4240785966f5cba8784b752d723a86c13c005ec57fe22bb18afd43d1093d232ac8b09f920d2a8cbec54e56f93edd6dd235a1ef"

MESSAGE="48656c6c6f2c2046616c636f6e21"  # "Hello, Falcon!" in hex

SIGNATURE="399e11dbc7c5328dbdd260d989a2e58c18e698b7ee2c94235312fabbae38c24058d1dd43fe030b3f2583c4e2dcc445a1c76624aa2e2a0527fd6a6398a521b5c6d6391c9caf0729893d087fd672d38c0232e9ff98e313bebbe069e93a371de31f7e6c2905544a210fa3363aa23ce2418803d6b1fee2a275f3e8f2d6585ffa30ac2bf639345d78b1da59a2c1187a3f79190b3b788537993873fb9755bc8dd7723fbbefeaa5fd89a25298609f4f7ec5988292c4a976f833d6f312eaea792e53d9b49b31bd5bd20ee4bef5a887359d5c71e86e4d14c56848d23d65f2dd65775d2a0f47549d6289b1ab4897142aa12d7424ac17c4ce1ba84ea6094f448e0e57c53ea64521596220cdef215ad311b6d57723de37438ebae27d38fae24e81eefc98a88e9ea39d5418a53b9fd4912624ae4f81e219759ecb1759b6bee72de06285432f3c7c310c0b867b5afdff29658f45610854fbdecb1b04524cc0b6d16edccb37dace29db3becd6779ded4caa6f5a277b852d11ad2a46b8d731c6ef694c39bb3772532bc0f99757ab4ce76ae25d646c7dd8eecdee84b3b3040797975ff39782a11b8eb65507fe415c5a39b6862949f6eeb1c53c996f14be765154c9b239230990621e52513b5da72bcfc6a48433cefcb843a1127a2335d559161f9db54eb798bb15c65d4ad073f0d9f52cc6cba122ed824726758226cbe41d340bd495c131f891eecb1837b9df7e66e8695355fd5853e736d4bedc224063f08ac33b6e9bd5e21ad8ec52a2b14e225299399a26287f28c4d8a3567f3a685fa5dfa2f94ac8476b38793b7d4fd711bafb5ebeac3f65e70466a51455cba3946a6688e6cb14ef1386143efc7638f655910f751bd4ecc5168a142495937fb5afb5e84698a35d829ef83a387336c622f1b8b3bab64d9eca1a0000000000000000000000000000"

stellar contract invoke \
    --id $CONTRACT_ID \
    --source demo \
    --network testnet \
    -- \
    verify \
    --public_key $PUBLIC_KEY \
    --message $MESSAGE \
    --signature $SIGNATURE
```

**Expected output:** `true`

## Contract Interface

### `verify(public_key, message, signature) -> bool`

Verifies a Falcon-512 signature.

| Parameter | Type | Description |
|-----------|------|-------------|
| `public_key` | `Bytes` | 897-byte Falcon-512 public key |
| `message` | `Bytes` | The message that was signed (any length) |
| `signature` | `Bytes` | Signature in compressed (~650 bytes) or padded (666 bytes) format |

Returns `true` if valid, `false` otherwise.

## Integration Example (Rust SDK)

```rust
use soroban_sdk::{contractimport, Bytes, Env};

contractimport!(
    file = "path/to/soroban_falcon_verifier.wasm"
);

pub fn verify_signature(env: &Env, pubkey: &[u8], message: &[u8], sig: &[u8]) -> bool {
    let contract_id = /* your deployed contract ID */;
    let client = Client::new(env, &contract_id);

    client.verify(
        &Bytes::from_slice(env, pubkey),
        &Bytes::from_slice(env, message),
        &Bytes::from_slice(env, sig),
    )
}
```

## Security

**This code has not been audited.** Use at your own risk in production environments.

## License

MIT
