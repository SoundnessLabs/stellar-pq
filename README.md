# Stellar Post-Quantum Cryptography

This repository provides experimental implementations of post-quantum cryptographic schemes for the Stellar blockchain, explored both at the **application level** (via Soroban Smart Accounts) and at the **protocol level**, by studying signature schemes that are candidates for aggregation.

> **WARNING:** This code has not been audited. Use at your own risk. Do **not** use in production or with real funds until a professional security audit has been completed.

## Contents

You will find:
- A pure Rust implementation of a [FALCON-512 verifier](./contracts/soroban-falcon-verifier), deployable as a Soroban smart contract
- A [post-quantum Soroban Smart Account](./contracts/soroban-falcon-smart-account) using the FALCON-512 verifier to authorize transactions, acting as a hybrid post-quantum account
- A [web demo](./web-demo) showcasing the above contracts deployed on testnet

The FALCON-512 verifier follows the NIST standard and can be used to verify signatures produced by any NIST-compatible implementation, such as [falcon.py](https://github.com/tprest/falcon.py) or the official C reference implementation. The implementation was tested against the provided Known Answer Test (KAT) vectors. For convenience, we also provide a [falcon-rust](https://github.com/SoundnessLabs/falcon-rust) library, which uses C bindings to the reference implementation.

## License

MIT
