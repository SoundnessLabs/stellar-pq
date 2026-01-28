# Falcon-512 Smart Account for Soroban

A post-quantum secure smart account implementing Soroban's `CustomAccountInterface` with **embedded Falcon-512 signature verification**. This contract enables quantum-resistant transaction authentication on Stellar.

## Contract Interface

### Constructor

The contract is initialized at deployment with a Falcon-512 public key:

```rust
__constructor(falcon_pubkey: Bytes)  // 897-byte Falcon-512 public key
```

### Functions

| Function | Description |
|----------|-------------|
| `get_pubkey() -> Bytes` | Get the stored Falcon-512 public key |
| `__check_auth(...)` | Verify transaction authorization (called by Soroban runtime) |

### Input Sizes

| Parameter | Size | Description |
|-----------|------|-------------|
| `falcon_pubkey` | 897 bytes | Falcon-512 public key |
| `signature` | 42-700 bytes | Falcon signature (typically ~666 bytes) |

## Usage

### Deploy Your Own Instance

```bash
# Build the contract
cd soroban-falcon-smart-account
stellar contract build

# Deploy with constructor argument
stellar contract deploy \
  --wasm target/wasm32v1-none/release/soroban_falcon_smart_account.wasm \
  --source <YOUR_KEY> \
  --network testnet \
  -- \
  --falcon_pubkey <897_BYTE_HEX_PUBKEY>
```

### Example: On-chain Verification with Rust SDK

```rust
// 1. Build transfer transaction
let invoke_args = InvokeContractArgs {
    contract_address: XLM_SAC,
    function_name: "transfer",
    args: [from: SMART_ACCOUNT, to: DESTINATION, amount: 10_000_000],
};

// 2. First simulation - get nonce and invocation
let sim1 = simulate_transaction(unsigned_tx);
let nonce = sim1.auth_entry.credentials.nonce;
let invocation = sim1.auth_entry.root_invocation;

// 3. Compute payload hash
let preimage = HashIdPreimageSorobanAuthorization {
    network_id: sha256(NETWORK_PASSPHRASE),
    nonce,
    signature_expiration_ledger: current_ledger + 100,
    invocation,
};
let payload_hash: [u8; 32] = sha256(preimage.to_xdr());

// 4. Sign with Falcon-512
let falcon_signature = keypair.sign(payload_hash);

// 5. Build signed auth entry
let signed_auth = SorobanAuthorizationEntry {
    credentials: SorobanAddressCredentials {
        address: SMART_ACCOUNT,
        nonce,
        signature_expiration_ledger,
        signature: ScVal::Bytes(falcon_signature),
    },
    root_invocation: invocation,
};

// 6. Re-simulate with signed auth
let tx_with_auth = build_tx_with_auth(signed_auth);
let sim2 = simulate_transaction(tx_with_auth);

// 7. Build final transaction with exact resources
let final_tx = Transaction {
    fee: base_fee + sim2.min_resource_fee,
    ext: TransactionExt::V1(sim2.transaction_data),
    operations: [invoke_op_with_signed_auth],
};

// 8. Sign envelope and submit
let signed_envelope = fee_payer.sign(final_tx);
submit(signed_envelope);
```

## Live Demo

A live demo is available at: [stellar-pq.soundness.xyz](https://stellar-pq.soundness.xyz/)

## Related

- [Falcon-512 Verifier](../soroban-falcon-verifier) - Standalone verifier contract (reference implementation)
- [Falcon NIST Submission](https://falcon-sign.info/) - Falcon algorithm specification
- [Soroban Custom Accounts](https://developers.stellar.org/docs/build/guides/conventions/custom-account) - Stellar documentation
- [NIST PQC](https://csrc.nist.gov/projects/post-quantum-cryptography) - Post-quantum cryptography standards

## License

MIT
