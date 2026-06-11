# End-to-end on-chain receipts

Each JSON file in this directory is the immutable record of one real
on-chain run. There are two kinds:

**Smart-account receipts** (`*-testnet.json` without `verifier`) are
the output of one run of [`e2e/run.ts`](../../e2e/README.md) — a real
Falcon-signed transaction on Stellar testnet that exercises the full
smart-account flow:

1. Contract deploy via `stellar contract deploy`, with the Falcon-512
   public key passed to `__constructor`.
2. Smart-account funded with XLM via the native SAC (Ed25519 source).
3. Transfer-out from the smart account, authorized by a Falcon-512
   signature over `DOMAIN_SEPARATOR ‖ signature_payload`.

**Verifier receipts** (`*-verifier-*.json`) record a deployment of the
standalone Falcon-512 verifier contract (testnet or mainnet) plus a
`verify(public_key, message, signature)` exercise with the embedded
test vector — positive and wrong-message negative.

## How to verify a receipt independently

Pick `<run>.json`. Then:

1. Open `transfer.explorerUrl` and confirm `status: SUCCESS` with
   source contract `smart_account_id`.
2. Pull the contract's instance storage and confirm `F_PUBKEY` equals
   `falcon_pubkey_hex`.
3. Reconstruct the auth preimage from the on-chain data (`networkId`
   from the network passphrase, `nonce`, `signatureExpirationLedger`,
   `rootInvocation`), SHA-256 it, prepend `domain_separator`, and
   verify `transfer.falconSigHex` against `falcon_pubkey_hex` using any
   Falcon-512 reference implementation (the vendored `falcon-wasm`
   exposes `Falcon512PublicKey.verify(message, signature)`).

If `falcon_seed_origin == "ephemeral"`, `falcon_seed_hex` is also in
the receipt for full reproducibility — the keypair was generated fresh
for that run, signs only this throwaway testnet account, and is never
reused on mainnet.

## File index

| File | Date | Network | Contract | Highlights |
| --- | --- | --- | --- | --- |
| [`2026-05-05-testnet.json`](2026-05-05-testnet.json) | 2026-05-05 | testnet | Smart account `CANNCY2STTSAR7UQLZ7MVKQNMQ45WCDLJ67ILTOVSO6K3BJTULXSYPC4` | First clean run after F-001 CT fix and SDK v14 upgrade. 666-byte Falcon signature (max compressed format). |
| [`2026-06-07-verifier-testnet.json`](2026-06-07-verifier-testnet.json) | 2026-06-07 | testnet | Verifier `CDDZZJ3B3BMKBPJ7ZVMC3JQC7MDNIODUXYHBCHNCGVXAL56UFBEPM4RC` | First standalone-verifier deployment; on-chain `verify(...) → true` submitted as a real transaction. |
| [`2026-06-11-verifier-mainnet.json`](2026-06-11-verifier-mainnet.json) | 2026-06-11 | **mainnet** | Verifier `CA5RY3BUC4AXNQ4MJJITOUZVMFO3MW3CF4743SIAD46CGY4ICSU6J7OY` | WASM byte-identical to the testnet artifact (`eb27c1d6…`). `verify → true` and wrong-message → `false` confirmed via read-only simulation. |
