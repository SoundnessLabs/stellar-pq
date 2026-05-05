# End-to-end testnet receipts

Each JSON file in this directory is the immutable output of one run of
[`e2e/run.ts`](../../e2e/README.md) — a real Falcon-signed transaction
on Stellar testnet that exercises the full smart-account flow:

1. Contract deploy via `stellar contract deploy`, with the Falcon-512
   public key passed to `__constructor`.
2. Smart-account funded with XLM via the native SAC (Ed25519 source).
3. Transfer-out from the smart account, authorized by a Falcon-512
   signature over `DOMAIN_SEPARATOR ‖ signature_payload`.

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

| File | Date | Smart account | Highlights |
| --- | --- | --- | --- |
| [`2026-05-05-testnet.json`](2026-05-05-testnet.json) | 2026-05-05 | `CANNCY2STTSAR7UQLZ7MVKQNMQ45WCDLJ67ILTOVSO6K3BJTULXSYPC4` | First clean run after F-001 CT fix and SDK v14 upgrade. 666-byte Falcon signature (max compressed format). |
