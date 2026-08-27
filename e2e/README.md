# Falcon smart-account end-to-end testnet harness

A reproducible, audit-grade evidence script for the SCF Audit Bank
submission. Deploys the contract, funds it, then sends a real
Falcon-512-signed transfer on Stellar testnet and writes a JSON receipt
with explorer URLs the auditor can click and verify externally.

## What you need

- `bun` ≥ 1.x  (`brew install oven-sh/bun/bun` or `npm i -g bun`)
- `stellar` CLI ≥ 23  (`brew install stellar/stellar-cli/stellar-cli` or
  `cargo install --locked stellar-cli`)
- `cargo` + `wasm32v1-none` target  (`rustup target add wasm32v1-none`)
- A funded testnet account (Friendbot, or `stellar keys generate --fund`)

## One-time setup

From the repo root:

```bash
# 1. Build the contract WASM (writes to target/wasm32v1-none/release/)
make build

# 2. Configure the harness
cd e2e
cp .env.example .env
# edit .env — set SOURCE_SECRET to a funded testnet account
bun install
```

If you don't already have a testnet account:

```bash
stellar keys generate --fund e2e-source --network testnet
echo "SOURCE_SECRET=$(stellar keys show e2e-source)" >> e2e/.env
```

## Run it

From `e2e/`:

```bash
bun run start              # full flow: deploy, fund, Falcon-signed transfer
bun run deploy-only        # stop after deploy + fund (skip transfer)
```

A receipt lands at `e2e/runs/run-<iso-timestamp>.json`. The receipts
directory is gitignored — commit a sanitized copy to
`docs/audit/e2e-receipts/` if you want it as a permanent audit artifact.

## What the receipt contains

```jsonc
{
  "timestamp":             "2026-05-05T...Z",
  "network":               "testnet",
  "network_passphrase":    "Test SDF Network ; September 2015",
  "source_account":        "G...",
  "smart_account_id":      "C...",
  "smart_account_explorer": "https://stellar.expert/explorer/testnet/contract/C...",
  "falcon_pubkey_hex":     "09...",
  "falcon_pubkey_size":    897,
  "falcon_seed_origin":    "ephemeral" | "env",
  "falcon_seed_hex":       "..." ,   // present only if ephemeral OR RECEIPT_INCLUDE_SEED=1
  "domain_separator":      "soroban-falcon-smart-account-v1",
  "domain_separator_hex":  "73...",
  "deploy":   { "stdout_tail": "C..." },
  "fund":     { "stdout_tail": "...", "amount_xlm": 20 },
  "transfer": {
    "hash":              "...",
    "explorer_url":      "https://stellar.expert/explorer/testnet/tx/...",
    "nonce":             "1234567890",
    "expiration_ledger": 9876543,
    "payload_hash_hex":  "...",
    "falcon_sig_len":    666,
    "falcon_sig_hex":    "..."
  }
}
```

The auditor can independently verify the receipt by:

1. Opening `transfer.explorer_url` and confirming the tx exists, has
   status SUCCESS, and the source contract is `smart_account_id`.
2. Fetching `smart_account_id`'s state and checking `F_PUBKEY` storage
   equals `falcon_pubkey_hex`.
3. Reconstructing the auth preimage from the on-chain tx (network id,
   nonce, expiration ledger, root invocation), SHA-256ing it, prepending
   `domain_separator`, and verifying `falcon_sig_hex` against
   `falcon_pubkey_hex`. The vendored `falcon-wasm` exposes a `verify`
   method on `Falcon512PublicKey` for this.

## Security notes

- **Never** set `SOURCE_SECRET` to a key that holds real value. Testnet
  XLM only.
- The default flow generates an ephemeral Falcon seed and includes it
  in the receipt for reproducibility — this is fine because the seed
  controls a throwaway testnet account. If you set `FALCON_SEED` in
  the environment, the receipt omits it unless you also export
  `RECEIPT_INCLUDE_SEED=1`.
- The harness does not handle key rotation. Rotation is a two-step flow
  (`propose_key` with the current key, then `accept_key` with a
  proof-of-possession signature by the pending key over
  `"soroban-falcon-smart-account-accept-v1" || SHA-256(pending_pubkey)`;
  `cancel_key` drops a pending proposal). To exercise it, copy the
  smart-account-id out of the receipt and run separate
  `stellar contract invoke ...` calls.
- This script signs with a hot key in the harness process. In a real
  production wallet, the Falcon signing should happen inside a
  hardware-backed credential store (open item Tamper.4 in the threat
  model).

## Troubleshooting

| Symptom | Likely cause |
| --- | --- |
| `WASM not found at target/...` | Run `make build` first. |
| `stellar CLI failed` early in step 3 | `stellar` CLI not in `PATH` or wrong version. Try `stellar --version`. Need ≥ 23. |
| Simulation fails at step 5 with `host fn ... auth violation` | Smart-account contract doesn't have funds (step 4 failed) or the constructor pubkey doesn't match the signing key. Inspect `smart_account_explorer`. |
| `Falcon WASM not found` | `bun install` was not run. From `e2e/`, run `bun install` and try again. |
