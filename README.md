# Stellar Post-Quantum Cryptography

This repository provides experimental implementations of post-quantum
cryptographic schemes for the Stellar blockchain, explored both at the
**application level** (via Soroban Smart Accounts) and at the **protocol
level**, by studying signature schemes that are candidates for aggregation.

> **WARNING.** This code has not been audited. Do **not** use in
> production or with real funds until a professional security audit has
> been completed. A formal review under the
> [Stellar SCF Soroban Security Audit Bank](https://stellar.gitbook.io/scf-handbook/supporting-programs/audit-bank/official-rules)
> is being scheduled — see [Audit readiness](#audit-readiness) below.

## What's here

| Path | Purpose |
| --- | --- |
| [`contracts/falcon-512-core`](./contracts/falcon-512-core) | Pure-Rust, `no_std`, soroban-sdk-free Falcon-512 verifier. Shared by the two contracts so crypto fixes land in one place. |
| [`contracts/soroban-falcon-verifier`](./contracts/soroban-falcon-verifier) | Standalone Soroban contract exposing `verify(pk, msg, sig) -> bool` as a public utility. |
| [`contracts/soroban-falcon-smart-account`](./contracts/soroban-falcon-smart-account) | Soroban `CustomAccountInterface` that authorizes transactions with a Falcon-512 signature over a domain-separated payload. Supports `__constructor(falcon_pubkey)` and `rotate_key`. |
| [`web-demo`](./web-demo) | Vite + React demo: deploys, funds, and submits Falcon-signed transfers from the browser. Uses a vendored `falcon-wasm` for off-chain signing. |
| [`e2e`](./e2e) | Reproducible testnet harness — produces an audit-grade JSON receipt with a real Falcon-signed transaction. See [`e2e/README.md`](./e2e/README.md). |
| [`docs/audit`](./docs/audit) | Pre-audit security artifacts: threat model, constant-time analysis, dependency / lint scan, remediation log, and committed e2e receipts. |

The Falcon-512 verifier follows the NIST standard and can be used to
verify signatures produced by any NIST-compatible implementation, such
as [falcon.py](https://github.com/tprest/falcon.py) or the official C
reference. The implementation was tested against the published Known
Answer Test (KAT) vectors. For convenience we also publish
[falcon-rust](https://github.com/SoundnessLabs/falcon-rust), a thin
binding to the reference C implementation.

## Architecture in one paragraph

The smart-account contract holds the user's Falcon-512 public key in
instance storage. When Soroban's host runs `__check_auth`, the contract
prepends a fixed domain-separation tag (`b"soroban-falcon-smart-account-v1"`)
to the host-provided `signature_payload` and Falcon-verifies the
provided signature against the stored public key. The
`signature_payload` itself is a SHA-256 of the
`HashIdPreimageSorobanAuthorization` XDR struct, which already binds
the network id, account nonce, expiration ledger, and the full root
invocation — so almost every replay vector is defeated by the host's
own preimage and the contract's job is essentially "refuse to undo
that". The standalone verifier contract is the same Falcon primitive
exposed without the smart-account wrapper.

## Quick start

```bash
# Build all three contract WASMs (writes to each crate's target/)
make build

# Run unit tests across all three crates
make test

# Run the testnet end-to-end harness (Falcon-signed transfer on testnet)
# Requires SOURCE_SECRET in e2e/.env — see e2e/README.md
make e2e

# Re-run the security tooling scans whose output lives in docs/audit/
make audit-scan    # cargo audit + cargo clippy on every crate
make ct-scan       # constant-time analysis fixtures
```

Prerequisites: a recent stable `rustc` with the `wasm32v1-none` target
(`rustup target add wasm32v1-none`), `cargo`, the
[`stellar` CLI](https://developers.stellar.org/docs/tools/developer-tools/cli)
v23+, and `bun` v1+ for the e2e harness. The constant-time scan
additionally needs the
[Trail of Bits `constant-time-analysis`](https://github.com/trailofbits/constant-time-analysis)
plugin or its analyzer script — see `docs/audit/ct-analysis/run.sh`.

## Repository layout

```
.
├── README.md                       # this file
├── Makefile                        # build / test / e2e / audit-scan / ct-scan
├── LICENSE                         # MIT
├── contracts/
│   ├── falcon-512-core/            # no_std verify primitive (NTT, SHAKE-256)
│   ├── soroban-falcon-verifier/    # public verify(pk,msg,sig) contract
│   └── soroban-falcon-smart-account/  # CustomAccountInterface impl
├── web-demo/                       # Vite + React demo of the smart account
├── e2e/                            # reproducible testnet harness (Bun)
└── docs/
    └── audit/
        ├── threat-model.md             # STRIDE model, 24 threats, code-cited mitigations
        ├── constant-time-analysis.md   # Trail of Bits CT scan + F-001 remediation
        ├── dependency-and-lint-scan.md # cargo audit + clippy report
        ├── remediation-log.md          # formal vulnerability registry
        ├── ct-analysis/                # standalone fixtures + run.sh
        ├── dep-scan/                   # captured raw outputs + run.sh
        └── e2e-receipts/               # committed testnet run receipts
```

## Audit readiness

The repo is being prepared for an SCF Soroban Security Audit Bank
engagement. The full pre-audit pack lives under
[`docs/audit/`](./docs/audit/):

| Document | What it covers |
| --- | --- |
| [`threat-model.md`](./docs/audit/threat-model.md) | STRIDE analysis using Stellar's 4-section template. 24 concrete threats across S/T/R/I/D/E, each mitigation cites `file:line` against committed code. Includes the system data flow diagram and trust boundaries. |
| [`constant-time-analysis.md`](./docs/audit/constant-time-analysis.md) | Trail of Bits CT analyzer scan of `falcon-512-core` across `{arm64, x86_64} × {-Oz, -O3}`. One finding (F-001 — UDIV in `hash_to_point`) was identified and remediated in the same commit; current scan is clean on every (arch, opt) cell. |
| [`dependency-and-lint-scan.md`](./docs/audit/dependency-and-lint-scan.md) | `cargo audit` against each crate's `Cargo.lock` plus `cargo clippy` across all targets. Three transitive upstream advisories surfaced (none reachable in our usage); a fourth (`keccak 0.1.5`) was remediated by a lockfile bump. No security-relevant clippy findings. |
| [`remediation-log.md`](./docs/audit/remediation-log.md) | Formal vulnerability registry: per-finding ID, severity, status, owner, fix commit, and reference. Includes the application-level commitment to remediate audit-firm critical / high / medium findings within 20 business days. |
| [`e2e-receipts/`](./docs/audit/e2e-receipts/) | Committed JSON receipts from real testnet runs of the e2e harness — contract id, Falcon public key, transaction hash, payload hash, and the on-chain explorer URL the auditor can click and independently verify. The first receipt deploys to `CANNCY2STTSAR7UQLZ7MVKQNMQ45WCDLJ67ILTOVSO6K3BJTULXSYPC4` and lands a 666-byte Falcon signature. |

## Status

| Area | Status |
| --- | --- |
| `falcon-512-core` verify path | Constant-time-clean at the contract's `-Oz` profile (see `docs/audit/constant-time-analysis.md`); 6 unit tests |
| Test coverage | **35 tests** across the 3 crates (13 unit + 22 integration), including a `tests/kat.rs` suite that replays **all 100 official NIST Falcon-512 KAT vectors** (`tests/falcon512-KAT.rsp`) plus negative tests for wrong-message and wrong-public-key |
| Smart-account contract | Domain-separated `__check_auth`, panic-free runtime paths, key rotation, KAT + integration + benchmark tests |
| Standalone verifier contract | KAT + integration + benchmark tests; deterministic Soroban env-test snapshots committed under `test_snapshots/` |
| Web demo | Functional on testnet; not hardened for mainnet (see `remediation-log.md` TM-001) |
| End-to-end testnet flow | One full Falcon-signed transfer landed on testnet (see receipt) |
| Mainnet | Not yet recommended — pending audit completion and TM-001 / TM-002 follow-ups |

## License

MIT — see [`LICENSE`](./LICENSE).

## Security contact

For security issues, please email
[security@soundnesslabs.com](mailto:security@soundnesslabs.com) rather
than opening a public issue. We will acknowledge receipt within two
business days. The standing remediation policy is documented in
[`docs/audit/remediation-log.md`](./docs/audit/remediation-log.md).
