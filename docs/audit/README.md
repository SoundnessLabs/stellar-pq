# Audit readiness

This directory is the complete pre-audit security pack for the
repository's [Stellar SCF Soroban Security Audit Bank](https://stellar.gitbook.io/scf-handbook/supporting-programs/audit-bank/official-rules)
engagement. Everything an audit firm needs — threat model, tool scans
with raw outputs, remediation history, performance analysis, and
verifiable on-chain receipts — lives here.

## Scope

In scope: the three contract crates —
[`contracts/falcon-512-core`](../../contracts/falcon-512-core),
[`contracts/soroban-falcon-verifier`](../../contracts/soroban-falcon-verifier),
and [`contracts/soroban-falcon-smart-account`](../../contracts/soroban-falcon-smart-account).

Out of scope: the [`web-demo`](../../web-demo) reference frontend.
Frontends are user-replaceable; the contracts must remain secure under
any signer (see [`threat-model.md`](./threat-model.md)).

## Documents

| Document | What it covers |
| --- | --- |
| [`threat-model.md`](./threat-model.md) | STRIDE analysis using Stellar's 4-section template. 24 concrete threats across S/T/R/I/D/E, each mitigation cites `file:line` against committed code. Includes the system data flow diagram and trust boundaries. |
| [`constant-time-analysis.md`](./constant-time-analysis.md) | Trail of Bits CT analyzer scan of `falcon-512-core` across `{arm64, x86_64} × {-Oz, -O3}`. One finding (F-001 — UDIV in `hash_to_point`) was identified and remediated in the same commit; current scan is clean on every (arch, opt) cell. |
| [`dependency-and-lint-scan.md`](./dependency-and-lint-scan.md) | `cargo audit` against each crate's `Cargo.lock` plus `cargo clippy` across all targets. Three transitive upstream advisories surfaced (none reachable in our usage); a fourth (`keccak 0.1.5`) was remediated by a lockfile bump. No security-relevant clippy findings. |
| [`scout-scan.md`](./scout-scan.md) | CoinFabrik Scout (`cargo-scout-audit 0.3.16`) scan of both Soroban contracts. The one Critical finding (S-001 — integer overflow in `__check_auth` message assembly) was remediated; the remaining flags are documented false positives (Scout's static analysis missing upstream size gates / compile-time constants). `falcon-512-core` is soroban-sdk-free so Scout cannot analyze it — the CT analyzer covers it instead. Fulfils the Audit Bank bonus "Security Tool Scanning" item. |
| [`remediation-log.md`](./remediation-log.md) | Formal vulnerability registry: per-finding ID, severity, status, owner, fix commit, and reference. Includes the application-level commitment to remediate audit-firm critical / high / medium findings within 20 business days. |
| [`optimization-report.md`](./optimization-report.md) | Gas & performance optimization pass: per-call verification cost is **≈ 13 k CPU instructions (≈ 0.013 % of the per-tx budget), down from ≈ 397 k** after the bulk host-copy optimization; covers the NTT / branch-free-arithmetic / zero-heap / bulk-copy wins, a worst-case 16 KB-message measurement (≈ 15 k), and the contract-size reduction. All numbers reproducible. |
| [`e2e-receipts/`](./e2e-receipts/) | Committed JSON receipts from real on-chain runs — contract id, transaction hash, and the explorer URL an auditor can click and independently verify. Indexed in [`e2e-receipts/README.md`](./e2e-receipts/README.md). |

## Raw tool outputs & reproduction

| Directory | Contents |
| --- | --- |
| [`ct-analysis/`](./ct-analysis/) | Standalone fixtures (`falcon_ntt_standalone.rs`, `falcon_verify_standalone.rs`) and `run.sh` for the Trail of Bits constant-time analyzer. |
| [`dep-scan/`](./dep-scan/) | Captured `cargo audit` and `cargo clippy` outputs per crate, plus `run.sh`. |
| [`scout-scan/`](./scout-scan/) | Captured Scout outputs per contract, plus `run.sh`. |

Re-run the scans from the repository root:

```bash
make audit-scan    # cargo audit + cargo clippy on every crate
make ct-scan       # constant-time analysis fixtures
```

## On-chain deployments

| Network | Contract | Evidence |
| --- | --- | --- |
| Testnet | Standalone verifier [`CDDZZJ3B3BMKBPJ7ZVMC3JQC7MDNIODUXYHBCHNCGVXAL56UFBEPM4RC`](https://stellar.expert/explorer/testnet/contract/CDDZZJ3B3BMKBPJ7ZVMC3JQC7MDNIODUXYHBCHNCGVXAL56UFBEPM4RC) | [Deploy tx](https://stellar.expert/explorer/testnet/tx/ebbf06a947c1291c63e93f03d70648571eacb7b07313043adaccb7d8c81aaa1a) and on-chain [`verify(...) → true`](https://stellar.expert/explorer/testnet/tx/b133de953dd09e53f7a524d74faf7ceb593f647538e3d9526d00d2ad5a10b62d) (wrong message → `false`). Receipt: [`2026-06-07-verifier-testnet.json`](./e2e-receipts/2026-06-07-verifier-testnet.json). |
| **Mainnet** | Standalone verifier [`CA5RY3BUC4AXNQ4MJJITOUZVMFO3MW3CF4743SIAD46CGY4ICSU6J7OY`](https://stellar.expert/explorer/public/contract/CA5RY3BUC4AXNQ4MJJITOUZVMFO3MW3CF4743SIAD46CGY4ICSU6J7OY) | WASM byte-identical to the testnet artifact (`wasm_hash eb27c1d6…`). [Upload tx](https://stellar.expert/explorer/public/tx/8b674194033df6e5981e6b9ff056fb43d59d7c6e07a68897781f967c0298d692), [deploy tx](https://stellar.expert/explorer/public/tx/4d4a3f335ff62568d4a31646cf67ad089a6235f8bd62376ac62ffc09283229e6); `verify(...) → true` / wrong message → `false` confirmed via read-only simulation. Receipt: [`2026-06-11-verifier-mainnet.json`](./e2e-receipts/2026-06-11-verifier-mainnet.json). |
| Testnet | Smart account [`CANNCY2STTSAR7UQLZ7MVKQNMQ45WCDLJ67ILTOVSO6K3BJTULXSYPC4`](https://stellar.expert/explorer/testnet/contract/CANNCY2STTSAR7UQLZ7MVKQNMQ45WCDLJ67ILTOVSO6K3BJTULXSYPC4) | Full Falcon-signed transfer landed via `__check_auth` (666-byte signature, max compressed format). Receipt: [`2026-05-05-testnet.json`](./e2e-receipts/2026-05-05-testnet.json). |

> **Deployment ≠ endorsement.** The mainnet verifier deployment exists
> so auditors and integrators can exercise the real artifact. The audit
> is still pending: production reliance on the verifier, and any
> smart-account mainnet use, remain **not recommended** until audit
> completion and the TM-002 follow-up.

## Security contact

For security issues, please email
[security@soundnesslabs.com](mailto:security@soundnesslabs.com) rather
than opening a public issue. We will acknowledge receipt within two
business days. The standing remediation policy is documented in
[`remediation-log.md`](./remediation-log.md).
