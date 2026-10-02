# Audit readiness

This directory is the security pack for the repository's
[Stellar SCF Soroban Security Audit Bank](https://stellar.gitbook.io/scf-handbook/supporting-programs/audit-bank/official-rules)
engagement: the Veridise audit report, threat model, tool scans with raw
outputs, remediation history, performance analysis, and verifiable
on-chain receipts.

## Audit report

Veridise audited the three contract crates at commit `79d8c99`
(2026-08-12 to 2026-08-17; 2 analysts, 8 person-days, plus 96 hours of
differential fuzzing against `falcon-rs`). The report found five issues,
none high or critical, and V2 marks all five fixed, each confirmed at
the pull request listed below.

| Report | Version | Date | SHA-256 |
| --- | --- | --- | --- |
| [`reports/VAR_Stellar_260810_Soundness_Labs_Falcon_512-V2.pdf`](./reports/VAR_Stellar_260810_Soundness_Labs_Falcon_512-V2.pdf) | V2 (supersedes V1 of 2026-08-24) | 2026-09-10 | `14ee2e51ceb79f013f040ca02e8f434b3d2b3842f0c86199a94ceef185c3f7c5` |

Veridise publishes its reports at
[veridise.com/audits-archive](https://veridise.com/audits-archive/); only
copies from that archive, or confirmed by Veridise, are official.

| Report ID | Finding | Severity | Status | Fix PR (head confirmed by Veridise) | Write-up |
| --- | --- | --- | --- | --- | --- |
| V-FSA-VUL-001 | Non-standard `0x29` detached signatures accepted | Medium | Fixed | [#2](https://github.com/SoundnessLabs/stellar-pq/pull/2) (`ec54f5c`) | [VER-001](./findings/VER-001-nonstandard-0x29-signatures.md) |
| V-FSA-VUL-002 | Unsafe key rotation may permanently lock smart accounts | Low | Fixed | [#3](https://github.com/SoundnessLabs/stellar-pq/pull/3) (`8c34429`) | [VER-002](./findings/VER-002-unsafe-key-rotation.md) |
| V-FSA-VUL-003 | Non-standard Falcon input limits | Low | Fixed | [#4](https://github.com/SoundnessLabs/stellar-pq/pull/4) (`58101d6`) | [VER-003](./findings/VER-003-nonstandard-input-limits.md) |
| V-FSA-VUL-004 | Undocumented NTT representation invariants | Warning | Fixed | [#5](https://github.com/SoundnessLabs/stellar-pq/pull/5) (`73b7a42`) | [VER-004](./findings/VER-004-ntt-representation-invariants.md) |
| V-FSA-VUL-005 | Maintainability and documentation findings | Warning | Fixed | [#6](https://github.com/SoundnessLabs/stellar-pq/pull/6) (`132b85f`) | [VER-005](./findings/VER-005-maintainability-and-documentation.md) |

The five PRs were merged together with merge commits, so each confirmed
head is part of `main`'s history unchanged. Where two PRs edited the
same code, the merge commits record how the conflict was resolved. The
report's three general recommendations are tracked as VER-R1 to VER-R3
in [`remediation-log.md`](./remediation-log.md).

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
| [`reports/`](./reports/) | The Veridise audit report (V2). See [Audit report](#audit-report) above. |
| [`findings/`](./findings/) | One write-up per Veridise finding (VER-001 to VER-005): the finding as reported, the remediation, and repository notes. |
| [`remediation-log.md`](./remediation-log.md) | Formal vulnerability registry: per-finding ID, severity, status, owner, fix commit, and reference. Includes the application-level commitment to remediate audit-firm critical / high / medium findings within 20 business days. |
| [`optimization-report.md`](./optimization-report.md) | Gas & performance optimization pass: per-call verification cost is **≈ 13 k CPU instructions (≈ 0.013 % of the per-tx budget), down from ≈ 397 k** after the bulk host-copy optimization; covers the NTT / branch-free-arithmetic / zero-heap / bulk-copy wins, long-message measurements (≈ 41 k at 16 KiB, ≈ 125 k at 64 KiB; the message length is uncapped and the cost grows linearly), and the contract-size reduction. All numbers reproducible. |
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
| **Mainnet** | Standalone verifier [`CA5RY3BUC4AXNQ4MJJITOUZVMFO3MW3CF4743SIAD46CGY4ICSU6J7OY`](https://stellar.expert/explorer/public/contract/CA5RY3BUC4AXNQ4MJJITOUZVMFO3MW3CF4743SIAD46CGY4ICSU6J7OY) | WASM byte-identical to the testnet artifact (`wasm_hash eb27c1d6…`). [Upload tx](https://stellar.expert/explorer/public/tx/8b674194033df6e5981e6b9ff056fb43d59d7c6e07a68897781f967c0298d692), [deploy tx](https://stellar.expert/explorer/public/tx/4d4a3f335ff62568d4a31646cf67ad089a6235f8bd62376ac62ffc09283229e6), and on-chain [`verify(...) → true`](https://stellar.expert/explorer/public/tx/39559d91354d478fb9b522533b4e4213fdeba0026dbc5e7d1ffe46c9599a2e77) (wrong message → `false` via read-only simulation). Receipt: [`2026-06-11-verifier-mainnet.json`](./e2e-receipts/2026-06-11-verifier-mainnet.json). |
| Testnet | Smart account [`CANNCY2STTSAR7UQLZ7MVKQNMQ45WCDLJ67ILTOVSO6K3BJTULXSYPC4`](https://stellar.expert/explorer/testnet/contract/CANNCY2STTSAR7UQLZ7MVKQNMQ45WCDLJ67ILTOVSO6K3BJTULXSYPC4) | Full Falcon-signed transfer landed via `__check_auth` (666-byte signature, max compressed format). Receipt: [`2026-05-05-testnet.json`](./e2e-receipts/2026-05-05-testnet.json). |

> **The deployed contracts predate the audit fixes.** All three
> deployments above were built before the Veridise remediations. The
> verifiers (testnet and mainnet, `wasm_hash eb27c1d6…`) still accept the
> non-standard `0x29` header (V-FSA-VUL-001) and enforce the old limits:
> 42–666-byte signatures and messages up to 16 KiB (V-FSA-VUL-003). The
> testnet smart account still has the one-step `rotate_key`
> (V-FSA-VUL-002). The contracts have no upgrade hook, so the fixes
> reach the chain only through new deployments. Until then, production
> reliance on these deployments, and any smart-account mainnet use,
> remain **not recommended**. TM-002 also remains open.

## Security contact

For security issues, please email
[security@soundnesslabs.com](mailto:security@soundnesslabs.com) rather
than opening a public issue. We will acknowledge receipt within two
business days. The standing remediation policy is documented in
[`remediation-log.md`](./remediation-log.md).
