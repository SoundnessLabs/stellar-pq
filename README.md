# Stellar Post-Quantum Cryptography

This repository provides experimental implementations of post-quantum
cryptographic schemes for the Stellar blockchain, explored both at the
**application level** (via Soroban Smart Accounts) and at the **protocol
level**, by studying signature schemes that are candidates for aggregation.

The direction of the work tracks Stellar discussion
[#1915 — Post-Quantum Signature Verification Host Functions in Soroban](https://github.com/orgs/stellar/discussions/1915),
which scopes native verification for the three NIST PQ signature schemes
— ML-DSA (FIPS 204), FN-DSA / Falcon (FIPS 206), and SLH-DSA (FIPS 205).
FALCON-512 is implemented today; see [Roadmap](#roadmap) for what's
next.

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
| [`web-demo`](./web-demo) | Vite + React reference frontend driving the smart account — deploys, funds, and submits Falcon-signed transfers from the browser using a vendored `falcon-wasm` signer. **Out of audit scope:** frontends are user-replaceable; the contract must remain secure under any signer (see [`docs/audit/threat-model.md`](./docs/audit/threat-model.md)). |
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
| Web demo | Reference frontend — **out of audit scope**; functional on testnet |
| End-to-end testnet flow | One full Falcon-signed transfer landed on testnet (see receipt) |
| Mainnet | Not yet recommended — pending audit completion and TM-002 follow-up |

## Roadmap

What's next, aligned with Stellar discussion
[#1915](https://github.com/orgs/stellar/discussions/1915):

- **ML-DSA verifier (FIPS 204).** Pure-Rust ML-DSA-44 / ML-DSA-65
  verifier deployable as a Soroban smart contract, mirroring the
  structure of the FALCON-512 verifier. ML-DSA is the
  NIST-standardized general-purpose PQ signature, supported across
  HSMs, KMS providers, and consumer platforms (e.g. Apple CryptoKit,
  AWS / Google Cloud KMS).
- **SLH-DSA verifier (FIPS 205).** Pure-Rust SLH-DSA-128s / SLH-DSA-128f
  verifier deployable as a Soroban smart contract. SLH-DSA is the
  conservative hash-based fallback in the NIST PQ portfolio: its
  security reduces to standard hash preimage and second-preimage
  resistance, making it the right fit for high-value vaults,
  governance, and key-rotation flows. Signing is expensive, but
  verification — the only path that runs on-chain — is plain SHAKE.
- **PQ signer registration in the Smart Account.** Extend the Soroban
  Smart Account so a PQ public key (ML-DSA, FALCON-512, or SLH-DSA) —
  or a proof-based signature commitment (see below) — can be
  registered as a signer alongside existing signers. This is the
  "add another signer" form of the hybrid pattern: any registered
  signer can authorize a transaction, letting users pick a scheme
  (or rotate between them) without redeploying the account.
- **Public Soroban PQ benchmark harness.** Compare host-function vs.
  pure-WASM verification costs across all three NIST schemes (ML-DSA,
  FALCON, SLH-DSA) inside a real Soroban contract, so the
  cost-profile arguments in #1915 are backed by reproducible numbers.
- **Proof-based signatures: a Stellar-native PQ migration path.**
  Ed25519 under RFC 8032 already derives the signing scalar
  deterministically from a seed via SHA-512 — the seed *is* the
  preimage. When a quantum threat becomes realistic, Stellar can
  stop accepting Ed25519 signatures and start accepting *proof-based
  signatures* (specifically, a proof of seed): a PQ zero-knowledge
  proof that the holder of an address knows the seed `x` such that
  `Q = (SHA-512-derived scalar of x) · G`, without revealing `x`.
  This is the only migration strategy that satisfies all four desired
  properties (P1–P4) in the
  [Coinbase Independent Advisory Board position paper on Quantum Computing and Blockchain](https://www.coinbase.com/blog/coinbase-quantum-advisory-council-publishes-position-paper-on-quantum-computing-and-blockchain),
  which cites this approach directly. The Soroban-side verifier is
  based on [WHIR](https://eprint.iacr.org/2024/1586); a prototype and
  benchmarks are in progress. The same WHIR verifier plugs into the
  Smart Account as an additional signer type — a registered seed
  commitment authorizes a transaction by submitting a proof-based
  signature, sitting alongside the NIST PQ signers above.

  Crucially, this is **straightforward to adopt on the signer side**:
  wallets and custodians keep their existing Ed25519 keys, key
  derivation paths, and HSM/MPC stacks unchanged, and only need to
  add the ability to *produce a proof* over the seed they already
  hold. Compare this to rolling out a new PQ signature scheme, which
  requires new key formats, new HSM/KMS curve support, new MPC
  protocols, and a coordinated key-migration ceremony for every
  account. Proof-based signatures move the PQ work into software
  that sits next to the existing signer, rather than into the signer
  itself.

## License

MIT — see [`LICENSE`](./LICENSE).

## Security contact

For security issues, please email
[security@soundnesslabs.com](mailto:security@soundnesslabs.com) rather
than opening a public issue. We will acknowledge receipt within two
business days. The standing remediation policy is documented in
[`docs/audit/remediation-log.md`](./docs/audit/remediation-log.md).
