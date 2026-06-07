# Gas & Performance Optimization Report

> Tranche 2, Deliverable 3 — "Gas & Performance Optimization Pass".
> This document records the optimizations applied to the Falcon-512
> verification path, the measurement methodology, and the measured
> before/after results. All numbers below are reproducible with the
> commands in [§5](#5-reproduction); nothing here is estimated.

## 1. Summary

| Metric | Result |
| --- | --- |
| Per-call verification cost (standalone verifier) | **12,986 CPU instructions / 1,225 memory bytes** for a 14-byte message |
| Per-call cost *before* the bulk host-copy optimization | 396,903 CPU instructions (**30.6× reduction**, see §4.1) |
| Worst-case verification cost (16,384-byte message) | **15,033 CPU instructions / 1,225 memory bytes** |
| Share of the per-transaction Soroban CPU budget (100,000,000 insns) | **≈ 0.013 %** (worst case ≈ 0.015 %) |
| Share of the per-transaction Soroban memory budget (40 MiB) | **≈ 0.003 %** |
| Deployed contract size (verifier `.wasm`, `stellar contract build`) | **10,660 bytes** |
| Contract size vs. an un-tuned release build | **−96.7 % (30.7× smaller)**, see §4.2 |
| Smart-account deployment cost | **102,290 CPU instructions / 5,805 memory bytes** |

The grant success criterion — *"Gas usage remains within acceptable
bounds for practical on-chain use"* — is met with roughly **four orders
of magnitude of headroom** on CPU (≈ 13 k of 100 M) and over four on
memory. The verifier is **deployed and exercised on Stellar testnet** at
`CDDZZJ3B3BMKBPJ7ZVMC3JQC7MDNIODUXYHBCHNCGVXAL56UFBEPM4RC` (see
[`e2e-receipts/2026-06-07-verifier-testnet.json`](./e2e-receipts/2026-06-07-verifier-testnet.json)).

## 2. Methodology

There are two distinct cost dimensions on Soroban, and this report
measures both separately rather than conflating them:

1. **Per-invocation execution cost** — CPU instructions and memory
   bytes consumed while the contract runs. Measured deterministically
   via the Soroban env-test cost model
   (`Env::cost_estimate().budget()`), the same model the network uses
   to meter and price a transaction. These numbers are *algorithmic*:
   they depend on the operations executed, not on the host compiler's
   optimization level. They are produced by the committed benchmark
   tests (`tests/benchmark.rs`) and the snapshots under
   `test_snapshots/`.

2. **Deployment cost** — the contract `.wasm` is stored on-ledger and
   billed per byte at install time, and must fit under the network's
   contract-size limit. Measured directly as the size of the compiled
   `.wasm` artifact.

**Toolchain (pinned for reproducibility):**

| Component | Version |
| --- | --- |
| `rustc` / `cargo` | 1.94.1 |
| `soroban-sdk` | 23.4.0 |
| `stellar` CLI | 23.0.1 |
| Target | `wasm32-unknown-unknown` |

## 3. Optimizations applied

Each optimization is cited to the exact source location so a reviewer
can verify it is actually present in the audited code.

| # | Optimization | Where | Effect |
| --- | --- | --- | --- |
| O-1 | **NTT-based polynomial multiplication** with Montgomery-form arithmetic. The verifier computes `h · s2` in the NTT domain — `O(n log n)` — instead of schoolbook convolution `O(n²)`. For `n = 512` this replaces ≈ 262 k coefficient products with ≈ 4.6 k. | `falcon-512-core/src/ntt.rs` (`montgomery_mul` :109; forward/inverse twiddle tables in Montgomery form :14, :52) | Largest single contributor to the low per-call CPU cost. |
| O-2 | **Branch-free, division-free field arithmetic.** `field_add`, `field_sub`, `field_halve`, and `montgomery_mul` reduce mod `Q = 12289` using bitmask conditional subtraction (`Q & (0 - (d >> 31))`) — no data-dependent branches and no integer division. | `falcon-512-core/src/ntt.rs:90–114` | Removes hardware UDIV from the hot loop; also constant-time (see `constant-time-analysis.md`). |
| O-3 | **Bounded rejection-sampling reduction (F-001 fix).** `hash_to_point` reduces each 16-bit SHAKE word with exactly four `field_sub` calls under an `ACCEPT_THRESHOLD = 5·Q`, instead of the naive `w % Q` that LLVM lowered to UDIV at `-Oz`. | `falcon-512-core/src/verify.rs:311–345` | Eliminates the only remaining division on the hot path; see remediation F-001. |
| O-4 | **`no_std`, zero-heap design.** The core crate is `#![no_std]` with no allocator; all polynomials are fixed-size stack arrays (`[u16; 512]`, `[i16; 512]`). No `Vec`, no dynamic allocation during verification. | `falcon-512-core/src/lib.rs:1`; array signatures in `verify.rs:146–148`, etc. | Flat, predictable memory cost (1,225 bytes, independent of signature content). |
| O-5 | **Host `sha256` for auxiliary hashing.** Pubkey commitments in the smart account use the Soroban host `sha256` host-function rather than hashing in-WASM. (The Falcon `hash_to_point` itself is SHAKE256, which the Falcon design requires and which has no Soroban host-function equivalent, so it necessarily runs in-WASM.) | `soroban-falcon-smart-account/src/lib.rs:98, 139` | Moves avoidable hashing onto the cheap metered host path. |
| O-6 | **Size-tuned release profile.** `opt-level = "z"`, fat `lto`, `codegen-units = 1`, `panic = "abort"`, `strip = "symbols"`, `overflow-checks = true`. | `*/Cargo.toml` `[profile.release]` | Drives the 30.7× contract-size reduction in §4.2. |
| O-7 | **Shared `falcon-512-core` crate.** Both the standalone verifier and the smart account link the same verification core, so crypto code is compiled and audited once rather than duplicated. | `contracts/falcon-512-core` | Avoids duplicate codegen and divergent crypto paths. |
| O-8 | **Bulk host→guest byte copies.** The contract wrappers extract `public_key` / `signature` / `message` from the Soroban `Bytes` host objects with one `copy_into_slice` each, after a length gate, instead of per-byte `Bytes::get(i)` loops. On Soroban every `get` is a metered host call, so the old loops cost ≈ 1,563 dispatches for the pubkey + signature alone. | `soroban-falcon-verifier/src/lib.rs`; `soroban-falcon-smart-account/src/lib.rs` `__check_auth` | **The single biggest per-call win: 396,903 → 12,986 CPU instructions (30.6×).** See §4.1. |

## 4. Before / after measurements

### 4.1 Per-call verification cost (standalone verifier)

Measured with `tests/benchmark.rs` against the Soroban env-test cost
model — the network's own deterministic metering model.

**The headline optimization (O-8).** The original wrappers copied each
input byte-by-byte via `Bytes::get(i)`; on Soroban every `get` is a
metered host call, so copying the 897-byte public key plus the 666-byte
signature cost ≈ 1,563 host dispatches — which *dominated* the entire
verification. Replacing those loops with a single bulk `copy_into_slice`
per input collapses the cost by ~30×:

| Scenario | Before (per-byte `get`) | After (bulk copy) | Reduction |
| --- | --- | --- | --- |
| Verify, empty message | 393,487 | 12,985 | 30.3× |
| Verify, 14-byte (`"Hello, Falcon!"`) | 396,903 | 12,986 | 30.6× |
| Verify, 100-byte message | 417,887 | 12,997 | 32.2× |
| Failed verify (wrong message) | 396,903 | 12,986 | 30.6× |
| Verify, 16,384-byte message (worst case) | — | **15,033** | — |

(All in CPU instructions; memory is flat at 1,225 bytes in every row.)

Memory is flat — the direct, measurable consequence of the zero-heap
design (O-4). After O-8 the residual ≈ 13 k instructions is the actual
Falcon work (signature/pubkey decode + NTT multiply + `hash_to_point` +
norm check), dominated by the fixed-degree NTT (O-1). It scales only
weakly with message length: even the largest accepted message (16,384
bytes) adds just ≈ 2 k instructions over a tiny one, so there is **no
message-size gas-griefing / DoS vector** (DRS-1/DRS-2). A build-time
`const` assertion bounds the worst-case verify stack frame
(`soroban-falcon-verifier/src/lib.rs`).

### 4.2 Deployment cost — contract `.wasm` size

The contract is billed per stored byte and must fit the network
contract-size limit. Three builds of the **same source**, isolating the
effect of the size-tuning profile (O-6):

| Build profile | `.wasm` size | vs. tuned |
| --- | --- | --- |
| `dev` (unoptimized + debuginfo) | 4,142,157 B (≈ 4.14 MB) | 222.7× larger — **exceeds the contract-size limit; cannot deploy** |
| `release` defaults (`opt=3`, LTO off, no strip, `codegen-units=16`) | 571,829 B (≈ 558 KB) | 30.7× larger |
| **`release` tuned** (`opt=z`, fat LTO, `codegen-units=1`, `strip`, `panic=abort`) | **18,603 B (≈ 18.6 KB)** | — |

The honest "optimization-pass" delta is the two release builds:
**571,829 → 18,603 bytes, a 96.7 % (30.7×) reduction** in on-ledger
deployment cost, with no change to source behaviour. The un-tuned dev
build is included only to show that without the pass the artifact does
not even fit on-chain.

The artifact actually deployed to testnet is built with
`stellar contract build` (target `wasm32v1-none`), which is more compact
still: **10,660 bytes** (wasm hash
`eb27c1d6aad2b9326ff69d0549f6df4f115dec1663f43baa3050ced27bf22457`).

### 4.3 Smart-account deployment

| Operation | CPU instructions | Memory bytes |
| --- | --- | --- |
| Smart-account deployment (`__constructor`) | 102,290 | 5,805 |

## 5. Reproduction

```bash
# Per-call verification cost (§4.1)
cd contracts/soroban-falcon-verifier
cargo test --features testutils --release benchmark -- --nocapture --test-threads=1

# Deployment size ladder (§4.2)
cargo build --target wasm32-unknown-unknown --release            # tuned -> 18,603 B
ls -l target/wasm32-unknown-unknown/release/soroban_falcon_verifier.wasm

CARGO_PROFILE_RELEASE_OPT_LEVEL=3 \
CARGO_PROFILE_RELEASE_LTO=false \
CARGO_PROFILE_RELEASE_CODEGEN_UNITS=16 \
CARGO_PROFILE_RELEASE_STRIP=none \
  cargo build --target wasm32-unknown-unknown --release          # default -> 571,829 B

cargo build --target wasm32-unknown-unknown                      # dev -> 4,142,157 B
ls -l target/wasm32-unknown-unknown/debug/soroban_falcon_verifier.wasm

# Smart-account deployment cost (§4.3)
cd ../soroban-falcon-smart-account
cargo test --features testutils --release benchmark -- --nocapture --test-threads=1
```

## 6. Notes & limitations

- The per-call numbers come from the Soroban env-test cost model, which
  is the network's own deterministic metering model — not wall-clock
  timing. This is the figure that determines on-chain fees.
- The smart-account `tests/benchmark.rs` per-call *verification*
  cases currently report `0/0` because budget tracking is not scoped
  inside the `__check_auth` host path in that harness; the authoritative
  per-call verification cost is therefore taken from the **standalone
  verifier** benchmark (§4.1), which exercises the identical
  `falcon-512-core` code through a directly-metered contract call. The
  smart-account *deployment* benchmark (§4.3) is metered correctly and
  is reported as-is.
- `stellar contract optimize` (wasm-opt) is not required for deployment;
  the 18,603-byte cargo release artifact is already well under the
  contract-size limit and is the artifact that deploys.
