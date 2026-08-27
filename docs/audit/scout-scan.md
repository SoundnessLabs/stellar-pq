# CoinFabrik Scout Scan Report

| | |
| --- | --- |
| Date | 2026-05-07 |
| Tool | [CoinFabrik Scout](https://github.com/CoinFabrik/scout-soroban) (`cargo-scout-audit 0.3.16`) |
| Scope | `contracts/soroban-falcon-smart-account`, `contracts/soroban-falcon-verifier` |
| Out of scope | `contracts/falcon-512-core` — Scout requires one of `ink`, `soroban`, or `substrate-pallets` as a dependency to know what it is analyzing; the core crate is `no_std` and soroban-sdk-free, so Scout cannot run on it. The CT analyzer (`docs/audit/constant-time-analysis.md`) covers `falcon-512-core` instead. |
| Listed under | Stellar SCF Audit Bank readiness checklist — bonus item "Security Tool Scanning: Report from approved [ecosystem scanning tools](https://developers.stellar.org/docs/tools/developer-tools/security-tools)". |
| Result | All Critical-severity findings remediated. Two categories of false positives remain on each contract — both verified to be Scout's static analysis missing the upstream size gates / compile-time constants. Documented below for the audit firm. |

---

## 1. Initial scan

| Crate | Critical | Medium | Minor | Enhancement |
| --- | --- | --- | --- | --- |
| `soroban-falcon-smart-account` | **1** | 1 | 0 | 2 |
| `soroban-falcon-verifier` | 0 | 5 | 0 | 1 |

## 2. Per-finding triage

### S-001 — `[CRITICAL]` integer overflow at `lib.rs:156` (smart-account) — FIXED

```rust
let msg_len = domain.len() + payload_array.len();
```

Scout flagged the `+` as a potential `usize` overflow. In practice both
operands are compile-time bounded — `domain = DOMAIN_SEPARATOR` is a 31-byte
constant and `payload_array` is `[u8; 32]` — so the sum is statically 63
and cannot overflow. **False positive on the threat, true positive on the
operator**: the unchecked `+` is a code-quality concern even when safe.

**Fix (commit applied in this scan iteration).** Replaced the runtime
calculation with two compile-time constants:

```rust
const SIGNED_MESSAGE_LEN: usize = DOMAIN_SEPARATOR.len() + 32;
const _: () = assert!(SIGNED_MESSAGE_LEN <= SIGNED_MESSAGE_MAX);
```

The runtime path now indexes the buffer by the const directly, removing
both the unchecked `+` and the previous runtime `if msg_len > SIGNED_MESSAGE_MAX`
guard (now enforced at compile time). Re-scan: **closed**.

### S-002 — `[ENHANCEMENT]` storage change events on `rotate_key` (smart-account) — FIXED

Scout flagged that `rotate_key` (and by extension `__constructor`) write
to instance storage without emitting an event. **True positive**: off-chain
indexers had no way to detect rotation without re-reading state.

**Fix.** Added two events:

```rust
// __constructor:
env.events().publish(
    (symbol_short!("falcon"), symbol_short!("init")),
    falcon_pubkey,
);

// rotate_key:
env.events().publish(
    (symbol_short!("falcon"), symbol_short!("rotate")),
    new_pubkey,
);
```

Re-scan: **closed**.

### V-001 — `[MEDIUM]` three `unwrap()` calls in `verify` path (verifier) — FIXED

`contracts/soroban-falcon-verifier/src/lib.rs:48,54,60` each had
`signature.get(i as u32).unwrap()` style code. The smart account's
`__check_auth` had been hardened away from `unwrap` (commit `133334e`)
but the standalone verifier hadn't received the same treatment.

While the `unwrap`s would only panic if the upstream size gates were
incorrect, panicking inside a Soroban contract returns a host trap to
the caller, which is a worse failure mode than returning `false`.

**Fix.** Replaced each with `let-else` that returns `false` on a
`None` from `Bytes::get`:

```rust
let Some(b) = public_key.get(i as u32) else {
    return false;
};
pk_bytes[i] = b;
```

Re-scan: **closed**.

## 3. Post-fix scan

| Crate | Critical | Medium | Minor | Enhancement |
| --- | --- | --- | --- | --- |
| `soroban-falcon-smart-account` | 0 | 1 | 0 | 2 |
| `soroban-falcon-verifier` | 0 | 2 | 0 | 1 |

## 4. Open false positives

These remain in the post-fix scan. Each is documented here so an audit
reviewer does not re-raise them.

### F-FP-1 — `[MEDIUM] dos_unbounded_operation` on per-byte copy loops

Affects three sites in the post-fix codebase:

- smart-account `lib.rs:165` — sig-byte copy in `__check_auth`
- verifier `lib.rs:62` — sig-byte copy in `verify`
- verifier `lib.rs:71` — message-byte copy in `verify`

Scout reports "This loop seems to do not have a fixed number of iterations".

**Why this is a false positive.** Each loop runs over a length variable
(`sig_len_usize` or `msg_len_usize`) that is checked against a hard
compile-time constant **immediately above the loop**:

```rust
if sig_len < FALCON_SIG_MIN_SIZE || sig_len > FALCON_SIG_MAX_SIZE {
    return Err(Error::InvalidSignatureSize);
}
// ... a few lines later ...
for i in 0..sig_len_usize { ... }
```

`FALCON_SIG_MAX_SIZE = 752` and `FALCON_512_PUBKEY_SIZE = 897`. The
message copy has no length cap, but it runs through a fixed 1,024-byte
chunk buffer, so each iteration is bounded and the iteration count is
proportional to a length the submitting transaction itself pays for
under the Soroban host's deterministic gas metering. Scout's static
analysis traces neither the size-gate guards nor the chunking, so it
sees "variable-length" loops.

We could suppress with `#[allow(...)]` if Scout supported it, but a
documented note is more transparent for the audit firm.

### F-FP-2 — `[ENHANCEMENT] soroban_version` claims latest is 26.0.0

Scout reports that the latest Soroban version is `26.0.0` and that we
should upgrade from `23.4.0`. The `soroban-sdk` crate as published on
crates.io is at the `23.x` series (23.5.3 in our smart-account
`Cargo.lock`); `26.0.0` appears to refer to an internal Stellar
protocol/runtime version rather than the SDK crate version, so there
is no upgrade path on the SDK side. We re-evaluate this on each
`soroban-sdk` major bump.

### F-FP-3 — `[ENHANCEMENT] assert_violation` on the new compile-time assert

Smart-account only. Scout flags

```rust
const _: () = assert!(SIGNED_MESSAGE_LEN <= SIGNED_MESSAGE_MAX);
```

with "Assert causes panic. Instead, return a proper error." This is a
**const-context** assertion: the `assert!` runs at compile time as part
of the `const _` evaluation, never at runtime. If the invariant is
violated, the build fails — a panic at runtime is impossible. Scout's
lint does not distinguish const-context from runtime asserts.

This idiom is the Rust standard way to encode compile-time invariants
prior to stable `const_assert!` macros, and the alternative (no check
at all, or a runtime check) is strictly worse.

## 5. Reproduction

```bash
cargo install cargo-scout-audit --locked  # one-time
bash docs/audit/scout-scan/run.sh
```

Per-crate raw outputs are committed at
[`scout-scan/scout-soroban-falcon-smart-account.txt`](scout-scan/scout-soroban-falcon-smart-account.txt)
and
[`scout-scan/scout-soroban-falcon-verifier.txt`](scout-scan/scout-soroban-falcon-verifier.txt).
