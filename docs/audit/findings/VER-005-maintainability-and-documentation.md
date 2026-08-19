# VER-005 — Maintainability and Documentation Findings

| | |
| --- | --- |
| Finding ID | **VER-005** |
| Veridise issue | **#1290** |
| Source | Veridise audit report |
| Severity | **Warning** |
| Likelihood | Not Likely |
| Impact | Bad |
| Reported | 2026-08-18 |
| Status | **Open** — remediation not yet implemented |
| Owner | TBD |
| Affects | [`falcon-512-core/src/verify.rs`](../../../contracts/falcon-512-core/src/verify.rs), [`falcon-512-core/src/ntt.rs`](../../../contracts/falcon-512-core/src/ntt.rs), [`falcon-512-core/src/lib.rs`](../../../contracts/falcon-512-core/src/lib.rs), [`soroban-falcon-smart-account/src/lib.rs`](../../../contracts/soroban-falcon-smart-account/src/lib.rs) |
| Related | **VER-004** (item 7 overlaps), **VER-002** (item 10 touches the same file), **VER-001** (item 7 touches the same file) |

> **Tracking stub.** This document records the finding and the agreed
> remediation. No code change lands in this PR.

## Finding as reported

### Description

Veridise analysts identified the following improvements to make the codebase
more maintainable and clearly documented:

1. Within `hash_to_point()` in `falcon-512-core/src/verify.rs`, the code
   guarantees that v lies in `[0, Q)`, with `debug_assert!(v < Q)` serving as
   defense in depth against future regressions. Because this check is omitted
   from release builds, replacing it with a runtime assertion would preserve the
   safeguard in the on-chain verifier.
2. In `falcon-512-core/src/verify.rs`, `hash_to_point()` absorbs nonce and
   message into SHAKE256 without encoding their boundary, so distinct input
   pairs with the same concatenation are processed identically, for example,
   `[1, 1] || [2, 2]` and `[1] || [1, 2, 2]`. This ambiguity does not affect the
   current implementation because the only caller, `verify_512()`, always
   supplies a 40-byte nonce. However, `hash_to_point()` should document this
   fixed-length requirement to prevent future callers from using ambiguous
   inputs.
3. The `FalconSmartAccount` stores its 897-byte Falcon public key in contract
   instance storage, consuming approximately 1.4% of the 64 KiB entry limit
   before serialization and ledger-entry overhead. While this is acceptable for
   the current design, the storage footprint and shared limit should be
   documented so future extensions account for the remaining capacity before
   adding instance state.
4. Within `ntt_inverse()` in `falcon-512-core/src/ntt.rs`, the local declaration
   `let logn = 9` duplicates the existing `FALCON_512_LOGN` constant. Using the
   shared constant would make the parameter dependency explicit and prevent the
   values from diverging during future changes.
5. Within `__check_auth()` in `soroban-falcon-smart-account/src/lib.rs`, the
   length check on the stored public key duplicates validation already performed
   by `__constructor()` and `rotate_key()`, the only functions that write to
   `FALCON_PUBKEY_KEY`. The stored value is therefore guaranteed to have the
   expected size under the current design, making this check redundant unless it
   is intentionally retained as defense in depth against future storage changes.
6. In `falcon-512-core/src/verify.rs`, `decode_pubkey()` writes decoded
   coefficients to the mutable output buffer `h` as processing progresses. If
   decoding later fails, the function returns false after `h` may have been
   partially modified, leaving its contents unspecified. The current caller,
   `verify_512()`, immediately returns on failure and therefore does not use
   this state; however, `decode_pubkey()` should document that callers must
   discard `h` whenever decoding fails.
7. In `falcon-512-core/src/verify.rs`, `verify_raw_512()` is publicly accessible
   even though it relies on invariants established by `verify_512()`: `c0` must
   contain canonical coefficient-domain entries, `s2` must use the expected
   signed range, and `h` must be canonical, Montgomery-encoded, and in the
   evaluation domain. Calling it directly with malformed inputs may cause a
   panic or return true for values that do not represent a valid Falcon
   signature. Since this function is an internal verification primitive, its
   visibility should be restricted. The functions in `ntt.rs` should likewise
   use the narrowest visibility required by their callers, making their internal
   status explicit and reducing the risk of misuse.
8. In `falcon-512-core/src/ntt.rs`, line 172 the value `ni` is recomputed on
   every invocation by halving `R` nine times, although the fixed Falcon-512
   parameters make this value invariant: `ni = R / 512 mod Q = 128`. While this
   does not currently affect correctness, it introduces unnecessary arithmetic
   and control flow, obscures a protocol constant, and increases maintenance
   risk. Define `ni` as a constant within `falcon-512-core/src/lib.rs` and use
   it directly.
9. In `falcon-512-core/src/verify.rs`, `decode_pubkey()` checks public-key
   length to be exactly 896 bytes on line 250, matching 512 14-bit coefficients
   with no padding. Therefore, `acc_len` is always zero at the final check on
   line 279, making it ineffective regardless of `acc`. Remove it or replace it
   with `debug_assert_eq!(acc_len, 0)` to document the invariant.
10. `FalconSmartAccount` depends on `soroban-sdk` 23.4.0, where
    `Events::publish` is deprecated in favor of `#[contractevent]`. Both
    `__constructor` (line 103) and `rotate_key` (line 148) still call
    `env.events().publish((symbol_short!("falcon"), symbol_short!("init"|"rotate")), pubkey_hash)`.
    Replace those calls with `#[contractevent]` types so the events stay in the
    contract spec and the deprecation does not become a break on a later SDK
    bump.

## Planned remediation

- [ ] **1.** Replace `debug_assert!(v < Q)` in `hash_to_point` (`verify.rs:370`)
      with a runtime check that survives release builds. Decide whether it
      becomes an `assert!` (panics on-chain) or a `return`/`false` path — the
      smart account's `__check_auth` is required to stay panic-free, so a panic
      here is not automatically acceptable.
- [ ] **2.** Document `hash_to_point`'s fixed-40-byte-nonce requirement and the
      concatenation ambiguity that would follow from a variable-length nonce.
- [ ] **3.** Document the 897-byte instance-storage footprint and the 64 KiB
      entry limit in the smart-account module docs.
- [ ] **4.** Replace `let logn = 9` in `ntt_inverse` (`ntt.rs:145`) with
      `FALCON_512_LOGN`.
- [ ] **5.** Decide the pubkey-length check in `__check_auth` explicitly: keep
      it as documented defense-in-depth, or remove it as redundant. Record the
      choice in a comment either way.
- [ ] **6.** Document that `decode_pubkey`'s `h` output is unspecified when it
      returns `false` and callers must discard it.
- [ ] **7.** Narrow `verify_raw_512` from `pub` to `pub(crate)` (or private),
      and narrow the ten `ntt.rs` primitives to the minimum visibility their
      callers need.
- [ ] **8.** Define `ni = 128` as a named constant in `falcon-512-core/src/lib.rs`
      and use it in `ntt_inverse` instead of the nine-iteration halving loop at
      `ntt.rs:171`.
- [ ] **9.** Replace the ineffective `acc_len` check at `verify.rs:279` with
      `debug_assert_eq!(acc_len, 0)`, or remove it.
- [ ] **10.** Migrate the `init` and `rotate` events to `#[contractevent]`
      types.
- [ ] Add a **VER-005** row to [`remediation-log.md`](../remediation-log.md).

## Repository notes

All ten items were checked against current source and every cited location is
accurate: `debug_assert!(v < Q)` at `verify.rs:370`, `pub fn verify_raw_512` at
`verify.rs:172`, `decode_pubkey`'s `acc_len` check at `verify.rs:279`,
`let logn = 9` at `ntt.rs:145`, `let mut ni = R` at `ntt.rs:171`, and
`soroban-sdk = "23.4.0"` in the smart account's `Cargo.toml`.

**Sequencing.** This finding is not independent of the others and should land
last:

- Item 7 edits `verify.rs`, the same file **VER-001** rewrites. Landing
  VER-005 first will conflict with the header-gate change.
- Item 7 also overlaps **VER-004**, which documents the same `ntt.rs`
  primitives that item 7 wants to make private. Narrowing visibility first
  reduces how much public API needs a documented contract.
- Item 10 edits the same smart-account file **VER-002** restructures for
  two-step rotation, and VER-002 will add `propose` / `accept` / `cancel`
  events that should be defined as `#[contractevent]` from the start rather
  than migrated twice.

**Item 1 needs a decision, not just an edit.** Promoting `debug_assert!` to a
runtime assertion in a contract whose `__check_auth` must not panic is a
behavioral change, not a hygiene change. The likely correct form is a checked
branch returning verification failure rather than `assert!`. Flagging it here so
it is not applied mechanically alongside the other nine items.

**Item 5 asks a question rather than reporting a defect.** The finding
explicitly allows retaining the check as defense in depth. Note that
**VER-002** may add a second writer to `FALCON_PUBKEY_KEY` (the pending-key
promotion path), which strengthens the case for keeping it.
