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
| Status | **Fixed** — all ten items implemented 2026-08-24 (commit pending) |
| Owner | gnosed |
| Affects | [`falcon-512-core/src/verify.rs`](../../../contracts/falcon-512-core/src/verify.rs), [`falcon-512-core/src/ntt.rs`](../../../contracts/falcon-512-core/src/ntt.rs), [`falcon-512-core/src/lib.rs`](../../../contracts/falcon-512-core/src/lib.rs), [`soroban-falcon-smart-account/src/lib.rs`](../../../contracts/soroban-falcon-smart-account/src/lib.rs) |
| Related | **VER-004** (item 7 overlaps), **VER-002** (item 10 touches the same file), **VER-001** (item 7 touches the same file) |

> **Remediated.** All ten items were implemented on
> `audit/ver-005-maintainability-and-documentation` (2026-08-24); the
> checklist below records what landed and the decisions taken on items 1,
> 5, and 7.
> Full test suite (unit + KAT + `testutils` integration), clippy, and both
> WASM builds pass.

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

- [x] **1.** Implemented as a **checked `false` return**, not `assert!`:
      `hash_to_point` now returns `bool`, `verify_512` fails verification if
      the `[0, Q)` guarantee is ever violated. The check survives release
      builds and `__check_auth` stays panic-free. A `debug_assert_eq!` on the
      40-byte nonce length was added alongside (see item 2).
- [x] **2.** `hash_to_point` doc comment now spells out the unframed
      `nonce || message` absorption, the concatenation-ambiguity example, and
      the MUST-pass-exactly-40-nonce-bytes requirement for future callers.
- [x] **3.** Smart-account module docs gained an "Instance-storage footprint"
      section covering the 897-byte key, the 64 KiB shared entry limit, and
      the budgeting rule for future instance state.
- [x] **4.** The `let logn = 9` local is gone entirely: item 8's constant
      replaced the halving loop, and the compile-time assertion pinning it is
      expressed via `FALCON_512_LOGN`.
- [x] **5.** **Kept** as defense in depth, with a comment recording that
      `__constructor`/`rotate_key` are today's only writers, why the check is
      deliberately retained (future storage migration or additional writer,
      e.g. VER-002's promote path), and its trivial cost.
- [x] **6.** `decode_pubkey` docs now state the on-failure contract: `h` is
      unspecified/partially written and MUST be discarded on `false`.
- [x] **7.** `verify_raw_512` is now **private** with a doc comment listing
      the three caller-established invariants. In `ntt.rs`: `pub(crate)` for
      the six functions `verify.rs` uses (`field_sub`, `ntt_forward`,
      `ntt_inverse`, `poly_pointwise_mul`, `poly_sub`,
      `poly_prepare_for_mul`); private for `field_add`, `montgomery_mul`,
      `poly_to_montgomery`, `GMB`, `IGMB`. `field_halve` was deleted — its
      only caller was the halving loop removed by item 8.
- [x] **8.** `FALCON_512_NI: u32 = 128` defined in `falcon-512-core/src/lib.rs`
      (`pub(crate)`), used directly in `ntt_inverse`; a compile-time
      `const _: () = assert!((FALCON_512_NI << FALCON_512_LOGN) % Q == R)` in
      `ntt.rs` pins the derivation `NI · N ≡ R (mod Q)`.
- [x] **9.** Replaced with `debug_assert_eq!(acc_len, 0, ...)` plus a comment
      explaining why the accumulator is always drained (896 · 8 = 512 · 14).
- [x] **10.** `FalconInit` / `FalconRotate` `#[contractevent]` types with
      `topics = ["falcon", "init"|"rotate"]` and
      `data_format = "single-value"`, preserving the exact wire shape of the
      old `env.events().publish(...)` calls (topics tuple + single
      `BytesN<32>` data) so existing indexers are unaffected.
- [x] Add a **VER-005** row to [`remediation-log.md`](../remediation-log.md).

## Repository notes

All ten items were checked against current source and every cited location is
accurate: `debug_assert!(v < Q)` at `verify.rs:370`, `pub fn verify_raw_512` at
`verify.rs:172`, `decode_pubkey`'s `acc_len` check at `verify.rs:279`,
`let logn = 9` at `ntt.rs:145`, `let mut ni = R` at `ntt.rs:171`, and
`soroban-sdk = "23.4.0"` in the smart account's `Cargo.toml`.

**Sequencing.** This branch is based directly on `main` and contains only the
ten items above, so it can be reviewed on its own. It overlaps the other
findings, and merging it alongside them needs care:

- **VER-001** touches the same "Accepted signature formats" module docs and
  the header gate in `verify.rs`. This branch deliberately leaves both
  alone — including the "signers disagree about the nibble" text, which
  VER-001 establishes is factually wrong and rewrites. Take VER-001's
  version of the header/format region when the two are merged; the changes
  here sit elsewhere in the file.
- **VER-002** restructures the same smart-account file for two-step
  rotation, and its API replaces `rotate_key`. Its `propose`/`accept`/
  `cancel` events should be defined as `#[contractevent]` from the start,
  mirroring `FalconInit`/`FalconRotate`, rather than migrated twice; the
  `FalconRotate` type defined here dies with `rotate_key` unless the
  `rotate` topic is kept for indexer continuity.
- **VER-004** documents the same `ntt.rs` primitives item 7 makes private,
  so less public API is left needing a documented contract than when
  VER-004 was written. Its contracts still apply to the surviving
  functions; the `field_halve` documentation goes away with the function.

**Item 1 needs a decision, not just an edit.** Promoting `debug_assert!` to a
runtime assertion in a contract whose `__check_auth` must not panic is a
behavioral change, not a hygiene change. The likely correct form is a checked
branch returning verification failure rather than `assert!`. Flagging it here so
it is not applied mechanically alongside the other nine items.

**Item 5 asks a question rather than reporting a defect.** The finding
explicitly allows retaining the check as defense in depth. Note that
**VER-002** may add a second writer to `FALCON_PUBKEY_KEY` (the pending-key
promotion path), which strengthens the case for keeping it.
