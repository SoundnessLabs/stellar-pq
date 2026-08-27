# VER-003 — Non-standard Falcon input limits may impair interoperability

| | |
| --- | --- |
| Finding ID | **VER-003** |
| Veridise issue | **#1291** |
| Source | Veridise audit report |
| Severity | **Low** |
| Likelihood | Likely |
| Impact | Bad |
| Reported | 2026-08-19 |
| Status | **Fixed** — remediated on this branch (pending merge to `main`; testnet/mainnet redeploy pending) |
| Owner | gnosed |
| Affects | [`contracts/falcon-512-core/src/lib.rs`](../../../contracts/falcon-512-core/src/lib.rs) (constants), [`verify.rs`](../../../contracts/falcon-512-core/src/verify.rs) (`verify_512`, `decode_sig_compressed`), [`soroban-falcon-verifier/src/lib.rs`](../../../contracts/soroban-falcon-verifier/src/lib.rs), [`soroban-falcon-smart-account/src/lib.rs`](../../../contracts/soroban-falcon-smart-account/src/lib.rs) |
| Related | **AUD-001** (padding canonicity — the 666-byte rule this finding revisits) |

> This document records the finding, the agreed remediation, and the
> implemented fix (see "Implemented remediation" below).

## Finding as reported

### Description

The verifier applies several limits on message and signature size and
coefficients, that do not agree with standard Falcon-512 encodings:

- **Message Length:** `FALCON_MAX_MESSAGE_SIZE` is set to `16,384` bytes in
  `contracts/falcon-512-core/src/lib.rs` line 36. The limit is enforced in
  `FalconVerifier::verify_512` and by the Soroban wrapper at
  `contracts/soroban-falcon-verifier/src/lib.rs`. Falcon itself does not impose
  this, hence this is an implementation-specific limit.
- **Signature Coefficients:** `decode_sig_compressed` in
  `contracts/falcon-512-core/src/verify.rs` line 318 rejects an `s_2`
  coefficient whose absolute value exceeds `2,047`. Although coefficients fall
  within `[-2047, 2047]` with overwhelming probability, and the reference
  compressed encoder applies the same restriction, the configured squared-norm
  bound of `34,034,726` does not by itself exclude coefficients up to `5,833`.
  The verifier consequently accepts only a subset of mathematically valid
  signature vectors.
- **Maximum Signature Length:** In `contracts/falcon-512-core/src/lib.rs` line
  24 `FALCON_SIG_MAX_SIZE` is set to `666` bytes. While `666` bytes is the exact
  size of a padded Falcon-512 signature, the maximum length of a
  variable-length compressed signature is `752` bytes. Valid compressed
  signatures between 667 and 752 bytes are rejected before decoding.
- **Minimum signature length:** `FALCON_SIG_MIN_SIZE` is set to `42` bytes,
  based on a one-byte header, a `40`-byte nonce, and one polynomial byte. A
  compressed Falcon-512 signature encodes `512` coefficients, each requiring at
  least nine bits. The actual minimum is therefore
  `1 + 40 + (512 × 9 / 8) = 617` bytes. Inputs between `42` and `616` bytes pass
  the initial size check but are subsequently rejected during decoding.

### Impact

Messages longer than 16,384 bytes and otherwise valid compressed signatures
exceeding the coefficient or size limits cannot be verified. This may cause
interoperability or availability issues when signatures are produced by
implementations operating over the complete supported range.

The permissive minimum-length check will not result in invalid signatures being
accepted, but allows malformed inputs to proceed through additional decoding
work before rejection.

### Recommendation

Align the message, coefficient, and signature-length limits with the Falcon
specification. In particular, support messages of arbitrary length, compressed
signatures up to 752 bytes, and all coefficients permitted by the verification
rules. The minimum signature length should be increased to 617 bytes to reject
impossible encodings before decoding. Where an implementation-specific
restriction is intentionally retained, explicitly document the deviation, the
accepted range, the reason for introducing the restriction, and its
interoperability implications.

## Planned remediation

Agreed approach: **follow the report's recommendation literally** rather than
documenting the limits as intentional deviations.

- [x] Raise `FALCON_SIG_MIN_SIZE` from `42` to `617`.
- [x] Raise `FALCON_SIG_MAX_SIZE` from `666` to `752` and resize the
      fixed-size signature buffers that are currently `[0u8; 666]`
      (`__check_auth` in the smart account, and the verifier wrapper).
- [x] Relax the `|s₂| > 2047` rejection in `decode_sig_compressed` so that the
      squared-norm bound `L2_BOUND_512` is the only constraint on coefficient
      magnitude.
- [x] Remove or substantially raise `FALCON_MAX_MESSAGE_SIZE` so messages of
      arbitrary length can be hashed, and rework the wrapper paths that copy
      the message into a fixed-size buffer before hashing.
- [x] Revisit the **AUD-001** canonicity rule: it keys "padded" on the exact
      length 666. With the max raised to 752 the padded-vs-natural
      determination must be re-derived so arbitrary-length zero padding does
      not become acceptable again.
- [x] Re-run the gas/CPU benchmarks in
      [`optimization-report.md`](../optimization-report.md); the buffer growth
      and unbounded message hashing invalidate the current
      "≈ 13 k CPU instructions" and "worst-case 16 KB message ≈ 15 k" figures.
- [x] Rebuild and re-measure contract size. Redeploying the testnet (and
      mainnet) artifacts is still **pending**; the deployed contracts run the
      previous limits until then.
- [x] Add a **VER-003** row to [`remediation-log.md`](../remediation-log.md).

## Implemented remediation

- **Constants** (`falcon-512-core/src/lib.rs`): `FALCON_SIG_MIN_SIZE`
  42 → **617** (1 header + 40 nonce + 576 body bytes; 512 coefficients at
  no fewer than 9 bits each), `FALCON_SIG_MAX_SIZE` 666 → **752** (the
  report's maximum for a variable-length compressed signature).
  `FALCON_MAX_MESSAGE_SIZE` is **removed** — no message length limit
  remains anywhere in the verification path.
- **Coefficient bound** (`verify.rs`): `decode_sig_compressed` now rejects
  magnitudes above `MAX_SIG_COEFF = 5833 = ⌊√L2_BOUND_512⌋`, the largest
  magnitude whose square does not exceed the norm bound by itself. Two
  compile-time assertions pin the constant to `L2_BOUND_512`, making the
  norm bound the only constraint on coefficient magnitude. Negative-zero
  rejection and the exact-consumption rule are unchanged.
- **Arbitrary message length**: verification is restructured around a
  streaming `Falcon512Verification` session (parse key + signature, absorb
  message in chunks, finalize); `FalconVerifier::verify_512` keeps its
  signature as the one-shot form. The Soroban verifier contract hashes the
  message through a fixed 1,024-byte chunk buffer (`MSG_CHUNK_SIZE`), so
  message length is unbounded while the stack frame stays constant
  (build-time assertion retained). Messages that fit one chunk keep the
  previous single-host-call copy. The smart account is unaffected — it
  hashes a fixed 63-byte message.
- **Canonicity after the raise**: unchanged rule, re-derived — "padded"
  still means total length exactly 666 with a zero tail, so lengths
  667–752 must decode exactly and arbitrary zero padding stays rejected
  (`test_arbitrary_padding_rejected`-style coverage still passes).
- **Tests**: new unit tests cover the 617/752 gate bounds, decoding of
  magnitudes 2048/5833 and rejection of 5834, negative-zero rejection, a
  minimal 617-byte parseable signature, and chunking equivalence against
  the one-shot path (40 KB message, chunk sizes 1/3/1024/whole); a new
  contract-level test verifies KAT vectors whose message lengths straddle
  the 1,024-byte chunk boundary (1,023 / 1,056 / 3,300 bytes) end-to-end.
- **Measurements** ([`optimization-report.md`](../optimization-report.md)
  updated): standard verify unchanged at **12,986 CPU / 1,225 mem**;
  16 KiB message 40,840 CPU, 64 KiB 125,080 CPU (linear, caller-paid);
  verifier `.wasm` 10,660 → **10,922 bytes**.
- **Docs**: threat model DoS.1/DoS.2/DoS.7 and Elevation.4 rows and the
  Scout F-FP-1 rationale updated to the new limits;
  [`ct-analysis/falcon_verify_standalone.rs`](../ct-analysis/falcon_verify_standalone.rs)
  synced (constants, no message gate, norm-derived coefficient cap).

## Repository notes

The four limits are not equally cheap to change, and the implementer should
expect the last three to be substantially more involved than the first:

1. **`FALCON_SIG_MIN_SIZE` 42 → 617 is free.** It strictly narrows an input
   gate that currently lets impossible encodings reach the decoder. No buffer,
   no benchmark, and no signer is affected.
2. **`FALCON_SIG_MAX_SIZE` 666 → 752 changes on-chain memory layout.** This is
   a `no_std` WASM contract that copies signatures into fixed-size stack
   buffers (`let mut sig_bytes = [0u8; FALCON_SIG_MAX_SIZE as usize];`).
   Growing it grows the contract's stack footprint and its per-call cost.
3. **Relaxing the coefficient bound widens the accepted set beyond what any
   real signer emits.** The `2047` limit is what the reference *encoder*
   produces — the finding acknowledges this ("the reference compressed encoder
   applies the same restriction"). Accepting up to `5833` admits signatures no
   conforming signer generates.
4. **Removing `FALCON_MAX_MESSAGE_SIZE` is the largest change.** Arbitrary
   message length is incompatible with the current fixed-buffer, zero-heap
   design that the optimization report treats as a headline property. This
   likely requires streaming the message into SHAKE256 rather than copying it
   host→guest first.

None of this contradicts the recommendation — it is the cost of implementing
it, recorded here so the work is scoped accurately. If the team later prefers
the report's own escape hatch ("where an implementation-specific restriction is
intentionally retained, explicitly document the deviation"), that decision
should be recorded in this file rather than made silently during
implementation.
