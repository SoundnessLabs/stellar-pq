# Vulnerability Remediation Log

| | |
| --- | --- |
| Project | `stellar-pq` — Falcon-512 smart account on Stellar Soroban |
| Last updated | 2026-10-02 (Veridise report V2 confirms VER-001..005 fixed; the five fix PRs merged together) |
| Scope | Issues identified by self-review, threat modeling, constant-time analysis, dependency audit, clippy lints, a multi-agent adversarial audit (2026-06-07), and the Veridise audit engagement (VER-nnn rows, severities on Veridise's scale). Row VER-nnn is the report's finding V-FSA-VUL-nnn; the report itself is [`reports/VAR_Stellar_260810_Soundness_Labs_Falcon_512-V2.pdf`](reports/VAR_Stellar_260810_Soundness_Labs_Falcon_512-V2.pdf). |
| Standing commitment | Per the Stellar SCF Audit Bank initial-audit terms, all critical, high, and medium severity findings produced by the audit firm will be addressed within 20 business days of the report's delivery, with this log updated to reflect each fix. Met for the Veridise audit: the V1 report was delivered 2026-08-24 and all five findings, including the one Medium, were fixed by 2026-08-27. |

## Severity definitions

| Severity | Definition |
| --- | --- |
| **Critical** | Direct account compromise, fund drain, or root-key bypass with no preconditions. |
| **High** | Meaningful security degradation with a realistic exploit path under expected operating conditions. |
| **Medium** | Requires specific conditions to exploit OR limited blast radius (e.g. only the affected account is impacted, no cross-account effect). |
| **Low** | Defense-in-depth concern; not directly exploitable under the documented threat model. |
| **Informational** | No security impact under the threat model. Code-quality, hygiene, portability, or future-proofing items. |

## Status definitions

| Status | Meaning |
| --- | --- |
| **Open** | Active issue; remediation pending. |
| **In progress** | Fix is being implemented. |
| **Fixed** | Remediation merged. Commit hash recorded. |
| **Accepted** | Will not fix. Rationale recorded in the row's notes. |
| **Out of scope** | Lives in code or infrastructure outside this project's control (e.g. upstream `soroban-sdk`). Tracked for visibility only. |

---

## Finding registry

Rows written before VER-002 refer to the one-step `rotate_key`, which VER-002
replaced with `propose_key` / `accept_key` / `cancel_key`. Their text is kept
as it was when they were closed.

| ID | Title | Source | Severity | Status | Owner | Date opened | Date closed | Fix commit | Reference |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| **F-001** | UDIV in `hash_to_point` rejection-sampling reduction | CT analysis | Informational | **Fixed** | gnosed | 2026-05-05 | 2026-05-05 | `06318c1` | [`constant-time-analysis.md`](constant-time-analysis.md) |
| **S-001** | Unchecked `+` on `domain.len() + payload_array.len()` flagged as potential `usize` overflow | Scout | Informational | **Fixed** (false positive on threat — operands compile-time bounded; refactored to compile-time const + static-assert anyway) | gnosed | 2026-05-07 | 2026-05-07 | _pending commit_ | [`scout-scan.md`](scout-scan.md) §S-001 |
| **S-002** | `rotate_key` and `__constructor` mutate storage without emitting events | Scout | Informational | **Fixed** (added `falcon::init` / `falcon::rotate` events) | gnosed | 2026-05-07 | 2026-05-07 | _pending commit_ | [`scout-scan.md`](scout-scan.md) §S-002 |
| **V-001** | Three `unwrap()` calls on per-byte copy in `verify` path; smart-account had been hardened, verifier had not | Scout | Informational | **Fixed** (let-else returning `false` on `None`, matching smart-account's panic-free pattern) | gnosed | 2026-05-07 | 2026-05-07 | _pending commit_ | [`scout-scan.md`](scout-scan.md) §V-001 |
| **F-FP-1** | `dos_unbounded_operation` on size-bounded copy loops (smart-account + verifier) | Scout | Medium | **Accepted** as false positive — loop bounds enforced by upstream size gates that Scout cannot trace | gnosed | 2026-05-07 | — | — | [`scout-scan.md`](scout-scan.md) §F-FP-1 |
| **F-FP-2** | `soroban_version` enhancement claims latest is 26.0.0 (vs runtime 23.x) | Scout | Informational | **Accepted** — Scout tracks runtime/protocol version, not the SDK crate version | gnosed | 2026-05-07 | — | — | [`scout-scan.md`](scout-scan.md) §F-FP-2 |
| **F-FP-3** | `assert_violation` on the new `const _: () = assert!(...)` compile-time invariant | Scout | Informational | **Accepted** as false positive — const-context asserts run at compile time, never at runtime | gnosed | 2026-05-07 | — | — | [`scout-scan.md`](scout-scan.md) §F-FP-3 |
| **D-001** | `keccak 0.1.5` ARMv8-ASM unsoundness + yanked version (RUSTSEC-2026-0012) | cargo audit | Informational | **Fixed** | gnosed | 2026-05-05 | 2026-05-05 | `f37ac25` | [`dependency-and-lint-scan.md`](dependency-and-lint-scan.md) §3.2 |
| **D-002** | `derivative 2.2.0` unmaintained (RUSTSEC-2024-0388) | cargo audit | Informational | **Out of scope** | upstream | 2026-05-05 | — | — | [`dependency-and-lint-scan.md`](dependency-and-lint-scan.md) §3.1 |
| **D-003** | `paste 1.0.15` unmaintained (RUSTSEC-2024-0436) | cargo audit | Informational | **Out of scope** | upstream | 2026-05-05 | — | — | [`dependency-and-lint-scan.md`](dependency-and-lint-scan.md) §3.1 |
| **D-004** | `rand 0.8.5` unsound with custom logger (RUSTSEC-2026-0097) | cargo audit | Informational | **Out of scope** | upstream | 2026-05-05 | — | — | [`dependency-and-lint-scan.md`](dependency-and-lint-scan.md) §3.1 |
| **TM-002** | Key-rotation race: an attacker holding the current key can act before the rotation completes (originally: race a malicious tx into the same ledger as `rotate_key`; since VER-002, anything up to `accept_key`, including cancelling or replacing the proposal) | Threat model (Elevation.3) | Low | **Open** | TBD | 2026-05-05 | — | — | [`threat-model.md`](threat-model.md) Elevation.3.R.1 + §3 follow-up #1 |
| **TM-003** | Rotation entry points (`rotate_key`; since VER-002 `propose_key` / `cancel_key` / `accept_key`) not explicitly rate-limited; relies on per-call gas economics | Threat model (DoS.5) | Informational | **Accepted** | gnosed | 2026-05-05 | — | — | [`threat-model.md`](threat-model.md) DoS.5.R.1 + §3 follow-up #2 |
| **CI-001** | `cargo audit`, `cargo clippy`, and the constant-time scan run only manually via `make`; no CI gate to prevent regressions | Process | Informational | **Open** | TBD | 2026-05-05 | — | — | [`threat-model.md`](threat-model.md) §3 follow-up #3 |
| **SR-001** | `rotate_key` validated new-pubkey size before `require_auth`, exposing an unauthenticated probe oracle on pubkey-size handling | Self-review | Low | **Fixed** (reorder: `require_auth()` runs first, then size check; tests pin the ordering) | gnosed | 2026-05-11 | 2026-05-11 | _pending commit_ | smart-account/src/lib.rs:125-143 |
| **SR-002** | No integration test exercised `rotate_key`'s auth-routing dynamically; only the domain-separator constant was pinned | Self-review | Low | **Fixed** (added `test_rotate_key_succeeds_with_mocked_auth`, `_without_auth_fails`, `_bad_size_after_auth_returns_error`) | gnosed | 2026-05-11 | 2026-05-11 | _pending commit_ | smart-account/tests/integration.rs |
| **SR-003** | Instance-storage TTL never proactively extended in `__constructor` / `rotate_key`; relied entirely on Soroban auto-bump | Self-review | Low (defense in depth) | **Fixed** (calls `extend_ttl` after each pubkey write) | gnosed | 2026-05-11 | 2026-05-11 | _pending commit_ | smart-account/src/lib.rs:94, :135 |
| **SR-004** | Init / rotate events re-emitted the full 897-byte pubkey, bloating ledger metadata and linking the account's pubkey across the lifetime | Self-review | Informational | **Fixed** (events now publish `env.crypto().sha256(pubkey)` instead; full pubkey remains readable via `get_pubkey`) | gnosed | 2026-05-11 | 2026-05-11 | _pending commit_ | smart-account/src/lib.rs:98-100, :139-141 |
| **SR-005** | `get_pubkey` used `.expect("Public key not set")`, leaving a contract-side panic on an unreachable-but-existing path | Self-review | Informational | **Fixed** (returns `Result<Bytes, Error>` with `Error::PublicKeyMissing`) | gnosed | 2026-05-11 | 2026-05-11 | _pending commit_ | smart-account/src/lib.rs:111-116 |
| **SR-006** | `threat-model.md` `lib.rs:NN` cross-references were ~50 lines stale relative to current source, increasing auditor friction; `Elevation.2.R.1` described a runtime over-length check that no longer exists (replaced by compile-time `const _: () = assert!(...)`) | Self-review | Informational | **Fixed** (all line refs updated; Elevation.2.R.1 rewritten to cite the compile-time invariant; Elevation.1.R.1 updated to reflect SR-001 ordering) | gnosed | 2026-05-11 | 2026-05-11 | _pending commit_ | docs/audit/threat-model.md |
| **SR-007** | `verify.rs` header-byte gate comment was imprecise about Falcon spec §3.11.1 conventions for 0x2X / 0x3X / 0x5X | Self-review | Informational | **Fixed** (comment rewritten to cite the spec section and explain the two-layer CT defense) | gnosed | 2026-05-11 | 2026-05-11 | _pending commit_ | falcon-512-core/src/verify.rs:86-103 |
| **AUD-001** | Signature decoder tolerated zero-padding to *any* length in `(natural, 666]`, not just the fixed padded size — an unbounded-length malleability (distinct byte strings verifying for the same (pk,msg)) | Multi-agent audit (DEC-002) | Low | **Fixed** (enforce exact-length consumption: natural compressed `decoded_len == body.len()` **or** total length `== FALCON_512_SIG_PADDED_SIZE` (666) with zero tail; KAT still passes; new `test_arbitrary_padding_rejected` regression test) | gnosed | 2026-06-07 | 2026-06-07 | _pending commit_ | falcon-512-core/src/verify.rs (canonicity block); verifier `tests/kat.rs` |
| **AUD-002** | Header gate accepts both `0x2X` and `0x3X` high nibbles, and does not bind the nibble to body length — residual byte-level malleability | Multi-agent audit (DEC-001) | Low | **Superseded by VER-001** — the original "Accepted" rationale (interop with signers emitting `0x29`) was factually wrong; see VER-001. Fixed there by pinning the header to `0x39`. | gnosed | 2026-06-07 | 2026-08-24 | _pending commit_ | falcon-512-core/src/verify.rs |
| **VER-001** | Non-standard `0x29` detached Falcon signatures accepted: header gate treated `0x2X`/`0x3X` interchangeably, so flipping a valid signature's `0x39` header to `0x29` kept it valid (byte-level malleability, interop divergence from strict verifiers). Root cause: `0x29` is only the *nonce-less* tail header inside the NIST `crypto_sign` envelope — every conforming detached compressed/padded signer emits `0x39` (`0x59` = CT), so the "signers disagree" interop rationale in AUD-002 and the module docs was inaccurate; the KAT tests were creating the non-standard hybrid by preserving the envelope's `0x29` | Veridise audit, V-FSA-VUL-001 (PR #2, issue #1292) | Medium | **Fixed**, confirmed in Veridise report V2 (2026-09-10) (header pinned to exactly `0x39`; natural vs. 666-byte padded form still determined by decoder consumption + length; KAT conversion now rewrites `0x29`→`0x39` and asserts the envelope header; new `test_envelope_header_0x29_rejected` flips a valid header to `0x29`/`0x59`/others and asserts rejection; docs and web-demo comments corrected) | gnosed | 2026-08-19 | 2026-08-24 | `ec54f5c` | [`findings/VER-001-nonstandard-0x29-signatures.md`](findings/VER-001-nonstandard-0x29-signatures.md); falcon-512-core/src/verify.rs; verifier & smart-account `tests/kat.rs`; verifier `src/lib.rs`; web-demo/src/lib/falcon.ts; docs/audit/threat-model.md; docs/audit/ct-analysis/falcon_verify_standalone.rs |
| **AUD-003** | Format comments in `verify.rs` and `tests/kat.rs` were inaccurate/inverted (claimed `0x2X`=padded-fixed / KAT uses `0x39`); SR-007's earlier fix was incomplete. Empirically the official KAT uses `0x29` with *variable* length | Multi-agent audit (DEC-004) | Informational | **Fixed** (comments corrected against the measured KAT; supersedes SR-007) | gnosed | 2026-06-07 | 2026-06-07 | _pending commit_ | falcon-512-core/src/verify.rs:22-46, 86-100; verifier `tests/kat.rs` |
| **AUD-004** | README / optimization-report overclaimed "follows the NIST standard" and framed the scheme as "FIPS 206 / FN-DSA"; the code implements NIST **Round-3 Falcon-512**, which differs from draft FIPS 206 (domain-sep byte, context string, pubkey-hash binding) | Multi-agent audit (H2P-001) | Low | **Fixed** (README + report wording qualified to Round-3 Falcon, with an explicit FIPS-206 note) | gnosed | 2026-06-07 | 2026-06-07 | _pending commit_ | README.md; docs/audit/optimization-report.md |
| **AUD-005** | Contract wrappers copied `Bytes` inputs byte-by-byte via `Bytes::get(i)` (≈1,563 metered host calls for pubkey+sig), dominating verification cost | Multi-agent audit (DRS-3 / optimization) | Informational (perf) | **Fixed** (bulk `copy_into_slice` after length gate; **396,903 → 12,986 CPU instructions, 30.6×**; panic-free preserved) | gnosed | 2026-06-07 | 2026-06-07 | _pending commit_ | verifier & smart-account `src/lib.rs` |
| **AUD-006** | 16 KiB message stack buffer was undocumented and the worst-case (max-message) gas was unmeasured | Multi-agent audit (DRS-1 / DRS-2) | Low | **Fixed** (build-time `const` stack-budget assertion; added 16,384-byte worst-case benchmark = 15,033 CPU insns) | gnosed | 2026-06-07 | 2026-06-07 | _pending commit_ | verifier `src/lib.rs`, `tests/benchmark.rs` |
| **AUD-007** | At the Falcon primitive layer, `hash_to_point` omits the FN-DSA (FIPS 206) bindings: domain-separation byte, context string, and SHA-256(pubkey) absorbed into the challenge (key-binding / BUFF) | Multi-agent audit (H2P-002) | Informational | **Accepted / Roadmap** — implementation targets Round-3 Falcon; application-layer domain separation is supplied by the smart account. FN-DSA conformance tracked in the README Roadmap. | gnosed | 2026-06-07 | — | — | README.md (Roadmap); falcon-512-core/src/verify.rs:311-349 |
| **VER-004** | Undocumented NTT primitives representation invariants may cause incorrect computations | Veridise audit, V-FSA-VUL-004 (PR #5, issue #1289) | Warning (Veridise scale) | **Fixed**, confirmed in Veridise report V2 (2026-09-10) (documentation-only: module-level representation-invariants section in `ntt.rs` defining canonical range / field encoding / polynomial domain, plus per-function rustdoc contracts on all ten primitives, per the recommendation's enumeration; `field_halve`'s contract went away with the function in VER-005) | gnosed | 2026-08-18 | 2026-08-24 | `73b7a42` | [`findings/VER-004-ntt-representation-invariants.md`](findings/VER-004-ntt-representation-invariants.md); [PR #5](https://github.com/SoundnessLabs/stellar-pq/pull/5) |
| **VER-005** | Ten maintainability/documentation items: `hash_to_point` range check debug-only, unframed `nonce\|\|message` absorption undocumented, instance-storage footprint undocumented, duplicated `logn` local, undocumented defense-in-depth pubkey check, `decode_pubkey` partial-write contract undocumented, over-broad visibility of `verify_raw_512` + `ntt.rs` primitives, recomputed inverse-NTT scaling constant, dead `acc_len` check, deprecated `Events::publish` | Veridise audit, V-FSA-VUL-005 (PR #6, issue #1290) | Warning (≈ Informational) | **Fixed**, confirmed in Veridise report V2 (2026-09-10) (all ten items; item 1 as a checked `false` return so `__check_auth` stays panic-free; item 5 retained as documented defense-in-depth; item 7 makes `verify_raw_512` private and narrows `ntt.rs` to `pub(crate)`/private; item 8 adds `FALCON_512_NI = 128` with a compile-time derivation assert; item 10 migrates the events to `#[contractevent]` types with an unchanged wire shape: `FalconInit`, plus `FalconPropose` / `FalconAccept` / `FalconCancel` once merged with VER-002, which removed `rotate_key` and its `FalconRotate` event) | gnosed | 2026-08-18 | 2026-08-24 | `132b85f` | [`findings/VER-005-maintainability-and-documentation.md`](findings/VER-005-maintainability-and-documentation.md) |
| **VER-R1** | Report recommendation: extend inline documentation for arithmetic assumptions in `ntt.rs` — mathematical purpose, expected input range, representation, and output guarantees for each NTT/field helper, plus justification for constants that deviate from common Falcon conventions | Veridise audit (report §1, Recommendations) | Recommendation | **Done** — delivered by VER-004 (module-level "Representation invariants" section plus per-function pre/postconditions on all ten primitives). Every constant carries its derivation: `Q0I`, `R`, `R2`, `PHI`, `FALCON_512_NI`, and `MAX_SIG_COEFF`, the last two with compile-time assertions tying them to `Q`/`R` and `L2_BOUND_512`. | gnosed | 2026-08-19 | 2026-08-27 | `73b7a42` | falcon-512-core/src/ntt.rs; [`findings/VER-004-ntt-representation-invariants.md`](findings/VER-004-ntt-representation-invariants.md) |
| **VER-R2** | Report recommendation: encode field and polynomial representations in the type system — a field-element newtype always canonical mod Q, and distinct polynomial types per domain (coefficient/evaluation) and encoding (natural/Montgomery), so the compiler rejects representation mismatches | Veridise audit (report §1, Recommendations) | Recommendation | **Deferred — not implemented.** Deliberate: this rewrites the signature of every primitive in `ntt.rs` (9 functions, 5 scalar field params) and 10 array-typed signatures in `verify.rs`, i.e. the exact API surface VER-004 documented and VER-005 set visibility on. Landing it here would mean the merged branch no longer matches any branch the auditors verified, and a defect in the newtype's canonicalisation would be a cryptographic defect. The invariants it would enforce are, in the meantime, documented per function (VER-R1) and covered by exhaustive tests (VER-R3). Recommended as a separate post-sign-off workstream with its own review. | gnosed | 2026-08-19 | — | — | falcon-512-core/src/ntt.rs, src/verify.rs |
| **VER-R3** | Report recommendation: extend arithmetic and parser test coverage — exhaustive field-operation checks against an independent oracle, NTT round trips, comparison against an independent schoolbook negacyclic multiplication, regeneration of the Montgomery constants and twiddle tables from their definitions, and parser tests for malformed encodings | Veridise audit (report §1, Recommendations) | Recommendation | **Done** — `ntt.rs` gained a test module (12 tests, previously none): `field_add`/`field_sub`/`montgomery_mul` checked exhaustively over all `Q^2` = 151 M canonical pairs against a naive `%`-based oracle; `GMB`/`IGMB` regenerated entry by entry from `R·PHI^±brv9(i) mod Q` with `PHI = 49` verified a primitive 1024th root; `Q0I`/`R`/`R2`/`NI` re-derived; NTT round-trip identity; NTT product compared against an independent schoolbook negacyclic multiplication; canonicality asserted after every transformation. Parser coverage extended in `verify.rs` (16 tests): truncation at every byte length, nonzero unused padding bits, out-of-range public-key coefficients at several positions, wrong public-key lengths, alongside the existing negative-zero, 2047/2048-boundary, alternate-header, and malformed-padding cases. `field_halve` is not covered because VER-005 removed it as dead. Added after the Veridise review; tests only, the contract WASMs are byte-identical with and without it. | gnosed | 2026-08-19 | 2026-08-27 | `6a2e9f5` | falcon-512-core/src/ntt.rs (tests), src/verify.rs (tests) |
| **VER-002** | One-step `rotate_key` validated only pubkey length; a well-formed-but-wrong or corrupted key permanently bricks the account | Veridise audit, V-FSA-VUL-002 (PR #3, issue #1288) | Low | **Fixed**, confirmed in Veridise report V2 (2026-09-10) — `rotate_key` replaced by two-step `propose_key` / `accept_key` / `cancel_key`: propose (current-key auth first, then validate) validates full Falcon-512 well-formedness via `decode_pubkey` and stores pending; accept requires a proof-of-possession signature by the pending key over `ACCEPT_DOMAIN_SEPARATOR ‖ SHA-256(pending_pubkey)`, so an unpossessed key can never activate. Constructor gets the same well-formedness gate (DoS.6). `propose`/`accept`/`cancel` events per SR-004. 11 new integration tests plus deterministic falcon-wasm proof fixtures. | gnosed | 2026-08-18 | 2026-08-25 | `8c34429` | [`findings/VER-002-unsafe-key-rotation.md`](findings/VER-002-unsafe-key-rotation.md); smart-account `src/lib.rs`, `tests/integration.rs` |
| **VER-003** | Verifier input limits diverged from standard Falcon-512 encodings: message length capped at 16,384 bytes, `\|s₂\|` coefficients capped at 2,047 (a subset of mathematically valid vectors), signature length gated to `[42, 666]` where the spec-derived range is `[617, 752]` | Veridise audit, V-FSA-VUL-003 (PR #4, issue #1291) | Low | **Fixed**, confirmed in Veridise report V2 (2026-09-10) (limits aligned with the spec: `FALCON_SIG_MIN_SIZE` = 617, `FALCON_SIG_MAX_SIZE` = 752, coefficient cap re-derived from the norm bound as `⌊√L2_BOUND_512⌋` = 5,833 with compile-time asserts, message length uncapped via a streaming `Falcon512Verification` session hashing through a fixed 1,024-byte chunk buffer; padded canonicity still pinned to exactly 666; standard verify cost unchanged at 12,986 CPU insns; testnet/mainnet redeploy pending) | gnosed | 2026-08-19 | 2026-08-27 | `58101d6` | [`findings/VER-003-nonstandard-input-limits.md`](findings/VER-003-nonstandard-input-limits.md); falcon-512-core `src/lib.rs`, `src/verify.rs`; verifier `src/lib.rs`, `tests/`; docs/audit/threat-model.md, optimization-report.md, scout-scan.md, ct-analysis/falcon_verify_standalone.rs |

> **Multi-agent audit (2026-06-07).** A 6-dimension adversarial review (each
> finding cross-checked by 3 independent verifiers) examined the verification
> equation, `hash_to_point`, decoders/malleability, the Soroban surface, DoS/
> resource use, and optimization. It found **no Critical / High / Medium**
> issues. The core crypto was independently differential-tested against
> PQClean `falcon-512/clean` (L2 bound, NTT ring-multiply, `is_short`
> saturation, centering bijection). All confirmed findings were Low /
> Informational and are tracked as AUD-001..007 above.

---

## Detail — open items

### TM-002 — Key-rotation race

**What.** If the current Falcon key is compromised and the user issues
`rotate_key(new_pk)`, an attacker who still holds the old key can
submit a malicious authorization in the same ledger. Soroban orders
operations within a ledger by submission order/fee priority, so if the
attacker's tx is sequenced first, it lands before the rotation takes
effect. This is the standard race that affects every account-
abstraction contract supporting in-place key rotation.

VER-002 replaced `rotate_key` with `propose_key` / `accept_key` /
`cancel_key`. That stops a wrong key from being installed, but it does not
close this race: until `accept_key` lands, the compromised current key can
still authorize transactions, and it can also cancel or replace the
proposal. The window now spans two transactions instead of one.

**Plan.**

1. Decide whether to add a `pause()` / `unpause()` admin pair (also
   routed through `__check_auth`) so the operator can freeze the account
   before rotating, sequence-isolating the old key.
2. Alternatively, add a monotonic `key_version: u32` counter and bind
   it into the domain separator (`b"...v1" → b"...v1:N"`), invalidating
   all old-key signatures the moment a rotation lands. This is more
   invasive (changes the signing protocol).

**Why deferred.** The Veridise audit did not raise it as a finding: its
trust model treats a rotation as an operator action (§4.1) and recommends
rotating immediately after any suspected compromise (§4.2). It stays open
as a possible hardening item, to be revisited if another reviewer
considers it a finding for this contract class.

### TM-003 — Rotation spam

**What.** An attacker holding the current key can call `propose_key` or
`cancel_key` repeatedly (before VER-002, `rotate_key`), burning the
account's stored fees. There is no explicit rate limit at the contract
layer.

**Why accepted.** Each of those calls is a Soroban-authorized invocation
that costs gas to submit and consumes a nonce. An attacker holding the
current key can drain funds directly via a transfer; spamming the rotation
calls is strictly less attractive. `accept_key` can be submitted by anyone,
but without a valid proof from the pending key it fails without touching
storage, and the submitter pays for it. The Veridise audit did not flag
it; the row will be reopened if spam becomes a real concern.

### CI-001 — Continuous integration

**What.** All three of the self-service tooling scans (`cargo audit`,
`cargo clippy`, constant-time analysis) run via `make` targets. There
is no automated gate preventing a future commit from re-introducing the
F-001 UDIV, the keccak advisory, or a new clippy regression.

**Plan.**

1. Add `.github/workflows/audit.yml` that, on every PR and on `main`:
   - Runs `make test` for all three crates.
   - Runs `make audit-scan` and fails the job on any new advisory.
   - Runs `make ct-scan` and fails the job on any error-level finding.
2. Pin the rust toolchain via `rust-toolchain.toml` so CI and developer
   machines agree on the lowering rules behind the CT scan.

**Why deferred.** Hygiene rather than security; it did not block the
audit.

---

## Change log

| Date | Change |
| --- | --- |
| 2026-05-05 | Initial registry. F-001 + D-001 fixed in-commit. TM-001…003 + CI-001 opened. D-002…004 documented as upstream-tracked. |
| 2026-05-11 | TM-001 removed: frontends / off-chain signers (including `web-demo` and the vendored `falcon-wasm`) are out of audit scope per the updated threat model. Signer integrity is a wallet-grade concern owned by whichever frontend drives the contract. |
| 2026-05-11 | Self-review pass surfaced 7 findings (SR-001…007); all fixed pre-engagement. Tests added (`test_rotate_key_*`), `rotate_key` re-ordered (auth first), TTL bumps added, events emit pubkey hash instead of full pubkey, `get_pubkey` returns `Result`, threat-model line references refreshed, `verify.rs` header-gate comment cites Falcon spec §3.11.1. |
| 2026-08-24 | Audit-firm finding (PR #2) registered as VER-001 and fixed: detached signature header pinned to exactly `0x39`; `0x29` (NIST envelope nonce-less tail) no longer accepted. AUD-002 reopened — its "required for interop" acceptance rationale was wrong (all conforming signers emit `0x39` detached; verified against the project's own e2e receipts, which record `signature_header_byte: 0x39` for falcon-wasm's 666-byte padded output) — and closed as superseded by VER-001. |
| 2026-08-24 | VER-004 (Veridise #1289) fixed: `falcon-512-core/src/ntt.rs` gains a module-level "Representation invariants" section and rustdoc pre/postconditions on all ten NTT primitives. Documentation-only; no executable code changed. Lands via [PR #5](https://github.com/SoundnessLabs/stellar-pq/pull/5). |
| 2026-08-24 | VER-005 (Veridise #1290) fixed: all ten maintainability/documentation items implemented across `falcon-512-core` and the smart account. Notable decisions: release-build range check in `hash_to_point` implemented as a checked `false` return (panic-free `__check_auth` preserved); `__check_auth` pubkey-length check retained as documented defense-in-depth; `verify_raw_512` made private and `ntt.rs` narrowed to `pub(crate)`/private (`field_halve` deleted as dead after the `FALCON_512_NI` constant replaced the halving loop); `init`/`rotate` events migrated to `#[contractevent]` with an unchanged wire shape. Unit + KAT + `testutils` integration tests, clippy, and both WASM builds pass. |
| 2026-08-24 | VER-002 (Veridise #1288) fixed: `rotate_key` removed in favor of two-step `propose_key` / `accept_key` (pending-key proof of possession) / `cancel_key`; well-formedness gate on propose **and** constructor. Follow-up: TM-002 revisit + threat-model `rotate_key` references need a refresh pass. |
| 2026-08-27 | Audit-firm finding (#1291) registered as VER-003 and fixed: signature length range aligned to the spec-derived `[617, 752]`, coefficient magnitude cap re-derived from the norm bound (5,833), and the message length cap removed in favor of chunked streaming verification. Benchmarks, threat model, Scout rationale, and the CT-analysis standalone updated; unit + KAT + integration tests and both WASM builds pass. Testnet/mainnet redeploy of the rebuilt artifacts pending. |
| 2026-08-27 | Final pass over the merged branch against the full report. The three Executive-Summary recommendations are now tracked as VER-R1/R2/R3: R1 satisfied by VER-004, R3 implemented here (`ntt.rs` gained its first tests — exhaustive field arithmetic against a naive oracle, twiddle-table regeneration from `R·PHI^±brv9(i)`, NTT round trip, schoolbook cross-check; `verify.rs` gained truncation, unused-bit, and public-key coefficient parser tests), R2 (representation types) deliberately deferred with rationale. Also reconciled references the VER-003 streaming refactor had invalidated: `verify_raw_512` documented an `s2` range of `[-2047, 2047]` that the norm-derived cap replaced, and the constant-time standalone plus its report still named `hash_to_point`. The standalone is now byte-identical to the crate for every function the analysis reasons about. |
| 2026-10-02 | Veridise report V2 (2026-09-10) marks all five findings Fixed, each confirmed at its PR (V-FSA-VUL-001…005 ↔ VER-001…005 ↔ PRs #2, #3, #4, #5, #6); the report is now in [`reports/`](reports/). The five PR heads Veridise confirmed (`ec54f5c`, `8c34429`, `58101d6`, `73b7a42`, `132b85f`) are merged unchanged, so each VER row's fix commit is the audited one. VER-002 closed. TM-002/TM-003 and the threat model updated for two-step rotation (Tamper.2, DoS.5, DoS.6, Elevation.1, Elevation.3, data-flow diagram, line references). The merged code was checked against each audited head: every merge step builds and passes its tests; contract test snapshots and emitted events are byte-identical to the audited VER-002/VER-003 contracts; a differential run of about 12,000 signatures (the 100 NIST KAT vectors, falcon-wasm signatures over messages up to 100 KB, and mutations) shows the merged verifier accepts exactly what VER-003 accepts restricted to the `0x39` header; the constant-time scan passes on all eight cells. The READMEs, threat model, scan reports, and this log now describe the audit as complete, and code comments no longer reference the audit or its fixes. |
