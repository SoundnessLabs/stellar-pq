# Vulnerability Remediation Log

| | |
| --- | --- |
| Project | `stellar-pq` — Falcon-512 smart account on Stellar Soroban |
| Last updated | 2026-08-24 (audit-firm finding EXT-001 fixed; AUD-002 reopened and superseded) |
| Scope | Issues identified by self-review, threat modeling, constant-time analysis, dependency audit, clippy lints, and a multi-agent adversarial audit (2026-06-07). Pre-engagement findings only — findings produced by the audit firm during the engagement will be tracked in this same file as they are reported. |
| Standing commitment | Per the Stellar SCF Audit Bank initial-audit terms, all critical, high, and medium severity findings produced by the audit firm will be addressed within 20 business days of the report's delivery, with this log updated to reflect each fix. |

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
| **TM-002** | Key-rotation race: an attacker holding the current key can race a malicious tx into the same ledger as `rotate_key` | Threat model (Elevation.3) | Low | **Open** | TBD | 2026-05-05 | — | — | [`threat-model.md`](threat-model.md) Elevation.3.R.1 + §3 follow-up #2 |
| **TM-003** | `rotate_key` spam not explicitly rate-limited; relies on per-call gas economics | Threat model (DoS.5) | Informational | **Accepted** | gnosed | 2026-05-05 | — | — | [`threat-model.md`](threat-model.md) DoS.5.R.1 + §3 follow-up #3 |
| **CI-001** | `cargo audit`, `cargo clippy`, and the constant-time scan run only manually via `make`; no CI gate to prevent regressions | Process | Informational | **Open** | TBD | 2026-05-05 | — | — | [`threat-model.md`](threat-model.md) §3 follow-up #4 |
| **SR-001** | `rotate_key` validated new-pubkey size before `require_auth`, exposing an unauthenticated probe oracle on pubkey-size handling | Self-review | Low | **Fixed** (reorder: `require_auth()` runs first, then size check; tests pin the ordering) | gnosed | 2026-05-11 | 2026-05-11 | _pending commit_ | smart-account/src/lib.rs:125-143 |
| **SR-002** | No integration test exercised `rotate_key`'s auth-routing dynamically; only the domain-separator constant was pinned | Self-review | Low | **Fixed** (added `test_rotate_key_succeeds_with_mocked_auth`, `_without_auth_fails`, `_bad_size_after_auth_returns_error`) | gnosed | 2026-05-11 | 2026-05-11 | _pending commit_ | smart-account/tests/integration.rs |
| **SR-003** | Instance-storage TTL never proactively extended in `__constructor` / `rotate_key`; relied entirely on Soroban auto-bump | Self-review | Low (defense in depth) | **Fixed** (calls `extend_ttl` after each pubkey write) | gnosed | 2026-05-11 | 2026-05-11 | _pending commit_ | smart-account/src/lib.rs:94, :135 |
| **SR-004** | Init / rotate events re-emitted the full 897-byte pubkey, bloating ledger metadata and linking the account's pubkey across the lifetime | Self-review | Informational | **Fixed** (events now publish `env.crypto().sha256(pubkey)` instead; full pubkey remains readable via `get_pubkey`) | gnosed | 2026-05-11 | 2026-05-11 | _pending commit_ | smart-account/src/lib.rs:98-100, :139-141 |
| **SR-005** | `get_pubkey` used `.expect("Public key not set")`, leaving a contract-side panic on an unreachable-but-existing path | Self-review | Informational | **Fixed** (returns `Result<Bytes, Error>` with `Error::PublicKeyMissing`) | gnosed | 2026-05-11 | 2026-05-11 | _pending commit_ | smart-account/src/lib.rs:111-116 |
| **SR-006** | `threat-model.md` `lib.rs:NN` cross-references were ~50 lines stale relative to current source, increasing auditor friction; `Elevation.2.R.1` described a runtime over-length check that no longer exists (replaced by compile-time `const _: () = assert!(...)`) | Self-review | Informational | **Fixed** (all line refs updated; Elevation.2.R.1 rewritten to cite the compile-time invariant; Elevation.1.R.1 updated to reflect SR-001 ordering) | gnosed | 2026-05-11 | 2026-05-11 | _pending commit_ | docs/audit/threat-model.md |
| **SR-007** | `verify.rs` header-byte gate comment was imprecise about Falcon spec §3.11.1 conventions for 0x2X / 0x3X / 0x5X | Self-review | Informational | **Fixed** (comment rewritten to cite the spec section and explain the two-layer CT defense) | gnosed | 2026-05-11 | 2026-05-11 | _pending commit_ | falcon-512-core/src/verify.rs:86-103 |
| **AUD-001** | Signature decoder tolerated zero-padding to *any* length in `(natural, 666]`, not just the fixed padded size — an unbounded-length malleability (distinct byte strings verifying for the same (pk,msg)) | Multi-agent audit (DEC-002) | Low | **Fixed** (enforce exact-length consumption: natural compressed `decoded_len == body.len()` **or** total length `== FALCON_512_SIG_PADDED_SIZE` (666) with zero tail; KAT still passes; new `test_dec002_arbitrary_padding_rejected` regression test) | gnosed | 2026-06-07 | 2026-06-07 | _pending commit_ | falcon-512-core/src/verify.rs (canonicity block); verifier `tests/kat.rs` |
| **AUD-002** | Header gate accepts both `0x2X` and `0x3X` high nibbles, and does not bind the nibble to body length — residual byte-level malleability | Multi-agent audit (DEC-001) | Low | **Superseded by EXT-001** — the original "Accepted" rationale (interop with signers emitting `0x29`) was factually wrong; see EXT-001. Fixed there by pinning the header to `0x39`. | gnosed | 2026-06-07 | 2026-08-24 | _pending commit_ | falcon-512-core/src/verify.rs |
| **EXT-001** | Non-standard `0x29` detached Falcon signatures accepted: header gate treated `0x2X`/`0x3X` interchangeably, so flipping a valid signature's `0x39` header to `0x29` kept it valid (byte-level malleability, interop divergence from strict verifiers). Root cause: `0x29` is only the *nonce-less* tail header inside the NIST `crypto_sign` envelope — every conforming detached compressed/padded signer emits `0x39` (`0x59` = CT), so the "signers disagree" interop rationale in AUD-002 and the module docs was inaccurate; the KAT tests were creating the non-standard hybrid by preserving the envelope's `0x29` | Audit firm (PR #2) | Low | **Fixed** (header pinned to exactly `0x39`; natural vs. 666-byte padded form still determined by decoder consumption + length; KAT conversion now rewrites `0x29`→`0x39` and asserts the envelope header; new `test_envelope_header_0x29_rejected` flips a valid header to `0x29`/`0x59`/others and asserts rejection; docs and web-demo comments corrected) | gnosed | 2026-08-24 | 2026-08-24 | _pending commit_ | falcon-512-core/src/verify.rs; verifier & smart-account `tests/kat.rs`; verifier `src/lib.rs`; web-demo/src/lib/falcon.ts; docs/audit/threat-model.md; docs/audit/ct-analysis/falcon_verify_standalone.rs |
| **AUD-003** | Format comments in `verify.rs` and `tests/kat.rs` were inaccurate/inverted (claimed `0x2X`=padded-fixed / KAT uses `0x39`); SR-007's earlier fix was incomplete. Empirically the official KAT uses `0x29` with *variable* length | Multi-agent audit (DEC-004) | Informational | **Fixed** (comments corrected against the measured KAT; supersedes SR-007) | gnosed | 2026-06-07 | 2026-06-07 | _pending commit_ | falcon-512-core/src/verify.rs:22-46, 86-100; verifier `tests/kat.rs` |
| **AUD-004** | README / optimization-report overclaimed "follows the NIST standard" and framed the scheme as "FIPS 206 / FN-DSA"; the code implements NIST **Round-3 Falcon-512**, which differs from draft FIPS 206 (domain-sep byte, context string, pubkey-hash binding) | Multi-agent audit (H2P-001) | Low | **Fixed** (README + report wording qualified to Round-3 Falcon, with an explicit FIPS-206 note) | gnosed | 2026-06-07 | 2026-06-07 | _pending commit_ | README.md; docs/audit/optimization-report.md |
| **AUD-005** | Contract wrappers copied `Bytes` inputs byte-by-byte via `Bytes::get(i)` (≈1,563 metered host calls for pubkey+sig), dominating verification cost | Multi-agent audit (DRS-3 / optimization) | Informational (perf) | **Fixed** (bulk `copy_into_slice` after length gate; **396,903 → 12,986 CPU instructions, 30.6×**; panic-free preserved) | gnosed | 2026-06-07 | 2026-06-07 | _pending commit_ | verifier & smart-account `src/lib.rs` |
| **AUD-006** | 16 KiB message stack buffer was undocumented and the worst-case (max-message) gas was unmeasured | Multi-agent audit (DRS-1 / DRS-2) | Low | **Fixed** (build-time `const` stack-budget assertion; added 16,384-byte worst-case benchmark = 15,033 CPU insns) | gnosed | 2026-06-07 | 2026-06-07 | _pending commit_ | verifier `src/lib.rs`, `tests/benchmark.rs` |
| **AUD-007** | At the Falcon primitive layer, `hash_to_point` omits the FN-DSA (FIPS 206) bindings: domain-separation byte, context string, and SHA-256(pubkey) absorbed into the challenge (key-binding / BUFF) | Multi-agent audit (H2P-002) | Informational | **Accepted / Roadmap** — implementation targets Round-3 Falcon; application-layer domain separation is supplied by the smart account. FN-DSA conformance tracked in the README Roadmap. | gnosed | 2026-06-07 | — | — | README.md (Roadmap); falcon-512-core/src/verify.rs:311-349 |

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

**Plan.**

1. Decide with the audit firm whether to add a `pause()` / `unpause()`
   admin pair (also routed through `__check_auth`) so the operator can
   freeze the account before rotating, sequence-isolating the old key.
2. Alternatively, add a monotonic `key_version: u32` counter and bind
   it into the domain separator (`b"...v1" → b"...v1:N"`), invalidating
   all old-key signatures the moment a rotation lands. This is more
   invasive (changes the signing protocol).

**Why deferred.** Decision depends on the firm's scoping advice and
whether other reviewers consider it a finding for this contract class.

### TM-003 — `rotate_key` spam

**What.** An attacker holding the current key can call `rotate_key`
repeatedly, burning the account's stored fees. There is no explicit
rate limit at the contract layer.

**Why accepted.** Each call is itself a Soroban-authorized invocation
that costs gas to submit and consumes a nonce. An attacker holding the
current key can drain funds directly via a transfer; spamming
`rotate_key` is strictly less attractive. If the audit firm flags it
as a real concern, this row will be reopened.

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

**Why deferred.** Hygiene rather than security; not blocking submission.

---

## Change log

| Date | Change |
| --- | --- |
| 2026-05-05 | Initial registry. F-001 + D-001 fixed in-commit. TM-001…003 + CI-001 opened. D-002…004 documented as upstream-tracked. |
| 2026-05-11 | TM-001 removed: frontends / off-chain signers (including `web-demo` and the vendored `falcon-wasm`) are out of audit scope per the updated threat model. Signer integrity is a wallet-grade concern owned by whichever frontend drives the contract. |
| 2026-05-11 | Self-review pass surfaced 7 findings (SR-001…007); all fixed pre-engagement. Tests added (`test_rotate_key_*`), `rotate_key` re-ordered (auth first), TTL bumps added, events emit pubkey hash instead of full pubkey, `get_pubkey` returns `Result`, threat-model line references refreshed, `verify.rs` header-gate comment cites Falcon spec §3.11.1. |
| 2026-08-24 | Audit-firm finding (PR #2) registered as EXT-001 and fixed: detached signature header pinned to exactly `0x39`; `0x29` (NIST envelope nonce-less tail) no longer accepted. AUD-002 reopened — its "required for interop" acceptance rationale was wrong (all conforming signers emit `0x39` detached; verified against the project's own e2e receipts, which record `signature_header_byte: 0x39` for falcon-wasm's 666-byte padded output) — and closed as superseded by EXT-001. |
