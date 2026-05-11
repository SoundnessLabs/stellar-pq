# Vulnerability Remediation Log

| | |
| --- | --- |
| Project | `stellar-pq` — Falcon-512 smart account on Stellar Soroban |
| Last updated | 2026-05-11 |
| Scope | Issues identified by self-review, threat modeling, constant-time analysis, dependency audit, and clippy lints. Pre-engagement findings only — findings produced by the audit firm during the engagement will be tracked in this same file as they are reported. |
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
