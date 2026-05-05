# Dependency & Lint Scan Report

| Field | Value |
| --- | --- |
| Date | 2026-05-05 |
| Scope | `contracts/falcon-512-core`, `contracts/soroban-falcon-smart-account`, `contracts/soroban-falcon-verifier` |
| Tools | `cargo audit 0.22.1`, `cargo clippy 0.1.94` |
| Toolchain | `cargo 1.94.1 (29ea6fb6a 2026-03-24)`, `rustc 1.94.1 (e408947bf 2026-03-25)` |
| Advisory DB | `RustSec/advisory-db.git`, 1067 advisories loaded |
| Result | **No security-relevant clippy findings.** Three transitive `cargo audit` advisories surfaced; all upstream issues in `soroban-sdk` / arkworks dep tree, not exploitable in this codebase. One initially-flagged `keccak 0.1.5` advisory was remediated in the same commit by a lockfile bump. |

---

## 1. Methodology

Each crate was scanned independently with its own `Cargo.lock`:

```bash
cd contracts/<crate> && cargo clippy --release --all-targets
cd contracts/<crate> && cargo audit
```

Raw outputs are committed alongside this report under
[`dep-scan/`](dep-scan/). Reproduce with [`dep-scan/run.sh`](dep-scan/run.sh).

`cargo clippy` was deliberately run **without** `-D warnings` so the
report captures every signal — including stylistic ones the team may
choose to keep. A separate triage section below distinguishes
security-relevant lints from stylistic ones.

## 2. `cargo clippy` results

| Crate | Errors | Warnings | Categories |
| --- | --- | --- | --- |
| `falcon-512-core` | 0 | 5 | 4× `needless_range_loop`, 1× `unnecessary_cast` |
| `soroban-falcon-verifier` | 0 | 4 | 1× `manual_range_contains`, 3× `needless_range_loop` |
| `soroban-falcon-smart-account` | 0 | 3 | 1× `manual_range_contains`, 3× `needless_range_loop`* |

*`soroban-falcon-smart-account` initially also reported 4 raw warnings; one is a duplicate from the test target.

**No security-relevant lints fired.** The scan included the categories that
typically flag real bugs in cryptographic code:

| Lint category | Hits | Rationale |
| --- | --- | --- |
| `clippy::cast_possible_truncation` | 0 | No lossy `as` casts on secret-derived values |
| `clippy::indexing_slicing` | 0 | Bounds-checked or constant-bound indexing only |
| `clippy::integer_arithmetic` | 0 | Wrapping/checked arithmetic used where appropriate |
| `clippy::unwrap_used`, `clippy::expect_used` | 0 (in entry points) | `__check_auth` and verifier paths use `?` rather than `unwrap`/`expect` (see commit `133334e`) |
| `clippy::panic` | 0 (in runtime paths) | Constructors panic on bad input; runtime entry points return `Error` enums |

All raised warnings are stylistic / refactor suggestions:

- **`needless_range_loop`** (10 hits): clippy suggests rewriting indexed
  `for i in 0..N { a[i] = ... }` loops as iterator chains. In NTT inner
  loops and fixed-size byte copies (`pk_bytes`, `sig_bytes`), the
  index-by-`i` form is the documented Falcon reference style; rewriting
  with `iter_mut().enumerate().take(N)` does not change codegen and
  reduces readability against the spec. Keeping as-is.
- **`unnecessary_cast`** (1 hit, `verify.rs:268`): `(b & 127) as u32`
  where `b` is already `u32`. Trivially fixable; tracked as a non-blocking
  cleanup.
- **`manual_range_contains`** (2 hits): `len < MIN || len > MAX` vs.
  `!(MIN..=MAX).contains(&len)`. The explicit form is arguably clearer
  for size validation in security-sensitive entry points; keeping as-is.

The `needless_range_loop` style choice should be documented in
`CLAUDE.md` (or equivalent) so an audit firm reviewing the codebase does
not raise it as a finding. Suggested follow-up: add a `#[allow(...)]`
crate-level attribute with a rationale comment, or drop the lint via
`clippy.toml`.

## 3. `cargo audit` results

| Crate | Total deps | Advisories surfaced | Notes |
| --- | --- | --- | --- |
| `falcon-512-core` | 11 | **0** | Standalone `no_std` core; minimal surface (`sha3` only). |
| `soroban-falcon-smart-account` | 182 | 3 | All transitive via `soroban-sdk` / arkworks. |
| `soroban-falcon-verifier` | 182 | 3 | Same three; previously had a 4th (`keccak 0.1.5`) — see §3.2. |

### 3.1 Advisory triage (current state)

#### A-001 — `derivative 2.2.0` is unmaintained ([RUSTSEC-2024-0388](https://rustsec.org/advisories/RUSTSEC-2024-0388))

- **Type:** Maintenance status, not a vulnerability.
- **Reach:** Compile-time only — `derivative` is a proc-macro used by
  `ark-poly`, `ark-ec`, `ark-ff`. None of its expanded code runs at
  runtime in either the host process or the deployed WASM.
- **Owned by:** Upstream (`arkworks-rs`).
- **Action:** None required from this project. Will resolve when
  `soroban-env-host` upgrades its arkworks pin.

#### A-002 — `paste 1.0.15` is unmaintained ([RUSTSEC-2024-0436](https://rustsec.org/advisories/RUSTSEC-2024-0436))

- **Type:** Maintenance status.
- **Reach:** Compile-time only — proc-macro used by `wasmi_core`
  (host-side WASM runtime, not deployed) and `ark-ff`.
- **Owned by:** Upstream (`soroban-wasmi`, `arkworks-rs`).
- **Action:** None required from this project.

#### A-003 — `rand 0.8.5` unsound with custom logger ([RUSTSEC-2026-0097](https://rustsec.org/advisories/RUSTSEC-2026-0097))

- **Type:** Soundness, narrow trigger condition.
- **Trigger:** Code that installs a custom logger and then calls
  `rand::rng()`. Neither contract installs a custom logger, nor does
  either call `rand::rng()`. The dep is pulled in by `soroban-sdk` and
  `ark-std` as a test/utility dependency; it is not invoked from any
  contract entry point.
- **Reach:** Not exploitable in this codebase under the documented
  trigger.
- **Owned by:** Upstream (`rand-rs`); `soroban-sdk` will pick up the
  fix when it bumps `rand`.
- **Action:** None required.

### 3.2 Remediation applied — keccak 0.1.5 → 0.1.6

The verifier's `Cargo.lock` initially pinned `keccak 0.1.5`, which is
both yanked and the subject of [RUSTSEC-2026-0012](https://rustsec.org/advisories/RUSTSEC-2026-0012)
("Unsoundness in opt-in ARMv8 assembly backend for `keccak`"). The
unsound code path is gated by an opt-in feature flag and is unreachable
from the WASM target, so the practical exposure was nil — but the
finding showed up as an avoidable advisory.

Fix: `cargo update -p keccak` in `contracts/soroban-falcon-verifier/`,
which bumps the entry to `0.1.6` (still semver-compatible; no
`Cargo.toml` change). The smart-account lockfile already had `0.1.6`.

After remediation: both lockfiles agree on `keccak 0.1.6`, and re-running
`cargo audit` no longer surfaces the keccak advisory.

## 4. Summary verdict

- **Code quality:** Clean for security purposes. Stylistic clippy
  warnings are intentional design choices (NTT loop indexing, explicit
  range checks).
- **Dependency hygiene:** No exploitable vulnerabilities. All three
  remaining `cargo audit` warnings are upstream maintenance issues that
  will be cleared when `soroban-sdk` rolls forward its pinned deps.
  None are reachable in our usage.
- **Recommended cadence:** Re-run this scan whenever `soroban-sdk` is
  bumped, when `rust-toolchain.toml` changes, or quarterly — whichever
  is sooner. CI integration is a sensible follow-up.

## 5. Optional follow-ups (non-blocking)

1. Trivial `unnecessary_cast` cleanup in `verify.rs:268`.
2. Add a `clippy.toml` or crate-level `#![allow(clippy::needless_range_loop)]`
   with a rationale comment so the warning does not recur on every scan.
3. Wire `cargo audit` and `cargo clippy --all-targets` into CI as
   non-blocking jobs; switch them to blocking once stylistic lints are
   suppressed and the upstream advisories clear.
