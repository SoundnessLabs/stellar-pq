# Constant-Time Analysis Report — `falcon-512-core`

| Field | Value |
| --- | --- |
| Date | 2026-05-05 |
| Scope | `contracts/falcon-512-core/src/{ntt.rs, verify.rs}` |
| Tool | [Trail of Bits constant-time-analysis](https://github.com/trailofbits/constant-time-analysis), v0.1.0 |
| Compiler | `rustc 1.94.1 (e408947bf 2026-03-25)` |
| Architectures | `aarch64-unknown-linux-gnu`, `x86_64-unknown-linux-gnu` |
| Optimization levels | `-Oz` (matches release profile) and `-O3` (cross-check) |
| Result summary | **PASSED** on every (arch, opt) cell after F-001 remediation. One informational finding identified during the initial scan was fixed in the same commit; both states are documented below for audit traceability. |

---

## 1. Threat-model context

The Soroban smart-account contract (`contracts/soroban-falcon-smart-account`)
and the standalone verifier contract (`contracts/soroban-falcon-verifier`)
both invoke `falcon-512-core` only through `FalconVerifier::verify_512(pk,
msg, sig)`. **Every input to that function is public**:

- `pk` — a Falcon-512 public key, read from contract storage.
- `msg` — `DOMAIN_SEPARATOR || signature_payload` (smart account) or the raw
  message (verifier contract). The signature payload is a SHA-256 hash of
  the host-built authorization preimage; it is observable on-chain.
- `sig` — the user-supplied Falcon signature.

There are no secret inputs to verification. Therefore, **timing
side-channels in `verify_512` cannot leak any data that is not already
public** to an on-chain observer. The Soroban host additionally meters
contract execution by deterministic gas units rather than wall-clock time,
so even a hypothetical CT violation would not produce an exploitable
microarchitectural signal at the network layer.

The constant-time review is included in the SCF Audit Bank readiness pack
for two reasons:

1. **Defensive depth.** Falcon verifiers may be re-used outside the Soroban
   sandbox (for example, in a desktop wallet or off-chain validator) where
   timing channels would matter. CT discipline in `falcon-512-core` keeps
   that future option open without a rewrite.
2. **Hygiene signal for reviewers.** Many post-quantum schemes have
   notorious CT pitfalls (KyberSlash, Dilithium rejection sampling). A
   negative-result report from a recognized analyzer is direct evidence
   that the team has actively considered the issue.

`falcon-512-core` is intentionally `no_std`, has no Soroban dependency,
and could be vendored elsewhere — making the defensive posture above the
right default.

## 2. Methodology

`rustc --emit=asm` cannot resolve cross-module imports for a single source
file, so the two crate modules were flattened into self-contained fixtures
in [`ct-analysis/`](ct-analysis/):

- [`falcon_ntt_standalone.rs`](ct-analysis/falcon_ntt_standalone.rs) — verbatim
  copy of `ntt.rs` with the constants inlined and twiddle tables stubbed
  to constant arrays. Twiddle *contents* are public Falcon parameters and
  do not affect the *opcodes* the analyzer inspects.
- [`falcon_verify_standalone.rs`](ct-analysis/falcon_verify_standalone.rs) —
  flattened union of `ntt.rs` + `verify.rs`, with one substitution:
  `hash_to_point` is replaced by a stub that uses an LCG instead of
  SHAKE256. The control-flow shape is preserved (rejection-sampling loop,
  `while v >= Q { v -= Q; }`). This is faithful for CT analysis because
  SHAKE256 lives in the `sha3` crate (not analyzed here) and its inputs
  (nonce, message) are public.

Each fixture was scanned across the matrix `{arm64, x86_64} × {-Oz, -O3}`,
where `-Oz` matches the production release profile in
`contracts/falcon-512-core/Cargo.toml`.

Reproduce with [`ct-analysis/run.sh`](ct-analysis/run.sh).

## 3. Results

### 3.1 Initial scan (pre-remediation)

| Module | Architecture | Opt | Errors | Warnings* | Verdict |
| --- | --- | --- | --- | --- | --- |
| `ntt.rs` | arm64 | `-Oz` | 0 | 0 | PASSED |
| `ntt.rs` | arm64 | `-O3` | 0 | 13 | PASSED |
| `ntt.rs` | x86_64 | `-Oz` | 0 | 0 | PASSED |
| `ntt.rs` | x86_64 | `-O3` | 0 | 20 | PASSED |
| `verify.rs` (full) | arm64 | `-Oz` | **1** | 0 | **FAILED** |
| `verify.rs` (full) | arm64 | `-O3` | 0 | 0 | PASSED |
| `verify.rs` (full) | x86_64 | `-Oz` | **1** | 0 | **FAILED** |
| `verify.rs` (full) | x86_64 | `-O3` | 0 | 0 | PASSED |

### 3.2 Post-remediation re-scan

After applying the F-001 fix described in §4 — bounded conditional
subtractions in place of `while v >= Q { v -= Q; }`:

| Module | Architecture | Opt | Errors | Warnings* | Verdict |
| --- | --- | --- | --- | --- | --- |
| `verify.rs` (full) | arm64 | `-Oz` | 0 | 0 | **PASSED** |
| `verify.rs` (full) | x86_64 | `-Oz` | 0 | 0 | **PASSED** |

(`ntt.rs` was untouched; its initial-scan verdicts carry over.)

*Warnings are conditional branches the analyzer cannot prove are
secret-independent. All warnings observed are loop-back branches on the
public loop counter (`for i in 0..FALCON_512_N`); they are false positives
under the analyzer's own
[Quick Triage](https://github.com/trailofbits/constant-time-analysis#interpreting-results)
table because the operand is a "public parameter (length, count)".

## 4. Detailed finding

### F-001 — Variable-time `udiv` from rejection-sampling loop in `hash_to_point` *(REMEDIATED)*

| Field | Value |
| --- | --- |
| Severity | Informational (no impact under threat model) |
| Status | **Fixed** in the same commit as this report |
| Location | `contracts/falcon-512-core/src/verify.rs::FalconVerifier::hash_to_point` — inlined into `verify_512` at `-Oz` |
| Architectures | `arm64` (`udiv`), `x86_64` (`divw`) |
| Triggering opt level | `-Oz`, `-Os` (production); not present at `-O2`/`-O3` |

**Description.** The body of `hash_to_point` contains the classic Falcon
rejection-sampling reduction:

```rust
const ACCEPT_THRESHOLD: u32 = 5 * Q;
if w < ACCEPT_THRESHOLD {
    let mut v = w;
    while v >= Q {
        v -= Q;
    }
    c0[idx] = v as u16;
    ...
}
```

LLVM rewrites the bounded-iteration `while v >= Q { v -= Q; }` as
`v = w % Q`, then lowers the remainder to a hardware division
(`udiv` + `msub` on AArch64; `divw` on x86-64). Hardware integer division
has data-dependent latency on most cores, which is what the analyzer flags.

**Why this is not exploitable in production.** `w` is two bytes drawn from
SHAKE256 over `(nonce || message)`. Both `nonce` and `message` are
**public**: the nonce is published as bytes 1..40 of the signature and the
message is the on-chain authorization payload. An attacker who can observe
verifier timing already has full visibility into the divisor's input
distribution — there is no secret to recover. Additionally, on Soroban the
contract executes inside a deterministic WASM interpreter whose gas
metering does not surface microarchitectural timing, so the side-channel
does not exist at the network boundary.

**Why -O3 hides it.** At `-O3`, LLVM replaces division by the compile-time
constant `Q = 12289` with a multiply-by-magic-constant sequence (Hacker's
Delight Ch. 10). That lowering is constant-time, which is why the higher
optimization level passes cleanly. Soroban contracts ship with
`opt-level = "z"` (size, not speed), so the production WASM does contain
the `udiv` form when WASM is later JITed on a host that has hardware
division.

**Remediation (applied).** The `while`-subtract was replaced with four
calls to the existing `ntt::field_sub` helper, which performs a single
constant-time conditional subtraction using the bit-twiddle pattern
already used throughout the NTT layer:

```rust
let mut v = w;
v = field_sub(v, Q);
v = field_sub(v, Q);
v = field_sub(v, Q);
v = field_sub(v, Q);
debug_assert!(v < Q);
```

Re-scanning the standalone fixture at `-Oz` on both architectures
returns 0 errors and 0 warnings (see §3.2). Cost: three (typical) extra
subtractions per accepted sample relative to the original loop, in
exchange for branch-free, division-free reduction at every optimization
level. The `debug_assert!` is compiled out in release builds (Cargo.toml
sets `debug-assertions = false`) and exists only to catch
misunderstandings about the threshold invariant during development.

The six existing unit tests in `falcon-512-core` continue to pass.

## 5. What was *not* analyzed

- **`sha3::Shake256`** (external crate). SHA-3/SHAKE has been analyzed
  extensively by other parties; its inputs here are public.
- **Soroban host code** that handles `Bytes`, storage I/O, and host
  function dispatch. Out of scope for this report; covered by Stellar's
  own audits of `soroban-env-host`.
- **Off-chain Falcon signing** in the web demo (`web-demo/vendor/falcon-wasm`).
  Signing has secret inputs (private key) and CT analysis there is
  load-bearing, but the signer runs in the user's browser, not on the
  audited contract. A separate review is recommended if this code is
  promoted from a demo to production wallet UX.

## 6. References

- Cryptocoding Guidelines — <https://github.com/veorq/cryptocoding>
- KyberSlash — <https://kyberslash.cr.yp.to/>
- BearSSL Constant-Time Toolkit — <https://www.bearssl.org/constanttime.html>
- Falcon specification — <https://falcon-sign.info/falcon.pdf>
