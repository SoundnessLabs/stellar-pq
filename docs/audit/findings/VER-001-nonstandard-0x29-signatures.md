# VER-001 — Non-standard `0x29` detached Falcon signatures are accepted

| | |
| --- | --- |
| Finding ID | **VER-001** |
| Veridise issue | **#1292** |
| Source | Veridise audit report |
| Severity | **Medium** |
| Likelihood | Likely |
| Impact | Bad |
| Reported | 2026-08-19 |
| Status | **Fixed** — remediated on `claude/falcon-signature-headers-9xo65t` (pending merge to `main`) |
| Owner | gnosed |
| Affects | [`contracts/falcon-512-core/src/verify.rs`](../../../contracts/falcon-512-core/src/verify.rs) (header gate + module docs), verifier and smart-account `tests/kat.rs` |
| Supersedes | **AUD-002** (previously closed as _Accepted — required for interop_; see note below) |
| Related | **AUD-003** (format comments corrected), **AUD-001** (padding canonicity) |

> **Tracking stub.** This document records the finding and the agreed
> remediation. No code change landed in the PR that introduced it (PR #2);
> the fix branch this document was merged into implements the full
> remediation below.

## Finding as reported

### Description

The verifier accepts both `0x29` and `0x39` as headers for the same detached
signature layout:

```
header || nonce[40] || compressed(s₂)
```

After checking that the high nibble is either `0x2X` or `0x3X`, the verifier
always extracts bytes 1–40 as the nonce and invokes the compressed polynomial
decoder. The selected header family therefore has no effect on framing or
decoding.

This conflates two distinct formats defined by Falcon:

- `0x39` identifies a Falcon-512 compressed signature containing the nonce.
  Both natural-length and 666-byte padded signatures use this header.
- `0x59` identifies the alternate fixed-width/constant-time encoding and
  requires a different decoder.
- `0x29` is used only for the nonce-less signature tail inside the NIST
  `crypto_sign` signed-message envelope.

Consequently, the local representation `0x29 || nonce || compressed(s₂)` is a
non-standard hybrid format.

The comments claiming that signers disagree about the meanings of these nibbles
are inaccurate. The Falcon specification, reference C implementation, PQClean,
and the Python signer agree on the relevant conventions:

- Detached compressed and padded Falcon-512 signatures use `0x39`.
- The CT/fixed-width representation uses `0x59`.
- `0x29` belongs to the nonce-less tail of the NIST signed-message envelope.

The KAT tests currently create the non-standard hybrid by extracting the nonce
from the NIST envelope while preserving its `0x29` nonce-less header. A correct
conversion to detached form would replace `0x29` with `0x39`.

### Impact

An attacker can change the first byte of a valid `0x39` signature to `0x29`
without invalidating it. This produces multiple accepted byte encodings for the
same signature and message.

This does not appear to enable a signature over a new message or public key.
However, it has the following consequences:

- The verifier accepts signatures that do not conform to either defined Falcon
  framing.
- Signature bytes are malleable, which can affect systems that hash, identify,
  deduplicate, cache, or route signatures using their serialized
  representation.
- The permissive behavior can cause interoperability differences with strict
  Falcon implementations, whose detached verifiers reject `0x29`.
- It creates ambiguity for future format dispatch, particularly if support for
  the `0x59` fixed-width encoding is added.
- Documentation incorrectly treats the behavior as necessary for signer
  interoperability.

### Recommendation

Require `0x39` for every compressed detached Falcon-512 signature:

```rust
if signature[0] != 0x39 {
    return false;
}
```

Continue determining natural versus padded compressed form from decoder
consumption and length:

- Accept exact consumption for a natural-length compressed signature.
- Accept trailing zeros only when the total signature length is exactly 666
  bytes.
- Do not use `0x29` to identify padded signatures; padded signatures also use
  `0x39`.

## Planned remediation

- [x] Replace the `fmt != 0x20 && fmt != 0x30` gate in `verify_512` with a
      strict `signature[0] != 0x39` rejection.
      (`verify_512` now pins `FALCON_512_SIG_HEADER = 0x30 | logn` = `0x39`.)
- [x] Rewrite the module-level "Accepted signature formats" docs in
      `verify.rs`, which currently assert the opposite of the spec.
- [x] Rewrite the Step-2 header-gate comment in `verify_512` for the same
      reason.
- [x] Update the KAT harness to rewrite `0x29` → `0x39` when converting a NIST
      signed-message envelope into detached form, instead of preserving the
      envelope's nonce-less header. (Both the verifier and smart-account KAT
      suites now assert the envelope header is `0x29` and emit `0x39`; all
      100 vectors pass.)
- [x] Add a regression test asserting a `0x29`-headed signature is rejected
      while its `0x39` twin verifies.
      (`test_envelope_header_0x29_rejected` in the verifier KAT suite also
      rejects `0x59`/`0x31`/`0x38`; a core unit test covers the gate.)
- [x] Re-close **AUD-002** in [`remediation-log.md`](../remediation-log.md)
      with a corrected rationale, and add a **VER-001** row.

## Developers response

Confirmed and fixed as recommended. The header gate now requires exactly
`0x39`; natural vs. 666-byte padded form is still decided by decoder
consumption and total length, with a zero-only tail accepted solely at the
fixed 666-byte size. The incorrect "signers disagree" interop rationale was
retracted in the module docs, KAT comments, web-demo comments, threat model,
and remediation log (AUD-002 closed as superseded by VER-001). The CT-analysis
standalone copy was updated to match the new gate.

## Repository notes

**This finding overturns AUD-002.** The multi-agent audit of 2026-06-07 closed
the identical issue as _"Accepted — accepting both nibbles is **required for
interop**"_, on the stated grounds that "PQClean/falcon-wasm emit `0x39`
compressed and `0x29` padded". That premise was checked directly against this
repository's own signers on 2026-08-12 and does not hold:

- `web-demo/vendor/falcon-wasm`: `sign()` emits `0x39` at natural length
  (~654–658 B); `signPadded()` emits `0x39` at exactly 666 B with a zero tail.
  **It never emits `0x29`.**
- Both committed e2e receipts record `signature_header_byte: 0x39`.
- `falcon.py` uses `0x30 + logn` → `0x39`.
- PQClean's `0x3X` vs `0x2X` split is *detached API vs NIST signed-message
  API*, not compressed vs padded; `falcon-padded-512/clean` also uses
  `0x30 + 9`.

Falcon spec §3.11.3 fixes the header as `0cc1nnnn` with the 4th bit set, making
`0x39` (compressed) and `0x59` (CT) the only valid standalone headers. `0x29`
exists solely inside the §3.11.6 signed-message container that the KAT `.rsp`
vectors carry.

The practical consequence: **no signer in this system produces `0x29`**, so
narrowing the gate to `0x39` costs nothing in production and removes the
malleability set. The only consumer that depends on `0x29` today is the KAT
harness itself, which is the thing the finding asks us to fix.
