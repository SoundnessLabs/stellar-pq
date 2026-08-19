# VER-004 — Undocumented NTT primitives representation invariants may cause incorrect computations

| | |
| --- | --- |
| Finding ID | **VER-004** |
| Veridise issue | **#1289** |
| Source | Veridise audit report |
| Severity | **Warning** |
| Likelihood | Not Likely |
| Impact | Bad |
| Reported | 2026-08-18 |
| Status | **Open** — remediation not yet implemented |
| Owner | TBD |
| Affects | [`contracts/falcon-512-core/src/ntt.rs`](../../../contracts/falcon-512-core/src/ntt.rs) |
| Related | **VER-005** items 7 and 8 (visibility narrowing and the `ni` constant, same file) |

> **Tracking stub.** This document records the finding and the agreed
> remediation. No code change lands in this PR.

## Finding as reported

### Description

The NTT implementation represents field elements as `u32` values in scalar
helpers and as `u16` values in polynomial arrays. A field element has multiple
integer representatives congruent modulo Q, while its canonical representative
lies in `[0, Q)`. The implementation also uses two polynomial domains:
coefficient and evaluation and two field encodings: natural and Montgomery.

Most primitives in `ntt.rs` rely on specific range, domain, and encoding
invariants. When these preconditions hold, the functions produce correct
canonical outputs in the documented domain and encoding. These preconditions are
not documented consistently.

### Impact

Non-canonical inputs may violate arithmetic bounds, resulting in overflow,
incorrect values, or non-canonical outputs. Likewise, passing a polynomial in
the wrong domain or Montgomery representation may produce values that are valid
field elements but do not represent the intended computation. Future refactors
or code reuse could therefore pass values with an unsupported range, domain, or
encoding. Such misuse can potentially lead to erroneous verification decisions.

### Recommendation

For each of the functions document the conditions on the inputs and the
resulting guarantees on the result in precisely. The following functions should
clearly document their input and output invariants:

1. `field_add()` and `field_sub()` require canonical `x` and `y` using the same
   encoding, either natural or Montgomery. Their output is canonical and
   preserves that encoding.
2. `field_halve()` requires canonical `x` in either natural or Montgomery
   encoding. Its output is canonical and preserves the encoding.
3. `montgomery_mul` requires `x` and `y` so that `x*y` is bounded by `2^16*Q`.
   The result will be canonical.
4. `ntt_forward` requires `a` to be a coefficient-domain polynomial with
   canonical entries using a consistent encoding, either natural or Montgomery.
   Its output is canonical, remains in the same encoding, and is in the
   evaluation domain.
5. `ntt_inverse` requires `a` to be an evaluation-domain polynomial with
   canonical entries using a consistent encoding, either natural or Montgomery.
   Its output is canonical, remains in the same encoding, and is in the
   coefficient domain.
6. `poly_to_montgomery` requires f to contain canonical entries in natural
   encoding. Its output is canonical and Montgomery-encoded. Because the
   operation is pointwise, it preserves the polynomial domain.
7. `poly_sub` requires `f` and `g` to contain canonical entries and to use the
   same polynomial domain and encoding. Its output is canonical and preserves
   the other two properties.
8. `poly_prepare_for_mul` requires `h` to be a coefficient-domain polynomial
   with canonical entries in natural encoding. Its output is canonical,
   Montgomery-encoded, and in the evaluation domain.
9. `poly_pointwise_mul()` requires `f` and `g` to be evaluation-domain
   polynomials with canonical entries. Its output is canonical and remains in
   the evaluation domain. The encoding will depend on the encoding of the
   inputs.

## Planned remediation

Documentation-only change. Add rustdoc to each of the nine primitives stating
its preconditions (range, polynomial domain, field encoding) and its
postconditions, exactly as enumerated above.

- [ ] `field_add` — `ntt.rs:91`
- [ ] `field_sub` — `ntt.rs:97`
- [ ] `field_halve` — `ntt.rs:103`
- [ ] `montgomery_mul` — `ntt.rs:109`
- [ ] `ntt_forward` — `ntt.rs:117`
- [ ] `ntt_inverse` — `ntt.rs:143`
- [ ] `poly_to_montgomery` — `ntt.rs:180`
- [ ] `poly_pointwise_mul` — `ntt.rs:186`
- [ ] `poly_sub` — `ntt.rs:192`
- [ ] `poly_prepare_for_mul` — `ntt.rs:198`
- [ ] Add a module-level section to `ntt.rs` defining the three axes once
      (canonical vs. non-canonical representative, coefficient vs. evaluation
      domain, natural vs. Montgomery encoding) so the per-function docs can
      reference the vocabulary instead of redefining it ten times.
- [ ] Add a **VER-004** row to [`remediation-log.md`](../remediation-log.md).

## Repository notes

All ten functions named in the finding exist at the cited locations and are
currently `pub`. That visibility is what makes the missing contracts reachable
from outside the crate — **VER-005 item 7** asks for the same functions to be
narrowed to the minimum visibility their callers need. The two findings should
be implemented together or in a deliberate order: narrowing visibility first
reduces the blast radius, and documenting the invariants is what makes the
remaining public surface safe to use.

Note that documenting a precondition is not enforcing it. If the team wants the
invariants checked rather than merely stated, that is a separate decision with
a gas cost on the on-chain path, and it interacts with **VER-005 item 1**
(replacing `debug_assert!` with a runtime assertion in `hash_to_point`). Record
that decision here if it is made.
