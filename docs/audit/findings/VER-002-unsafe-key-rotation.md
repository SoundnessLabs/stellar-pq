# VER-002 — Unsafe key rotation may permanently lock smart accounts

| | |
| --- | --- |
| Finding ID | **VER-002** |
| Source | Veridise audit report |
| Severity | Not stated in the delivered report |
| Status | **Open** — remediation not yet implemented |
| Owner | TBD |
| Affects | [`contracts/soroban-falcon-smart-account/src/lib.rs`](../../../contracts/soroban-falcon-smart-account/src/lib.rs) — `rotate_key` |
| Related | **TM-002** (rotation race, Open), **TM-003** (rotation spam, Accepted), **SR-001** (auth-before-validate ordering, Fixed) |

> **Tracking stub.** This document records the finding and the agreed
> remediation. No code change lands in this PR.

## Finding as reported

### Description

The key-rotation process of the `FalconSmartAccount` contract is a one-step
process that only validates whether the new public key is of the required size,
but does not verify whether it is a valid Falcon public key or, more
importantly, whether it is the intended public key. Therefore, this process is
not robust against potential mistakes during its execution.

### Impact

Setting an incorrect public key during key rotation is an irrecoverable mistake
that renders the smart wallet unusable. This includes both a key other than the
intended one and a corrupted copy of the intended key.

### Recommendation

Validate that `new_pubkey` is a well-formed Falcon-512 public key before storing
it. A well-formedness check will reject malformed encodings, including some
typos in an otherwise intended key.

A well-formed but incorrect public key will still pass that check. To address
that case, use a two-step key-rotation process in which the current key
authorizes `propose_key()`, storing `new_pubkey` as pending while the existing
key remains active. The pending key should then authorize `accept_key()`,
proving possession of the corresponding private key before activation. If this
verification is impractical, `accept_key()` may instead require authorization
from the current key as an additional confirmation step. Until activation, the
current key should remain able to cancel or replace the pending rotation.

At minimum, document that the current implementation cannot recover from an
incorrect key rotation and emphasize that operators must carefully verify the
new public key before proceeding.

## Planned remediation

- [ ] Add a well-formedness check on `new_pubkey` before storing: reject unless
      `decode_pubkey` succeeds (this also pins the `pubkey[0] == 9` header and
      the 14-bit coefficient encoding, not just the 897-byte length).
- [ ] Introduce two-step rotation:
  - [ ] `propose_key(new_pubkey)` — authorized by the **current** key; stores
        `new_pubkey` as pending; current key stays active.
  - [ ] `accept_key()` — authorized by the **pending** key, proving possession
        of the corresponding private key; promotes pending → active.
  - [ ] `cancel_key()` — authorized by the current key; clears the pending
        rotation. The current key must also be able to replace a pending
        proposal by calling `propose_key` again.
- [ ] Decide whether `accept_key()` can practically be authorized by the
      pending key under Soroban's `__check_auth` routing (the account's auth
      currently resolves against the *stored active* key). If not, fall back to
      the report's alternative: `accept_key()` re-authorized by the current
      key as a confirmation step.
- [ ] Add a pending-key storage slot and extend its TTL alongside the active
      key.
- [ ] Emit `propose` / `accept` / `cancel` events (SHA-256 of the pubkey, matching
      the existing `init` / `rotate` convention from **SR-004**).
- [ ] Tests: happy-path two-step rotation; accept without propose; propose
      twice; cancel then accept; malformed pubkey rejected at propose time.
- [ ] Document the irrecoverability of a bad rotation in the contract docs and
      README regardless of which option is implemented.
- [ ] Add a **VER-002** row to [`remediation-log.md`](../remediation-log.md).

## Repository notes

`rotate_key` today calls `require_auth()` first and then checks only
`new_pubkey.len() != FALCON_512_PUBKEY_SIZE` before writing to instance storage.
The auth-before-validate ordering is deliberate and was itself a remediation
(**SR-001**) — any redesign must preserve it, so `propose_key` should likewise
authorize before validating.

This finding interacts with **TM-002** (already Open): an attacker holding the
current key can race a malicious transaction into the same ledger as a
rotation. A two-step flow widens that window from one transaction to two, so
the TM-002 analysis should be revisited as part of this work rather than
treated as independent.

Note that a two-step rotation is a **breaking change to the contract
interface**. The deployed testnet smart account
(`CANNCY2STTSAR7UQLZ7MVKQNMQ45WCDLJ67ILTOVSO6K3BJTULXSYPC4`) exposes
`rotate_key`; deciding whether to keep it as a deprecated alias or remove it
is part of this finding's scope.
