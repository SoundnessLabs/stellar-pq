# VER-002 — Unsafe key rotation may permanently lock smart accounts

| | |
| --- | --- |
| Finding ID | **VER-002** |
| Veridise issue | **#1288** |
| Source | Veridise audit report |
| Severity | **Low** |
| Likelihood | Not Likely |
| Impact | Protocol Breaking |
| Reported | 2026-08-18 |
| Status | **In progress** — remediation implemented on branch `claude/falcon-key-rotation-validation-bd4fd8`, awaiting review |
| Owner | gnosed |
| Affects | [`contracts/soroban-falcon-smart-account/src/lib.rs`](../../../contracts/soroban-falcon-smart-account/src/lib.rs) — `rotate_key` (now replaced by `propose_key` / `accept_key` / `cancel_key`) |
| Related | **TM-002** (rotation race, Open), **TM-003** (rotation spam, Accepted), **SR-001** (auth-before-validate ordering, Fixed) |

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

## Implemented remediation

- [x] Well-formedness check on `new_pubkey` before storing: shared
      `check_pubkey_well_formed` gate (897-byte length, then `decode_pubkey`:
      `0x09` header, all 512 coefficients < Q, zero residual bits). Applied to
      `propose_key` and `__constructor` — a malformed deploy key bricks the
      account the same way (threat-model DoS.6). New error codes
      `MalformedPublicKey`, `NoPendingKey`, `ProofVerificationFailed`.
- [x] Two-step rotation, replacing `rotate_key`:
  - [x] `propose_key(new_pubkey)` — authorized by the current key
        (`require_auth()` first, then validate); stores `new_pubkey` under
        the `F_PENDING` instance-storage slot; current key stays active.
        Calling it again replaces the proposal.
  - [x] `accept_key(proof)` — `proof` must be a Falcon-512 signature by the
        pending key over `ACCEPT_DOMAIN_SEPARATOR || SHA-256(pending_pubkey)`,
        verified with the embedded verifier. Promotes pending to active and
        clears the slot.
  - [x] `cancel_key()` — authorized by the current key; clears the pending
        rotation. `get_pending_key()` view added.
- [x] Auth-routing decision: routing the pending key through `__check_auth`
      isn't practical, since the host resolves the account's auth against the
      stored active key. So `accept_key` takes the proof as a parameter and
      verifies it inline — the proof itself is the authorization. That's the
      report's primary option (pending-key possession), not the current-key
      fallback. The proof's domain tag is prefix-free against the transaction
      tag, so a proof can't be replayed as a transaction signature or vice
      versa.
- [x] Pending-key storage slot lives in instance storage; TTL extended on
      propose and accept alongside the active key.
- [x] `propose` / `accept` / `cancel` events emitted with the SHA-256 of the
      affected pubkey (SR-004 convention).
- [x] Tests (`tests/integration.rs`): happy-path two-step rotation; accept
      without propose; wrong-key/corrupted/undersized proof; propose twice
      (replacement); cancel then accept; cancel without pending; propose/cancel
      without auth; bad size after auth; malformed encodings (bad header,
      coefficient ≥ Q, corrupted real key); malformed constructor key.
      Proof fixtures are generated deterministically from the vendored
      falcon-wasm signer by
      [`tests/fixtures/gen_accept_fixtures.mjs`](../../../contracts/soroban-falcon-smart-account/tests/fixtures/gen_accept_fixtures.mjs).
- [x] Irrecoverability and operator guidance documented in the crate README
      ("Key rotation (two-step)"), the module docs, the root README row, and
      `e2e/README.md`.
- [x] Row added to [`remediation-log.md`](../remediation-log.md).
- [ ] Revisit TM-002 with the widened two-transaction window (see notes below)
      and refresh the threat model's `rotate_key` references (`threat-model.md`
      still describes the one-step flow).

## Repository notes

The old `rotate_key` called `require_auth()` first and only then checked
`new_pubkey.len() != FALCON_512_PUBKEY_SIZE` before writing to instance
storage. That auth-before-validate ordering was itself an earlier
remediation, and the redesign keeps it: `propose_key` and `cancel_key`
authorize before touching anything. `accept_key` has no `require_auth` on
purpose — its
authorization is the proof-of-possession signature, the same way
`__check_auth` treats signature verification as authorization. Worth flagging
for review: once a rotation is proposed, anyone holding the pending private
key can finalize it. That's the state the current key already authorized at
propose time, and it also means losing the current key mid-rotation doesn't
strand an already-proposed rotation.

This finding interacts with TM-002 (already open): an attacker holding the
current key can race a malicious transaction into the same ledger as a
rotation. A two-step flow widens that window from one transaction to two, so
TM-002 should get revisited alongside this rather than treated separately.
It doesn't make TM-002 worse in substance — an attacker with the current key
was already game over — but `threat-model.md` still describes the one-step
`rotate_key` in Tamper.2, DoS.5, and Elevation.1/3, and needs a refresh pass.

Interface decision: `rotate_key` is removed, not kept as an alias. A one-step
write-through path would preserve exactly the hazard this finding describes.
That's a breaking change to the contract interface; the deployed testnet
smart account (`CANNCY2STTSAR7UQLZ7MVKQNMQ45WCDLJ67ILTOVSO6K3BJTULXSYPC4`)
still runs the old code and keeps its `rotate_key` until redeployed — the
contract has no upgrade hook, so existing instances are unaffected.
