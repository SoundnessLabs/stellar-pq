//! Falcon-512 signature verification.
//!
//! Falcon is a lattice-based post-quantum signature scheme built on NTRU
//! lattices and the hash-and-sign paradigm. NIST selected it for
//! standardization.
//!
//! # Verification algorithm
//!
//! Given a public key `h`, message `m`, and signature `(r, s)`:
//!
//! 1. Hash to a point: `c = H(r || m) mod q`, where `H` is SHAKE256 with
//!    rejection sampling, so the coefficients come out uniform in `Z_q`.
//! 2. Recover `s1 = c - s·h mod q`, multiplying in `Z_q[X]/(X^n + 1)`.
//! 3. Accept only if the L2 norm of `(s1, s)` is within the bound.
//!
//! # Accepted signature formats
//!
//! The header byte's low nibble must equal `logn = 9`. The high nibble
//! selects the encoding family and **both `0x2X` and `0x3X` are accepted**,
//! because real Falcon-512 signers disagree on the nibble: the official NIST
//! Round-3 KAT vectors (and `falcon.py`) emit `0x29` with a *variable-length*
//! compressed body, while PQClean `falcon-512/clean` and this project's
//! `falcon-wasm` signer emit `0x39` for compressed and `0x29` for the
//! 666-byte padded form. The verifier therefore treats the high nibble
//! loosely and enforces canonicity on the *body* instead (see `verify_512`):
//!
//!   * the compressed body decodes exactly, with no leftover bytes, or
//!   * the signature is the fixed padded size
//!     (`FALCON_512_SIG_PADDED_SIZE` = 666 bytes) with an all-zero tail.
//!
//! Any other zero-padded length is rejected. The constant-time (CT, `0x5X`)
//! format is 809 bytes and is rejected by the size gate; its decoder path
//! does not exist.
//!
//! Because both the compressed and padded encodings of the same underlying
//! signature verify, the scheme is EUF-CMA (no forgery) but not strongly
//! non-malleable at the byte level. Consumers that need a unique signature
//! identifier must not key on the raw bytes; the smart-account layer is
//! unaffected because Soroban's `signature_payload` (not the signature bytes)
//! is the replay key.
//!
//! # References
//!
//! - Falcon specification: <https://falcon-sign.info/falcon.pdf>
//! - NIST PQC: <https://csrc.nist.gov/projects/post-quantum-cryptography>

use crate::ntt::{
    field_sub, ntt_forward, ntt_inverse, poly_pointwise_mul, poly_prepare_for_mul, poly_sub,
};
use crate::{
    FALCON_512_N, FALCON_512_PUBKEY_SIZE, FALCON_512_SIG_PADDED_SIZE, FALCON_MAX_MESSAGE_SIZE,
    FALCON_SIG_MAX_SIZE, FALCON_SIG_MIN_SIZE, L2_BOUND_512, Q,
};

/// Falcon-512 signature verifier. Stateless; all methods are associated
/// functions.
pub struct FalconVerifier;

impl FalconVerifier {
    /// Verifies a Falcon-512 signature.
    ///
    /// Takes the 897-byte public key, the signed message (at most
    /// `FALCON_MAX_MESSAGE_SIZE` bytes), and a compressed or padded
    /// signature. Returns `false` on any failure, and never panics.
    pub fn verify_512(pubkey: &[u8], message: &[u8], signature: &[u8]) -> bool {
        // Step 1: Validate public key format
        if pubkey.len() != FALCON_512_PUBKEY_SIZE {
            return false;
        }
        // Header byte encodes logn; for Falcon-512, logn = 9 (since n = 2^9 = 512)
        const FALCON_512_LOGN: u8 = 9;
        if pubkey[0] != FALCON_512_LOGN {
            return false;
        }

        // Callers gate this too. Repeated here because the caller may have
        // copied into a fixed buffer already, and a longer slice would hide
        // the truncation.
        if message.len() > FALCON_MAX_MESSAGE_SIZE {
            return false;
        }

        // Step 2: Parse signature header and determine format
        let sig_len = signature.len();
        if sig_len < FALCON_SIG_MIN_SIZE as usize || sig_len > FALCON_SIG_MAX_SIZE as usize {
            return false;
        }
        let sig_header = signature[0];
        if (sig_header & 0x0F) != FALCON_512_LOGN {
            return false;
        }
        // The high nibble of the header selects the encoding family. Real
        // signers disagree on which nibble means what (see the module-level
        // "Accepted signature formats" docs): the NIST Round-3 KAT and
        // falcon.py use 0x2X for variable-length compressed signatures, while
        // PQClean and the falcon-wasm signer use 0x3X for compressed and 0x2X
        // for the 666-byte padded form. We therefore accept BOTH 0x2X and
        // 0x3X and do not bind the nibble to a particular body length;
        // canonicity is enforced on the decoded body instead (Step 5 below).
        //
        // 0x5X (CT, 809 bytes) is rejected here and, redundantly, by the size
        // gate above (809 > FALCON_SIG_MAX_SIZE = 666). Reference: Falcon NIST
        // Round-3 submission §3.11.1.
        let fmt = sig_header & 0xF0;
        if fmt != 0x20 && fmt != 0x30 {
            return false;
        }

        // Step 3: Decode public key polynomial h
        let mut h = [0u16; FALCON_512_N];
        if !Self::decode_pubkey(pubkey, &mut h) {
            return false;
        }

        // Step 4: Extract nonce (bytes 1-40)
        let nonce = &signature[1..41];

        // Step 5: Decode signature polynomial s2
        let mut s2 = [0i16; FALCON_512_N];
        let sig_data = &signature[41..];
        let decoded_len = Self::decode_sig_compressed(sig_data, &mut s2);
        if decoded_len == 0 {
            return false;
        }

        // Canonicity: the body must decode exactly, or be the 666-byte
        // padded form with a zero tail. Any other padded length is rejected,
        // so a signature cannot be re-encoded at an arbitrary length in
        // between and still verify.
        let total_sig_len = signature.len(); // header(1) + nonce(40) + body
        let is_natural = decoded_len == sig_data.len();
        let is_padded = total_sig_len == FALCON_512_SIG_PADDED_SIZE;
        if !is_natural && !is_padded {
            return false;
        }
        // Trailing bytes (padded form only) must be zero.
        for i in decoded_len..sig_data.len() {
            if sig_data[i] != 0 {
                return false;
            }
        }

        // Step 6: hash to the challenge polynomial. `false` means a
        // coefficient escaped [0, Q), which cannot happen as written.
        let mut c0 = [0u16; FALCON_512_N];
        if !Self::hash_to_point(nonce, message, &mut c0) {
            return false;
        }

        // Step 7: move h into the NTT domain and Montgomery form, then verify.
        poly_prepare_for_mul(&mut h);

        Self::verify_raw_512(&c0, &s2, &h)
    }

    /// Checks `||(c0 - s2·h, s2)|| ≤ L2_BOUND_512`.
    ///
    /// Validates nothing, so it can return `true` for garbage. `verify_512`
    /// is what guarantees the inputs:
    ///
    /// * `c0`: canonical, in `[0, Q)` (`hash_to_point`)
    /// * `s2`: in `[-2047, 2047]` (`decode_sig_compressed`)
    /// * `h`: canonical, Montgomery, NTT domain (`poly_prepare_for_mul`)
    fn verify_raw_512(
        c0: &[u16; FALCON_512_N],
        s2: &[i16; FALCON_512_N],
        h: &[u16; FALCON_512_N],
    ) -> bool {
        let mut tt = [0u16; FALCON_512_N];

        // Step 1: Convert s2 from signed to unsigned representation mod q
        for i in 0..FALCON_512_N {
            let w = s2[i] as i32;
            let w = if w < 0 {
                (w + Q as i32) as u32
            } else {
                w as u32
            };
            tt[i] = w as u16;
        }

        // Step 2: s2·h in the ring Z_q[X]/(X^n + 1). h arrives already in
        // NTT+Montgomery form; only tt needs transforming.
        ntt_forward(&mut tt);
        poly_pointwise_mul(&mut tt, h);
        ntt_inverse(&mut tt);

        // Step 3: s1 = c0 - s2·h, computed as -s1 = s2·h - c0. The norm is
        // the same either way, so the sign flip is free.
        poly_sub(&mut tt, c0);

        // Step 4: Convert -s1 back to signed representation for norm computation
        let mut s1 = [0i16; FALCON_512_N];
        for i in 0..FALCON_512_N {
            let w = tt[i] as i32;
            let w = if w > (Q as i32 / 2) { w - Q as i32 } else { w };
            s1[i] = w as i16;
        }

        // Step 5: Verify that the signature vector (s1, s2) is short enough
        Self::is_short(&s1, s2)
    }

    /// Verifies that ||(s1, s2)||² ≤ L2_BOUND_512.
    ///
    /// # Overflow handling
    ///
    /// The running norm can pass `2^32` (worst case ≈ `1024 · (q/2)² ≈
    /// 3.86·10¹⁰`), so `s` wraps. A wrap must still reject, or a norm far
    /// above the bound comes back looking small.
    ///
    /// Every `z²` is at most `(q/2)² ≈ 3.77·10⁷`, well under `2³¹`. So an
    /// addition can only wrap past `2³²` if the value going in was
    /// `≥ 2³² − z² > 2³¹`, i.e. had bit 31 set. `ng |= s` after each
    /// addition catches that bit, and `s |= 0 - (ng >> 31)` then saturates
    /// `s` to `0xFFFFFFFF`, failing the bounds check.
    fn is_short(s1: &[i16; FALCON_512_N], s2: &[i16; FALCON_512_N]) -> bool {
        let mut s: u32 = 0;
        let mut ng: u32 = 0;

        for i in 0..FALCON_512_N {
            let z1 = s1[i] as i32;
            s = s.wrapping_add((z1 * z1) as u32);
            ng |= s;

            let z2 = s2[i] as i32;
            s = s.wrapping_add((z2 * z2) as u32);
            ng |= s;
        }

        // Saturate to u32::MAX if any intermediate sum had bit 31 set.
        s |= 0u32.wrapping_sub(ng >> 31);

        s <= L2_BOUND_512
    }

    /// Decodes a Falcon-512 public key from its packed binary format:
    /// 14 bits per coefficient, MSB-first.
    ///
    /// On success `h` holds 512 coefficients in `[0, Q)`. On failure it is
    /// partially written; discard it.
    pub fn decode_pubkey(pubkey: &[u8], h: &mut [u16; FALCON_512_N]) -> bool {
        if pubkey.len() != FALCON_512_PUBKEY_SIZE {
            return false;
        }
        if pubkey[0] != 9 {
            return false;
        }

        let data = &pubkey[1..];
        let mut acc: u32 = 0;
        let mut acc_len = 0;
        let mut u = 0;
        let mut buf_idx = 0;

        while u < FALCON_512_N {
            acc = (acc << 8) | (data[buf_idx] as u32);
            buf_idx += 1;
            acc_len += 8;

            if acc_len >= 14 {
                acc_len -= 14;
                let w = (acc >> acc_len) & 0x3FFF;
                if w >= Q {
                    return false;
                }
                h[u] = w as u16;
                u += 1;
            }
        }

        // 896 * 8 == 512 * 14, so the accumulator always drains and there
        // are no leftover bits to check. Only true while the length gate
        // above is exact.
        debug_assert_eq!(acc_len, 0, "896 payload bytes = 512 * 14 bits exactly");

        true
    }

    /// Decodes a signature from compressed format, returning the number of
    /// bytes consumed, or 0 if the body is malformed.
    fn decode_sig_compressed(data: &[u8], s2: &mut [i16; FALCON_512_N]) -> usize {
        let mut acc: u32 = 0;
        let mut acc_len: u32 = 0;
        let mut v = 0;

        for u in 0..FALCON_512_N {
            if v >= data.len() {
                return 0;
            }
            acc = (acc << 8) | (data[v] as u32);
            v += 1;

            let b = acc >> acc_len;
            let sign = b & 128;
            let mut m = (b & 127) as u32;

            loop {
                if acc_len == 0 {
                    if v >= data.len() {
                        return 0;
                    }
                    acc = (acc << 8) | (data[v] as u32);
                    v += 1;
                    acc_len = 8;
                }
                acc_len -= 1;

                if ((acc >> acc_len) & 1) != 0 {
                    break;
                }
                m += 128;
                if m > 2047 {
                    return 0;
                }
            }

            if sign != 0 && m == 0 {
                return 0;
            }

            s2[u] = if sign != 0 { -(m as i16) } else { m as i16 };
        }

        if (acc & ((1u32 << acc_len) - 1)) != 0 {
            return 0;
        }

        v
    }

    /// Hashes nonce || message to a challenge polynomial using SHAKE256 with rejection sampling.
    ///
    /// Nonce and message are absorbed with no separator, as in the
    /// reference, so only the concatenation matters: `[1,1] || [2,2]` and
    /// `[1] || [1,2,2]` hash the same. Unambiguous only with a fixed-length
    /// nonce. Pass 40 bytes.
    ///
    /// Returns `false` if a coefficient lands outside `[0, Q)`, which the
    /// bounds below rule out. Checked rather than asserted because
    /// `__check_auth` must not panic. `c0` is garbage on `false`.
    fn hash_to_point(nonce: &[u8], message: &[u8], c0: &mut [u16; FALCON_512_N]) -> bool {
        use sha3::{
            digest::{ExtendableOutput, Update, XofReader},
            Shake256,
        };

        debug_assert_eq!(nonce.len(), 40, "hash_to_point requires a 40-byte nonce");

        let mut hasher = Shake256::default();
        hasher.update(nonce);
        hasher.update(message);
        let mut xof = hasher.finalize_xof();

        let mut remaining = FALCON_512_N;
        let mut idx = 0;

        while remaining > 0 {
            let mut buf = [0u8; 2];
            xof.read(&mut buf);

            let w = ((buf[0] as u32) << 8) | (buf[1] as u32);

            const ACCEPT_THRESHOLD: u32 = 5 * Q;
            if w < ACCEPT_THRESHOLD {
                // w < 5*Q, so four conditional subtractions reduce it. Do
                // not rewrite as a loop: LLVM turns `while v >= Q` into
                // `w % Q` and lowers it to UDIV at -Oz/-Os, which is not
                // constant time. See docs/audit/constant-time-analysis.md.
                let mut v = w;
                v = field_sub(v, Q);
                v = field_sub(v, Q);
                v = field_sub(v, Q);
                v = field_sub(v, Q);
                if v >= Q {
                    return false;
                }
                c0[idx] = v as u16;
                idx += 1;
                remaining -= 1;
            }
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_short_zero() {
        let s1 = [0i16; FALCON_512_N];
        let s2 = [0i16; FALCON_512_N];
        assert!(FalconVerifier::is_short(&s1, &s2));
    }

    #[test]
    fn test_is_short_small() {
        let mut s1 = [0i16; FALCON_512_N];
        let mut s2 = [0i16; FALCON_512_N];
        for i in 0..FALCON_512_N {
            s1[i] = ((i % 10) as i16) - 5;
            s2[i] = ((i % 10) as i16) - 5;
        }
        assert!(FalconVerifier::is_short(&s1, &s2));
    }

    #[test]
    fn test_is_short_rejects_overflow() {
        // Fill with ±(q/2 - 1); true squared norm ≈ 1024 · 6144² ≈ 3.87·10¹⁰,
        // which is ~9× u32::MAX, and must be rejected.
        let mut s1 = [0i16; FALCON_512_N];
        let mut s2 = [0i16; FALCON_512_N];
        for i in 0..FALCON_512_N {
            s1[i] = 6144;
            s2[i] = -6144;
        }
        assert!(
            !FalconVerifier::is_short(&s1, &s2),
            "must reject when true squared norm wraps u32"
        );
    }

    #[test]
    fn test_pubkey_decode_header() {
        let mut h = [0u16; FALCON_512_N];
        let bad_pk = [8u8; FALCON_512_PUBKEY_SIZE];
        assert!(!FalconVerifier::decode_pubkey(&bad_pk, &mut h));
        let short_pk = [9u8; 100];
        assert!(!FalconVerifier::decode_pubkey(&short_pk, &mut h));
    }

    #[test]
    fn test_message_too_long_rejected() {
        let pk = [9u8; FALCON_512_PUBKEY_SIZE];
        let msg = [0u8; FALCON_MAX_MESSAGE_SIZE + 1];
        let mut sig = [0u8; 666];
        sig[0] = 0x29;
        assert!(!FalconVerifier::verify_512(&pk, &msg, &sig));
    }

    #[test]
    fn test_ct_format_rejected_by_size_gate() {
        // A 809-byte "signature" with the CT header nibble must be rejected
        // by the size gate, not silently accepted by a broken CT decoder.
        let pk = [9u8; FALCON_512_PUBKEY_SIZE];
        let mut sig = [0u8; 809];
        sig[0] = 0x59;
        assert!(!FalconVerifier::verify_512(&pk, b"", &sig));
    }
}
