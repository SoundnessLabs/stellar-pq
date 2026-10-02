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
//! # Accepted signature format
//!
//! The verifier accepts exactly the detached compressed Falcon-512 framing:
//!
//! ```text
//! 0x39 || nonce[40] || compressed(s2) [|| zero padding to 666 bytes]
//! ```
//!
//! The header byte is fixed: `0x39 = 0x30 | logn` (logn = 9). Every
//! conforming Falcon-512 signer — the reference C implementation, PQClean
//! `falcon-512/clean`, `falcon.py`, and this project's `falcon-wasm` — emits
//! `0x39` for detached compressed signatures, natural-length and 666-byte
//! padded alike (Falcon Round-3 spec §3.11.3–4). Two related headers are
//! deliberately rejected:
//!
//!   * `0x29` (`0x20 | logn`) labels only the *nonce-less* signature tail
//!     inside the NIST `crypto_sign` signed-message envelope
//!     (`sig_len || nonce || message || 0x29 || compressed(s2)`); it is not
//!     a valid header for the detached layout above, and accepting it would
//!     make the first signature byte malleable.
//!   * `0x59` (CT/fixed-width) requires a different decoder, which does not
//!     exist here; it is also rejected redundantly by the size gate
//!     (809 > `FALCON_SIG_MAX_SIZE` = 752).
//!
//! Natural- versus padded-form canonicity is enforced on the *body*
//! (see `verify_512`):
//!
//!   * the compressed body decodes exactly, with no leftover bytes, or
//!   * the signature is the fixed padded size
//!     (`FALCON_512_SIG_PADDED_SIZE` = 666 bytes) with an all-zero tail.
//!
//! Any other zero-padded length is rejected. The natural-length and 666-byte
//! padded encodings of the same underlying signature both verify, so the
//! scheme is EUF-CMA (no forgery) but byte-level uniqueness is still not
//! guaranteed across the two forms. Consumers that need a unique signature
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
    FALCON_512_N, FALCON_512_PUBKEY_SIZE, FALCON_512_SIG_PADDED_SIZE, FALCON_SIG_MAX_SIZE,
    FALCON_SIG_MIN_SIZE, L2_BOUND_512, Q,
};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

/// Largest coefficient magnitude a valid signature can contain: one
/// coefficient with `|c| > ⌊√L2_BOUND_512⌋` exceeds the squared-norm bound
/// on its own, so the decoder rejects it without looking at the rest.
const MAX_SIG_COEFF: u32 = 5833;
const _: () = assert!(MAX_SIG_COEFF * MAX_SIG_COEFF <= L2_BOUND_512);
const _: () = assert!((MAX_SIG_COEFF + 1) * (MAX_SIG_COEFF + 1) > L2_BOUND_512);

/// Falcon-512 signature verifier. Stateless; all methods are associated
/// functions.
pub struct FalconVerifier;

/// Streaming Falcon-512 verification.
///
/// [`Falcon512Verification::new`] parses the public key and signature and
/// starts the message hash; [`Falcon512Verification::absorb_message`] feeds
/// the message in chunks of any size; [`Falcon512Verification::finalize`]
/// returns the verdict. Only the concatenation of the chunks matters, so a
/// caller can hash a message of any length through a small buffer.
/// [`FalconVerifier::verify_512`] is the one-shot form of the same
/// computation.
pub struct Falcon512Verification {
    h: [u16; FALCON_512_N],
    s2: [i16; FALCON_512_N],
    hasher: Shake256,
}

impl Falcon512Verification {
    /// Parses `pubkey` and `signature`. Returns `None` when either is
    /// malformed; the message plays no part in these checks.
    pub fn new(pubkey: &[u8], signature: &[u8]) -> Option<Self> {
        // Validate public key format
        if pubkey.len() != FALCON_512_PUBKEY_SIZE {
            return None;
        }
        // Header byte encodes logn; for Falcon-512, logn = 9 (since n = 2^9 = 512)
        const FALCON_512_LOGN: u8 = 9;
        if pubkey[0] != FALCON_512_LOGN {
            return None;
        }

        // Parse signature header and determine format
        let sig_len = signature.len();
        if sig_len < FALCON_SIG_MIN_SIZE as usize || sig_len > FALCON_SIG_MAX_SIZE as usize {
            return None;
        }
        // Detached compressed Falcon-512 signatures — natural-length and
        // 666-byte padded alike — always carry header 0x39 = 0x30 | logn
        // (see the module-level "Accepted signature format" docs). 0x29
        // belongs only to the nonce-less tail of the NIST crypto_sign
        // envelope, and 0x59 (CT) has no decoder here, so any header other
        // than 0x39 is rejected. Natural vs. padded form is determined from
        // decoder consumption and total length (below), not from the header.
        const FALCON_512_SIG_HEADER: u8 = 0x30 | FALCON_512_LOGN;
        if signature[0] != FALCON_512_SIG_HEADER {
            return None;
        }

        // Decode public key polynomial h
        let mut h = [0u16; FALCON_512_N];
        if !FalconVerifier::decode_pubkey(pubkey, &mut h) {
            return None;
        }

        // Decode signature polynomial s2 (body follows the 40-byte nonce)
        let mut s2 = [0i16; FALCON_512_N];
        let sig_data = &signature[41..];
        let decoded_len = FalconVerifier::decode_sig_compressed(sig_data, &mut s2);
        if decoded_len == 0 {
            return None;
        }

        // Canonicity: the body must decode exactly, or be the 666-byte
        // padded form with a zero tail. Any other zero-padded length is
        // rejected, so one signature cannot be re-encoded at an arbitrary
        // length and still verify.
        let is_natural = decoded_len == sig_data.len();
        let is_padded = sig_len == FALCON_512_SIG_PADDED_SIZE;
        if !is_natural && !is_padded {
            return None;
        }
        for i in decoded_len..sig_data.len() {
            if sig_data[i] != 0 {
                return None;
            }
        }

        // The challenge is SHAKE256(nonce || message), absorbed with no
        // separator between them, as in the reference. Only the
        // concatenation matters, so the framing would be ambiguous for a
        // variable-length nonce; here it is always these fixed 40 bytes,
        // taken from the signature rather than from any caller.
        let mut hasher = Shake256::default();
        hasher.update(&signature[1..41]);

        // Move h into the NTT domain and Montgomery form for the pointwise
        // multiplication in `finalize`.
        poly_prepare_for_mul(&mut h);

        Some(Self { h, s2, hasher })
    }

    /// Absorbs the next message chunk.
    pub fn absorb_message(&mut self, chunk: &[u8]) {
        self.hasher.update(chunk);
    }

    /// Returns whether the signature is valid over the absorbed message.
    pub fn finalize(self) -> bool {
        let mut c0 = [0u16; FALCON_512_N];
        if !Self::squeeze_challenge(self.hasher, &mut c0) {
            return false;
        }
        FalconVerifier::verify_raw_512(&c0, &self.s2, &self.h)
    }

    /// Squeezes the challenge polynomial out of the finished hash state:
    /// SHAKE256 output, rejection-sampled to uniform elements of `Z_q`.
    /// Returns `false` if a coefficient lands outside `[0, Q)`, which the
    /// bounds below rule out. Checked rather than asserted because
    /// `__check_auth` must not panic. `c0` is garbage on `false`.
    fn squeeze_challenge(hasher: Shake256, c0: &mut [u16; FALCON_512_N]) -> bool {
        let mut xof = hasher.finalize_xof();

        let mut remaining = FALCON_512_N;
        let mut idx = 0;

        while remaining > 0 {
            let mut buf = [0u8; 2];
            xof.read(&mut buf);

            let w = ((buf[0] as u32) << 8) | (buf[1] as u32);

            const ACCEPT_THRESHOLD: u32 = 5 * Q;
            if w < ACCEPT_THRESHOLD {
                // Reduce w mod Q with four conditional subtractions; the
                // accept threshold guarantees w < 5*Q. A `while v >= Q`
                // loop is off limits: LLVM rewrites it as `w % Q` and
                // lowers that to hardware UDIV at -Oz/-Os, which is not
                // constant time.
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

impl FalconVerifier {
    /// Verifies a Falcon-512 signature.
    ///
    /// # Arguments
    /// * `pubkey` - 897-byte Falcon-512 public key
    /// * `message` - The message that was signed, of any length
    /// * `signature` - The signature bytes (compressed or padded format only)
    ///
    /// # Returns
    /// `true` if the signature is valid, `false` otherwise.
    pub fn verify_512(pubkey: &[u8], message: &[u8], signature: &[u8]) -> bool {
        match Falcon512Verification::new(pubkey, signature) {
            Some(mut v) => {
                v.absorb_message(message);
                v.finalize()
            }
            None => false,
        }
    }

    /// Checks `||(c0 - s2·h, s2)|| ≤ L2_BOUND_512`.
    ///
    /// Validates nothing, so it can return `true` for garbage. The
    /// verification session is what guarantees the inputs:
    ///
    /// * `c0`: canonical, in `[0, Q)` ([`Falcon512Verification::finalize`])
    /// * `s2`: in `[-MAX_SIG_COEFF, MAX_SIG_COEFF]` (`decode_sig_compressed`)
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
                // Magnitudes past MAX_SIG_COEFF cannot appear in any valid
                // signature; rejecting them here also bounds the unary run.
                if m > MAX_SIG_COEFF {
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
    fn test_envelope_header_0x29_rejected() {
        // 0x29 = 0x20 | logn labels the nonce-less tail of the NIST
        // crypto_sign envelope, not a detached signature; the header gate
        // must reject it. The KAT suite additionally proves that flipping
        // a valid signature's 0x39 header to 0x29 invalidates it.
        let pk = [9u8; FALCON_512_PUBKEY_SIZE];
        let mut sig = [0u8; 666];
        sig[0] = 0x29;
        assert!(!FalconVerifier::verify_512(&pk, b"", &sig));
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

    /// Compressed-encodes `coeffs` into `out` (sign bit, 7 low bits,
    /// unary high part, MSB-first, zero-padded to a byte). Returns the
    /// body length in bytes.
    fn encode_sig_body(coeffs: &[i16; FALCON_512_N], out: &mut [u8; 1024]) -> usize {
        fn push(out: &mut [u8; 1024], nbits: &mut usize, bit: u32) {
            if bit != 0 {
                out[*nbits >> 3] |= 128 >> (*nbits & 7);
            }
            *nbits += 1;
        }
        let mut nbits = 0usize;
        for &c in coeffs.iter() {
            let m = c.unsigned_abs() as u32;
            push(out, &mut nbits, (c < 0) as u32);
            for i in (0..7).rev() {
                push(out, &mut nbits, (m >> i) & 1);
            }
            for _ in 0..(m >> 7) {
                push(out, &mut nbits, 0);
            }
            push(out, &mut nbits, 1);
        }
        nbits.div_ceil(8)
    }

    /// A well-formed 897-byte public key: header 0x09 over a payload whose
    /// 14-bit coefficients all land below Q.
    fn parseable_pubkey() -> [u8; FALCON_512_PUBKEY_SIZE] {
        [9u8; FALCON_512_PUBKEY_SIZE]
    }

    /// A signature of exactly `FALCON_SIG_MIN_SIZE` bytes that parses:
    /// header 0x39, zero nonce, all-zero coefficients (9 bits each).
    fn minimal_parseable_sig() -> [u8; FALCON_SIG_MIN_SIZE as usize] {
        let coeffs = [0i16; FALCON_512_N];
        let mut body = [0u8; 1024];
        let body_len = encode_sig_body(&coeffs, &mut body);
        assert_eq!(1 + 40 + body_len, FALCON_SIG_MIN_SIZE as usize);

        let mut sig = [0u8; FALCON_SIG_MIN_SIZE as usize];
        sig[0] = 0x39;
        sig[41..].copy_from_slice(&body[..body_len]);
        sig
    }

    #[test]
    fn test_min_size_signature_parses() {
        let sig = minimal_parseable_sig();
        assert!(Falcon512Verification::new(&parseable_pubkey(), &sig).is_some());
        // The pipeline must run to the norm check without panicking; an
        // all-zero s2 leaves s1 = c0, whose norm is far above the bound.
        assert!(!FalconVerifier::verify_512(&parseable_pubkey(), b"msg", &sig));
    }

    #[test]
    fn test_sig_size_gate_bounds() {
        let pk = parseable_pubkey();
        let mut sig = [0u8; FALCON_SIG_MAX_SIZE as usize + 1];
        sig[0] = 0x39;
        // One byte under the minimum and one over the maximum.
        assert!(Falcon512Verification::new(&pk, &sig[..FALCON_SIG_MIN_SIZE as usize - 1]).is_none());
        assert!(Falcon512Verification::new(&pk, &sig).is_none());
    }

    #[test]
    fn test_decode_accepts_norm_bounded_coefficients() {
        // 2048 and 5833 both square to at most L2_BOUND_512, so the decoder
        // must let them through to the norm check.
        for value in [2048i16, 5833, -5833] {
            let mut coeffs = [0i16; FALCON_512_N];
            coeffs[0] = value;
            let mut body = [0u8; 1024];
            let body_len = encode_sig_body(&coeffs, &mut body);

            let mut s2 = [0i16; FALCON_512_N];
            let consumed = FalconVerifier::decode_sig_compressed(&body[..body_len], &mut s2);
            assert_eq!(consumed, body_len, "value {value} should decode");
            assert_eq!(s2[0], value);
        }
    }

    #[test]
    fn test_decode_rejects_over_norm_coefficient() {
        // 5834² alone exceeds L2_BOUND_512; no valid signature can carry it.
        let mut coeffs = [0i16; FALCON_512_N];
        coeffs[0] = 5834;
        let mut body = [0u8; 1024];
        let body_len = encode_sig_body(&coeffs, &mut body);

        let mut s2 = [0i16; FALCON_512_N];
        assert_eq!(
            FalconVerifier::decode_sig_compressed(&body[..body_len], &mut s2),
            0
        );
    }

    #[test]
    fn test_decode_rejects_negative_zero() {
        // Sign bit set with magnitude zero has no canonical meaning.
        let mut body = [0u8; 1024];
        // First coefficient: 1 (sign) 0000000 (low bits) 1 (stop), rest zero.
        body[0] = 0b1000_0000;
        body[1] = 0b1000_0000;
        let mut s2 = [0i16; FALCON_512_N];
        assert_eq!(FalconVerifier::decode_sig_compressed(&body[..600], &mut s2), 0);
    }

    /// Truncating the compressed body must be rejected wherever the cut
    /// lands, not only on a whole-byte boundary: the decoder consumes a
    /// bit at a time and has to run out cleanly.
    #[test]
    fn test_decode_rejects_truncation_at_every_length() {
        let mut coeffs = [0i16; FALCON_512_N];
        for (i, c) in coeffs.iter_mut().enumerate() {
            *c = ((i % 401) as i16) - 200;
        }
        let mut body = [0u8; 1024];
        let full_len = encode_sig_body(&coeffs, &mut body);

        for cut in 1..full_len {
            let mut s2 = [0i16; FALCON_512_N];
            assert_eq!(
                FalconVerifier::decode_sig_compressed(&body[..cut], &mut s2),
                0,
                "body truncated to {cut} of {full_len} bytes must not decode"
            );
        }
        // The untruncated body still decodes, so the loop above is not
        // rejecting for some unrelated reason.
        let mut s2 = [0i16; FALCON_512_N];
        assert_eq!(
            FalconVerifier::decode_sig_compressed(&body[..full_len], &mut s2),
            full_len
        );
        assert_eq!(s2, coeffs);
    }

    /// The bits after the final coefficient are padding to the byte
    /// boundary and must be zero; a nonzero tail bit is a distinct encoding
    /// of the same polynomial and is rejected.
    #[test]
    fn test_decode_rejects_nonzero_unused_bits() {
        // All-zero coefficients take 9 bits each: 4608 bits, a whole 576
        // bytes with no spare bits to dirty. Giving one coefficient a
        // magnitude of 128 adds a single unary bit, so the body ends 1 bit
        // into its last byte and leaves 7 unused padding bits.
        let mut coeffs = [0i16; FALCON_512_N];
        coeffs[0] = 128;
        let mut body = [0u8; 1024];
        let len = encode_sig_body(&coeffs, &mut body);
        assert_eq!(len, 577, "expected a body ending mid-byte");

        let mut s2 = [0i16; FALCON_512_N];
        assert_eq!(
            FalconVerifier::decode_sig_compressed(&body[..len], &mut s2),
            len,
            "baseline body should decode"
        );
        assert_eq!(s2[0], 128);

        // Each of the 7 unused low bits of the final byte must be rejected;
        // they are padding, and a nonzero one is a second encoding of the
        // same polynomial.
        for bit in 0..7 {
            let mut dirty = body;
            dirty[len - 1] |= 1u8 << bit;
            assert_ne!(dirty[len - 1], body[len - 1], "bit {bit} should be spare");
            let mut s2 = [0i16; FALCON_512_N];
            assert_eq!(
                FalconVerifier::decode_sig_compressed(&dirty[..len], &mut s2),
                0,
                "nonzero unused bit {bit} must be rejected"
            );
        }
    }

    /// A public key whose packed 14-bit coefficients are not all below Q
    /// must be rejected, wherever the offending coefficient sits.
    #[test]
    fn test_decode_pubkey_rejects_out_of_range_coefficient() {
        let mut h = [0u16; FALCON_512_N];

        // All-ones payload: the very first coefficient is 0x3FFF > Q.
        let mut pk = [0xffu8; FALCON_512_PUBKEY_SIZE];
        pk[0] = 9;
        assert!(!FalconVerifier::decode_pubkey(&pk, &mut h));

        // A valid all-zero key, then force one coefficient past Q at a few
        // positions spread across the payload.
        for pos in [1usize, 100, 448, 895] {
            let mut pk = [0u8; FALCON_512_PUBKEY_SIZE];
            pk[0] = 9;
            pk[pos] = 0xff;
            if pos + 1 < FALCON_512_PUBKEY_SIZE {
                pk[pos + 1] = 0xff;
            }
            assert!(
                !FalconVerifier::decode_pubkey(&pk, &mut h),
                "0xffff at byte {pos} should push a coefficient >= Q"
            );
        }

        // The clean key still decodes.
        let mut pk = [0u8; FALCON_512_PUBKEY_SIZE];
        pk[0] = 9;
        assert!(FalconVerifier::decode_pubkey(&pk, &mut h));
    }

    /// A public key of any length other than exactly 897 bytes is rejected
    /// before decoding, including one byte short and one byte long.
    #[test]
    fn test_decode_pubkey_rejects_wrong_length() {
        let mut h = [0u16; FALCON_512_N];
        let full = parseable_pubkey();
        for len in [0usize, 1, 896, 898] {
            let mut buf = [9u8; FALCON_512_PUBKEY_SIZE + 1];
            buf[..full.len().min(len)].copy_from_slice(&full[..full.len().min(len)]);
            assert!(
                !FalconVerifier::decode_pubkey(&buf[..len], &mut h),
                "pubkey of {len} bytes must be rejected"
            );
        }
    }

    #[test]
    fn test_chunked_message_matches_one_shot() {
        // The challenge depends only on the concatenated message, not on
        // chunk boundaries or message length.
        let pk = parseable_pubkey();
        let sig = minimal_parseable_sig();
        let msg = [7u8; 40_000];

        let one_shot = {
            let mut v = Falcon512Verification::new(&pk, &sig).unwrap();
            v.absorb_message(&msg);
            let mut c0 = [0u16; FALCON_512_N];
            Falcon512Verification::squeeze_challenge(v.hasher, &mut c0);
            c0
        };

        for chunk_size in [1usize, 3, 1024, 40_000] {
            let mut v = Falcon512Verification::new(&pk, &sig).unwrap();
            for chunk in msg.chunks(chunk_size) {
                v.absorb_message(chunk);
            }
            let mut c0 = [0u16; FALCON_512_N];
            Falcon512Verification::squeeze_challenge(v.hasher, &mut c0);
            assert_eq!(c0, one_shot, "chunk size {chunk_size}");
        }
    }
}
