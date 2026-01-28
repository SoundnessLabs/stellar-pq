//! Falcon-512 Signature Verification
//!
//! # Overview
//!
//! Falcon is a lattice-based post-quantum signature scheme built on the
//! "hash-and-sign" paradigm using NTRU lattices. It was selected by NIST
//! for standardization as a post-quantum digital signature algorithm.
//!
//! # Verification Algorithm
//!
//! Given a public key `h`, message `m`, and signature `(r, s)`:
//!
//! 1. **Hash to point**: Compute challenge c = H(r || m) mod q
//!    where H is SHAKE256 with rejection sampling to get uniform elements in Z_q
//!
//! 2. **Recover s1**: Compute s1 = c - s·h mod q
//!    where multiplication is in the ring Z_q[X]/(X^n + 1)
//!
//! 3. **Verify norm**: Check that ||(s1, s)|| ≤ bound
//!    The signature is valid iff the L2 norm of (s1, s) is small enough
//!
//! # Security
//!
//! The security relies on the hardness of the Short Integer Solution (SIS)
//! problem over NTRU lattices. A valid signature proves knowledge of a
//! short vector in the lattice, which can only be efficiently computed
//! with the secret key.
//!
//! # References
//!
//! - Falcon specification: <https://falcon-sign.info/falcon.pdf>
//! - NIST PQC: <https://csrc.nist.gov/projects/post-quantum-cryptography>

use crate::ntt::{ntt_forward, ntt_inverse, poly_pointwise_mul, poly_prepare_for_mul, poly_sub};
use crate::{FALCON_512_N, FALCON_512_PUBKEY_SIZE, L2_BOUND_512, Q};

/// Falcon-512 signature verifier.
///
/// This struct provides static methods for signature verification.
/// It is stateless and all methods can be called without instantiation.
pub struct FalconVerifier;

impl FalconVerifier {
    /// Verifies a Falcon-512 signature.
    ///
    /// # Arguments
    /// * `pubkey` - 897-byte Falcon-512 public key
    /// * `message` - The message that was signed (arbitrary length)
    /// * `signature` - The signature bytes (supports multiple formats)
    ///
    /// # Returns
    /// `true` if the signature is valid, `false` otherwise.
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

        // Step 2: Parse signature header and determine format
        // Minimum signature size: 1 (header) + 40 (nonce) + 1 (at least one byte)
        if signature.len() < 42 {
            return false;
        }
        let sig_header = signature[0];
        // Low nibble must be logn = 9
        if (sig_header & 0x0F) != FALCON_512_LOGN {
            return false;
        }
        // High nibble indicates format:
        // 0x50 = CT (constant-time), 0x30 = compressed, 0x20 = padded
        let is_ct = (sig_header & 0xF0) == 0x50;
        let is_compressed = (sig_header & 0xF0) == 0x30;
        let is_padded = (sig_header & 0xF0) == 0x20;
        if !is_ct && !is_compressed && !is_padded {
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
        let decoded_len = if is_ct {
            Self::decode_sig_ct(sig_data, &mut s2)
        } else {
            // Both compressed and padded use the same decoding algorithm
            Self::decode_sig_compressed(sig_data, &mut s2)
        };

        if decoded_len == 0 {
            return false;
        }

        // Padded format: remaining bytes after encoded data must be zero
        if !is_ct && decoded_len < sig_data.len() {
            for i in decoded_len..sig_data.len() {
                if sig_data[i] != 0 {
                    return false;
                }
            }
        }

        // Step 6: Hash message to challenge polynomial c0
        let mut c0 = [0u16; FALCON_512_N];
        Self::hash_to_point(nonce, message, &mut c0);

        // Step 7: Prepare public key and verify
        // Convert h to NTT domain and Montgomery form for efficient multiplication
        poly_prepare_for_mul(&mut h);

        Self::verify_raw_512(&c0, &s2, &h)
    }

    pub fn verify_raw_512(
        c0: &[u16; FALCON_512_N],
        s2: &[i16; FALCON_512_N],
        h: &[u16; FALCON_512_N],
    ) -> bool {
        let mut tt = [0u16; FALCON_512_N];

        // Step 1: Convert s2 from signed to unsigned representation mod q
        // s2 values are in range [-q/2, q/2], convert to [0, q-1]
        for i in 0..FALCON_512_N {
            let w = s2[i] as i32;
            // If negative, add q to get equivalent positive value mod q
            let w = if w < 0 {
                (w + Q as i32) as u32
            } else {
                w as u32
            };
            tt[i] = w as u16;
        }

        // Step 2: Compute s2·h in the ring Z_q[X]/(X^n + 1)
        // Using NTT: multiply(a, b) = INTT(NTT(a) ⊙ NTT(b))
        // Since h is already in NTT form, we only need to transform tt
        ntt_forward(&mut tt); // tt = NTT(s2)
        poly_pointwise_mul(&mut tt, h); // tt = NTT(s2) ⊙ NTT(h) = NTT(s2·h)
        ntt_inverse(&mut tt); // tt = s2·h

        // Step 3: Compute s1 = c0 - s2·h  (equivalently, -s1 = s2·h - c0)
        // Note: we compute tt = tt - c0, which gives us -s1
        poly_sub(&mut tt, c0);

        // Step 4: Convert -s1 back to signed representation for norm computation
        // Values in [0, q-1] are converted to [-q/2, q/2] (centered representation)
        // Then negate to get s1 (but for norm, sign doesn't matter)
        let mut s1 = [0i16; FALCON_512_N];
        for i in 0..FALCON_512_N {
            let w = tt[i] as i32;
            // Center: if w > q/2, interpret as negative (w - q)
            let w = if w > (Q as i32 / 2) { w - Q as i32 } else { w };
            // The result is -s1, but ||s1|| = ||-s1||, so this is fine for norm check
            s1[i] = w as i16;
        }

        // Step 5: Verify that the signature vector (s1, s2) is short enough
        Self::is_short(&s1, s2)
    }

    /// Verifies that ||(s1, s2)||² ≤ L2_BOUND_512.
    fn is_short(s1: &[i16; FALCON_512_N], s2: &[i16; FALCON_512_N]) -> bool {
        let mut s: u32 = 0; // Running sum of squared coefficients
        let mut ng: u32 = 0; // Overflow detector (accumulates sign bits)

        for i in 0..FALCON_512_N {
            // Add s1[i]² to the sum
            let z1 = s1[i] as i32;
            s = s.wrapping_add((z1 * z1) as u32);
            ng |= s; // Capture if sum went negative (overflow)

            // Add s2[i]² to the sum
            let z2 = s2[i] as i32;
            s = s.wrapping_add((z2 * z2) as u32);
            ng |= s; // Capture if sum went negative (overflow)
        }

        // If overflow occurred (ng has sign bit set), force s to max value
        // This ensures we reject potentially forged signatures that overflowed
        // Expression: if ng bit 31 is set, OR s with 0xFFFFFFFF; else OR with 0
        s |= 0u32.wrapping_sub(ng >> 31);

        // The squared L2 norm must not exceed the bound
        // ||(s1, s2)||² = Σ(s1[i]² + s2[i]²) ≤ L2_BOUND_512
        s <= L2_BOUND_512
    }

    /// Decodes a Falcon-512 public key from its packed binary format (14 bits per coefficient, MSB-first).
    pub fn decode_pubkey(pubkey: &[u8], h: &mut [u16; FALCON_512_N]) -> bool {
        if pubkey.len() != FALCON_512_PUBKEY_SIZE {
            return false;
        }
        if pubkey[0] != 9 {
            // logn = 9 for Falcon-512
            return false;
        }

        let data = &pubkey[1..]; // Skip header byte
        let mut acc: u32 = 0; // Bit accumulator (up to 32 bits)
        let mut acc_len = 0; // Number of valid bits in accumulator
        let mut u = 0; // Output coefficient index
        let mut buf_idx = 0; // Input byte index

        // Extract 512 coefficients, each 14 bits
        while u < FALCON_512_N {
            // Load next byte into accumulator (MSB-first)
            acc = (acc << 8) | (data[buf_idx] as u32);
            buf_idx += 1;
            acc_len += 8;

            // Extract a coefficient when we have at least 14 bits
            if acc_len >= 14 {
                acc_len -= 14;
                // Extract top 14 bits (MSB-first packing)
                let w = (acc >> acc_len) & 0x3FFF; // 0x3FFF = 14 bits mask
                                                   // Coefficient must be in valid range [0, q-1]
                if w >= Q {
                    return false;
                }
                h[u] = w as u16;
                u += 1;
            }
        }

        // Any leftover bits must be zero (proper padding)
        if (acc & ((1u32 << acc_len) - 1)) != 0 {
            return false;
        }

        true
    }

    /// Decodes a signature from compressed format. Returns bytes consumed, or 0 on error.
    fn decode_sig_compressed(data: &[u8], s2: &mut [i16; FALCON_512_N]) -> usize {
        let mut acc: u32 = 0; // Bit accumulator
        let mut acc_len: u32 = 0; // Valid bits in accumulator
        let mut v = 0; // Input byte index

        for u in 0..FALCON_512_N {
            // Read next byte containing sign bit and low 7 bits
            if v >= data.len() {
                return 0;
            }
            acc = (acc << 8) | (data[v] as u32);
            v += 1;

            // Extract the 8 bits we just added
            let b = acc >> acc_len;
            let sign = b & 128; // Bit 7: sign (1 = negative)
            let mut m = (b & 127) as u32; // Bits 0-6: low 7 bits of |value|

            // Decode unary high part: count zeros until we hit a 1
            loop {
                if acc_len == 0 {
                    // Need more bits
                    if v >= data.len() {
                        return 0;
                    }
                    acc = (acc << 8) | (data[v] as u32);
                    v += 1;
                    acc_len = 8;
                }
                acc_len -= 1;

                if ((acc >> acc_len) & 1) != 0 {
                    // Hit the terminating 1 bit
                    break;
                }
                // Each 0 bit adds 128 to the magnitude
                m += 128;
                if m > 2047 {
                    // Maximum allowed magnitude exceeded
                    return 0;
                }
            }

            // "-0" is forbidden (use "+0" instead)
            if sign != 0 && m == 0 {
                return 0;
            }

            // Apply sign and store
            s2[u] = if sign != 0 { -(m as i16) } else { m as i16 };
        }

        // Any leftover bits in accumulator must be zero
        if (acc & ((1u32 << acc_len) - 1)) != 0 {
            return 0;
        }

        v
    }

    /// Decodes a signature from constant-time (CT) format (12 bits per coefficient). Returns bytes consumed, or 0 on error.
    fn decode_sig_ct(data: &[u8], s2: &mut [i16; FALCON_512_N]) -> usize {
        const BITS: u32 = 12; // Bits per coefficient for Falcon-512
        let n = FALCON_512_N;
        let in_len = ((n as u32 * BITS) + 7) / 8; // Total bytes needed

        if data.len() < in_len as usize {
            return 0;
        }

        let mut acc: u32 = 0; // Bit accumulator
        let mut acc_len: u32 = 0; // Valid bits in accumulator
        let mask1 = (1u32 << BITS) - 1; // 0xFFF: mask for 12 bits
        let mask2 = 1u32 << (BITS - 1); // 0x800: sign bit position
        let mut buf_idx = 0;
        let mut u = 0;

        while u < n {
            // Load next byte (MSB-first packing)
            acc = (acc << 8) | (data[buf_idx] as u32);
            buf_idx += 1;
            acc_len += 8;

            // Extract coefficients while we have enough bits
            while acc_len >= BITS && u < n {
                acc_len -= BITS;
                let mut w = (acc >> acc_len) & mask1;

                // Sign extension for negative values (two's complement)
                // If bit 11 is set, the value is negative; extend sign to full u32
                if (w & mask2) != 0 {
                    w |= !mask1; // Set all upper bits to 1
                }

                if w == (0u32.wrapping_sub(mask2) & mask1) {
                    return 0;
                }

                s2[u] = w as i16;
                u += 1;
            }
        }

        // Any leftover bits in accumulator must be zero
        if (acc & ((1u32 << acc_len) - 1)) != 0 {
            return 0;
        }

        in_len as usize
    }

    /// Hashes nonce || message to a challenge polynomial using SHAKE256 with rejection sampling.
    fn hash_to_point(nonce: &[u8], message: &[u8], c0: &mut [u16; FALCON_512_N]) {
        use sha3::{
            digest::{ExtendableOutput, Update, XofReader},
            Shake256,
        };

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
                let mut v = w;
                while v >= Q {
                    v -= Q;
                }
                c0[idx] = v as u16;
                idx += 1;
                remaining -= 1;
            }
        }
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

        // Small values should pass
        for i in 0..FALCON_512_N {
            s1[i] = ((i % 10) as i16) - 5;
            s2[i] = ((i % 10) as i16) - 5;
        }
        assert!(FalconVerifier::is_short(&s1, &s2));
    }

    #[test]
    fn test_pubkey_decode_header() {
        let mut h = [0u16; FALCON_512_N];

        // Wrong header should fail
        let bad_pk = [8u8; FALCON_512_PUBKEY_SIZE]; // Wrong logn
        assert!(!FalconVerifier::decode_pubkey(&bad_pk, &mut h));

        // Too short should fail
        let short_pk = [9u8; 100];
        assert!(!FalconVerifier::decode_pubkey(&short_pk, &mut h));
    }

    #[test]
    fn test_cross_verify_with_c_bindings() {
        // Generated with seed: 2a31383f464d545b626970777e858c939aa1a8afb6bdc4cbd2d9e0e7eef5fc030a11181f262d343b424950575e656c73
        let pubkey_hex = "0902c671f64d92df6c446a63f5061d73fab61be667e74db66752251102a105922a6fe56a7b3a48196bafc22de2275600dfd8b4149842bf0a5f3b7df4e1f6608f5394aae63e918a7bc492426a62e64d1873fb72c020a3c6be3a9295bc29aaf1c351267c6b00ffc2aa003f64fa9133628b2996b4327b7ee6366b9acb4067e30715fcf68273e04880a453eb468eff0a8d563af3235c6cae44984e8ed8911a34222ed6ec3274f8c491893a9f74ab6b1d67daa0083eb666c098acd4745aa208362a8e14b906437c2cc1ca044a5b903724c9066cd662a622cc38165a4d91322e193c48d12b5e20977bdb4816d6c1aa6a8a4118705029de6fd8723d3ca408ea0c296ceba31e903fbbc9dd60b0c1ca74a1a995d3cf449518815ab29f227d257491f758630484e3a6e36c83008069e538e3e65272f0a5440d8e6998e516e1a5390045b986c24975567c8ce8eae5b29916797516c04f69085a0112e9295b8d96e878410e12507ff9ba012c1f352a84be660a467a95321c8947b07440d58ac215b9cc2ee3d2e5c5af1e9044aed41e94305390c5110c27e5ee3a620c898f90671911e58f75c1085551618b5b4443e3e3527955357007d8696bb59e0d625f248f513de19916a093b43ef00b8d8211a3801874c9687b792e9588a59622b748ae5adc1ff98d0040506cd7c720e64123631bdd70628fa2534bf1094d92b82f2d5fb586d715dee362ac6cd33268a3249669c853fde1643222968b072d07be36764962d3c6a0550038bce88219585357616fb63e701f923ae986247850c7c5ad74bd3e8cf342623cabb8e467fe55a1103975f9af1235995ca30bfe8ea9af0619a2995a283e5cd49bae9a9737201d152d253f50e526d55c59ae8675eeca051bbf44f4c9e530cdfca2c0b192cf8f779a85de921e06a48b71ac1170af6c50c16d3328149c5a682ceb18a01f1de6207319d54a5f205ff82d8ae5536a924721e68c83b82d47dbc0854db1d392e055e2702e8a9401e200616d43aa8c25075712b1f0274f097cf51423685a051d35afb9a9d3217e365e95d95bff5a31e8320bc423bc5052d1ec04739005090a8e6f95b53014129aa30b937cf157c6d0bfa77263e3a2d435954e30f790a4ca062e7d17aa2d52a5a4aec83108c12e24fcf97a9119554eadf26b5447b1d0d7e0484b58122a1b68aa15bd3e5db8927b4240785966f5cba8784b752d723a86c13c005ec57fe22bb18afd43d1093d232ac8b09f920d2a8cbec54e56f93edd6dd235a1ef";
        let pubkey = hex::decode(pubkey_hex).expect("Invalid pubkey hex");

        // falcon512_0: "Hello, Falcon!" (0x48656c6c6f2c2046616c636f6e21)
        let sig_0 = "399e11dbc7c5328dbdd260d989a2e58c18e698b7ee2c94235312fabbae38c24058d1dd43fe030b3f2583c4e2dcc445a1c76624aa2e2a0527fd6a6398a521b5c6d6391c9caf0729893d087fd672d38c0232e9ff98e313bebbe069e93a371de31f7e6c2905544a210fa3363aa23ce2418803d6b1fee2a275f3e8f2d6585ffa30ac2bf639345d78b1da59a2c1187a3f79190b3b788537993873fb9755bc8dd7723fbbefeaa5fd89a25298609f4f7ec5988292c4a976f833d6f312eaea792e53d9b49b31bd5bd20ee4bef5a887359d5c71e86e4d14c56848d23d65f2dd65775d2a0f47549d6289b1ab4897142aa12d7424ac17c4ce1ba84ea6094f448e0e57c53ea64521596220cdef215ad311b6d57723de37438ebae27d38fae24e81eefc98a88e9ea39d5418a53b9fd4912624ae4f81e219759ecb1759b6bee72de06285432f3c7c310c0b867b5afdff29658f45610854fbdecb1b04524cc0b6d16edccb37dace29db3becd6779ded4caa6f5a277b852d11ad2a46b8d731c6ef694c39bb3772532bc0f99757ab4ce76ae25d646c7dd8eecdee84b3b3040797975ff39782a11b8eb65507fe415c5a39b6862949f6eeb1c53c996f14be765154c9b239230990621e52513b5da72bcfc6a48433cefcb843a1127a2335d559161f9db54eb798bb15c65d4ad073f0d9f52cc6cba122ed824726758226cbe41d340bd495c131f891eecb1837b9df7e66e8695355fd5853e736d4bedc224063f08ac33b6e9bd5e21ad8ec52a2b14e225299399a26287f28c4d8a3567f3a685fa5dfa2f94ac8476b38793b7d4fd711bafb5ebeac3f65e70466a51455cba3946a6688e6cb14ef1386143efc7638f655910f751bd4ecc5168a142495937fb5afb5e84698a35d829ef83a387336c622f1b8b3bab64d9eca1a0000000000000000000000000000";
        let sig_0_bytes = hex::decode(sig_0).expect("Invalid sig hex");
        assert!(
            FalconVerifier::verify_512(&pubkey, b"Hello, Falcon!", &sig_0_bytes),
            "falcon512_0: 'Hello, Falcon!' verification failed"
        );

        // falcon512_1: "Test message for cross-implementation verification"
        let sig_1 = "399e11dbc7c5328dbdd260d989a2e58c18e698b7ee2c94235312fabbae38c24058d1dd43fe030b3f2591405b77214f2bd4393a17b9c35ef79a4ce21eda5ef85a912da064952654634e34294e4b2dcfdc11257ad245db17ca89445ec4c3871ada38484bf8a2a96829c16edf3d335bb7e96438bbb42b81a490e849d0fc72b2d13eaa152e2549375acd1f1cd6fa9c934987574ac9d2f58cd4e6e5ce5ad91ecc9218d210f5cf173235b9b8e775fae71fc41560c7ab344fc489803372ea7da65b01b5678655d55e1465f218a0344831e968b78dfa696838c50731346792e306b54d64d28675d2c2c65f46caee820edf265bd8dff8fca8e10a4755797751fd643db8b35e68f7546e1292640af0daab7b641ea1f364e98ada0d85441b4ecdd7c947da6d965bb3e7c9bf469ac4c19c3a3cd949385d38aee31bacb0ed3bd65caad0a6dae9ead699b3bef43b4f33aaf34375d7be1f813ac11b26ca7f8179db36cb587a13e4a4f5382cbe65264d99be82daf8d9e4b6149a49d6c5eb14a76642db163912c7e4c7140d07073995d920eddc667f538ed9ed3851cc8cdda11c7d8d9bbcfe4e62f7d35fa561f2f2522850b9fe6a02a4b046596c8a710580b5843f971edac9547ca3aea815393669b6d952082f6be3245f19a8e3c2b97664c8e919ae9972c59acf6d2d5e6e28cf11654f4a32e764de3b295c372101cafbfaf1bf76651c4e99e1096e12f9747635bfa94098c529a36d85b664e7cfd319170a2ff1641a78ba79497970be9fe47ea3a2e660499e73273378377417f6327359b430d1b7ed38aab2bdea3fab0b9d281e8df529b8cf286cf18c506e6ca1b229f8a81c873486cf23f58105d7ec4aa4a2d255b16d9ac0bc7ad7caa7f53c26edd7d99848b34a360cc25eae5bb1cb8b150731216f742bbc2fe9bd6421b9c4000000000000000000";
        let sig_1_bytes = hex::decode(sig_1).expect("Invalid sig hex");
        assert!(
            FalconVerifier::verify_512(
                &pubkey,
                b"Test message for cross-implementation verification",
                &sig_1_bytes
            ),
            "falcon512_1: cross-impl verification failed"
        );

        // falcon512_2: empty message
        let sig_2 = "399e11dbc7c5328dbdd260d989a2e58c18e698b7ee2c94235312fabbae38c24058d1dd43fe030b3f25bbafe2f1767a33929d6cbe92c46e1666c9e36c314cec389f476cf63a639a984e46fd63e4ec65fae59abb3e4570d016d67b6f52bdff6eef1d24d0a20869518d31667dabbd77b3063317b8ce5fa7b94eab750a929066395fbe54fd8897bfe517e12826813c94d2ad9e384391992d8da2851430ba8c0e9d8d547a7525827f0382a13c4e1aab19e98957810975a0d822992439fc03dcd5f9bcb1971e30d87234ec67462dc6d75b5e9a0db6f53f675e5c522951640d675ed096bdfe8889a4b2686829b21eeec48c35662bac39b8e723edaf71920519dbe357366c3c2a7272f192d21315fc7c7749e993aae132cb29dcd41b197e7997f7652c971824438351984c151d06192177319f9da62be786966e495695c4e82d99cb9fcd66e86a3e84d25c56a2c8ea4fddf2ab9c2c1c53acd597aee372867db08fb4f3b92e569027115a475dfed273599a51ed460d35ca7be3f99c22018da0b9c976e20fce8714d71687dfce50588336aeb6d48f926e81b8e9a5aaa9f2702c3bd5baf3b3a9e28956a2118fab99e8ff2e16b44856c83953e6273ce46655a3460ae996ba4520a7a722be6b1a0628802f9c4822b7a27ee529a419fa9d6a767d643fd1a9eea66bf68efd4f92a5f005d48323150b2e5d9379147218a0bb7853067af0faac2cbd3a879d3f87850935b0056bc703bdc3ae33fb2cff849d4e59af2b44ee76316a572d45155d7aaecaf2b3fbe271de6cb8e7063c9ad53ca428fa6f60b3a510a260fd091c810a605ef652e542c633deb1c0b31a662b61a2c3a00a6f8bbcc8582db5861e45998f6b60142ab4fa6ade67497c6d8f65f5c604e7efab1cc9ca79e38ddaa7b72b01ddd9ef1318f61e00000000000000000000000000000000";
        let sig_2_bytes = hex::decode(sig_2).expect("Invalid sig hex");
        let empty_msg: &[u8] = b"";
        assert!(
            FalconVerifier::verify_512(&pubkey, empty_msg, &sig_2_bytes),
            "falcon512_2: empty message verification failed"
        );

        // falcon512_3: binary data 0x00..0x63 (100 bytes)
        let sig_3 = "399e11dbc7c5328dbdd260d989a2e58c18e698b7ee2c94235312fabbae38c24058d1dd43fe030b3f2584574f5f13cef9416249e48bd1e249b63af2728c4871e45b21a271d0432b256616b63300cce2dce131833da501e2c7eb7455dd03875579e2c89b553ebd2b9274d19a56f2c4093875b8924ebb1e6b13b61d0868dc5e2aa9a0dfbf0a9f8fa915e238586dc289068d3d32d8269a8e715f99e99072b2d3f306dea87cbcca090353a12dcb3672b3ecda9a9fc6dbdae9e8a5254357384fa8cf6b052084d67fae0479d187e3a3e85a24deb948ecfa8ace45f88d7ed2f50aa4b43a4d65d5c161556bc507debbe9fe9a9c85074688658f84e943e5ffa259af6d5e999dc3f369345d82957f1f6dab8f2d8316c48d21628cd61341313124133291c563892262dca51a95a18f6e77c503d78984dc180617694c49e96b0a95b3a9eee16ab89cae13fb5fa62c824bf776a55f9bd8fff777ba24817d9eca896569077aa416fa16f5ba64ef542429d55cfe3b6410a9525e8fe4655774b3648620b7315cb6cd232a15b358beca70e40e01df74a5bcc74f3066a1ad1cf39eb972fa0bec360beeae2a7913ea4e94033369c9264a7259677aa51c23fd0ec617fe96370cff654541a3a2fc51335f2ebe65f1373a2479fb23066bcf9e6b1d2acf0fdd114c5249560e58311c698c03abefa12d570466286b9ca993837e5d6bfcadb14f7498736b5d22f86ed25ddeab3509a1aa39442f51ae9faeac4a81a573abff6b66253cad32dd774244c62ab74e13226f91b314e5b39daa0237bed0ba0a0ecb356cf27f2ac9b483e0f4c4e3a605ee4f7aba4e567674e7fca18e6a268944a82cdaeaec73bde42b9adab7ac5ad2b294778e8da0ba34e97555ce69bbbffbd640a025d5ba449e98286c4350c7346e4f2935adf00e9628f7c00000000000000000000000";
        let sig_3_bytes = hex::decode(sig_3).expect("Invalid sig hex");
        let binary_msg: [u8; 100] = core::array::from_fn(|i| i as u8);
        assert!(
            FalconVerifier::verify_512(&pubkey, &binary_msg, &sig_3_bytes),
            "falcon512_3: binary data verification failed"
        );

        // Negative tests - wrong messages should fail
        assert!(
            !FalconVerifier::verify_512(&pubkey, b"Wrong message", &sig_0_bytes),
            "Wrong message should fail"
        );
        assert!(
            !FalconVerifier::verify_512(&pubkey, b"Hello, Falcon!", &sig_1_bytes),
            "Mismatched signature should fail"
        );
        assert!(
            !FalconVerifier::verify_512(&pubkey, b"Hello, Falcon!", &sig_2_bytes),
            "Empty msg signature with 'Hello, Falcon!' should fail"
        );
    }
}
