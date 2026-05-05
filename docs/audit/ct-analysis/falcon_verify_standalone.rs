// Standalone, self-contained copy of contracts/falcon-512-core/src/verify.rs
// + ntt.rs flattened so `rustc --emit=asm` can build it without cargo.
//
// `hash_to_point` is stubbed: it just calls into the well-vetted `sha3` crate
// over PUBLIC inputs (nonce + message), so its CT properties are not part of
// our threat model. We replace it with a deterministic stand-in that still
// produces the same control-flow shape (rejection-sampling loop with
// `while v >= Q { v -= Q; }`).

#![allow(dead_code)]
#![crate_type = "lib"]
#![no_std]

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! { loop {} }

const FALCON_512_N: usize = 512;
const FALCON_512_PUBKEY_SIZE: usize = 897;
const FALCON_SIG_MAX_SIZE: u32 = 666;
const FALCON_SIG_MIN_SIZE: u32 = 42;
const FALCON_MAX_MESSAGE_SIZE: usize = 16384;
const Q: u32 = 12289;
const L2_BOUND_512: u32 = 34034726;
const Q0I: u32 = 12287;
const R: u32 = 4091;
const R2: u32 = 10952;

// Twiddle tables stubbed (contents don't affect CT analysis of the ops).
static GMB: [u16; 512] = [4091; 512];
static IGMB: [u16; 512] = [4091; 512];

// ===== ntt primitives (verbatim from ntt.rs) =====

#[inline(always)]
pub fn field_add(x: u32, y: u32) -> u32 {
    let d = x.wrapping_add(y).wrapping_sub(Q);
    d.wrapping_add(Q & (0u32.wrapping_sub(d >> 31)))
}

#[inline(always)]
pub fn field_sub(x: u32, y: u32) -> u32 {
    let d = x.wrapping_sub(y);
    d.wrapping_add(Q & (0u32.wrapping_sub(d >> 31)))
}

#[inline(always)]
pub fn field_halve(x: u32) -> u32 {
    let x = x.wrapping_add(Q & (0u32.wrapping_sub(x & 1)));
    x >> 1
}

#[inline(always)]
pub fn montgomery_mul(x: u32, y: u32) -> u32 {
    let z = x * y;
    let w = ((z.wrapping_mul(Q0I)) & 0xFFFF).wrapping_mul(Q);
    let z = (z + w) >> 16;
    let z = z.wrapping_sub(Q);
    z.wrapping_add(Q & (0u32.wrapping_sub(z >> 31)))
}

pub fn ntt_forward(a: &mut [u16; FALCON_512_N]) {
    let n = FALCON_512_N;
    let mut t = n;
    let mut m = 1;
    while m < n {
        let ht = t >> 1;
        let mut j1 = 0;
        for i in 0..m {
            let s = GMB[m + i] as u32;
            let j2 = j1 + ht;
            for j in j1..j2 {
                let u = a[j] as u32;
                let v = montgomery_mul(a[j + ht] as u32, s);
                a[j] = field_add(u, v) as u16;
                a[j + ht] = field_sub(u, v) as u16;
            }
            j1 += t;
        }
        t = ht;
        m <<= 1;
    }
}

pub fn ntt_inverse(a: &mut [u16; FALCON_512_N]) {
    let n = FALCON_512_N;
    let logn = 9;
    let mut t = 1;
    let mut m = n;
    while m > 1 {
        let hm = m >> 1;
        let dt = t << 1;
        let mut j1 = 0;
        for i in 0..hm {
            let j2 = j1 + t;
            let s = IGMB[hm + i] as u32;
            for j in j1..j2 {
                let u = a[j] as u32;
                let v = a[j + t] as u32;
                a[j] = field_add(u, v) as u16;
                let w = field_sub(u, v);
                a[j + t] = montgomery_mul(w, s) as u16;
            }
            j1 += dt;
        }
        t = dt;
        m = hm;
    }
    let mut ni = R;
    for _ in 0..logn { ni = field_halve(ni); }
    for i in 0..n { a[i] = montgomery_mul(a[i] as u32, ni) as u16; }
}

pub fn poly_to_montgomery(f: &mut [u16; FALCON_512_N]) {
    for i in 0..FALCON_512_N { f[i] = montgomery_mul(f[i] as u32, R2) as u16; }
}

pub fn poly_pointwise_mul(f: &mut [u16; FALCON_512_N], g: &[u16; FALCON_512_N]) {
    for i in 0..FALCON_512_N { f[i] = montgomery_mul(f[i] as u32, g[i] as u32) as u16; }
}

pub fn poly_sub(f: &mut [u16; FALCON_512_N], g: &[u16; FALCON_512_N]) {
    for i in 0..FALCON_512_N { f[i] = field_sub(f[i] as u32, g[i] as u32) as u16; }
}

pub fn poly_prepare_for_mul(h: &mut [u16; FALCON_512_N]) {
    ntt_forward(h);
    poly_to_montgomery(h);
}

// ===== verify.rs proper =====

pub struct FalconVerifier;

impl FalconVerifier {
    pub fn verify_512(pubkey: &[u8], message: &[u8], signature: &[u8]) -> bool {
        if pubkey.len() != FALCON_512_PUBKEY_SIZE { return false; }
        const FALCON_512_LOGN: u8 = 9;
        if pubkey[0] != FALCON_512_LOGN { return false; }
        if message.len() > FALCON_MAX_MESSAGE_SIZE { return false; }
        let sig_len = signature.len();
        if sig_len < FALCON_SIG_MIN_SIZE as usize || sig_len > FALCON_SIG_MAX_SIZE as usize { return false; }
        let sig_header = signature[0];
        if (sig_header & 0x0F) != FALCON_512_LOGN { return false; }
        let fmt = sig_header & 0xF0;
        if fmt != 0x20 && fmt != 0x30 { return false; }

        let mut h = [0u16; FALCON_512_N];
        if !Self::decode_pubkey(pubkey, &mut h) { return false; }

        let nonce = &signature[1..41];
        let mut s2 = [0i16; FALCON_512_N];
        let sig_data = &signature[41..];
        let decoded_len = Self::decode_sig_compressed(sig_data, &mut s2);
        if decoded_len == 0 { return false; }

        for i in decoded_len..sig_data.len() {
            if sig_data[i] != 0 { return false; }
        }

        let mut c0 = [0u16; FALCON_512_N];
        Self::hash_to_point(nonce, message, &mut c0);

        poly_prepare_for_mul(&mut h);
        Self::verify_raw_512(&c0, &s2, &h)
    }

    pub fn verify_raw_512(
        c0: &[u16; FALCON_512_N],
        s2: &[i16; FALCON_512_N],
        h: &[u16; FALCON_512_N],
    ) -> bool {
        let mut tt = [0u16; FALCON_512_N];
        for i in 0..FALCON_512_N {
            let w = s2[i] as i32;
            let w = if w < 0 { (w + Q as i32) as u32 } else { w as u32 };
            tt[i] = w as u16;
        }
        ntt_forward(&mut tt);
        poly_pointwise_mul(&mut tt, h);
        ntt_inverse(&mut tt);
        poly_sub(&mut tt, c0);

        let mut s1 = [0i16; FALCON_512_N];
        for i in 0..FALCON_512_N {
            let w = tt[i] as i32;
            let w = if w > (Q as i32 / 2) { w - Q as i32 } else { w };
            s1[i] = w as i16;
        }
        Self::is_short(&s1, s2)
    }

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
        s |= 0u32.wrapping_sub(ng >> 31);
        s <= L2_BOUND_512
    }

    pub fn decode_pubkey(pubkey: &[u8], h: &mut [u16; FALCON_512_N]) -> bool {
        if pubkey.len() != FALCON_512_PUBKEY_SIZE { return false; }
        if pubkey[0] != 9 { return false; }
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
                if w >= Q { return false; }
                h[u] = w as u16;
                u += 1;
            }
        }
        if (acc & ((1u32 << acc_len) - 1)) != 0 { return false; }
        true
    }

    fn decode_sig_compressed(data: &[u8], s2: &mut [i16; FALCON_512_N]) -> usize {
        let mut acc: u32 = 0;
        let mut acc_len: u32 = 0;
        let mut v = 0;
        for u in 0..FALCON_512_N {
            if v >= data.len() { return 0; }
            acc = (acc << 8) | (data[v] as u32);
            v += 1;
            let b = acc >> acc_len;
            let sign = b & 128;
            let mut m = (b & 127) as u32;
            loop {
                if acc_len == 0 {
                    if v >= data.len() { return 0; }
                    acc = (acc << 8) | (data[v] as u32);
                    v += 1;
                    acc_len = 8;
                }
                acc_len -= 1;
                if ((acc >> acc_len) & 1) != 0 { break; }
                m += 128;
                if m > 2047 { return 0; }
            }
            if sign != 0 && m == 0 { return 0; }
            s2[u] = if sign != 0 { -(m as i16) } else { m as i16 };
        }
        if (acc & ((1u32 << acc_len) - 1)) != 0 { return 0; }
        v
    }

    // STUB: real impl uses sha3::Shake256 over PUBLIC (nonce, message). We
    // preserve the rejection-sampling shape so the analyzer sees the
    // post-fix mod-Q reduction. The fake "xof" stream is an LCG, which is
    // enough to drive the same control flow.
    //
    // Mirrors the F-001 mitigation in contracts/falcon-512-core/src/verify.rs:
    // bounded conditional subtractions instead of `while v >= Q { v -= Q; }`.
    fn hash_to_point(nonce: &[u8], message: &[u8], c0: &mut [u16; FALCON_512_N]) {
        let mut counter: u32 = 0;
        for b in nonce.iter().chain(message.iter()) {
            counter = counter.wrapping_add(*b as u32);
        }

        let mut remaining = FALCON_512_N;
        let mut idx = 0;
        while remaining > 0 {
            counter = counter.wrapping_mul(1103515245).wrapping_add(12345);
            let w = counter & 0xFFFF;
            const ACCEPT_THRESHOLD: u32 = 5 * Q;
            if w < ACCEPT_THRESHOLD {
                let mut v = w;
                v = field_sub(v, Q);
                v = field_sub(v, Q);
                v = field_sub(v, Q);
                v = field_sub(v, Q);
                c0[idx] = v as u16;
                idx += 1;
                remaining -= 1;
            }
        }
    }
}
