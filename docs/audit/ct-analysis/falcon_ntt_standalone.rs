// Standalone, self-contained copy of contracts/falcon-512-core/src/ntt.rs
// flattened so `rustc --emit=asm` can build it without cargo.
//
// PURPOSE: feed to constant-time-analyzer for the Falcon-512 SCF audit
// readiness pack. Threat-model note: in the on-chain Soroban context the
// inputs to verify (pubkey, message, signature) are all PUBLIC, so timing
// side-channels do not leak secrets. We still run CT analysis as a
// hygiene/audit-readiness signal and to surface any DIV/IDIV that would
// hurt host-side determinism or future re-use of this code.

#![allow(dead_code)]
#![crate_type = "lib"]
#![no_std]

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! { loop {} }

const FALCON_512_N: usize = 512;
const Q: u32 = 12289;

// ===== from ntt.rs =====

const Q0I: u32 = 12287;
const R: u32 = 4091;
const R2: u32 = 10952;

// Twiddle tables stubbed: their *contents* are public constants that don't
// change CT analysis of the *operations* below. Use small placeholder
// arrays so rustc still emits the same instruction shapes; the analyzer
// inspects opcodes, not table values.
static GMB: [u16; 512] = [4091; 512];
static IGMB: [u16; 512] = [4091; 512];

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
    for _ in 0..logn {
        ni = field_halve(ni);
    }
    for i in 0..n {
        a[i] = montgomery_mul(a[i] as u32, ni) as u16;
    }
}

pub fn poly_to_montgomery(f: &mut [u16; FALCON_512_N]) {
    for i in 0..FALCON_512_N {
        f[i] = montgomery_mul(f[i] as u32, R2) as u16;
    }
}

pub fn poly_pointwise_mul(f: &mut [u16; FALCON_512_N], g: &[u16; FALCON_512_N]) {
    for i in 0..FALCON_512_N {
        f[i] = montgomery_mul(f[i] as u32, g[i] as u32) as u16;
    }
}

pub fn poly_sub(f: &mut [u16; FALCON_512_N], g: &[u16; FALCON_512_N]) {
    for i in 0..FALCON_512_N {
        f[i] = field_sub(f[i] as u32, g[i] as u32) as u16;
    }
}

pub fn poly_prepare_for_mul(h: &mut [u16; FALCON_512_N]) {
    ntt_forward(h);
    poly_to_montgomery(h);
}

// ===== is_short, the saturate-on-overflow norm check =====

const L2_BOUND_512: u32 = 34034726;

pub fn is_short(s1: &[i16; FALCON_512_N], s2: &[i16; FALCON_512_N]) -> bool {
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

