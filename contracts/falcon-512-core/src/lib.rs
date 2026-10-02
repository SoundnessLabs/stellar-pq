#![no_std]

//! Falcon-512 verifier core.
//!
//! Pure `no_std` Falcon-512 verification, no soroban-sdk dependency.
//! Shared by the verifier and smart-account contracts.

mod ntt;
pub mod verify;

pub use verify::{Falcon512Verification, FalconVerifier};

// Falcon-512 parameters (fixed by the NIST submission).
pub const FALCON_512_LOGN: u32 = 9;
pub const FALCON_512_N: usize = 512;
pub const FALCON_512_PUBKEY_SIZE: usize = 897;

/// Largest accepted signature: the maximum length of a variable-length
/// compressed Falcon-512 signature. Also rejects the 809-byte constant-time
/// format, which has no decoder here.
pub const FALCON_SIG_MAX_SIZE: u32 = 752;

/// Smallest decodable signature: 1 header byte + 40 nonce bytes + 576 body
/// bytes (512 coefficients at no fewer than 9 bits each).
pub const FALCON_SIG_MIN_SIZE: u32 = 617;

/// Exact size of a Falcon-512 signature in padded format.
pub const FALCON_512_SIG_PADDED_SIZE: usize = 666;

/// The prime modulus for Falcon ring arithmetic.
pub const Q: u32 = 12289;

/// `N⁻¹` in Montgomery form, for the inverse NTT's final scaling:
/// `R / N mod Q = 2^16 / 2^9 = 128`. Asserted in `ntt.rs`.
pub(crate) const FALCON_512_NI: u32 = 128;

/// Squared L2 norm bound for Falcon-512 signatures.
pub const L2_BOUND_512: u32 = 34034726;
