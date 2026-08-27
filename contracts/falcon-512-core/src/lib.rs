#![no_std]

//! Falcon-512 verifier core.
//!
//! Pure `no_std` Falcon-512 verification, no soroban-sdk dependency.
//! Shared by the verifier and smart-account contracts.

mod ntt;
pub mod verify;

pub use verify::FalconVerifier;

// Falcon-512 parameters (fixed by the NIST submission).
pub const FALCON_512_LOGN: u32 = 9;
pub const FALCON_512_N: usize = 512;
pub const FALCON_512_PUBKEY_SIZE: usize = 897;

/// Largest signature accepted, in bytes. Compressed runs up to 666 and
/// padded is exactly 666, so this also rejects the 809-byte CT format.
pub const FALCON_SIG_MAX_SIZE: u32 = 666;

/// Minimum size: 1 header byte + 40 nonce bytes + at least one polynomial byte.
pub const FALCON_SIG_MIN_SIZE: u32 = 42;

/// Exact size of a Falcon-512 signature in padded format.
pub const FALCON_512_SIG_PADDED_SIZE: usize = 666;

/// Longest message `verify_512` will hash. The contract entry points cap it
/// too, so oversized input is rejected instead of truncated into a buffer.
pub const FALCON_MAX_MESSAGE_SIZE: usize = 16384;

/// The prime modulus for Falcon ring arithmetic.
pub const Q: u32 = 12289;

/// `N⁻¹` in Montgomery form, for the inverse NTT's final scaling:
/// `R / N mod Q = 2^16 / 2^9 = 128`. Asserted in `ntt.rs`.
pub(crate) const FALCON_512_NI: u32 = 128;

/// Squared L2 norm bound for Falcon-512 signatures.
pub const L2_BOUND_512: u32 = 34034726;
