#![no_std]

//! Falcon-512 verifier core.
//!
//! Pure, `no_std`, soroban-sdk-free implementation of Falcon-512 signature
//! verification. Shared by `soroban-falcon-verifier` and
//! `soroban-falcon-smart-account` so that crypto fixes land in one place.

mod ntt;
pub mod verify;

pub use verify::FalconVerifier;

// Falcon-512 parameters (fixed by the NIST submission).
pub const FALCON_512_LOGN: u32 = 9;
pub const FALCON_512_N: usize = 512;
pub const FALCON_512_PUBKEY_SIZE: usize = 897;

/// Maximum size in bytes of a Falcon-512 signature that this verifier accepts.
///
/// Compressed signatures are variable-length up to 666 bytes; padded signatures
/// are exactly 666 bytes. The 666-byte cap deliberately forbids the 809-byte
/// constant-time (CT) format.
pub const FALCON_SIG_MAX_SIZE: u32 = 666;

/// Minimum size: 1 header byte + 40 nonce bytes + at least one polynomial byte.
pub const FALCON_SIG_MIN_SIZE: u32 = 42;

/// Exact size of a Falcon-512 signature in padded format.
pub const FALCON_512_SIG_PADDED_SIZE: usize = 666;

/// Maximum message length that `verify_512` will hash.
///
/// Enforced at the contract entry point to rule out buffer truncation; matches
/// the largest message size the on-chain wrapper is willing to allocate.
pub const FALCON_MAX_MESSAGE_SIZE: usize = 16384;

/// The prime modulus for Falcon ring arithmetic.
pub const Q: u32 = 12289;

/// Squared L2 norm bound for Falcon-512 signatures.
pub const L2_BOUND_512: u32 = 34034726;
