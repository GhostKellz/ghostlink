//! Crypto module for GhostLink v0.3.0
//! 
//! This module provides gcrypt-based cryptography for GhostChain ecosystem

pub mod traits;

// Re-export the external gcrypt crate
#[cfg(feature = "gcrypt")]
pub use gcrypt;

#[cfg(not(feature = "gcrypt"))]
compile_error!("GhostLink v0.3.0 requires gcrypt feature");
