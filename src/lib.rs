//! # GhostLink
//! 
//! Rust gRPC client for GhostChain, ZNS, and GhostMesh ecosystem.
//! 
//! GhostLink provides high-performance async gRPC connectivity to:
//! - **GhostChain**: Rust blockchain with ZVM/zEVM smart contract execution
//! - **ZNS**: Zig Name Service for .ghost/.bc domain resolution  
//! - **GhostID**: Identity management system
//! - **Multi-service resolution**: ENS, Unstoppable Domains, etc.
//! 
//! ## Features
//! 
//! - ⚡ **Zero-copy gRPC** over QUIC for maximum performance
//! - 🔐 **Ed25519 cryptography** with secure memory handling
//! - 🌐 **Multi-network domain resolution** (.ghost, .bc, .eth, .crypto)
//! - 🦀 **Native async/await** with Tokio runtime
//! - 📦 **FFI compatibility** with Zig GhostBridge
//! 
//! ## Quick Start
//! 
//! ```rust
//! use ghostlink::{GhostClient, GhostClientConfig};
//! 
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let config = GhostClientConfig::builder()
//!         .endpoint("https://ghostbridge.local:9443")
//!         .with_tls()
//!         .build();
//!     
//!     let client = GhostClient::connect(config).await?;
//!     
//!     // Resolve a .ghost domain
//!     let domain = client.zns().resolve_domain("ghostkellz.ghost").await?;
//!     println!("Resolved: {:?}", domain);
//!     
//!     // Check wallet balance
//!     let balance = client.ghostchain()
//!         .get_balance("ghost1abc123...")
//!         .await?;
//!     println!("MANA balance: {}", balance.get("MANA").unwrap_or(&"0".to_string()));
//!     
//!     Ok(())
//! }
//! ```

pub mod client;
pub mod config;
pub mod crypto;
pub mod error;
pub mod proto;
pub mod cache;
pub mod transport;
pub mod zns_integration;

#[cfg(feature = "zvm")]
pub mod zvm;

// Re-exports for convenience
pub use client::*;
pub use config::*;
pub use error::*;
pub use transport::{TransportManager, TransportConfig, TransportProtocol};
pub use zns_integration::{ZnsIntegration, ZnsConfig, DomainStorage, DomainRecord, DomainOwnership};

/// Current version of GhostLink
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Default GhostBridge endpoint
pub const DEFAULT_ENDPOINT: &str = "https://ghostbridge.local:9443";

/// Supported domain extensions by ZNS
pub const ZNS_DOMAINS: &[&str] = &[".ghost", ".bc", ".zkellz", ".kz"];

/// Supported external name services
pub const EXTERNAL_SERVICES: &[&str] = &["ENS", "UNSTOPPABLE", "HANDSHAKE"];
