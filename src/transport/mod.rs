//! GhostLink Transport Layer
//! 
//! Provides multiple transport options:
//! - HTTP/2 gRPC (existing tonic)
//! - QUIC with multiplexed channels
//! - HTTP/3 gRPC-Web compatibility

pub mod grpc;
pub mod manager;

#[cfg(feature = "quic")]
pub mod quic;

#[cfg(feature = "http3")]
pub mod http3;

// Re-exports
pub use manager::{TransportManager, TransportConnection};

use anyhow::Result;
use async_trait::async_trait;
use std::fmt::Debug;

/// Transport abstraction for different protocols
#[async_trait]
pub trait Transport: Send + Sync + Debug {
    type Connection: Send + Sync;
    
    /// Connect to the remote endpoint
    async fn connect(&self, endpoint: &str) -> Result<Self::Connection>;
    
    /// Send request and receive response
    async fn request(&self, conn: &mut Self::Connection, service: &str, method: &str, data: Vec<u8>) -> Result<Vec<u8>>;
    
    /// Close the connection
    async fn close(&self, conn: Self::Connection) -> Result<()>;
}

/// Transport configuration
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TransportConfig {
    pub protocol: TransportProtocol,
    pub tls_enabled: bool,
    pub ipv6_enabled: bool,
    pub keep_alive: bool,
    pub multiplexing: bool,
}

/// Supported transport protocols
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum TransportProtocol {
    /// Traditional HTTP/2 gRPC
    Http2Grpc,
    /// QUIC with custom multiplexing
    Quic,
    /// HTTP/3 with gRPC-Web
    Http3,
    /// Binary protocol over QUIC
    QuicBinary,
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            protocol: if cfg!(feature = "quic") {
                TransportProtocol::Quic
            } else {
                TransportProtocol::Http2Grpc
            },
            tls_enabled: true,
            ipv6_enabled: true,
            keep_alive: true,
            multiplexing: true,
        }
    }
}

/// Service channel identifiers for multiplexing
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ServiceChannel {
    /// GhostChain blockchain operations
    Wallet,
    /// GhostID identity management
    Identity,
    /// ZNS domain resolution
    Dns,
    /// ZVM smart contract execution
    Vm,
}

impl ServiceChannel {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Wallet => "wallet",
            Self::Identity => "identity", 
            Self::Dns => "dns",
            Self::Vm => "vm",
        }
    }
    
    pub fn sni_hostname(&self, base: &str) -> String {
        format!("{}.{}", self.as_str(), base)
    }
}

/// Channel registry for service routing
#[derive(Debug)]
pub struct ChannelRegistry {
    channels: std::collections::HashMap<ServiceChannel, u64>,
}

impl ChannelRegistry {
    pub fn new() -> Self {
        let mut channels = std::collections::HashMap::new();
        channels.insert(ServiceChannel::Wallet, 1);
        channels.insert(ServiceChannel::Identity, 2);
        channels.insert(ServiceChannel::Dns, 3);
        channels.insert(ServiceChannel::Vm, 4);
        
        Self { channels }
    }
    
    pub fn channel_id(&self, service: &ServiceChannel) -> Option<u64> {
        self.channels.get(service).copied()
    }
    
    pub fn service_by_id(&self, id: u64) -> Option<ServiceChannel> {
        self.channels.iter()
            .find(|(_, &channel_id)| channel_id == id)
            .map(|(service, _)| service.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_channel_registry() {
        let registry = ChannelRegistry::new();
        
        assert_eq!(registry.channel_id(&ServiceChannel::Wallet), Some(1));
        assert_eq!(registry.channel_id(&ServiceChannel::Dns), Some(3));
        
        assert_eq!(registry.service_by_id(2), Some(ServiceChannel::Identity));
        assert_eq!(registry.service_by_id(99), None);
    }
    
    #[test]
    fn test_sni_hostnames() {
        assert_eq!(ServiceChannel::Wallet.sni_hostname("ghostbridge.local"), "wallet.ghostbridge.local");
        assert_eq!(ServiceChannel::Dns.sni_hostname("ghostbridge.local"), "dns.ghostbridge.local");
    }
}