//! HTTP/2 gRPC Transport (existing implementation)

use super::{Transport, TransportConfig};
use anyhow::Result;
use async_trait::async_trait;
use tonic::transport::{Channel, Endpoint};

/// HTTP/2 gRPC transport using tonic
#[derive(Debug)]
pub struct GrpcTransport {
    config: TransportConfig,
}

impl GrpcTransport {
    pub fn new(config: TransportConfig) -> Self {
        Self { config }
    }
}

#[async_trait]
impl Transport for GrpcTransport {
    type Connection = Channel;

    async fn connect(&self, endpoint: &str) -> Result<Self::Connection> {
        let endpoint = Endpoint::from_shared(endpoint.to_string())?;
        
        let endpoint = if self.config.tls_enabled {
            endpoint.tls_config(tonic::transport::ClientTlsConfig::new())?
        } else {
            endpoint
        };

        Ok(endpoint.connect().await?)
    }

    async fn request(&self, _conn: &mut Self::Connection, _service: &str, _method: &str, _data: Vec<u8>) -> Result<Vec<u8>> {
        // This is a simplified interface - in practice, you'd use the specific gRPC clients
        // This is just for interface compatibility
        todo!("Use specific gRPC clients (GhostChainClient, ZnsClient, etc.)")
    }

    async fn close(&self, _conn: Self::Connection) -> Result<()> {
        // tonic Channels close automatically
        Ok(())
    }
}