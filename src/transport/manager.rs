//! Transport Manager for unified protocol handling

use super::{Transport, TransportConfig, TransportProtocol};
use super::grpc::GrpcTransport;

#[cfg(feature = "quic")]
use super::quic::QuicTransport;

#[cfg(feature = "http3")]
use super::http3::Http3Transport;

use anyhow::{anyhow, Result};
use std::any::Any;
use tracing::info;

/// Unified transport manager that handles different protocols
pub struct TransportManager {
    config: TransportConfig,
    transport: Box<dyn Transport<Connection = Box<dyn Any + Send + Sync>>>,
}

impl std::fmt::Debug for TransportManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransportManager")
            .field("config", &self.config)
            .field("protocol", &self.config.protocol)
            .finish()
    }
}

impl TransportManager {
    /// Create a new transport manager with the given configuration
    pub fn new(config: TransportConfig) -> Result<Self> {
        info!("Creating transport manager with protocol: {:?}", config.protocol);

        let transport: Box<dyn Transport<Connection = Box<dyn Any + Send + Sync>>> = match config.protocol {
            TransportProtocol::Http2Grpc => {
                Box::new(GrpcTransportWrapper::new(GrpcTransport::new(config.clone())))
            }
            
            #[cfg(feature = "quic")]
            TransportProtocol::Quic | TransportProtocol::QuicBinary => {
                Box::new(QuicTransportWrapper::new(QuicTransport::new(config.clone())?))
            }
            
            #[cfg(feature = "http3")]
            TransportProtocol::Http3 => {
                Box::new(Http3TransportWrapper::new(Http3Transport::new(config.clone())?))
            }

            #[cfg(not(feature = "quic"))]
            TransportProtocol::Quic | TransportProtocol::QuicBinary => {
                return Err(anyhow!("QUIC support not compiled in. Enable 'quic' feature."));
            }

            #[cfg(not(feature = "http3"))]
            TransportProtocol::Http3 => {
                return Err(anyhow!("HTTP/3 support not compiled in. Enable 'http3' feature."));
            }
        };

        Ok(Self { config, transport })
    }

    /// Connect to the remote endpoint
    pub async fn connect(&self, endpoint: &str) -> Result<TransportConnection> {
        let connection = self.transport.connect(endpoint).await?;
        Ok(TransportConnection { inner: connection })
    }

    /// Send a request through the transport
    pub async fn request(
        &self,
        conn: &mut TransportConnection,
        service: &str,
        method: &str,
        data: Vec<u8>,
    ) -> Result<Vec<u8>> {
        self.transport.request(&mut conn.inner, service, method, data).await
    }

    /// Close the connection
    pub async fn close(&self, conn: TransportConnection) -> Result<()> {
        self.transport.close(conn.inner).await
    }

    /// Get the transport configuration
    pub fn config(&self) -> &TransportConfig {
        &self.config
    }
}

/// Connection wrapper for type erasure
pub struct TransportConnection {
    inner: Box<dyn Any + Send + Sync>,
}

impl std::fmt::Debug for TransportConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransportConnection").finish()
    }
}

// Wrapper types for type erasure
struct GrpcTransportWrapper(GrpcTransport);

impl GrpcTransportWrapper {
    fn new(transport: GrpcTransport) -> Self {
        Self(transport)
    }
}

impl std::fmt::Debug for GrpcTransportWrapper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GrpcTransportWrapper").finish()
    }
}

#[async_trait::async_trait]
impl Transport for GrpcTransportWrapper {
    type Connection = Box<dyn Any + Send + Sync>;

    async fn connect(&self, endpoint: &str) -> Result<Self::Connection> {
        let conn = self.0.connect(endpoint).await?;
        Ok(Box::new(conn))
    }

    async fn request(&self, _conn: &mut Self::Connection, _service: &str, _method: &str, _data: Vec<u8>) -> Result<Vec<u8>> {
        // This is a placeholder - in practice, you'd need to downcast and use proper gRPC clients
        Err(anyhow!("gRPC requests should use specific service clients"))
    }

    async fn close(&self, _conn: Self::Connection) -> Result<()> {
        // gRPC connections close automatically
        Ok(())
    }
}

#[cfg(feature = "quic")]
struct QuicTransportWrapper(QuicTransport);

#[cfg(feature = "quic")]
impl QuicTransportWrapper {
    fn new(transport: QuicTransport) -> Self {
        Self(transport)
    }
}

#[cfg(feature = "quic")]
impl std::fmt::Debug for QuicTransportWrapper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuicTransportWrapper").finish()
    }
}

#[cfg(feature = "quic")]
#[async_trait::async_trait]
impl Transport for QuicTransportWrapper {
    type Connection = Box<dyn Any + Send + Sync>;

    async fn connect(&self, endpoint: &str) -> Result<Self::Connection> {
        let conn = self.0.connect(endpoint).await?;
        Ok(Box::new(conn))
    }

    async fn request(&self, _conn: &mut Self::Connection, _service: &str, _method: &str, _data: Vec<u8>) -> Result<Vec<u8>> {
        // TODO: Implement proper QUIC request handling
        Ok(vec![])
    }

    async fn close(&self, _conn: Self::Connection) -> Result<()> {
        // TODO: Implement proper QUIC connection closing
        Ok(())
    }
}

#[cfg(feature = "http3")]
struct Http3TransportWrapper(Http3Transport);

#[cfg(feature = "http3")]
impl Http3TransportWrapper {
    fn new(transport: Http3Transport) -> Self {
        Self(transport)
    }
}

#[cfg(feature = "http3")]
impl std::fmt::Debug for Http3TransportWrapper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Http3TransportWrapper").finish()
    }
}

#[cfg(feature = "http3")]
#[async_trait::async_trait]
impl Transport for Http3TransportWrapper {
    type Connection = Box<dyn Any + Send + Sync>;

    async fn connect(&self, endpoint: &str) -> Result<Self::Connection> {
        let conn = self.0.connect(endpoint).await?;
        Ok(Box::new(conn))
    }

    async fn request(&self, _conn: &mut Self::Connection, _service: &str, _method: &str, _data: Vec<u8>) -> Result<Vec<u8>> {
        // TODO: Implement proper HTTP/3 request handling
        Ok(vec![])
    }

    async fn close(&self, _conn: Self::Connection) -> Result<()> {
        // TODO: Implement proper HTTP/3 connection closing
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_transport_manager_creation() {
        // Initialize rustls crypto provider for testing
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        
        let config = TransportConfig::default();
        let manager = TransportManager::new(config);
        assert!(manager.is_ok());
    }

    #[cfg(feature = "quic")]
    #[tokio::test]
    async fn test_quic_transport_manager() {
        // Initialize rustls crypto provider for testing
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        
        let config = TransportConfig {
            protocol: TransportProtocol::Quic,
            ..Default::default()
        };
        let manager = TransportManager::new(config);
        assert!(manager.is_ok());
    }

    #[cfg(feature = "http3")]
    #[test]
    fn test_http3_transport_manager() {
        let config = TransportConfig {
            protocol: TransportProtocol::Http3,
            ..Default::default()
        };
        let manager = TransportManager::new(config);
        assert!(manager.is_ok());
    }
}