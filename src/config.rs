//! GhostLink Client Configuration

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use url::Url;
use crate::transport::{TransportConfig, TransportProtocol};

/// Configuration for GhostLink client connections
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GhostClientConfig {
    /// GhostBridge endpoint URL
    pub endpoint: Url,
    /// Enable TLS encryption
    pub tls_enabled: bool,
    /// Connection timeout
    pub timeout: Duration,
    /// Request timeout
    pub request_timeout: Duration,
    /// Keep-alive interval
    pub keep_alive: Option<Duration>,
    /// Maximum concurrent requests
    pub max_concurrent_requests: usize,
    /// User agent string
    pub user_agent: String,
    /// Transport configuration
    pub transport: TransportConfig,
}

impl Default for GhostClientConfig {
    fn default() -> Self {
        Self {
            endpoint: Url::parse(crate::DEFAULT_ENDPOINT).unwrap(),
            tls_enabled: true,
            timeout: Duration::from_secs(30),
            request_timeout: Duration::from_secs(10),
            keep_alive: Some(Duration::from_secs(30)),
            max_concurrent_requests: 100,
            user_agent: format!("GhostLink/{}", crate::VERSION),
            transport: TransportConfig::default(),
        }
    }
}

/// Builder for GhostClientConfig
pub struct GhostClientConfigBuilder {
    config: GhostClientConfig,
}

impl GhostClientConfigBuilder {
    /// Create a new builder with default values
    pub fn new() -> Self {
        Self {
            config: GhostClientConfig::default(),
        }
    }

    /// Set the endpoint URL
    pub fn endpoint<S: AsRef<str>>(mut self, endpoint: S) -> Self {
        self.config.endpoint = Url::parse(endpoint.as_ref())
            .expect("Invalid endpoint URL");
        self
    }

    /// Enable TLS encryption
    pub fn with_tls(mut self) -> Self {
        self.config.tls_enabled = true;
        self
    }

    /// Disable TLS encryption (use only for development)
    pub fn without_tls(mut self) -> Self {
        self.config.tls_enabled = false;
        self
    }

    /// Set connection timeout
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.config.timeout = timeout;
        self
    }

    /// Set request timeout
    pub fn request_timeout(mut self, timeout: Duration) -> Self {
        self.config.request_timeout = timeout;
        self
    }

    /// Set keep-alive interval
    pub fn keep_alive(mut self, interval: Duration) -> Self {
        self.config.keep_alive = Some(interval);
        self
    }

    /// Disable keep-alive
    pub fn no_keep_alive(mut self) -> Self {
        self.config.keep_alive = None;
        self
    }

    /// Set maximum concurrent requests
    pub fn max_concurrent_requests(mut self, max: usize) -> Self {
        self.config.max_concurrent_requests = max;
        self
    }

    /// Set custom user agent
    pub fn user_agent<S: Into<String>>(mut self, user_agent: S) -> Self {
        self.config.user_agent = user_agent.into();
        self
    }

    /// Set transport protocol
    pub fn transport_protocol(mut self, protocol: TransportProtocol) -> Self {
        self.config.transport.protocol = protocol;
        self
    }

    /// Enable QUIC transport
    pub fn with_quic(mut self) -> Self {
        self.config.transport.protocol = TransportProtocol::Quic;
        self
    }

    /// Enable HTTP/3 transport
    pub fn with_http3(mut self) -> Self {
        self.config.transport.protocol = TransportProtocol::Http3;
        self
    }

    /// Enable binary protocol over QUIC
    pub fn with_quic_binary(mut self) -> Self {
        self.config.transport.protocol = TransportProtocol::QuicBinary;
        self
    }

    /// Enable IPv6 support
    pub fn with_ipv6(mut self) -> Self {
        self.config.transport.ipv6_enabled = true;
        self
    }

    /// Disable IPv6 support
    pub fn without_ipv6(mut self) -> Self {
        self.config.transport.ipv6_enabled = false;
        self
    }

    /// Enable multiplexing
    pub fn with_multiplexing(mut self) -> Self {
        self.config.transport.multiplexing = true;
        self
    }

    /// Disable multiplexing
    pub fn without_multiplexing(mut self) -> Self {
        self.config.transport.multiplexing = false;
        self
    }

    /// Build the configuration
    pub fn build(self) -> GhostClientConfig {
        self.config
    }
}

impl GhostClientConfig {
    /// Create a new builder
    pub fn builder() -> GhostClientConfigBuilder {
        GhostClientConfigBuilder::new()
    }

    /// Get the gRPC endpoint URI
    pub fn grpc_endpoint(&self) -> String {
        if self.tls_enabled {
            format!("https://{}", self.endpoint.authority())
        } else {
            format!("http://{}", self.endpoint.authority())
        }
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<()> {
        if self.endpoint.scheme() != "https" && self.endpoint.scheme() != "http" {
            return Err(anyhow::anyhow!("Invalid endpoint scheme: {}", self.endpoint.scheme()));
        }

        if self.timeout.is_zero() {
            return Err(anyhow::anyhow!("Timeout cannot be zero"));
        }

        if self.request_timeout.is_zero() {
            return Err(anyhow::anyhow!("Request timeout cannot be zero"));
        }

        if self.max_concurrent_requests == 0 {
            return Err(anyhow::anyhow!("Max concurrent requests must be greater than 0"));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = GhostClientConfig::default();
        assert_eq!(config.endpoint.as_str(), "https://ghostbridge.local:9443/");
        assert!(config.tls_enabled);
        assert_eq!(config.timeout, Duration::from_secs(30));
    }

    #[test]
    fn test_builder() {
        let config = GhostClientConfig::builder()
            .endpoint("https://custom.endpoint:9443")
            .timeout(Duration::from_secs(60))
            .without_tls()
            .build();

        assert_eq!(config.endpoint.as_str(), "https://custom.endpoint:9443/");
        assert!(!config.tls_enabled);
        assert_eq!(config.timeout, Duration::from_secs(60));
    }

    #[test]
    fn test_grpc_endpoint() {
        let config = GhostClientConfig::builder()
            .endpoint("https://ghostbridge.local:9443")
            .build();
        
        assert_eq!(config.grpc_endpoint(), "https://ghostbridge.local:9443");

        let config = GhostClientConfig::builder()
            .endpoint("http://localhost:9443")
            .without_tls()
            .build();
        
        assert_eq!(config.grpc_endpoint(), "http://localhost:9443");
    }

    #[test]
    fn test_validation() {
        let config = GhostClientConfig::default();
        assert!(config.validate().is_ok());

        let mut config = GhostClientConfig::default();
        config.timeout = Duration::from_secs(0);
        assert!(config.validate().is_err());
    }
}
