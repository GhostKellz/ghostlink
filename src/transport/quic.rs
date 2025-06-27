//! QUIC Transport with multiplexed channels

#[cfg(feature = "quic")]
use super::{Transport, TransportConfig, ChannelRegistry, ServiceChannel};
#[cfg(feature = "quic")]
use anyhow::{anyhow, Result};
#[cfg(feature = "quic")]
use async_trait::async_trait;
#[cfg(feature = "quic")]
use quinn::{ClientConfig, Connection, Endpoint, RecvStream, SendStream, VarInt};
#[cfg(feature = "quic")]
use rustls::{ClientConfig as RustlsClientConfig, RootCertStore};
#[cfg(feature = "quic")]
use std::collections::HashMap;
#[cfg(feature = "quic")]
use std::net::SocketAddr;
#[cfg(feature = "quic")]
use std::sync::Arc;
#[cfg(feature = "quic")]
use tokio::sync::Mutex;
#[cfg(feature = "quic")]
use tracing::{debug, info, warn};

#[cfg(feature = "quic")]
/// QUIC transport with multiplexed service channels
#[derive(Debug)]
pub struct QuicTransport {
    config: TransportConfig,
    channel_registry: ChannelRegistry,
    endpoint: Option<Endpoint>,
}

#[cfg(feature = "quic")]
#[derive(Debug)]
pub struct QuicConnection {
    connection: Connection,
    streams: Arc<Mutex<HashMap<ServiceChannel, (SendStream, RecvStream)>>>,
}

#[cfg(feature = "quic")]
impl QuicTransport {
    pub fn new(config: TransportConfig) -> Result<Self> {
        let client_config = Self::create_client_config(config.tls_enabled)?;
        let mut endpoint = Endpoint::client(if config.ipv6_enabled {
            "[::]:0".parse()?
        } else {
            "0.0.0.0:0".parse()?
        })?;
        endpoint.set_default_client_config(client_config);

        Ok(Self {
            config,
            channel_registry: ChannelRegistry::new(),
            endpoint: Some(endpoint),
        })
    }

    fn create_client_config(tls_enabled: bool) -> Result<ClientConfig> {
        if !tls_enabled {
            // Development/testing only - no TLS verification
            warn!("QUIC running without TLS verification - development mode only!");
            return Err(anyhow!("Insecure QUIC connections not supported in this version"));
        }

        // Production TLS config
        let mut root_store = rustls::RootCertStore::empty();
        root_store.add_server_trust_anchors(
            webpki_roots::TLS_SERVER_ROOTS
                .0
                .iter()
                .map(|ta| {
                    rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
                        ta.subject,
                        ta.spki,
                        ta.name_constraints,
                    )
                }),
        );

        let crypto = rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        Ok(ClientConfig::new(Arc::new(crypto)))
    }

    async fn setup_service_streams(&self, conn: &Connection) -> Result<HashMap<ServiceChannel, (SendStream, RecvStream)>> {
        let mut streams = HashMap::new();

        for (service, &channel_id) in self.channel_registry.channels.iter() {
            debug!("Opening stream for service: {:?} (channel {})", service, channel_id);
            
            let (send_stream, recv_stream) = conn.open_bi().await
                .map_err(|e| anyhow!("Failed to open bidirectional stream: {}", e))?;

            // Send channel identifier
            self.send_channel_header(&send_stream, channel_id).await?;
            
            streams.insert(service.clone(), (send_stream, recv_stream));
        }

        info!("Established {} service streams", streams.len());
        Ok(streams)
    }

    async fn send_channel_header(&self, mut send_stream: &SendStream, channel_id: u64) -> Result<()> {
        let header = channel_id.to_le_bytes();
        send_stream.write_all(&header).await
            .map_err(|e| anyhow!("Failed to send channel header: {}", e))?;
        send_stream.finish().await
            .map_err(|e| anyhow!("Failed to finish channel header: {}", e))?;
        Ok(())
    }
}

#[cfg(feature = "quic")]
#[async_trait]
impl Transport for QuicTransport {
    type Connection = QuicConnection;

    async fn connect(&self, endpoint: &str) -> Result<Self::Connection> {
        let endpoint_ref = self.endpoint.as_ref()
            .ok_or_else(|| anyhow!("QUIC endpoint not initialized"))?;

        // Parse endpoint URL
        let url = url::Url::parse(endpoint)?;
        let host = url.host_str().ok_or_else(|| anyhow!("Invalid hostname"))?;
        let port = url.port().unwrap_or(443);

        let server_addr: SocketAddr = format!("{}:{}", host, port).parse()?;
        
        info!("Connecting to QUIC endpoint: {}", server_addr);

        let connection = endpoint_ref.connect(server_addr, host)?
            .await
            .map_err(|e| anyhow!("QUIC connection failed: {}", e))?;

        info!("✅ QUIC connection established to {}", server_addr);

        // Setup multiplexed service streams
        let streams = self.setup_service_streams(&connection).await?;

        Ok(QuicConnection {
            connection,
            streams: Arc::new(Mutex::new(streams)),
        })
    }

    async fn request(&self, conn: &mut Self::Connection, service: &str, method: &str, data: Vec<u8>) -> Result<Vec<u8>> {
        let service_channel = match service {
            "ghostchain" => ServiceChannel::Wallet,
            "ghostid" => ServiceChannel::Identity,
            "zns" => ServiceChannel::Dns,
            "zvm" => ServiceChannel::Vm,
            _ => return Err(anyhow!("Unknown service: {}", service)),
        };

        let mut streams = conn.streams.lock().await;
        let (send_stream, recv_stream) = streams.get_mut(&service_channel)
            .ok_or_else(|| anyhow!("Service stream not found: {:?}", service_channel))?;

        // Send request: [method_len][method][data_len][data]
        let method_bytes = method.as_bytes();
        let method_len = (method_bytes.len() as u32).to_le_bytes();
        let data_len = (data.len() as u32).to_le_bytes();

        send_stream.write_all(&method_len).await?;
        send_stream.write_all(method_bytes).await?;
        send_stream.write_all(&data_len).await?;
        send_stream.write_all(&data).await?;

        // Read response: [status][data_len][data]
        use quinn::{ReadExactError, ReadToEndError};
        
        let mut status_buf = [0u8; 1];
        match recv_stream.read_exact(&mut status_buf).await {
            Ok(_) => {},
            Err(ReadExactError::FinishedEarly) => return Err(anyhow!("Stream finished early")),
            Err(ReadExactError::ReadError(e)) => return Err(anyhow!("Read error: {}", e)),
        }
        
        if status_buf[0] != 0 {
            return Err(anyhow!("Request failed with status: {}", status_buf[0]));
        }

        let mut len_buf = [0u8; 4];
        match recv_stream.read_exact(&mut len_buf).await {
            Ok(_) => {},
            Err(ReadExactError::FinishedEarly) => return Err(anyhow!("Stream finished early")),
            Err(ReadExactError::ReadError(e)) => return Err(anyhow!("Read error: {}", e)),
        }
        let response_len = u32::from_le_bytes(len_buf) as usize;

        let mut response_data = vec![0u8; response_len];
        match recv_stream.read_exact(&mut response_data).await {
            Ok(_) => {},
            Err(ReadExactError::FinishedEarly) => return Err(anyhow!("Stream finished early")),
            Err(ReadExactError::ReadError(e)) => return Err(anyhow!("Read error: {}", e)),
        }

        Ok(response_data)
    }

    async fn close(&self, conn: Self::Connection) -> Result<()> {
        conn.connection.close(VarInt::from_u32(0), b"Closing connection");
        info!("QUIC connection closed");
        Ok(())
    }
}


#[cfg(test)]
#[cfg(feature = "quic")]
mod tests {
    use super::*;

    #[test]
    fn test_quic_transport_creation() {
        let config = TransportConfig::default();
        let transport = QuicTransport::new(config);
        assert!(transport.is_ok());
    }

    #[tokio::test]
    async fn test_client_config_creation() {
        let config_tls = QuicTransport::create_client_config(true);
        assert!(config_tls.is_ok());

        let config_no_tls = QuicTransport::create_client_config(false);
        assert!(config_no_tls.is_ok());
    }
}