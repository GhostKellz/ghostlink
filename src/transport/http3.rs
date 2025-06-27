//! HTTP/3 Transport with gRPC-Web compatibility

#[cfg(feature = "http3")]
use super::{Transport, TransportConfig, ServiceChannel};
#[cfg(feature = "http3")]
use anyhow::{anyhow, Result};
#[cfg(feature = "http3")]
use async_trait::async_trait;
#[cfg(feature = "http3")]
use h3::client::SendRequest;
#[cfg(feature = "http3")]
use h3_quinn::Connection as H3Connection;
#[cfg(feature = "http3")]
use http::{Request, Response, HeaderMap, HeaderValue};
#[cfg(feature = "http3")]
use quinn::{ClientConfig, Endpoint};
#[cfg(feature = "http3")]
use rustls::{ClientConfig as RustlsClientConfig, RootCertStore};
#[cfg(feature = "http3")]
use std::net::SocketAddr;
#[cfg(feature = "http3")]
use std::sync::Arc;
#[cfg(feature = "http3")]
use tracing::{debug, info, warn};

#[cfg(feature = "http3")]
/// HTTP/3 transport with gRPC-Web compatibility
#[derive(Debug)]
pub struct Http3Transport {
    config: TransportConfig,
    endpoint: Option<Endpoint>,
}

#[cfg(feature = "http3")]
#[derive(Debug)]
pub struct Http3Connection {
    send_request: SendRequest<h3_quinn::OpenStreams, bytes::Bytes>,
    base_url: String,
}

#[cfg(feature = "http3")]
impl Http3Transport {
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
            endpoint: Some(endpoint),
        })
    }

    fn create_client_config(tls_enabled: bool) -> Result<ClientConfig> {
        if !tls_enabled {
            warn!("HTTP/3 running without TLS verification - development mode only!");
            return Err(anyhow!("Insecure HTTP/3 connections not supported in this version"));
        }

        // Production TLS config with ALPN for HTTP/3
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

        let mut crypto = rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        // Set ALPN for HTTP/3
        // crypto.alpn_protocols = vec![b"h3".to_vec()]; // TODO: Enable when h3 works

        Ok(ClientConfig::new(Arc::new(crypto)))
    }

    fn service_to_path(&self, service: &str) -> &'static str {
        match service {
            "ghostchain" => "/ghostchain.v1.GhostChain",
            "ghostid" => "/ghostid.v1.GhostId", 
            "zns" => "/zns.v1.ZNS",
            "zvm" => "/zvm.v1.ZVM",
            _ => "/unknown",
        }
    }

    fn create_grpc_web_headers(&self) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("content-type", HeaderValue::from_static("application/grpc-web+proto"));
        headers.insert("accept", HeaderValue::from_static("application/grpc-web+proto"));
        headers.insert("user-agent", HeaderValue::from_str(&format!("GhostLink-HTTP3/{}", crate::VERSION)).unwrap());
        headers.insert("te", HeaderValue::from_static("trailers"));
        headers
    }

    fn encode_grpc_web_frame(&self, data: Vec<u8>) -> Vec<u8> {
        // gRPC-Web frame format: [compressed_flag][length][data]
        let mut frame = Vec::with_capacity(5 + data.len());
        frame.push(0); // No compression
        frame.extend_from_slice(&(data.len() as u32).to_be_bytes());
        frame.extend_from_slice(&data);
        frame
    }

    fn decode_grpc_web_frame(&self, mut data: Vec<u8>) -> Result<Vec<u8>> {
        if data.len() < 5 {
            return Err(anyhow!("Invalid gRPC-Web frame: too short"));
        }

        let _compressed = data[0];
        let length = u32::from_be_bytes([data[1], data[2], data[3], data[4]]) as usize;
        
        if data.len() < 5 + length {
            return Err(anyhow!("Invalid gRPC-Web frame: length mismatch"));
        }

        data.drain(0..5);
        data.truncate(length);
        Ok(data)
    }
}

#[cfg(feature = "http3")]
#[async_trait]
impl Transport for Http3Transport {
    type Connection = Http3Connection;

    async fn connect(&self, endpoint: &str) -> Result<Self::Connection> {
        let endpoint_ref = self.endpoint.as_ref()
            .ok_or_else(|| anyhow!("HTTP/3 endpoint not initialized"))?;

        // Parse endpoint URL
        let url = url::Url::parse(endpoint)?;
        let host = url.host_str().ok_or_else(|| anyhow!("Invalid hostname"))?;
        let port = url.port().unwrap_or(443);

        let server_addr: SocketAddr = format!("{}:{}", host, port).parse()?;
        
        info!("Connecting to HTTP/3 endpoint: {}", server_addr);

        let quinn_conn = endpoint_ref.connect(server_addr, host)?
            .await
            .map_err(|e| anyhow!("HTTP/3 connection failed: {}", e))?;

        info!("✅ HTTP/3 QUIC connection established to {}", server_addr);

        // Establish HTTP/3 connection
        let h3_conn = H3Connection::new(quinn_conn);
        let (mut driver, send_request) = h3::client::new(h3_conn).await
            .map_err(|e| anyhow!("HTTP/3 handshake failed: {}", e))?;

        // Spawn driver task
        tokio::spawn(async move {
            if let Err(e) = (&mut driver).await {
                warn!("HTTP/3 driver error: {}", e);
            }
        });

        info!("✅ HTTP/3 connection ready");

        Ok(Http3Connection {
            send_request,
            base_url: format!("https://{}:{}", host, port),
        })
    }

    async fn request(&self, conn: &mut Self::Connection, service: &str, method: &str, data: Vec<u8>) -> Result<Vec<u8>> {
        let service_path = self.service_to_path(service);
        let full_path = format!("{}/{}", service_path, method);
        let url = format!("{}{}", conn.base_url, full_path);

        debug!("HTTP/3 request: {} {}", "POST", url);

        // Create gRPC-Web request
        let grpc_frame = self.encode_grpc_web_frame(data);
        let mut headers = self.create_grpc_web_headers();
        
        let request = Request::builder()
            .method("POST")
            .uri(&url)
            .body(())?;

        let mut request = request;
        *request.headers_mut() = headers;

        // Send request
        let mut stream = conn.send_request.send_request(request).await
            .map_err(|e| anyhow!("Failed to send HTTP/3 request: {}", e))?;

        stream.send_data(grpc_frame.into()).await
            .map_err(|e| anyhow!("Failed to send request body: {}", e))?;

        stream.finish().await
            .map_err(|e| anyhow!("Failed to finish request stream: {}", e))?;

        // Receive response
        let response = stream.recv_response().await
            .map_err(|e| anyhow!("Failed to receive HTTP/3 response: {}", e))?;

        if !response.status().is_success() {
            return Err(anyhow!("HTTP/3 request failed: {}", response.status()));
        }

        // Read response body
        let mut response_data = Vec::new();
        while let Some(chunk) = stream.recv_data().await
            .map_err(|e| anyhow!("Error reading response data: {}", e))? {
            response_data.extend_from_slice(&chunk);
        }

        // Decode gRPC-Web frame
        let decoded_data = self.decode_grpc_web_frame(response_data)?;
        
        debug!("HTTP/3 response received: {} bytes", decoded_data.len());
        Ok(decoded_data)
    }

    async fn close(&self, _conn: Self::Connection) -> Result<()> {
        info!("HTTP/3 connection closed");
        Ok(())
    }
}


#[cfg(test)]
#[cfg(feature = "http3")]
mod tests {
    use super::*;

    #[test]
    fn test_http3_transport_creation() {
        let config = TransportConfig {
            protocol: super::super::TransportProtocol::Http3,
            ..Default::default()
        };
        let transport = Http3Transport::new(config);
        assert!(transport.is_ok());
    }

    #[test]
    fn test_grpc_web_frame_encoding() {
        let transport = Http3Transport::new(TransportConfig::default()).unwrap();
        let data = vec![1, 2, 3, 4];
        let frame = transport.encode_grpc_web_frame(data.clone());
        
        assert_eq!(frame.len(), 9); // 5 bytes header + 4 bytes data
        assert_eq!(frame[0], 0); // No compression
        assert_eq!(&frame[5..], &data);
        
        let decoded = transport.decode_grpc_web_frame(frame).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_service_path_mapping() {
        let transport = Http3Transport::new(TransportConfig::default()).unwrap();
        assert_eq!(transport.service_to_path("ghostchain"), "/ghostchain.v1.GhostChain");
        assert_eq!(transport.service_to_path("zns"), "/zns.v1.ZNS");
        assert_eq!(transport.service_to_path("unknown"), "/unknown");
    }
}