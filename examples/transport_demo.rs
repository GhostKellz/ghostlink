//! GhostLink Transport Demo
//! 
//! Demonstrates the different transport protocols:
//! - HTTP/2 gRPC (traditional)
//! - QUIC with multiplexing
//! - HTTP/3 gRPC-Web

use ghostlink::{GhostClientConfig, TransportProtocol};
use anyhow::Result;
use tracing::{info, Level};
use tracing_subscriber;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_max_level(Level::INFO)
        .init();

    info!("🚀 GhostLink Transport Demo");

    // Demo HTTP/2 gRPC (traditional)
    demo_http2_grpc().await?;

    // Demo QUIC transport
    #[cfg(feature = "quic")]
    demo_quic_transport().await?;

    // Demo HTTP/3 transport
    #[cfg(feature = "http3")]
    demo_http3_transport().await?;

    info!("✅ All transport demos completed");
    Ok(())
}

/// Demonstrate traditional HTTP/2 gRPC transport
async fn demo_http2_grpc() -> Result<()> {
    info!("📡 HTTP/2 gRPC Transport Demo");
    
    let config = GhostClientConfig::builder()
        .endpoint("https://ghostbridge.local:9443")
        .with_tls()
        .transport_protocol(TransportProtocol::Http2Grpc)
        .build();

    info!("Config: {:?}", config.transport.protocol);
    
    // This would connect in a real scenario
    // let client = GhostClient::connect(config).await?;
    info!("✅ HTTP/2 gRPC configuration ready");
    
    Ok(())
}

/// Demonstrate QUIC transport with multiplexing
#[cfg(feature = "quic")]
async fn demo_quic_transport() -> Result<()> {
    info!("⚡ QUIC Transport Demo");
    
    let config = GhostClientConfig::builder()
        .endpoint("https://ghostbridge.local:443")
        .with_quic()
        .with_ipv6()
        .with_multiplexing()
        .build();

    info!("Config: {:?}", config.transport.protocol);
    info!("IPv6 enabled: {}", config.transport.ipv6_enabled);
    info!("Multiplexing: {}", config.transport.multiplexing);
    
    // This would connect in a real scenario
    // let client = GhostClient::connect(config).await?;
    info!("✅ QUIC configuration ready");
    
    Ok(())
}

/// Demonstrate HTTP/3 transport
#[cfg(feature = "http3")]
async fn demo_http3_transport() -> Result<()> {
    info!("🌐 HTTP/3 Transport Demo");
    
    let config = GhostClientConfig::builder()
        .endpoint("https://ghostbridge.local:443")
        .with_http3()
        .with_ipv6()
        .build();

    info!("Config: {:?}", config.transport.protocol);
    
    // This would connect in a real scenario
    // let client = GhostClient::connect(config).await?;
    info!("✅ HTTP/3 configuration ready");
    
    Ok(())
}

/// Demo showcasing service channel routing (when QUIC is available)
#[cfg(feature = "quic")]
async fn demo_service_channels() -> Result<()> {
    info!("🔀 Service Channel Demo");
    
    use ghostlink::transport::{ServiceChannel, ChannelRegistry};
    
    let registry = ChannelRegistry::new();
    
    info!("Service channels:");
    info!("  Wallet: channel {}", registry.channel_id(&ServiceChannel::Wallet).unwrap());
    info!("  DNS: channel {}", registry.channel_id(&ServiceChannel::Dns).unwrap());
    info!("  Identity: channel {}", registry.channel_id(&ServiceChannel::Identity).unwrap());
    info!("  VM: channel {}", registry.channel_id(&ServiceChannel::Vm).unwrap());
    
    info!("SNI hostnames:");
    info!("  Wallet: {}", ServiceChannel::Wallet.sni_hostname("ghostbridge.local"));
    info!("  DNS: {}", ServiceChannel::Dns.sni_hostname("ghostbridge.local"));
    
    Ok(())
}

/// Demo transport manager selection
async fn demo_transport_selection() -> Result<()> {
    info!("⚙️ Transport Selection Demo");
    
    use ghostlink::transport::{TransportManager, TransportConfig};
    
    // Different transport configurations
    let configs = vec![
        ("HTTP/2 gRPC", TransportConfig {
            protocol: TransportProtocol::Http2Grpc,
            ..Default::default()
        }),
        #[cfg(feature = "quic")]
        ("QUIC", TransportConfig {
            protocol: TransportProtocol::Quic,
            multiplexing: true,
            ipv6_enabled: true,
            ..Default::default()
        }),
        #[cfg(feature = "http3")]
        ("HTTP/3", TransportConfig {
            protocol: TransportProtocol::Http3,
            ipv6_enabled: true,
            ..Default::default()
        }),
    ];
    
    for (name, config) in configs {
        match TransportManager::new(config) {
            Ok(manager) => {
                info!("✅ {} transport manager created", name);
                info!("   Protocol: {:?}", manager.config().protocol);
            }
            Err(e) => {
                info!("❌ {} transport not available: {}", name, e);
            }
        }
    }
    
    Ok(())
}