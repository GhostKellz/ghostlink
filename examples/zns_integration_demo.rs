//! ZNS Integration Demo
//! 
//! This example demonstrates how to use the ZNS integration with GhostChain
//! for blockchain-verified domain resolution.

use anyhow::Result;
use std::time::Duration;
use tokio::time::sleep;

use ghostlink::{
    GhostClient, GhostClientConfig, 
    ZnsIntegration, ZnsConfig
};
use ghostlink::zns_integration::DnsRecord;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();
    
    println!("🚀 GhostLink ZNS Integration Demo");
    println!("=====================================");
    
    // Create GhostClient configuration
    let config = GhostClientConfig::builder()
        .endpoint("https://ghostbridge.local:9443")
        .with_tls()
        .timeout(Duration::from_secs(30))
        .build();
    
    // Connect to GhostBridge
    println!("🔗 Connecting to GhostBridge...");
    match GhostClient::connect(config).await {
        Ok(client) => {
            println!("✅ Connected to GhostBridge successfully!");
            
            // Create ZNS integration
            let zns_config = ZnsConfig {
                domain_contract_address: "ghost_domain_registry_v1".to_string(),
                cache_ttl: 300, // 5 minutes
                verification_timeout: 30, // 30 seconds
                notification_interval: 1, // 1 second
            };
            
            let mut zns_integration = ZnsIntegration::new(client, zns_config);
            
            // Demo 1: Domain Resolution with Blockchain Verification
            println!("\n📋 Demo 1: Domain Resolution with Blockchain Verification");
            println!("----------------------------------------------------------");
            
            let test_domains = vec![
                "ghostkellz.ghost",
                "devteam.ghost", 
                "api.ghost",
                "example.bc"
            ];
            
            for domain in test_domains {
                println!("🔍 Resolving domain: {}", domain);
                
                match zns_integration.resolve_domain(domain).await {
                    Ok(record) => {
                        println!("✅ Domain {} resolved successfully!", domain);
                        println!("   Owner: {}", record.owner_id);
                        println!("   Verified: {}", record.verified);
                        println!("   Records: {} DNS records", record.records.len());
                        
                        // Display crypto addresses
                        if !record.crypto_addresses.is_empty() {
                            println!("   Crypto addresses:");
                            for (chain, address) in &record.crypto_addresses {
                                println!("     {}: {}", chain, address);
                            }
                        }
                        
                        // Display DNS records
                        if !record.records.is_empty() {
                            println!("   DNS records:");
                            for dns_record in &record.records {
                                println!("     {} {} (TTL: {})", 
                                    dns_record.record_type, 
                                    dns_record.value, 
                                    dns_record.ttl
                                );
                            }
                        }
                    }
                    Err(e) => {
                        println!("❌ Failed to resolve domain {}: {}", domain, e);
                    }
                }
                
                println!();
            }
            
            // Demo 2: Domain Registration
            println!("\n📋 Demo 2: Domain Registration");
            println!("-------------------------------");
            
            let new_domain = "demo.ghost";
            let owner_address = "ghost1demo123456789";
            
            let initial_records = vec![
                DnsRecord {
                    record_type: "A".to_string(),
                    value: "203.0.113.10".to_string(),
                    ttl: 300,
                    priority: 0,
                },
                DnsRecord {
                    record_type: "TXT".to_string(),
                    value: "v=spf1 include:_spf.ghostchain.com ~all".to_string(),
                    ttl: 300,
                    priority: 0,
                },
            ];
            
            // Mock signature (in real implementation this would be properly signed)
            let signature = vec![1, 2, 3, 4, 5, 6, 7, 8];
            
            println!("📝 Registering domain: {}", new_domain);
            println!("   Owner: {}", owner_address);
            println!("   Initial records: {} DNS records", initial_records.len());
            
            match zns_integration.register_domain(
                new_domain, 
                owner_address, 
                initial_records, 
                signature
            ).await {
                Ok(tx_hash) => {
                    println!("✅ Domain {} registered successfully!", new_domain);
                    println!("   Transaction hash: {}", tx_hash);
                }
                Err(e) => {
                    println!("❌ Failed to register domain {}: {}", new_domain, e);
                }
            }
            
            // Demo 3: Real-time Domain Change Monitoring
            println!("\n📋 Demo 3: Real-time Domain Change Monitoring");
            println!("----------------------------------------------");
            
            let mut change_receiver = zns_integration.subscribe_domain_changes();
            
            println!("🔔 Starting domain change monitoring...");
            println!("   Listening for domain changes (5 seconds)...");
            
            // Start monitoring task
            let monitoring_task = tokio::spawn(async move {
                let _ = zns_integration.start_monitoring().await;
            });
            
            // Listen for change events with timeout
            let timeout_duration = Duration::from_secs(5);
            let start_time = std::time::Instant::now();
            
            while start_time.elapsed() < timeout_duration {
                tokio::select! {
                    event = change_receiver.recv() => {
                        match event {
                            Ok(change_event) => {
                                println!("📢 Domain change detected!");
                                println!("   Domain: {}", change_event.domain);
                                println!("   Change type: {}", change_event.change_type);
                                println!("   Timestamp: {}", change_event.timestamp);
                            }
                            Err(e) => {
                                println!("❌ Error receiving change event: {}", e);
                                break;
                            }
                        }
                    }
                    _ = sleep(Duration::from_millis(100)) => {
                        // Continue monitoring
                    }
                }
            }
            
            // Stop monitoring
            monitoring_task.abort();
            println!("⏹️  Monitoring stopped.");
            
            // Demo 4: Cache Performance Test
            println!("\n📋 Demo 4: Cache Performance Test");
            println!("----------------------------------");
            
            let test_domain = "cache-test.ghost";
            
            println!("🚀 Testing cache performance for domain: {}", test_domain);
            
            // First resolution (should hit blockchain)
            let start_time = std::time::Instant::now();
            match zns_integration.resolve_domain(test_domain).await {
                Ok(_) => {
                    let first_duration = start_time.elapsed();
                    println!("✅ First resolution (blockchain): {:?}", first_duration);
                    
                    // Second resolution (should hit cache)
                    let start_time = std::time::Instant::now();
                    match zns_integration.resolve_domain(test_domain).await {
                        Ok(_) => {
                            let second_duration = start_time.elapsed();
                            println!("✅ Second resolution (cache): {:?}", second_duration);
                            
                            if second_duration < first_duration {
                                println!("🎯 Cache performance improvement: {:?}", 
                                    first_duration - second_duration);
                            }
                        }
                        Err(e) => {
                            println!("❌ Second resolution failed: {}", e);
                        }
                    }
                }
                Err(e) => {
                    println!("❌ First resolution failed: {}", e);
                }
            }
            
            println!("\n🎉 ZNS Integration Demo completed!");
            println!("=====================================");
            
        }
        Err(e) => {
            println!("❌ Failed to connect to GhostBridge: {}", e);
            println!("💡 Make sure GhostBridge is running at https://ghostbridge.local:9443");
            println!("💡 Or update the endpoint in the configuration");
        }
    }
    
    Ok(())
}

/// Helper function to demonstrate domain ownership verification
async fn demonstrate_ownership_verification(domain: &str) -> Result<()> {
    println!("🔐 Demonstrating blockchain ownership verification for: {}", domain);
    
    // This would normally involve:
    // 1. Querying the domain registry smart contract
    // 2. Verifying the owner's signature
    // 3. Checking the current block height
    // 4. Validating the domain's DNS records
    
    println!("   ✅ Ownership verified on blockchain");
    println!("   ✅ Signature validation passed");
    println!("   ✅ Block height confirmed");
    println!("   ✅ DNS records validated");
    
    Ok(())
}

/// Helper function to demonstrate multi-service resolution
async fn demonstrate_multi_service_resolution(domain: &str) -> Result<()> {
    println!("🌐 Demonstrating multi-service resolution for: {}", domain);
    
    let services = vec!["ENS", "UNSTOPPABLE", "GHOST"];
    
    for service in services {
        println!("   🔍 Checking {} service...", service);
        
        // Mock resolution results
        match service {
            "ENS" => println!("   ✅ ENS: ethereum:0x1234567890abcdef"),
            "UNSTOPPABLE" => println!("   ✅ Unstoppable: polygon:0xabcdef1234567890"),
            "GHOST" => println!("   ✅ Ghost: ghost1owner123456789"),
            _ => println!("   ❌ {}: Not supported", service),
        }
    }
    
    Ok(())
}

/// Helper function to format duration for display
fn format_duration(duration: Duration) -> String {
    let millis = duration.as_millis();
    if millis < 1000 {
        format!("{}ms", millis)
    } else {
        format!("{:.2}s", duration.as_secs_f64())
    }
}