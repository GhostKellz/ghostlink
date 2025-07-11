//! Integration tests for GhostLink v0.3.0

#[tokio::test]
async fn test_ghostlink_basic_types() {
    // Test basic type compilation
    use ghostlink::error::GhostLinkError;
    
    let error = GhostLinkError::Connection("test".to_string());
    assert!(format!("{:?}", error).contains("Connection"));
}

#[cfg(feature = "zvm-integration")]
#[tokio::test]
async fn test_zvm_integration_compiles() {
    // Test ZVM integration compilation
    use ghostlink::zvm::contract::ContractUtils;
    
    let selector = ContractUtils::function_selector("transfer(address,uint256)");
    assert_eq!(selector.len(), 4);
    
    let address = [0x42u8; 20];
    let encoded = ContractUtils::encode_address(&address);
    assert_eq!(encoded.len(), 32);
    
    let decoded = ContractUtils::decode_address(&encoded).unwrap();
    assert_eq!(decoded, address);
}

#[test]
fn test_version_constants() {
    assert!(!ghostlink::VERSION.is_empty());
    assert!(!ghostlink::DEFAULT_ENDPOINT.is_empty());
    assert!(!ghostlink::ZNS_DOMAINS.is_empty());
    assert!(!ghostlink::EXTERNAL_SERVICES.is_empty());
}

#[cfg(feature = "zns-integration")]
#[tokio::test]
async fn test_zns_integration_basic() {
    use ghostlink::{ZnsIntegration, ZnsConfig, DomainStorage};
    
    // Test ZNS configuration
    let config = ZnsConfig::default();
    assert_eq!(config.cache_ttl, 300);
    assert_eq!(config.notification_interval, 1);
    
    // Test domain storage
    let storage = DomainStorage::new();
    
    // Test that we can create a domain ownership record
    let ownership = ghostlink::DomainOwnership {
        domain: "test.ghost".to_string(),
        owner_address: "ghost1test123".to_string(),
        contract_address: "ghost_registry".to_string(),
        block_height: 1000,
        verified_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        signature: vec![1, 2, 3, 4],
    };
    
    storage.store_domain_ownership(ownership.clone()).await.unwrap();
    let retrieved = storage.get_domain_ownership("test.ghost").await.unwrap();
    
    assert!(retrieved.is_some());
    assert_eq!(retrieved.unwrap().owner_address, "ghost1test123");
}

#[cfg(feature = "zns-integration")]
#[tokio::test]
async fn test_zns_domain_record_structure() {
    use ghostlink::{DomainRecord, DnsRecord};
    use std::collections::HashMap;
    
    // Test domain record creation
    let mut crypto_addresses = HashMap::new();
    crypto_addresses.insert("ghost".to_string(), "ghost1abc123".to_string());
    crypto_addresses.insert("ethereum".to_string(), "0x1234567890abcdef".to_string());
    
    let dns_records = vec![
        DnsRecord {
            record_type: "A".to_string(),
            value: "192.168.1.1".to_string(),
            ttl: 300,
            priority: 0,
        },
        DnsRecord {
            record_type: "TXT".to_string(),
            value: "v=spf1 include:_spf.google.com ~all".to_string(),
            ttl: 300,
            priority: 0,
        },
    ];
    
    let domain_record = DomainRecord {
        domain: "example.ghost".to_string(),
        records: dns_records,
        crypto_addresses,
        owner_id: "ghost1owner123".to_string(),
        resolver: "ghost_resolver".to_string(),
        signature: vec![1, 2, 3, 4, 5],
        ttl: 300,
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        verified: true,
    };
    
    // Verify record structure
    assert_eq!(domain_record.domain, "example.ghost");
    assert_eq!(domain_record.records.len(), 2);
    assert_eq!(domain_record.crypto_addresses.len(), 2);
    assert!(domain_record.verified);
    assert_eq!(domain_record.crypto_addresses.get("ghost").unwrap(), "ghost1abc123");
}
