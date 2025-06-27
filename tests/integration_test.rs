//! Integration tests for GhostLink v0.1.0

use anyhow::Result;

#[tokio::test]
async fn test_ghostlink_basic_types() {
    // Test basic type compilation
    use ghostlink::error::GhostLinkError;
    
    let error = GhostLinkError::ConnectionError("test".to_string());
    assert!(format!("{:?}", error).contains("ConnectionError"));
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
