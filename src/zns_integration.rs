//! ZNS Integration Module
//! 
//! This module provides the bridge between ZNS (Zig Name Service) and GhostChain,
//! enabling domain resolution with blockchain verification and real-time updates.

use anyhow::Result;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::{broadcast, RwLock};
use tracing::{debug, info, warn};

use crate::client::GhostClient;
use crate::error::GhostLinkError;
use crate::proto::zns;

/// ZNS Integration with GhostChain
pub struct ZnsIntegration {
    /// GhostChain client for blockchain operations
    pub ghost_client: GhostClient,
    /// Domain ownership storage
    pub domain_storage: DomainStorage,
    /// Domain change event broadcaster
    pub change_broadcaster: broadcast::Sender<DomainChangeEvent>,
    /// Configuration
    pub config: ZnsConfig,
}

/// Domain storage for caching ownership and records
pub struct DomainStorage {
    /// Domain ownership cache
    pub ownership_cache: RwLock<HashMap<String, DomainOwnership>>,
    /// Domain records cache
    pub records_cache: RwLock<HashMap<String, DomainRecord>>,
}

/// Domain ownership information from blockchain
#[derive(Clone, Debug)]
pub struct DomainOwnership {
    /// Domain name
    pub domain: String,
    /// Owner address on GhostChain
    pub owner_address: String,
    /// Smart contract address managing this domain
    pub contract_address: String,
    /// Block height when ownership was confirmed
    pub block_height: u64,
    /// Timestamp of last verification
    pub verified_at: u64,
    /// Ownership signature
    pub signature: Vec<u8>,
}

/// Domain record with blockchain verification
#[derive(Clone, Debug)]
pub struct DomainRecord {
    /// Domain name
    pub domain: String,
    /// DNS records
    pub records: Vec<DnsRecord>,
    /// Crypto addresses mapped to chains
    pub crypto_addresses: HashMap<String, String>,
    /// Owner ID (GhostID)
    pub owner_id: String,
    /// Resolver contract address
    pub resolver: String,
    /// Domain signature for verification
    pub signature: Vec<u8>,
    /// Time-to-live for caching
    pub ttl: u64,
    /// Last update timestamp
    pub timestamp: u64,
    /// Blockchain verification status
    pub verified: bool,
}

/// DNS record
#[derive(Clone, Debug)]
pub struct DnsRecord {
    /// Record type (A, AAAA, TXT, MX, etc.)
    pub record_type: String,
    /// Record value
    pub value: String,
    /// Time-to-live
    pub ttl: u32,
    /// Priority (for MX records)
    pub priority: i32,
}

/// Domain change event
#[derive(Clone, Debug)]
pub struct DomainChangeEvent {
    /// Domain name
    pub domain: String,
    /// Change type (CREATED, UPDATED, DELETED)
    pub change_type: String,
    /// New record (if applicable)
    pub new_record: Option<DomainRecord>,
    /// Timestamp
    pub timestamp: u64,
}

/// ZNS Integration configuration
#[derive(Clone, Debug)]
pub struct ZnsConfig {
    /// Domain contract address on GhostChain
    pub domain_contract_address: String,
    /// Cache TTL for domain records (seconds)
    pub cache_ttl: u64,
    /// Blockchain verification timeout (seconds)
    pub verification_timeout: u64,
    /// Update notification interval (seconds)
    pub notification_interval: u64,
}

impl Default for ZnsConfig {
    fn default() -> Self {
        Self {
            domain_contract_address: "ghost_domain_registry".to_string(),
            cache_ttl: 300, // 5 minutes
            verification_timeout: 30, // 30 seconds
            notification_interval: 1, // 1 second for real-time updates
        }
    }
}

impl ZnsIntegration {
    /// Create a new ZNS integration instance
    pub fn new(ghost_client: GhostClient, config: ZnsConfig) -> Self {
        let (change_broadcaster, _) = broadcast::channel(1000);
        
        Self {
            ghost_client,
            domain_storage: DomainStorage::new(),
            change_broadcaster,
            config,
        }
    }

    /// Resolve a domain with blockchain verification
    pub async fn resolve_domain(&mut self, domain: &str) -> Result<DomainRecord> {
        info!("Resolving domain with blockchain verification: {}", domain);

        // Check cache first
        if let Some(cached_record) = self.domain_storage.get_domain_record(domain).await? {
            if !self.is_cache_expired(&cached_record) {
                debug!("Using cached domain record for: {}", domain);
                return Ok(cached_record);
            }
        }

        // Query ZNS for domain resolution
        let mut zns_client = self.ghost_client.zns();
        let zns_record = zns_client.resolve_domain(domain).await?;

        // Verify ownership on blockchain
        let ownership = self.verify_domain_ownership(domain).await?;

        // Convert to verified domain record
        let verified_record = DomainRecord {
            domain: domain.to_string(),
            records: zns_record.records.into_iter().map(|r| DnsRecord {
                record_type: r.record_type,
                value: r.value,
                ttl: r.ttl,
                priority: 0,
            }).collect(),
            crypto_addresses: zns_record.addresses,
            owner_id: ownership.owner_address.clone(),
            resolver: ownership.contract_address.clone(),
            signature: ownership.signature.clone(),
            ttl: self.config.cache_ttl,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            verified: true,
        };

        // Cache the verified record
        self.domain_storage.store_domain_record(verified_record.clone()).await?;

        info!("Domain {} resolved and verified successfully", domain);
        Ok(verified_record)
    }

    /// Verify domain ownership on blockchain
    async fn verify_domain_ownership(&mut self, domain: &str) -> Result<DomainOwnership> {
        debug!("Verifying domain ownership on blockchain: {}", domain);

        // Check ownership cache
        if let Some(cached_ownership) = self.domain_storage.get_domain_ownership(domain).await? {
            if !self.is_ownership_cache_expired(&cached_ownership) {
                debug!("Using cached ownership for: {}", domain);
                return Ok(cached_ownership);
            }
        }

        // Query blockchain for domain ownership
        let mut ghostchain_client = self.ghost_client.ghostchain();
        
        // Call domain registry contract
        let contract_call_result = ghostchain_client.call_contract(
            &self.config.domain_contract_address,
            "get_domain_owner",
            domain.as_bytes().to_vec(),
            "system", // System caller
            vec![], // No signature needed for read-only call
        ).await?;

        // Parse contract response
        let owner_address = String::from_utf8(contract_call_result)
            .map_err(|e| GhostLinkError::DomainResolution(format!("Invalid owner address: {}", e)))?;

        if owner_address.is_empty() {
            return Err(GhostLinkError::DomainResolution(format!("Domain not found: {}", domain)).into());
        }

        // Get current block height for verification
        // Note: We'll use a mock block height for now since we don't have direct access to the client
        let mock_block_height = 1000u64;

        let ownership = DomainOwnership {
            domain: domain.to_string(),
            owner_address,
            contract_address: self.config.domain_contract_address.clone(),
            block_height: mock_block_height,
            verified_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            signature: vec![], // TODO: Get signature from contract
        };

        // Cache the ownership
        self.domain_storage.store_domain_ownership(ownership.clone()).await?;

        info!("Domain {} ownership verified for address: {}", domain, ownership.owner_address);
        Ok(ownership)
    }

    /// Register a domain with blockchain verification
    pub async fn register_domain(
        &mut self,
        domain: &str,
        owner: &str,
        initial_records: Vec<DnsRecord>,
        signature: Vec<u8>,
    ) -> Result<String> {
        info!("Registering domain with blockchain verification: {}", domain);

        // Convert DNS records to ZNS format
        let zns_records: Vec<zns::DnsRecord> = initial_records.into_iter().map(|r| zns::DnsRecord {
            r#type: r.record_type,
            value: r.value,
            ttl: r.ttl as i32,
            priority: r.priority,
        }).collect();

        // Register domain via ZNS
        let mut zns_client = self.ghost_client.zns();
        let transaction_hash = zns_client.register_domain(
            domain,
            owner,
            zns_records,
            signature.clone(),
        ).await?;

        // Create domain change event
        let change_event = DomainChangeEvent {
            domain: domain.to_string(),
            change_type: "CREATED".to_string(),
            new_record: None, // Will be populated when resolved
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        // Broadcast change event
        if let Err(e) = self.change_broadcaster.send(change_event) {
            warn!("Failed to broadcast domain change event: {}", e);
        }

        info!("Domain {} registered successfully with transaction: {}", domain, transaction_hash);
        Ok(transaction_hash)
    }

    /// Subscribe to domain changes
    pub fn subscribe_domain_changes(&self) -> broadcast::Receiver<DomainChangeEvent> {
        self.change_broadcaster.subscribe()
    }

    /// Start monitoring domain changes
    pub async fn start_monitoring(&mut self) -> Result<()> {
        info!("Starting domain change monitoring");

        // TODO: Implement blockchain event monitoring
        // This would typically involve:
        // 1. Subscribing to blockchain events
        // 2. Monitoring contract state changes
        // 3. Broadcasting domain change events

        Ok(())
    }

    /// Check if domain record cache is expired
    fn is_cache_expired(&self, record: &DomainRecord) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        now - record.timestamp > self.config.cache_ttl
    }

    /// Check if ownership cache is expired
    fn is_ownership_cache_expired(&self, ownership: &DomainOwnership) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        now - ownership.verified_at > self.config.verification_timeout
    }
}

impl DomainStorage {
    /// Create a new domain storage instance
    pub fn new() -> Self {
        Self {
            ownership_cache: RwLock::new(HashMap::new()),
            records_cache: RwLock::new(HashMap::new()),
        }
    }

    /// Store domain ownership information
    pub async fn store_domain_ownership(&self, ownership: DomainOwnership) -> Result<()> {
        let mut cache = self.ownership_cache.write().await;
        cache.insert(ownership.domain.clone(), ownership);
        Ok(())
    }

    /// Get domain ownership information
    pub async fn get_domain_ownership(&self, domain: &str) -> Result<Option<DomainOwnership>> {
        let cache = self.ownership_cache.read().await;
        Ok(cache.get(domain).cloned())
    }

    /// Store domain record
    pub async fn store_domain_record(&self, record: DomainRecord) -> Result<()> {
        let mut cache = self.records_cache.write().await;
        cache.insert(record.domain.clone(), record);
        Ok(())
    }

    /// Get domain record
    pub async fn get_domain_record(&self, domain: &str) -> Result<Option<DomainRecord>> {
        let cache = self.records_cache.read().await;
        Ok(cache.get(domain).cloned())
    }

    /// Clear all caches
    pub async fn clear_all(&self) {
        let mut ownership_cache = self.ownership_cache.write().await;
        let mut records_cache = self.records_cache.write().await;
        
        ownership_cache.clear();
        records_cache.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_domain_storage() {
        let storage = DomainStorage::new();
        
        let ownership = DomainOwnership {
            domain: "test.ghost".to_string(),
            owner_address: "ghost1test123".to_string(),
            contract_address: "ghost_registry".to_string(),
            block_height: 1000,
            verified_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            signature: vec![1, 2, 3, 4],
        };

        // Store and retrieve ownership
        storage.store_domain_ownership(ownership.clone()).await.unwrap();
        let retrieved = storage.get_domain_ownership("test.ghost").await.unwrap();
        
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().owner_address, "ghost1test123");
    }

    #[tokio::test]
    async fn test_zns_config() {
        let config = ZnsConfig::default();
        assert_eq!(config.cache_ttl, 300);
        assert_eq!(config.verification_timeout, 30);
        assert_eq!(config.notification_interval, 1);
    }
}