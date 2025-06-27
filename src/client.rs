//! GhostLink gRPC Client Implementation

use anyhow::Result;
use std::collections::HashMap;
use tonic::transport::{Channel, ClientTlsConfig, Endpoint};
use tracing::{debug, info, warn};

use crate::cache::{BalanceRecord, CacheManager, DomainRecord};
use crate::config::GhostClientConfig;
use crate::error::GhostLinkError;
use crate::proto::{ghostchain, ghostid, zns};

/// Main GhostLink client for interacting with the GhostChain ecosystem
pub struct GhostClient {
    ghostchain_client: ghostchain::ghost_chain_client::GhostChainClient<Channel>,
    ghostid_client: ghostid::ghost_id_client::GhostIdClient<Channel>,
    zns_client: zns::zns_client::ZnsClient<Channel>,
    cache_manager: CacheManager,
    #[allow(dead_code)]
    config: GhostClientConfig,
}

impl GhostClient {
    /// Connect to GhostBridge with the given configuration
    pub async fn connect(config: GhostClientConfig) -> Result<Self> {
        config.validate()?;
        
        info!("Connecting to GhostBridge at {}", config.grpc_endpoint());
        
        let endpoint = Endpoint::from_shared(config.grpc_endpoint())?
            .timeout(config.timeout)
            .connect_timeout(config.request_timeout);

        let endpoint = if config.tls_enabled {
            endpoint.tls_config(ClientTlsConfig::new())?
        } else {
            endpoint
        };

        let channel = endpoint.connect().await
            .map_err(|e| GhostLinkError::Connection(format!("Failed to connect: {}", e)))?;

        debug!("✅ Connected to GhostBridge");

        let ghostchain_client = ghostchain::ghost_chain_client::GhostChainClient::new(channel.clone());
        let ghostid_client = ghostid::ghost_id_client::GhostIdClient::new(channel.clone());
        let zns_client = zns::zns_client::ZnsClient::new(channel);

        Ok(Self {
            ghostchain_client,
            ghostid_client,
            zns_client,
            cache_manager: CacheManager::new(),
            config,
        })
    }

    /// Get GhostChain client for blockchain operations
    pub fn ghostchain(&mut self) -> GhostChainClient {
        GhostChainClient {
            client: &mut self.ghostchain_client,
            cache_manager: &self.cache_manager,
        }
    }

    /// Get GhostID client for identity operations
    pub fn ghostid(&mut self) -> GhostIdClient {
        GhostIdClient {
            client: &mut self.ghostid_client,
        }
    }

    /// Get ZNS client for domain resolution
    pub fn zns(&mut self) -> ZnsClient {
        ZnsClient {
            client: &mut self.zns_client,
            cache_manager: &self.cache_manager,
        }
    }

    /// Get cache statistics
    pub fn cache_stats(&self) -> crate::cache::CacheStats {
        self.cache_manager.stats()
    }

    /// Clear all caches
    pub fn clear_caches(&self) {
        self.cache_manager.clear_all();
    }

    /// Clean up expired cache entries
    pub fn cleanup_caches(&self) {
        self.cache_manager.cleanup_expired();
    }
}

/// GhostChain blockchain client wrapper
pub struct GhostChainClient<'a> {
    client: &'a mut ghostchain::ghost_chain_client::GhostChainClient<Channel>,
    cache_manager: &'a CacheManager,
}

impl<'a> GhostChainClient<'a> {
    /// Get wallet balance for the given address
    pub async fn get_balance(&mut self, address: &str) -> Result<HashMap<String, String>> {
        // Check cache first
        if let Some(cached) = self.cache_manager.balance_cache.get(&address.to_string()) {
            debug!("Balance cache hit for address: {}", address);
            return Ok(cached.balances);
        }

        debug!("Fetching balance for address: {}", address);
        
        let request = tonic::Request::new(ghostchain::BalanceRequest {
            address: address.to_string(),
            tokens: vec![], // Empty means all tokens
        });

        let response = self.client.get_balance(request).await
            .map_err(|e| GhostLinkError::Status(e))?;

        let balances = response.into_inner().balances;
        
        // Cache the result
        let balance_record = BalanceRecord {
            address: address.to_string(),
            balances: balances.clone(),
            block_height: 0, // TODO: Get from response
            cached_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };
        
        self.cache_manager.balance_cache.insert(address.to_string(), balance_record);
        
        Ok(balances)
    }

    /// Send a transaction
    pub async fn send_transaction(
        &mut self,
        from: &str,
        to: &str,
        amount: &str,
        token: &str,
        signature: Vec<u8>,
    ) -> Result<String> {
        info!("Sending transaction: {} {} from {} to {}", amount, token, from, to);
        
        let request = tonic::Request::new(ghostchain::TransactionRequest {
            from: from.to_string(),
            to: to.to_string(),
            amount: amount.to_string(),
            token: token.to_string(),
            signature,
        });

        let response = self.client.send_transaction(request).await
            .map_err(|e| GhostLinkError::Status(e))?;

        let tx_response = response.into_inner();
        
        if !tx_response.success {
            let error_msg = if tx_response.error_message.is_empty() {
                "Unknown error".to_string()
            } else {
                tx_response.error_message
            };
            return Err(GhostLinkError::Transaction(error_msg).into());
        }

        // Invalidate balance cache for involved addresses
        self.cache_manager.balance_cache.remove(&from.to_string());
        self.cache_manager.balance_cache.remove(&to.to_string());

        info!("Transaction successful: {}", tx_response.transaction_hash);
        Ok(tx_response.transaction_hash)
    }

    /// Get transaction history for an address
    pub async fn get_transaction_history(
        &mut self,
        address: &str,
        limit: Option<i32>,
        cursor: Option<String>,
    ) -> Result<Vec<ghostchain::Transaction>> {
        debug!("Fetching transaction history for address: {}", address);
        
        let request = tonic::Request::new(ghostchain::HistoryRequest {
            address: address.to_string(),
            limit: limit.unwrap_or(50),
            cursor: cursor.unwrap_or_default(),
        });

        let response = self.client.get_transaction_history(request).await
            .map_err(|e| GhostLinkError::Status(e))?;

        Ok(response.into_inner().transactions)
    }

    /// Deploy a smart contract
    pub async fn deploy_contract(
        &mut self,
        wasm_code: Vec<u8>,
        constructor_args: Vec<u8>,
        deployer: &str,
        signature: Vec<u8>,
    ) -> Result<String> {
        info!("Deploying contract with {} bytes of code", wasm_code.len());
        
        let request = tonic::Request::new(ghostchain::DeployContractRequest {
            wasm_code,
            constructor_args,
            deployer: deployer.to_string(),
            signature,
        });

        let response = self.client.deploy_contract(request).await
            .map_err(|e| GhostLinkError::Status(e))?;

        let deploy_response = response.into_inner();
        
        if !deploy_response.success {
            let error_msg = if deploy_response.error_message.is_empty() {
                "Unknown error".to_string()
            } else {
                deploy_response.error_message
            };
            return Err(GhostLinkError::SmartContract(error_msg).into());
        }

        info!("Contract deployed at: {}", deploy_response.contract_address);
        Ok(deploy_response.contract_address)
    }

    /// Call a smart contract
    pub async fn call_contract(
        &mut self,
        contract_address: &str,
        method: &str,
        args: Vec<u8>,
        caller: &str,
        signature: Vec<u8>,
    ) -> Result<Vec<u8>> {
        debug!("Calling contract {} method {}", contract_address, method);
        
        let request = tonic::Request::new(ghostchain::CallContractRequest {
            contract_address: contract_address.to_string(),
            method: method.to_string(),
            args,
            caller: caller.to_string(),
            signature,
        });

        let response = self.client.call_contract(request).await
            .map_err(|e| GhostLinkError::Status(e))?;

        let call_response = response.into_inner();
        
        if !call_response.success {
            let error_msg = if call_response.error_message.is_empty() {
                "Unknown error".to_string()
            } else {
                call_response.error_message
            };
            return Err(GhostLinkError::SmartContract(error_msg).into());
        }

        Ok(call_response.result)
    }
}

/// GhostID identity client wrapper
pub struct GhostIdClient<'a> {
    client: &'a mut ghostid::ghost_id_client::GhostIdClient<Channel>,
}

impl<'a> GhostIdClient<'a> {
    /// Create a new identity
    pub async fn create_identity(
        &mut self,
        username: &str,
        public_key: &str,
    ) -> Result<ghostid::GhostIdentity> {
        info!("Creating GhostID for username: {}", username);
        
        let request = tonic::Request::new(ghostid::CreateIdentityRequest {
            username: username.to_string(),
            public_key: public_key.to_string(),
            metadata: HashMap::new(),
            signature: vec![], // TODO: Add proper signature
        });

        let response = self.client.create_identity(request).await
            .map_err(|e| GhostLinkError::Status(e))?;

        let create_response = response.into_inner();
        
        if !create_response.success {
            let error_msg = if create_response.error_message.is_empty() {
                "Unknown error".to_string()
            } else {
                create_response.error_message
            };
            return Err(GhostLinkError::Crypto(error_msg).into());
        }

        // Get the created identity
        self.get_identity(&create_response.identity_id).await
    }

    /// Get an identity by ID
    pub async fn get_identity(&mut self, identity_id: &str) -> Result<ghostid::GhostIdentity> {
        debug!("Fetching identity: {}", identity_id);
        
        let request = tonic::Request::new(ghostid::GetIdentityRequest {
            identity_id: identity_id.to_string(),
        });

        let response = self.client.get_identity(request).await
            .map_err(|e| GhostLinkError::Status(e))?;

        Ok(response.into_inner().identity.unwrap())
    }

    /// Verify an identity
    pub async fn verify_identity(
        &mut self,
        identity_id: &str,
        challenge: Vec<u8>,
        signature: Vec<u8>,
    ) -> Result<bool> {
        debug!("Verifying identity: {}", identity_id);
        
        let request = tonic::Request::new(ghostid::VerifyIdentityRequest {
            identity_id: identity_id.to_string(),
            challenge,
            signature,
        });

        let response = self.client.verify_identity(request).await
            .map_err(|e| GhostLinkError::Status(e))?;

        Ok(response.into_inner().valid)
    }
}

/// ZNS domain resolution client wrapper
pub struct ZnsClient<'a> {
    client: &'a mut zns::zns_client::ZnsClient<Channel>,
    cache_manager: &'a CacheManager,
}

impl<'a> ZnsClient<'a> {
    /// Resolve a domain name
    pub async fn resolve_domain(&mut self, domain: &str) -> Result<DomainRecord> {
        // Check cache first
        if let Some(cached) = self.cache_manager.domain_cache.get(&domain.to_string()) {
            debug!("Domain cache hit for: {}", domain);
            return Ok(cached);
        }

        info!("Resolving domain: {}", domain);
        
        let request = tonic::Request::new(zns::ResolveDomainRequest {
            domain: domain.to_string(),
            record_types: vec!["A".to_string(), "AAAA".to_string(), "TXT".to_string()],
        });

        let response = self.client.resolve_domain(request).await
            .map_err(|e| GhostLinkError::Status(e))?;

        let domain_record = response.into_inner().domain_record.unwrap();
        
        // Convert to cache format
        let cache_record = DomainRecord {
            domain: domain_record.domain,
            addresses: domain_record.crypto_addresses,
            records: domain_record.records.into_iter().map(|r| crate::cache::DnsRecord {
                record_type: r.r#type,
                value: r.value,
                ttl: r.ttl as u32,
            }).collect(),
            ttl: domain_record.ttl as u64,
            cached_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };
        
        // Cache the result
        self.cache_manager.domain_cache.insert(domain.to_string(), cache_record.clone());
        
        Ok(cache_record)
    }

    /// Resolve multiple domains
    pub async fn resolve_batch(&mut self, domains: Vec<String>) -> Result<Vec<DomainRecord>> {
        let mut results = Vec::new();
        
        for domain in domains {
            match self.resolve_domain(&domain).await {
                Ok(record) => results.push(record),
                Err(e) => {
                    warn!("Failed to resolve domain {}: {}", domain, e);
                    // Continue with other domains
                }
            }
        }
        
        Ok(results)
    }

    /// Register a new domain
    pub async fn register_domain(
        &mut self,
        domain: &str,
        owner: &str,
        initial_records: Vec<zns::DnsRecord>,
        signature: Vec<u8>,
    ) -> Result<String> {
        info!("Registering domain: {}", domain);
        
        let request = tonic::Request::new(zns::RegisterDomainRequest {
            domain: domain.to_string(),
            owner: owner.to_string(),
            initial_records,
            signature,
        });

        let response = self.client.register_domain(request).await
            .map_err(|e| GhostLinkError::Status(e))?;

        let register_response = response.into_inner();
        
        if !register_response.success {
            let error_msg = if register_response.error_message.is_empty() {
                "Unknown error".to_string()
            } else {
                register_response.error_message
            };
            return Err(GhostLinkError::DomainResolution(error_msg).into());
        }

        // Clear cache for this domain
        self.cache_manager.domain_cache.remove(&domain.to_string());

        Ok(register_response.transaction_hash)
    }
}
