//! Caching utilities for GhostLink

use dashmap::DashMap;
use lru::LruCache;
use serde::{Deserialize, Serialize};
use std::hash::Hash;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// TTL cache entry
#[derive(Debug, Clone)]
struct CacheEntry<T> {
    value: T,
    expires_at: Instant,
}

impl<T> CacheEntry<T> {
    fn new(value: T, ttl: Duration) -> Self {
        Self {
            value,
            expires_at: Instant::now() + ttl,
        }
    }

    fn is_expired(&self) -> bool {
        Instant::now() > self.expires_at
    }
}

/// Thread-safe TTL cache with LRU eviction
pub struct TtlCache<K, V> {
    cache: Arc<Mutex<LruCache<K, CacheEntry<V>>>>,
    default_ttl: Duration,
}

impl<K, V> TtlCache<K, V>
where
    K: Hash + Eq + Clone,
    V: Clone,
{
    /// Create a new TTL cache with specified capacity and default TTL
    pub fn new(capacity: usize, default_ttl: Duration) -> Self {
        Self {
            cache: Arc::new(Mutex::new(
                LruCache::new(NonZeroUsize::new(capacity).unwrap())
            )),
            default_ttl,
        }
    }

    /// Insert a value with default TTL
    pub fn insert(&self, key: K, value: V) {
        self.insert_with_ttl(key, value, self.default_ttl);
    }

    /// Insert a value with custom TTL
    pub fn insert_with_ttl(&self, key: K, value: V, ttl: Duration) {
        let entry = CacheEntry::new(value, ttl);
        let mut cache = self.cache.lock().unwrap();
        cache.put(key, entry);
    }

    /// Get a value from cache
    pub fn get(&self, key: &K) -> Option<V> {
        let mut cache = self.cache.lock().unwrap();
        
        if let Some(entry) = cache.get(key) {
            if !entry.is_expired() {
                return Some(entry.value.clone());
            } else {
                // Remove expired entry
                cache.pop(key);
            }
        }
        
        None
    }

    /// Remove a value from cache
    pub fn remove(&self, key: &K) -> Option<V> {
        let mut cache = self.cache.lock().unwrap();
        cache.pop(key).map(|entry| entry.value)
    }

    /// Clear all entries
    pub fn clear(&self) {
        let mut cache = self.cache.lock().unwrap();
        cache.clear();
    }

    /// Get cache size
    pub fn len(&self) -> usize {
        let cache = self.cache.lock().unwrap();
        cache.len()
    }

    /// Check if cache is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Clean up expired entries
    pub fn cleanup_expired(&self) {
        let mut cache = self.cache.lock().unwrap();
        let mut expired_keys = Vec::new();
        
        // Collect expired keys
        for (key, entry) in cache.iter() {
            if entry.is_expired() {
                expired_keys.push(key.clone());
            }
        }
        
        // Remove expired entries
        for key in expired_keys {
            cache.pop(&key);
        }
    }
}

/// Concurrent hash map cache without TTL
pub struct ConcurrentCache<K, V> {
    cache: DashMap<K, V>,
    max_size: usize,
}

impl<K, V> ConcurrentCache<K, V>
where
    K: Hash + Eq + Clone,
    V: Clone,
{
    /// Create a new concurrent cache
    pub fn new(max_size: usize) -> Self {
        Self {
            cache: DashMap::new(),
            max_size,
        }
    }

    /// Insert a value
    pub fn insert(&self, key: K, value: V) {
        // Simple eviction: if we're at capacity, remove entries to make space
        while self.cache.len() >= self.max_size {
            // Find any key to remove (simple FIFO-like eviction)
            let key_to_remove = {
                let mut iter = self.cache.iter();
                if let Some(entry) = iter.next() {
                    let key = entry.key().clone();
                    drop(iter); // Release iterator before removal
                    Some(key)
                } else {
                    break; // Cache is empty
                }
            };
            
            if let Some(k) = key_to_remove {
                self.cache.remove(&k);
            } else {
                break;
            }
        }
        
        self.cache.insert(key, value);
    }

    /// Get a value
    pub fn get(&self, key: &K) -> Option<V> {
        self.cache.get(key).map(|entry| entry.value().clone())
    }

    /// Remove a value
    pub fn remove(&self, key: &K) -> Option<V> {
        self.cache.remove(key).map(|(_, value)| value)
    }

    /// Clear all entries
    pub fn clear(&self) {
        self.cache.clear();
    }

    /// Get cache size
    pub fn len(&self) -> usize {
        self.cache.len()
    }

    /// Check if cache is empty
    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }

    /// Check if key exists
    pub fn contains_key(&self, key: &K) -> bool {
        self.cache.contains_key(key)
    }
}

/// Domain resolution cache
pub type DomainCache = TtlCache<String, DomainRecord>;

/// Balance cache for wallet addresses
pub type BalanceCache = TtlCache<String, BalanceRecord>;

/// Contract state cache
pub type ContractCache = ConcurrentCache<String, ContractRecord>;

/// Domain record for caching
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainRecord {
    pub domain: String,
    pub addresses: std::collections::HashMap<String, String>, // chain -> address
    pub records: Vec<DnsRecord>,
    pub ttl: u64,
    pub cached_at: u64,
}

/// DNS record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsRecord {
    pub record_type: String,
    pub value: String,
    pub ttl: u32,
}

/// Balance record for caching
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BalanceRecord {
    pub address: String,
    pub balances: std::collections::HashMap<String, String>, // token -> amount
    pub block_height: u64,
    pub cached_at: u64,
}

/// Contract record for caching
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractRecord {
    pub address: String,
    pub bytecode: Option<Vec<u8>>,
    pub abi: Option<String>,
    pub state: std::collections::HashMap<String, Vec<u8>>, // key -> value
    pub cached_at: u64,
}

/// Cache manager for all GhostLink caches
pub struct CacheManager {
    pub domain_cache: DomainCache,
    pub balance_cache: BalanceCache,
    pub contract_cache: ContractCache,
}

impl CacheManager {
    /// Create a new cache manager with default settings
    pub fn new() -> Self {
        Self {
            domain_cache: TtlCache::new(1000, Duration::from_secs(300)), // 5 minutes
            balance_cache: TtlCache::new(5000, Duration::from_secs(60)),  // 1 minute
            contract_cache: ConcurrentCache::new(1000),
        }
    }

    /// Create cache manager with custom settings
    pub fn with_settings(
        domain_capacity: usize,
        domain_ttl: Duration,
        balance_capacity: usize,
        balance_ttl: Duration,
        contract_capacity: usize,
    ) -> Self {
        Self {
            domain_cache: TtlCache::new(domain_capacity, domain_ttl),
            balance_cache: TtlCache::new(balance_capacity, balance_ttl),
            contract_cache: ConcurrentCache::new(contract_capacity),
        }
    }

    /// Clear all caches
    pub fn clear_all(&self) {
        self.domain_cache.clear();
        self.balance_cache.clear();
        self.contract_cache.clear();
    }

    /// Clean up expired entries in TTL caches
    pub fn cleanup_expired(&self) {
        self.domain_cache.cleanup_expired();
        self.balance_cache.cleanup_expired();
    }

    /// Get cache statistics
    pub fn stats(&self) -> CacheStats {
        CacheStats {
            domain_entries: self.domain_cache.len(),
            balance_entries: self.balance_cache.len(),
            contract_entries: self.contract_cache.len(),
        }
    }
}

impl Default for CacheManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Cache statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheStats {
    pub domain_entries: usize,
    pub balance_entries: usize,
    pub contract_entries: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_ttl_cache() {
        let cache = TtlCache::new(2, Duration::from_millis(100));
        
        cache.insert("key1", "value1");
        cache.insert("key2", "value2");
        
        assert_eq!(cache.get(&"key1"), Some("value1"));
        assert_eq!(cache.get(&"key2"), Some("value2"));
        
        // Wait for expiration
        thread::sleep(Duration::from_millis(150));
        
        assert_eq!(cache.get(&"key1"), None);
        assert_eq!(cache.get(&"key2"), None);
    }

    #[test]
    fn test_concurrent_cache() {
        let cache = ConcurrentCache::new(2);
        
        cache.insert("key1", "value1");
        cache.insert("key2", "value2");
        
        assert_eq!(cache.get(&"key1"), Some("value1"));
        assert_eq!(cache.get(&"key2"), Some("value2"));
        
        // Adding a third item should evict one
        cache.insert("key3", "value3");
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn test_cache_manager() {
        let manager = CacheManager::new();
        
        let domain_record = DomainRecord {
            domain: "test.ghost".to_string(),
            addresses: std::collections::HashMap::new(),
            records: vec![],
            ttl: 300,
            cached_at: 0,
        };
        
        manager.domain_cache.insert("test.ghost".to_string(), domain_record.clone());
        
        let retrieved = manager.domain_cache.get(&"test.ghost".to_string());
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().domain, "test.ghost");
        
        let stats = manager.stats();
        assert_eq!(stats.domain_entries, 1);
        assert_eq!(stats.balance_entries, 0);
        assert_eq!(stats.contract_entries, 0);
    }
}
