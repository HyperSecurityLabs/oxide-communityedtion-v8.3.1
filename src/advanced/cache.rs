use anyhow::Result;


use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{
         SystemTime, 
         UNIX_EPOCH};
use tokio::fs;
use tokio::sync::RwLock;

// always give me serial answers 

use serde::{Serialize
              , Deserialize};

use crate::detection::analyzer::Finding;

/// Persistent cache for scan results and resume capability
pub struct ScanCache {
    cache_dir: PathBuf,
    memory_cache: RwLock<HashMap<String, CacheEntry>>,
    max_memory_entries: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheEntry {
    pub key: String,
    pub data: Vec<u8>,
    pub created_at: u64,
    pub expires_at: u64,
    pub access_count: u32,
    pub last_accessed: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanCheckpoint {
    pub scan_id: String,
    pub target: String,
    pub start_time: u64,
    pub last_update: u64,
    pub completed_urls: Vec<String>,
    pub pending_urls: Vec<String>,
    pub findings: Vec<Finding>,
    pub scan_config: HashMap<String, String>,
}

impl ScanCache {
    pub async fn new(cache_dir: &str) -> Result<Self> {
        let path = PathBuf::from(cache_dir);
        
        // Create cache directory if it doesn't exist
        if !path.exists() {
            fs::create_dir_all(&path).await?;
        }
        
        Ok(Self {
            cache_dir: path,
            memory_cache: RwLock::new(HashMap::new()),
            max_memory_entries: 1000,
        })
    }

    /// Store data in cache
    pub async fn put(&self, key: &str, data: Vec<u8>, ttl_seconds: u64) -> Result<()> {
        let now = self.now();
        let entry = CacheEntry {
            key: key.to_string(),
            data: data.clone(),
            created_at: now,
            expires_at: now + ttl_seconds,
            access_count: 0,
            last_accessed: now,
        };
        
        // Store in memory
        {
            let mut cache = self.memory_cache.write().await;
            
            // Evict old entries if at capacity
            if cache.len() >= self.max_memory_entries {
                self.evict_oldest(&mut cache).await;
            }
            
            cache.insert(key.to_string(), entry.clone());
        }
        
        // Persist to disk
        self.persist_entry(&entry).await?;
        
        Ok(())
    }

    /// Retrieve data from cache
    pub async fn get(&self, key: &str) -> Option<Vec<u8>> {
        // Check memory cache first
        {
            let mut cache = self.memory_cache.write().await;
            if let Some(entry) = cache.get_mut(key) {
                let now = self.now();
                
                // Check if expired
                if entry.expires_at < now {
                    cache.remove(key);
                    return None;
                }
                
                // Update access stats
                entry.access_count += 1;
                entry.last_accessed = now;
                
                return Some(entry.data.clone());
            }
        }
        
        // Try loading from disk
        if let Ok(entry) = self.load_entry(key).await {
            let now = self.now();
            
            if entry.expires_at >= now {
                // Add to memory cache
                let mut cache = self.memory_cache.write().await;
                cache.insert(key.to_string(), entry.clone());
                
                return Some(entry.data);
            }
        }
        
        None
    }

    /// Remove entry from cache
    pub async fn remove(&self, key: &str) -> Result<()> {
        // Remove from memory
        self.memory_cache.write().await.remove(key);
        
        // Remove from disk
        let path = self.cache_dir.join(format!("{}.cache", self.sanitize_key(key)));
        if path.exists() {
            fs::remove_file(&path).await?;
        }
        
        Ok(())
    }

    /// Clear all cache entries
    pub async fn clear(&self) -> Result<()> {
        // Clear memory
        self.memory_cache.write().await.clear();
        
        // Clear disk
        let mut entries = fs::read_dir(&self.cache_dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            if entry.path().extension().map(|e| e == "cache").unwrap_or(false) {
                fs::remove_file(entry.path()).await?;
            }
        }
        
        println!("[CACHE] Cleared all cache entries");
        Ok(())
    }

    /// Create scan checkpoint for resume
    pub async fn create_checkpoint(&self, checkpoint: &ScanCheckpoint) -> Result<()> {
        let key = format!("checkpoint_{}", checkpoint.scan_id);
        let data = serde_json::to_vec(checkpoint)?;
        
        // Checkpoints never expire
        self.put(&key, data, u64::MAX).await?;
        
          println!("[CACHE] Checkpoint created for scan {}", checkpoint.scan_id);
        Ok(())
    }

    /// Load scan checkpoint
    pub async fn load_checkpoint(&self, scan_id: &str) -> Option<ScanCheckpoint> {
        let key = format!("checkpoint_{}", scan_id);
        
        self.get(&key).await
            .and_then(|data| serde_json::from_slice(&data).ok())
    }

    /// List all checkpoints
    pub async fn list_checkpoints(&self) -> Vec<ScanCheckpoint> {
        let mut checkpoints = Vec::new();
        let cache = self.memory_cache.read().await;
        
        for (key, entry) in cache.iter() {
            if key.starts_with("checkpoint_") {
                if let Ok(cp) = serde_json::from_slice::<ScanCheckpoint>(&entry.data) {
                    checkpoints.push(cp);
                }
            }
        }
        
        checkpoints
    }

    /// Delete checkpoint
    pub async fn delete_checkpoint(&self, scan_id: &str) -> Result<()> {
        let key = format!("checkpoint_{}", scan_id);
        self.remove(&key).await
    }

    /// Cache HTTP response
    pub async fn cache_response(&self, url: &str, body: &str, status: u16) -> Result<()> {
        let key = format!("response_{}_{}", self.hash_url(url), status);
        let data = body.as_bytes().to_vec();
        
        // Cache for 1 hour
        self.put(&key, data, 3600).await?;
        Ok(())
    }

    /// Get cached response
    pub async fn get_cached_response(&self, url: &str, status: u16) -> Option<String> {
        let key = format!("response_{}_{}", self.hash_url(url), status);
        
        self.get(&key).await
            .and_then(|data| String::from_utf8(data).ok())
    }

    /// Persist entry to disk
    async fn persist_entry(&self, entry: &CacheEntry) -> Result<()> {
        let filename = format!("{}.cache", self.sanitize_key(&entry.key));
        let path = self.cache_dir.join(filename);
        
        let data = serde_json::to_vec(entry)?;
        fs::write(&path, data).await?;
        
        Ok(())
    }

    /// Load entry from disk
    async fn load_entry(&self, key: &str) -> Result<CacheEntry> {
        let filename = format!("{}.cache", self.sanitize_key(key));
        let path = self.cache_dir.join(filename);
        
        let data = fs::read(&path).await?;
        let entry = serde_json::from_slice(&data)?;
        
        Ok(entry)
    }

    /// Evict oldest entries from memory cache
    async fn evict_oldest(&self, cache: &mut HashMap<String, CacheEntry>) {
        // Find entry with oldest last_accessed
        if let Some(oldest_key) = cache.iter()
            .min_by_key(|(_, v)| v.last_accessed)
            .map(|(k, _)| k.clone()) {
            
            cache.remove(&oldest_key);
            println!("[CACHE] Evicted old entry: {}", oldest_key);
        }
    }

    /// Get cache statistics
    pub async fn get_stats(&self) -> CacheStats {
        let memory = self.memory_cache.read().await;
        let disk_count = match fs::read_dir(&self.cache_dir).await {
            Ok(mut entries) => {
                let mut count = 0;
                while let Ok(Some(_)) = entries.next_entry().await {
                    count += 1;
                }
                count
            }
            Err(_) => 0,
        };
        
        let total_memory_bytes: usize = memory.values()
            .map(|e| e.data.len())
            .sum();
        
        CacheStats {
            memory_entries: memory.len(),
            disk_entries: disk_count,
            total_memory_bytes,
            avg_entry_size: if !memory.is_empty() { 
                total_memory_bytes / memory.len() 
            } else { 
                0 
            },
        }
    }

    /// Get current timestamp
    fn now(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    /// Hash URL for cache key
    fn hash_url(&self, url: &str) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut hasher = DefaultHasher::new();
        url.hash(&mut hasher);
        format!("{:016x}", hasher.finish())
    }

    /// Sanitize key for filesystem
    fn sanitize_key(&self, key: &str) -> String {
        key.replace(|c: char| !c.is_alphanumeric() && c != '-' && c != '_', "_")
    }

    /// Clean expired entries
    pub async fn cleanup_expired(&self) -> Result<usize> {
        let now = self.now();
        let mut removed = 0;
        
        // Clean memory cache
        {
            let mut cache = self.memory_cache.write().await;
            let expired: Vec<String> = cache
                .iter()
                .filter(|(_, v)| v.expires_at < now)
                .map(|(k, _)| k.clone())
                .collect();
            
            for key in expired {
                cache.remove(&key);
                removed += 1;
            }
        }
        
        println!("[CACHE] Cleaned up {} expired entries", removed);
        Ok(removed)
    }
}

#[derive(Debug)]
pub struct CacheStats {
    pub memory_entries: usize,
    pub disk_entries: usize,
    pub total_memory_bytes: usize,
    pub avg_entry_size: usize,
}

/// Simple in-memory cache for thread-local caching
pub struct LocalCache<T: Clone> {
    data: RwLock<HashMap<String, T>>,
    max_size: usize,
}

impl<T: Clone> LocalCache<T> {
    pub fn new(max_size: usize) -> Self {
        Self {
            data: RwLock::new(HashMap::new()),
            max_size,
        }
    }

    pub async fn get(&self, key: &str) -> Option<T> {
        self.data.read().await.get(key).cloned()
    }

    pub async fn put(&self, key: String, value: T) {
        let mut data = self.data.write().await;
        
        if data.len() >= self.max_size {
            // Remove random entry
            if let Some(first_key) = data.keys().next().cloned() {
                data.remove(&first_key);
            }
        }
        
        data.insert(key, value);
    }

    pub async fn clear(&self) {
        self.data.write().await.clear();
    }
}
