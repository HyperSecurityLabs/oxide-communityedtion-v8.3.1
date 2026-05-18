//! Baseline Learning Module
//! Learns normal behavior per endpoint for anomaly detection
//! Tracks response statistics over time to establish baselines

use std::collections::HashMap;
use std::time::
{Duration,
    Instant};

use crate::zero_day::features::{


    ResponseFeatures, FeatureStats

};

/// Per-endpoint baseline profile
/// Tracks normal behavior statistics for anomaly detection
/// Uses Welford's algorithm for online mean/variance calculation
#[derive(Debug, Clone)]
pub struct EndpointBaseline {
    pub url_pattern: String,
    pub first_seen: Instant,
    pub last_updated: Instant,
    pub sample_count: usize,
    
    // Feature statistics (calculated via Welford's algorithm)
    pub response_time_stats: FeatureStats,
    pub body_length_stats: FeatureStats,
    pub entropy_stats: FeatureStats,
    
    // Welford's algorithm running state for online statistics
    // (mean, M2/sum of squares of differences from mean)
    response_time_welford: (f64, f64),  // (mean, M2)
    body_length_welford: (f64, f64),
    entropy_welford: (f64, f64),
    
    // Min/max tracking for percentile calculation
    response_time_min: f64,
    response_time_max: f64,
    body_length_min: f64,
    body_length_max: f64,
    entropy_min: f64,
    entropy_max: f64,
    
    pub status_code_distribution: HashMap<u16, usize>,
    
    // Content fingerprints of normal responses
    pub normal_hashes: Vec<String>,
    pub hash_frequency: HashMap<String, usize>,
    
    // Learned thresholds
    pub response_time_threshold: Duration,
    pub size_change_threshold: f64,
    pub entropy_change_threshold: f64,
}

// Manual serde implementation for EndpointBaseline to handle Instant and Duration
impl serde::Serialize for EndpointBaseline {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("EndpointBaseline", 13)?;
        state.serialize_field("url_pattern", &self.url_pattern)?;
        // Serialize Instants as duration since epoch (as seconds)
        state.serialize_field("first_seen_secs", &self.first_seen.elapsed().as_secs())?;
        state.serialize_field("last_updated_secs", &self.last_updated.elapsed().as_secs())?;
        state.serialize_field("sample_count", &self.sample_count)?;
        state.serialize_field("response_time_stats", &self.response_time_stats)?;
        state.serialize_field("body_length_stats", &self.body_length_stats)?;
        state.serialize_field("entropy_stats", &self.entropy_stats)?;
        state.serialize_field("status_code_distribution", &self.status_code_distribution)?;
        state.serialize_field("normal_hashes", &self.normal_hashes)?;
        state.serialize_field("hash_frequency", &self.hash_frequency)?;
        // Serialize Duration as millis
        state.serialize_field("response_time_threshold_ms", &self.response_time_threshold.as_millis())?;
        state.serialize_field("size_change_threshold", &self.size_change_threshold)?;
        state.serialize_field("entropy_change_threshold", &self.entropy_change_threshold)?;
        state.end()
    }
}

impl<'de> serde::Deserialize<'de> for EndpointBaseline {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(serde::Deserialize)]
        struct EndpointBaselineData {
            url_pattern: String,
            first_seen_secs: u64,
            last_updated_secs: u64,
            sample_count: usize,
            response_time_stats: FeatureStats,
            body_length_stats: FeatureStats,
            entropy_stats: FeatureStats,
            status_code_distribution: HashMap<u16, usize>,
            normal_hashes: Vec<String>,
            hash_frequency: HashMap<String, usize>,
            response_time_threshold_ms: u128,
            size_change_threshold: f64,
            entropy_change_threshold: f64,
        }
        
        let data = EndpointBaselineData::deserialize(deserializer)?;
        let now = Instant::now();
        
        // Clone stats before moving to avoid use-after-move
        let rt_mean = data.response_time_stats.mean;
        let rt_std = data.response_time_stats.std_dev;
        let bl_mean = data.body_length_stats.mean;
        let bl_std = data.body_length_stats.std_dev;
        let ent_mean = data.entropy_stats.mean;
        let ent_std = data.entropy_stats.std_dev;
        let rt_min = data.response_time_stats.min;
        let rt_max = data.response_time_stats.max;
        let bl_min = data.body_length_stats.min;
        let bl_max = data.body_length_stats.max;
        let ent_min = data.entropy_stats.min;
        let ent_max = data.entropy_stats.max;
        
        Ok(EndpointBaseline {
            url_pattern: data.url_pattern,
            // Use current time minus elapsed for reconstruction (approximate)
            first_seen: now - Duration::from_secs(data.first_seen_secs),
            last_updated: now - Duration::from_secs(data.last_updated_secs),
            sample_count: data.sample_count,
            response_time_stats: data.response_time_stats,
            body_length_stats: data.body_length_stats,
            entropy_stats: data.entropy_stats,
            // Reconstruct Welford state from saved stats (approximate)
            response_time_welford: (rt_mean, rt_std.powi(2) * data.sample_count as f64),
            body_length_welford: (bl_mean, bl_std.powi(2) * data.sample_count as f64),
            entropy_welford: (ent_mean, ent_std.powi(2) * data.sample_count as f64),
            // Min/max from saved stats
            response_time_min: rt_min,
            response_time_max: rt_max,
            body_length_min: bl_min,
            body_length_max: bl_max,
            entropy_min: ent_min,
            entropy_max: ent_max,
            status_code_distribution: data.status_code_distribution,
            normal_hashes: data.normal_hashes,
            hash_frequency: data.hash_frequency,
            response_time_threshold: Duration::from_millis(data.response_time_threshold_ms as u64),
            size_change_threshold: data.size_change_threshold,
            entropy_change_threshold: data.entropy_change_threshold,
        })
    }
}

impl EndpointBaseline {
    /// Create new baseline for URL pattern
    pub fn new(url_pattern: String) -> Self {
        Self {
            url_pattern,
            first_seen: Instant::now(),
            last_updated: Instant::now(),
            sample_count: 0,
            response_time_stats: FeatureStats {
                mean: 0.0,
                std_dev: 0.0,
                min: 0.0,
                max: 0.0,
                percentile_95: 0.0,
            },
            body_length_stats: FeatureStats {
                mean: 0.0,
                std_dev: 0.0,
                min: 0.0,
                max: 0.0,
                percentile_95: 0.0,
            },
            entropy_stats: FeatureStats {
                mean: 0.0,
                std_dev: 0.0,
                min: 0.0,
                max: 0.0,
                percentile_95: 0.0,
            },
            status_code_distribution: HashMap::new(),
            normal_hashes: Vec::new(),
            hash_frequency: HashMap::new(),
            response_time_threshold: Duration::from_millis(1000),
            size_change_threshold: 0.5,  // 50% change threshold
            entropy_change_threshold: 2.0,
            // Welford's algorithm initial state
            response_time_welford: (0.0, 0.0),
            body_length_welford: (0.0, 0.0),
            entropy_welford: (0.0, 0.0),
            // Min/max initial values
            response_time_min: f64::INFINITY,
            response_time_max: f64::NEG_INFINITY,
            body_length_min: f64::INFINITY,
            body_length_max: f64::NEG_INFINITY,
            entropy_min: f64::INFINITY,
            entropy_max: f64::NEG_INFINITY,
        }
    }
    
    /// Update baseline with new response sample
    pub fn update(&mut self, features: &ResponseFeatures) {
        self.sample_count += 1;
        self.last_updated = Instant::now();
        
        // Update status code distribution
        *self.status_code_distribution.entry(features.status_code).or_insert(0) += 1;
        
        // Update hash frequency (for content fingerprinting)
        *self.hash_frequency.entry(features.content_hash.clone()).or_insert(0) += 1;
        
        // Add to normal hashes if seen multiple times
        if let Some(count) = self.hash_frequency.get(&features.content_hash) {
            if *count >= 2 && !self.normal_hashes.contains(&features.content_hash) {
                self.normal_hashes.push(features.content_hash.clone());
            }
        }
        
        // Update statistics using Welford's online algorithm
        // This is numerically stable and computes mean/variance in a single pass
        self.update_welford_statistics(features);
        
        // Update thresholds based on new statistics
        self.update_thresholds();
    }
    
    /// Update statistics using Welford's online algorithm
    /// Numerically stable single-pass mean and variance calculation
    fn update_welford_statistics(&mut self, features: &ResponseFeatures) {
        let n = self.sample_count as f64;
        
        // Response time (f64)
        let rt = features.response_time_ms as f64;
        let (rt_mean, rt_m2) = self.response_time_welford;
        let delta_rt = rt - rt_mean;
        let new_rt_mean = rt_mean + delta_rt / n;
        let new_rt_m2 = rt_m2 + delta_rt * (rt - new_rt_mean);
        self.response_time_welford = (new_rt_mean, new_rt_m2);
        self.response_time_min = self.response_time_min.min(rt);
        self.response_time_max = self.response_time_max.max(rt);
        
        // Body length (f64)
        let bl = features.body_length as f64;
        let (bl_mean, bl_m2) = self.body_length_welford;
        let delta_bl = bl - bl_mean;
        let new_bl_mean = bl_mean + delta_bl / n;
        let new_bl_m2 = bl_m2 + delta_bl * (bl - new_bl_mean);
        self.body_length_welford = (new_bl_mean, new_bl_m2);
        self.body_length_min = self.body_length_min.min(bl);
        self.body_length_max = self.body_length_max.max(bl);
        
        // Entropy (f64)
        let ent = features.entropy;
        let (ent_mean, ent_m2) = self.entropy_welford;
        let delta_ent = ent - ent_mean;
        let new_ent_mean = ent_mean + delta_ent / n;
        let new_ent_m2 = ent_m2 + delta_ent * (ent - new_ent_mean);
        self.entropy_welford = (new_ent_mean, new_ent_m2);
        self.entropy_min = self.entropy_min.min(ent);
        self.entropy_max = self.entropy_max.max(ent);
        
        // Update FeatureStats structs from Welford state
        self.update_feature_stats_from_welford();
    }
    
    /// Update FeatureStats from Welford's running state
    fn update_feature_stats_from_welford(&mut self) {
        let n = self.sample_count;
        
        if n >= 2 {
            // Response time stats
            let (rt_mean, rt_m2) = self.response_time_welford;
            let rt_variance = rt_m2 / (n - 1) as f64;
            self.response_time_stats = FeatureStats {
                mean: rt_mean,
                std_dev: rt_variance.sqrt(),
                min: self.response_time_min,
                max: self.response_time_max,
                percentile_95: rt_mean + 1.645 * rt_variance.sqrt(), // 95th percentile approx
            };
            
            // Body length stats
            let (bl_mean, bl_m2) = self.body_length_welford;
            let bl_variance = bl_m2 / (n - 1) as f64;
            self.body_length_stats = FeatureStats {
                mean: bl_mean,
                std_dev: bl_variance.sqrt(),
                min: self.body_length_min,
                max: self.body_length_max,
                percentile_95: bl_mean + 1.645 * bl_variance.sqrt(),
            };
            
            // Entropy stats
            let (ent_mean, ent_m2) = self.entropy_welford;
            let ent_variance = ent_m2 / (n - 1) as f64;
            self.entropy_stats = FeatureStats {
                mean: ent_mean,
                std_dev: ent_variance.sqrt(),
                min: self.entropy_min,
                max: self.entropy_max,
                percentile_95: ent_mean + 1.645 * ent_variance.sqrt(),
            };
        } else if n == 1 {
            // First sample - initialize with first values
            let (rt_mean, _) = self.response_time_welford;
            let (bl_mean, _) = self.body_length_welford;
            let (ent_mean, _) = self.entropy_welford;
            
            self.response_time_stats.mean = rt_mean;
            self.body_length_stats.mean = bl_mean;
            self.entropy_stats.mean = ent_mean;
            
            // Std dev is undefined for single sample
            self.response_time_stats.std_dev = 0.0;
            self.body_length_stats.std_dev = 0.0;
            self.entropy_stats.std_dev = 0.0;
            
            // Min/max are the same for first sample
            self.response_time_stats.min = rt_mean;
            self.response_time_stats.max = rt_mean;
            self.body_length_stats.min = bl_mean;
            self.body_length_stats.max = bl_mean;
            self.entropy_stats.min = ent_mean;
            self.entropy_stats.max = ent_mean;
        }
    }
    
    /// Update learned thresholds based on current statistics
    fn update_thresholds(&mut self) {
        if self.sample_count >= 5 {
            // Set threshold to mean + 3 standard deviations
            // This covers 99.7% of normal values under normal distribution
            let threshold_ms = (self.response_time_stats.mean + 
                               3.0 * self.response_time_stats.std_dev) as u64;
            self.response_time_threshold = Duration::from_millis(threshold_ms.max(100)); // Min 100ms
            
            // Size change threshold based on coefficient of variation
            if self.body_length_stats.mean > 0.0 {
                let cv = self.body_length_stats.std_dev / self.body_length_stats.mean;
                // More variable = higher threshold needed
                self.size_change_threshold = (0.3 + cv).min(2.0); // Cap at 200%
            }
            
            // Entropy threshold based on observed variance
            self.entropy_change_threshold = (self.entropy_stats.std_dev * 2.0).max(1.0);
        }
    }
    
    /// Calculate statistics from feature history
    pub fn calculate_statistics(&mut self, history: &[ResponseFeatures]) {
        if history.is_empty() {
            return;
        }
        
        // Response time statistics
        let times: Vec<f64> = history.iter()
            .map(|f| f.response_time_ms as f64)
            .collect();
        self.response_time_stats = FeatureStats::from_samples(&times);
        
        // Body length statistics
        let lengths: Vec<f64> = history.iter()
            .map(|f| f.body_length as f64)
            .collect();
        self.body_length_stats = FeatureStats::from_samples(&lengths);
        
        // Entropy statistics
        let entropies: Vec<f64> = history.iter()
            .map(|f| f.entropy)
            .collect();
        self.entropy_stats = FeatureStats::from_samples(&entropies);
        
        // Update thresholds based on statistics
        self.response_time_threshold = Duration::from_millis(
            (self.response_time_stats.mean + 3.0 * self.response_time_stats.std_dev) as u64
        );
    }
    
    /// Check if response is anomalous compared to baseline
    pub fn is_anomaly(&self, features: &ResponseFeatures) -> AnomalyCheck {
        let mut anomaly_scores = Vec::new();
        let mut reasons = Vec::new();
        
        // Check response time anomaly
        if self.sample_count >= 5 {
            let time_score = self.response_time_stats.anomaly_score(features.response_time_ms as f64);
            if time_score > 0.7 {
                anomaly_scores.push(time_score);
                reasons.push(format!(
                    "Response time anomaly: {}ms (normal: {:.0}ms +/- {:.0}ms)",
                    features.response_time_ms,
                    self.response_time_stats.mean,
                    self.response_time_stats.std_dev
                ));
            }
            
            // Check body length anomaly
            let size_score = self.body_length_stats.anomaly_score(features.body_length as f64);
            if size_score > 0.7 {
                anomaly_scores.push(size_score);
                reasons.push(format!(
                    "Response size anomaly: {} bytes (normal: {:.0} +/- {:.0})",
                    features.body_length,
                    self.body_length_stats.mean,
                    self.body_length_stats.std_dev
                ));
            }
            
            // Check entropy anomaly
            let entropy_score = self.entropy_stats.anomaly_score(features.entropy);
            if entropy_score > 0.7 {
                anomaly_scores.push(entropy_score);
                reasons.push(format!(
                    "Entropy anomaly: {:.2} (normal: {:.2} +/- {:.2})",
                    features.entropy,
                    self.entropy_stats.mean,
                    self.entropy_stats.std_dev
                ));
            }
        }
        
        // Check for new content hash (possible different response)
        if self.sample_count >= 3 && !self.normal_hashes.is_empty() {
            if !self.normal_hashes.contains(&features.content_hash) {
                anomaly_scores.push(0.5);
                reasons.push("New response content pattern detected".to_string());
            }
        }
        
        // Check status code anomaly
        if self.sample_count >= 3 {
            let normal_status = self.get_most_common_status();
            if features.status_code != normal_status {
                // Different status code might indicate error-based injection
                anomaly_scores.push(0.6);
                reasons.push(format!(
                    "Status code change: {} (normal: {})",
                    features.status_code,
                    normal_status
                ));
            }
        }
        
        // Calculate overall anomaly score — use max so a single strong signal
        // isn't diluted by other normal-looking features (avoids false negatives).
        let max_score = anomaly_scores.iter().cloned().fold(0.0_f64, f64::max);

        AnomalyCheck {
            is_anomaly: max_score > 0.6,
            score: max_score,
            reasons,
            confidence: (self.sample_count as f64 / 10.0).min(1.0),
        }
    }
    
    /// Get most common status code
    fn get_most_common_status(&self) -> u16 {
        self.status_code_distribution
            .iter()
            .max_by_key(|(_, count)| *count)
            .map(|(code, _)| *code)
            .unwrap_or(200)
    }
    
    /// Create baseline from snapshot (for persistence restore)
    pub fn from_snapshot(url_pattern: &str, snapshot: &BaselineSnapshot) -> Self {
        let now = Instant::now();
        Self {
            url_pattern: url_pattern.to_string(),
            first_seen: now,
            last_updated: now,
            sample_count: snapshot.sample_count,
            response_time_stats: FeatureStats {
                mean: snapshot.response_time_mean,
                std_dev: snapshot.response_time_std,
                min: 0.0,
                max: 0.0,
                percentile_95: 0.0,
            },
            body_length_stats: FeatureStats {
                mean: snapshot.body_length_mean,
                std_dev: snapshot.body_length_std,
                min: 0.0,
                max: 0.0,
                percentile_95: 0.0,
            },
            entropy_stats: FeatureStats {
                mean: snapshot.entropy_mean,
                std_dev: snapshot.entropy_std,
                min: 0.0,
                max: 0.0,
                percentile_95: 0.0,
            },
            // Restore Welford state from snapshot stats
            response_time_welford: (snapshot.response_time_mean, 
                snapshot.response_time_std.powi(2) * snapshot.sample_count as f64),
            body_length_welford: (snapshot.body_length_mean,
                snapshot.body_length_std.powi(2) * snapshot.sample_count as f64),
            entropy_welford: (snapshot.entropy_mean,
                snapshot.entropy_std.powi(2) * snapshot.sample_count as f64),
            // Min/max unknown from snapshot, use mean as fallback
            response_time_min: snapshot.response_time_mean,
            response_time_max: snapshot.response_time_mean,
            body_length_min: snapshot.body_length_mean,
            body_length_max: snapshot.body_length_mean,
            entropy_min: snapshot.entropy_mean,
            entropy_max: snapshot.entropy_mean,
            status_code_distribution: {
                let mut map = HashMap::new();
                map.insert(snapshot.normal_status, snapshot.sample_count);
                map
            },
            normal_hashes: Vec::new(),
            hash_frequency: HashMap::new(),
            response_time_threshold: Duration::from_millis(
                (snapshot.response_time_mean + 3.0 * snapshot.response_time_std) as u64
            ),
            size_change_threshold: 0.5,
            entropy_change_threshold: 2.0,
        }
    }
    
    /// Get baseline age
    pub fn age(&self) -> Duration {
        self.first_seen.elapsed()
    }
    
    /// Get baseline health metrics
    pub fn health_metrics(&self) -> BaselineHealth {
        BaselineHealth {
            sample_count: self.sample_count,
            is_mature: self.is_mature(),
            age_seconds: self.age().as_secs(),
            coverage_score: (self.sample_count as f64 / 20.0).min(1.0),
        }
    }
    
    /// Check if baseline is mature enough for reliable detection
    pub fn is_mature(&self) -> bool {
        self.sample_count >= 5
    }
}

/// Baseline health metrics for monitoring
#[derive(Debug, Clone)]
pub struct BaselineHealth {
    pub sample_count: usize,
    pub is_mature: bool,
    pub age_seconds: u64,
    pub coverage_score: f64,
}

/// Result of anomaly check
#[derive(Debug, Clone)]
pub struct AnomalyCheck {
    pub is_anomaly: bool,
    pub score: f64,
    pub reasons: Vec<String>,
    pub confidence: f64,
}

/// Baseline learner that manages per-endpoint baselines
pub struct BaselineLearner {
    baselines: HashMap<String, EndpointBaseline>,
    history: HashMap<String, Vec<ResponseFeatures>>,
    max_history_size: usize,
}

impl BaselineLearner {
    /// Create new baseline learner
    pub fn new() -> Self {
        Self {
            baselines: HashMap::new(),
            history: HashMap::new(),
            max_history_size: 50,
        }
    }
    
    /// Learn from new response
    pub fn learn(&mut self, url: &str, features: &ResponseFeatures) {
        let url_key = self.normalize_url(url);
        
        // Get or create baseline
        let baseline = self.baselines.entry(url_key.clone()).or_insert_with(|| {
            EndpointBaseline::new(url_key.clone())
        });
        
        // Update baseline
        baseline.update(features);
        
        // Store in history for statistics calculation
        let history = self.history.entry(url_key.clone()).or_insert_with(Vec::new);
        history.push(features.clone());
        
        // Limit history size
        if history.len() > self.max_history_size {
            history.remove(0);
        }
        
        // Recalculate statistics periodically
        if baseline.sample_count % 5 == 0 {
            baseline.calculate_statistics(history);
        }
    }
    
    /// Check if response is anomalous for this endpoint
    pub fn check_anomaly(&self, url: &str, features: &ResponseFeatures) -> AnomalyCheck {
        let url_key = self.normalize_url(url);
        
        if let Some(baseline) = self.baselines.get(&url_key) {
            baseline.is_anomaly(features)
        } else {
            AnomalyCheck {
                is_anomaly: false,
                score: 0.0,
                reasons: vec!["No baseline established".to_string()],
                confidence: 0.0,
            }
        }
    }
    
    /// Get baseline for URL
    pub fn get_baseline(&self, url: &str) -> Option<&EndpointBaseline> {
        let url_key = self.normalize_url(url);
        self.baselines.get(&url_key)
    }
    
    /// Normalize URL to pattern
    /// Converts /api/users/123 to /api/users/{id} for pattern matching
    fn normalize_url(&self, url: &str) -> String {
        // Simple normalization - remove query strings and fragment IDs
        let normalized = url.split('?').next().unwrap_or(url).to_string();
        
        // Remove numeric path segments (potential IDs)
        let segments: Vec<&str> = normalized.split('/').collect();
        let normalized_segments: Vec<String> = segments.iter().map(|s| {
            if s.parse::<u64>().is_ok() {
                "{id}".to_string()
            } else if s.len() == 36 && s.matches('-').count() == 4 {
                // UUID pattern
                "{uuid}".to_string()
            } else {
                s.to_string()
            }
        }).collect();
        
        normalized_segments.join("/")
    }
    
    /// Get all baseline URLs
    pub fn get_all_baseline_urls(&self) -> Vec<String> {
        self.baselines.keys().cloned().collect()
    }
    
    /// Export baselines as snapshots for persistence
    pub fn export_baselines(&self) -> HashMap<String, BaselineSnapshot> {
        self.baselines.iter().map(|(k, v)| {
            (k.clone(), BaselineSnapshot::from_baseline(v))
        }).collect()
    }
    
    /// Get comprehensive health report for all baselines
    pub fn get_health_report(&self) -> Vec<(String, BaselineHealth)> {
        let mut report = Vec::new();
        for url in self.get_all_baseline_urls() {
            if let Some(baseline) = self.get_baseline(&url) {
                report.push((url.clone(), baseline.health_metrics()));
            }
        }
        report
    }

    /// Import baselines from snapshots (for persistence restore)
    pub fn import_baselines(&mut self, snapshots: HashMap<String, BaselineSnapshot>) {
        for (url_key, snapshot) in snapshots {
            let baseline = EndpointBaseline::from_snapshot(&url_key, &snapshot);
            self.baselines.insert(url_key.clone(), baseline);
            // Initialize empty history for imported baseline
            self.history.entry(url_key).or_insert_with(Vec::new);
        }
    }

    /// Clear all history (memory optimization)
    pub fn clear_history(&mut self) {
        self.history.clear();
    }

    /// Get detailed baseline age information
    pub fn get_baseline_ages(&self) -> Vec<(String, Duration)> {
        let mut ages = Vec::new();
        for url in self.get_all_baseline_urls() {
            if let Some(baseline) = self.get_baseline(&url) {
                ages.push((url.clone(), baseline.age()));
            }
        }
        ages
    }

    /// Get only mature baselines that are ready for detection
    pub fn get_mature_baselines(&self) -> Vec<&EndpointBaseline> {
        self.baselines.values().filter(|b| b.is_mature()).collect()
    }

    /// Save baseline to file with JSON serialization
    pub fn save_baseline_to_file(&self, url: &str, path: &str) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(baseline) = self.get_baseline(url) {
            let snapshot = BaselineSnapshot::from_baseline(baseline);
            let json = snapshot.to_json()?;
            std::fs::write(path, json)?;
            Ok(())
        } else {
            Err("Baseline not found".into())
        }
    }

    /// Load baseline from file
    pub fn load_baseline_from_file(&mut self, url: &str, path: &str) -> Result<(), Box<dyn std::error::Error>> {
        let json = std::fs::read_to_string(path)?;
        let snapshot = BaselineSnapshot::from_json(&json)?;

        if !snapshot.is_valid() {
            return Err("Invalid baseline snapshot data".into());
        }

        let url_key = self.normalize_url(url);
        let baseline = EndpointBaseline::from_snapshot(&url_key, &snapshot);
        self.baselines.insert(url_key.clone(), baseline);
        self.history.entry(url_key).or_insert_with(Vec::new);
        Ok(())
    }
}

/// Serializable baseline snapshot for persistence
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BaselineSnapshot {
    pub url_pattern: String,
    pub sample_count: usize,
    pub response_time_mean: f64,
    pub response_time_std: f64,
    pub body_length_mean: f64,
    pub body_length_std: f64,
    pub entropy_mean: f64,
    pub entropy_std: f64,
    pub normal_status: u16,
}

impl BaselineSnapshot {
    pub fn from_baseline(baseline: &EndpointBaseline) -> Self {
        Self {
            url_pattern: baseline.url_pattern.clone(),
            sample_count: baseline.sample_count,
            response_time_mean: baseline.response_time_stats.mean,
            response_time_std: baseline.response_time_stats.std_dev,
            body_length_mean: baseline.body_length_stats.mean,
            body_length_std: baseline.body_length_stats.std_dev,
            entropy_mean: baseline.entropy_stats.mean,
            entropy_std: baseline.entropy_stats.std_dev,
            normal_status: baseline.get_most_common_status(),
        }
    }

    /// Deserialize from JSON string
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// Serialize to JSON string
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Validate snapshot has statistically sound data
    pub fn is_valid(&self) -> bool {
        self.sample_count >= 5
            && self.response_time_std >= 0.0
            && self.body_length_std >= 0.0
            && self.entropy_std >= 0.0
            && self.response_time_mean > 0.0
    }
}
