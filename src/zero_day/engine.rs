//! Zero-Day Detection Engine
//! Main orchestrator combining all ML components
//! Provides high-level API for zero-day vulnerability detection

use std::sync::Arc;
use std::time::Instant;

use tokio::sync::RwLock;

use crate::http::response::HttpResponse;
use crate::zero_day::features::ResponseFeatures;
use crate::zero_day::anomaly::
{   AnomalyEngine,
           AnomalyResult};

/// High-level zero-day detection engine
/// Combines ML classification, baseline learning, and anomaly detection
pub struct ZeroDayEngine {
    /// Core anomaly detection engine
    anomaly_engine: Arc<AnomalyEngine>,
    
    /// Scan statistics
    stats: Arc<RwLock<ScanStats>>,
    
    /// Configuration
    config: EngineConfig,
}

/// Engine configuration
#[derive(Debug, Clone)]
pub struct EngineConfig {
    /// Enable learning mode (build baselines)
    pub learning_mode: bool,
    
    
    /// Threshold for flagging as zero-day
    pub detection_threshold: f64,
    
    /// Enable time-based detection
    pub enable_time_based_detection: bool,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            learning_mode: true,
            detection_threshold: 0.7,
            enable_time_based_detection: true,
        }
    }
}

/// Scan statistics
#[derive(Debug)]
pub struct ScanStats {
    pub responses_analyzed: usize,
    pub anomalies_detected: usize,
    pub vulnerabilities_found: usize,
    pub baselines_established: usize,
    pub start_time: Instant,
}

impl Default for ScanStats {
    fn default() -> Self {
        Self {
            responses_analyzed: 0,
            anomalies_detected: 0,
            vulnerabilities_found: 0,
            baselines_established: 0,
            start_time: Instant::now(),
        }
    }
}

impl ScanStats {
    pub fn new() -> Self {
        Self {
            start_time: Instant::now(),
            ..Default::default()
        }
    }
}

/// Zero-day detection report
#[derive(Debug, Clone)]
pub struct DetectionReport {
    pub is_zero_day: bool,
    pub confidence: f64,
    pub anomaly_result: AnomalyResult,
    pub recommendations: Vec<String>,
}

impl ZeroDayEngine {
    /// Create new zero-day detection engine
    pub fn new() -> Self {
        Self::with_config(EngineConfig::default())
    }
    
    /// Create with custom configuration
    pub fn with_config(config: EngineConfig) -> Self {
        Self {
            anomaly_engine: Arc::new(AnomalyEngine::new()),
            stats: Arc::new(RwLock::new(ScanStats::new())),
            config,
        }
    }
    
    /// Analyze single response for zero-day indicators
    pub async fn analyze_response(
        &self,
        url: &str,
        response: &HttpResponse,
        response_time_ms: u64,
    ) -> DetectionReport {
        // Extract features (zero out response time if disabled)
        let effective_time = if self.config.enable_time_based_detection { response_time_ms } else { 0 };
        let features = ResponseFeatures::from_response(response, url, effective_time);
        
        // If in learning mode, update baselines
        if self.config.learning_mode {
            self.anomaly_engine.learn(url, &features).await;
            
            // Periodically check baseline health (every 100 responses)
            let stats = self.stats.read().await;
            let response_count = stats.responses_analyzed;
            let should_check_health = response_count % 100 == 0 && response_count > 0;
            let should_export = response_count % 500 == 0;
            drop(stats);
            
            if should_check_health {
                // Trigger baseline health check asynchronously
                let health = self.anomaly_engine.get_baseline_health().await;
                for (baseline_url, health_metrics) in health {
                    if !health_metrics.is_mature {
                        tracing::info!("Baseline for {} is not yet mature ({} samples, {:.1}% coverage)", 
                            baseline_url, health_metrics.sample_count, health_metrics.coverage_score * 100.0);
                    }
                    // Check if baseline is stale (older than 7 days)
                    let age_days = health_metrics.age_seconds / 86400;
                    if age_days > 7 {
                        tracing::warn!("Baseline for {} is stale ({} days old)", baseline_url, age_days);
                    }
                }
                
                // Export baselines periodically for backup (every 500 responses)
                if should_export {
                    match self.anomaly_engine.export_data().await {
                        Ok(engine_data) => {
                            // Log baseline statistics
                            let total_baselines = engine_data.baselines.len();
                            tracing::info!("Exported {} baselines for backup", total_baselines);
                            
                            // Create statistics for monitoring
                            let _baseline_stats = crate::zero_day::anomaly::BaselineStatistics {
                                classifier_trained: false, // Would need to get from classifier
                            };
                        }
                        Err(e) => tracing::warn!("Failed to export baseline data: {}", e),
                    }
                }
            }
        }
        
        // Run anomaly detection
        let anomaly_result = self.anomaly_engine.analyze(url, &features).await;
        
        // Update statistics
        {
            let mut stats = self.stats.write().await;
            stats.responses_analyzed += 1;
            if anomaly_result.is_anomaly {
                stats.anomalies_detected += 1;
            }
            if anomaly_result.is_vulnerable {
                stats.vulnerabilities_found += 1;
            }
        }
        
        // Generate recommendations
        let recommendations = self.generate_recommendations(&anomaly_result);
        
        // Log severity level for monitoring
        let severity_level = match &anomaly_result.severity {
            crate::zero_day::classifier::Severity::Critical => "CRITICAL",
            crate::zero_day::classifier::Severity::High => "HIGH",
            crate::zero_day::classifier::Severity::Medium => "MEDIUM",
            crate::zero_day::classifier::Severity::Low => "LOW",
        };
        
        if anomaly_result.is_vulnerable {
            tracing::warn!("Potential vulnerability detected at {} (severity: {}, confidence: {:.2})",
                url, severity_level, anomaly_result.confidence);
        }
        
        DetectionReport {
            is_zero_day: self.is_zero_day(&anomaly_result),
            confidence: anomaly_result.combined_score,
            anomaly_result,
            recommendations,
        }
    }
    
    /// Check if detection qualifies as zero-day
    fn is_zero_day(&self, result: &AnomalyResult) -> bool {
        // Without timing signal require stricter anomaly threshold
        let min_anomaly = if self.config.enable_time_based_detection {
            self.config.detection_threshold
        } else {
            self.config.detection_threshold * 1.5
        };
        let anomaly_indicator = result.anomaly_score > min_anomaly;
        let vuln_indicator = result.vulnerability_score > self.config.detection_threshold;
        let novel_indicator = result.vulnerability_type.as_ref()
            .map(|t| t.contains("Unknown") || t.contains("Potential"))
            .unwrap_or(false);
        
        (anomaly_indicator && vuln_indicator) || (vuln_indicator && novel_indicator)
    }
    
    /// Generate remediation recommendations
    fn generate_recommendations(&self, result: &AnomalyResult) -> Vec<String> {
        let mut recommendations = Vec::new();
        
        if result.is_vulnerable {
            recommendations.push(
                "Investigate potential vulnerability - unusual response pattern detected".to_string()
            );
            
            if result.anomaly_score > 0.8 {
                recommendations.push(
                    "High anomaly score - verify behavior with manual testing".to_string()
                );
            }
            
            match result.vulnerability_type.as_deref() {
                Some("SQL Injection") => {
                    recommendations.push("Implement parameterized queries".to_string());
                    recommendations.push("Add input validation".to_string());
                }
                Some("Path Traversal") => {
                    recommendations.push("Validate and sanitize file paths".to_string());
                    recommendations.push("Use allowlist for accessible files".to_string());
                }
                Some("Information Disclosure") => {
                    recommendations.push("Disable detailed error messages".to_string());
                    recommendations.push("Review error handling".to_string());
                }
                _ => {
                    recommendations.push("Perform manual security assessment".to_string());
                    recommendations.push("Consider code review of affected endpoint".to_string());
                }
            }
        }
        
        if result.is_anomaly && !result.is_vulnerable {
            recommendations.push(
                "Response differs from baseline - may indicate configuration change".to_string()
            );
        }
        
        recommendations
    }
    
    /// Get current scan statistics
    pub async fn get_stats(&self) -> ScanStats {
        let stats = self.stats.read().await;
        stats.clone()
    }
    
    /// Reset statistics
    pub async fn reset_stats(&self) {
        let mut stats = self.stats.write().await;
        *stats = ScanStats::new();
    }
    
    /// Train classifier with labeled samples
    pub async fn train_classifier(&self, samples: Vec<(ResponseFeatures, bool)>) -> Result<(), String> {
        self.anomaly_engine.train_classifier(samples).await
    }
    
    /// Export detection model for persistence using bincode serialization
    pub async fn export_model(&self) -> Result<Vec<u8>, String> {
        // Export anomaly engine data
        let engine_data = self.anomaly_engine.export_data().await
            .map_err(|e| format!("Failed to export engine data: {}", e))?;
        
        // Serialize with bincode
        match bincode::serialize(&engine_data) {
            Ok(data) => Ok(data),
            Err(e) => Err(format!("Serialization failed: {}", e)),
        }
    }
    
    /// Import detection model from serialized data
    pub async fn import_model(&mut self, data: &[u8]) -> Result<(), String> {
        // Deserialize with bincode
        let engine_data: crate::zero_day::anomaly::AnomalyEngineData = 
            bincode::deserialize(data)
                .map_err(|e| format!("Deserialization failed: {}", e))?;
        
        // Import the data
        self.anomaly_engine.import_data(engine_data).await
            .map_err(|e| format!("Import failed: {}", e))
    }
    
    /// Export model to JSON for human-readable inspection
    pub async fn export_model_json(&self) -> Result<String, String> {
        let engine_data = self.anomaly_engine.export_data().await
            .map_err(|e| format!("Failed to export engine data: {}", e))?;
        
        serde_json::to_string_pretty(&engine_data)
            .map_err(|e| format!("JSON serialization failed: {}", e))
    }
    
    /// Save model to file
    pub async fn save_model_to_file(&self, path: &str) -> Result<(), String> {
        let data = self.export_model().await?;
        std::fs::write(path, &data)
            .map_err(|e| format!("Failed to write file: {}", e))
    }
    
    /// Get comprehensive engine status
    pub async fn get_status(&self) -> EngineStatus {
        let baseline_stats = self.anomaly_engine.get_detailed_baseline_stats().await;
        let (anomaly_thresh, vuln_thresh) = self.anomaly_engine.get_thresholds().await;
        
        EngineStatus {
            classifier_trained: baseline_stats.classifier_trained,
            anomaly_threshold: anomaly_thresh,
            vulnerability_threshold: vuln_thresh,
        }
    }
    
    /// Get baseline health report for monitoring
    pub async fn get_baseline_health(&self) -> Vec<(String, crate::zero_day::baseline::BaselineHealth)> {
        self.anomaly_engine.get_baseline_health().await
    }
    
    /// Save baseline to file for persistence
    pub async fn save_baseline(&self, url: &str, path: &str) -> Result<(), Box<dyn std::error::Error>> {
        self.anomaly_engine.save_baseline(url, path).await
    }
    
    /// Load baseline from file
    pub async fn load_baseline(&self, url: &str, path: &str) -> Result<(), Box<dyn std::error::Error>> {
        self.anomaly_engine.load_baseline(url, path).await
    }
    
    /// Get mature baselines ready for detection
    pub async fn get_mature_baselines(&self) -> Vec<String> {
        self.anomaly_engine.get_mature_baselines().await
    }
    
    /// Get baseline ages for monitoring staleness
    pub async fn get_baseline_ages(&self) -> Vec<(String, std::time::Duration)> {
        self.anomaly_engine.get_baseline_ages().await
    }
    
    /// Clear history for memory optimization
    pub async fn clear_history(&self) {
        self.anomaly_engine.clear_history().await;
    }
    
    /// Import baselines with validation
    pub async fn import_baselines_validated(&self, data: crate::zero_day::anomaly::AnomalyEngineData) -> Result<Vec<(String, bool)>, String> {
        self.anomaly_engine.import_baselines_validated(data).await
    }
    
}

/// Comprehensive engine status for monitoring
#[derive(Debug, Clone)]
pub struct EngineStatus {
    pub classifier_trained: bool,
    pub anomaly_threshold: f64,
    pub vulnerability_threshold: f64,
}

impl Clone for ScanStats {
    fn clone(&self) -> Self {
        Self {
            responses_analyzed: self.responses_analyzed,
            anomalies_detected: self.anomalies_detected,
            vulnerabilities_found: self.vulnerabilities_found,
            baselines_established: self.baselines_established,
            start_time: self.start_time,
        }
    }
}
