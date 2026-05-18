//! Anomaly Detection Engine
//! High-level anomaly detection combining ML classifier and baseline analysis

use std::sync::Arc;

use tokio::sync::RwLock;

use crate::zero_day::features::ResponseFeatures;
use crate::zero_day::classifier::{VulnerabilityClassifier, 
                  RuleBasedClassifier,
                      ClassificationResult,
                                    Severity};
use crate::zero_day::baseline::{ 
                 BaselineLearner, AnomalyCheck};

/// Anomaly detection result combining multiple signals
#[derive(Debug, Clone)]
pub struct AnomalyResult {
    pub is_anomaly: bool,
    pub is_vulnerable: bool,
    pub anomaly_score: f64,
    pub vulnerability_score: f64,
    pub combined_score: f64,
    pub reasons: Vec<String>,
    pub vulnerability_type: Option<String>,
    pub severity: Severity,
    pub confidence: f64,
}

/// Anomaly detection engine combining multiple detection methods
pub struct AnomalyEngine {
    /// ML classifier for vulnerability detection
    classifier: Arc<RwLock<VulnerabilityClassifier>>,
    
    /// Baseline learner for per-endpoint anomaly detection
    baseline_learner: Arc<RwLock<BaselineLearner>>,
    
    /// Threshold for flagging as anomaly
    anomaly_threshold: Arc<RwLock<f64>>,
    
    /// Threshold for flagging as vulnerable
    vulnerability_threshold: Arc<RwLock<f64>>,
    
    /// Enable rule-based fallback when ML not trained
    use_rule_based_fallback: bool,
}

impl AnomalyEngine {
    /// Create new anomaly detection engine
    pub fn new() -> Self {
        Self {
            classifier: Arc::new(RwLock::new(VulnerabilityClassifier::new())),
            baseline_learner: Arc::new(RwLock::new(BaselineLearner::new())),
            anomaly_threshold: Arc::new(RwLock::new(0.6)),
            vulnerability_threshold: Arc::new(RwLock::new(0.7)),
            use_rule_based_fallback: true,
        }
    }
    
    /// Process response through anomaly detection pipeline
    pub async fn analyze(&self, url: &str, features: &ResponseFeatures) -> AnomalyResult {
        // Step 1: Check baseline anomaly
        let baseline_check = self.check_baseline(url, features).await;
        
        // Step 2: ML classification
        let ml_result = self.classify(features).await;
        
        // Step 3: Rule-based detection (fallback or additional signal)
        let rule_result = self.rule_based_check(features).await;
        
        // Step 4: Combine scores
        let combined = self.combine_results(&baseline_check, &ml_result, &rule_result);
        
        // Step 5: Build result
        self.build_result(&combined, &baseline_check, &ml_result, &rule_result).await
    }
    
    /// Check against learned baseline
    async fn check_baseline(&self, url: &str, features: &ResponseFeatures) -> AnomalyCheck {
        let learner = self.baseline_learner.read().await;
        learner.check_anomaly(url, features)
    }
    
    /// ML classification
    async fn classify(&self, features: &ResponseFeatures) -> ClassificationResult {
        let classifier = self.classifier.read().await;
        
        if classifier.is_trained() {
            classifier.predict(features)
        } else if self.use_rule_based_fallback {
            RuleBasedClassifier::classify(features)
        } else {
            ClassificationResult {
                is_vulnerable: false,
                confidence: 0.0,
                vulnerability_type: None,
            }
        }
    }
    
    /// Rule-based detection
    async fn rule_based_check(&self, features: &ResponseFeatures) -> ClassificationResult {
        RuleBasedClassifier::classify(features)
    }
    
    /// Combine multiple detection signals
    fn combine_results(
        &self,
        baseline: &AnomalyCheck,
        ml: &ClassificationResult,
        rule: &ClassificationResult,
    ) -> CombinedScores {
        // Weights: ML has highest weight when trained (confidence > 0),
        // baseline adds behavioral context, rule-based is a lightweight signal.
        let ml_weight       = if ml.confidence > 0.0 { 0.5 } else { 0.1 };
        let baseline_weight = if baseline.confidence > 0.5 { 0.3 } else { 0.15 };
        let rule_weight     = 0.2;

        // Normalize so weights sum to 1.0
        let total_weight = ml_weight + baseline_weight + rule_weight;
        let ml_norm       = ml_weight       / total_weight;
        let baseline_norm = baseline_weight / total_weight;
        let rule_norm     = rule_weight     / total_weight;

        // Vulnerability score: one signal per source, no double-counting
        let ml_vuln_signal   = if ml.is_vulnerable   { ml.confidence }   else { 0.0 };
        let rule_vuln_signal = if rule.is_vulnerable { rule.confidence } else { 0.0 };
        let vuln_score = ml_vuln_signal * ml_norm
                       + rule_vuln_signal * rule_norm;

        // Anomaly score: baseline deviation + rule signal
        let baseline_signal = if baseline.is_anomaly { baseline.score } else { baseline.score * 0.3 };
        let anomaly_score = baseline_signal * baseline_norm
                          + rule_vuln_signal * rule_norm * 0.5;

        // Combined: vulnerability is the primary signal
        let combined = (vuln_score * 0.7 + anomaly_score * 0.3).min(1.0);

        CombinedScores {
            vulnerability_score: vuln_score.min(1.0),
            anomaly_score: anomaly_score.min(1.0),
            combined_score: combined,
        }
    }
    
    /// Build final anomaly result
    async fn build_result(
        &self,
        scores: &CombinedScores,
        baseline: &AnomalyCheck,
        ml: &ClassificationResult,
        rule: &ClassificationResult,
    ) -> AnomalyResult {
        let mut reasons = Vec::new();
        
        // Collect reasons from all signals
        reasons.extend(baseline.reasons.clone());
        
        if ml.is_vulnerable {
            reasons.push(format!(
                "ML classifier detected {} with {:.1}% confidence",
                ml.vulnerability_type.as_deref().unwrap_or("vulnerability"),
                ml.confidence * 100.0
            ));
        }
        
        if rule.is_vulnerable && rule.confidence > 0.5 {
            reasons.push(format!(
                "Rule-based detection: {} ({:.1}% confidence)",
                rule.vulnerability_type.as_deref().unwrap_or("suspicious pattern"),
                rule.confidence * 100.0
            ));
        }
        
        // Determine final vulnerability type
        let vulnerability_type = if ml.is_vulnerable && ml.confidence > 0.6 {
            ml.vulnerability_type.clone()
        } else if rule.is_vulnerable && rule.confidence > 0.6 {
            rule.vulnerability_type.clone()
        } else {
            None
        };
        
        // Calculate confidence based on signal agreement
        let confidence = self.calculate_confidence(scores, baseline, ml, rule);
        
        // Read thresholds (async - do not block in async context)
        let anomaly_threshold = *self.anomaly_threshold.read().await;
        let vulnerability_threshold = *self.vulnerability_threshold.read().await;
        
        AnomalyResult {
            is_anomaly: scores.anomaly_score > anomaly_threshold,
            is_vulnerable: scores.vulnerability_score > vulnerability_threshold,
            anomaly_score: scores.anomaly_score,
            vulnerability_score: scores.vulnerability_score,
            combined_score: scores.combined_score,
            reasons,
            vulnerability_type,
            severity: Severity::from_score(scores.combined_score),
            confidence,
        }
    }
    
    /// Calculate confidence based on signal agreement
    fn calculate_confidence(
        &self,
        _scores: &CombinedScores,
        baseline: &AnomalyCheck,
        ml: &ClassificationResult,
        rule: &ClassificationResult,
    ) -> f64 {
        let signals_agree = (ml.is_vulnerable && rule.confidence > 0.5) ||
                           (!ml.is_vulnerable && rule.confidence < 0.3);
        
        // Use ML confidence as indicator of trained classifier
        // Untrained classifier returns 0.0 confidence
        let ml_meaningful = ml.confidence > 0.0;
        
        let base_confidence = if ml_meaningful {
            ml.confidence * 0.6 + baseline.confidence * 0.3 + rule.confidence * 0.1
        } else {
            baseline.confidence * 0.5 + rule.confidence * 0.5
        };
        
        // Boost confidence if signals agree
        if signals_agree {
            (base_confidence * 1.2).min(1.0)
        } else {
            base_confidence * 0.8
        }
    }
    
    /// Learn from response (update baseline)
    pub async fn learn(&self, url: &str, features: &ResponseFeatures) {
        let mut learner = self.baseline_learner.write().await;
        learner.learn(url, features);
        
        // Check baseline age for staleness monitoring (uses age() method)
        if let Some(baseline) = learner.get_baseline(url) {
            let age = baseline.age();
            if age > std::time::Duration::from_secs(86400 * 7) { // 7 days
                // Baseline is older than 7 days, could trigger refresh
                tracing::info!("Baseline for {} is stale ({} days old)", url, age.as_secs() / 86400);
            }
        }
    }
    
    /// Train ML classifier with labeled samples
    pub async fn train_classifier(&self, samples: Vec<(ResponseFeatures, bool)>) -> Result<(), String> {
        let mut classifier = self.classifier.write().await;
        classifier.train(samples)
    }

    /// Get current detection thresholds
    pub async fn get_thresholds(&self) -> (f64, f64) {
        (
            *self.anomaly_threshold.read().await,
            *self.vulnerability_threshold.read().await,
        )
    }

    /// Get detailed baseline statistics with health metrics
    pub async fn get_detailed_baseline_stats(&self) -> BaselineStatistics {
        let classifier = self.classifier.read().await;

        BaselineStatistics {
            classifier_trained: classifier.is_trained(),
        }
    }

    /// Export all learned data for persistence
    pub async fn export_data(&self) -> Result<AnomalyEngineData, String> {
        let learner = self.baseline_learner.read().await;
        let baselines = learner.export_baselines();

        Ok(AnomalyEngineData {
            baselines,
            anomaly_threshold: *self.anomaly_threshold.read().await,
            vulnerability_threshold: *self.vulnerability_threshold.read().await,
        })
    }

    /// Import learned data from persistence
    pub async fn import_data(&self, data: AnomalyEngineData) -> Result<(), String> {
        let mut learner = self.baseline_learner.write().await;
        learner.import_baselines(data.baselines);

        let mut anomaly_thresh = self.anomaly_threshold.write().await;
        let mut vuln_thresh = self.vulnerability_threshold.write().await;
        *anomaly_thresh = data.anomaly_threshold.clamp(0.0, 1.0);
        *vuln_thresh = data.vulnerability_threshold.clamp(0.0, 1.0);

        Ok(())
    }

    /// Save specific baseline to file
    pub async fn save_baseline(&self, url: &str, path: &str) -> Result<(), Box<dyn std::error::Error>> {
        let learner = self.baseline_learner.read().await;
        learner.save_baseline_to_file(url, path)
    }

    /// Load baseline from file
    pub async fn load_baseline(&self, url: &str, path: &str) -> Result<(), Box<dyn std::error::Error>> {
        let mut learner = self.baseline_learner.write().await;
        learner.load_baseline_from_file(url, path)
    }

    /// Get mature baselines only
    pub async fn get_mature_baselines(&self) -> Vec<String> {
        let learner = self.baseline_learner.read().await;
        learner.get_mature_baselines()
            .into_iter()
            .map(|b| b.url_pattern.clone())
            .collect()
    }

    /// Get baseline ages for monitoring
    pub async fn get_baseline_ages(&self) -> Vec<(String, std::time::Duration)> {
        let learner = self.baseline_learner.read().await;
        learner.get_baseline_ages()
    }

    /// Clear history for memory optimization
    pub async fn clear_history(&self) {
        let mut learner = self.baseline_learner.write().await;
        learner.clear_history();
    }

    /// Import baselines with validation
    pub async fn import_baselines_validated(&self, data: AnomalyEngineData) -> Result<Vec<(String, bool)>, String> {
        let mut learner = self.baseline_learner.write().await;

        // Capture thresholds before consuming data
        let anomaly_thresh_val = data.anomaly_threshold.clamp(0.0, 1.0);
        let vuln_thresh_val    = data.vulnerability_threshold.clamp(0.0, 1.0);

        // Validate before importing
        let validation_results: Vec<(String, bool)> = data.baselines.iter()
            .map(|(url, snapshot)| (url.clone(), snapshot.is_valid()))
            .collect();

        // Only import valid baselines
        let valid_baselines: std::collections::HashMap<String, _> = data.baselines.into_iter()
            .filter(|(_, snapshot)| snapshot.is_valid())
            .collect();

        learner.import_baselines(valid_baselines);

        *self.anomaly_threshold.write().await    = anomaly_thresh_val;
        *self.vulnerability_threshold.write().await = vuln_thresh_val;

        Ok(validation_results)
    }

    /// Get baseline health report
    pub async fn get_baseline_health(&self) -> Vec<(String, crate::zero_day::baseline::BaselineHealth)> {
        let learner = self.baseline_learner.read().await;
        learner.get_health_report()
    }

}

/// Comprehensive baseline statistics for monitoring
#[derive(Debug, Clone)]
pub struct BaselineStatistics {
    pub classifier_trained: bool,
}

/// Serializable data for persistence
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AnomalyEngineData {
    pub baselines: std::collections::HashMap<String, crate::zero_day::baseline::BaselineSnapshot>,
    pub anomaly_threshold: f64,
    pub vulnerability_threshold: f64,
}

/// Combined scores from multiple detection methods
#[derive(Debug)]
struct CombinedScores {
    vulnerability_score: f64,
    anomaly_score: f64,
    combined_score: f64,
}
