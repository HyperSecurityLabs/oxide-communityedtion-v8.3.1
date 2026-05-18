//! ML Classifier Module
//! Random Forest classifier using smartcore library
//! Trains on known vulnerable vs safe responses
//! Special Module Trained 
//! Matrix Coordinations 


use tracing::info;
use smartcore::linalg::basic::matrix::DenseMatrix; //SpecialModule For HyperSecurity_offensiveLabs

use smartcore::linalg::basic::arrays::Array;
use smartcore::ensemble::random_forest_classifier::RandomForestClassifier;
use smartcore::model_selection::train_test_split;

use crate::zero_day::features::ResponseFeatures;

/// Classification result with confidence score
#[derive(Debug, Clone)]
pub struct ClassificationResult {
    pub is_vulnerable: bool,
    pub confidence: f64,
    pub vulnerability_type: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn from_score(score: f64) -> Self {
        if score >= 0.9 {
            Severity::Critical
        } else if score >= 0.7 {
            Severity::High
        } else if score >= 0.5 {
            Severity::Medium
        } else {
            Severity::Low
        }
    }
}

/// Random Forest classifier for vulnerability detection
/// Uses Vec<u32> for labels (1 = vulnerable, 0 = safe) to match smartcore Ord requirement
pub struct VulnerabilityClassifier {
    model: Option<RandomForestClassifier<f64, u32, DenseMatrix<f64>, Vec<u32>>>,
    trained: bool,
    feature_importance: Vec<f64>,
    training_samples: usize,
    accuracy: f64,
}

impl VulnerabilityClassifier {
    /// Create new classifier
    pub fn new() -> Self {
        Self {
            model: None,
            trained: false,
            feature_importance: Vec::new(),
            training_samples: 0,
            accuracy: 0.0,
        }
    }
    
    /// Train classifier on labeled dataset
    /// samples: vector of (features, label) where label 1 = vulnerable, 0 = safe
    pub fn train(&mut self, samples: Vec<(ResponseFeatures, bool)>) -> Result<(), String> {
        if samples.len() < 10 {
            return Err("Need at least 10 samples to train".to_string());
        }
        
        // Convert to feature matrix and label vector
        let n_samples = samples.len();
        let n_features = samples[0].0.to_vector().len();
        
        let mut x_data = Vec::with_capacity(n_samples * n_features);
        let mut y_data = Vec::with_capacity(n_samples);
        
        for (features, is_vulnerable) in samples {
            x_data.extend(features.to_vector());
            // Convert bool to u32 for smartcore compatibility (needs Ord trait)
            y_data.push(if is_vulnerable { 1u32 } else { 0u32 });
        }
        
        // Create dense matrix using DenseMatrix::new (column_major=false for row-major)
        let x = DenseMatrix::new(n_samples, n_features, x_data, false);
        let y = y_data; // Keep as Vec<u32>
        
        // Split for validation (80/20 split) with seed 42 for reproducibility
        let (x_train, x_test, y_train, y_test) = train_test_split(&x, &y, 0.2, true, Some(42));
        
        // Train Random Forest with default parameters
        match RandomForestClassifier::fit(&x_train, &y_train, Default::default()) {
            Ok(model) => {
                // Evaluate on test set
                let predictions = model.predict(&x_test).map_err(|e| e.to_string())?;
                
                // Calculate metrics manually (smartcore metrics require complex trait bounds)
                self.accuracy = Self::calculate_accuracy(&y_test, &predictions);
                let precision_score = Self::calculate_precision(&y_test, &predictions);
                let recall_score = Self::calculate_recall(&y_test, &predictions);
                let f1_score = Self::calculate_f1(precision_score, recall_score);
                
                info!(
                    "Classifier trained - Accuracy: {:.2}%, Precision: {:.2}%, Recall: {:.2}%, F1: {:.2}%",
                    self.accuracy * 100.0,
                    precision_score * 100.0,
                    recall_score * 100.0,
                    f1_score * 100.0
                );
                
                self.model = Some(model);
                self.trained = true;
                self.training_samples = n_samples;
                
                // Calculate feature importance (simplified)
                self.calculate_feature_importance(&x_train, &y_train);
                
                Ok(())
            }
            Err(e) => Err(format!("Training failed: {}", e)),
        }
    }
    
    /// Calculate accuracy manually
    fn calculate_accuracy(y_true: &Vec<u32>, y_pred: &Vec<u32>) -> f64 {
        let correct = y_true.iter().zip(y_pred.iter())
            .filter(|(a, b)| a == b)
            .count();
        correct as f64 / y_true.len() as f64
    }
    
    /// Calculate precision manually
    fn calculate_precision(y_true: &Vec<u32>, y_pred: &Vec<u32>) -> f64 {
        let true_positives = y_true.iter().zip(y_pred.iter())
            .filter(|(t, p)| **t == 1 && **p == 1)
            .count() as f64;
        let predicted_positives = y_pred.iter()
            .filter(|p| **p == 1)
            .count() as f64;
        
        if predicted_positives > 0.0 {
            true_positives / predicted_positives
        } else {
            0.0
        }
    }
    
    /// Calculate recall manually
    fn calculate_recall(y_true: &Vec<u32>, y_pred: &Vec<u32>) -> f64 {
        let true_positives = y_true.iter().zip(y_pred.iter())
            .filter(|(t, p)| **t == 1 && **p == 1)
            .count() as f64;
        let actual_positives = y_true.iter()
            .filter(|t| **t == 1)
            .count() as f64;
        
        if actual_positives > 0.0 {
            true_positives / actual_positives
        } else {
            0.0
        }
    }
    
    /// Calculate F1 score from precision and recall
    fn calculate_f1(precision: f64, recall: f64) -> f64 {
        if precision + recall > 0.0 {
            2.0 * (precision * recall) / (precision + recall)
        } else {
            0.0
        }
    }
    
    /// Predict vulnerability from response features
    pub fn predict(&self, features: &ResponseFeatures) -> ClassificationResult {
        if !self.trained || self.model.is_none() {
            return ClassificationResult {
                is_vulnerable: false,
                confidence: 0.0,
                vulnerability_type: None,
            };
        }
        
        let feature_vec = features.to_vector();
        let x = DenseMatrix::new(1, feature_vec.len(), feature_vec, false);
        
        let model = match self.model.as_ref() {
            Some(m) => m,
            None => return ClassificationResult {
                is_vulnerable: false,
                confidence: 0.0,
                vulnerability_type: None,
            },
        };
        
        match model.predict(&x) {
            Ok(predictions) => {
                let prediction = predictions[0];
                let is_vulnerable = prediction == 1;
                
                // Calculate confidence based on feature anomalies
                let confidence = self.calculate_confidence(features);
                
                let vulnerability_type = if is_vulnerable {
                    self.classify_vulnerability_type(features)
                } else {
                    None
                };
                
                ClassificationResult {
                    is_vulnerable,
                    confidence,
                    vulnerability_type,
                }
            }
            Err(_) => ClassificationResult {
                is_vulnerable: false,
                confidence: 0.0,
                vulnerability_type: None,
            },
        }
    }
    
    /// Calculate confidence score based on feature analysis (0.0–1.0, capped)
    fn calculate_confidence(&self, features: &ResponseFeatures) -> f64 {
        // Each indicator contributes a fixed amount; we cap at 1.0 at the end.
        // Weights are additive evidence, not a probability distribution.
        let mut score = 0.0_f64;

        if features.has_sql_error      { score += 0.40; }
        if features.has_stack_trace    { score += 0.35; }
        if features.has_path_disclosure { score += 0.25; }
        if features.has_error_keywords {
            // Scale by keyword density, max +0.20
            let density = (features.error_keyword_count as f64 / 3.0).min(1.0);
            score += 0.20 * density;
        }
        if features.entropy > 5.0      { score += 0.10; }
        if features.is_error_status    { score += 0.15; }
        if features.response_time_ms > 2000 { score += 0.15; }

        score.min(1.0)
    }
    
    /// Classify vulnerability type based on feature patterns
    fn classify_vulnerability_type(&self, features: &ResponseFeatures) -> Option<String> {
        if features.has_sql_error {
            Some("SQL Injection".to_string())
        } else if features.has_stack_trace && features.is_error_status {
            Some("Information Disclosure".to_string())
        } else if features.has_path_disclosure {
            Some("Path Traversal".to_string())
        } else if features.response_time_ms > 3000 {
            Some("Time-Based Injection".to_string())
        } else if features.is_error_status && !features.has_error_keywords {
            Some("Potential Logic Flaw".to_string())
        } else if features.security_header_count < 2 {
            Some("Missing Security Headers".to_string())
        } else {
            Some("Unknown Vulnerability".to_string())
        }
    }
    
    /// Calculate feature importance using permutation importance algorithm
    fn calculate_feature_importance(&mut self, x: &DenseMatrix<f64>, y: &Vec<u32>) {
        let (nrows, ncols) = x.shape();
        if nrows == 0 || ncols == 0 || self.model.is_none() {
            self.feature_importance = vec![1.0 / ncols as f64; ncols];
            return;
        }
        
        let baseline_acc = self.accuracy;
        let mut importances = Vec::with_capacity(ncols);
        
        for feature_idx in 0..ncols {
            let mut feature_values: Vec<f64> = Vec::with_capacity(nrows);
            for row in 0..nrows {
                feature_values.push(*x.get((row, feature_idx)));
            }
            
            use rand::seq::SliceRandom;
            let mut rng = rand::rng();
            feature_values.shuffle(&mut rng);
            
            let mut permuted_data: Vec<Vec<f64>> = Vec::with_capacity(nrows);
            for row in 0..nrows {
                let mut new_row: Vec<f64> = Vec::with_capacity(ncols);
                for col in 0..ncols {
                    if col == feature_idx {
                        new_row.push(feature_values[row]);
                    } else {
                        new_row.push(*x.get((row, col)));
                    }
                }
                permuted_data.push(new_row);
            }
            
            let flat_data: Vec<f64> = permuted_data.into_iter().flatten().collect();
            let permuted_x = DenseMatrix::new(nrows, ncols, flat_data, false);
            
            if let Some(model) = self.model.as_ref() {
                if let Ok(predictions) = model.predict(&permuted_x) {
                    let correct = predictions.iter().zip(y.iter())
                        .filter(|(pred, actual)| **pred == **actual)
                        .count();
                    let permuted_acc = correct as f64 / y.len() as f64;
                    let importance = (baseline_acc - permuted_acc).max(0.0);
                    importances.push(importance);
                } else {
                    importances.push(0.0);
                }
            } else {
                importances.push(0.0);
            }
        }
        
        let total: f64 = importances.iter().sum();
        if total > 0.0 {
            self.feature_importance = importances.iter().map(|i| i / total).collect();
        } else {
            self.feature_importance = vec![1.0 / ncols as f64; ncols];
        }
    }
    
    /// Check if classifier is trained
    pub fn is_trained(&self) -> bool {
        self.trained
    }
}

/// Simple rule-based classifier for zero-shot detection
/// Used when no training data available
pub struct RuleBasedClassifier;

impl RuleBasedClassifier {
    /// Classify based on heuristics
    pub fn classify(features: &ResponseFeatures) -> ClassificationResult {
        let mut score = 0.0;
        let mut indicators = Vec::new();
        
        // Critical indicators
        if features.has_sql_error {
            score += 0.9;
            indicators.push("SQL error");
        }
        if features.has_stack_trace {
            score += 0.8;
            indicators.push("stack trace");
        }
        if features.has_path_disclosure {
            score += 0.7;
            indicators.push("path disclosure");
        }
        
        // Error indicators
        if features.has_error_keywords {
            score += 0.4 * (features.error_keyword_count as f64).min(3.0) / 3.0;
            indicators.push("error keywords");
        }
        
        // Timing-based blind detection
        if features.response_time_ms > 5000 {
            score += 0.6;
            indicators.push("time delay");
        }
        
        // Content anomalies
        if features.entropy > 6.0 && features.is_error_status {
            score += 0.3;
            indicators.push("entropy anomaly");
        }
        
        // Normalize score
        score = score.min(1.0);
        
        ClassificationResult {
            is_vulnerable: score > 0.5,
            confidence: score,
            vulnerability_type: Self::determine_type(&indicators),
        }
    }
    
    fn determine_type(indicators: &[&str]) -> Option<String> {
        if indicators.contains(&"SQL error") {
            Some("SQL Injection".to_string())
        } else if indicators.contains(&"stack trace") {
            Some("Information Disclosure".to_string())
        } else if indicators.contains(&"path disclosure") {
            Some("Path Traversal".to_string())
        } else if indicators.contains(&"time delay") {
            Some("Time-Based Injection".to_string())
        } else {
            Some("Potential Vulnerability".to_string())
        }
    }
}
