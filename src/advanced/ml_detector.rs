use std::collections::HashMap;

/// Machine Learning-based anomaly detection for responses
/// Note: This is a simplified implementation using statistical methods
/// For production, integrate with TensorFlow/PyTorch
pub struct MLDetector {
    normal_patterns: Vec<ResponsePattern>,
    threshold: f64,
    learning_rate: f64,
}

#[derive(Debug, Clone)]
pub struct ResponsePattern {
    pub features: Vec<f64>,
    pub response_type: ResponseType,
    pub confidence: f64,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ResponseType {
    Normal,
    Error,
    Suspicious,
    Anomaly,
}

#[derive(Debug)]
pub struct ResponseFeatures {
    pub response_time_ms: f64,
    pub body_length: f64,
    pub header_count: f64,
    pub error_keyword_count: f64,
    pub entropy: f64,
    pub digit_ratio: f64,
    pub uppercase_ratio: f64,
    pub special_char_ratio: f64,
}

impl MLDetector {
    pub fn new() -> Self {
        Self {
            normal_patterns: Vec::new(),
            threshold: 2.0, // Standard deviations
            learning_rate: 0.1,
        }
    }

    /// Extract numerical features from HTTP response
    pub fn extract_features(&self, response_time_ms: u128, body: &str, headers: &HashMap<String, String>) -> ResponseFeatures {
        let body_len = body.len() as f64;
        let header_count = headers.len() as f64;
        
        // Count error-related keywords
        let error_keywords = vec!["error", "exception", "fail", "invalid", "unauthorized", "forbidden"];
        let error_count = error_keywords.iter()
            .map(|kw| body.to_lowercase().matches(kw).count())
            .sum::<usize>() as f64;
        
        // Calculate entropy (randomness) of body
        let entropy = self.calculate_entropy(body);
        
        // Character composition
        let total_chars = body.len().max(1) as f64;
        let digit_count = body.chars().filter(|c| c.is_ascii_digit()).count() as f64;
        let uppercase_count = body.chars().filter(|c| c.is_ascii_uppercase()).count() as f64;
        let special_count = body.chars().filter(|c| !c.is_alphanumeric()).count() as f64;
        
        ResponseFeatures {
            response_time_ms: response_time_ms as f64,
            body_length: body_len,
            header_count,
            error_keyword_count: error_count,
            entropy,
            digit_ratio: digit_count / total_chars,
            uppercase_ratio: uppercase_count / total_chars,
            special_char_ratio: special_count / total_chars,
        }
    }

    /// Calculate Shannon entropy of a string
    fn calculate_entropy(&self, s: &str) -> f64 {
        if s.is_empty() {
            return 0.0;
        }
        
        let mut char_counts: HashMap<char, usize> = HashMap::new();
        for c in s.chars() {
            *char_counts.entry(c).or_insert(0) += 1;
        }
        
        let len = s.len() as f64;
        let mut entropy = 0.0;
        
        for count in char_counts.values() {
            let probability = *count as f64 / len;
            if probability > 0.0 {
                entropy -= probability * probability.log2();
            }
        }
        
        entropy
    }

    /// Convert features to vector
    fn features_to_vector(&self, features: &ResponseFeatures) -> Vec<f64> {
        vec![
            features.response_time_ms,
            features.body_length,
            features.header_count,
            features.error_keyword_count,
            features.entropy,
            features.digit_ratio,
            features.uppercase_ratio,
            features.special_char_ratio,
        ]
    }

    /// Normalize features using z-score normalization
    fn normalize_features(&self, features: &mut Vec<f64>, mean: &[f64], std: &[f64]) {
        for i in 0..features.len() {
            if std[i] > 0.0 {
                features[i] = (features[i] - mean[i]) / std[i];
            }
        }
    }

    /// Calculate mean and standard deviation of features
    fn calculate_statistics(&self, patterns: &[ResponsePattern]) -> (Vec<f64>, Vec<f64>) {
        if patterns.is_empty() {
            return (vec![0.0; 8], vec![1.0; 8]);
        }
        
        let feature_count = patterns[0].features.len();
        let mut means = vec![0.0; feature_count];
        let mut stds = vec![0.0; feature_count];
        
        // Calculate means
        for pattern in patterns {
            for (i, &value) in pattern.features.iter().enumerate() {
                means[i] += value;
            }
        }
        
        for mean in &mut means {
            *mean /= patterns.len() as f64;
        }
        
        // Calculate standard deviations
        for pattern in patterns {
            for (i, &value) in pattern.features.iter().enumerate() {
                stds[i] += (value - means[i]).powi(2);
            }
        }
        
        for std in &mut stds {
            *std = (*std / patterns.len() as f64).sqrt();
            if *std == 0.0 {
                *std = 1.0; // Avoid division by zero
            }
        }
        
        (means, stds)
    }

    /// Calculate Euclidean distance between two feature vectors
    fn euclidean_distance(&self, a: &[f64], b: &[f64]) -> f64 {
        a.iter().zip(b.iter())
            .map(|(x, y)| (x - y).powi(2))
            .sum::<f64>()
            .sqrt()
    }

    /// Train the model with normal responses
    pub fn train(&mut self, normal_responses: Vec<ResponseFeatures>) {
        self.normal_patterns.clear();
        
        for features in normal_responses {
            self.normal_patterns.push(ResponsePattern {
                features: self.features_to_vector(&features),
                response_type: ResponseType::Normal,
                confidence: 1.0,
            });
        }
        
        println!("[ML] Trained on {} normal response patterns", self.normal_patterns.len());
    }

    /// Detect if response is anomalous
    pub fn detect_anomaly(&self, features: &ResponseFeatures) -> AnomalyResult {
        if self.normal_patterns.is_empty() {
            // No training data, assume normal
            return AnomalyResult {
                is_anomaly: false,
                confidence: 0.5,
                response_type: ResponseType::Normal,
                details: "No training data available".to_string(),
            };
        }
        
        let new_features = self.features_to_vector(features);
        let (means, stds) = self.calculate_statistics(&self.normal_patterns);
        
        // Apply z-score normalization to features for comparison
        let mut normalized_features = new_features.clone();
        self.normalize_features(&mut normalized_features, &means, &stds);
        
        // Calculate average distance to normal patterns
        let mut total_distance = 0.0;
        let mut min_distance = f64::MAX;
        
        for pattern in &self.normal_patterns {
            let distance = self.euclidean_distance(&new_features, &pattern.features);
            total_distance += distance;
            min_distance = min_distance.min(distance);
        }
        
        let avg_distance = total_distance / self.normal_patterns.len() as f64;
        
        // Normalize distance relative to threshold
        let anomaly_score = avg_distance / self.threshold;
        let is_anomaly = anomaly_score > 1.0;
        
        // Determine response type
        let response_type = if is_anomaly {
            ResponseType::Anomaly
        } else if features.error_keyword_count > 0.0 {
            ResponseType::Error
        } else {
            ResponseType::Normal
        };
        
        // Calculate confidence
        let confidence = if is_anomaly {
            (anomaly_score - 1.0).min(1.0)
        } else {
            1.0 - anomaly_score
        };
        
        AnomalyResult {
            is_anomaly,
            confidence,
            response_type,
            details: format!(
                "Distance from normal: {:.2}, Min distance: {:.2}",
                avg_distance, min_distance
            ),
        }
    }

    /// Classify response type (normal, error, suspicious)
    pub fn classify(&self, features: &ResponseFeatures) -> ClassificationResult {
        let error_score = features.error_keyword_count * 10.0;
        let entropy_score = if features.entropy > 5.0 { 1.0 } else { 0.0 };
        let length_score = if features.body_length > 100000.0 { 0.5 } else { 0.0 };
        let time_score = if features.response_time_ms > 5000.0 { 1.0 } else { 0.0 };
        
        let total_score = error_score + entropy_score + length_score + time_score;
        
        let (class, confidence) = if total_score > 3.0 {
            ("Suspicious", (total_score / 10.0).min(1.0))
        } else if total_score > 1.0 {
            ("Error", (total_score / 5.0).min(1.0))
        } else {
            ("Normal", 1.0 - total_score)
        };
        
        ClassificationResult {
            class: class.to_string(),
            confidence,
            scores: vec![error_score, entropy_score, length_score, time_score],
        }
    }

    /// Add new normal pattern (online learning)
    pub fn add_normal_pattern(&mut self, features: ResponseFeatures) {
        self.normal_patterns.push(ResponsePattern {
            features: self.features_to_vector(&features),
            response_type: ResponseType::Normal,
            confidence: 1.0,
        });
        
        // Limit pattern count
        if self.normal_patterns.len() > 1000 {
            self.normal_patterns.remove(0);
        }
    }

    /// Get model statistics
    pub fn get_stats(&self) -> MLStats {
        MLStats {
            pattern_count: self.normal_patterns.len(),
            threshold: self.threshold,
            learning_rate: self.learning_rate,
        }
    }

    /// Update threshold
    pub fn set_threshold(&mut self, threshold: f64) {
        self.threshold = threshold.max(0.1);
    }
}

#[derive(Debug)]
pub struct AnomalyResult {
    pub is_anomaly: bool,
    pub confidence: f64,
    pub response_type: ResponseType,
    pub details: String,
}

#[derive(Debug)]
pub struct ClassificationResult {
    pub class: String,
    pub confidence: f64,
    pub scores: Vec<f64>,
}

#[derive(Debug)]
pub struct MLStats {
    pub pattern_count: usize,
    pub threshold: f64,
    pub learning_rate: f64,
}

/// Simple neural network layer for more advanced detection
/// Simplified implementation using perceptron model
pub struct NeuralLayer {
    weights: Vec<f64>,
    bias: f64,
}

impl NeuralLayer {
    pub fn new(input_size: usize) -> Self {
        // Initialize with random weights
        let weights: Vec<f64> = (0..input_size)
            .map(|_| (rand::random::<f64>() - 0.5) * 0.1)
            .collect();
        
        Self {
            weights,
            bias: 0.0,
        }
    }

    /// Forward pass (sigmoid activation)
    pub fn forward(&self, inputs: &[f64]) -> f64 {
        assert_eq!(inputs.len(), self.weights.len());
        
        let weighted_sum: f64 = inputs.iter()
            .zip(&self.weights)
            .map(|(x, w)| x * w)
            .sum::<f64>() + self.bias;
        
        self.sigmoid(weighted_sum)
    }

    /// Sigmoid activation function
    fn sigmoid(&self, x: f64) -> f64 {
        1.0 / (1.0 + (-x).exp())
    }

    /// Train with single example (gradient descent)
    pub fn train_step(&mut self, inputs: &[f64], target: f64, learning_rate: f64) {
        let prediction = self.forward(inputs);
        let error = target - prediction;
        
        // Update weights
        for (i, input) in inputs.iter().enumerate() {
            self.weights[i] += learning_rate * error * input * prediction * (1.0 - prediction);
        }
        
        // Update bias
        self.bias += learning_rate * error * prediction * (1.0 - prediction);
    }
}
