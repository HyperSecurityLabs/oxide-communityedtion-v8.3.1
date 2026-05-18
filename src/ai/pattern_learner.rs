use std::collections::HashMap;

/// Pattern learning system for adaptive exploitation.
///
/// Uses a Bayesian-style confidence update so the learning_rate actually
/// controls how quickly the score moves — a rate of 1.0 means pure
/// win/loss ratio, 0.1 means very conservative updates.
pub struct PatternLearner {
    patterns: HashMap<String, Pattern>,
    learning_rate: f32,
}

#[derive(Clone, Debug)]
pub struct Pattern {
    pub signature: String,
    pub success_count: usize,
    pub failure_count: usize,
    /// Smoothed confidence in [0, 1].  Starts at 0.5 (no prior knowledge).
    pub confidence: f32,
    pub context: Vec<String>,
}

impl PatternLearner {
    pub fn new(learning_rate: f32) -> Self {
        Self {
            patterns: HashMap::new(),
            learning_rate: learning_rate.clamp(0.01, 1.0),
        }
    }

    /// Record a successful exploitation of `signature`.
    pub fn learn_success(&mut self, signature: &str, context: Vec<String>) {
        let lr = self.learning_rate;
        let entry = self.patterns.entry(signature.to_string()).or_insert_with(|| Pattern {
            signature: signature.to_string(),
            success_count: 0,
            failure_count: 0,
            confidence: 0.5,
            context: Vec::new(),
        });
        entry.success_count += 1;
        entry.confidence = Self::update_confidence(entry.confidence, true, lr);
        entry.context.extend(context);
    }

    /// Record a failed exploitation of `signature`.
    pub fn learn_failure(&mut self, signature: &str) {
        let lr = self.learning_rate;
        let entry = self.patterns.entry(signature.to_string()).or_insert_with(|| Pattern {
            signature: signature.to_string(),
            success_count: 0,
            failure_count: 0,
            confidence: 0.5,
            context: Vec::new(),
        });
        entry.failure_count += 1;
        entry.confidence = Self::update_confidence(entry.confidence, false, lr);
    }

    /// Online confidence update using exponential moving average.
    ///
    /// `learning_rate` controls how much each new observation shifts the score:
    ///   new_conf = old_conf + lr * (outcome - old_conf)
    ///
    /// outcome = 1.0 for success, 0.0 for failure.
    /// This is equivalent to an EMA and actually uses learning_rate unlike the
    /// previous implementation that stored it but ignored it.
    fn update_confidence(current: f32, success: bool, learning_rate: f32) -> f32 {
        let outcome = if success { 1.0_f32 } else { 0.0_f32 };
        (current + learning_rate * (outcome - current)).clamp(0.0, 1.0)
    }

    /// Return the top `count` patterns sorted by confidence descending.
    pub fn get_best_patterns(&self, count: usize) -> Vec<&Pattern> {
        let mut patterns: Vec<&Pattern> = self.patterns.values().collect();
        patterns.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence)
            .unwrap_or(std::cmp::Ordering::Equal));
        patterns.into_iter().take(count).collect()
    }

    /// Predicted success probability for `signature` (0.5 if unseen).
    pub fn predict_success(&self, signature: &str) -> f32 {
        self.patterns.get(signature).map(|p| p.confidence).unwrap_or(0.5)
    }

    /// Aggregate statistics across all learned patterns.
    pub fn get_statistics(&self) -> HashMap<String, f32> {
        let mut stats = HashMap::new();
        let n = self.patterns.len() as f32;
        stats.insert("total_patterns".to_string(), n);

        if n > 0.0 {
            let avg_conf = self.patterns.values().map(|p| p.confidence).sum::<f32>() / n;
            stats.insert("avg_confidence".to_string(), avg_conf);

            let total_attempts: usize = self.patterns.values()
                .map(|p| p.success_count + p.failure_count).sum();
            stats.insert("total_attempts".to_string(), total_attempts as f32);

            let total_success: usize = self.patterns.values()
                .map(|p| p.success_count).sum();
            stats.insert("overall_success_rate".to_string(),
                total_success as f32 / total_attempts.max(1) as f32);
        }
        stats
    }

    /// Return the learning rate in use.
    pub fn learning_rate(&self) -> f32 { self.learning_rate }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_confidence_rises_on_success() {
        let mut learner = PatternLearner::new(0.8);
        learner.learn_success("sqli_1", vec!["ctx".to_string()]);
        learner.learn_success("sqli_1", vec![]);
        assert!(learner.predict_success("sqli_1") > 0.5);
    }

    #[test]
    fn test_confidence_falls_on_failure() {
        let mut learner = PatternLearner::new(0.8);
        learner.learn_failure("sqli_1");
        learner.learn_failure("sqli_1");
        assert!(learner.predict_success("sqli_1") < 0.5);
    }

    #[test]
    fn test_unseen_pattern_returns_half() {
        let learner = PatternLearner::new(0.5);
        assert_eq!(learner.predict_success("never_seen"), 0.5);
    }

    #[test]
    fn test_learning_rate_actually_used() {
        // With lr=1.0 a single success should push confidence to 1.0
        let mut learner = PatternLearner::new(1.0);
        learner.learn_success("p", vec![]);
        assert_eq!(learner.predict_success("p"), 1.0);

        // With lr=0.1 a single success should only nudge from 0.5 to 0.55
        let mut learner2 = PatternLearner::new(0.1);
        learner2.learn_success("p", vec![]);
        let conf = learner2.predict_success("p");
        assert!((conf - 0.55).abs() < 1e-5, "expected ~0.55, got {}", conf);
    }
}
