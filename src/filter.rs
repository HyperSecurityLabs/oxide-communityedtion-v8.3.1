use anyhow::Result;

// filter False positives Answers from this modules for real legit Answers for Red teamers 
///! This would be use in productions 
/// Match Regex hashes with url exact vulns Detections

use regex::Regex;
use std::collections::{
             HashMap, HashSet
              };
use std::sync:: 
              {Arc, Mutex
               };
use tokio::sync::RwLock;
use reqwest::Client;
use std::time::
       {Duration, Instant};

/// Real-time dynamic content filter with adaptive threshold detection
/// Analyzes website responses to detect anomalies, sensitive data exposure,
/// and dynamically adjusts detection parameters based on response patterns

pub struct HybridContentFilter {
    client: Client,
    baseline_stats: Arc<RwLock<ResponseStats>>,
    sensitive_patterns: Arc<Mutex<HashMap<String, Regex>>>,
    anomaly_threshold: Arc<RwLock<f64>>,
    detection_history: Arc<Mutex<Vec<DetectionEvent>>>,
    adaptive_mode: bool,
}

#[derive(Debug, Clone)]
pub struct ResponseStats {
    pub response_times: Vec<Duration>,
    pub content_lengths: Vec<usize>,
    pub status_codes: HashMap<u16, usize>,
    pub error_patterns: HashSet<String>,
    pub baseline_avg_time: f64,
    pub baseline_avg_length: f64,
    pub std_dev_time: f64,
    pub std_dev_length: f64,
    pub sample_count: usize,
}

#[derive(Debug, Clone)]
pub struct DetectionEvent {
    pub timestamp: Instant,
    pub url: String,
    pub event_type: DetectionType,
    pub severity: Severity,
    pub confidence: f64,
    pub details: String,
    pub extracted_data: Vec<ExtractedData>,
}

impl DetectionEvent {
    /// Get summary of the detection event for reporting
    pub fn summary(&self) -> String {
        format!(
            "[{}] {} at {} - {} (confidence: {:.2}, data items: {})",
            self.severity, self.event_type, self.url, self.details, self.confidence, self.extracted_data.len()
        )
    }
    
    /// Get extracted data count
    pub fn data_count(&self) -> usize {
        self.extracted_data.len()
    }
    
    /// Check if this event has extracted data
    pub fn has_data(&self) -> bool {
        !self.extracted_data.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DetectionType {
    SensitiveDataExposure,
    ErrorInformationDisclosure,
    TimingAnomaly,
    SizeAnomaly,
    PatternMatch,
    CredentialLeak,
    PrivateKeyExposure,
    DatabaseConnectionString,
    ApiKeyExposure,
    JwtTokenExposure,
}

impl std::fmt::Display for DetectionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DetectionType::SensitiveDataExposure => write!(f, "Sensitive Data Exposure"),
            DetectionType::ErrorInformationDisclosure => write!(f, "Error Info Disclosure"),
            DetectionType::TimingAnomaly => write!(f, "Timing Anomaly"),
            DetectionType::SizeAnomaly => write!(f, "Size Anomaly"),
            DetectionType::PatternMatch => write!(f, "Pattern Match"),
            DetectionType::CredentialLeak => write!(f, "Credential Leak"),
            DetectionType::PrivateKeyExposure => write!(f, "Private Key Exposure"),
            DetectionType::DatabaseConnectionString => write!(f, "Database Connection String"),
            DetectionType::ApiKeyExposure => write!(f, "API Key Exposure"),
            DetectionType::JwtTokenExposure => write!(f, "JWT Token Exposure"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Critical => write!(f, "CRITICAL"),
            Severity::High => write!(f, "HIGH"),
            Severity::Medium => write!(f, "MEDIUM"),
            Severity::Low => write!(f, "LOW"),
            Severity::Info => write!(f, "INFO"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ExtractedData {
    pub data_type: String,
    pub value: String,
    pub context: String,
    pub risk_score: f64,
}

impl ExtractedData {
    /// Format for display with context preview
    pub fn display(&self) -> String {
        format!(
            "[{}] {}... (context: {}...) - risk: {:.1}",
            self.data_type,
            &self.value,
            &self.context[..self.context.len().min(40)],
            self.risk_score
        )
    }
}

#[derive(Debug, Clone)]
pub struct FilterResult {
    pub url: String,
    pub should_filter: bool,
    pub filter_reason: Vec<String>,
    pub extracted_sensitive_data: Vec<ExtractedData>,
    pub anomalies_detected: Vec<DetectionEvent>,
    pub risk_score: f64,
}

impl FilterResult {
    /// Generate report for this filter result
    pub fn generate_report(&self) -> String {
        let mut report = format!("[FILTER-RESULT] URL: {}\n", self.url);
        report.push_str(&format!("[FILTER-RESULT] Risk Score: {:.1}/100\n", self.risk_score));
        report.push_str(&format!("[FILTER-RESULT] Should Filter: {}\n", self.should_filter));
        
        if !self.filter_reason.is_empty() {
            report.push_str("[FILTER-RESULT] Reasons:\n");
            for reason in &self.filter_reason {
                report.push_str(&format!("  - {}\n", reason));
            }
        }
        
        if !self.extracted_sensitive_data.is_empty() {
            report.push_str("[FILTER-RESULT] Extracted Data:\n");
            for data in &self.extracted_sensitive_data {
                report.push_str(&format!("  - {}\n", data.display()));
            }
        }
        
        if !self.anomalies_detected.is_empty() {
            report.push_str("[FILTER-RESULT] Anomalies:\n");
            for anomaly in &self.anomalies_detected {
                let data_info = if anomaly.has_data() {
                    format!(" [+{} data items]", anomaly.data_count())
                } else {
                    String::new()
                };
                report.push_str(&format!("  - {}{}\n", anomaly.summary(), data_info));
            }
        }
        
        report
    }
}

impl HybridContentFilter {
    pub fn new(adaptive_mode: bool) -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
            .build()?;

        let mut patterns = HashMap::new();
        
        // Real dangerous patterns - actively extracts sensitive data
        patterns.insert("aws_access_key".to_string(),
            Regex::new(r"AKIA[0-9A-Z]{16}").expect("Static AWS access key regex should be valid"));
        patterns.insert("aws_secret_key".to_string(),
            Regex::new(r"[\x22\x27][0-9a-zA-Z+/]{40}[\x22\x27]").expect("Static AWS secret key regex should be valid"));
        patterns.insert("private_key".to_string(),
            Regex::new(r"-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----").expect("Static private key regex should be valid"));
        patterns.insert("jwt_token".to_string(),
            Regex::new(r"eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*").expect("Static JWT token regex should be valid"));
        patterns.insert("api_key_generic".to_string(),
            Regex::new(r"(?i)(api[_-]?key|apikey)\s*[=:]\s*[\x22\x27]?([a-zA-Z0-9_-]{16,64})[\x22\x27]?").expect("Static API key regex should be valid"));
        patterns.insert("db_connection".to_string(),
            Regex::new(r"(?i)(mongodb|mysql|postgres|redis)://[^\s\x22<>]+").expect("Static DB connection regex should be valid"));
        patterns.insert("password_in_url".to_string(),
            Regex::new(r"(?i)://[^:]+:([^@]+)@").expect("Static password in URL regex should be valid"));
        patterns.insert("credit_card".to_string(),
            Regex::new(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b").expect("Static credit card regex should be valid"));
        patterns.insert("ssn".to_string(),
            Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").expect("Static SSN regex should be valid"));
        patterns.insert("email_password".to_string(),
            Regex::new(r"(?i)(password|passwd|pwd)\s*[=:]\s*[\x22\x27]?([^\x22\x27\s<>]+)[\x22\x27]?").expect("Static password regex should be valid"));
        patterns.insert("slack_token".to_string(),
            Regex::new(r"xox[baprs]-[0-9a-zA-Z-]+").expect("Static Slack token regex should be valid"));
        patterns.insert("github_token".to_string(),
            Regex::new(r"gh[pousr]_[a-zA-Z0-9]{36,}").expect("Static GitHub token regex should be valid"));
        patterns.insert("ip_address".to_string(),
            Regex::new(r"\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b").expect("Static IP address regex should be valid"));
        patterns.insert("internal_ip".to_string(),
            Regex::new(r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b").expect("Static internal IP regex should be valid"));
        patterns.insert("secret_key".to_string(),
            Regex::new(r"(?i)(secret|secret[_-]?key)\s*[=:]\s*[\x22\x27]?([a-zA-Z0-9_-]{16,64})[\x22\x27]?").expect("Static secret key regex should be valid"));

        Ok(Self {
            client,
            baseline_stats: Arc::new(RwLock::new(ResponseStats::new())),
            sensitive_patterns: Arc::new(Mutex::new(patterns)),
            anomaly_threshold: Arc::new(RwLock::new(2.0)), // 2 sigma default
            detection_history: Arc::new(Mutex::new(Vec::new())),
            adaptive_mode,
        })
    }

    /// Collect baseline statistics from normal responses to detect anomalies
    pub async fn establish_baseline(&self, urls: &[String]) -> Result<()> {
        let mut stats = ResponseStats::new();
        
        println!("[FILTER] Establishing baseline from {} URLs...", urls.len());
        
        for url in urls.iter().take(20) {
            let start = Instant::now();
            match self.client.get(url).send().await {
                Ok(response) => {
                    let duration = start.elapsed();
                    let status = response.status().as_u16();
                    let content_length = response.text().await.unwrap_or_default().len();
                    
                    stats.response_times.push(duration);
                    stats.content_lengths.push(content_length);
                    *stats.status_codes.entry(status).or_insert(0) += 1;
                }
                Err(e) => {
                    stats.error_patterns.insert(e.to_string());
                }
            }
        }
        
        // Calculate statistics
        if !stats.response_times.is_empty() {
            let times: Vec<f64> = stats.response_times.iter().map(|d| d.as_millis() as f64).collect();
            let lengths: Vec<f64> = stats.content_lengths.iter().map(|&l| l as f64).collect();
            
            stats.baseline_avg_time = Self::mean(&times);
            stats.baseline_avg_length = Self::mean(&lengths);
            stats.std_dev_time = Self::std_dev(&times, stats.baseline_avg_time);
            stats.std_dev_length = Self::std_dev(&lengths, stats.baseline_avg_length);
            stats.sample_count = stats.response_times.len();
        }
        
        let mut baseline = self.baseline_stats.write().await;
        *baseline = stats;
        
        println!("[FILTER] Baseline established: avg_time={:.2}ms, avg_size={:.0} bytes",
            baseline.baseline_avg_time, baseline.baseline_avg_length);
        
        Ok(())
    }

    /// Dynamically filter and analyze content with hybrid detection
    pub async fn filter_content(&self, url: &str, content: &str, status_code: u16, response_time: Duration) -> FilterResult {
        let mut result = FilterResult {
            url: url.to_string(),
            should_filter: false,
            filter_reason: Vec::new(),
            extracted_sensitive_data: Vec::new(),
            anomalies_detected: Vec::new(),
            risk_score: 0.0,
        };

        // Phase 1: Pattern-based detection (static analysis)
        let patterns = match self.sensitive_patterns.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        for (pattern_name, regex) in patterns.iter() {
            for mat in regex.find_iter(content) {
                let value = mat.as_str().to_string();
                let context = Self::extract_context(content, mat.start(), mat.end());
                
                let risk_score = Self::calculate_pattern_risk(pattern_name, &value, &context);
                result.risk_score += risk_score;
                
                result.extracted_sensitive_data.push(ExtractedData {
                    data_type: pattern_name.clone(),
                    value: Self::mask_sensitive(&value),
                    context: context.clone(),
                    risk_score,
                });
                
                result.should_filter = true;
                result.filter_reason.push(format!("Pattern match: {} in context '{}'", pattern_name, &context[..context.len().min(30)]));
                
                // Record detection event with URL
                let event = DetectionEvent {
                    timestamp: Instant::now(),
                    url: url.to_string(),
                    event_type: Self::pattern_to_detection_type(pattern_name),
                    severity: Self::risk_to_severity(risk_score),
                    confidence: 0.95,
                    details: format!("Detected {} pattern at position {} in {}", pattern_name, mat.start(), url),
                    extracted_data: result.extracted_sensitive_data.clone(),
                };

                let mut history = match self.detection_history.lock() {
                    Ok(guard) => guard,
                    Err(poisoned) => poisoned.into_inner(),
                };
                history.push(event.clone());
                result.anomalies_detected.push(event);
            }
        }
        drop(patterns);

        // Phase 2: Statistical anomaly detection (dynamic)
        if self.adaptive_mode {
            let baseline = self.baseline_stats.read().await;
            if baseline.sample_count > 0 {
                // Check response time anomaly
                let time_ms = response_time.as_millis() as f64;
                let time_zscore = (time_ms - baseline.baseline_avg_time) / baseline.std_dev_time;
                
                if time_zscore.abs() > *self.anomaly_threshold.read().await {
                    result.should_filter = true;
                    result.filter_reason.push(format!(
                        "Response time anomaly: {:.2}ms (z-score: {:.2})", 
                        time_ms, time_zscore
                    ));
                    
                    result.anomalies_detected.push(DetectionEvent {
                        timestamp: Instant::now(),
                        url: url.to_string(),
                        event_type: DetectionType::TimingAnomaly,
                        severity: if time_zscore.abs() > 3.0 { Severity::High } else { Severity::Medium },
                        confidence: (time_zscore.abs() / 4.0).min(0.99),
                        details: format!("Response time deviation: {:.2} sigma", time_zscore),
                        extracted_data: vec![],
                    });
                    
                    result.risk_score += time_zscore.abs() * 5.0;
                }

                // Check content size anomaly
                let length = content.len() as f64;
                let length_zscore = (length - baseline.baseline_avg_length) / baseline.std_dev_length;
                
                if length_zscore.abs() > *self.anomaly_threshold.read().await {
                    result.should_filter = true;
                    result.filter_reason.push(format!(
                        "Content size anomaly: {} bytes (z-score: {:.2})",
                        content.len(), length_zscore
                    ));
                    
                    result.anomalies_detected.push(DetectionEvent {
                        timestamp: Instant::now(),
                        url: url.to_string(),
                        event_type: DetectionType::SizeAnomaly,
                        severity: if length_zscore.abs() > 3.0 { Severity::High } else { Severity::Medium },
                        confidence: (length_zscore.abs() / 4.0).min(0.99),
                        details: format!("Content size deviation: {:.2} sigma", length_zscore),
                        extracted_data: vec![],
                    });
                    
                    result.risk_score += length_zscore.abs() * 3.0;
                }
            }
        }

        // Phase 3: Error-based information disclosure detection
        if Self::is_error_page(status_code) {
            let error_leakage = Self::detect_error_information(content);
            if !error_leakage.is_empty() {
                result.should_filter = true;
                result.filter_reason.push(format!("Error info disclosure: {}", error_leakage.join(", ")));
                
                for info in error_leakage {
                    result.anomalies_detected.push(DetectionEvent {
                        timestamp: Instant::now(),
                        url: url.to_string(),
                        event_type: DetectionType::ErrorInformationDisclosure,
                        severity: Severity::Medium,
                        confidence: 0.85,
                        details: info.clone(),
                        extracted_data: vec![],
                    });
                }
                
                result.risk_score += 15.0;
            }
        }

        // Normalize risk score
        result.risk_score = result.risk_score.min(100.0);
        
        result
    }

    /// Real-time adaptive threshold adjustment based on detection history
    pub async fn adapt_threshold(&self) {
        if !self.adaptive_mode {
            return;
        }

        let history = match self.detection_history.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let recent_detections: Vec<_> = history.iter()
            .filter(|e| e.timestamp.elapsed() < Duration::from_secs(300))
            .collect();
        
        if recent_detections.len() >= 10 {
            // Adjust threshold based on false positive rate
            let high_confidence = recent_detections.iter()
                .filter(|e| e.confidence > 0.9)
                .count();
            
            let ratio = high_confidence as f64 / recent_detections.len() as f64;
            let mut threshold = self.anomaly_threshold.write().await;
            
            if ratio > 0.7 {
                // Too many detections, raise threshold
                *threshold = (*threshold + 0.1).min(4.0);
            } else if ratio < 0.3 {
                // Too few, lower threshold
                *threshold = (*threshold - 0.1).max(1.0);
            }
            
            println!("[FILTER] Adaptive threshold adjusted to {:.2} (ratio: {:.2})", *threshold, ratio);
        }
    }

    /// Detect error-based information disclosure (stack traces, paths, etc.)
    fn detect_error_information(content: &str) -> Vec<String> {
        let mut findings = Vec::new();
        
        // Stack trace patterns
        if content.contains("at ") && content.contains(".java:") {
            findings.push("Java stack trace".to_string());
        }
        if content.contains("File \"") && content.contains(".py\", line") {
            findings.push("Python traceback".to_string());
        }
        if content.contains("#0 ") && content.contains(" in ") {
            findings.push("C/C++ stack trace".to_string());
        }
        
        // File path disclosure
        let Ok(path_regex) = Regex::new(r"(/[a-zA-Z0-9_/-]+\.(php|py|rb|js|java|go|rs|conf|ini|yaml|yml|json|xml))") else {
            return findings;
        };
        let paths: Vec<_> = path_regex.find_iter(content).take(5).map(|m| m.as_str().to_string()).collect();
        if !paths.is_empty() {
            findings.push(format!("File paths: {}", paths.join(", ")));
        }
        
        // Database errors
        if content.to_lowercase().contains("sql syntax") {
            findings.push("SQL syntax error".to_string());
        }
        if content.to_lowercase().contains("odbc") || content.to_lowercase().contains("jdbc") {
            findings.push("Database driver info".to_string());
        }
        
        // Server info
        if content.contains("Server: ") || content.contains("X-Powered-By: ") {
            findings.push("Server software info".to_string());
        }
        
        findings
    }

    fn calculate_pattern_risk(pattern_name: &str, value: &str, context: &str) -> f64 {
        let base_risk = match pattern_name {
            "private_key" => 100.0,
            "aws_access_key" | "aws_secret_key" => 90.0,
            "db_connection" => 85.0,
            "github_token" | "slack_token" => 80.0,
            "jwt_token" => 70.0,
            "password_in_url" => 75.0,
            "secret_key" => 65.0,
            "api_key_generic" => 60.0,
            "email_password" => 70.0,
            "credit_card" => 85.0,
            "ssn" => 90.0,
            "internal_ip" => 40.0,
            _ => 30.0,
        };
        
        // Increase risk if found in dangerous context (config files, logs, etc)
        let context_multiplier = if context.contains("config") || context.contains("password") || context.contains("secret") {
            1.2
        } else if context.contains("log") || context.contains("error") {
            1.1
        } else {
            1.0
        };
        
        // Increase risk if value looks more complete/valid
        let value_multiplier = if value.len() > 20 { 1.1 } else { 1.0 };
        
        let result: f64 = base_risk * context_multiplier * value_multiplier;
        result.min(100.0)
    }

    fn pattern_to_detection_type(pattern_name: &str) -> DetectionType {
        match pattern_name {
            "private_key" => DetectionType::PrivateKeyExposure,
            "aws_access_key" | "aws_secret_key" => DetectionType::ApiKeyExposure,
            "db_connection" => DetectionType::DatabaseConnectionString,
            "jwt_token" => DetectionType::JwtTokenExposure,
            "github_token" | "slack_token" => DetectionType::CredentialLeak,
            "password_in_url" | "email_password" => DetectionType::CredentialLeak,
            "api_key_generic" | "secret_key" => DetectionType::ApiKeyExposure,
            "credit_card" | "ssn" => DetectionType::SensitiveDataExposure,
            _ => DetectionType::PatternMatch,
        }
    }

    fn risk_to_severity(risk: f64) -> Severity {
        match risk {
            r if r >= 80.0 => Severity::Critical,
            r if r >= 60.0 => Severity::High,
            r if r >= 40.0 => Severity::Medium,
            r if r >= 20.0 => Severity::Low,
            _ => Severity::Info,
        }
    }

    fn is_error_page(status: u16) -> bool {
        status >= 400 || status == 500 || status == 502 || status == 503
    }

    fn extract_context(content: &str, start: usize, end: usize) -> String {
        let context_start = start.saturating_sub(50);
        let context_end = (end + 50).min(content.len());
        content[context_start..context_end].to_string()
    }

    fn mask_sensitive(value: &str) -> String {
        if value.len() > 8 {
            format!("{}...{}", &value[..4], &value[value.len()-4..])
        } else {
            "***".to_string()
        }
    }

    fn mean(values: &[f64]) -> f64 {
        values.iter().sum::<f64>() / values.len() as f64
    }

    fn std_dev(values: &[f64], mean: f64) -> f64 {
        let variance: f64 = values.iter()
            .map(|&x| (x - mean).powi(2))
            .sum::<f64>() / values.len() as f64;
        variance.sqrt()
    }

    /// Get detection statistics
    pub fn get_stats(&self) -> FilterStats {
        let history = match self.detection_history.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let by_type = Self::count_by_type(&history);
        let by_severity = Self::count_by_severity(&history);
        
        FilterStats {
            total_detections: history.len(),
            by_type: by_type.clone(),
            by_severity: by_severity.clone(),
            recent_detections: history.iter()
                .filter(|e| e.timestamp.elapsed() < Duration::from_secs(300))
                .count(),
        }
    }
    
    /// Generate detailed report of detection statistics
    pub fn generate_stats_report(&self) -> String {
        let stats = self.get_stats();
        let mut report = format!(
            "[FILTER-STATS] Total detections: {}\n[FILTER-STATS] Recent (5min): {}\n",
            stats.total_detections, stats.recent_detections
        );
        
        report.push_str("[FILTER-STATS] By Type:\n");
        for (det_type, count) in &stats.by_type {
            report.push_str(&format!("  - {}: {}\n", det_type, count));
        }
        
        report.push_str("[FILTER-STATS] By Severity:\n");
        for (sev, count) in &stats.by_severity {
            report.push_str(&format!("  - {:?}: {}\n", sev, count));
        }
        
        report
    }

    fn count_by_type(history: &[DetectionEvent]) -> HashMap<DetectionType, usize> {
        let mut counts = HashMap::new();
        for event in history {
            *counts.entry(event.event_type.clone()).or_insert(0) += 1;
        }
        counts
    }

    fn count_by_severity(history: &[DetectionEvent]) -> HashMap<Severity, usize> {
        let mut counts = HashMap::new();
        for event in history {
            *counts.entry(event.severity.clone()).or_insert(0) += 1;
        }
        counts
    }
}

impl ResponseStats {
    fn new() -> Self {
        Self {
            response_times: Vec::new(),
            content_lengths: Vec::new(),
            status_codes: HashMap::new(),
            error_patterns: HashSet::new(),
            baseline_avg_time: 0.0,
            baseline_avg_length: 0.0,
            std_dev_time: 1.0,
            std_dev_length: 1.0,
            sample_count: 0,
        }
    }
}

#[derive(Debug)]
pub struct FilterStats {
    pub total_detections: usize,
    pub by_type: HashMap<DetectionType, usize>,
    pub by_severity: HashMap<Severity, usize>,
    pub recent_detections: usize,
}
