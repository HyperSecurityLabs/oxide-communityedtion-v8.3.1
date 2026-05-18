use anyhow::Result;
use reqwest::Client;
use tokio::time::Duration;

/// CORS (Cross-Origin Resource Sharing) Misconfiguration Scanner
/// Tests for overly permissive CORS policies that could lead to data theft
pub struct CorsScanner {
    client: Client,
    timeout: Duration,
}

#[derive(Debug, Clone)]
pub struct CorsFinding {
    pub severity: CorsSeverity,
    pub title: String,
    pub description: String,
    pub evidence: String,
    pub remediation: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum CorsSeverity {
    Critical,
    High,
    Medium,
    Low,
}

impl CorsScanner {
    pub fn new(timeout_secs: u64) -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(timeout_secs))
            .build()?;
        
        Ok(Self {
            client,
            timeout: Duration::from_secs(timeout_secs),
        })
    }
    
    /// Get the configured timeout duration
    pub fn get_timeout(&self) -> Duration {
        self.timeout
    }
    
    /// Comprehensive CORS scan
    pub async fn scan(&self, target: &str) -> Vec<CorsFinding> {
        let mut findings = Vec::new();
        
        println!("[CORS] Starting CORS misconfiguration assessment...");
        
        // Test 1: Wildcard origin with credentials
        findings.extend(self.test_wildcard_with_credentials(target).await);
        
        // Test 2: Reflecting arbitrary origins
        findings.extend(self.test_arbitrary_origin_reflection(target).await);
        
        // Test 3: Null origin
        findings.extend(self.test_null_origin(target).await);
        
        // Test 4: Subdomain trust issues
        findings.extend(self.test_subdomain_trust(target).await);
        
        // Test 5: HTTP origin accepted on HTTPS site
        findings.extend(self.test_http_on_https(target).await);
        
        // Test 6: Overly permissive methods
        findings.extend(self.test_permissive_methods(target).await);
        
        // Test 7: Exposed headers
        findings.extend(self.test_exposed_headers(target).await);
        
        // Test 8: Long max-age with bad policy
        findings.extend(self.test_max_age(target).await);
        
        // Test 9: Special origins (file://, data://)
        findings.extend(self.test_special_origins(target).await);
        
        // Test 10: Preflight caching issues
        findings.extend(self.test_preflight_caching(target).await);
        
        findings
    }
    
    /// Test for wildcard with credentials (critical vulnerability)
    async fn test_wildcard_with_credentials(&self, target: &str) -> Vec<CorsFinding> {
        let mut findings = Vec::new();
        
        let response = self.client
            .request(reqwest::Method::OPTIONS, target)
            .header("Origin", "https://evil.com")
            .header("Access-Control-Request-Method", "GET")
            .send()
            .await;
        
        if let Ok(resp) = response {
            let headers = resp.headers();
            
            let acao = headers.get("access-control-allow-origin")
                .and_then(|v| v.to_str().ok());
            let acac = headers.get("access-control-allow-credentials")
                .and_then(|v| v.to_str().ok());
            
            if let Some(origin) = acao {
                if origin == "*" {
                    // Check if credentials are allowed with wildcard
                    if acac.map(|c| c.to_lowercase() == "true").unwrap_or(false) {
                        findings.push(CorsFinding {
                            severity: CorsSeverity::Critical,
                            title: "CORS: Wildcard with Credentials".to_string(),
                            description: "Server allows credentials with wildcard origin - this is a critical security vulnerability.".to_string(),
                            evidence: "Access-Control-Allow-Origin: *\nAccess-Control-Allow-Credentials: true".to_string(),
                            remediation: "Never use wildcard (*) with Access-Control-Allow-Credentials: true. Specify exact origins.".to_string(),
                        });
                    } else {
                        findings.push(CorsFinding {
                            severity: CorsSeverity::Medium,
                            title: "CORS: Wildcard Origin".to_string(),
                            description: "Server allows any origin via wildcard (*).".to_string(),
                            evidence: "Access-Control-Allow-Origin: *".to_string(),
                            remediation: "Specify explicit allowed origins instead of wildcard.".to_string(),
                        });
                    }
                }
            }
        }
        
        findings
    }
    
    /// Test reflecting arbitrary origins
    async fn test_arbitrary_origin_reflection(&self, target: &str) -> Vec<CorsFinding> {
        let mut findings = Vec::new();
        
        let test_origins = vec![
            "https://evil.com",
            "https://attacker.com",
            "http://malicious.com",
            "https://any-subdomain.example.com",
        ];
        
        for origin in test_origins {
            let response = self.client
                .get(target)
                .header("Origin", origin)
                .send()
                .await;
            
            if let Ok(resp) = response {
                let acao = resp.headers()
                    .get("access-control-allow-origin")
                    .and_then(|v| v.to_str().ok());
                
                let acac = resp.headers()
                    .get("access-control-allow-credentials")
                    .and_then(|v| v.to_str().ok());
                
                if acao == Some(origin) {
                    let severity = if acac.map(|c| c.to_lowercase() == "true").unwrap_or(false) {
                        CorsSeverity::Critical
                    } else {
                        CorsSeverity::High
                    };
                    
                    findings.push(CorsFinding {
                        severity,
                        title: "CORS: Arbitrary Origin Reflection".to_string(),
                        description: format!("Server reflects arbitrary origin: {}", origin),
                        evidence: format!("Origin: {}\nResponse: Access-Control-Allow-Origin: {}", origin, origin),
                        remediation: "Validate origins against whitelist. Do not echo user-supplied Origin header.".to_string(),
                    });
                    
                    break; // Found the issue, no need to test more
                }
            }
        }
        
        findings
    }
    
    /// Test for null origin acceptance
    async fn test_null_origin(&self, target: &str) -> Vec<CorsFinding> {
        let mut findings = Vec::new();
        
        let response = self.client
            .get(target)
            .header("Origin", "null")
            .send()
            .await;
        
        if let Ok(resp) = response {
            let acao = resp.headers()
                .get("access-control-allow-origin")
                .and_then(|v| v.to_str().ok());
            
            let acac = resp.headers()
                .get("access-control-allow-credentials")
                .and_then(|v| v.to_str().ok());
            
            if acao == Some("null") {
                let severity = if acac.map(|c| c.to_lowercase() == "true").unwrap_or(false) {
                    CorsSeverity::Critical
                } else {
                    CorsSeverity::High
                };
                
                findings.push(CorsFinding {
                    severity,
                    title: "CORS: Null Origin Allowed".to_string(),
                    description: "Server accepts null origin which can be exploited via sandboxed iframes or local files.".to_string(),
                    evidence: "Origin: null\nAccess-Control-Allow-Origin: null".to_string(),
                    remediation: "Reject null origin or treat it with the same restrictions as wildcard.".to_string(),
                });
            }
        }
        
        findings
    }
    
    /// Test subdomain trust issues
    async fn test_subdomain_trust(&self, target: &str) -> Vec<CorsFinding> {
        let mut findings = Vec::new();
        
        // Extract domain from target
        let domain = target.replace("https://", "").replace("http://", "");
        let domain = domain.split('/').next().unwrap_or(&domain);
        let domain = domain.split(':').next().unwrap_or(domain);
        
        // Test various subdomain patterns
        let test_origins = vec![
            format!("https://evil.{}", domain),
            format!("https://attacker.{}", domain),
            format!("https://xss.{}", domain),
        ];
        
        for origin in test_origins {
            let response = self.client
                .get(target)
                .header("Origin", &origin)
                .send()
                .await;
            
            if let Ok(resp) = response {
                let acao = resp.headers()
                    .get("access-control-allow-origin")
                    .and_then(|v| v.to_str().ok());
                
                if acao == Some(&origin) || acao == Some("*") {
                    findings.push(CorsFinding {
                        severity: CorsSeverity::Medium,
                        title: "CORS: Subdomain Trust Issue".to_string(),
                        description: format!("Server may trust all subdomains of {}", domain),
                        evidence: format!("Origin {} was allowed", origin),
                        remediation: "Maintain strict whitelist of allowed subdomains. Use exact matches.".to_string(),
                    });
                    
                    break;
                }
            }
        }
        
        findings
    }
    
    /// Test if HTTP origin is accepted on HTTPS site
    async fn test_http_on_https(&self, target: &str) -> Vec<CorsFinding> {
        let mut findings = Vec::new();
        
        if !target.starts_with("https://") {
            return findings;
        }
        
        // Create HTTP version of the target
        let http_target = target.replace("https://", "http://");
        let http_origin = http_target.split('/').next().unwrap_or(&http_target);
        
        let response = self.client
            .get(target)
            .header("Origin", http_origin)
            .send()
            .await;
        
        if let Ok(resp) = response {
            let acao = resp.headers()
                .get("access-control-allow-origin")
                .and_then(|v| v.to_str().ok());
            
            if acao == Some(http_origin) {
                findings.push(CorsFinding {
                    severity: CorsSeverity::High,
                    title: "CORS: HTTP Origin on HTTPS Site".to_string(),
                    description: "HTTPS site accepts HTTP origin, vulnerable to MITM attacks.".to_string(),
                    evidence: format!("HTTPS site accepted origin: {}", http_origin),
                    remediation: "Reject non-HTTPS origins on HTTPS sites. Redirect HTTP to HTTPS.".to_string(),
                });
            }
        }
        
        findings
    }
    
    /// Test for overly permissive methods
    async fn test_permissive_methods(&self, target: &str) -> Vec<CorsFinding> {
        let mut findings = Vec::new();
        
        let dangerous_methods = vec!["PUT", "DELETE", "PATCH", "TRACE", "CONNECT"];
        
        let response = self.client
            .request(reqwest::Method::OPTIONS, target)
            .header("Origin", "https://evil.com")
            .header("Access-Control-Request-Method", "DELETE")
            .send()
            .await;
        
        if let Ok(resp) = response {
            let acam = resp.headers()
                .get("access-control-allow-methods")
                .and_then(|v| v.to_str().ok());
            
            if let Some(methods) = acam {
                let dangerous_found: Vec<&str> = dangerous_methods.iter()
                    .filter(|&&m| methods.to_uppercase().contains(m))
                    .copied()
                    .collect();
                
                if !dangerous_found.is_empty() {
                    findings.push(CorsFinding {
                        severity: CorsSeverity::Medium,
                        title: "CORS: Dangerous Methods Allowed".to_string(),
                        description: format!("Server allows dangerous HTTP methods via CORS: {:?}", dangerous_found),
                        evidence: format!("Access-Control-Allow-Methods: {}", methods),
                        remediation: "Only allow necessary methods (GET, POST). Explicitly block PUT/DELETE/PATCH.".to_string(),
                    });
                }
            }
        }
        
        findings
    }
    
    /// Test for exposed sensitive headers
    async fn test_exposed_headers(&self, target: &str) -> Vec<CorsFinding> {
        let mut findings = Vec::new();
        
        let sensitive_headers = vec![
            "authorization",
            "cookie",
            "x-api-key",
            "x-auth-token",
            "x-csrf-token",
            "session-id",
            "jwt",
        ];
        
        let response = self.client
            .request(reqwest::Method::OPTIONS, target)
            .header("Origin", "https://evil.com")
            .header("Access-Control-Request-Headers", "authorization,x-api-key")
            .send()
            .await;
        
        if let Ok(resp) = response {
            let acah = resp.headers()
                .get("access-control-allow-headers")
                .and_then(|v| v.to_str().ok());
            
            if let Some(headers) = acah {
                let headers_lower = headers.to_lowercase();
                let exposed: Vec<&&str> = sensitive_headers.iter()
                    .filter(|&&h| headers_lower.contains(h))
                    .collect();
                
                if !exposed.is_empty() {
                    findings.push(CorsFinding {
                        severity: CorsSeverity::Medium,
                        title: "CORS: Sensitive Headers Exposed".to_string(),
                        description: format!("Server allows cross-origin access to sensitive headers: {:?}", exposed),
                        evidence: format!("Access-Control-Allow-Headers: {}", headers),
                        remediation: "Limit exposed headers. Never allow Authorization or Cookie headers in CORS.".to_string(),
                    });
                }
            }
        }
        
        findings
    }
    
    /// Test for long max-age with bad policy
    async fn test_max_age(&self, target: &str) -> Vec<CorsFinding> {
        let mut findings = Vec::new();
        
        let response = self.client
            .request(reqwest::Method::OPTIONS, target)
            .header("Origin", "https://evil.com")
            .send()
            .await;
        
        if let Ok(resp) = response {
            let acma = resp.headers()
                .get("access-control-max-age")
                .and_then(|v| v.to_str().ok());
            
            let acao = resp.headers()
                .get("access-control-allow-origin")
                .and_then(|v| v.to_str().ok());
            
            if let Some(max_age) = acma {
                if let Ok(seconds) = max_age.parse::<u64>() {
                    // If max-age is very long AND policy is permissive
                    let is_permissive = acao.map(|o| o == "*" || o != target).unwrap_or(false);
                    
                    if seconds > 86400 && is_permissive { // More than 24 hours
                        findings.push(CorsFinding {
                            severity: CorsSeverity::Medium,
                            title: "CORS: Long Max-Age with Permissive Policy".to_string(),
                            description: format!("Preflight cached for {} seconds with permissive CORS policy", seconds),
                            evidence: format!("Access-Control-Max-Age: {}", max_age),
                            remediation: "Reduce max-age to reasonable value (7200 seconds). Fix CORS policy first.".to_string(),
                        });
                    }
                }
            }
        }
        
        findings
    }
    
    /// Test for special origins (file://, data://)
    async fn test_special_origins(&self, target: &str) -> Vec<CorsFinding> {
        let mut findings = Vec::new();
        
        let special_origins = vec![
            "file://",
            "data:text/html,<script>alert(1)</script>",
            "javascript:alert(1)",
            "about:blank",
            "chrome-extension://abcdefghijklmnopqrstuvwxyz",
        ];
        
        for origin in special_origins {
            let response = self.client
                .get(target)
                .header("Origin", origin)
                .send()
                .await;
            
            if let Ok(resp) = response {
                let acao = resp.headers()
                    .get("access-control-allow-origin")
                    .and_then(|v| v.to_str().ok());
                
                if acao == Some(origin) || acao == Some("*") {
                    findings.push(CorsFinding {
                        severity: CorsSeverity::High,
                        title: "CORS: Special Origin Accepted".to_string(),
                        description: format!("Server accepts dangerous origin scheme: {}", &origin[..origin.len().min(50)]),
                        evidence: format!("Origin: {} was allowed", &origin[..origin.len().min(50)]),
                        remediation: "Reject all non-HTTP/HTTPS origins. Block file://, data://, javascript:// schemes.".to_string(),
                    });
                    
                    break;
                }
            }
        }
        
        findings
    }
    
    /// Test for preflight caching vulnerabilities
    async fn test_preflight_caching(&self, target: &str) -> Vec<CorsFinding> {
        let mut findings = Vec::new();
        
        // Make preflight request
        let response = self.client
            .request(reqwest::Method::OPTIONS, target)
            .header("Origin", "https://evil.com")
            .header("Access-Control-Request-Method", "POST")
            .header("Access-Control-Request-Headers", "Content-Type")
            .send()
            .await;
        
        if let Ok(resp) = response {
            let acma = resp.headers()
                .get("access-control-max-age")
                .and_then(|v| v.to_str().ok());
            
            let vary = resp.headers()
                .get("vary")
                .and_then(|v| v.to_str().ok());
            
            // Check if Vary: Origin is missing
            if vary.map(|v| !v.to_lowercase().contains("origin")).unwrap_or(true) {
                let acao = resp.headers()
                    .get("access-control-allow-origin")
                    .and_then(|v| v.to_str().ok());
                
                if acao.is_some() {
                    findings.push(CorsFinding {
                        severity: CorsSeverity::Low,
                        title: "CORS: Missing Vary: Origin Header".to_string(),
                        description: "CORS responses should include Vary: Origin to prevent caching issues.".to_string(),
                        evidence: "Vary header missing or does not include Origin".to_string(),
                        remediation: "Add 'Vary: Origin' to all CORS responses.".to_string(),
                    });
                }
            }
            
            // Check for extremely long cache
            if let Some(max_age) = acma {
                if let Ok(seconds) = max_age.parse::<u64>() {
                    if seconds > 604800 { // More than 1 week
                        findings.push(CorsFinding {
                            severity: CorsSeverity::Low,
                            title: "CORS: Excessive Max-Age".to_string(),
                            description: format!("Preflight cached for {} seconds (one week or more)", seconds),
                            evidence: format!("Access-Control-Max-Age: {}", max_age),
                            remediation: "Reduce max-age to 2 hours (7200) or less for development.".to_string(),
                        });
                    }
                }
            }
        }
        
        findings
    }
}
