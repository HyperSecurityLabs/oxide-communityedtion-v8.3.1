use std::collections::HashSet;
use std::sync::Arc;
use tokio::sync::Mutex;

/// JavaScript-enabled crawling for modern web apps (SPA support)
pub struct JsCrawler {
    discovered_urls: Arc<Mutex<HashSet<String>>>,
    js_resources: Arc<Mutex<HashSet<String>>>,
    api_endpoints: Arc<Mutex<HashSet<String>>>,
    max_depth: usize,
}

impl JsCrawler {
    pub fn new(max_depth: usize) -> Self {
        Self {
            discovered_urls: Arc::new(Mutex::new(HashSet::new())),
            js_resources: Arc::new(Mutex::new(HashSet::new())),
            api_endpoints: Arc::new(Mutex::new(HashSet::new())),
            max_depth,
        }
    }

    /// Extract URLs from JavaScript content with depth tracking
    pub async fn extract_js_urls(&self, js_content: &str, base_url: &str) -> Vec<String> {
        let mut urls = Vec::new();
        
        // Check depth limit
        let current_count = self.discovered_urls.lock().await.len();
        if current_count >= self.max_depth * 100 {
            return urls; // Stop if we've reached approximate limit
        }
        
        // Pattern 1: Fetch/XHR calls
        let fetch_patterns = vec![
            r#"fetch\(["']([^"']+)["']"#,
            r#"axios\.(?:get|post|put|delete)\(["']([^"']+)["']"#,
            r#"\$\.(?:get|post|ajax)\s*\(\s*["']([^"']+)["']"#,
            r#"XMLHttpRequest.*open.*["']([^"']+)["']"#,
        ];
        
        for pattern in &fetch_patterns {
            let Ok(regex) = regex::Regex::new(pattern) else { continue; };
            for cap in regex.captures_iter(js_content) {
                if let Some(matched) = cap.get(1) {
                    let url = matched.as_str();
                    if let Some(absolute) = self.resolve_url(url, base_url) {
                        urls.push(absolute);
                    }
                }
            }
        }
        
        // Pattern 2: Router configurations (React, Vue, Angular)
        let router_patterns = vec![
            r#"path\s*:\s*["']([^"']+)["']"#,           // React Router, Vue Router
            r#"route\s*:\s*["']([^"']+)["']"#,          // Generic routes
            r#"when\s*\(\s*["']([^"']+)["']"#,          // Angular
            r#"@Route\s*\(\s*["']([^"']+)["']"#,        // Decorators
        ];
        
        for pattern in &router_patterns {
            let Ok(regex) = regex::Regex::new(pattern) else { continue; };
            for cap in regex.captures_iter(js_content) {
                if let Some(matched) = cap.get(1) {
                    let route = matched.as_str();
                    let full_url = format!("{}{}", base_url.trim_end_matches('/'), route);
                    urls.push(full_url);
                }
            }
        }
        
        // Pattern 3: Dynamic imports
        let import_pattern = r#"import\s*\(\s*["']([^"']+)["']"#;
        let Ok(regex) = regex::Regex::new(import_pattern) else { return urls; };
        for cap in regex.captures_iter(js_content) {
            if let Some(matched) = cap.get(1) {
                let url = matched.as_str();
                if let Some(absolute) = self.resolve_url(url, base_url) {
                    urls.push(absolute);
                }
            }
        }
        
        // Pattern 4: GraphQL endpoints
        if js_content.contains("graphql") || js_content.contains("gql") {
            let gql_patterns = vec![
                r#"/graphql"#,
                r#"/api/gql"#,
                r#"/query"#,
            ];
            for pattern in &gql_patterns {
                if js_content.contains(pattern) {
                    let gql_url = format!("{}{}", base_url.trim_end_matches('/'), pattern);
                    let mut api_endpoints = self.api_endpoints.lock().await;
                    api_endpoints.insert(gql_url.clone());
                    urls.push(gql_url);
                    drop(api_endpoints);
                }
            }
        }
        
        // Pattern 5: WebSocket endpoints
        let ws_patterns = vec![
            r#"new\s+WebSocket\s*\(\s*["']([^"']+)["']"#,
            r#"ws[s]?://([^"'\s]+)"#,
        ];
        for pattern in &ws_patterns {
            let Ok(regex) = regex::Regex::new(pattern) else { continue; };
            for cap in regex.captures_iter(js_content) {
                if let Some(matched) = cap.get(1) {
                    urls.push(matched.as_str().to_string());
                }
            }
        }
        
        // Add to discovered set
        let mut discovered = self.discovered_urls.lock().await;
        for url in &urls {
            discovered.insert(url.clone());
        }
        
        urls
    }

    /// Extract API endpoints from JavaScript
    pub async fn extract_api_endpoints(&self, js_content: &str) -> Vec<String> {
        let mut endpoints = Vec::new();
        
        // REST API patterns
        let api_patterns = vec![
            r#"/api/v\d+/[^"'\s]+"#,
            r#"/rest/[^"'\s]+"#,
            r#"/v\d+/[^"'\s]+"#,
            r#"/services/[^"'\s]+"#,
            r#"/endpoint[s]?/[^"'\s]+"#,
        ];
        
        for pattern in &api_patterns {
            let Ok(regex) = regex::Regex::new(pattern) else { continue; };
            for mat in regex.find_iter(js_content) {
                endpoints.push(mat.as_str().to_string());
            }
        }
        
        // Store in set
        let mut api_set = self.api_endpoints.lock().await;
        for endpoint in &endpoints {
            api_set.insert(endpoint.clone());
        }
        
        endpoints
    }

    /// Extract JavaScript resource URLs from HTML
    pub async fn extract_js_resources(&self, html: &str, base_url: &str) -> Vec<String> {
        let mut resources = Vec::new();
        
        // Script src attributes
        let script_pattern = r#"<script[^>]+src=["']([^"']+)["']"#;
        let Ok(regex) = regex::Regex::new(script_pattern) else { return resources; };
        for cap in regex.captures_iter(html) {
            if let Some(matched) = cap.get(1) {
                let url = matched.as_str();
                if let Some(absolute) = self.resolve_url(url, base_url) {
                    resources.push(absolute);
                }
            }
        }
        
        // Module imports
        let module_pattern = r#"<script[^>]+type=["']module["'][^>]*>.*?import.*?from\s*["']([^"']+)["']"#;
        let Ok(regex) = regex::Regex::new(module_pattern) else { return resources; };
        for cap in regex.captures_iter(html) {
            if let Some(matched) = cap.get(1) {
                let url = matched.as_str();
                if let Some(absolute) = self.resolve_url(url, base_url) {
                    resources.push(absolute);
                }
            }
        }
        
        // Store in set
        let mut js_set = self.js_resources.lock().await;
        for resource in &resources {
            js_set.insert(resource.clone());
        }
        
        resources
    }

    /// Analyze single-page application routing
    pub async fn analyze_spa_routing(&self, html: &str, base_url: &str) -> Vec<String> {
        let mut routes = Vec::new();
        
        // Detect framework
        let framework = if html.contains("react") || html.contains("__REACT__") {
            "react"
        } else if html.contains("vue") || html.contains("__VUE__") {
            "vue"
        } else if html.contains("angular") || html.contains("ng-") {
            "angular"
        } else {
            "unknown"
        };
        
        println!("[JS_CRAWL] Detected SPA framework: {}", framework);
        
        // Extract initial state/data
        let state_patterns = vec![
            r#"window\.__INITIAL_STATE__\s*=\s*(\{[^}]+\})"#,
            r#"window\.__DATA__\s*=\s*(\{[^}]+\})"#,
            r#"window\.__PRELOADED_STATE__\s*=\s*(\{[^}]+\})"#,
        ];
        
        for pattern in &state_patterns {
            let Ok(regex) = regex::Regex::new(pattern) else { continue; };
            for cap in regex.captures_iter(html) {
                if let Some(state) = cap.get(1) {
                    // Parse JSON state for URLs
                    let state_str = state.as_str();
                    let Ok(url_pattern) = regex::Regex::new(r#"["'](https?://[^"']+)["']"#) else { continue; };
                    for url_cap in url_pattern.captures_iter(state_str) {
                        if let Some(url) = url_cap.get(1) {
                            routes.push(url.as_str().to_string());
                        }
                    }
                }
            }
        }
        
        // Common SPA routes based on framework
        let common_routes = match framework {
            "react" => vec!["/", "/home", "/about", "/contact", "/dashboard", "/profile", "/settings"],
            "vue" => vec!["/", "/home", "/about", "/contact", "/dashboard", "/profile"],
            "angular" => vec!["/", "/home", "/about", "/contact", "/dashboard"],
            _ => vec!["/", "/home", "/about", "/api"],
        };
        
        let base = base_url.trim_end_matches('/');
        for route in common_routes {
            routes.push(format!("{}{}", base, route));
        }
        
        routes
    }

    /// Find GraphQL operations in JavaScript
    pub async fn find_graphql_operations(&self, js_content: &str) -> Vec<GraphQLOperation> {
        let mut operations = Vec::new();
        
        // GraphQL query/mutation patterns
        let gql_pattern = r#"(?:query|mutation)\s+(\w+)\s*\{([^}]+)\}"#;
        let Ok(regex) = regex::Regex::new(gql_pattern) else { return operations; };
        
        for cap in regex.captures_iter(js_content) {
            if let (Some(name), Some(body)) = (cap.get(1), cap.get(2)) {
                operations.push(GraphQLOperation {
                    name: name.as_str().to_string(),
                    operation_type: if js_content.contains("mutation") { 
                        OperationType::Mutation 
                    } else { 
                        OperationType::Query 
                    },
                    body: body.as_str().to_string(),
                });
            }
        }
        
        // Apollo Client gql tag
        let apollo_pattern = r#"gql`([^`]+)`"#;
        let Ok(regex) = regex::Regex::new(apollo_pattern) else { return operations; };
        for cap in regex.captures_iter(js_content) {
            if let Some(body) = cap.get(1) {
                operations.push(GraphQLOperation {
                    name: "anonymous".to_string(),
                    operation_type: OperationType::Query,
                    body: body.as_str().to_string(),
                });
            }
        }
        
        operations
    }

    /// Get all discovered URLs
    pub async fn get_discovered_urls(&self) -> Vec<String> {
        let urls = self.discovered_urls.lock().await;
        urls.iter().cloned().collect()
    }

    /// Get all JavaScript resources
    pub async fn get_js_resources(&self) -> Vec<String> {
        let resources = self.js_resources.lock().await;
        resources.iter().cloned().collect()
    }

    /// Get all API endpoints
    pub async fn get_api_endpoints(&self) -> Vec<String> {
        let endpoints = self.api_endpoints.lock().await;
        endpoints.iter().cloned().collect()
    }

    /// Clear all discovered data
    pub async fn clear(&self) {
        self.discovered_urls.lock().await.clear();
        self.js_resources.lock().await.clear();
        self.api_endpoints.lock().await.clear();
    }

    /// Resolve relative URL to absolute
    fn resolve_url(&self, url: &str, base_url: &str) -> Option<String> {
        if url.starts_with("http://") || url.starts_with("https://") {
            Some(url.to_string())
        } else if url.starts_with("//") {
            Some(format!("https:{}", url))
        } else if url.starts_with('/') {
            let base = base_url.split('/').take(3).collect::<Vec<_>>().join("/");
            Some(format!("{}{}", base, url))
        } else if url.starts_with("./") || url.starts_with("../") || !url.contains("://") {
            // Relative path
            let base_parts: Vec<_> = base_url.split('/').collect();
            let base_path = base_parts[..base_parts.len()-1].join("/");
            Some(format!("{}/{}", base_path, url))
        } else {
            Some(url.to_string())
        }
    }
}

#[derive(Debug, Clone)]
pub struct GraphQLOperation {
    pub name: String,
    pub operation_type: OperationType,
    pub body: String,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum OperationType {
    Query,
    Mutation,
    Subscription,
}
