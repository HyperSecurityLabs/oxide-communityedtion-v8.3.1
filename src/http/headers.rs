// ── Headers — HyperSecurity_Offensive_Labs / khaninkali ──────────────────────
// HTTP header analysis toolkit used in offensive operations to fingerprint
// backend stacks, audit security header posture, and craft header-based
// injection payloads (CRLF, Host override, X-Forwarded-For spoofing).
// Designed for real-world red-team engagements.

use std::collections::HashMap;

#[derive(Clone, Debug)]
pub struct Headers {
    headers: HashMap<String, String>,
}

impl Headers {
    pub fn new() -> Self {
        Self {
            headers: HashMap::new(),
        }
    }

    pub fn default_headers() -> Self {
        let mut headers = Self::new();
        headers.add("User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0");
        headers.add("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");
        headers.add("Accept-Language", "en-US,en;q=0.5");
        headers.add("Accept-Encoding", "gzip, deflate");
        headers.add("Connection", "keep-alive");
        headers.add("Upgrade-Insecure-Requests", "1");
        headers
    }

    pub fn add(&mut self, key: &str, value: &str) {
        self.headers.insert(key.to_string(), value.to_string());
    }

    pub fn to_hashmap(&self) -> HashMap<String, String> {
        self.headers.clone()
    }

    pub fn audit_security_headers(response_headers: &HashMap<String, String>) -> Vec<(String, String, String)> {
        let checks = [
            ("Strict-Transport-Security", "HSTS", "Missing HTTP Strict-Transport-Security header"),
            ("Content-Security-Policy", "CSP", "Missing Content-Security-Policy header — XSS risk"),
            ("X-Content-Type-Options", "XCTO", "Missing X-Content-Type-Options: nosniff"),
            ("X-Frame-Options", "XFO", "Missing X-Frame-Options — clickjacking risk"),
            ("X-XSS-Protection", "XXSSP", "Missing X-XSS-Protection header"),
            ("Referrer-Policy", "Referrer", "Missing Referrer-Policy header"),
            ("Permissions-Policy", "Permissions", "Missing Permissions-Policy header"),
            ("Access-Control-Allow-Origin", "CORS", "Missing CORS headers"),
            ("Set-Cookie", "SecureCookie", "No Set-Cookie header found"),
        ];

        let mut results = Vec::new();
        for (header, short, desc) in &checks {
            if *header == "X-XSS-Protection" {
                if let Some(val) = response_headers.get("x-xss-protection") {
                    if val == "0" || val == "1" {
                        results.push((short.to_string(), "present".to_string(), "X-XSS-Protection header set".to_string()));
                        continue;
                    }
                }
            }

            let header_lower = header.to_lowercase();
            let found = response_headers.keys().any(|k| k.to_lowercase() == header_lower);

            if found {
                results.push((short.to_string(), "present".to_string(), desc.replacen("Missing ", "Found ", 1)));
            } else {
                results.push((short.to_string(), "missing".to_string(), desc.to_string()));
            }
        }
        results
    }

}

impl Default for Headers {
    fn default() -> Self {
        Self::new()
    }
}
