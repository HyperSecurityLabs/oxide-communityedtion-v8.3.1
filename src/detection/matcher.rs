use regex::Regex;
use std::collections::HashMap;

pub struct Matcher {
    patterns: HashMap<String, Regex>,
}

impl Matcher {
    pub fn new() -> Self {
        let mut patterns = HashMap::new();
        
        patterns.insert(
            "sql_error".to_string(),
            Regex::new(r"(SQL syntax|mysql_fetch|ORA-|PostgreSQL|SQLite|SQLServer)")
                .expect("Static SQL error regex should be valid")
        );
        
        patterns.insert(
            "xss_vulnerable".to_string(),
            Regex::new(r"(<script|javascript:|onload=|onerror=)")
                .expect("Static XSS regex should be valid")
        );
        
        patterns.insert(
            "path_traversal".to_string(),
            Regex::new(r"(\.\./|\.\.\\|%2e%2e%2f)")
                .expect("Static path traversal regex should be valid")
        );
        
        patterns.insert(
            "cve_2021_44228".to_string(),
            Regex::new(r"(\$\{jndi:|ldap://|rmi://)")
                .expect("Static Log4j CVE regex should be valid")
        );
        
        patterns.insert(
            "jwt_token".to_string(),
            Regex::new(r"eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*")
                .expect("Static JWT token regex should be valid")
        );
        
        patterns.insert(
            "api_key".to_string(),
            Regex::new(r"(api[_-]?key|apikey)\s*[=:]\s*[a-zA-Z0-9]{16,}")
                .expect("Static API key regex should be valid")
        );
        
        patterns.insert(
            "private_key".to_string(),
            Regex::new(r"-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----")
                .expect("Static private key regex should be valid")
        );
        
        patterns.insert(
            "email_pattern".to_string(),
            Regex::new(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
                .expect("Static email regex should be valid")
        );
        
        Self { patterns }
    }

    pub fn matches(&self, pattern_name: &str, text: &str) -> bool {
        if let Some(regex) = self.patterns.get(pattern_name) {
            regex.is_match(text)
        } else {
            false
        }
    }

    pub fn find_all(&self, pattern_name: &str, text: &str) -> Vec<String> {
        let mut results = Vec::new();
        
        if let Some(regex) = self.patterns.get(pattern_name) {
            for cap in regex.find_iter(text) {
                results.push(cap.as_str().to_string());
            }
        }
        
        results
    }

    pub fn add_pattern(&mut self, name: &str, pattern: &str) -> Result<(), regex::Error> {
        let regex = Regex::new(pattern)?;
        self.patterns.insert(name.to_string(), regex);
        Ok(())
    }

    pub fn has_pattern(&self, name: &str) -> bool {
        self.patterns.contains_key(name)
    }
}

impl Default for Matcher {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for Matcher {
    fn clone(&self) -> Self {
        Self {
            patterns: self.patterns.clone(),
        }
    }
}
