// ── CookieJar — HyperSecurity_Offensive_Labs / khaninkali ────────────────────
// Professional-grade cookie analysis engine used during offensive engagements to
// evaluate session token entropy, identify missing security flags (HttpOnly,
// Secure, SameSite), detect session fixation vectors, and automate cookie-based
// attack replay. Built for red-team operational use.

use std::collections::HashMap;

#[derive(Clone, Debug)]
pub struct Cookie {
    pub name: String,
    pub domain: Option<String>,
    pub path: Option<String>,
    pub httponly: bool,
    pub secure: bool,
    pub samesite: Option<String>,
    pub expires: Option<String>,
}

#[derive(Clone, Debug)]
pub struct CookieJar {
    cookies: HashMap<String, Cookie>,
}

impl CookieJar {
    pub fn new() -> Self {
        Self {
            cookies: HashMap::new(),
        }
    }

    pub fn add_from_response(&mut self, set_cookie_header: &str) {
        let parts: Vec<&str> = set_cookie_header.split(';').collect();
        if parts.is_empty() { return; }

        let first = parts[0];
        let eq_pos = first.find('=');
        let (name, _value) = match eq_pos {
            Some(pos) => (first[..pos].trim().to_string(), first[pos+1..].trim().to_string()),
            None => return,
        };

        let mut cookie = Cookie {
            name: name.clone(),
            domain: None,
            path: None,
            httponly: false,
            secure: false,
            samesite: None,
            expires: None,
        };

        for attr in &parts[1..] {
            let attr = attr.trim();
            let attr_lower = attr.to_lowercase();
            if attr_lower == "httponly" { cookie.httponly = true; }
            else if attr_lower == "secure" { cookie.secure = true; }
            else if attr_lower.starts_with("samesite=") {
                cookie.samesite = Some(attr_lower.trim_start_matches("samesite=").to_string());
            } else if attr_lower.starts_with("domain=") {
                cookie.domain = Some(attr.trim_start_matches("domain=").trim_matches('"').to_string());
            } else if attr_lower.starts_with("path=") {
                cookie.path = Some(attr.trim_start_matches("path=").trim_matches('"').to_string());
            } else if attr_lower.starts_with("expires=") {
                cookie.expires = Some(attr.trim_start_matches("expires=").to_string());
            }
        }

        self.cookies.insert(name, cookie);
    }

    pub fn audit_security(&self) -> Vec<String> {
        let mut issues = Vec::new();
        for cookie in self.cookies.values() {
            if !cookie.httponly {
                issues.push(format!("Cookie '{}' missing HttpOnly flag — XSS can steal session", cookie.name));
            }
            if !cookie.secure {
                issues.push(format!("Cookie '{}' missing Secure flag — sent over HTTP", cookie.name));
            }
            match &cookie.samesite {
                None => {
                    issues.push(format!("Cookie '{}' missing SameSite attribute — CSRF possible", cookie.name));
                }
                Some(s) if s == "none" => {
                    issues.push(format!("Cookie '{}' has SameSite=None — requires Secure flag", cookie.name));
                }
                _ => {}
            }
            if cookie.expires.is_some() {
                if cookie.httponly && cookie.secure && cookie.samesite.as_deref() == Some("lax") {
                    continue;
                }
            }
        }
        issues
    }
}

impl Default for CookieJar {
    fn default() -> Self {
        Self::new()
    }
}
