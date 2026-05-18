use anyhow::Result;
use reqwest::header::{HeaderMap, SET_COOKIE, HeaderValue};
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct SessionIssue {
    pub severity: Severity,
    pub title: String,
    pub description: String,
    pub evidence: String,
    pub remediation: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

pub struct SessionHijackTester {
    client: reqwest::Client,
}

impl SessionHijackTester {
    pub fn new(timeout_secs: u64, insecure: bool) -> Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(timeout_secs))
            .danger_accept_invalid_certs(insecure)
            .cookie_store(true)
            .user_agent("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36")
            .build()?;
        Ok(Self { client })
    }

    pub async fn full_test(&self, target: &str) -> Result<Vec<crate::detection::analyzer::Finding>> {
        let mut findings = Vec::new();

        let resp = match self.client.get(target)
            .header("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
            .header("Accept-Language", "en-US,en;q=0.5")
            .send().await
        {
            Ok(r) => r,
            Err(e) => {
                findings.push(crate::detection::analyzer::Finding::new(
                    target, crate::detection::analyzer::Severity::Low,
                    "Session Hijack: Target Unreachable",
                    &format!("Failed to connect: {}", e),
                ));
                return Ok(findings);
            }
        };

        let headers = resp.headers().clone();
        let body = resp.text().await.unwrap_or_default();

        // 1. Check response for session tokens in body/URLs
        if let Some(f) = check_session_in_body(target, &body) {
            findings.push(f);
        }

        // 2. Check Set-Cookie headers for security flags
        let set_cookie_findings = check_cookie_security(target, &headers);
        findings.extend(set_cookie_findings);

        // 3. Check if session ID is accepted via URL parameter (session fixation)
        if let Some(f) = self.check_session_fixation(target).await {
            findings.push(f);
        }

        // 4. Check for predictable session patterns
        if let Some(f) = check_session_predictability(target, &headers) {
            findings.push(f);
        }

        // 5. Check for HTTP (insecure) session transmission
        if !target.starts_with("https://") {
            findings.push(crate::detection::analyzer::Finding::new(
                target, crate::detection::analyzer::Severity::High,
                "Session Hijack: Insecure HTTP Session",
                "Session data transmitted over unencrypted HTTP — trivial to intercept"
            ).with_evidence("Target uses HTTP, not HTTPS")
             .with_remediation("Enforce HTTPS with HSTS and redirect all HTTP traffic"));
        }

        // 6. Check if session timeout is inferable
        if let Some(f) = check_session_timeout(target, &headers) {
            findings.push(f);
        }

        Ok(findings)
    }

    async fn check_session_fixation(&self, target: &str) -> Option<crate::detection::analyzer::Finding> {
        let test_id = format!("FIXATION_TEST_{}", rand::random::<u32>());
        let fixation_url = if target.contains('?') {
            format!("{}&session_id={}", target, test_id)
        } else {
            format!("{}?session_id={}", target, test_id)
        };

        let test_resp = match self.client.get(&fixation_url)
            .header("Accept", "text/html,application/xhtml+xml")
            .send().await
        {
            Ok(r) => r,
            Err(_) => return None,
        };

        let body_contains_id = test_resp.text().await.unwrap_or_default().contains(&test_id);

        if body_contains_id {
            return Some(crate::detection::analyzer::Finding::new(
                target,
                crate::detection::analyzer::Severity::High,
                "Session Hijack: Session Fixation Possible",
                "Application reflects the session_id parameter in the response, indicating session fixation may be possible"
            ).with_evidence(&format!("Sent session_id={} and it appeared in the response body", test_id))
             .with_remediation("Regenerate session ID on authentication; never accept session IDs from URL parameters"));
        }

        None
    }
}

fn check_session_in_body(target: &str, body: &str) -> Option<crate::detection::analyzer::Finding> {
    let session_patterns = [
        (r"jsessionid=[a-zA-Z0-9]+", "JSESSIONID"),
        (r"PHPSESSID=[a-zA-Z0-9]+", "PHPSESSID"),
        (r"ASP\.NET_SessionId=[a-zA-Z0-9]+", "ASP.NET_SessionId"),
        (r"session_id=[a-zA-Z0-9]+", "session_id"),
        (r"sid=[a-zA-Z0-9]+", "sid"),
        (r"token=[a-zA-Z0-9]+", "token"),
    ];

    for (pat, name) in &session_patterns {
        if let Ok(re) = regex::Regex::new(pat) {
            if re.is_match(body) {
                return Some(crate::detection::analyzer::Finding::new(
                    target,
                    crate::detection::analyzer::Severity::Medium,
                    "Session Hijack: Session Token in Response Body",
                    &format!("Found {} pattern in response body — session token exposed", name)
                ).with_evidence(&format!("{} matched in response content", name))
                 .with_remediation("Remove session tokens from response bodies; use cookies with HttpOnly flag"));
            }
        }
    }
    None
}

fn check_cookie_security(target: &str, headers: &HeaderMap) -> Vec<crate::detection::analyzer::Finding> {
    let mut findings = Vec::new();

    let set_cookie_headers: Vec<&HeaderValue> = headers.get_all(SET_COOKIE).iter().collect();

    if set_cookie_headers.is_empty() {
        return findings;
    }

    for hv in &set_cookie_headers {
        if let Ok(cookie_str) = hv.to_str() {
            let cookie_lower = cookie_str.to_lowercase();

            if !cookie_lower.contains("httponly") {
                if let Some(name) = cookie_str.split('=').next() {
                    findings.push(crate::detection::analyzer::Finding::new(
                        target,
                        crate::detection::analyzer::Severity::Medium,
                        "Session Hijack: Cookie Missing HttpOnly Flag",
                        &format!("Cookie '{}' lacks HttpOnly — accessible via JavaScript", name)
                    ).with_evidence(&format!("Set-Cookie: {}", cookie_str))
                     .with_remediation("Add HttpOnly flag to all session cookies"));
                }
            }

            if !cookie_lower.contains("secure") && !cookie_lower.contains("__host-") {
                if let Some(name) = cookie_str.split('=').next() {
                    findings.push(crate::detection::analyzer::Finding::new(
                        target,
                        crate::detection::analyzer::Severity::Medium,
                        "Session Hijack: Cookie Missing Secure Flag",
                        &format!("Cookie '{}' lacks Secure — transmitted over HTTP", name)
                    ).with_evidence(&format!("Set-Cookie: {}", cookie_str))
                     .with_remediation("Add Secure flag to all session cookies and enforce HTTPS"));
                }
            }

            if cookie_lower.contains("samesite") {
                if cookie_lower.contains("samesite=none") {
                    if let Some(name) = cookie_str.split('=').next() {
                        findings.push(crate::detection::analyzer::Finding::new(
                            target,
                            crate::detection::analyzer::Severity::Low,
                            "Session Hijack: Cookie SameSite=None",
                            &format!("Cookie '{}' uses SameSite=None — allows cross-site usage", name)
                        ).with_evidence(&format!("Set-Cookie: {}", cookie_str))
                         .with_remediation("Use SameSite=Lax or Strict unless cross-site access is required"));
                    }
                }
            } else if cookie_lower.contains("session") || cookie_lower.contains("sid") {
                if let Some(name) = cookie_str.split('=').next() {
                    findings.push(crate::detection::analyzer::Finding::new(
                        target,
                        crate::detection::analyzer::Severity::Low,
                        "Session Hijack: Cookie Missing SameSite Flag",
                        &format!("Session cookie '{}' lacks SameSite attribute", name)
                    ).with_evidence(&format!("Set-Cookie: {}", cookie_str))
                     .with_remediation("Add SameSite=Lax or Strict to prevent CSRF-based session hijack"));
                }
            }

            if !cookie_lower.contains("path=") {
                if let Some(name) = cookie_str.split('=').next() {
                    findings.push(crate::detection::analyzer::Finding::new(
                        target,
                        crate::detection::analyzer::Severity::Low,
                        "Session Hijack: Cookie Missing Path Attribute",
                        &format!("Cookie '{}' has no Path set — may be sent to subdirectories", name)
                    ).with_evidence(&format!("Set-Cookie: {}", cookie_str))
                     .with_remediation("Set explicit Path=/ for session cookies"));
                }
            }

            if cookie_lower.contains("expires=") || cookie_lower.contains("max-age=") {
                let is_persistent = cookie_lower.contains("max-age=")
                    && cookie_lower.split("max-age=").nth(1)
                        .and_then(|s| s.split(';').next())
                        .and_then(|s| s.trim().parse::<u64>().ok())
                        .map(|v| v > 3600)
                        .unwrap_or(false);

                if is_persistent {
                    if let Some(name) = cookie_str.split('=').next() {
                        findings.push(crate::detection::analyzer::Finding::new(
                            target,
                            crate::detection::analyzer::Severity::Medium,
                            "Session Hijack: Persistent Session Cookie",
                            &format!("Cookie '{}' has a long-lived expiration — increases hijack window", name)
                        ).with_evidence(&format!("Set-Cookie: {}", cookie_str))
                         .with_remediation("Use session cookies (no Expires/Max-Age) or short-lived tokens"));
                    }
                }
            }
        }
    }

    findings
}

fn check_session_predictability(_target: &str, headers: &HeaderMap) -> Option<crate::detection::analyzer::Finding> {
    let set_cookie_headers: Vec<&HeaderValue> = headers.get_all(SET_COOKIE).iter().collect();

    for hv in &set_cookie_headers {
        if let Ok(cookie_str) = hv.to_str() {
            let lower = cookie_str.to_lowercase();
            let is_session = lower.contains("session") || lower.contains("sid") || lower.contains("token");
            if is_session {
                if let Some(value) = cookie_str.split('=').nth(1) {
                    let value = value.split(';').next().unwrap_or("").trim();
                    if value.len() < 16 {
                        return Some(crate::detection::analyzer::Finding::new(
                            _target,
                            crate::detection::analyzer::Severity::High,
                            "Session Hijack: Short Session Token",
                            &format!("Session token is only {} characters — brute-forceable", value.len())
                        ).with_evidence(&format!("Cookie value length: {} chars", value.len()))
                         .with_remediation("Use session tokens of at least 128 bits (32+ hex chars)"));
                    }
                }
            }
        }
    }

    None
}

fn check_session_timeout(_target: &str, headers: &HeaderMap) -> Option<crate::detection::analyzer::Finding> {
    let set_cookie_headers: Vec<&HeaderValue> = headers.get_all(SET_COOKIE).iter().collect();

    for hv in &set_cookie_headers {
        if let Ok(cookie_str) = hv.to_str() {
            let lower = cookie_str.to_lowercase();
            if (lower.contains("session") || lower.contains("sid")) && !lower.contains("max-age") && !lower.contains("expires") {
                return None;
            }
        }
    }
    None
}
