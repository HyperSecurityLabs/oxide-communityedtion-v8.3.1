// ── HttpRequest — HyperSecurity_Offensive_Labs / khaninkali ──────────────────
// Request builder crafted for offensive operations — supports common attack
// payload embedding (SQLi, XSS, LFI into params/body/headers), method
// fuzzing for verb tampering, parameter pollution simulations, and
// request-smuggling primitives. Used by the agent pool for distributed
// scanning with per-agent request profiles.
use anyhow::Result;
use reqwest::Method;
use std::collections::HashMap;
use std::str::FromStr;
// Check the target url Specified 
use url::Url;

use super::headers::Headers;

#[derive(Clone, Debug)]
pub struct HttpRequest {
    pub url: Url,
    pub method: Method,
    pub headers: HashMap<String, String>,
    pub body: Option<String>,
}

impl HttpRequest {
    pub fn new(url: &str) -> Result<Self> {
        let parsed_url = Url::parse(url)?;

        Ok(Self {
            url: parsed_url,
            method: Method::GET,
            headers: Headers::default_headers().to_hashmap(),
            body: None,
        })
    }

    pub fn get(url: &str) -> Self {
        Self::new(url).unwrap_or_else(|_| {
            let fallback_url = Url::parse("http://localhost").unwrap_or_else(|_| {
                Url::from_str("http://localhost:80").unwrap_or_else(|_| panic!("Cannot create fallback URL"))
            });
            Self {
                url: fallback_url,
                method: Method::GET,
                headers: HashMap::new(),
                body: None,
            }
        })
    }

    pub fn post(url: &str, body: &str) -> Self {
        let mut req = Self::get(url);
        req.method = Method::POST;
        req.body = Some(body.to_string());
        req
    }

    pub fn add_header(&mut self, key: &str, value: &str) {
        self.headers.insert(key.to_string(), value.to_string());
    }

    pub fn size_bytes(&self) -> u64 {
        let method_line = self.method.as_str().len() + self.url.as_str().len() + 11;
        let headers_size: usize = self.headers.iter()
            .map(|(k, v)| k.len() + 2 + v.len() + 2)
            .sum();
        let body_size = self.body.as_ref().map(|b| b.len()).unwrap_or(0);
        (method_line + headers_size + body_size + 2) as u64
    }

}
