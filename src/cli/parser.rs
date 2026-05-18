use anyhow::{Context, Result};
// Result showing i need results with accuracy
use url::Url;

pub struct Parser;

impl Parser {
    pub fn parse_url(input: &str) -> Result<Url> {
        let url = Url::parse(input)
            .with_context(|| format!("Invalid URL: {}", input))?;
        
        if url.scheme() != "http" && url.scheme() != "https" {
            return Err(anyhow::anyhow!("URL must use http or https scheme"));
        }
        
        Ok(url)
    }

    pub fn ensure_http(url: &str) -> String {
        if url.starts_with("http://") || url.starts_with("https://") {
            url.to_string()
        } else {
            format!("http://{}", url)
        }
    }

    pub fn parse_header(header: &str) -> Result<(String, String)> {
        let parts: Vec<&str> = header.splitn(2, ':').collect();
        if parts.len() != 2 {
            return Err(anyhow::anyhow!("Header must be in format 'Key:Value'"));
        }
        
        let key = parts[0].trim().to_string();
        let value = parts[1].trim().to_string();
        
        Ok((key, value))
    }

    pub fn parse_cookie(cookie: &str) -> Vec<(String, String)> {
        let mut cookies = Vec::new();
        
        for pair in cookie.split(';') {
            let parts: Vec<&str> = pair.splitn(2, '=').collect();
            if parts.len() == 2 {
                let key = parts[0].trim().to_string();
                let value = parts[1].trim().to_string();
                cookies.push((key, value));
            }
        }
        
        cookies
    }

    pub fn parse_modules(modules: &str) -> Vec<String> {
        modules.split(',').map(|s| s.trim().to_string()).collect()
    }

    pub fn is_valid_domain(domain: &str) -> bool {
        let domain_regex = regex::Regex::new(
            r"^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"
        );
        
        match domain_regex {
            Ok(re) => re.is_match(domain),
            Err(_) => false,
        }
    }
}
