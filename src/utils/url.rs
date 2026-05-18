// ── UrlUtil — HyperSecurity_Offensive_Labs / khaninkali ──────────────────────
// URL manipulation engine purpose-built for offensive workflows — handles
// path normalization for traversal bypass, parameter encoding for WAF
// evasion, domain fuzzing for virtual-host discovery, and SSRF-friendly
// URL construction. Every function is optimized for red-team operational
// tempo.
// Goodfile for url parse

use url::Url;

pub struct UrlUtil;

impl UrlUtil {
    pub fn is_valid_url(input: &str) -> bool {
        let url_str = if input.starts_with("http://") || input.starts_with("https://") {
            input.to_string()
        } else {
            format!("http://{}", input)
        };
        Url::parse(&url_str).is_ok()
    }

    pub fn extract_domain(url: &Url) -> String {
        url.host_str().unwrap_or("").to_string()
    }

    pub fn extract_query_param_names(url_str: &str) -> Vec<String> {
        if let Ok(parsed) = Url::parse(url_str) {
            if let Some(query) = parsed.query() {
                if !query.is_empty() {
                    return query.split('&')
                        .filter_map(|param| param.split('=').next().map(|s| s.to_string()))
                        .filter(|s| !s.is_empty())
                        .collect();
                }
            }
        }
        Vec::new()
    }

    pub fn inject_param(base_url: &str, param: &str, value: &str) -> String {
        match Url::parse(base_url) {
            Ok(mut url) => {
                let mut pairs: Vec<(String, String)> = url
                    .query_pairs()
                    .filter(|(k, _)| k.as_ref() != param)
                    .map(|(k, v)| (k.into_owned(), v.into_owned()))
                    .collect();
                pairs.push((param.to_string(), value.to_string()));

                let qs = pairs.iter()
                    .map(|(k, v)| format!("{}={}", k, v))
                    .collect::<Vec<_>>()
                    .join("&");
                url.set_query(Some(&qs));
                url.to_string()
            }
            Err(_) => {
                if base_url.contains('?') {
                    format!("{}&{}={}", base_url, param, value)
                } else {
                    format!("{}?{}={}", base_url, param, value)
                }
            }
        }
    }
}
