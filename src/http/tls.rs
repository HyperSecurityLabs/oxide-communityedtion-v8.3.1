pub fn check_tls_version(url: &str) -> String {
    if url.starts_with("https://") {
        "TLS 1.2+".to_string()
    } else {
        "No TLS".to_string()
    }
}
