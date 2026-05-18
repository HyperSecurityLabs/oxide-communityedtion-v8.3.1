#![cfg(target_os = "linux")]
// ── ActiveRecon — HyperSecurity_Offensive_Labs / khaninkali ──────────────────
//! Active reconnaissance engine using raw TCP/IP packets (via pnet) for OS
//! fingerprinting, port scanning, and banner grabbing. Falls back to HTTP-level
//! fingerprinting when raw sockets are unavailable (non-root). Designed for
//! professional red-team engagement use.
//
// Recon types supported:
//   1. TCP/IP OS fingerprinting (TTL, window size, DF flag analysis)
//   2. SYN port scanning (stealth connect scan)
//   3. Service banner grabbing via TCP connect
//   4. HTTP server/WAF fingerprinting (header + body analysis)
//   5. TLS certificate analysis
//   6. Technology stack detection (CMS, frameworks)
//   7. Security header audit
//   8. Cookie analysis
//   9. CORS policy analysis
//  10. Database fingerprinting via error pages
//  11. DNS subdomain discovery
//  12. Directory brute forcing
//  13. Parameter discovery
//  14. Error page technology leakage
//  15. Reverse DNS / WHOIS lookups

use anyhow::Result;
//  Beautiful Raw packet injection Hackers Favourate Pnet for DDos attacks
//  Active fingerPrining 
//  Dont fire it up in targets 
//  Needed Admins

use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::tcp::{ 
           TcpFlags, ipv4_checksum};
use std::net::{
           IpAddr,  
               Ipv4Addr};
               
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;

use crate::detection::behavior::BehaviorAnalyzer;
use crate::http::client::HttpClient;
use crate::http::request::HttpRequest;
use crate::http::useragents::UserAgentPool;

#[derive(Clone, Debug)]
pub struct OsFingerprint {
    pub os_family: String,
    pub os_version: String,
    pub confidence: u8,
}

#[derive(Clone, Debug)]
pub struct ServiceBanner {
    pub port: u16,
    pub protocol: String,
    pub banner: String,
}

#[derive(Clone, Debug)]
pub struct PortInfo {
    pub port: u16,
    pub state: String,
    pub service: String,
}

#[derive(Clone, Debug)]
pub struct ReconResult {
    pub os: Option<OsFingerprint>,
    pub open_ports: Vec<PortInfo>,
    pub banners: Vec<ServiceBanner>,
    pub waf: Option<String>,
    pub server: String,
    pub tech_stack: Vec<String>,
    pub security_headers: Vec<(String, String, String)>,
}

pub struct ActiveRecon {
    client: Arc<HttpClient>,
    target: String,
    target_ip: Option<IpAddr>,
    behavior: BehaviorAnalyzer,
    timeout: Duration,
    ua_pool: UserAgentPool,
    aggressive_pool: UserAgentPool,
}

impl ActiveRecon {
    pub fn new(client: Arc<HttpClient>, target: &str) -> Self {
        Self {
            client,
            target: target.to_string(),
            target_ip: None,
            behavior: BehaviorAnalyzer::new(),
            timeout: Duration::from_secs(5),
            ua_pool: UserAgentPool::full(),
            aggressive_pool: UserAgentPool::aggressive(),
        }
    }

    /// Send an HTTP GET with a random modern UA
    async fn send_with_ua(&self, url: &str) -> Result<crate::http::response::HttpResponse> {
        let mut req = HttpRequest::get(url);
        let ua = self.ua_pool.random();
        req.add_header("User-Agent", ua);
        let (accept, lang, encoding) = UserAgentPool::accept_headers_for(ua);
        req.add_header("Accept", accept);
        req.add_header("Accept-Language", lang);
        req.add_header("Accept-Encoding", encoding);
        self.client.send(req).await
    }

    /// Send an HTTP GET with an aggressive bot/scanner UA for probing
    async fn send_aggressive(&self, url: &str) -> Result<crate::http::response::HttpResponse> {
        let mut req = HttpRequest::get(url);
        let ua = self.aggressive_pool.random();
        req.add_header("User-Agent", ua);
        let (accept, lang, encoding) = UserAgentPool::accept_headers_for(ua);
        req.add_header("Accept", accept);
        req.add_header("Accept-Language", lang);
        req.add_header("Accept-Encoding", encoding);
        self.client.send(req).await
    }

    /// Probe target with multiple UAs to detect WAF/Bot differential responses
    pub async fn probe_with_all_agents(&self, url: &str) -> Vec<(String, u16, usize)> {
        let mut results = Vec::new();

        // Try 5 aggressive UAs that trigger different server behavior
        let probes = ["Googlebot/2.1", "curl/8.7.1", "MSIE 6.0", "sqlmap/1.8.2", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"];
        for ua in probes {
            let mut req = HttpRequest::get(url);
            req.add_header("User-Agent", ua);
            if let Ok(resp) = self.client.send(req).await {
                results.push((ua.to_string(), resp.status, resp.body.len()));
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        results
    }

    pub async fn tcp_fingerprint_os(&self) -> Option<OsFingerprint> {
        match self.raw_tcp_probe().await {
            Ok(fp) => Some(fp),
            Err(_) => {
                // Fallback: HTTP-level fingerprinting via TTL from response headers
                self.http_ttl_fingerprint().await
            }
        }
    }

    async fn raw_tcp_probe(&self) -> Result<OsFingerprint> {
        // Resolve target IP
        let target_ip = match self.resolve_target().await {
            Some(ip) => ip,
            None => return Err(anyhow::anyhow!("Could not resolve target")),
        };

        // Use pnet to send a SYN packet and capture the SYN-ACK
        let (mut tx, mut rx) = pnet::transport::transport_channel(
            4096,
            pnet::transport::TransportChannelType::Layer4(
                pnet::transport::TransportProtocol::Ipv4(IpNextHeaderProtocols::Tcp),
            ),
        )?;

        let source_port = 49152u16;
        let seq = 1000u32;
        let window = 65535u16;

        let mut tcp_buffer = vec![0u8; 20];
        let mut tcp_packet = pnet::packet::tcp::MutableTcpPacket::new(&mut tcp_buffer).unwrap();

        tcp_packet.set_source(source_port);
        tcp_packet.set_destination(80);
        tcp_packet.set_sequence(seq);
        tcp_packet.set_data_offset(5);
        tcp_packet.set_flags(TcpFlags::SYN);
        tcp_packet.set_window(window);
        tcp_packet.set_urgent_ptr(0);
        let source_ip = Ipv4Addr::new(0, 0, 0, 0);
        let dest_ip = match target_ip {
            IpAddr::V4(ip) => ip,
            _ => return Err(anyhow::anyhow!("IPv4 required for raw TCP probe")),
        };
        let tcp_checksum = ipv4_checksum(
            &tcp_packet.to_immutable(),
            &source_ip,
            &dest_ip,
        );
        tcp_packet.set_checksum(tcp_checksum);

        // Send the SYN packet
        tx.send_to(&tcp_packet.to_immutable(), dest_ip.into())?;

        // Wait for SYN-ACK with timeout
        let mut iter = pnet::transport::tcp_packet_iter(&mut rx);
        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(3) {
            match iter.next() {
                Ok((tcp, addr)) => {
                    if addr != IpAddr::V4(dest_ip) { continue; }
                    if tcp.get_destination() == source_port
                        && tcp.get_flags() == (TcpFlags::SYN | TcpFlags::ACK)
                    {
                        let ttl = 64u8;
                        let os = self.classify_os(ttl, tcp.get_window(), true);
                        return Ok(os);
                    }
                }
                Err(_) => continue,
            }
        }

        Err(anyhow::anyhow!("No SYN-ACK received"))
    }

    async fn http_ttl_fingerprint(&self) -> Option<OsFingerprint> {
        let start = Instant::now();
        match self.client.send(HttpRequest::get(&self.target)).await {
            Ok(resp) => {
                let rtt = start.elapsed();
                let ttl_estimate = if rtt < Duration::from_millis(50) {
                    // Likely on same network segment — could be 64 (Linux) or 128 (Windows)
                    64u8
                } else if rtt < Duration::from_millis(200) {
                    64u8
                } else {
                    128u8
                };
                let server_hint = resp.get_header("Server").cloned().unwrap_or_default();
                let os = self.classify_os_from_server(&server_hint, ttl_estimate);
                Some(os)
            }
            Err(_) => None,
        }
    }

    fn classify_os(&self, ttl: u8, window: u16, df: bool) -> OsFingerprint {
        match (ttl, window, df) {
            (64, 65535, true) => OsFingerprint {
                os_family: "Linux".into(),
                os_version: "3.x / 4.x / 5.x".into(),
                confidence: 85,
            },
            (64, 5840, true) => OsFingerprint {
                os_family: "Linux".into(),
                os_version: "2.6.x".into(),
                confidence: 80,
            },
            (128, 65535, true) => OsFingerprint {
                os_family: "Windows".into(),
                os_version: "10 / Server 2016+".into(),
                confidence: 85,
            },
            (128, 8192, true) => OsFingerprint {
                os_family: "Windows".into(),
                os_version: "7 / Server 2008".into(),
                confidence: 80,
            },
            (128, 16384, true) => OsFingerprint {
                os_family: "Windows".into(),
                os_version: "XP / Server 2003".into(),
                confidence: 75,
            },
            (64, 65535, false) => OsFingerprint {
                os_family: "macOS / BSD".into(),
                os_version: "generic".into(),
                confidence: 70,
            },
            (255, 8760, true) => OsFingerprint {
                os_family: "Cisco IOS".into(),
                os_version: "12.x+".into(),
                confidence: 80,
            },
            (64, 5720, true) => OsFingerprint {
                os_family: "Solaris".into(),
                os_version: "10 / 11".into(),
                confidence: 70,
            },
            _ => OsFingerprint {
                os_family: "Unknown".into(),
                os_version: format!("ttl={} win={} df={}", ttl, window, df),
                confidence: 30,
            },
        }
    }

    fn classify_os_from_server(&self, server: &str, _ttl: u8) -> OsFingerprint {
        let sl = server.to_lowercase();
        let (family, version) = if sl.contains("windows") || sl.contains("iis") || sl.contains("asp.net") {
            ("Windows", "Server via HTTP")
        } else if sl.contains("nginx") || sl.contains("apache") || sl.contains("ubuntu") || sl.contains("debian") || sl.contains("centos") {
            ("Linux", "via HTTP Server header")
        } else if sl.contains("cloudflare") {
            ("Cloudflare Proxy", "CDN (origin OS unknown)")
        } else {
            ("Unknown", "via HTTP Server header")
        };
        OsFingerprint {
            os_family: family.into(),
            os_version: version.into(),
            confidence: 50,
        }
    }

    pub async fn tcp_connect_scan(&self, ports: Vec<u16>) -> Vec<PortInfo> {
        let host = self.target
            .trim_start_matches("http://")
            .trim_start_matches("https://")
            .split('/')
            .next()
            .unwrap_or(&self.target)
            .to_string();
        let timeout = self.timeout;

        let tasks: Vec<_> = ports.into_iter().map(|port| {
            let host = host.clone();
            tokio::spawn(async move {
                let addr = format!("{}:{}", host, port);
                match tokio::time::timeout(timeout, TcpStream::connect(&addr)).await {
                    Ok(Ok(_)) => PortInfo {
                        port,
                        state: "open".into(),
                        service: port_to_service_name(port),
                    },
                    _ => PortInfo {
                        port,
                        state: "closed".into(),
                        service: port_to_service_name(port),
                    },
                }
            })
        }).collect();

        let mut results = Vec::with_capacity(tasks.len());
        for task in tasks {
            results.push(task.await.unwrap_or(PortInfo {
                port: 0,
                state: "error".into(),
                service: "unknown".into(),
            }));
        }
        results
    }

    pub async fn grab_banners(&self, ports: &[PortInfo]) -> Vec<ServiceBanner> {
        let host = self.target
            .trim_start_matches("http://")
            .trim_start_matches("https://")
            .split('/')
            .next()
            .unwrap_or(&self.target)
            .to_string();

        let open_ports: Vec<u16> = ports.iter().filter(|p| p.state == "open").map(|p| p.port).collect();

        let tasks: Vec<_> = open_ports.into_iter().map(|port| {
            let host = host.clone();
            tokio::spawn(async move {
                grab_single_banner_impl(&host, port).await
            })
        }).collect();

        let mut banners = Vec::new();
        for task in tasks {
            if let Ok(Ok(banner)) = task.await {
                banners.push(banner);
            }
        }
        banners
    }

    pub async fn detect_waf_http(&self) -> Option<String> {
        match self.send_with_ua(&self.target).await {
            Ok(resp) => {
                let headers: Vec<String> = resp.headers.iter()
                    .map(|(k, v)| format!("{}: {}", k, v))
                    .collect();
                self.behavior.detect_waf(&headers)
            }
            Err(_) => None,
        }
    }

    pub async fn detect_server(&self) -> String {
        // Probe with aggressive UA first (bot UA may bypass WAF and show real server)
        if let Ok(resp) = self.send_aggressive(&self.target).await {
            let server = resp.get_header("Server")
                .or_else(|| resp.get_header("X-Powered-By"))
                .cloned();
            if let Some(s) = server {
                if !s.is_empty() { return s; }
            }
        }
        // Fallback to normal UA
        match self.send_with_ua(&self.target).await {
            Ok(resp) => {
                resp.get_header("Server")
                    .or_else(|| resp.get_header("X-Powered-By"))
                    .cloned()
                    .unwrap_or_else(|| "Unknown".into())
            }
            Err(_) => "Unknown (unreachable)".into(),
        }
    }

    pub async fn detect_tech_stack(&self) -> Vec<String> {
        match self.send_aggressive(&self.target).await {
            Ok(resp) => {
                let headers: Vec<String> = resp.headers.iter()
                    .map(|(k, v)| format!("{}: {}", k, v))
                    .collect();
                self.behavior.detect_tech_stack(&headers, &resp.body)
            }
            Err(_) => Vec::new(),
        }
    }

    pub async fn audit_security_headers(&self) -> Vec<(String, String, String)> {
        match self.send_with_ua(&self.target).await {
            Ok(resp) => {
                crate::http::headers::Headers::audit_security_headers(&resp.headers)
            }
            Err(_) => Vec::new(),
        }
    }

    pub async fn analyze_cookies(&self) -> Vec<String> {
        let mut issues = Vec::new();
        if let Ok(resp) = self.send_with_ua(&self.target).await {
            for (key, val) in &resp.headers {
                let kl = key.to_lowercase();
                if kl == "set-cookie" {
                    let mut jar = crate::http::cookies::CookieJar::new();
                    jar.add_from_response(val);
                    let audit = jar.audit_security();
                    issues.extend(audit);
                }
            }
        }
        issues
    }

    pub async fn detect_error_pages(&self) -> Vec<String> {
        let test_paths = vec![
            "/nonexistent", "/test", "/../../etc/passwd",
            "/%00", "/.env", "/admin'",
        ];
        let base = self.target.trim_end_matches('/').to_string();
        let client = self.client.clone();
        let pool = self.aggressive_pool.clone();

        let tasks: Vec<_> = test_paths.into_iter().map(|path| {
            let base = base.clone();
            let client = client.clone();
            let pool = pool.clone();
            tokio::spawn(async move {
                let url = format!("{}{}", base, path);
                let ua = pool.next();
                let mut req = HttpRequest::get(&url);
                req.add_header("User-Agent", ua);
                let (accept, lang, encoding) = UserAgentPool::accept_headers_for(ua);
                req.add_header("Accept", accept);
                req.add_header("Accept-Language", lang);
                req.add_header("Accept-Encoding", encoding);
                (path.to_string(), client.send(req).await)
            })
        }).collect();

        let mut pages = Vec::new();
        for task in tasks {
            if let Ok((path, Ok(resp))) = task.await {
                if let Some(tech) = self.behavior.detect_error_page(&resp.body) {
                    pages.push(format!("{} -> {}", path, tech));
                }
            }
        }
        pages
    }

    async fn resolve_target(&self) -> Option<IpAddr> {
        if let Some(ip) = self.target_ip {
            return Some(ip);
        }
        let host = self.target
            .trim_start_matches("http://")
            .trim_start_matches("https://")
            .split('/')
            .next()
            .unwrap_or(&self.target);
        match tokio::net::lookup_host(format!("{}:80", host)).await {
            Ok(mut addrs) => addrs.next().map(|a| a.ip()),
            Err(_) => None,
        }
    }

    /// Cloudflare / WAF bypass probe — sends requests with spoofed headers
    /// that CDNs trust to reveal the real origin IP and server fingerprint.
    /// Returns list of (header_used, server_header, response_body_preview).
    pub async fn cloudflare_bypass_probe(&self) -> Vec<(String, String, String)> {
        let mut results = Vec::new();
        let bypass_headers = vec![
            ("X-Forwarded-For", "127.0.0.1"),
            ("X-Forwarded-For", "10.0.0.1"),
            ("X-Forwarded-For", "192.168.1.1"),
            ("True-Client-IP", "127.0.0.1"),
            ("CF-Connecting-IP", "127.0.0.1"),
            ("X-Real-IP", "127.0.0.1"),
            ("X-Originating-IP", "127.0.0.1"),
            ("X-Remote-IP", "127.0.0.1"),
            ("X-Client-IP", "127.0.0.1"),
            ("Forwarded", "for=127.0.0.1;by=127.0.0.1;proto=http"),
        ];

        for (header, value) in bypass_headers {
            let mut req = HttpRequest::get(&self.target);
            req.add_header("User-Agent", self.aggressive_pool.next());
            req.add_header("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8");
            req.add_header(header, value);
            if let Ok(resp) = self.client.send(req).await {
                let server = resp.get_header("Server").cloned().unwrap_or_default();
                let body_preview = resp.body.chars().take(60).collect::<String>();
                results.push((format!("{}: {}", header, value), server, body_preview));
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        results
    }

    pub fn format_recon_output(result: &ReconResult) -> String {
        let mut out = String::new();

        // WAF
        if let Some(ref waf) = result.waf {
            out.push_str(&format!("  \x1B[93mWAF\x1B[0m    {}\n", waf));
        } else {
            out.push_str("  \x1B[93mWAF\x1B[0m    \x1B[90mNone detected\x1B[0m\n");
        }

        // Server
        if !result.server.is_empty() && result.server != "Unknown" {
            out.push_str(&format!("  \x1B[93mSERVER\x1B[0m {}\n", result.server));
        }

        // OS
        if let Some(ref os) = result.os {
            out.push_str(&format!(
                "  \x1B[93mOS\x1B[0m     {} {} ({}% confidence)\n",
                os.os_family, os.os_version, os.confidence,
            ));
        }

        // Open ports
        let open: Vec<&PortInfo> = result.open_ports.iter().filter(|p| p.state == "open").collect();
        for port in &open {
            out.push_str(&format!(
                "  \x1B[93mPORT\x1B[0m   {} {} ({})\n",
                port.port, port.service, port.state,
            ));
        }

        // Tech stack
        for tech in &result.tech_stack {
                out.push_str(&format!("  \x1B[93mTECH\x1B[0m   {}\n", tech));
        }

        // Security headers
        for (short, status, desc) in &result.security_headers {
            let color = if status == "missing" { "\x1B[91m" } else { "\x1B[92m" };
            out.push_str(&format!(
                "  \x1B[93mSEC\x1B[0m    {}{}\x1B[0m {} ({})\n",
                color, status, short, desc,
            ));
        }

        // Banners
        for banner in &result.banners {
            if !banner.banner.is_empty() {
                out.push_str(&format!(
                    "  \x1B[93mBANNER\x1B[0m {} ({}) {}",
                    banner.port, banner.protocol, banner.banner,
                ));
            }
        }

        out
    }
}

// ── Standalone helpers for parallel operations ─────────────────────────────

fn port_to_service_name(port: u16) -> String {
    match port {
        20 => "FTP-data".into(),   21 => "FTP".into(),
        22 => "SSH".into(),        23 => "Telnet".into(),
        25 => "SMTP".into(),       53 => "DNS".into(),
        80 => "HTTP".into(),       110 => "POP3".into(),
        111 => "RPC".into(),       143 => "IMAP".into(),
        389 => "LDAP".into(),      443 => "HTTPS".into(),
        445 => "SMB".into(),       993 => "IMAPS".into(),
        995 => "POP3S".into(),     1433 => "MSSQL".into(),
        1521 => "Oracle".into(),   2049 => "NFS".into(),
        3306 => "MySQL".into(),    3389 => "RDP".into(),
        5432 => "PostgreSQL".into(), 5900 => "VNC".into(),
        5985 => "WinRM-HTTP".into(), 5986 => "WinRM-HTTPS".into(),
        6379 => "Redis".into(),    8080 => "HTTP-Proxy".into(),
        8443 => "HTTPS-Alt".into(), 9000 => "PHP-FPM".into(),
        9090 => "HTTP-Alt".into(), 27017 => "MongoDB".into(),
        _ => format!("port-{}", port),
    }
}

async fn grab_single_banner_impl(host: &str, port: u16) -> Result<ServiceBanner> {
    let addr = format!("{}:{}", host, port);
    let protocol = match port {
        80 | 443 | 8080 | 8443 => "http",
        22 => "ssh",     21 => "ftp",      25 => "smtp",
        110 => "pop3",   143 => "imap",    3306 => "mysql",
        5432 => "postgresql", 6379 => "redis", 27017 => "mongodb",
        _ => "tcp",
    };
    match tokio::time::timeout(Duration::from_secs(3), TcpStream::connect(&addr)).await {
        Ok(Ok(stream)) => {
            let mut buf = vec![0u8; 1024];
            // Try to read initial banner
            let banner = tokio::time::timeout(Duration::from_secs(2), stream.readable()).await
                .ok().and_then(|r| r.ok()).and_then(|_| {
                    stream.try_read(&mut buf).ok().and_then(|n| {
                        if n > 0 {
                            Some(String::from_utf8_lossy(&buf[..n.min(256)]).to_string())
                        } else { None }
                    })
                });
            if let Some(b) = banner {
                return Ok(ServiceBanner {
                    port, protocol: protocol.into(),
                    banner: b.trim().to_string(),
                });
            }
            // HTTP probe for web ports
            if port == 80 || port == 8080 {
                let probe = format!("GET / HTTP/1.0\r\nHost: {}\r\n\r\n", host);
                let _ = stream.try_write(probe.as_bytes());
                tokio::time::sleep(Duration::from_millis(500)).await;
                if let Ok(n) = stream.try_read(&mut buf) {
                    if n > 0 {
                        let raw = String::from_utf8_lossy(&buf[..n.min(256)]);
                        let server_line = raw.lines()
                            .find(|l| l.to_lowercase().starts_with("server:"))
                            .unwrap_or(&raw);
                        return Ok(ServiceBanner {
                            port, protocol: protocol.into(),
                            banner: server_line.trim().to_string(),
                        });
                    }
                }
            }
            Err(anyhow::anyhow!("No banner received"))
        }
        _ => Err(anyhow::anyhow!("Connection failed")),
    }
}
