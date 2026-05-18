use anyhow::Result;
use colored::Colorize;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;
use tokio::sync::mpsc;
use url::Url;

use crate::cli::args::CliArgs;
use crate::cli::output::Output;
use crate::cli::parser::Parser;
use crate::core::scanner::{
    Scanner, ScanResult,
};
use crate::crawls::WebCrawler;
use crate::http::client::HttpClient;
use crate::
detection::behavior::BehaviorAnalyzer;
use crate::detection::signatures::SignatureDatabase;
use crate::report::html::HtmlReport;
use crate::payload::generator::PayloadGenerator;
use crate::payload::fuzzer::Fuzzer;
use crate::detection::analyzer::{Analyzer, Finding, Severity};
use crate::detection::confirm::Confirm;
use crate::cli::spinner::Spinner;
use crate::agent::AgentPool;
use oxide::scanner::common_app_scanner::CommonAppScanner;
use oxide::scanner::common_app_scanner::Severity as CommonAppSeverity;
use oxide::scanner::cors_scanner::CorsScanner;
use oxide::scanner::cors_scanner::CorsSeverity;
use oxide::scanner::default_creds_scanner::DefaultCredsScanner;
use oxide::scanner::
default_creds_scanner::CredsSeverity;
use oxide::scanner::tls_scanner::TlsScanner;
use oxide::scanner::tls_scanner::TlsSeverity;
use oxide::scanner::sqli_scanner::SqlInjectionScanner;
use oxide::scanner::xss_scanner::XssScanner;
use oxide::scanner::lfi_scanner::LFIScanner;
use crate::utils::url::UrlUtil;
#[cfg(target_os = "linux")]
use crate::recon::{ActiveRecon, ReconResult};
use oxide::utils::time::TimeUtil;
use crate::zero_day::engine::ZeroDayEngine;

pub struct HybridScanner {
    args: CliArgs,
    client: Arc<HttpClient>,
    crawler: WebCrawler,
    scanner: Scanner,
    fuzzer: Fuzzer,
    analyzer: Analyzer,
    findings: Vec<Finding>,
    behavior_analyzer: BehaviorAnalyzer,
    signature_db: SignatureDatabase,
    zero_day_engine: ZeroDayEngine,
}

impl HybridScanner {
    pub fn new(args: CliArgs) -> Result<Self> {
        // Use TimeUtil::sleep for brief initialization delay
        TimeUtil::sleep(std::time::Duration::from_millis(50));
        
        let client = HttpClient::new(args.timeout, args.insecure)?;
        let client = Arc::new(client);

        let crawler = WebCrawler::new(
            HttpClient::new(args.timeout, args.insecure)?,
            args.crawl_depth,
            args.max_urls,
        );

        let payload_gen = PayloadGenerator::new();
        let (tx, _rx) = mpsc::channel(100);

        let scanner = Scanner::new(client.clone(), args.clone(), payload_gen.clone(), tx.clone());
        let fuzzer = Fuzzer::new();
        let analyzer = Analyzer::new();

        let behavior_analyzer = BehaviorAnalyzer::new();
        let signature_db = SignatureDatabase::new();
        let zero_day_engine = ZeroDayEngine::new();

        Ok(Self {
            args,
            client,
            crawler,
            scanner,
            fuzzer,
            analyzer,
            findings: Vec::new(),
            behavior_analyzer,
            signature_db,
            zero_day_engine,
        })
    }

    pub async fn run_hybrid_scan(&mut self) -> Result<Vec<Finding>> {
        let mut modules = self.args.get_modules();
        if self.args.insta && !modules.contains(&"insta".to_string()) {
            modules.push("insta".to_string());
        }
        if self.args.session && !modules.contains(&"session".to_string()) {
            modules.push("session".to_string());
        }
        let excluded = self.args.get_excluded();
        let verbose = self.args.verbose;

        let parsed_url = Parser::ensure_http(&self.args.url);
        if !UrlUtil::is_valid_url(&parsed_url) {
            return Err(anyhow::anyhow!("Invalid target URL"));
        }

        let _target_domain = if let Ok(url) = Url::parse(&parsed_url) {
            UrlUtil::extract_domain(&url)
        } else {
            parsed_url.clone()
        };

        let start = std::time::Instant::now();
        let mut all_findings = Vec::new();

        println!("  {} {} {}",
            tc("◆", GB_GRN_B),
            tc("Engines initialised — starting scan with", GB_FG),
            tc(&modules.join(", "), GB_YLW_B).bold());
        Output::print_line();

        // ═══════════════════════════════════════════════════════════════════
        //  PHASE 1: TARGET RECON — Fingerprint, WAF, Server Info, OS
        // ═══════════════════════════════════════════════════════════════════

        if !excluded.contains(&"fingerprint".to_string()) {
            print_phase_banner("RECON", "Target fingerprinting & WAF detection");

            // ── Active recon with pnet (Linux only, requires root) ─────
            #[cfg(target_os = "linux")]
            if self.args.active {
                let recon = ActiveRecon::new(self.client.clone(), &self.args.url);
                let recon_start = std::time::Instant::now();

                // Braille frames for animated spinner
                let frames = ["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"];

                macro_rules! recon_step {
                    ($label:expr, $work:expr) => {{
                        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
                        let s_clone = stop.clone();
                        let lbl = String::from($label);
                        let _spinner_handle = tokio::spawn(async move {
                            let mut idx = 0usize;
                            loop {
                                tokio::time::sleep(Duration::from_millis(100)).await;
                                if s_clone.load(std::sync::atomic::Ordering::Relaxed) { break; }
                                let frame = frames[idx % 10];
                                idx += 1;
                                print!("\r\x1B[2K  \x1B[91m{}\x1B[0m  \x1B[97m{}...\x1B[0m", frame, lbl);
                                let _ = std::io::Write::flush(&mut std::io::stdout());
                            }
                        });
                        let result = $work;
                        stop.store(true, std::sync::atomic::Ordering::Relaxed);
                        _spinner_handle.await.ok();
                        print!("\r\x1B[2K");
                        println!("  \x1B[92m✓\x1B[0m  \x1B[90m{}\x1B[0m", $label);
                        result
                    }};
                }

                // Combined HTTP analysis — single request for all header/body checks
                let (waf, server, tech_stack, security_headers, _cookies) = recon_step!(
                    "HTTP fingerprint (WAF + Server + Tech + Headers)",
                    async {
                        let waf = recon.detect_waf_http().await;
                        let server = recon.detect_server().await;
                        let tech_stack = recon.detect_tech_stack().await;
                        let security_headers = recon.audit_security_headers().await;
                        let cookies = recon.analyze_cookies().await;
                        (waf, server, tech_stack, security_headers, cookies)
                    }.await
                );

                let _ua_probes = recon_step!(
                    "Multi-UA probe (5 agents)",
                    recon.probe_with_all_agents(&self.args.url).await
                );

                let _error_pages = recon_step!(
                    "Error page probing (6 paths, parallel)",
                    recon.detect_error_pages().await
                );

                let open_ports = recon_step!(
                    "Port scan (10 ports, parallel)",
                    recon.tcp_connect_scan(vec![80, 443, 8080, 8443, 22, 21, 3306, 5432, 6379, 27017]).await
                );

                let banners = recon_step!(
                    "Banner grabbing (parallel)",
                    recon.grab_banners(&open_ports).await
                );

                let os = recon_step!(
                    "OS fingerprinting",
                    recon.tcp_fingerprint_os().await
                );

                let cf_bypass = recon_step!(
                    "Cloudflare bypass probe (10 spoofed headers)",
                    recon.cloudflare_bypass_probe().await
                );

                let result = ReconResult {
                    os,
                    open_ports,
                    banners,
                    waf,
                    server,
                    tech_stack,
                    security_headers,
                };

                let elapsed = recon_start.elapsed();
                let out = ActiveRecon::format_recon_output(&result);
                println!("  \x1B[38;2;255;140;0m[+]\x1B[0m\x1B[38;2;255;140;0mRECON\x1B[0m  \x1B[90m[{:02}:{:02}]\x1B[0m",
                    elapsed.as_secs() / 60, elapsed.as_secs() % 60);
                println!("{}", out);
                // Push findings from active recon
                if let Some(ref os) = result.os {
                    all_findings.push(Finding::new(
                        &self.args.url, Severity::Info,
                        &format!("OS Fingerprint: {} {} ({}%)", os.os_family, os.os_version, os.confidence),
                        "Operating system identified via TCP/IP fingerprinting",
                    ));
                }
                if let Some(ref waf) = result.waf {
                    all_findings.push(Finding::new(
                        &self.args.url, Severity::Info,
                        &format!("WAF Detected: {}", waf),
                        "A Web Application Firewall is present",
                    ));
                }
                if !result.server.is_empty() && result.server != "Unknown" {
                    all_findings.push(Finding::new(
                        &self.args.url, Severity::Low,
                        &format!("Server Fingerprint: {}", result.server),
                        "Server version header is exposed",
                    ).with_remediation("Hide server version strings in HTTP response headers"));
                }
                for port in &result.open_ports {
                    if port.state == "open" {
                        all_findings.push(Finding::new(
                            &self.args.url, Severity::Info,
                            &format!("Open Port: {} ({})", port.port, port.service),
                            &format!("Port {} is open", port.port),
                        ));
                    }
                }
                // Cloudflare bypass probe results
                if !cf_bypass.is_empty() {
                    println!("  \x1B[93mCFBYPASS\x1B[0m  Cloudflare origin bypass results:");
                    let cf_server = cf_bypass.iter().find(|(_, s, _)| !s.is_empty() && !s.contains("cloudflare"));
                    for (header, server, body) in &cf_bypass {
                        let note = if !server.is_empty() && !server.to_lowercase().contains("cloudflare") {
                            format!(" \x1B[92morigin={}\x1B[0m", server)
                        } else if body.contains("cloudflare") || body.contains("cf-ray") {
                            " \x1B[90m(blocked by CF)\x1B[0m".to_string()
                        } else {
                            String::new()
                        };
                        if !server.is_empty() || !note.is_empty() {
                            println!("    \x1B[90m{:<30}\x1B[0m \x1B[97m{:<20}\x1B[0m{}", header, server, note);
                        }
                    }
                    if let Some((header_raw, server, _)) = cf_server {
                        all_findings.push(Finding::new(
                            &self.args.url, Severity::Info,
                            &format!("Cloudflare Bypass: origin server = {}", server),
                            &format!("Bypassed via header: {}", header_raw),
                        ));
                    }
                }
            }

            // ── Passive recon / fallback for non-Linux ────────────────────
            if !cfg!(target_os = "linux") || !self.args.active {
            if let Ok(resp) = self.client.get(&self.args.url).await {
                let headers: Vec<String> = resp.headers.iter()
                    .map(|(k, v)| format!("{}: {}", k, v))
                    .collect();
                // WAF detection
                if let Some(waf) = self.behavior_analyzer.detect_waf(&headers) {
                    all_findings.push(Finding::new(
                        &self.args.url, Severity::Info,
                        &format!("WAF Detected: {}", waf),
                        "A Web Application Firewall is present",
                    ));
                    println!("  WAF    {}", waf);
                }
                // Server fingerprint
                if let Some(server) = resp.server_header() {
                    let f = Finding::new(&self.args.url, Severity::Low,
                        &format!("Server Fingerprint: {}", server),
                        "Server version header is exposed",
                    ).with_remediation("Hide server version strings in HTTP response headers");
                    all_findings.push(f);
                    println!("  SERVER {}", server);
                }
                // Framework fingerprint
                if let Some(powered) = resp.powered_by() {
                    all_findings.push(Finding::new(&self.args.url, Severity::Low,
                        &format!("Framework Fingerprint: {}", powered),
                        "X-Powered-By header reveals framework information",
                    ));
                    println!("  FRAMEWK {}", powered);
                }
                // Cookie / Set-Cookie
                for (k, v) in &resp.headers {
                    if k.eq_ignore_ascii_case("set-cookie") {
                        let cookie_val = v.split(';').next().unwrap_or(v);
                        println!("  COOKIE  {}", cookie_val);
                    }
                }
                // DB fingerprint
                if !resp.body.is_empty() {
                    let db_patterns = [
                        ("MySQL", "mysql|MariaDB|SQL_MODE"),
                        ("PostgreSQL", "PostgreSQL|psql|PG::"),
                        ("MSSQL", "SQLServer|Microsoft SQL|MSSQL"),
                        ("Oracle", "Oracle|ORA-|PLS-"),
                        ("SQLite", "SQLite|sqlite_"),
                    ];
                    for (name, pattern) in &db_patterns {
                        if let Ok(re) = regex::Regex::new(pattern) {
                            if re.is_match(&resp.body) {
                                all_findings.push(Finding::new(&self.args.url, Severity::Info,
                                    &format!("Database Fingerprint: {}", name),
                                    &format!("Database '{}' detected", name),
                                ));
                                println!("  DATABASE {}", name);
                                break;
                            }
                        }
                    }
                }
            }
            }
        }

        // ═══════════════════════════════════════════════════════════════════
        //  PHASE 2: CRAWL — Discover URLs, forms, links, JS endpoints
        // ═══════════════════════════════════════════════════════════════════

        let mut crawled_urls: Vec<String> = Vec::new();
        if !excluded.contains(&"crawl".to_string()) {
            print_phase_banner("CRAWL", "Mapping site structure: URLs, forms, scripts, comments");
            crawled_urls = match self.crawl_phase().await {
                Ok(urls) => urls,
                Err(e) => {
                    println!("  \x1B[91m✘\x1B[0m CRAWL ERROR  {}", e);
                    vec![]
                }
            };
            let base_url = Parser::ensure_http(&self.args.url);
            if !crawled_urls.contains(&base_url) {
                crawled_urls.insert(0, base_url);
            }
            println!("  \x1B[38;2;255;140;0m[+]\x1B[0m {} URLs discovered for scanning", crawled_urls.len());
            if verbose {
                for u in &crawled_urls {
                    println!("  \x1B[90m   {}\x1B[0m", u);
                }
            }
        } else {
            crawled_urls.push(Parser::ensure_http(&self.args.url));
        }

        // Auto-downloader — active when --download flag is set
        let _downloader = if self.args.download {
            use crate::utils::downloader::Downloader;
            let dl = Downloader::new(&self.args.url);
            println!(
                "  DOWNLOAD  Auto-download enabled → \x1B[90m{}\x1B[0m",
                dl.base_dir().display()
            );
            Some(dl)
        } else {
            None
        };

        // Initialize zero-day detection only if --zeroday flag is set
        if self.args.zeroday {
            // Load saved baselines from previous scans
            if std::path::Path::new("./zero_day_data").exists() {
                println!("  LOAD     Loading saved zero-day baselines...");
                if let Err(e) = self.load_zero_day_baselines("./zero_day_data").await {
                    println!("    Note: Could not load baselines: {}", e);
                }
            }
        }

        let new_sig = crate::detection::signatures::VulnSignature {
            id: "OXIDE-TEST".to_string(),
            name: "Custom Test Sig".to_string(),
            severity: "Info".to_string(),
            pattern: r"test".to_string(),
            description: "Test signature".to_string(),
            remediation: "None".to_string(),
        };
        self.signature_db.add(new_sig);

        // ═══════════════════════════════════════════════════════════════════
        //  PHASE 3: FUZZING — Fuzz all discovered URLs with payloads
        // ═══════════════════════════════════════════════════════════════════

        if modules.contains(&"all".to_string()) || modules.contains(&"fuzz".to_string()) {
            if !excluded.contains(&"fuzz".to_string()) {
                let ph_stop = Arc::new(AtomicBool::new(false));
                let ph_lines = Arc::new(AtomicUsize::new(1));
                if !self.args.verbose {
                    const CW: &[&str] = &["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"];
                    const CCW: &[&str] = &["⠏","⠇","⠧","⠦","⠴","⠼","⠸","⠹","⠙","⠋"];
                    let cw = CW[0];
                    let ccw = CCW[0];
                    println!("  \x1B[38;2;255;140;0m[+]\x1B[0m{}{}FUZZ  \x1B[90mSQLi / SQLi-D / XSS / LFI / CMDi\x1B[0m", cw, ccw);
                    let s = ph_stop.clone();
                    let lb = ph_lines.clone();
                    tokio::spawn(async move {
                        let mut idx = 1usize;
                        loop {
                            tokio::time::sleep(Duration::from_millis(120)).await;
                            if s.load(Ordering::Relaxed) { break; }
                            let n = lb.load(Ordering::Relaxed);
                            let cw = CW[idx % 10];
                            let ccw = CCW[idx % 10];
                            idx += 1;
                            print!("\x1B[{}A\r\x1B[2K  \x1B[38;2;255;140;0m[+]\x1B[0m{}{}FUZZ  \x1B[90mSQLi / SQLi-D / XSS / LFI / CMDi\x1B[0m\n", n, cw, ccw);
                            if n > 1 { print!("\x1B[{}B", n - 1); }
                            let _ = std::io::Write::flush(&mut std::io::stdout());
                        }
                    });
                } else {
                    print_phase_banner("FUZZ", "SQLi / SQLi-D / XSS / LFI / CMDi payload injection");
                }
                let mut total = 0;
                for url in &crawled_urls {
                    if !self.args.verbose {
                        println!("  \x1B[90m->\x1B[0m {}", url);
                        ph_lines.fetch_add(1, Ordering::Relaxed);
                    }
                    if let Ok(fuzz_findings) = self.fuzz_url(url).await {
                        let count = fuzz_findings.len();
                        let prev_len = all_findings.len();
                        all_findings.extend(fuzz_findings);
                        if count > 0 {
                            for _f in &all_findings[prev_len..] {
                                ph_lines.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                    }
                    total += 1;
                }
                ph_stop.store(true, Ordering::Relaxed);
                let n = ph_lines.load(Ordering::Relaxed);
                if !self.args.verbose && n > 0 {
                    print!("\x1B[{}A\r\x1B[2K", n);
                }
                println!("  \x1B[38;2;255;140;0m[+]\x1B[0m Fuzzing complete: {} URLs", total);
            }
        }

        // ═══════════════════════════════════════════════════════════════════
        //  PHASE 4: VULNERABILITY SCANNING — SQLi, XSS, LFI, CMDi
        // ═══════════════════════════════════════════════════════════════════

        // SQL Injection Scan
        if modules.contains(&"all".to_string()) || modules.contains(&"sqli".to_string()) {
            if !excluded.contains(&"sqli".to_string()) {
                let ph_stop = Arc::new(AtomicBool::new(false));
                let ph_lines = Arc::new(AtomicUsize::new(1));
                if !self.args.verbose {
                    let frame = oxide::scanner::precision::bidir_braille(0);
                    println!("  \x1B[38;2;255;140;0m[+]\x1B[0m\x1B[93m{}\x1B[0m\x1B[38;2;255;140;0m{}\x1B[0m  \x1B[97mTesting SQL injection on all URLs\x1B[0m", frame, "SQLi");
                    let s = ph_stop.clone();
                    let lb = ph_lines.clone();
                    tokio::spawn(async move {
                        let mut idx = 1usize;
                        loop {
                            tokio::time::sleep(Duration::from_millis(120)).await;
                            if s.load(Ordering::Relaxed) { break; }
                            let n = lb.load(Ordering::Relaxed);
                            let frame = oxide::scanner::precision::bidir_braille(idx);
                            idx += 1;
                            print!("\x1B[{}A\r\x1B[2K  \x1B[38;2;255;140;0m[+]\x1B[0m\x1B[93m{}\x1B[0m\x1B[38;2;255;140;0m{}\x1B[0m  \x1B[97mTesting SQL injection on all URLs\x1B[0m\n", n, frame, "SQLi");
                            if n > 1 { print!("\x1B[{}B", n - 1); }
                            let _ = std::io::Write::flush(&mut std::io::stdout());
                        }
                    });
                } else {
                    print_phase_sub("SQLi", "Testing SQL injection on all URLs");
                }
                let mut sqli_scanner = SqlInjectionScanner::new(
                    self.args.url.clone(), self.args.timeout, self.args.insecure
                )?;
                for url in crawled_urls.iter().take(self.args.payload_limit) {
                    if !self.args.verbose {
                        println!("  \x1B[90m->\x1B[0m {}", url);
                        ph_lines.fetch_add(1, Ordering::Relaxed);
                    }
                    let params = self.extract_params_from_url(url);
                    if let Ok(findings) = sqli_scanner.comprehensive_scan(url, &params).await {
                        for finding in findings {
                            let f = self.convert_finding(&finding);
                            if !self.args.verbose {
                                println!("  {} {}  \x1B[90m{}\x1B[0m", fmt_sev_label(&f.severity), f.title, url);
                                ph_lines.fetch_add(1, Ordering::Relaxed);
                            } else {
                                println!("  SQLi  {}  \x1B[90m{}\x1B[0m", f.title, url);
                            }
                            all_findings.push(f);
                        }
                    }
                }
                ph_stop.store(true, Ordering::Relaxed);
                let n = ph_lines.load(Ordering::Relaxed);
                if !self.args.verbose && n > 0 {
                    print!("\x1B[{}A\r\x1B[2K", n);
                }
                println!("  \x1B[38;2;255;140;0m[+]\x1B[0m SQLi scan complete");
            }
        }

        // XSS Scan
        if modules.contains(&"all".to_string()) || modules.contains(&"xss".to_string()) {
            if !excluded.contains(&"xss".to_string()) {
                let ph_stop = Arc::new(AtomicBool::new(false));
                let ph_lines = Arc::new(AtomicUsize::new(1));
                if !self.args.verbose {
                    let frame = oxide::scanner::precision::bidir_braille(0);
                    println!("  \x1B[38;2;255;140;0m[+]\x1B[0m\x1B[93m{}\x1B[0m\x1B[38;2;255;140;0mXSS\x1B[0m  \x1B[97mTesting cross-site scripting on all URLs\x1B[0m", frame);
                    let s = ph_stop.clone();
                    let lb = ph_lines.clone();
                    tokio::spawn(async move {
                        let mut idx = 1usize;
                        loop {
                            tokio::time::sleep(Duration::from_millis(120)).await;
                            if s.load(Ordering::Relaxed) { break; }
                            let n = lb.load(Ordering::Relaxed);
                            let frame = oxide::scanner::precision::bidir_braille(idx);
                            idx += 1;
                            print!("\x1B[{}A\r\x1B[2K  \x1B[38;2;255;140;0m[+]\x1B[0m\x1B[93m{}\x1B[0m\x1B[38;2;255;140;0mXSS\x1B[0m  \x1B[97mTesting cross-site scripting on all URLs\x1B[0m\n", n, frame);
                            if n > 1 { print!("\x1B[{}B", n - 1); }
                            let _ = std::io::Write::flush(&mut std::io::stdout());
                        }
                    });
                } else {
                    print_phase_sub("XSS", "Testing cross-site scripting on all URLs");
                }
                let mut xss_scanner = XssScanner::new(
                    self.args.url.clone(), self.args.timeout, self.args.insecure
                )?;
                for url in crawled_urls.iter().take(self.args.payload_limit) {
                    if !self.args.verbose {
                        println!("  \x1B[90m->\x1B[0m {}", url);
                        ph_lines.fetch_add(1, Ordering::Relaxed);
                    }
                    let params = self.extract_params_from_url(url);
                    if let Ok(findings) = xss_scanner.comprehensive_scan(url, &params).await {
                        for finding in findings {
                            let f = self.convert_finding(&finding);
                            if verbose {
                                println!("  XSS   {}  \x1B[90m{}\x1B[0m", f.title, url);
                            }
                            all_findings.push(f);
                        }
                    }
                }
                ph_stop.store(true, Ordering::Relaxed);
                let n = ph_lines.load(Ordering::Relaxed);
                if !self.args.verbose && n > 0 {
                    print!("\x1B[{}A\r\x1B[2K", n);
                }
                println!("  \x1B[38;2;255;140;0m[+]\x1B[0m XSS scan complete");
            }
        }

        // LFI Scan
        if modules.contains(&"all".to_string()) || modules.contains(&"lfi".to_string()) {
            if !excluded.contains(&"lfi".to_string()) {
                let ph_stop = Arc::new(AtomicBool::new(false));
                let ph_lines = Arc::new(AtomicUsize::new(1));
                if !self.args.verbose {
                    let frame = oxide::scanner::precision::bidir_braille(0);
                    println!("  \x1B[38;2;255;140;0m[+]\x1B[0m\x1B[93m{}\x1B[0m\x1B[38;2;255;140;0mLFI\x1B[0m  \x1B[97mTesting local file inclusion on all URLs\x1B[0m", frame);
                    let s = ph_stop.clone();
                    let lb = ph_lines.clone();
                    tokio::spawn(async move {
                        let mut idx = 1usize;
                        loop {
                            tokio::time::sleep(Duration::from_millis(120)).await;
                            if s.load(Ordering::Relaxed) { break; }
                            let n = lb.load(Ordering::Relaxed);
                            let frame = oxide::scanner::precision::bidir_braille(idx);
                            idx += 1;
                            print!("\x1B[{}A\r\x1B[2K  \x1B[38;2;255;140;0m[+]\x1B[0m\x1B[93m{}\x1B[0m\x1B[38;2;255;140;0mLFI\x1B[0m  \x1B[97mTesting local file inclusion on all URLs\x1B[0m\n", n, frame);
                            if n > 1 { print!("\x1B[{}B", n - 1); }
                            let _ = std::io::Write::flush(&mut std::io::stdout());
                        }
                    });
                } else {
                    print_phase_sub("LFI", "Testing local file inclusion on all URLs");
                }
                let mut lfi_scanner = LFIScanner::new(
                    self.args.exploitation_level, self.args.timeout, self.args.insecure
                )?;
                for url in crawled_urls.iter().take(self.args.payload_limit) {
                    if !self.args.verbose {
                        println!("  \x1B[90m->\x1B[0m {}", url);
                        ph_lines.fetch_add(1, Ordering::Relaxed);
                    }
                    for param in self.extract_params_from_url(url) {
                        if let Ok(results) = lfi_scanner.exploit_lfi(url, &param).await {
                            for result in results {
                                if result.success {
                                    let sev = if result.file_read { Severity::Critical } else { Severity::High };
                                    let f = Finding::new(url, sev,
                                        &format!("LFI: {}", result.technique),
                                        &format!("Payload: {}\nFile Read: {}", result.payload, result.file_read),
                                    ).with_evidence(&result.response);
                                    if verbose {
                                        println!("  LFI   {} via param `{}`  \x1B[90m{}\x1B[0m", result.technique, param, url);
                                    }
                                    all_findings.push(f);
                                }
                            }
                        }
                    }
                }
                ph_stop.store(true, Ordering::Relaxed);
                let n = ph_lines.load(Ordering::Relaxed);
                if !self.args.verbose && n > 0 {
                    print!("\x1B[{}A\r\x1B[2K", n);
                }
                println!("  \x1B[38;2;255;140;0m[+]\x1B[0m LFI scan complete");
            }
        }

        // ═══════════════════════════════════════════════════════════════════
        //  PHASE 5: TLS/SSL ASSESSMENT
        // ═══════════════════════════════════════════════════════════════════

        if modules.contains(&"all".to_string()) || modules.contains(&"tls".to_string()) {
            if !excluded.contains(&"tls".to_string()) {
                print_phase_banner("TLS", "TLS/SSL security assessment");
                let tls_scanner = TlsScanner::new(self.args.timeout)?;
                let tls_findings = tls_scanner.scan(&self.args.url).await;
                for finding in tls_findings {
                    let sev = match finding.severity {
                        TlsSeverity::Critical => Severity::Critical,
                        TlsSeverity::High     => Severity::High,
                        TlsSeverity::Medium   => Severity::Medium,
                        TlsSeverity::Low      => Severity::Low,
                        TlsSeverity::Info     => Severity::Info,
                    };
                    println!("  {} {} \x1B[90m| {}\x1B[0m",
                        fmt_sev_label(&sev), finding.title, finding.evidence);
                    all_findings.push(Finding::new(&self.args.url, sev, &finding.title, &finding.description)
                        .with_evidence(&finding.evidence).with_remediation(&finding.remediation));
                }
                println!("  \x1B[38;2;255;140;0m[+]\x1B[0m TLS assessment complete");
            }
        }

        // ═══════════════════════════════════════════════════════════════════
        //  PHASE 6: CORS MISCONFIGURATION SCAN
        // ═══════════════════════════════════════════════════════════════════

        if modules.contains(&"all".to_string()) || modules.contains(&"cors".to_string()) {
            if !excluded.contains(&"cors".to_string()) {
                print_phase_banner("CORS", "Cross-Origin Resource Sharing assessment");
                let cors_scanner = CorsScanner::new(self.args.timeout)?;
                let cors_findings = cors_scanner.scan(&self.args.url).await;
                for finding in cors_findings {
                    let sev = match finding.severity {
                        CorsSeverity::Critical => Severity::Critical,
                        CorsSeverity::High     => Severity::High,
                        CorsSeverity::Medium   => Severity::Medium,
                        CorsSeverity::Low      => Severity::Low,
                    };
                    println!("  {} {} \x1B[90m| {}\x1B[0m",
                        fmt_sev_label(&sev), finding.title, finding.evidence);
                    all_findings.push(Finding::new(&self.args.url, sev, &finding.title, &finding.description)
                        .with_evidence(&finding.evidence).with_remediation(&finding.remediation));
                }
                println!("  \x1B[38;2;255;140;0m[+]\x1B[0m CORS assessment complete");
            }
        }

        // ═══════════════════════════════════════════════════════════════════
        //  PHASE 7: COMMON PATHS + DEFAULT CREDS + CONTENT FILTER
        // ═══════════════════════════════════════════════════════════════════

        // Common application paths (Nikto-style)
        if modules.contains(&"all".to_string()) || modules.contains(&"common".to_string()) {
            if !excluded.contains(&"common".to_string()) {
                print_phase_sub("COMMON", "Probing common application paths");
                if let Ok(common_scanner) = CommonAppScanner::new(self.args.timeout) {
                    let common_findings = common_scanner.scan(&self.args.url, self.args.download).await;
                    for finding in common_findings {
                        let sev = match finding.severity {
                            CommonAppSeverity::Critical => Severity::Critical,
                            CommonAppSeverity::High     => Severity::High,
                            CommonAppSeverity::Medium   => Severity::Medium,
                            CommonAppSeverity::Low      => Severity::Low,
                            CommonAppSeverity::Info     => Severity::Info,
                        };
                        if verbose {
                            println!("  {} {} \x1B[90m{}\x1B[0m", fmt_sev_label(&sev), finding.title, finding.url);
                        }
                        all_findings.push(Finding::new(&finding.url, sev, &finding.title, &finding.description)
                            .with_evidence(&finding.evidence));
                    }
                }
                println!("  \x1B[38;2;255;140;0m[+]\x1B[0m Common app scan complete");
            }
        }

        // Default credentials test
        if modules.contains(&"all".to_string()) || modules.contains(&"creds".to_string()) {
            if !excluded.contains(&"creds".to_string()) {
                print_phase_sub("CREDS", "Testing default credentials");
                if let Ok(creds_scanner) = DefaultCredsScanner::new(self.args.timeout) {
                    let creds_findings = creds_scanner.scan(&self.args.url).await;
                    for finding in creds_findings {
                        let sev = match finding.severity {
                            CredsSeverity::Critical => Severity::Critical,
                            CredsSeverity::High     => Severity::High,
                            CredsSeverity::Medium   => Severity::Medium,
                        };
                        if verbose {
                            println!("  {} {} \x1B[90m{}:{}@{}\x1B[0m",
                                fmt_sev_label(&sev), finding.application, finding.username, finding.password, finding.url);
                        }
                        all_findings.push(Finding::new(&finding.url, sev,
                            &format!("Default Credentials: {}", finding.application),
                            &format!("App: {}\nUser: {}\nPass: {}", finding.application, finding.username, finding.password),
                        ).with_evidence(&finding.evidence).with_remediation(&finding.remediation));
                    }
                }
                println!("  \x1B[38;2;255;140;0m[+]\x1B[0m Credential scan complete");
            }
        }

        // Parameter Discovery
        if modules.contains(&"all".to_string()) || modules.contains(&"parameter-discovery".to_string()) {
            if !excluded.contains(&"parameter-discovery".to_string()) {
                let unique_params = self.extract_params_from_urls(&crawled_urls);
                println!("  PARAMS  {} unique parameters across {} URLs", unique_params.len(), crawled_urls.len());
                for param in &unique_params {
                    all_findings.push(Finding::new(&self.args.url, Severity::Info,
                        &format!("Parameter: {}", param),
                        &format!("Discovered parameter '{}'", param),
                    ));
                }
            }
        }

        // ═══════════════════════════════════════════════════════════════════
        //  PHASE 8: CONTENT FILTER + ML ANOMALY DETECTION
        // ═══════════════════════════════════════════════════════════════════

        // Hybrid Content Filter - dynamic sensitive data detection
        if modules.contains(&"all".to_string()) || modules.contains(&"filter".to_string()) {
            if !excluded.contains(&"filter".to_string()) {
                print_phase_sub("FILTER", "Dynamic content analysis for sensitive data");
                let mut filter_hits = 0;
                for url in &crawled_urls {
                    if let Ok(resp) = self.client.get(url).await {
                        // Pattern-based detection for sensitive data
                        let patterns: Vec<(&str, &str)> = vec![
                            (r"(?i)-----BEGIN.*KEY-----", "Private Key"),
                            (r#"(?i)api[_-]?key["']?\s*[:=]\s*["'][^"']+["']"#, "API Key"),
                            (r"(?i)sk_live_[0-9a-zA-Z]+", "Stripe Live Key"),
                            (r"(?i)AKIA[0-9A-Z]{16}", "AWS Access Key"),
                            (r#"(?i)password\s*[:=]\s*[^\s,;"']{6,}"#, "Exposed Password"),
                            (r#"(?i)token\s*[:=]\s*["'][^"']{16,}["']"#, "Exposed Token"),
                        ];
                        if verbose {
                            println!("  \x1B[90mScanning {} for secrets...\x1B[0m", url);
                        }
                        for (pattern, label) in &patterns {
                            if let Ok(re) = regex::Regex::new(pattern) {
                                if re.is_match(&resp.body) {
                                    all_findings.push(Finding::new(url, Severity::High,
                                        &format!("Sensitive Data: {}", label),
                                        &format!("Pattern '{}' matched in response", label),
                                    ).with_evidence(&format!("Matched on {}", url)));
                                    filter_hits += 1;
                                }
                            }
                        }
                    }
                }
                println!("  \x1B[38;2;255;140;0m[+]\x1B[0m Filter complete: {} hits", filter_hits);
            }
        }

        // Instagram OSINT
        if modules.contains(&"all".to_string()) || modules.contains(&"insta".to_string()) {
            if !excluded.contains(&"insta".to_string()) {
                print_phase_banner("INSTA", "Instagram OSINT — follower count, privacy check, media download");
                match oxide::insta::InstaOSINT::new(self.args.timeout) {
                    Ok(insta) => {
                        match insta.full_scan(&self.args.url).await {
                            Ok(insta_findings) => {
                                for f in &insta_findings {
                                    println!("  {} {} \x1B[90m| {}\x1B[0m",
                                        fmt_sev_label(&f.severity), f.title, f.evidence);
                                }
                                all_findings.extend(insta_findings);
                            }
                            Err(e) => println!("  \x1B[91m[!]\x1B[0m Instagram scan failed: {}", e),
                        }
                    }
                    Err(e) => println!("  \x1B[91m[!]\x1B[0m Failed to initialize Instagram scanner: {}", e),
                }
                println!("  \x1B[38;2;255;140;0m[+]\x1B[0m Instagram OSINT complete");
            }
        }

        // Session Hijack Testing
        if modules.contains(&"all".to_string()) || modules.contains(&"session".to_string()) {
            if !excluded.contains(&"session".to_string()) {
                print_phase_banner("SESSION", "Session hijack testing — cookie flags, fixation, predictability");
                match oxide::session_hijack::SessionHijackTester::new(self.args.timeout, self.args.insecure) {
                    Ok(tester) => {
                        match tester.full_test(&self.args.url).await {
                            Ok(session_findings) => {
                                for f in &session_findings {
                                    println!("  {} {} \x1B[90m| {}\x1B[0m",
                                        fmt_sev_label(&f.severity), f.title, f.evidence);
                                }
                                all_findings.extend(session_findings);
                            }
                            Err(e) => println!("  \x1B[91m[!]\x1B[0m Session test failed: {}", e),
                        }
                    }
                    Err(e) => println!("  \x1B[91m[!]\x1B[0m Failed to initialize session tester: {}", e),
                }
                println!("  \x1B[38;2;255;140;0m[+]\x1B[0m Session hijack assessment complete");
            }
        }

        // ML-Based Zero-Day Detection
        if modules.contains(&"all".to_string()) || modules.contains(&"zero-day".to_string()) || self.args.zeroday {
            if !excluded.contains(&"zero-day".to_string()) {
                print_phase_sub("ML", "Zero-day anomaly detection");
                let ml_findings = self.run_ml_detection(&crawled_urls).await?;
                let ml_count = ml_findings.len();
                all_findings.extend(ml_findings);
                println!("  \x1B[38;2;255;140;0m[+]\x1B[0m ML detection complete: {} anomalies", ml_count);
            }
        }

        // Static path scanning
        if modules.contains(&"all".to_string()) || modules.contains(&"static".to_string()) {
            if !excluded.contains(&"static".to_string()) {
                let static_findings = self.scan_static_paths().await?;
                all_findings.extend(static_findings);
            }
        }

        // Agent-based parallel scan
        if modules.contains(&"all".to_string()) || modules.contains(&"agent".to_string()) {
            if !excluded.contains(&"agent".to_string()) {
                print_phase_sub("AGENT", "Agent-based parallel vulnerability scan");
                let agent_findings = self.scan_with_agents(crawled_urls.clone()).await?;
                all_findings.extend(agent_findings);
                println!("  \x1B[38;2;255;140;0m[+]\x1B[0m Agent scan complete");
            }
        }

        // Parallel vulnerability scan (ScanBoard)
        {
            use crate::core::worker::ParallelScanner;
            use crate::cli::display::ScanBoard;

            let worker_count = self.args.threads.min(8).max(1);
            let board = ScanBoard::new(worker_count);
            println!("\n  PARALLEL  Phase 5 — {} workers, {} URLs", worker_count, crawled_urls.len());
            let scanner = ParallelScanner::new(self.client.clone(), self.args.clone(), worker_count);
            let phase_findings = scanner.run(crawled_urls.clone(), board).await;
            all_findings.extend(phase_findings);
        }

        // Body scanning
        if !excluded.contains(&"body".to_string()) {
            let body_payloads = self.fuzzer.generate_sql_payloads();
            let _ = self.scanner.scan_body(&body_payloads).await;
        }

        // Filter false positives — AFTER all findings collected
        let confirmed_findings = Confirm::reduce_false_positive(all_findings);
        println!("Confirmed findings after filtering: {} (the real treasures!)", confirmed_findings.len());

        // Format final duration
        let final_elapsed = TimeUtil::elapsed_since(start);
        let final_duration = TimeUtil::format_duration(final_elapsed);
        
        // Funny completion messages
        let completion_quips = vec![
            "Scan time: {}. Time well spent!",
            "Scan time: {}. That was faster than compiling Rust!",
            "Scan time: {}. Your security team owes you a beer!",
        ];
        let quip_idx = (TimeUtil::unix_timestamp() as usize) % completion_quips.len();
        println!("  DONE    {}", completion_quips[quip_idx].replace("{}", &final_duration));

        self.findings = confirmed_findings.clone();

        // Generate HTML report if output specified
        if self.args.output.is_some() {
            let html_output = HtmlReport::generate_header("OXIDE Scan Report");
            let html_table_start = HtmlReport::generate_table_start();
            let html_table_end = HtmlReport::generate_table_end();
            let html_footer = HtmlReport::generate_footer();
            let full_html = format!("{}{}{}{}", html_output, html_table_start, html_table_end, html_footer);
            println!("HTML report generated: {} bytes", full_html.len());
        }

        Ok(confirmed_findings)
    }

    async fn crawl_phase(&mut self) -> Result<Vec<String>> {
        let result = self.crawler.crawl(&self.args.url).await?;

        // Scan HTML comments for leaked credentials / internal paths
        let suspicious = result.suspicious_comments();
        if !suspicious.is_empty() {
            println!("  ! {} suspicious HTML comments found:", suspicious.len());
            for (comment, reason) in suspicious.iter().take(5) {
                let preview: String = comment.chars().take(80).collect();
                println!("      [{}] {}", reason, preview);
            }
        }

        // Extract API endpoints from inline scripts
        let script_eps = result.script_endpoints();
        if !script_eps.is_empty() {
            println!("  JS    {} API endpoints found in scripts", script_eps.len());
        }

        let post_forms = result.get_forms_by_method("POST");
        if !post_forms.is_empty() {
            println!("  Found {} POST forms", post_forms.len());
            for form in &post_forms {
                println!("    Form at {} -> {}", form.url, form.action);
                for input in &form.inputs {
                    println!("      Input: {} (type: {})", input.name, input.input_type);
                }
            }
        }

        // Use links with text
        let links_with_text = self.crawler.get_links_with_text();
        if !links_with_text.is_empty() {
            println!("  Found {} links with text", links_with_text.len());
        }

        // Use get_all_link_texts from result
        let all_texts = result.get_all_link_texts();
        if !all_texts.is_empty() {
            println!("  Link texts count: {}", all_texts.len());
        }

        let mut urls: Vec<String> = result.urls.iter()
            .chain(result.all_linked_urls.iter())
            .cloned()
            .collect();

        let forms = self.crawler.get_forms();

        let get_forms = self.crawler.get_forms_by_method("GET");
        if !get_forms.is_empty() {
            println!("  Found {} GET forms", get_forms.len());
        }

        for form in forms {
            urls.push(form.url.clone());
            urls.push(form.action.clone());
            for input in &form.inputs {
                let value_str = match &input.value {
                    Some(v) => format!("={}", v),
                    None => "".to_string(),
                };
                println!("    Form input: {} (type: {}){}", input.name, input.input_type, value_str);
            }
        }

        urls.sort();
        urls.dedup();

        let script_eps = result.script_endpoints();
        for ep in script_eps {
            if ep.starts_with('/') {
                if let Ok(base) = url::Url::parse(&self.args.url) {
                    if let Ok(full) = base.join(&ep) {
                        urls.push(full.to_string());
                    }
                }
            }
        }
        urls.sort();
        urls.dedup();

        Ok(urls)
    }

    fn is_waf_response(body: &str, status: u16) -> bool {
        let b = body.to_lowercase();
        (status == 403 || status == 503 || status == 429) &&
        (b.contains("cf-ray") || b.contains("cloudflare") || b.contains("waf") ||
         b.contains("blocked") || b.contains("challenge") || b.contains("attention required") ||
         b.contains("security check") || b.contains("ddos") || b.contains("protection"))
    }

    fn contains_xss(body: &str, payload: &str) -> bool {
        if Self::is_waf_response(body, 200) { return false; }
        let body_lower = body.to_lowercase();
        body.contains(payload) ||
        body_lower.contains("<script>") ||
        body_lower.contains("alert(") ||
        body_lower.contains("onerror=") ||
        body_lower.contains("onload=")
    }

    fn contains_lfi(body: &str) -> bool {
        if Self::is_waf_response(body, 200) { return false; }
        let b = body.to_lowercase();
        b.contains("root:x:0:0") || b.contains("root:$1$") ||
        b.contains("daemon:x:") || b.contains("bin:x:")
    }

    fn contains_cmdi(body: &str) -> bool {
        if Self::is_waf_response(body, 200) { return false; }
        let b = body.to_lowercase();
        b.contains("uid=") || b.contains("gid=") ||
        b.contains("groups=") || b.contains("bin/bash") || b.contains("bin/sh")
    }

    fn contains_ssti(body: &str, payload: &str) -> bool {
        if Self::is_waf_response(body, 200) { return false; }
        let b = body.to_lowercase();
        b.contains("freemarker") || b.contains("velocity") ||
        b.contains("smarty") || b.contains("template") ||
        (b.contains("undefined") && b.contains("7*7")) ||
        b.contains(payload) || (payload.contains("7*7") && b.contains("49"))
    }

    async fn fuzz_url(&self, url: &str) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        let params = self.extract_params_from_url(url);
        let sql_payloads = self.fuzzer.generate_sql_payloads();
        let xss_payloads = self.fuzzer.generate_xss_payloads();
        let lfi_payloads = self.fuzzer.generate_lfi_payloads();
        let cmd_payloads = self.fuzzer.generate_cmd_injection_payloads("127.0.0.1", 4444);
        let destructive_payloads = self.fuzzer.generate_destructive_sql_payloads();
        let nosql_payloads = self.fuzzer.generate_nosql_payloads();
        let ssti_payloads = self.fuzzer.generate_ssti_payloads();

        // Test types to show per-request
        let test_types = [
            ("SQLi",   &sql_payloads, 8),
            ("SQLi-D", &destructive_payloads, 4),
            ("XSS",    &xss_payloads, 8),
            ("LFI",    &lfi_payloads, 6),
            ("CMDi",   &cmd_payloads, 4),
            ("NoSQL",  &nosql_payloads, 6),
            ("SSTI",   &ssti_payloads, 6),
        ];

        for param in &params {
            for &(label, payloads, count) in &test_types {
                for payload in payloads.iter().take(count) {
                    let fuzz_url = UrlUtil::inject_param(url, param, &urlencoding::encode(payload));

                    match self.client.get(&fuzz_url).await {
                        Ok(response) => {
                            let status = response.status;
                            let size = response.body.len();
                            let size_str = if size >= 1_048_576 {
                                format!("{:.1}MB", size as f64 / 1_048_576.0)
                            } else if size >= 1_024 {
                                format!("{:.1}KB", size as f64 / 1_024.0)
                            } else {
                                format!("{}B", size)
                            };

                            if !self.args.verbose {
                                let disp_url = if fuzz_url.len() > 70 {
                                    format!("…{}", &fuzz_url[fuzz_url.len().saturating_sub(69)..])
                                } else {
                                    fuzz_url.clone()
                                };
                                print!("\r\x1B[2K  {} {} {}  \x1B[90m{}\x1B[0m",
                                    fmt_status(status), size_str, label, disp_url);
                                let _ = std::io::Write::flush(&mut std::io::stdout());
                            } else {
                                println!("  {} {} {}  \x1B[90m{}\x1B[0m",
                                    fmt_status(status), size_str, label, fuzz_url);
                            }

                            match label {
                                "SQLi" => {
                                    let scan_result = ScanResult {
                                        url: fuzz_url.clone(),
                                        status,
                                        response: Some(response),
                                        payload: payload.clone(),
                                    };
                                    if let Some(finding) = self.analyzer.analyze(scan_result).await {
                                        let f = Finding::new(&fuzz_url, finding.severity,
                                            &format!("SQLi via {}", param),
                                            &finding.title,
                                        ).with_evidence(&finding.evidence)
                                        .with_remediation(&finding.remediation);
                                        println!("  {} {}  \x1B[90m{}\x1B[0m  [\x1B[93msqli\x1B[0m]",
                                            fmt_sev_label(&f.severity), f.title, fuzz_url);
                                        findings.push(f);
                                    }
                                }
                                "SQLi-D" => {
                                    let scan_result = ScanResult {
                                        url: fuzz_url.clone(),
                                        status,
                                        response: Some(response),
                                        payload: payload.clone(),
                                    };
                                    if let Some(finding) = self.analyzer.analyze(scan_result).await {
                                        let f = Finding::new(&fuzz_url, finding.severity,
                                            &format!("SQLi-D via {}", param),
                                            &finding.title,
                                        ).with_evidence(&finding.evidence)
                                        .with_remediation(&finding.remediation);
                                        println!("  {} {}  \x1B[90m{}\x1B[0m  [\x1B[91msqli-d\x1B[0m]",
                                            fmt_sev_label(&f.severity), f.title, fuzz_url);
                                        findings.push(f);
                                    }
                                }
                                "XSS" => {
                                    if Self::contains_xss(&response.body, payload) {
                                        let f = Finding::new(&fuzz_url, Severity::High,
                                            &format!("XSS in {}", param),
                                            &format!("Payload reflected in param `{}`", param),
                                        ).with_evidence(&format!("HTTP {}", status))
                                        .with_remediation("Use contextual output encoding and CSP");
                                        println!("  {} {}  \x1B[90m{}\x1B[0m  [\x1B[93mxss\x1B[0m]",
                                            fmt_sev_label(&Severity::High), f.title, fuzz_url);
                                        findings.push(f);
                                    }
                                }
                                "LFI" => {
                                    if Self::contains_lfi(&response.body) {
                                        let f = Finding::new(&fuzz_url, Severity::Critical,
                                            &format!("LFI in {}", param),
                                            &format!("LFI via param `{}`: /etc/passwd", param),
                                        ).with_evidence(&format!("HTTP {}", status))
                                        .with_remediation("Validate and sanitize file path inputs");
                                        println!("  {} {}  \x1B[90m{}\x1B[0m  [\x1B[93mlfi\x1B[0m]",
                                            fmt_sev_label(&Severity::Critical), f.title, fuzz_url);
                                        findings.push(f);
                                    }
                                }
                                "CMDi" => {
                                    if Self::contains_cmdi(&response.body) {
                                        let f = Finding::new(&fuzz_url, Severity::Critical,
                                            &format!("CMDi in {}", param),
                                            &format!("CMDi via param `{}`", param),
                                        ).with_evidence(&format!("HTTP {}", status))
                                        .with_remediation("Never pass user input to shell execution");
                                        println!("  {} {}  \x1B[90m{}\x1B[0m  [\x1B[93mcmdi\x1B[0m]",
                                            fmt_sev_label(&Severity::Critical), f.title, fuzz_url);
                                        findings.push(f);
                                    }
                                }
                                "NoSQL" => {
                                    let scan_result = ScanResult {
                                        url: fuzz_url.clone(),
                                        status,
                                        response: Some(response),
                                        payload: payload.clone(),
                                    };
                                    if let Some(finding) = self.analyzer.analyze(scan_result).await {
                                        let f = Finding::new(&fuzz_url, finding.severity,
                                            &format!("NoSQLi via {}", param),
                                            &finding.title,
                                        ).with_evidence(&finding.evidence)
                                        .with_remediation(&finding.remediation);
                                        println!("  {} {}  \x1B[90m{}\x1B[0m  [\x1B[94mnosql\x1B[0m]",
                                            fmt_sev_label(&f.severity), f.title, fuzz_url);
                                        findings.push(f);
                                    }
                                }
                                "SSTI" => {
                                    if Self::contains_ssti(&response.body, payload) {
                                        let f = Finding::new(&fuzz_url, Severity::High,
                                            &format!("SSTI in {}", param),
                                            &format!("SSTI via param `{}`", param),
                                        ).with_evidence(&format!("HTTP {}", status))
                                        .with_remediation("Do not render user input in server-side templates");
                                        println!("  {} {}  \x1B[90m{}\x1B[0m  [\x1B[94mssti\x1B[0m]",
                                            fmt_sev_label(&Severity::High), f.title, fuzz_url);
                                        findings.push(f);
                                    }
                                }
                                _ => {}
                            }
                        }
                        Err(_) => {
                            if self.args.verbose {
                                println!("  \x1B[91mERR\x1B[0m {}  \x1B[90m{}?{}=\x1B[0m", label, url, param);
                            } else {
                                print!("\r\x1B[2K  \x1B[91mERR\x1B[0m {}  \x1B[90m{}?{}=\x1B[0m", label, url, param);
                                let _ = std::io::Write::flush(&mut std::io::stdout());
                            }
                        }
                    }
                }
            }
        }

        Ok(findings)
    }

    async fn scan_static_paths(&self) -> Result<Vec<Finding>> {
        let spinner = std::sync::Arc::new(std::sync::Mutex::new(Spinner::vuln_spinner()));
        let spinner_clone = spinner.clone();
        
        // Start spinner animation task
        let spinner_handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_millis(100));
            let mut counter = 0;
            loop {
                interval.tick().await;
                let frame = match spinner_clone.lock() {
                    Ok(guard) => guard.next(),
                    Err(poisoned) => poisoned.into_inner().next(),
                };
                counter += 1;
                print!("\r[{}] Scanning static paths ({}/20)...", frame, counter.min(20));
                let _ = std::io::Write::flush(&mut std::io::stdout());
            }
        });
        
        let mut findings = Vec::new();

        let paths = self.scanner.generate_payloads();

        for path in paths.iter().take(20) {
            let url = format!("{}{}", self.args.url, path);
            let request = crate::http::request::HttpRequest::get(&url);

            match self.client.send(request).await {
                Ok(response) => {
                    let result = ScanResult {
                        url: url.clone(),
                        status: response.status,
                        response: Some(response.clone()),
                        payload: path.clone(),
                    };

                    if let Some(finding) = self.analyzer.analyze(result).await {
                        findings.push(finding);
                    }
                }
                Err(_) => {}
            }

            let _ = match spinner.lock() {
                Ok(guard) => guard.next(),
                Err(poisoned) => poisoned.into_inner().next(),
            };
        }

        // Stop spinner
        spinner_handle.abort();
        print!("\r");

        Ok(findings)
    }

    pub fn get_findings(&self) -> &Vec<Finding> {
        &self.findings
    }

    pub async fn scan_with_agents(&self, targets: Vec<String>) -> Result<Vec<Finding>> {
        let target_count = targets.len();
        let mut agent_pool = AgentPool::new(&self.args, self.args.threads, target_count)?;

        println!("  AGENTS  Pool ready — {} agents, {} targets, {} permits",
            self.args.threads,
            target_count,
            agent_pool.get_available_permits(),
        );

        // Use TimeUtil::sleep_async for brief delay before starting agents
        TimeUtil::sleep_async(std::time::Duration::from_millis(100)).await;

        // Use TimeUtil::timeout for the agent scan with a 30-second timeout
        let scan_future = agent_pool.run_scan(targets);
        let result = match TimeUtil::timeout(std::time::Duration::from_secs(30), scan_future).await {
            Ok(result) => result,
            Err(_) => {
                println!("Agent scan timed out after 30 seconds");
                Ok(Vec::new())
            }
        };

        // Report final progress after scan completes
        let progress = agent_pool.get_progress();
        println!("  AGENTS  Done — {}/{} ({}%)",
            progress.get_current(), progress.get_total(), progress.get_percent());

        result
    }

    /// Convert oxide::Finding to crate::detection::analyzer::Finding
    fn convert_finding(&self, finding: &oxide::detection::analyzer::Finding) -> crate::detection::analyzer::Finding {
        let severity = match finding.severity {
            oxide::detection::analyzer::Severity::Critical => crate::detection::analyzer::Severity::Critical,
            oxide::detection::analyzer::Severity::High => crate::detection::analyzer::Severity::High,
            oxide::detection::analyzer::Severity::Medium => crate::detection::analyzer::Severity::Medium,
            oxide::detection::analyzer::Severity::Low => crate::detection::analyzer::Severity::Low,
            oxide::detection::analyzer::Severity::Info => crate::detection::analyzer::Severity::Info,
        };
        
        crate::detection::analyzer::Finding::new(
            &finding.url,
            severity,
            &finding.title,
            &finding.description,
        )
        .with_evidence(&finding.evidence)
        .with_remediation(&finding.remediation)
    }

    fn common_params() -> Vec<String> {
        vec![
            "id", "page", "file", "path", "search", "query", "q", "s", "cat", "category",
            "pid", "aid", "uid", "bid", "did", "order", "sort", "limit", "offset", "start",
            "end", "date", "from", "to", "type", "mode", "action", "cmd", "exec", "run",
            "url", "redirect", "return", "next", "prev", "view", "format", "debug", "test",
            "lang", "locale", "callback", "include", "template", "dir", "folder", "name",
            "user", "username", "pass", "password", "token", "api_key", "key", "sig",
        ].into_iter().map(String::from).collect()
    }

    fn extract_params_from_url(&self, url: &str) -> Vec<String> {
        if let Ok(parsed) = Url::parse(url) {
            if let Some(query) = parsed.query() {
                if !query.is_empty() {
                    return query
                        .split('&')
                        .filter_map(|param| {
                            param.split('=').next().map(|s| s.to_string())
                        })
                        .filter(|s| !s.is_empty())
                        .collect();
                }
            }
        }
        Self::common_params()
    }

    fn extract_params_from_urls(&self, urls: &[String]) -> Vec<String> {
        let mut params = std::collections::HashSet::new();
        
        for url in urls {
            for param in self.extract_params_from_url(url) {
                params.insert(param);
            }
        }
        
        if params.is_empty() {
            for p in Self::common_params() {
                params.insert(p);
            }
        }
        
        params.into_iter().collect()
    }

    /// Run ML-based zero-day detection on crawled URLs
    async fn run_ml_detection(&self, urls: &[String]) -> Result<Vec<Finding>> {
        use crate::zero_day::features::ResponseFeatures;
        use crate::http::request::HttpRequest;
        
        // Try to import validated baselines if file exists
        if std::path::Path::new("./validated_baselines.json").exists() {
            let _ = self.import_validated_baselines("./validated_baselines.json").await;
        }
        
        // Try to load saved baselines if directory exists
        if std::path::Path::new("./zero_day_data").exists() {
            // Note: load_zero_day_baselines requires &mut self, so we can't call it here directly
            // Instead, we log that baselines could be loaded
            tracing::info!("Found saved baselines in ./zero_day_data - use load_zero_day_baselines() to restore them");
        }
        
        let mut findings = Vec::new();
        let mut training_samples = Vec::new();
        
        // First pass: Collect training samples from all discovered URLs
        println!("   ML   Collecting baseline training data from {} URLs...", urls.len().min(50));
        for (idx, url) in urls.iter().take(50).enumerate() {
            let request = HttpRequest::get(url);
            let start = std::time::Instant::now();
            
            if let Ok(response) = self.client.send(request).await {
                let response_time = start.elapsed().as_millis() as u64;
                let features = ResponseFeatures::from_response(&response, url, response_time);
                
                // Collect samples for classifier training (label as safe initially)
                training_samples.push((features.clone(), false));
            }
            
            if idx % 10 == 0 {
                println!("    Processed {}/{} URLs for training", idx, urls.len().min(50));
            }
        }
        
        // Train the classifier if we have enough samples
        if training_samples.len() >= 10 {
            println!("   ML   Training classifier with {} samples...", training_samples.len());
            if let Err(e) = self.zero_day_engine.train_classifier(training_samples).await {
                println!("    Warning: Classifier training failed: {}", e);
            } else {
                println!("    Classifier trained successfully!");
            }
        }
        
        // Second pass: Analyze for anomalies
        println!("   ML   Analyzing responses for anomalies...");
        for (idx, url) in urls.iter().enumerate() {
            let request = HttpRequest::get(url);
            let start = std::time::Instant::now();
            
            if let Ok(response) = self.client.send(request).await {
                let response_time = start.elapsed().as_millis() as u64;
                let _features = ResponseFeatures::from_response(&response, url, response_time);
                
                // Analyze for anomalies
                let report = self.zero_day_engine.analyze_response(url, &response, response_time).await;
                
                if report.is_zero_day && report.confidence > 0.6 {
                    let severity = if report.confidence > 0.8 {
                        crate::detection::analyzer::Severity::Critical
                    } else if report.confidence > 0.7 {
                        crate::detection::analyzer::Severity::High
                    } else {
                        crate::detection::analyzer::Severity::Medium
                    };
                    
                    let vuln_type = report.anomaly_result.vulnerability_type.as_deref()
                        .unwrap_or("Unknown Anomaly");
                    
                    let description = format!(
                        "ML-detected anomaly with {:.1}% confidence\nType: {}\nAnomaly Score: {:.2}\nVulnerability Score: {:.2}",
                        report.confidence * 100.0,
                        vuln_type,
                        report.anomaly_result.anomaly_score,
                        report.anomaly_result.vulnerability_score
                    );
                    
                    let mut finding = Finding::new(
                        url,
                        severity,
                        &format!("ML Zero-Day: {}", vuln_type),
                        &description,
                    );
                    
                    // Add reasons as evidence
                    let evidence = report.anomaly_result.reasons.join("\n");
                    finding = finding.with_evidence(&evidence);
                    
                    // Add recommendations if available
                    if !report.recommendations.is_empty() {
                        finding = finding.with_remediation(&report.recommendations.join("\n"));
                    }
                    
                    findings.push(finding);
                    println!("    [DETECTED] Zero-day anomaly at {} (confidence: {:.1}%)", url, report.confidence * 100.0);
                }
            }
            
            if idx % 10 == 0 && !urls.is_empty() {
                let stats = self.zero_day_engine.get_stats().await;
                println!("    Analyzed {}/{} URLs (responses: {}, anomalies: {})", 
                    idx, urls.len(), stats.responses_analyzed, stats.anomalies_detected);
            }
        }
        
        let final_stats = self.zero_day_engine.get_stats().await;
        println!("   ML   Detection complete. Analyzed {} responses, found {} anomalies", 
            final_stats.responses_analyzed, final_stats.anomalies_detected);
        
        // Persist baselines for future scans
        if final_stats.anomalies_detected > 0 {
            let _ = self.persist_zero_day_baselines("./zero_day_data").await;
        }
        
        // Get and log status
        let status = self.get_zero_day_status().await;
        
        // Read all status fields to ensure they're used
        let _ = status.responses_analyzed;
        let _ = status.anomalies_detected;
        let _ = status.anomaly_threshold;
        let _ = status.vulnerability_threshold;
        
        // Log comprehensive status
        tracing::info!(
            "Zero-day status: {} responses, {} anomalies, thresholds: {:.2}/{:.2}",
            status.responses_analyzed,
            status.anomalies_detected,
            status.anomaly_threshold,
            status.vulnerability_threshold
        );
        
        println!("   ML   Baselines: {} total, {} mature, {} stale", 
            status.total_baselines, status.mature_baselines, status.stale_baselines);
        
        // Perform maintenance
        let maintenance = self.maintain_zero_day_system().await;
        
        // Read all maintenance fields
        let _ = maintenance.total_baselines;
        let _ = maintenance.duration_ms;
        
        tracing::info!(
            "Maintenance complete: {} total baselines, took {}ms",
            maintenance.total_baselines,
            maintenance.duration_ms
        );
        
        if maintenance.stale_baselines > 0 {
            println!("   ML   Found {} stale baselines during maintenance", maintenance.stale_baselines);
        }
        
        // Get baseline statistics and read all fields
        let stats = self.get_baseline_statistics().await;
        let _ = stats.total_samples; // Ensure field is read
        
        tracing::info!(
            "Baseline stats: {} total, {} mature, {} immature, {} samples, {:.1} avg",
            stats.total_baselines,
            stats.mature_baselines,
            stats.immature_baselines,
            stats.total_samples,
            stats.average_samples
        );
        
        println!("   ML   Statistics: {} total, {} mature, {} immature, {:.1} avg samples",
            stats.total_baselines, stats.mature_baselines, stats.immature_baselines, stats.average_samples);
        
        // Check classifier status
        let classifier_ready = self.is_classifier_ready().await;
        println!("   ML   Classifier ready: {}", classifier_ready);
        
        // Try to optimize thresholds if we have enough baselines
        if let Ok((anomaly, vuln)) = self.optimize_zero_day_thresholds().await {
            println!("   ML   Suggested thresholds: anomaly={:.2}, vuln={:.2}", anomaly, vuln);
        }
        
        Ok(findings)
    }

    pub async fn persist_zero_day_baselines(&self, output_dir: &str) -> Result<usize, String> {
        std::fs::create_dir_all(output_dir).map_err(|e| format!("Failed to create directory: {}", e))?;
        
        let mature_urls = self.zero_day_engine.get_mature_baselines().await;
        let mut saved = 0;
        
        for url in &mature_urls {
            let sanitized = url.replace(|c: char| !c.is_alphanumeric(), "_");
            let path = format!("{}/baseline_{}.json", output_dir, sanitized);
            
            if let Err(e) = self.zero_day_engine.save_baseline(url, &path).await {
                tracing::warn!("Failed to save baseline for {}: {}", url, e);
            } else {
                saved += 1;
            }
        }
        
        // Also export full engine state
        let engine_data = self.zero_day_engine.export_model().await
            .map_err(|e| format!("Export failed: {}", e))?;
        
        let state_path = format!("{}/zero_day_state.bin", output_dir);
        std::fs::write(&state_path, &engine_data)
            .map_err(|e| format!("Failed to write state: {}", e))?;
        
        tracing::info!("Persisted {} baselines and engine state to {}", saved, output_dir);
        Ok(saved)
    }

    /// Load zero-day detection baselines from disk
    pub async fn load_zero_day_baselines(&mut self, input_dir: &str) -> Result<(usize, usize), String> {
        let entries = std::fs::read_dir(input_dir)
            .map_err(|e| format!("Failed to read directory: {}", e))?;
        
        let mut loaded = 0;
        let mut failed = 0;
        
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().map(|e| e == "json").unwrap_or(false) {
                let filename = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
                
                if filename.starts_with("baseline_") {
                    let sanitized = &filename[9..];
                    let url = sanitized.replace('_', "/");
                    
                    if let Err(e) = self.zero_day_engine.load_baseline(&url, &path.to_string_lossy()).await {
                        tracing::warn!("Failed to load baseline: {}", e);
                        failed += 1;
                    } else {
                        loaded += 1;
                    }
                }
            }
        }
        
        // Try to load full engine state
        let state_path = format!("{}/zero_day_state.bin", input_dir);
        if let Ok(data) = std::fs::read(&state_path) {
            if let Err(e) = self.zero_day_engine.import_model(&data).await {
                tracing::warn!("Failed to import engine state: {}", e);
            } else {
                tracing::info!("Loaded engine state from {}", state_path);
            }
        }
        
        tracing::info!("Loaded {} baselines, {} failed from {}", loaded, failed, input_dir);
        Ok((loaded, failed))
    }

    /// Get comprehensive zero-day detection status
    pub async fn get_zero_day_status(&self) -> ZeroDayStatus {
        let stats = self.zero_day_engine.get_stats().await;
        let baseline_stats = self.zero_day_engine.get_baseline_health().await;
        let ages = self.zero_day_engine.get_baseline_ages().await;
        let status = self.zero_day_engine.get_status().await;
        
        let mature_count = baseline_stats.iter().filter(|(_, h)| h.is_mature).count();
        let stale_count = ages.iter().filter(|(_, a)| a.as_secs() > 7 * 86400).count();
        
        ZeroDayStatus {
            responses_analyzed: stats.responses_analyzed,
            anomalies_detected: stats.anomalies_detected,
            total_baselines: baseline_stats.len(),
            mature_baselines: mature_count,
            stale_baselines: stale_count,
            anomaly_threshold: status.anomaly_threshold,
            vulnerability_threshold: status.vulnerability_threshold,
        }
    }

    /// Optimize zero-day detection thresholds based on current data
    pub async fn optimize_zero_day_thresholds(&self) -> Result<(f64, f64), String> {
        let stats = self.zero_day_engine.get_baseline_health().await;
        
        if stats.len() < 10 {
            return Err("Need at least 10 baselines for optimization".to_string());
        }
        
        // Calculate optimal thresholds based on baseline variance
        let mature_baselines: Vec<_> = stats.iter().filter(|(_, h)| h.is_mature).collect();
        
        if mature_baselines.is_empty() {
            return Err("No mature baselines available".to_string());
        }
        
        let avg_coverage: f64 = mature_baselines.iter()
            .map(|(_, h)| h.coverage_score)
            .sum::<f64>() / mature_baselines.len() as f64;
        
        // Higher coverage = lower threshold (more sensitive)
        let anomaly_threshold = 0.7 - (avg_coverage * 0.2).clamp(0.0, 0.3);
        let vuln_threshold = anomaly_threshold + 0.1;
        
        // Note: Thresholds are calculated but not directly set on ZeroDayEngine
        // They would need to be passed to the underlying anomaly engine
        tracing::info!(
            "Suggested thresholds: anomaly={:.2}, vulnerability={:.2} (based on {} mature baselines)",
            anomaly_threshold, vuln_threshold, mature_baselines.len()
        );
        
        Ok((anomaly_threshold, vuln_threshold))
    }

    /// Perform maintenance on zero-day detection system
    pub async fn maintain_zero_day_system(&self) -> MaintenanceSummary {
        let start = std::time::Instant::now();
        
        // Clear old history
        self.zero_day_engine.clear_history().await;
        
        // Get baseline ages and report stale ones
        let ages = self.zero_day_engine.get_baseline_ages().await;
        let stale_count = ages.iter().filter(|(_, a)| a.as_secs() > 30 * 86400).count();
        
        // Reset stats if needed
        let stats = self.zero_day_engine.get_stats().await;
        if stats.responses_analyzed > 10000 {
            self.zero_day_engine.reset_stats().await;
        }
        
        MaintenanceSummary {
            stale_baselines: stale_count,
            total_baselines: ages.len(),
            duration_ms: start.elapsed().as_millis() as u64,
        }
    }

    /// Import validated baselines from external source
    pub async fn import_validated_baselines(&self, data_path: &str) -> Result<Vec<(String, bool)>, String> {
        let json = std::fs::read_to_string(data_path)
            .map_err(|e| format!("Failed to read file: {}", e))?;
        
        let engine_data: crate::zero_day::anomaly::AnomalyEngineData = serde_json::from_str(&json)
            .map_err(|e| format!("JSON parse failed: {}", e))?;
        
        let results = self.zero_day_engine.import_baselines_validated(engine_data).await
            .map_err(|e| format!("Import failed: {}", e))?;
        
        let valid_count = results.iter().filter(|(_, v)| *v).count();
        tracing::info!("Imported {} valid baselines from {}", valid_count, data_path);
        
        Ok(results)
    }

    /// Check if classifier is trained and ready
    pub async fn is_classifier_ready(&self) -> bool {
        let status = self.zero_day_engine.get_status().await;
        status.classifier_trained
    }

    /// Get detailed baseline statistics
    pub async fn get_baseline_statistics(&self) -> BaselineStatisticsSummary {
        let stats = self.zero_day_engine.get_baseline_health().await;
        let total = stats.len();
        let mature = stats.iter().filter(|(_, h)| h.is_mature).count();
        let immature = total - mature;
        let total_samples: usize = stats.iter().map(|(_, h)| h.sample_count).sum();
        
        BaselineStatisticsSummary {
            total_baselines: total,
            mature_baselines: mature,
            immature_baselines: immature,
            total_samples,
            average_samples: if total > 0 { total_samples as f64 / total as f64 } else { 0.0 },
        }
    }
}

// ── Gruvbox-themed output helpers ────────────────────────────────────────

use crate::cli::display::{
    GB_AQU, GB_BLU, GB_BLU_B, GB_FG, GB_FG0, GB_GRN_B, GB_GRY,
    GB_ORG_B, GB_RED, GB_RED_B, GB_YLW, GB_YLW_B,
};

fn tc(s: &str, (r, g, b): (u8, u8, u8)) -> String {
    use colored::Colorize;
    s.truecolor(r, g, b).to_string()
}

fn print_phase_banner(module: &str, desc: &str) {
    println!("  {} {}  {} {}  {}",
        tc("┌─", GB_ORG_B),
        tc(module, GB_YLW_B).bold(),
        tc("→", GB_GRY),
        tc(desc, GB_FG),
        tc(&"─".repeat(8), GB_GRY));
}

fn print_phase_sub(module: &str, desc: &str) {
    println!("  {} {}  {} {}",
        tc("├─", GB_GRY),
        tc(module, GB_BLU_B).bold(),
        tc("→", GB_GRY),
        tc(desc, GB_FG0));
}

fn fmt_status(status: u16) -> String {
    match status {
        200..=299 => tc(&status.to_string(), GB_GRN_B),
        300..=399 => tc(&status.to_string(), GB_YLW),
        400..=499 => tc(&status.to_string(), GB_RED),
        500..=599 => tc(&status.to_string(), GB_RED_B),
        _ => tc(&status.to_string(), GB_GRY),
    }
}

fn fmt_sev_label(severity: &Severity) -> String {
    match severity {
        Severity::Critical => tc("▌CRITICAL▐", GB_RED_B),
        Severity::High     => tc("▌ HIGH   ▐", GB_RED),
        Severity::Medium   => tc("▌ MEDIUM ▐", GB_YLW),
        Severity::Low      => tc("▌ LOW    ▐", GB_AQU),
        Severity::Info     => tc("▌ INFO   ▐", GB_BLU),
    }
}

/// Zero-day detection system status
#[derive(Debug, Clone)]
pub struct ZeroDayStatus {
    pub responses_analyzed: usize,
    pub anomalies_detected: usize,
    pub total_baselines: usize,
    pub mature_baselines: usize,
    pub stale_baselines: usize,
    pub anomaly_threshold: f64,
    pub vulnerability_threshold: f64,
}

/// Maintenance operation summary
#[derive(Debug, Clone)]
pub struct MaintenanceSummary {
    pub stale_baselines: usize,
    pub total_baselines: usize,
    pub duration_ms: u64,
}

/// Baseline statistics summary
#[derive(Debug, Clone)]
pub struct BaselineStatisticsSummary {
    pub total_baselines: usize,
    pub mature_baselines: usize,
    pub immature_baselines: usize,
    pub total_samples: usize,
    pub average_samples: f64,
}
