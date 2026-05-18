use colored::Colorize;
use std::process;
use std::time::Instant;
///! Oxidation Reaction Main control


mod crawls;
mod hybrid;
mod agent;
#[cfg(target_os = "linux")]
mod recon;
mod zero_day;

pub use oxide::cli;
pub use oxide::core;
pub use oxide::http;
pub use oxide::payload;
pub use oxide::detection;
pub use oxide::report;
pub use oxide::utils;

use crate::cli::args::CliArgs;
use crate::cli::colors;
use crate::cli::colors::Colors;
use crate::cli::config::Config;
use crate::http::client::HttpClient;
use crate::cli::display::{
    GB_AQU_B, GB_BLU_B, GB_FG, GB_FG0, GB_GRN_B, GB_GRY, GB_RED_B, GB_YLW, RP_GOLD,
};
use crate::cli::output::Output;
use crate::cli::parser::Parser;
use crate::cli::spinner::Spinner;
use crate::utils::time::TimeUtil;
use hybrid::HybridScanner;
use core::engine::ScanEngine;

fn tc(s: &str, (r, g, b): (u8, u8, u8)) -> String {
    s.truecolor(r, g, b).to_string()
}

fn print_banner() {
    use crate::cli::display::{
        GB_AQU, GB_FG0, GB_GRN_B, GB_GRY, GB_YLW_B, RP_GOLD, RP_PINE,
    };
    println!();
    println!("{}", tc("   ____ _  __ ________  ______", GB_GRN_B));
    println!("{}", tc("  / __ \\ |/ //  _/ __ \\/ ____/", GB_YLW_B));
    println!("{}", tc(" / / / /   / / // / / / __/", RP_GOLD));
    println!("{}", tc("/ /_/ /   |_/ // /_/ / /___", GB_AQU));
    println!("{}", tc("\\____/_/|_/___/_____/_____/", GB_GRY));
    println!();
    println!("{}", tc("═══════════════════════════════════════════════════════════════════════════════", GB_YLW_B));
    println!("  {} {}",
        tc("◈", RP_GOLD),
        tc("Hypersecurity Offensive Labs  |  OXIDE Community Edition v8.3.1", GB_FG0));
    println!("  {} {}",
        tc(">>", GB_AQU),
        tc("Open eXtensible Intelligence & Detection Engine — Community Edition << /evergreen okay", GB_GRY));
    println!("{}", tc("═══════════════════════════════════════════════════════════════════════════════", RP_PINE));
    println!();
}

/// Resolve the IP address(es) for a hostname using tokio's built-in DNS.
/// Returns a deduplicated list of IP strings, or an empty vec on failure.

async fn resolve_ip(host: &str) -> Vec<String> {
    use std::collections::BTreeSet;
    // lookup_host needs a host:port pair
    let addr = format!("{}:80", host);
    match tokio::net::lookup_host(addr).await {
        Ok(addrs) => {
            let ips: BTreeSet<String> = addrs.map(|a| a.ip().to_string()).collect();
            ips.into_iter().collect()
        }
        Err(_) => Vec::new(),
    }
}

async fn print_scan_info(args: &CliArgs) {
    let tc = |s: &str, (r, g, b): (u8, u8, u8)| s.truecolor(r, g, b).to_string();
    use crate::cli::display::{
        GB_AQU, GB_BLU_B, GB_FG, GB_FG0, GB_GRN_B, GB_GRY, GB_RED_B, GB_YLW_B, RP_GOLD, RP_ROSE,
    };

    let clean = Parser::ensure_http(&args.url);
    let host = url::Url::parse(&clean)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.to_string()))
        .unwrap_or_default();
    let ips = resolve_ip(&host).await;
    let ip_display = if ips.is_empty() {
        tc("unresolved", GB_RED_B)
    } else {
        tc(&ips.join(", "), GB_GRN_B)
    };

    Output::print_header("Target Information");
    println!("  {} {}  {} {}",
        tc("▸", GB_YLW_B), tc("Target", GB_GRY).bold(),
        tc("→", GB_GRY), args.url.truecolor(GB_FG0.0, GB_FG0.1, GB_FG0.2).bold());
    println!("  {} {}  {} {}",
        tc("▸", GB_YLW_B), tc("IP", GB_GRY).bold(),
        tc("→", GB_GRY), ip_display);
    println!("  {} {}  {} {}  {} {}",
        tc("▸", GB_YLW_B), tc("Threads", GB_GRY).bold(),
        tc("→", GB_GRY), tc(&args.threads.to_string(), GB_GRN_B),
        tc("⏱", RP_GOLD), tc(&format!("{}s timeout", args.timeout), GB_FG));

    let modules = args.get_modules();
    let module_line: Vec<String> = modules.iter().map(|m| tc(m, GB_AQU)).collect();
    println!("  {} {}  {} {}",
        tc("▸", GB_YLW_B), tc("Modules", GB_GRY).bold(),
        tc("→", GB_GRY), module_line.join(tc(" │ ", GB_GRY).as_str()));

    if let Some(output) = &args.output {
        println!("  {} {}  {} {}",
            tc("▸", GB_YLW_B), tc("Output", GB_GRY).bold(),
            tc("→", GB_GRY), tc(&output.display().to_string(), GB_GRN_B));
    }

    if args.verbose  { println!("  {} {}", tc("▸", GB_YLW_B), tc("Verbose mode", GB_GRN_B)); }
    if args.insecure { println!("  {} {}", tc("▸", GB_YLW_B), tc("SSL verification disabled", GB_RED_B)); }
    if args.zeroday  { println!("  {} {}", tc("▸", GB_YLW_B), tc("Zero-day detection", RP_GOLD)); }
    if args.train    { println!("  {} {}", tc("▸", GB_YLW_B), tc("Training mode", RP_ROSE)); }
    if args.insta    { println!("  {} {}", tc("▸", GB_YLW_B), tc("Instagram OSINT", GB_BLU_B)); }
    if args.session  { println!("  {} {}", tc("▸", GB_YLW_B), tc("Session hijack testing", GB_AQU)); }

    if !args.header.is_empty() {
        Output::print_section("Custom Headers");
        for header in &args.header {
            match Parser::parse_header(header) {
                Ok((key, value)) => println!("    {}: {}",
                    tc(&key, GB_GRN_B), tc(&value, GB_FG0)),
                Err(e) => println!("    Invalid header '{}': {}", header, e),
            }
        }
    }

    if let Some(cookie) = &args.cookie {
        Output::print_section("Cookies");
        for (key, value) in &Parser::parse_cookie(cookie) {
            println!("    {}: {}",
                tc(&key, GB_GRN_B), tc(&value, GB_FG0));
        }
    }

    Output::print_line();
    println!();
}

#[tokio::main]
async fn main() {
    print_banner();
    
    // Use TimeUtil for timing
    let start_time = Instant::now();
    let scan_start = TimeUtil::now();
    println!("Scan started at: {}", TimeUtil::format_timestamp(&scan_start));
    println!("Unix timestamp: {}", TimeUtil::unix_timestamp());
    
    let args = match CliArgs::parse_args() {
        Ok(args) => args,
        Err(e) => {
            eprintln!("{} {}", "[ERROR]".red().bold(), e);
            process::exit(1);
        }
    };
    
    // Validate proxy library — binary won't run without it
    crate::http::proxy_loader::ensure_proxy_library();
    
    // Load or create default config
    let config_path = std::path::PathBuf::from("oxide-config.toml");
    let mut config = if config_path.exists() {
        match Config::load(&config_path) {
            Ok(c) => {
                println!("Loaded config from {}", config_path.display());
                c
            }
            Err(e) => {
                println!("Failed to load config: {}, using defaults", e);
                Config::default()
            }
        }
    } else {
        let default_config = Config::default();
        if let Err(e) = default_config.save(&config_path) {
            println!("Failed to save default config: {}", e);
        } else {
            println!("Created default config at {}", config_path.display());
        }
        default_config
    };
    
    // Add custom headers to config
    for header in &args.header {
        if let Ok((key, value)) = Parser::parse_header(header) {
            config.add_header(&key, &value);
        }
    }
    
    // Get and display config headers
    let headers = config.get_headers();
    if !headers.is_empty() {
        println!("Loaded {} custom headers from config", headers.len());
    }
    
    // Validate URL using Parser
    let validated_url = Parser::ensure_http(&args.url);
    
    // Use Parser::parse_url for strict validation
    match Parser::parse_url(&validated_url) {
        Ok(url) => println!("Valid URL parsed: {}", url),
        Err(e) => {
            eprintln!("{} Invalid URL: {}", "[ERROR]".red().bold(), e);
            process::exit(1);
        }
    }
    
    // Use Parser::is_valid_domain for domain validation
    let clean_url = validated_url.replace("http://", "").replace("https://", "");
    let domain = clean_url.split('/').next().unwrap_or("");
    if !Parser::is_valid_domain(domain) {
        eprintln!("{} Invalid domain: {}", "[ERROR]".red().bold(), domain);
        process::exit(1);
    }
    println!("Domain validation passed: {} (no sneaky redirects detected... yet)", domain);
    
    let funny_messages = vec![
        "Scanning so hard, even the server is nervous...",
        "Looking for bugs like a raccoon in a trash can...",
        "Poking endpoints with a digital stick...",
        "Hunting vulnerabilities like it's a video game...",
        "Scanning for weak spots like a caffeinated pentester...",
        "Making packets do the heavy lifting...",
        "Scanning with the intensity of a midnight coder...",
    ];
    let msg_idx = (scan_start.timestamp() as usize) % funny_messages.len();
    println!("[+] {}", funny_messages[msg_idx].bright_cyan());
    
    println!("Using config: {} threads, {}s timeout, {} custom headers", 
        config.threads, config.timeout, headers.len());
    println!("[+] Firing up the engines... hope your firewall is ready");
    
    print_scan_info(&args).await;
    
    // Initialize fingerprint spinner
    let _finger_spin = Spinner::finger_spinner();
    
    // ── Train mode: run all scanners and train zero-day ML classifier ─────
    if args.train {
        println!("{}", "Training mode engaged — indexing all scanners...".bright_green().bold());
        let client = std::sync::Arc::new(HttpClient::new(args.timeout, args.insecure)
            .expect("Failed to create HTTP client for training"));
        let engine = zero_day::engine::ZeroDayEngine::new();
        let trainer = zero_day::trainer::ZeroDayTrainer::new(
            client, engine, &args.url, args.timeout,
        );
        match trainer.run_training().await {
            Ok(()) => {
                println!("{} Training complete!", "[OK]".green().bold());
                process::exit(0);
            }
            Err(e) => {
                eprintln!("{} Training failed: {}", "[ERROR]".red().bold(), e);
                process::exit(1);
            }
        }
    }

    println!("  {} {}",
        tc("◈", RP_GOLD),
        tc("Launching scan — sit tight", GB_FG0).bold());
    println!();
    
    // Use legacy ScanEngine if engine module is specified
    let (findings, hybrid_scanner) = if args.get_modules().contains(&"engine".to_string()) {
        println!("Using legacy ScanEngine...");
        let engine = match ScanEngine::new(args.clone()) {
            Ok(e) => e,
            Err(e) => {
                eprintln!("{} Failed to create HTTP client: {}", "[ERROR]".red().bold(), e);
                process::exit(1);
            }
        };
        match engine.run().await {
            Ok(_) => (Vec::new(), None),
            Err(e) => {
                eprintln!("{} ScanEngine failed: {}", "[ERROR]".red().bold(), e);
                process::exit(1);
            }
        }
    } else {
        // Use hybrid scanner (default)
        let mut hybrid_scanner = match HybridScanner::new(args.clone()) {
            Ok(scanner) => scanner,
            Err(e) => {
                eprintln!("{} Failed to initialize scanner: {}", "[ERROR]".red().bold(), e);
                process::exit(1);
            }
        };
        
        match hybrid_scanner.run_hybrid_scan().await {
            Ok(f) => {
                println!("[+] Scan complete! Time to review the carnage...");
                (f, Some(hybrid_scanner))
            }
            Err(e) => {
                eprintln!("\n{} Scan failed: {}", "[FAILED]".red().bold(), e);
                process::exit(1);
            }
        }
    };
    
    let elapsed = start_time.elapsed();

    Output::print_scan_complete(
        &format!("{:.1}s", elapsed.as_secs_f64()),
        findings.len(),
        &findings,
    );
    
    if findings.is_empty() {
        println!("  {} {}", tc("◈", GB_AQU_B), tc("No vulnerabilities found — target appears secure", GB_FG));
    } else if findings.len() < 5 {
        println!("  {} {}", tc("◈", GB_YLW), tc("Found a few issues", GB_FG));
    } else {
        println!("  {} {}", tc("◈", GB_RED_B), tc(&format!("Found {} issues — review recommended", findings.len()), GB_FG));
    }

    if let Some(scanner) = &hybrid_scanner {
        let detailed_findings = scanner.get_findings();
        if !detailed_findings.is_empty() && args.verbose {
            println!("  {}", tc("Detailed findings:", GB_GRY).underline());
            for (idx, finding) in detailed_findings.iter().take(10).enumerate() {
                println!("    {}. {} — {}",
                    tc(&format!("{:>2}", idx + 1), GB_GRY),
                    tc(&finding.title, GB_FG0),
                    tc(&finding.url[..finding.url.len().min(60)], GB_BLU_B));
            }
            if detailed_findings.len() > 10 {
                println!("    {} {} more findings not shown", tc("⋯", GB_GRY), detailed_findings.len() - 10);
            }
        }
    }

    let final_duration = TimeUtil::format_duration(elapsed);
    println!("  {} {}    {} {}",
        tc("⏱", RP_GOLD), tc(&format!("Duration: {}", final_duration), GB_FG),
        tc("◷", GB_GRN_B), tc(&format!("Ended: {}", TimeUtil::format_timestamp(&TimeUtil::now())), GB_GRY));
    
    if let Some(output_path) = &args.output {
        let mut reporter = report::generator::ReportGenerator::new(&args.format);
        for finding in &findings {
            reporter.add_finding(finding.clone());
        }
        
        // Use print_summary method
        reporter.print_summary();
        
        match reporter.save(output_path) {
            Ok(_) => println!("\n{} Report saved to: {}", Colors::ok("[OK]"), output_path.display()),
            Err(e) => eprintln!("\n{} Failed to save report: {}", "[ERROR]".red(), e),
        }
    }
    
    // Use Colors::ok for final status display
    println!("{}", Colors::ok(&format!("Scan complete: {} vulnerabilities found", findings.len())));
    colors::print_status("OK", &format!("Found {} vulnerabilities", findings.len()));
    
    let farewells = vec![
        "Until next time, keep your patches tight!",
        "Scan finished. Go forth and remediate!",
        "Mission accomplished. Time for a victory lap!",
        "Done! Now go fix those bugs before they bite back!",
        "Scan complete. Don't forget to blame the intern!",
    ];
    let bye_idx = (TimeUtil::unix_timestamp() as usize) % farewells.len();
    println!("[+] {}", farewells[bye_idx].bright_green());
    
    // Use additional TimeUtil functions
    let utc_now = TimeUtil::now_utc();
    println!("Scan completed at (UTC): {}", TimeUtil::format_timestamp_iso(&utc_now));
    
    // Use TimeUtil::elapsed_since with a new instant
    let test_start = std::time::Instant::now();
    TimeUtil::sleep(std::time::Duration::from_millis(10));
    let _test_elapsed = TimeUtil::elapsed_since(test_start);
    
    // Use sleep_async and timeout
    let sleep_future = TimeUtil::sleep_async(std::time::Duration::from_millis(10));
    let _ = TimeUtil::timeout(std::time::Duration::from_millis(100), sleep_future).await;
    
    println!("\n{} Scan completed successfully", "[DONE]".green().bold());
}
