use clap::Parser;
use std::path::PathBuf;

use crate::cli::parser::Parser as ArgParser;

#[derive(Parser, Debug, Clone)]
#[command(name = "oxide")]
#[command(about = "OXIDE Community Edition - Open eXtensible Intelligence & Detection Engine v8.3.1")]
#[command(version = "8.3.1")]
pub struct CliArgs {
    #[arg(short, long, help = "Target URL to break... err, scan")]
    pub url: String,

    #[arg(short, long, help = "Concurrent threads (1-100). Higher = faster but more aggressive", default_value = "20")]
    pub threads: usize,

    #[arg(short = 'T', long, help = "How long to wait before giving up (seconds)", default_value = "30")]
    pub timeout: u64,

    #[arg(short, long, help = "Where to write your bug report masterpiece")]
    pub output: Option<PathBuf>,

    #[arg(short, long, help = "Output format (json, html, csv, xml). We recommend json for machines, html for your manager", default_value = "json")]
    pub format: String,

    #[arg(long, help = "Pretend to be someone else (User-Agent)")]
    pub user_agent: Option<String>,

    #[arg(long, help = "Cookies to sweeten the request")]
    pub cookie: Option<String>,

    #[arg(long, help = "Extra headers to confuse... err, inform the server")]
    pub header: Vec<String>,

    #[arg(short, long, help = "Talk more. Like, a LOT more")]
    pub verbose: bool,

    #[arg(long, help = "Slow down, turbo (requests per second)")]
    pub rate_limit: Option<u32>,

    #[arg(long, help = "Follow redirects like a lost puppy")]
    pub follow_redirects: bool,

    #[arg(long, help = "How many redirects before we get dizzy", default_value = "10")]
    pub max_redirects: usize,

    #[arg(long, help = "Ignore SSL cert errors (living dangerously)")]
    pub insecure: bool,

    #[arg(long, help = "Route traffic through a middleman (proxy URL)")]
    pub proxy: Option<String>,

    #[arg(long, help = "Pick your weapons (modules: all, engine, static, agent, body, fingerprint, tls, common, cors, creds, insta, session, (sqli, xss, lfi)Already in fuzz..., db-fingerprint)")]
    pub modules: Option<String>,

    #[arg(long, help = "How hard to hit it (1-100, higher = more aggressive Try At your own Risk)", default_value = "50")]
    pub exploitation_level: u8,

    #[arg(long, help = "Max payloads before the server cries uncle", default_value = "50")]
    pub payload_limit: usize,

    #[arg(long, help = "How deep the rabbit hole goes (crawl depth)", default_value = "3")]
    pub crawl_depth: usize,

    #[arg(long, help = "Max pages to spider before getting bored", default_value = "100")]
    pub max_urls: usize,

    #[arg(long, help = "Shhh... be very very quiet (less noise)")]
    pub silent_mode: bool,

    #[arg(long, help = "Download sensitive files when found (database dumps, configs, etc)")]
    pub download: bool,

    #[arg(long, help = "Modules to skip (they're on vacation)")]
    pub exclude: Option<String>,

    #[arg(long, help = "Enable zero-day vulnerability detection Call of Laywer if found 0Day dont tell others (experimental)")]
    pub zeroday: bool,

    #[arg(long, help = "Active TCP fingerprinting via raw packets (requires sudo). Pokes the server with a stick to see what OS it runs")]
    pub active: bool,

    #[arg(long, help = "Train zero-day ML classifier by scanning with all modules and collecting labeled response data")]
    pub train: bool,

    #[arg(long, help = "Enable Instagram OSINT module — follower count, private profile detection, media download")]
    pub insta: bool,

    #[arg(long, help = "Enable session hijack testing — cookie flags, fixation, predictability")]
    pub session: bool,
}

impl CliArgs {
    pub fn parse_args() -> anyhow::Result<Self> {
        let mut args = Self::parse();

        // Validate and clamp threads to safe range (1-100)
        if args.threads > 100 {
            eprintln!("[WARN] threads clamped to 100 (was {})", args.threads);
            args.threads = 100;
        }
        if args.threads < 1 {
            eprintln!("[WARN] threads raised to 1 (was {})", args.threads);
            args.threads = 1;
        }

        // Clamp exploitation level
        if args.exploitation_level > 100 {
            eprintln!("[WARN] exploitation_level clamped to 100 (was {})", args.exploitation_level);
            args.exploitation_level = 100;
        }

        // Clamp payload limit
        if args.payload_limit > 500 {
            eprintln!("[WARN] payload_limit clamped to 500 (was {})", args.payload_limit);
            args.payload_limit = 500;
        }

        // Clamp crawl depth
        if args.crawl_depth > 10 {
            eprintln!("[WARN] crawl_depth clamped to 10 (was {})", args.crawl_depth);
            args.crawl_depth = 10;
        }

        // Clamp max_urls
        if args.max_urls > 10_000 {
            eprintln!("[WARN] max_urls clamped to 10000 (was {})", args.max_urls);
            args.max_urls = 10_000;
        }

        Ok(args)
    }

    pub fn get_modules(&self) -> Vec<String> {
        match &self.modules {
            Some(m) => ArgParser::parse_modules(m),
            None => vec!["all".to_string()],
        }
    }

    pub fn get_excluded(&self) -> Vec<String> {
        match &self.exclude {
            Some(e) => e.split(',').map(|s| s.trim().to_string()).collect(),
            None => vec![],
        }
    }
}
