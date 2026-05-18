/// OXIDE User-Agent rotation for red team operations.
///
/// Strategies:
///   - Modern browser UAs that match real traffic patterns
///   - Randomised minor version numbers to avoid fingerprinting
///   - Cloudflare/WAF evasion: realistic Accept/Accept-Language headers
///   - Mobile UAs for bypassing desktop-only WAF rules
///   - Headless browser detection bypass (no "HeadlessChrome" string)
///   - Bot/crawler UAs that trigger different server behavior
///   - Written by KhaninKali

use std::sync::atomic::{AtomicUsize, Ordering};

/// A pool of realistic user-agent strings.
/// Call `next()` to rotate through them in round-robin order.
pub struct UserAgentPool {
    agents: &'static [&'static str],
    cursor: AtomicUsize,
}

impl Clone for UserAgentPool {
    fn clone(&self) -> Self {
        Self {
            agents: self.agents,
            cursor: AtomicUsize::new(self.cursor.load(Ordering::Relaxed)),
        }
    }
}

impl UserAgentPool {
    pub fn full() -> Self {
        Self { agents: ALL_AGENTS, cursor: AtomicUsize::new(0) }
    }

    /// Aggressive pool: bots + scanners that bypass WAF and trigger real server responses
    pub fn aggressive() -> Self {
        Self { agents: AGGRESSIVE_AGENTS, cursor: AtomicUsize::new(0) }
    }

    /// Rotate to the next agent.
    pub fn next(&self) -> &'static str {
        let idx = self.cursor.fetch_add(1, Ordering::Relaxed);
        self.agents[idx % self.agents.len()]
    }

    /// Pick a random agent (uses the rotation index as a pseudo-random seed).
    pub fn random(&self) -> &'static str {
        let idx = self.cursor.fetch_add(7, Ordering::Relaxed);
        self.agents[idx % self.agents.len()]
    }

    /// Return the full set of Accept headers that match the given UA.
    /// Pairing UA + Accept headers is critical for Cloudflare bypass.
    pub fn accept_headers_for(ua: &str) -> (&'static str, &'static str, &'static str) {
        // (Accept, Accept-Language, Accept-Encoding)
        if ua.contains("Firefox") {
            (
                "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                "en-US,en;q=0.5",
                "gzip, deflate, br",
            )
        } else if ua.contains("Safari") && !ua.contains("Chrome") {
            (
                "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "en-US,en;q=0.9",
                "gzip, deflate, br",
            )
        } else if ua.contains("Googlebot") || ua.contains("bingbot") || ua.contains("Slurp") {
            (
                "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "en-US,en;q=0.5",
                "gzip, deflate",
            )
        } else {
            // Chrome / Edge / default
            (
                "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                "en-US,en;q=0.9",
                "gzip, deflate, br, zstd",
            )
        }
    }
}

// ── Aggressive WAF bypass / server probing agents ────────────────────────────
// These trigger different server behavior, bypass WAF allowlists, and expose
// backend fingerprints that modern browsers hide behind CDN.

const AGGRESSIVE_AGENTS: &[&str] = &[
    // ── Search engine bots (WAFs rarely block these) ──
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    "Mozilla/5.0 (compatible; DuckDuckBot-Https/1.1; +https://duckduckgo.com/duckduckbot)",
    "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)",
    "Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)",
    "Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)",
    // ── Legacy / old browsers (trigger fallback paths, no modern security) ──
    "Mozilla/5.0 (Windows NT 5.1; rv:11.0) Gecko/20100101 Firefox/11.0",
    "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)",
    "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)",
    "Mozilla/5.0 (Windows NT 4.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/37.0.2049.0 Safari/537.36",
    // ── CLI tools (bypass JS challenges, no JS execution) ──
    "curl/8.7.1",
    "Wget/1.24.5 (linux-gnu)",
    "Python-urllib/3.12",
    "python-requests/2.31.0",
    "Go-http-client/2.0",
    "HTTPie/3.2.2",
    "Aria2/1.37.0",
    "Lynx/2.9.2dev.9 libwww-FM/2.14 SSL-MM/1.4.1 OpenSSL/3.0.12",
    // ── RSS readers / feed fetchers ──
    "FeedReader/3.14 Generic/2.0",
    "NetNewsWire/6.1 (Macintosh; Intel Mac OS X 14.4)",
    // ── Cloud infra / health checks ──
    "kube-probe/1.29",
    "Amazon-Route53-Health-Check-Service (amazon.com)",
    "ELB-HealthChecker/2.0",
    "Google-Cloud-Tasks/1.0",
    "Travis-CI/1.0 (travis-ci.com)",
    "GitHub-Actions-CI/1.0",
    // ── Security scanners (trigger defensive responses) ──
    "Nmap Scripting Engine",
    "nikto/2.5.0 (https://cirt.net/nikto2)",
    "sqlmap/1.8.2 (https://sqlmap.org)",
    "OpenVAS/22.4.1",
    "Metasploit/6.4.0",
    "Burp-Suite-Professional/2024.2.1",
    "ZAP/2.15.0",
    // ── Headless / automation (no "HeadlessChrome" — stealth) ──
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
];

// ── Combined pool ─────────────────────────────────────────────────────────────

const ALL_AGENTS: &[&str] = &[
    // Chrome Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    // Chrome macOS
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    // Chrome Linux
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    // Edge
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 Edg/123.0.0.0",
    // Firefox
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.4; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
    // Safari
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    // Mobile Chrome
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.82 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 13; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.6312.118 Mobile Safari/537.36",
    // Mobile Safari
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3.1 Mobile/15E148 Safari/604.1",
    // Opera
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 OPR/109.0.0.0",
];
