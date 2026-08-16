# oxide-communityedtion
Open eXtensible Intelligence &amp; Detection Engine — AI-augmented web vulnerability scanner written in Rust with ML-driven zero-day detection, encrypted test database, and cross-platform support.

<div align="center">

```
    ____ _  __ ________  ______
   / __ \ |/ //  _/ __ \/ ____/
 / / / /   / / // / / / __/
/ /_/ /   |_/ // /_/ / /___
\____/_/|_/___/_____/_____/
```

<img src="https://img.shields.io/badge/Rust-fab41e?style=for-the-badge&logo=rust&logoColor=1d2021" />
<img src="https://img.shields.io/badge/version-8.3.1-fe8019?style=for-the-badge" />
<img src="https://img.shields.io/badge/license-Proprietary-fe8019?style=for-the-badge" />
<img src="https://img.shields.io/badge/platform-Linux%20%7C%20Windows%20%7C%20-b8bb26?style=for-the-badge" />
<img src="https://img.shields.io/badge/async-Tokio-98971a?style=for-the-badge&logo=rust&logoColor=1d2021" />

### **Open eXtensible Intelligence & Detection Engine**
#### *Built with 🦀 Rust · Powered by AI/ML · Engineered for Offensive Security*

---

> **⚠️ LEGAL WARNING & COPYRIGHT NOTICE**
>
> This tool is developed and maintained by **khaninkali** @ **HyperSecurityLabs**.
> Unauthorized copying, redistribution, or use of this codebase — in whole or in part — without
> explicit written permission is **strictly prohibited** and may result in legal action.
>
> OXIDE is intended **exclusively** for authorized penetration testing, security research,
> and educational purposes. **You are solely responsible** for ensuring you have proper
> authorization before scanning any target. Misuse of this tool against systems you do not
> own or have explicit permission to test is **illegal** and unethical.
>
> © 2024 khaninkali · HyperSecurityLabs · All Rights Reserved

</div>

---

## 🧬 What is OXIDE?

**OXIDE** (Open eXtensible Intelligence & Detection Engine) is a next-generation, AI-augmented web vulnerability scanner written entirely in **Rust**. It combines the raw performance of systems-level programming with machine learning-driven detection to find what traditional scanners miss.

From classic SQLi and XSS to zero-day anomaly detection using real ML models — OXIDE is built for the modern offensive security professional.

<img width="1440" height="900" alt="Screenshot_2026-05-18_12_04_21" src="https://github.com/user-attachments/assets/0e5233ac-3e51-4482-9b0a-7dd8da7b4fa1" />

---

## ⚡ Feature Highlights

### 🔍 Vulnerability Scanners
| Module | Description |
|--------|-------------|
| `sqli` | SQL Injection — error-based, blind, time-based |
| `blind-sqli` | Blind SQLi with timing analysis |
| `xss` | Cross-Site Scripting — reflected, stored, DOM |
| `lfi` | Local File Inclusion with path traversal chains |
| `path-traversal` | Directory traversal across OS variants |
| `cmd-injection` | OS Command Injection detection |
| `cors` | CORS misconfiguration assessment |
| `tls` | Full TLS/SSL security audit |
| `creds` | Default credential brute-force (6000+ combos) |
| `common` | Nikto-style common app checks (2790+ tests) |
| `db-fingerprint` | Database engine fingerprinting |
| `insta` | Instagram OSINT — follower count, private status, profile pic |
| `session` | Session hijack testing — cookie flags, fixation, predictability |
| `train` | ML classifier trainer — learns from live scanner results |

### 🤖 AI / ML Engine
- **Zero-Day Detection** — statistical anomaly detection using `smartcore` (Random Forest, SVM) and `linfa` clustering
- **Pattern Learner** — adaptive payload mutation based on response patterns
- **Exploit Analyzer** — AI-driven exploit chain analysis
- **Response Analyzer** — behavioral fingerprinting of HTTP responses
- **Payload Mutator** — ML-guided payload evolution

### 🕷️ Crawling & Discovery
- Async multi-threaded web crawler with configurable depth and URL limits
- JavaScript-aware crawling (`crawler_js`)
- Automatic parameter discovery across all crawled URLs
- Form input extraction and endpoint mapping

### 🛡️ Advanced Capabilities
| Feature | Details |
|---------|---------|
| **API Fuzzer** | REST/GraphQL endpoint fuzzing |
| **WebSocket Scanner** | WS/WSS protocol vulnerability testing |
| **Evasion Engine** | WAF bypass techniques built-in |
| **Session Manager** | Cookie/token-aware scanning |
| **Rate Limiter** | Configurable request throttling via `governor` |
| **Cluster Mode** | Distributed scanning across nodes |
| **Plugin System** | Dynamic plugin loading via `libloading` |
| **ML Detector** | Anomaly-based detection layer |
| **Proxy Library** | Shared-library proxy middleware (`liboxide_proxy.{so,dll}`) |
| **Instagram OSINT** | Follower count, private detection, profile pic download |
| **Session Hijack Testing** | Cookie flags, fixation, token predictability |
| **Encrypted Test DB** | 2623 tests in XOR-encrypted SQLite, loaded at runtime |
| **Tokyo Night Theme** | Switch terminal palette via `oxide_build.sh --tokyo-night` |

### 📊 Reporting
- Output formats: **JSON**, **HTML**, **CSV**, **XML**
- Severity-classified findings: Critical / High / Medium / Low / Info
- Auto-download of sensitive discovered files (`--download`)
- Verbose mode with full evidence and remediation guidance

---

## 🚀 Installation

### Prerequisites
- [Rust](https://rustup.rs/) 1.75+ (2021 edition)
- Cargo (bundled with Rust)
- **Linux** (primary target) / **Windows** / **macOS**

### Build from Source

```bash
git clone https://github.com/hypersecuritylabs/oxide-communityedition-v8.3.1
cd oxide-communityedition-v8.3.1

# Quick build (default debug)
cargo build

# Release build
cargo build --release

# Or use the build script with theme customization
./oxide_build.sh --release --tokyo-night
```

The binary will be at `./target/release/oxide` or `./target/debug/oxide`.

### ⚙️ Proxy Shared Library

OXIDE requires a proxy dynamic library — `liboxide_proxy.so` (Linux) or `liboxide_proxy.dll` (Windows) — that provides proxy routing, authentication, URL obfuscation, and rotation logic. The binary **refuses to run** without it.

**Build it:**
```bash
cd oxide-proxy
cargo build --release
```

**Install it** (one of):
```bash
# Next to the binary (auto-detected)
cp oxide-proxy/target/release/liboxide_proxy.so target/release/

# System-wide (Linux)
sudo cp oxide-proxy/target/release/liboxide_proxy.so /usr/lib/

# Custom path (Linux)
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/path/to/liboxide_proxy.so
```

On **Windows**, the file is `liboxide_proxy.dll`; place it in the same directory as `oxide.exe` or set `PATH`.

### 🔒 Encrypted Test Database

OXIDE ships with a pre-built encrypted SQLite database (`cgi_database/oxide_tests.db.enc`) containing 2623 vulnerability tests across 32 categories. To rebuild it from source CSVs (private, not in repo):

```bash
# Requires the CSV source files (you must obtain them separately)
python3 tools/build_db.py
```

### Build Script

Use `oxide_build.sh` for theme customization and DB management:

```bash
# Default debug build, Gruvbox theme
./oxide_build.sh

# Tokyo Night theme + release mode
./oxide_build.sh --tokyo-night --release

# Revert to Gruvbox
./oxide_build.sh --revert-theme

# Rebuild encrypted DB from CSVs
./oxide_build.sh --build-db
```

### Optimized Release Build

The release profile is pre-configured for maximum performance:
```toml
opt-level = 3
lto = "thin"
codegen-units = 1
```

---

## 🪟 Windows Compatibility

OXIDE is built with pure Rust and **cross-compiles to Windows** via both `x86_64-pc-windows-gnu` (MinGW) and `x86_64-pc-windows-msvc` (MSVC).

| Component | Windows Status |
|-----------|---------------|
| Core scanner | ✅ Full support |
| CLI & display | ✅ Full support (colored output) |
| SQLite DB | ✅ `rusqlite` with bundled SQLite |
| HTTP client | ✅ reqwest with native-tls or rustls |
| Proxy library | ✅ Builds as `liboxide_proxy.dll` (cdylib) |
| Instagram OSINT | ✅ Pure HTTP requests |
| Session hijack | ✅ Pure HTTP requests |
| ML engine | ✅ smartcore / linfa / ndarray |
| Rate limiter | ✅ governor |
| DNS resolver | ✅ trust-dns-resolver |
| `pnet` (raw packet) | ⚠️ Limited — disable with `--no-default-features` |

**Build for Windows (cross-compile from Linux):**
```bash
# GNU toolchain (recommended — no MSVC linker required)
rustup target add x86_64-pc-windows-gnu
cargo build --release --target x86_64-pc-windows-gnu

# MSVC toolchain (requires mingw-w64 or native MSVC)
rustup target add x86_64-pc-windows-msvc
cargo build --release --target x86_64-pc-windows-msvc
```

**Or build natively on Windows:**
```powershell
cargo build --release
# Place liboxide_proxy.dll next to oxide.exe
```

**Environment variable** (Windows): `set OXIDE_DB_DIR=C:\path\to\cgi_database`

---

## 🧩 Proxy Library System

### How It Works

The proxy system is split into two parts:

**1. `oxide-proxy/` (cdylib → `liboxide_proxy.so`)**

A standalone Rust library compiled as a C-compatible dynamic library (`cdylib`) exporting 7 `extern "C"` functions:

| Export | Signature | Purpose |
|--------|-----------|---------|
| `proxy_ping` | `() -> u32` | Health check — returns version string length |
| `proxy_route` | `(target, *mut Config) -> i32` | Selects proxy type (HTTP/HTTPS/SOCKS5) based on target URL |
| `proxy_auth` | `(username, password) -> i32` | Validates and Base64-encodes proxy credentials |
| `proxy_obfuscate` | `(input, *mut buf, max_len) -> i32` | XOR (0xAA) obfuscates proxy URLs |
| `proxy_deobfuscate` | `(input, *mut buf, max_len) -> i32` | Reverses obfuscation |
| `proxy_rotation_seed` | `() -> u64` | Time-based seed for proxy rotation pool |
| `proxy_validate` | `(*const Config) -> i32` | Validates proxy configuration struct (host, port) |

The .so is built with `opt-level = "z"`, `lto = "fat"`, `panic = "abort"`, and stripped — resulting in a **278KB** binary footprint.

**2. `src/http/proxy_loader.rs` (the loader)**

Loaded at startup via `libloading`. The flow:

```
main() → ensure_proxy_library()
           │
           ├─ Finds .so (CWD → /usr/lib/ → /usr/local/lib/ → /opt/oxide/lib/ → LD_LIBRARY_PATH)
           ├─ Opens via libloading::Library
           ├─ Verifies all 7 symbols exist
           ├─ Stores Arc<Library> in OnceLock global
           └─ Prints version on success, exits on failure
```

Once loaded, safe Rust wrappers (`proxy_route()`, `proxy_auth()`, etc.) call the C ABI functions with proper `CString` marshalling. The global `OnceLock` ensures the library is loaded **once** at startup — subsequent calls are lock-free reads.

### Why a Shared Library?

- **Runtime enforcement** — binary refuses to run without it; prevents standalone binary abuse
- **Updatable independently** — replace the .so without recompiling the scanner
- **FFI sandbox** — proxy logic runs in a separate compilation unit with `panic=abort`
- **Obfuscation isolation** — XOR keys live in the .so, not in the main binary

---

## 🎯 Usage

```bash
oxide --url <TARGET> [OPTIONS]
```

### Basic Scan

```bash
oxide --url https://target.example.com
```

### Full Scan with All Modules

```bash
oxide --url https://target.example.com --modules all --threads 20 --verbose
```

### Targeted Module Scan

```bash
oxide --url https://target.example.com --modules sqli,xss,cors,tls
```

### Save Report

```bash
oxide --url https://target.example.com --output report.html --format html
```

### Zero-Day Detection Mode

```bash
oxide --url https://target.example.com --zeroday --verbose
```

### Stealth / Rate-Limited Scan

```bash
oxide --url https://target.example.com --rate-limit 5 --silent-mode
```

### With Authentication

```bash
oxide --url https://target.example.com \
  --cookie "session=abc123" \
  --header "Authorization: Bearer <token>"
```

---

## 🧰 CLI Reference

| Flag | Default | Description |
|------|---------|-------------|
| `-u, --url` | required | Target URL |
| `-t, --threads` | `10` | Concurrent worker threads |
| `-T, --timeout` | `30` | Request timeout (seconds) |
| `-o, --output` | — | Output file path |
| `-f, --format` | `json` | Report format: `json`, `html`, `csv`, `xml` |
| `--modules` | `all` | Comma-separated module list |
| `--exclude` | — | Modules to skip |
| `--exploitation-level` | `50` | Aggression level (1–100) |
| `--payload-limit` | `50` | Max payloads per endpoint |
| `--crawl-depth` | `3` | Spider recursion depth |
| `--max-urls` | `100` | Max URLs to crawl |
| `--rate-limit` | — | Requests per second cap |
| `--proxy` | — | HTTP/HTTPS proxy URL |
| `--user-agent` | — | Custom User-Agent string |
| `--cookie` | — | Session cookies |
| `--header` | — | Extra request headers (repeatable) |
| `--follow-redirects` | false | Follow HTTP redirects |
| `--insecure` | false | Disable TLS verification |
| `--download` | false | Auto-save discovered sensitive files |
| `--zeroday` | false | Enable zero-day ML detection |
| `--train` | false | Train ML classifier from live scanner results |
| `--insta` | false | Enable Instagram OSINT module |
| `--session` | false | Enable session hijack testing module |
| `--silent-mode` | false | Suppress non-essential output |
| `-v, --verbose` | false | Full verbose output |

### Available Modules

```
all · engine · static · agent · body · fingerprint · tls · common
cors · creds · sqli · xss · lfi · path-traversal · cmd-injection
blind-sqli · db-fingerprint · parameter-discovery · fuzz · insta
session · zeroday · train
```

---

## 🏗️ Architecture

```
OxideCommunityEdtionv8.3/
├── src/
│   ├── main.rs              # Entry point & banner (Gruvbox + Rosé Pine)
│   ├── hybrid.rs            # HybridScanner orchestrator (12-phase scan pipeline)
│   ├── agent.rs             # AgentPool — parallel agent-based scanning
│   ├── crawls.rs            # Async web crawler
│   ├── recon.rs             # Reconnaissance module
│   ├── db.rs                # Encrypted SQLite DB loader (XOR decrypt + rusqlite)
│   ├── filter.rs            # False-positive filter
│   ├── lib.rs               # Crate root — all `pub mod` declarations
│   │
│   ├── insta/               # Instagram OSINT
│   │   └── mod.rs           # follower_count, is_private, download_profile_pic
│   ├── session_hijack/      # Session hijack testing
│   │   └── mod.rs           # cookie flags, fixation, predictability
│   │
│   ├── core/                # Scan engine core
│   │   ├── engine.rs        # ScanEngine
│   │   ├── scanner.rs       # Scanner primitives
│   │   ├── worker.rs        # ParallelScanner + WorkerPool
│   │   ├── coordinator.rs   # Progress tracking
│   │   └── dispatcher.rs    # Parallel HTTP dispatcher
│   │
│   ├── scanner/             # Vulnerability-specific scanners
│   │   ├── sqli_scanner.rs
│   │   ├── blind_sqli_scanner.rs
│   │   ├── xss_scanner.rs
│   │   ├── lfi_scanner.rs
│   │   ├── path_traversal_scanner.rs
│   │   ├── cmd_injection_scanner.rs
│   │   ├── cors_scanner.rs
│   │   ├── tls_scanner.rs
│   │   ├── default_creds_scanner.rs
│   │   ├── common_app_scanner.rs
│   │   ├── db_fingerprinter.rs
│   │   └── precision.rs
│   │
│   ├── ai/                  # AI-powered analysis
│   │   ├── exploit_analyzer.rs
│   │   ├── response_analyzer.rs
│   │   ├── payload_mutator.rs
│   │   └── pattern_learner.rs
│   │
│   ├── zero_DAY/            # Zero-day ML detection
│   │   ├── engine.rs        # ZeroDayEngine
│   │   ├── classifier.rs    # ML classifier (Random Forest / SVM)
│   │   ├── baseline.rs      # Behavioral baseline builder
│   │   ├── anomaly.rs       # Anomaly scoring
│   │   ├── features.rs      # Feature extraction
│   │   └── trainer.rs       # ML trainer — auto-index scanners → train → export model
│   │
│   ├── advanced/            # Advanced offensive features
│   │   ├── api_fuzzer.rs
│   │   ├── evasion.rs
│   │   ├── websocket.rs
│   │   ├── cluster.rs
│   │   ├── session.rs
│   │   ├── ml_detector.rs
│   │   ├── crawler_js.rs
│   │   ├── rate_limiter.rs
│   │   ├── cache.rs
│   │   └── plugin.rs
│   │
│   ├── payload/             # Payload generation & mutation
│   │   ├── generator.rs
│   │   ├── mutator.rs
│   │   ├── fuzzer.rs
│   │   ├── encoder.rs
│   │   ├── sql_injection.rs
│   │   ├── xss.rs
│   │   ├── lfi.rs
│   │   ├── command_injection.rs
│   │   └── path_traversal.rs
│   │
│   ├── detection/           # Detection & analysis
│   │   ├── analyzer.rs      # Finding + Severity types
│   │   ├── signatures.rs    # Vulnerability signature DB
│   │   ├── behavior.rs      # Behavioral analysis
│   │   ├── timing.rs        # Time-based detection
│   │   ├── confirm.rs       # Vulnerability confirmation
│   │   └── matcher.rs
│   │
│   ├── http/                # HTTP layer
│   │   ├── client.rs        # Async HTTP client (reqwest)
│   │   ├── request.rs
│   │   ├── response.rs
│   │   ├── headers.rs
│   │   ├── cookies.rs
│   │   ├── redirect.rs
│   │   ├── tls.rs
│   │   ├── useragents.rs
│   │   └── proxy_loader.rs  # Dynamic library loader (FFI wrappers)
│   │
│   ├── report/              # Report generation
│   │   ├── generator.rs
│   │   ├── json.rs
│   │   ├── html.rs
│   │   ├── csv.rs
│   │   └── xml.rs
│   │
│   ├── cli/                 # CLI interface
│   │   ├── args.rs          # Clap argument definitions
│   │   ├── display.rs       # Terminal display engine (Gruvbox / Tokyo Night)
│   │   ├── output.rs
│   │   ├── progress.rs
│   │   ├── spinner.rs
│   │   ├── colors.rs
│   │   ├── config.rs
│   │   └── parser.rs
│   │
│   └── utils/               # Utilities
│       ├── url.rs
│       ├── encoding.rs      # Base64, hex, URL, HTML, unicode
│       ├── time.rs
│       └── downloader.rs
│
├── oxide-proxy/             # Proxy shared library (cdylib)
│   ├── Cargo.toml
│   └── src/
│       └── lib.rs           # 7 extern "C" exports
│
├── cgi_database/
│   └── oxide_tests.db.enc   # Encrypted SQLite test database (2623 tests)
│
└── tools/
    └── build_db.py          # Rebuild encrypted DB from CSV source files
```

---

## 📋 Changelog — v8.3.1

### New Features
- **Encrypted SQLite Test Database** — 2623 tests across 32 categories in a single XOR-encrypted `.db.enc` file; loaded at runtime via `rusqlite` with bundled SQLite
- **Instagram OSINT Module** (`--insta`) — Scrapes public profiles for follower count, private/verified status, bio, profile picture download
- **Session Hijack Testing** (`--session`) — OWASP best-practice cookie flag checks (HttpOnly, Secure, SameSite, Path, expiration), session fixation, token predictability
- **ML Classifier Trainer** (`--train`) — Runs TLS/CORS/CommonApp/Creds scanners against live targets, collects `(ResponseFeatures, is_vulnerable)` pairs, trains Random Forest, exports `zero_day_model.bin` + `.json`
- **Tokyo Night Theme** — Swap terminal color palette via `./oxide_build.sh --tokyo-night` (default: Gruvbox Dark + Rosé Pine accents)

### Improvements
- **Windows Cross-Compilation** — Full support for `x86_64-pc-windows-gnu` and `x86_64-pc-windows-msvc`; proxy library builds as `liboxide_proxy.dll`
- **Proxy Loader — Platform-Aware** — Auto-detects `.so` (Linux) vs `.dll` (Windows); searches `LD_LIBRARY_PATH` or `PATH` accordingly
- **Active Recon — Linux Only** — `pnet` raw TCP socket module gated behind `#[cfg(target_os = "linux")]`; passive HTTP recon runs on all platforms
- **Display Overhaul** — Gruvbox Dark color constants + Rosé Pine accents across all output; boxed severity badges, full-width completion banners, tree-style phase headers
- **Build Script** (`oxide_build.sh`) — `--tokyo-night`, `--revert-theme`, `--release`, `--build-db`, `--help`
- **Database Path** — Single `DB_DIR` constant in `src/db.rs`; configurable via `OXIDE_DB_DIR` env var

### Cleanup
- **Zero Rust Warnings** — Eliminated all 109 `dead_code` warnings; removed unused struct fields, methods, constants, and dead modules; zero `#[allow(dead_code)]`
- **Orphaned Code Removed** — Duplicate `print_scan_info` function body deleted from `main.rs`
- **Banner Simplified** — Block-art banner replaced with ASCII art from `banner` file; `/evergreen okay` tagline added
- **CSV Fallback Removed** — `common_app_scanner.rs` no longer loads individual CSV files; encrypted DB is the only data source
- **Unused Imports Cleaned** — `GB_FG`, `GB_RED_B`, `GB_AQU_B`, `GB_GRY_B`, `GB_PUR_B`, `RP_GOLD`, `RP_ROSE`, `Progress` removed from dead paths

### Security
- **XOR Encryption** — Database encrypted at rest with key tied to version (`OXIDE::v8.3.1::HyperSecurityOffensiveLabs`)
- **SQLite Magic Header Verification** — Decrypted temp file validated before opening
- **Temp File Cleanup** — Decrypted database deleted immediately after load

---

## 🧪 Test Database

OXIDE ships with a pre-built **encrypted SQLite database** (`cgi_database/oxide_tests.db.enc`) containing **2623 vulnerability tests** across **32 categories**:

- Web APIs & Microservices
- Cloud (AWS, GCP, Azure, Kubernetes)
- Infrastructure & Databases
- DevOps / CI-CD pipelines
- AI/ML endpoints
- Web3 & Blockchain
- Serverless Functions
- Legacy & Admin panels
- Mobile backends
- Supply chain endpoints
- Network infrastructure
- DoS & Stealth testing
- Breach data exposure
- Config & Secrets exposure
- Backup & Log files
- ... and more

The database is loaded at runtime, XOR-decrypted to memory, and queried via SQLite. The source CSVs are kept private; only the `.enc` file is distributed.

---

## 🔬 Tech Stack

| Crate | Purpose |
|-------|---------|
| `tokio` | Async runtime |
| `reqwest` | HTTP client (gzip, brotli, cookies) |
| `clap` | CLI argument parsing |
| `scraper` | HTML parsing & crawling |
| `smartcore` | ML algorithms (Random Forest, SVM) |
| `linfa` | ML clustering & preprocessing |
| `ndarray` | N-dimensional arrays for ML |
| `statrs` | Statistical distributions |
| `rustls` | TLS implementation |
| `trust-dns-resolver` | DNS resolution |
| `governor` | Rate limiting |
| `libloading` | Dynamic library loading (proxy .so, plugins) |
| `base64` | Proxy credential encoding |
| `serde` / `serde_json` | Serialization |
| `colored` | Terminal color output |
| `regex` | Pattern matching |
| `sha2` / `sha1` / `md5` | Cryptographic hashing |
| `uuid` | Unique scan identifiers |
| `chrono` | Timestamps & duration |
| `rusqlite` | Embedded SQLite database engine (bundled) |
| `csv` | CSV parsing (legacy fallback) |

---

## 👤 Author

<div align="center">

**khaninkali** · *HyperSecurityLabs*

[![GitHub](https://img.shields.io/badge/GitHub-hypersecuritylabs-fab41e?style=for-the-badge&logo=github&logoColor=1d2021)](https://github.com/hypersecuritylabs)
[![Website](https://img.shields.io/badge/hypersecurityoffensivelabs.great-site.net-b8bb26?style=for-the-badge&logo=google-chrome&logoColor=1d2021)](https://hypersecuritylabs.netlify.app)
[![Telegram](https://img.shields.io/badge/Telegram-hypersecurity__offsec-fe8019?style=for-the-badge&logo=telegram&logoColor=1d2021)](https://t.me/hypersecurity_offsec)

*"Scan everything. Trust nothing. Patch accordingly."*

</div>

---

## ⚖️ License & Legal

**Proprietary Software License** — Copyright © 2024 khaninkali · HyperSecurityLabs · All Rights Reserved

See [`LICENSE`](LICENSE) for full terms. In short:

| Action | Public | HyperSecurity Members |
|--------|--------|----------------------|
| View source | ✅ Yes | ✅ Yes |
| Fork for reference | ✅ Yes | ✅ Yes |
| Personal / educational use | ✅ Yes | ✅ Yes |
| Authorized pentesting | ✅ Yes | ✅ Yes |
| Modify code | ❌ No | ✅ Yes |
| Submit PRs / merge | ❌ No (may submit, no merge rights) | ✅ Yes |
| Remove name / tags / attribution | ❌ No — legal action | ❌ No — never |
| Rebrand as own work | ❌ No — legal action | ❌ No — never |
| Sell / monetize | ❌ No — written permission only | ❌ No — written permission only |
| Redistribute | ❌ No — written permission only | ✅ Yes (with attribution) |

**Only HyperSecurityLabs members may modify, merge, or redistribute this code. Removing the author name, version tags, or HyperSecurityLabs branding is a direct license violation and will result in legal action.**

> **By using OXIDE, you agree that you have obtained proper authorization for all targets
> and that you bear full legal and ethical responsibility for your actions.**

---

<div align="center">

*Built with* 🦀 *Rust · Forged in the offensive security trenches*

**HyperSecurityLabs** · OXIDE Framework v8.3.1

</div>
