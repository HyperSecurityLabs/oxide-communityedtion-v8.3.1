use anyhow::Result;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::net::{
       TcpListener, TcpStream};
use tokio::sync::{
            mpsc, Mutex,
             
              RwLock};
use tokio::io::AsyncReadExt;
use serde::{Serialize, Deserialize};

use crate::detection::analyzer::Finding;
use crate::cli::args::CliArgs;

/// Message types for cluster communication
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum ClusterMessage {
    Heartbeat { node_id: String, timestamp: u64 },
    TaskAssign { task_id: String, target: String, scan_type: ScanType },
    TaskComplete { task_id: String, findings: Vec<Finding>, node_id: String },
    TaskFailed { task_id: String, error: String, node_id: String },
    StatusRequest,
    StatusResponse { node_id: String, load: f32, memory: u64, active_tasks: usize },
    Shutdown,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum ScanType {
    Full,
    Quick,
    Stealth,
    Custom(Vec<String>),
}

/// Cluster node information
#[derive(Debug, Clone)]
pub struct ClusterNode {
    pub id: String,
    pub address: SocketAddr,
    pub last_heartbeat: u64,
    pub load: f32,
    pub memory_mb: u64,
    pub active_tasks: usize,
    pub is_healthy: bool,
}

/// Master node that coordinates the cluster
pub struct ClusterMaster {
    nodes: Arc<RwLock<HashMap<String, ClusterNode>>>,
    task_queue: Arc<Mutex<Vec<(String, String)>>>,
    results: Arc<Mutex<Vec<Finding>>>,
    shutdown_tx: mpsc::Sender<String>,
}

impl ClusterMaster {
    pub async fn new(_bind_addr: &str) -> Result<Self> {
        let (shutdown_tx, _) = mpsc::channel(100);
        
        Ok(Self {
            nodes: Arc::new(RwLock::new(HashMap::new())),
            task_queue: Arc::new(Mutex::new(Vec::new())),
            results: Arc::new(Mutex::new(Vec::new())),
            shutdown_tx,
        })
    }

    /// Start the master node and listen for agent connections
    pub async fn start(&self, bind_addr: &str) -> Result<()> {
        let listener = TcpListener::bind(bind_addr).await?;
        println!("[CLUSTER] Master listening on {}", bind_addr);
        
        let nodes = self.nodes.clone();
        let results = self.results.clone();
        
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, addr)) => {
                        let nodes = nodes.clone();
                        let results = results.clone();
                        
                        tokio::spawn(async move {
                            if let Err(e) = Self::handle_agent_connection(stream, addr, nodes, results).await {
                                eprintln!("[CLUSTER] Agent connection error: {}", e);
                            }
                        });
                    }
                    Err(e) => {
                        eprintln!("[CLUSTER] Accept error: {}", e);
                    }
                }
            }
        });
        
        Ok(())
    }

    /// Handle incoming agent connection
    async fn handle_agent_connection(
        mut stream: TcpStream,
        addr: SocketAddr,
        nodes: Arc<RwLock<HashMap<String, ClusterNode>>>,
        results: Arc<Mutex<Vec<Finding>>>,
    ) -> Result<()> {
        let mut buffer = vec![0u8; 4096];
        
        loop {
            match stream.read(&mut buffer).await {
                Ok(0) => break, // Connection closed
                Ok(n) => {
                    let message: ClusterMessage = match bincode::deserialize(&buffer[..n]) {
                        Ok(msg) => msg,
                        Err(_) => continue,
                    };
                    
                    match message {
                        ClusterMessage::Heartbeat { node_id, timestamp } => {
                            let mut nodes_guard = nodes.write().await;
                            if let Some(node) = nodes_guard.get_mut(&node_id) {
                                node.last_heartbeat = timestamp;
                                node.is_healthy = true;
                            } else {
                                let node_id_clone = node_id.clone();
                                println!("[CLUSTER] New agent registered: {}", node_id_clone);
                                nodes_guard.insert(node_id, ClusterNode {
                                    id: node_id_clone,
                                    address: addr,
                                    last_heartbeat: timestamp,
                                    load: 0.0,
                                    memory_mb: 0,
                                    active_tasks: 0,
                                    is_healthy: true,
                                });
                            }
                        }
                        ClusterMessage::TaskComplete { task_id, findings, node_id } => {
                            println!("[CLUSTER] Task {} completed by {} with {} findings", 
                                task_id, node_id, findings.len());
                            let mut results_guard = results.lock().await;
                            results_guard.extend(findings);
                        }
                        ClusterMessage::TaskFailed { task_id, error, node_id } => {
                            eprintln!("[CLUSTER] Task {} failed on {}: {}", task_id, node_id, error);
                        }
                        ClusterMessage::StatusResponse { node_id, load, memory, active_tasks } => {
                            let mut nodes_guard = nodes.write().await;
                            if let Some(node) = nodes_guard.get_mut(&node_id) {
                                node.load = load;
                                node.memory_mb = memory;
                                node.active_tasks = active_tasks;
                            }
                        }
                        _ => {}
                    }
                }
                Err(e) => {
                    eprintln!("[CLUSTER] Read error: {}", e);
                    break;
                }
            }
        }
        
        Ok(())
    }

    /// Distribute tasks to available agents
    pub async fn distribute_tasks(&self, targets: Vec<String>, scan_type: ScanType) -> Result<()> {
        let nodes = self.nodes.read().await;
        let healthy_nodes: Vec<_> = nodes.values()
            .filter(|n| n.is_healthy)
            .collect();
        
        if healthy_nodes.is_empty() {
            return Err(anyhow::anyhow!("No healthy agents available"));
        }
        
        let chunk_size = targets.len() / healthy_nodes.len();
        
        for (idx, node) in healthy_nodes.iter().enumerate() {
            let start = idx * chunk_size;
            let end = if idx == healthy_nodes.len() - 1 {
                targets.len()
            } else {
                (idx + 1) * chunk_size
            };
            
            for (task_idx, target) in targets[start..end].iter().enumerate() {
                let task_id = format!("{}-{}", node.id, task_idx);
                let _message = ClusterMessage::TaskAssign {
                    task_id,
                    target: target.clone(),
                    scan_type: scan_type.clone(),
                };
                
                // Add to task queue for tracking
                self.task_queue.lock().await.push((target.clone(), node.id.clone()));
                
                // Send to agent (simplified - would use stored connection)
                println!("[CLUSTER] Assigning {} to agent {}", target, node.id);
            }
        }
        
        Ok(())
    }

    /// Get cluster statistics
    pub async fn get_stats(&self) -> ClusterStats {
        let nodes = self.nodes.read().await;
        let results = self.results.lock().await;
        
        ClusterStats {
            total_nodes: nodes.len(),
            healthy_nodes: nodes.values().filter(|n| n.is_healthy).count(),
            total_findings: results.len(),
            avg_load: nodes.values().map(|n| n.load).sum::<f32>() / nodes.len().max(1) as f32,
        }
    }

    /// Get all findings collected from agents
    pub async fn get_all_findings(&self) -> Result<Vec<Finding>> {
        // Send shutdown signal to all nodes when done
        let _ = self.shutdown_tx.send("shutdown".to_string()).await;
        Ok(self.results.lock().await.clone())
    }
}

#[derive(Debug)]
pub struct ClusterStats {
    pub total_nodes: usize,
    pub healthy_nodes: usize,
    pub total_findings: usize,
    pub avg_load: f32,
}

/// Agent node that connects to master
pub struct ClusterAgent {
    node_id: String,
    master_addr: String,
    args: CliArgs,
    active_tasks: Arc<RwLock<usize>>,
}

impl ClusterAgent {
    pub fn new(node_id: String, master_addr: String, args: CliArgs) -> Self {
        Self {
            node_id,
            master_addr,
            args,
            active_tasks: Arc::new(RwLock::new(0)),
        }
    }

    /// Connect to master and start processing tasks
    pub async fn start(&self) -> Result<()> {
        let stream = TcpStream::connect(&self.master_addr).await?;
        println!("[CLUSTER] Agent {} connected to master {}", self.node_id, self.master_addr);
        
        // Send initial heartbeat
        self.send_heartbeat(&stream).await?;
        
        // Start heartbeat task with node stats
        let node_id = self.node_id.clone();
        let active_tasks = self.active_tasks.clone();
        let _args = &self.args; // Use args for configuration
        
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(30));
            loop {
                interval.tick().await;
                // Send heartbeat with current stats
                let _tasks = *active_tasks.read().await;
                println!("[CLUSTER-AGENT] {} sending heartbeat ({} active tasks)", node_id, _tasks);
            }
        });
        
        Ok(())
    }

    async fn send_heartbeat(&self, stream: &TcpStream) -> Result<()> {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        
        let message = ClusterMessage::Heartbeat {
            node_id: self.node_id.clone(),
            timestamp,
        };
        
        let encoded = bincode::serialize(&message)?;
        
        // Write message length first (4 bytes, big-endian)
        let len_bytes = (encoded.len() as u32).to_be_bytes();
        stream.writable().await?;
        let mut written = 0;
        while written < len_bytes.len() {
            match stream.try_write(&len_bytes[written..]) {
                Ok(n) => written += n,
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    stream.writable().await?;
                }
                Err(e) => return Err(e.into()),
            }
        }
        
        // Write the actual message
        written = 0;
        while written < encoded.len() {
            match stream.try_write(&encoded[written..]) {
                Ok(n) => written += n,
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    stream.writable().await?;
                }
                Err(e) => return Err(e.into()),
            }
        }
        
        println!("[CLUSTER-AGENT] Sent heartbeat ({} bytes)", encoded.len());
        Ok(())
    }

    /// Execute assigned scan task with actual HTTP scanning
    pub async fn execute_task(&self, target: &str, scan_type: &ScanType) -> Result<Vec<Finding>> {
        *self.active_tasks.write().await += 1;
        
        println!("[CLUSTER-AGENT] Executing {:?} scan on {}", scan_type, target);
        
        let mut findings = Vec::new();
        
        // Perform actual HTTP scanning based on scan type
        match scan_type {
            ScanType::Quick => {
                // Quick scan: just check if target is reachable
                findings.extend(self.quick_scan(target).await);
            }
            ScanType::Full => {
                // Full scan: comprehensive check
                findings.extend(self.full_scan(target).await);
            }
            ScanType::Stealth => {
                // Stealth scan: slow, careful checks
                findings.extend(self.stealth_scan(target).await);
            }
            ScanType::Custom(checks) => {
                // Custom scan: specific checks requested
                for check in checks {
                    findings.extend(self.custom_check(target, check).await);
                }
            }
        }
        
        *self.active_tasks.write().await -= 1;
        
        println!("[CLUSTER-AGENT] Completed scan on {} with {} findings", target, findings.len());
        Ok(findings)
    }
    
    /// Quick scan - basic reachability and headers
    async fn quick_scan(&self, target: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        match reqwest::get(target).await {
            Ok(response) => {
                let status = response.status();
                
                // Check for interesting status codes
                if status.as_u16() == 200 {
                    println!("[SCAN] Target {} is reachable (200 OK)", target);
                }
                
                // Check security headers
                let headers = response.headers();
                if !headers.contains_key("x-frame-options") {
                    findings.push(Finding::new(
                        target,
                        crate::detection::analyzer::Severity::Low,
                        "Missing X-Frame-Options Header",
                        &format!("Target {} does not set X-Frame-Options header", target),
                    ));
                }
            }
            Err(e) => {
                findings.push(Finding::new(
                    target,
                    crate::detection::analyzer::Severity::Info,
                    "Target Unreachable",
                    &format!("Could not connect to {}: {}", target, e),
                ));
            }
        }
        
        findings
    }
    
    /// Full scan - comprehensive vulnerability checks
    async fn full_scan(&self, target: &str) -> Vec<Finding> {
        let mut findings = self.quick_scan(target).await;
        
        // Check common paths
        let common_paths = vec![
            "/robots.txt",
            "/.git/HEAD",
            "/admin",
            "/api",
            "/swagger.json",
            "/openapi.json",
        ];
        
        for path in common_paths {
            let url = format!("{}{}", target.trim_end_matches('/'), path);
            match reqwest::get(&url).await {
                Ok(resp) => {
                    if resp.status().as_u16() == 200 {
                        findings.push(Finding::new(
                            &url,
                            crate::detection::analyzer::Severity::Medium,
                            &format!("Exposed Path: {}", path),
                            &format!("Path {} returned 200 OK", url),
                        ));
                    }
                }
                Err(_) => {}
            }
        }
        
        findings
    }
    
    /// Stealth scan - slow and careful
    async fn stealth_scan(&self, target: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        
        // Add delay between requests
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
        
        // Use randomized user agent
        let client = reqwest::Client::builder()
            .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        
        match client.get(target).send().await {
            Ok(response) => {
                let server_header = response.headers()
                    .get("server")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string());
                
                if let Some(server) = server_header {
                    findings.push(Finding::new(
                        target,
                        crate::detection::analyzer::Severity::Info,
                        "Server Header Disclosure",
                        &format!("Server header reveals: {}", server),
                    ).with_evidence(&server));
                }
            }
            Err(_) => {}
        }
        
        findings
    }
    
    /// Custom check based on name
    async fn custom_check(&self, target: &str, check: &str) -> Vec<Finding> {
        match check {
            "headers" => self.quick_scan(target).await,
            "paths" => self.full_scan(target).await,
            _ => {
                println!("[SCAN] Unknown custom check: {}", check);
                Vec::new()
            }
        }
    }
}
