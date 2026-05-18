// ═══════════════════════════════════════════════════════════════════════════
//  OXIDE Framework — Agent Pool  v8.2.0
//  HyperSecurityOffensiveLabs
//
//  AgentPool distributes URLs across up to 8 concurrent ScanAgents.
//  Live display uses AgentBar — a fixed N+1 line block with per-agent
//  Very difficult
//  braille spinners. Findings print above the block and scroll into history.
// ═══════════════════════════════════════════════════════════════════════════

use anyhow::Result;
use std::sync::Arc;
use std::time::Duration;
// Arc mutex Coordination For data and threads Acess 
/// System Engineering
 
use tokio::sync::{
       mpsc, Semaphore,
        RwLock};

use crate::cli::args::CliArgs;
use crate::cli::display::AgentBar;
use crate::http::client::HttpClient;
use crate::http::request::HttpRequest;
use crate::http::response::HttpResponse;
                           
use crate::core::scanner::ScanResult;
use crate::detection::analyzer::{
                       Analyzer, Finding};
use crate::cli::progress::Progress;
use tokio::time::Instant;

const MAX_AGENTS: usize = 8;

// ── ScanAgent ─────────────────────────────────────────────────────────────────

pub struct ScanAgent {
    id:             usize,
    client:         Arc<HttpClient>,
    analyzer:       Analyzer,
    semaphore:      Arc<Semaphore>,
    progress:       Arc<Progress>,
    tx:             mpsc::Sender<AgentResult>,
    current_target: Arc<RwLock<Option<String>>>,
    is_working:     Arc<RwLock<bool>>,
}

#[derive(Clone, Debug)]
pub struct AgentResult {
    pub finding:       Option<Finding>,
    pub error:         Option<String>,
}

impl ScanAgent {
    pub fn new(
        id: usize,
        client: Arc<HttpClient>,
        semaphore: Arc<Semaphore>,
        progress: Arc<Progress>,
        tx: mpsc::Sender<AgentResult>,
    ) -> Self {
        Self {
            id,
            client,
            analyzer:       Analyzer::new(),
            semaphore,
            progress,
            tx,
            current_target: Arc::new(RwLock::new(None)),
            is_working:     Arc::new(RwLock::new(false)),
        }
    }

    pub async fn scan_target(&self, target: &str, bar: &Arc<AgentBar>) -> Result<AgentResult> {
        *self.is_working.write().await = true;
        *self.current_target.write().await = Some(target.to_string());

        let _permit = self.semaphore.acquire().await?;
        let start   = Instant::now();

        let phase = match self.id % 8 {
            0 => "recon",
            1 => "sqli",
            2 => "xss",
            3 => "lfi",
            4 => "cmdi",
            5 => "crawl",
            6 => "cors",
            _ => "fuzz",
        };
        bar.agent_start_with_phase(self.id, phase, target).await;

        let result = match self.client.send(HttpRequest::get(target)).await {
            Ok(response) => {
                let _response_time = start.elapsed();
                let finding = self.analyze_response(target, &response).await;

                if let Some(ref f) = finding {
                    bar.print_finding(&format!("{:?}", f.severity), &f.title, target).await;
                    bar.add_finding().await;
                }

                AgentResult {
                    finding,
                    error:    None,
                }
            }
            Err(e) => {
                bar.agent_error(self.id).await;
                AgentResult {
                    finding:       None,
                    error:         Some(e.to_string()),
                }
            }
        };

        *self.is_working.write().await = false;
        *self.current_target.write().await = None;

        self.progress.increment();
        let _ = self.tx.send(result.clone()).await;
        Ok(result)
    }

    async fn analyze_response(&self, url: &str, response: &HttpResponse) -> Option<Finding> {
        let scan_result = ScanResult {
            url:            url.to_string(),
            status:         response.status,
            response:       Some(response.clone()),
            payload:        String::new(),
        };
        self.analyzer.analyze(scan_result).await
    }

    pub async fn scan_batch(&self, targets: &[String], bar: &Arc<AgentBar>) -> Vec<Result<AgentResult>> {
        let mut results = Vec::new();
        for target in targets {
            results.push(self.scan_target(target, bar).await);
        }
        results
    }
}

// ── AgentPool ─────────────────────────────────────────────────────────────────

pub struct AgentPool {
    agents:    Vec<ScanAgent>,
    semaphore: Arc<Semaphore>,
    progress:  Arc<Progress>,
    rx:        mpsc::Receiver<AgentResult>,
    active:    bool,
}

impl AgentPool {
    pub fn new(args: &CliArgs, agent_count: usize, total_targets: usize) -> Result<Self> {
        let n      = agent_count.min(MAX_AGENTS).max(1);
        let client = Arc::new(HttpClient::new(args.timeout, args.insecure)?);
        let sem    = Arc::new(Semaphore::new(args.threads.min(MAX_AGENTS)));
        let prog   = Arc::new(Progress::new(total_targets));
        let (tx, rx) = mpsc::channel(256);

        let agents = (0..n)
            .map(|id| ScanAgent::new(id, client.clone(), sem.clone(), prog.clone(), tx.clone()))
            .collect();

        Ok(Self { agents, semaphore: sem, progress: prog, rx, active: args.active })
    }

    pub async fn run_scan(&mut self, targets: Vec<String>) -> Result<Vec<Finding>> {
        if targets.is_empty() {
            return Ok(Vec::new());
        }

        let num_targets    = targets.len();
        let effective      = self.agents.len().min(num_targets).max(1);
        let chunk_size     = (num_targets + effective - 1) / effective;

        // Shared AgentBar — all agents write to it, animation loop reads it
        let bar = AgentBar::new(effective);
        if self.active { bar.set_active(); }
        bar.set_total(num_targets);
        bar.draw_initial().await;

        // Spawn one task per agent
        let mut handles = Vec::new();
        for idx in 0..effective {
            let start = idx * chunk_size;
            let end   = ((idx + 1) * chunk_size).min(num_targets);
            let chunk: Vec<String> = targets[start..end].to_vec();

            let agent = ScanAgent::new(
                idx,
                self.agents[idx].client.clone(),
                self.agents[idx].semaphore.clone(),
                self.agents[idx].progress.clone(),
                self.agents[idx].tx.clone(),
            );
            let bar_clone = bar.clone();

            handles.push(tokio::spawn(async move {
                let results = agent.scan_batch(&chunk, &bar_clone).await;
                bar_clone.agent_done(idx, results.iter().filter(|r| r.is_ok()).count()).await;
                results
            }));
        }

        // Animation loop — redraw every 120ms while agents work
        let bar_anim = bar.clone();
        let anim_handle = tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(120)).await;
                bar_anim.redraw().await;
            }
        });

        let mut all_findings = Vec::new();
        let mut completed    = 0;
        let mut error_count  = 0;

        while completed < num_targets {
            match tokio::time::timeout(Duration::from_millis(50), self.rx.recv()).await {
                Ok(Some(result)) => {
                    if let Some(f) = result.finding {
                        all_findings.push(f);
                    }
                    if result.error.is_some() { error_count += 1; }
                    completed += 1;
                    bar.progress_tick();
                }
                Ok(None) => break,
                Err(_)   => {
                    if self.progress.is_complete() { break; }
                }
            }
        }

        anim_handle.abort();
        for h in handles { let _ = h.await; }

        // Final redraw + summary
        bar.redraw().await;
        bar.finish();

        if error_count > 0 {
            eprintln!("\x1B[90m[AGENTS] {} errors during scan\x1B[0m", error_count);
        }

        Ok(all_findings)
    }

    pub fn get_progress(&self) -> &Arc<Progress> { &self.progress }

    pub fn get_available_permits(&self) -> usize { self.semaphore.available_permits() }
}
