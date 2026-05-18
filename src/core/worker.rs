use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::RwLock;

use crate::cli::args::CliArgs;
use crate::cli::display::ScanBoard;
use crate::core::scanner::ScanResult;
use crate::detection::analyzer::{Analyzer, Finding, Severity};
use crate::http::client::HttpClient;
use crate::http::request::HttpRequest;
use crate::utils::url::UrlUtil;

pub struct ParallelScanner {
    client:  Arc<HttpClient>,
    args:    CliArgs,
    workers: usize,
}

impl ParallelScanner {
    pub fn new(client: Arc<HttpClient>, args: CliArgs, workers: usize) -> Self {
        Self { client, args, workers: workers.max(1) }
    }

    pub async fn run(&self, urls: Vec<String>, board: Arc<ScanBoard>) -> Vec<Finding> {
        if urls.is_empty() { return Vec::new(); }
        let total     = urls.len();
        let effective = self.workers.min(total).max(1);
        board.set_total(total);
        let urls         = Arc::new(urls);
        let cursor       = Arc::new(AtomicUsize::new(0));
        let all_findings = Arc::new(RwLock::new(Vec::<Finding>::new()));
        let mut handles  = Vec::new();

        let worker_phases = ["recon", "sqli", "xss", "lfi", "cmdi", "crawl", "cors", "fuzz"];

        for wid in 0..effective {
            let client       = self.client.clone();
            let args         = self.args.clone();
            let urls         = urls.clone();
            let cursor       = cursor.clone();
            let board        = board.clone();
            let findings_out = all_findings.clone();

            handles.push(tokio::spawn(async move {
                let analyzer = Analyzer::new();
                loop {
                    let idx = cursor.fetch_add(1, Ordering::Relaxed);
                    if idx >= urls.len() { break; }
                    let url = &urls[idx];
                    let phase = worker_phases[wid % worker_phases.len()];
                    board.worker_start(wid, phase, url).await;
                    match client.send(HttpRequest::get(url)).await {
                        Ok(response) => {
                            let scan_result = ScanResult {
                                url:            url.clone(),
                                status:         response.status,
                                response:       Some(response),
                                payload:        String::new(),
                            };
                            if let Some(finding) = analyzer.analyze(scan_result).await {
                                board.print_finding_live(
                                    &format!("{:?}", finding.severity),
                                    &finding.title, url,
                                ).await;
                                findings_out.write().await.push(finding);
                            }
                            Self::probe_vulns(&client, &args, url, wid, &board, &findings_out).await;
                            board.done.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(e) => { board.worker_error(wid, e.to_string()).await; }
                    }
                }
                board.worker_done(wid, 0).await;
            }));
        }

        let _ = board.render().await;
        loop {
            tokio::time::sleep(std::time::Duration::from_millis(120)).await;
            let h = board.render_height().await;
            if h > 0 { print!("\x1B[{}A\x1B[0G", h); }
            println!("{}", board.render().await);
            std::io::Write::flush(&mut std::io::stdout()).ok();
            if board.done.load(Ordering::Relaxed) >= total { break; }
        }
        let h = board.render_height().await;
        if h > 0 { print!("\x1B[{}A\x1B[0G", h); }
        println!("{}", board.render().await);

        for handle in handles { let _ = handle.await; }
        Arc::try_unwrap(all_findings).map(|rw| rw.into_inner()).unwrap_or_default()
    }

    async fn probe_vulns(
        client:   &Arc<HttpClient>,
        args:     &CliArgs,
        base_url: &str,
        wid:      usize,
        board:    &Arc<ScanBoard>,
        findings: &Arc<RwLock<Vec<Finding>>>,
    ) {
        let probes: &[(&str, &str, &str)] = &[
            ("SQLi", "'",                        "sql syntax"),
            ("SQLi", "' OR '1'='1",              "sql syntax"),
            ("XSS",  "<script>alert(1)</script>", "<script>alert(1)</script>"),
            ("LFI",  "../../../../etc/passwd",    "root:x:"),
            ("LFI",  "..%2F..%2Fetc%2Fpasswd",   "root:x:"),
        ];

        let mut params = UrlUtil::extract_query_param_names(base_url);
        if params.is_empty() {
            params = vec![
                "id".into(), "q".into(), "page".into(),
                "file".into(), "url".into(), "name".into(),
                "cat".into(), "dir".into(), "path".into(),
            ];
        }

        for param in &params {
            for &(label, payload, indicator) in probes {
                let probe_url = UrlUtil::inject_param(base_url, param, &urlencoding::encode(payload));
                board.worker_start(wid, label, base_url).await;
                if let Ok(resp) = client.send(HttpRequest::get(&probe_url)).await {
                    if resp.body.to_lowercase().contains(&indicator.to_lowercase()) {
                        let finding = Finding::new(
                            base_url, Severity::High,
                            &format!("{} detected", label),
                            &format!("Payload `{}` on param `{}` triggered `{}`", payload, param, indicator),
                        )
                        .with_evidence(&format!("probe: {}", probe_url))
                        .with_remediation("Sanitize all user-supplied input.");
                        board.print_finding_live(
                            &format!("{:?}", finding.severity), &finding.title, base_url,
                        ).await;
                        findings.write().await.push(finding);
                    }
                }
                if let Some(rate) = args.rate_limit {
                    if rate > 0 {
                        tokio::time::sleep(
                            std::time::Duration::from_millis(1000 / rate as u64)
                        ).await;
                    }
                }
            }
        }
    }
}
