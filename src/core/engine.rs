use anyhow::Result;
use std::sync::Arc;
use tokio::sync::mpsc;

use crate::cli::args::CliArgs;
use crate::http::client::HttpClient;
use crate::payload::generator::PayloadGenerator;
use crate::detection::analyzer::Analyzer;
use crate::report::generator::ReportGenerator;

pub struct ScanEngine {
    args: CliArgs,
    client: Arc<HttpClient>,
    payload_gen: PayloadGenerator,
    analyzer: Analyzer,
    reporter: ReportGenerator,
}

impl ScanEngine {
    pub fn new(args: CliArgs) -> Result<Self> {
        let client = HttpClient::new(args.timeout, args.insecure)
            .map_err(|e| anyhow::anyhow!("Failed to create HTTP client: {}", e))?;
        let client = Arc::new(client);

        let payload_gen = PayloadGenerator::new();
        let analyzer = Analyzer::new();
        let reporter = ReportGenerator::new(&args.format);

        Ok(Self {
            args,
            client,
            payload_gen,
            analyzer,
            reporter,
        })
    }

    pub async fn run(&self) -> Result<()> {
        println!("Starting scan on: {}", self.args.url);
        println!("Threads: {} | Timeout: {}s", self.args.threads, self.args.timeout);
        println!();

        let (tx, mut rx) = mpsc::channel(100);

        let scanner = crate::core::scanner::Scanner::new(
            self.client.clone(),
            self.args.clone(),
            self.payload_gen.clone(),
            tx,
        );

        let analyze_task = tokio::spawn({
            let analyzer = self.analyzer.clone();
            let output_path = self.args.output.clone();
            let mut reporter = self.reporter.clone();
            
            async move {
                while let Some(result) = rx.recv().await {
                    let finding = analyzer.analyze(result).await;
                    if let Some(finding) = finding {
                        reporter.add_finding(finding);
                    }
                }
                
                if let Some(path) = output_path {
                    let _ = reporter.save(&path);
                }
            }
        });

        scanner.scan().await?;
        
        let _ = analyze_task.await;

        Ok(())
    }
}
