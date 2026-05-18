use anyhow::Result;
use std::sync::Arc;
use tokio::sync::mpsc::Sender;

use crate::cli::args::CliArgs;
use crate::cli::spinner::Spinner;
use crate::http::client::HttpClient;
use crate::http::request::HttpRequest;
use crate::http::response::HttpResponse;
use crate::payload::generator::PayloadGenerator;

pub struct Scanner {
    client: Arc<HttpClient>,
    args: CliArgs,
    payload_gen: PayloadGenerator,
    tx: Sender<ScanResult>,
}

#[derive(Clone, Debug)]
pub struct ScanResult {
    pub url: String,
    pub status: u16,
    pub response: Option<HttpResponse>,
    pub payload: String,
}

impl Scanner {
    pub fn new(
        client: Arc<HttpClient>,
        args: CliArgs,
        payload_gen: PayloadGenerator,
        tx: Sender<ScanResult>,
    ) -> Self {
        Self {
            client,
            args,
            payload_gen,
            tx,
        }
    }

    pub async fn scan(&self) -> Result<()> {
        let paths = self.payload_gen.generate_paths();
        let params = self.payload_gen.generate_params();
        let headers = self.payload_gen.generate_headers();

        self.scan_paths(&paths).await?;
        self.scan_params(&params).await?;
        self.scan_headers(&headers).await?;

        Ok(())
    }

    async fn scan_paths(&self, paths: &[String]) -> Result<()> {
        let spinner = Spinner::path_spinner();

        for path in paths {
            let url = format!("{}{}", self.args.url, path);
            let request = HttpRequest::get(&url);

            match self.client.send(request).await {
                Ok(response) => {
                    let result = ScanResult {
                        url: url.clone(),
                        status: response.status,
                        response: Some(response),
                        payload: path.clone(),
                    };
                    let _ = self.tx.send(result).await;
                }
                Err(_) => {
                    let result = ScanResult {
                        url: url.clone(),
                        status: 0,
                        response: None,
                        payload: path.clone(),
                    };
                    let _ = self.tx.send(result).await;
                }
            }

            let _ = spinner.next();
        }

        Ok(())
    }

    async fn scan_params(&self, params: &[String]) -> Result<()> {
        let spinner = Spinner::param_spinner();

        for param in params {
            let url = format!("{}?{}", self.args.url, param);
            let request = HttpRequest::get(&url);

            match self.client.send(request).await {
                Ok(response) => {
                    let result = ScanResult {
                        url: url.clone(),
                        status: response.status,
                        response: Some(response),
                        payload: param.clone(),
                    };
                    let _ = self.tx.send(result).await;
                }
                Err(_) => {}
            }

            let _ = spinner.next();
        }

        Ok(())
    }

    pub fn generate_payloads(&self) -> Vec<String> {
        self.payload_gen.generate_paths()
    }

    async fn scan_headers(&self, headers: &[String]) -> Result<()> {
        let spinner = Spinner::header_spinner();

        for header_str in headers {
            let mut request = HttpRequest::get(&self.args.url);

            if let Some((key, value)) = header_str.split_once(':') {
                request.add_header(key.trim(), value.trim());
            }

            match self.client.send(request).await {
                Ok(response) => {
                    let result = ScanResult {
                        url: self.args.url.clone(),
                        status: response.status,
                        response: Some(response),
                        payload: header_str.clone(),
                    };
                    let _ = self.tx.send(result).await;
                }
                Err(_) => {}
            }

            let _ = spinner.next();
        }

        Ok(())
    }

    pub async fn scan_body(&self, payloads: &[String]) -> Result<()> {
        for payload in payloads {
            let url = format!("{}", self.args.url);

            let _test_post = self.client.post(&url, payload).await;

            let request = HttpRequest::post(&url, payload);

            match self.client.send(request).await {
                Ok(response) => {
                    let result = ScanResult {
                        url: url.clone(),
                        status: response.status,
                        response: Some(response),
                        payload: payload.clone(),
                    };
                    let _ = self.tx.send(result).await;
                }
                Err(_) => {}
            }
        }
        Ok(())
    }
}
