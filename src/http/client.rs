//! i need the result at any cost so i use anyhow 
use anyhow::{Context, Result};
use reqwest::{Client, ClientBuilder};
use std::time::Duration;
/// Special Dependency
use super::request::HttpRequest;
use super::response::HttpResponse;
use super::useragents::UserAgentPool;

pub struct HttpClient {
    client:   Client,
    ua_pool:  UserAgentPool,
}

impl HttpClient {
    pub fn new(timeout_secs: u64, insecure: bool) -> Result<Self> {
        let client = Self::build_client(timeout_secs, insecure)?;
        Ok(Self {
            client,
            ua_pool:  UserAgentPool::full(),
        })
    }

    fn build_client(timeout_secs: u64, insecure: bool) -> Result<Client> {
        ClientBuilder::new()
            .timeout(Duration::from_secs(timeout_secs))
            .danger_accept_invalid_certs(insecure)
            .build()
            .with_context(|| "Failed to build HTTP client")
    }

    pub async fn send(&self, request: HttpRequest) -> Result<HttpResponse> {
        let ua = self.ua_pool.next();
        let (accept, accept_lang, accept_enc) = UserAgentPool::accept_headers_for(ua);

        let mut req = self.client.request(request.method.clone(), request.url.as_str())
            .header("User-Agent",      ua)
            .header("Accept",          accept)
            .header("Accept-Language", accept_lang)
            .header("Accept-Encoding", accept_enc);

        // Request-level headers override the defaults above
        for (key, value) in &request.headers {
            req = req.header(key, value);
        }
        if let Some(body) = &request.body {
            req = req.body(body.clone());
        }
        let response = req
            .send()
            .await
            .with_context(|| format!("Failed to send request to {}", request.url))?;
        HttpResponse::from_reqwest(response).await
    }

    pub async fn get(&self, url: &str) -> Result<HttpResponse> {
        self.send(HttpRequest::get(url)).await
    }

    pub async fn post(&self, url: &str, body: &str) -> Result<HttpResponse> {
        self.send(HttpRequest::post(url, body)).await
    }
}
