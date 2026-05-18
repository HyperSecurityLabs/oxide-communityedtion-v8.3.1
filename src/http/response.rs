use anyhow::{Context, Result};
use reqwest::Response as ReqwestResponse;
use std::collections::HashMap;

#[derive(Clone, Debug)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: HashMap<String, String>,
    pub body: String,
}

impl HttpResponse {
    pub async fn from_reqwest(response: ReqwestResponse) -> Result<Self> {
        let status = response.status().as_u16();
        
        let headers: HashMap<String, String> = response
            .headers()
            .iter()
            .filter_map(|(k, v)| {
                v.to_str()
                    .ok()
                    .map(|val| (k.to_string(), val.to_string()))
            })
            .collect();

        let body = response
            .text()
            .await
            .with_context(|| "Failed to read response body")?;

        Ok(Self {
            status,
            headers,
            body,
        })
    }

    pub fn is_success(&self) -> bool {
        self.status >= 200 && self.status < 300
    }

    pub fn is_server_error(&self) -> bool {
        self.status >= 500 && self.status < 600
    }

    pub fn get_header(&self, name: &str) -> Option<&String> {
        self.headers.get(name).or_else(|| {
            self.headers.get(&name.to_lowercase())
        })
    }

    pub fn server_header(&self) -> Option<&String> {
        self.get_header("Server")
    }

    pub fn powered_by(&self) -> Option<&String> {
        self.get_header("X-Powered-By")
    }

    /// Calculate the approximate size of the response in bytes
    /// Includes: status line (HTTP version + status code + reason) + headers + body
    pub fn size_bytes(&self) -> u64 {
        // Status line: "HTTP/1.1 200 OK\r\n" (approximation based on status code digits)
        let status_digits = if self.status == 0 { 3 } else { self.status.to_string().len() };
        let status_line = 9 + status_digits + 1 + 2 + 2; // "HTTP/1.1 " + status + " " + "OK" + "\r\n"

        // Headers size: "Key: Value\r\n" for each header
        let headers_size: usize = self.headers.iter()
            .map(|(k, v)| k.len() + 2 + v.len() + 2) // "Key: Value\r\n"
            .sum();

        // Body size
        let body_size = self.body.len();

        // Final CRLF before body
        let terminator = 2; // \r\n

        (status_line + headers_size + body_size + terminator) as u64
    }
}
