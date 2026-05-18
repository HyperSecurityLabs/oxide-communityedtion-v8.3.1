use crate::http::client::HttpClient;
use std::sync::Arc;

pub struct Dispatcher;

impl Dispatcher {
    pub fn new(_client: Arc<HttpClient>, _max_concurrent: usize) -> Self {
        Self
    }
}
