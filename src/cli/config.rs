use anyhow::{Context, Result};
use serde::{
    Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Config {
    pub threads: usize,
    pub timeout: u64,
    pub user_agent: String,
    pub follow_redirects: bool,
    pub max_redirects: usize,
    pub insecure: bool,
    pub rate_limit: Option<u32>,
    pub modules: Vec<String>,
    pub headers: HashMap<String, String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            threads: 20,
            timeout: 30,
            user_agent: "OXIDE/1.0.0".to_string(),
            follow_redirects: true,
            max_redirects: 10,
            insecure: false,
            rate_limit: None,
            modules: vec!["all".to_string()],
            headers: HashMap::new(),
        }
    }
}

impl Config {
    pub fn load(path: &PathBuf) -> Result<Self> {
        let content = fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file: {}", path.display()))?;
        
        let config: Config = toml::from_str(&content)
            .with_context(|| "Failed to parse config file")?;
        
        Ok(config)
    }

    pub fn save(&self, path: &PathBuf) -> Result<()> {
        let content = toml::to_string_pretty(self)
            .with_context(|| "Failed to serialize config")?;
        
        fs::write(path, content)
            .with_context(|| format!("Failed to write config file: {}", path.display()))?;
        
        Ok(())
    }

    pub fn add_header(&mut self, key: &str, value: &str) {
        self.headers.insert(key.to_string(), value.to_string());
    }

    pub fn get_headers(&self) -> &HashMap<String, String> {
        &self.headers
    }
}
