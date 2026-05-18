use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub struct Downloader {
    base_dir: PathBuf,
}

impl Downloader {
    pub fn new(target_url: &str) -> Self {
        let domain = target_url
            .replace("https://", "")
            .replace("http://", "")
            .split('/')
            .next()
            .unwrap_or("unknown")
            .replace(':', "_");

        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let base_dir = PathBuf::from(format!("downloads/{}_{}", domain, ts));
        Self { base_dir }
    }

    pub fn base_dir(&self) -> &Path { &self.base_dir }
}
