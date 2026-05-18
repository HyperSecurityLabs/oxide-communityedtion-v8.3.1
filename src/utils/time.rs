use std::time::{Duration, Instant, SystemTime};
use chrono::{DateTime, Local, Utc};

pub struct TimeUtil;

impl TimeUtil {
    pub fn now() -> DateTime<Local> {
        Local::now()
    }

    pub fn now_utc() -> DateTime<Utc> {
        Utc::now()
    }

    pub fn format_timestamp(dt: &DateTime<Local>) -> String {
        dt.format("%Y-%m-%d %H:%M:%S").to_string()
    }

    pub fn format_timestamp_iso(dt: &DateTime<Utc>) -> String {
        dt.to_rfc3339()
    }

    pub fn elapsed_since(start: Instant) -> Duration {
        start.elapsed()
    }

    pub fn format_duration(duration: Duration) -> String {
        let secs = duration.as_secs();
        let mins = secs / 60;
        let secs = secs % 60;
        let millis = duration.subsec_millis();
        
        if mins > 0 {
            format!("{}m {}s", mins, secs)
        } else {
            format!("{}.{:03}s", secs, millis)
        }
    }

    pub fn sleep(duration: Duration) {
        std::thread::sleep(duration);
    }

    pub async fn sleep_async(duration: Duration) {
        tokio::time::sleep(duration).await;
    }

    pub fn timeout<F, T>(duration: Duration, future: F) -> tokio::time::Timeout<F>
    where
        F: std::future::Future<Output = T>,
    {
        tokio::time::timeout(duration, future)
    }

    pub fn unix_timestamp() -> i64 {
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    }
}
