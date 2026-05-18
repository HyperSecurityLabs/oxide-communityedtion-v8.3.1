use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Thread-safe scan progress tracker with per-severity vuln counters,
/// bytes-transferred accounting, and ETA calculation.
pub struct Progress {
    pub total: usize,
    current:   AtomicUsize,
    // Severity buckets
    critical:  AtomicUsize,
    high:      AtomicUsize,
    medium:    AtomicUsize,
    low:       AtomicUsize,
    info:      AtomicUsize,
    // Network accounting
    bytes_tx:  AtomicU64,
    bytes_rx:  AtomicU64,
    requests:  AtomicUsize,
    errors:    AtomicUsize,
    start_time: Instant,
}

impl Progress {
    pub fn new(total: usize) -> Self {
        Self {
            total,
            current:    AtomicUsize::new(0),
            critical:   AtomicUsize::new(0),
            high:       AtomicUsize::new(0),
            medium:     AtomicUsize::new(0),
            low:        AtomicUsize::new(0),
            info:       AtomicUsize::new(0),
            bytes_tx:   AtomicU64::new(0),
            bytes_rx:   AtomicU64::new(0),
            requests:   AtomicUsize::new(0),
            errors:     AtomicUsize::new(0),
            start_time: Instant::now(),
        }
    }

    // ── Counters ──────────────────────────────────────────────────────────────

    pub fn increment(&self) { self.current.fetch_add(1, Ordering::Relaxed); }

    pub fn add_critical(&self) { self.critical.fetch_add(1, Ordering::Relaxed); }
    pub fn add_high(&self)     { self.high.fetch_add(1, Ordering::Relaxed); }
    pub fn add_medium(&self)   { self.medium.fetch_add(1, Ordering::Relaxed); }
    pub fn add_low(&self)      { self.low.fetch_add(1, Ordering::Relaxed); }
    pub fn add_info(&self)     { self.info.fetch_add(1, Ordering::Relaxed); }
    pub fn add_request(&self)  { self.requests.fetch_add(1, Ordering::Relaxed); }

    // ── Reads ─────────────────────────────────────────────────────────────────

    pub fn get_current(&self)  -> usize { self.current.load(Ordering::Relaxed) }
    pub fn get_total(&self)    -> usize { self.total }
    pub fn get_vulns(&self)    -> usize { self.get_critical() + self.get_high() + self.get_medium() + self.get_low() }
    pub fn get_critical(&self) -> usize { self.critical.load(Ordering::Relaxed) }
    pub fn get_high(&self)     -> usize { self.high.load(Ordering::Relaxed) }
    pub fn get_medium(&self)   -> usize { self.medium.load(Ordering::Relaxed) }
    pub fn get_low(&self)      -> usize { self.low.load(Ordering::Relaxed) }
    pub fn get_info_count(&self) -> usize { self.info.load(Ordering::Relaxed) }
    pub fn get_errors(&self)   -> usize { self.errors.load(Ordering::Relaxed) }
    pub fn get_requests(&self) -> usize { self.requests.load(Ordering::Relaxed) }
    pub fn get_bytes_tx(&self) -> u64   { self.bytes_tx.load(Ordering::Relaxed) }
    pub fn get_bytes_rx(&self) -> u64   { self.bytes_rx.load(Ordering::Relaxed) }
    pub fn get_elapsed(&self)  -> Duration { self.start_time.elapsed() }

    pub fn get_percent(&self) -> usize {
        if self.total == 0 { return 0; }
        ((self.get_current() * 100) / self.total).min(100)
    }

    pub fn is_complete(&self) -> bool { self.get_current() >= self.total }

    pub fn get_elapsed_string(&self) -> String {
        let s = self.get_elapsed().as_secs();
        format!("{:02}:{:02}", s / 60, s % 60)
    }

    pub fn clone_arc(self) -> Arc<Self> { Arc::new(self) }
}

impl Clone for Progress {
    fn clone(&self) -> Self {
        Self {
            total:      self.total,
            current:    AtomicUsize::new(self.get_current()),
            critical:   AtomicUsize::new(self.get_critical()),
            high:       AtomicUsize::new(self.get_high()),
            medium:     AtomicUsize::new(self.get_medium()),
            low:        AtomicUsize::new(self.get_low()),
            info:       AtomicUsize::new(self.get_info_count()),
            bytes_tx:   AtomicU64::new(self.get_bytes_tx()),
            bytes_rx:   AtomicU64::new(self.get_bytes_rx()),
            requests:   AtomicUsize::new(self.get_requests()),
            errors:     AtomicUsize::new(self.get_errors()),
            start_time: self.start_time,
        }
    }
}
