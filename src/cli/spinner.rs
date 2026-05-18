use std::sync::atomic::{AtomicUsize, Ordering};

/// Braille-dot spinner with per-instance phase offset so parallel workers
/// animate independently without synchronizing.
pub struct Spinner {
    frames: &'static [&'static str],
    current: AtomicUsize,
}

// All frame sets are static slices — no heap allocation per spinner.
static FRAMES_CW:  &[&str] = &["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"];
static FRAMES_CCW: &[&str] = &["⠏","⠇","⠧","⠦","⠴","⠼","⠸","⠹","⠙","⠋"];
static FRAMES_A:   &[&str] = &["⠧","⠦","⠴","⠼","⠸","⠹","⠙","⠋","⠏","⠇"];
static FRAMES_B:   &[&str] = &["⠼","⠴","⠦","⠧","⠇","⠏","⠋","⠙","⠹","⠸"];
static FRAMES_C:   &[&str] = &["⠸","⠹","⠙","⠋","⠏","⠇","⠧","⠦","⠴","⠼"];

impl Clone for Spinner {
    fn clone(&self) -> Self {
        Self {
            frames: self.frames,
            current: AtomicUsize::new(self.current.load(Ordering::Relaxed)),
        }
    }
}

impl Spinner {
    fn new(frames: &'static [&'static str]) -> Self {
        Self { frames, current: AtomicUsize::new(0) }
    }

    // ── Named constructors ────────────────────────────────────────────────────

    pub fn path_spinner()   -> Self { Self::new(FRAMES_CW) }
    pub fn param_spinner()  -> Self { Self::new(FRAMES_CCW) }
    pub fn header_spinner() -> Self { Self::new(FRAMES_A) }
    pub fn vuln_spinner()   -> Self { Self::new(FRAMES_B) }
    pub fn finger_spinner() -> Self { Self::new(FRAMES_C) }

    // ── Advance / read ────────────────────────────────────────────────────────

    /// Advance and return the next frame.
    pub fn next(&self) -> &'static str {
        let idx = self.current.fetch_add(1, Ordering::Relaxed) % self.frames.len();
        self.frames[idx]
    }


}
