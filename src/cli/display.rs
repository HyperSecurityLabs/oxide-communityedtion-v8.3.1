// ═══════════════════════════════════════════════════════════════════════════
//  OXIDE Community Edition — Terminal Display Engine
//  HyperSecurityOffensiveLabs  |  v8.3.1
//  Theme: Gruvbox Dark + Rosé Pine accents

use std::sync::atomic::{AtomicUsize, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Instant;
use colored::Colorize;
use tokio::sync::RwLock;
use crate::cli::colors::Colors;
use std::sync::atomic::AtomicBool;

const BORDER_WIDTH: usize = 78;

// ── Gruvbox Dark palette ─────────────────────────────────────────────────
pub const GB_BG:            (u8, u8, u8) = (40,  40,  40);
pub const GB_FG:            (u8, u8, u8) = (235, 219, 178);
pub const GB_FG0:           (u8, u8, u8) = (251, 241, 199);
pub const GB_RED:           (u8, u8, u8) = (204, 36,  29);
pub const GB_RED_B:         (u8, u8, u8) = (251, 73,  52);
pub const GB_GRN:           (u8, u8, u8) = (152, 151, 26);
pub const GB_GRN_B:         (u8, u8, u8) = (184, 187, 38);
pub const GB_YLW:           (u8, u8, u8) = (215, 153, 33);
pub const GB_YLW_B:         (u8, u8, u8) = (250, 189, 47);
pub const GB_BLU:           (u8, u8, u8) = (69,  133, 136);
pub const GB_BLU_B:         (u8, u8, u8) = (131, 165, 152);
pub const GB_PUR:           (u8, u8, u8) = (177, 98,  134);
pub const GB_PUR_B:         (u8, u8, u8) = (211, 134, 155);
pub const GB_AQU:           (u8, u8, u8) = (104, 157, 106);
pub const GB_AQU_B:         (u8, u8, u8) = (142, 192, 124);
pub const GB_ORG:           (u8, u8, u8) = (214, 93,  14);
pub const GB_ORG_B:         (u8, u8, u8) = (254, 128, 25);
pub const GB_GRY:           (u8, u8, u8) = (146, 131, 116);
pub const GB_GRY_B:         (u8, u8, u8) = (168, 153, 132);

// ── Rosé Pine accents ────────────────────────────────────────────────────
pub const RP_BASE: (u8, u8, u8) = (25,  23,  36);   // #191724
pub const RP_GOLD: (u8, u8, u8) = (246, 193, 119);  // #f6c177
pub const RP_ROSE: (u8, u8, u8) = (235, 188, 186);  // #ebbcba
pub const RP_PINE: (u8, u8, u8) = (49,  116, 143);  // #31748f
pub const RP_FOAM: (u8, u8, u8) = (156, 207, 216);  // #9ccfd8
pub const RP_IRIS: (u8, u8, u8) = (196, 167, 231);  // #c4a7e7
const MAX_WORKERS:  usize = 8;

// Ten-frame braille cycles
const BRAILLE:  &[&str] = &["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"];
const BRAILLE_CW: &[&str] = &["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"];
const BRAILLE_CCW: &[&str] = &["⠏","⠇","⠧","⠦","⠴","⠼","⠸","⠹","⠙","⠋"];
// Each worker gets a different starting offset so they animate independently
const WORKER_OFFSETS: &[usize] = &[0, 3, 6, 1, 4, 7, 2, 5];

// ── WorkerSlot ────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq)]
pub enum SlotState { Idle, Active, Done, Error }

struct WorkerSlot {
    state:     SlotState,
    phase:     String,          // "scan" | "SQLi" | "XSS" | "LFI" | …
    target:    String,          // current URL (truncated on render)
    spin:      AtomicU8,        // independent braille frame index
    elapsed:   Option<Instant>,
}

impl WorkerSlot {
    fn new(id: usize) -> Self {
        Self {
            state:   SlotState::Idle,
            phase:   String::new(),
            target:  String::new(),
            spin:    AtomicU8::new((WORKER_OFFSETS[id % WORKER_OFFSETS.len()]) as u8),
            elapsed: None,
        }
    }

    /// Advance and return this worker's braille frame.
    fn tick(&self) -> &'static str {
        let idx = self.spin.fetch_add(1, Ordering::Relaxed) as usize;
        BRAILLE[idx % BRAILLE.len()]
    }

    fn elapsed_str(&self) -> String {
        match self.elapsed {
            Some(t) => {
                let s = t.elapsed().as_secs();
                format!("{}:{:02}", s / 60, s % 60)
            }
            None => String::new(),
        }
    }

    fn render_row(&self, id: usize, is_last: bool) -> String {
        let prefix = if is_last { "└" } else { "├" };
        let base = format!(
            "\x1B[2K  \x1B[38;2;255;140;0m{}\x1B[0m \x1B[97mA{:<2}\x1B[0m",
            prefix, id,
        );
        match self.state {
            SlotState::Idle => {
                format!(
                    "{} \x1B[90m·\x1B[0m  \x1B[90m{:<6}\x1B[0m  \x1B[90m{:─<44}\x1B[0m  \x1B[90m{:>4}\x1B[0m",
                    base, "idle", "", "--:--",
                )
            }
            SlotState::Active => {
                let spin  = self.tick();
                let phase = if self.phase.len() > 6 { &self.phase[..6] } else { &self.phase };
                let tgt   = truncate_url(&self.target, 44);
                let ela   = self.elapsed_str();
                format!(
                    "{} \x1B[92m{}\x1B[0m  \x1B[96m{:<6}\x1B[0m  \x1B[90m{}\x1B[0m  \x1B[90m{:>4}\x1B[0m",
                    base, spin, phase, tgt, ela,
                )
            }
            SlotState::Done => {
                format!(
                    "{} \x1B[92m+\x1B[0m  \x1B[92m{:<6}\x1B[0m  \x1B[90m{:─<44}\x1B[0m  \x1B[90m{:>4}\x1B[0m",
                    base, "done", "", self.elapsed_str(),
                )
            }
            SlotState::Error => {
                format!(
                    "{} \x1B[91m-\x1B[0m  \x1B[91m{:<6}\x1B[0m  \x1B[90m{}\x1B[0m  \x1B[90m{:>4}\x1B[0m",
                    base, "err", truncate_url(&self.phase, 44), self.elapsed_str(),
                )
            }
        }
    }
}

fn truncate_url(url: &str, max: usize) -> String {
    if url.len() <= max { return url.to_string(); }
    format!("…{}", &url[url.len().saturating_sub(max - 1)..])
}

// ─── Animated scan bar ────────────────────────────────────────────────────
// When active, renders a moving light-green pulse across the bar.
// Normal mode: static filled/unfilled segments.

fn render_scan_bar(_pct: usize, filled: usize, light_pos: &AtomicUsize, active: bool) -> String {
    if !active || filled == 0 {
        let empty = 20usize.saturating_sub(filled);
        return format!("\x1B[92m{}\x1B[90m{}\x1B[0m",
            "=".repeat(filled), "-".repeat(empty));
    }
    // Active mode: moving light pulse
    let pos = light_pos.fetch_add(1, Ordering::Relaxed) % (filled * 2 - 2).max(1);
    let light = if pos < filled { pos } else { (filled * 2 - 2) - pos };
    let mut out = String::with_capacity(20);
    for i in 0..20 {
        if i < filled {
            if i == light {
                out.push_str("\x1B[92;1m█\x1B[0m");
            } else if i.abs_diff(light) <= 1 {
                out.push_str("\x1B[92m▓\x1B[0m");
            } else if i.abs_diff(light) <= 2 {
                out.push_str("\x1B[92m▒\x1B[0m");
            } else {
                out.push_str("\x1B[92m░\x1B[0m");
            }
        } else {
            out.push_str("\x1B[90m─\x1B[0m");
        }
    }
    out
}

// ── ScanBoard ─────────────────────────────────────────────────────────────────

pub struct ScanBoard {
    slots:           RwLock<Vec<WorkerSlot>>,
    start:           Instant,
    total:           AtomicUsize,
    pub(crate) done: AtomicUsize,
    findings:        AtomicUsize,
    errors:          AtomicUsize,
    spin_idx:        AtomicUsize,
    lines_on_screen: AtomicUsize,
    light_pos:       AtomicUsize,
    active:          AtomicBool,
}

impl ScanBoard {
    pub fn new(worker_count: usize) -> Arc<Self> {
        let n = worker_count.min(MAX_WORKERS);
        let slots = (0..n).map(WorkerSlot::new).collect();
        Arc::new(Self {
            slots:           RwLock::new(slots),
            start:           Instant::now(),
            total:           AtomicUsize::new(0),
            done:            AtomicUsize::new(0),
            findings:        AtomicUsize::new(0),
            errors:          AtomicUsize::new(0),
            spin_idx:        AtomicUsize::new(0),
            lines_on_screen: AtomicUsize::new(0),
            light_pos:       AtomicUsize::new(0),
            active:          AtomicBool::new(false),
        })
    }

    pub fn set_total(&self, n: usize) { self.total.store(n, Ordering::Relaxed); }

    pub async fn worker_start(&self, id: usize, phase: &str, target: &str) {
        let mut slots = self.slots.write().await;
        if let Some(s) = slots.get_mut(id) {
            s.state   = SlotState::Active;
            s.phase   = phase.to_string();
            s.target  = target.to_string();
            if s.elapsed.is_none() { s.elapsed = Some(Instant::now()); }
        }
    }

    pub async fn worker_done(&self, id: usize, found: usize) {
        let mut slots = self.slots.write().await;
        if let Some(s) = slots.get_mut(id) { s.state = SlotState::Done; }
        self.findings.fetch_add(found, Ordering::Relaxed);
    }

    pub async fn worker_error(&self, id: usize, msg: String) {
        let mut slots = self.slots.write().await;
        if let Some(s) = slots.get_mut(id) {
            s.state = SlotState::Error;
            s.phase = msg[..msg.len().min(20)].to_string();
        }
        self.errors.fetch_add(1, Ordering::Relaxed);
        self.done.fetch_add(1, Ordering::Relaxed);
    }

    // ── Rendering ─────────────────────────────────────────────────────────────

    /// Build the full block string. All N worker slots are always rendered so the
    /// block height is deterministic (1 header + N rows). This guarantees that
    /// `redraw()` can always move the cursor up by the exact same number of lines.
    pub async fn render_block(&self) -> String {
        let slots    = self.slots.read().await;
        let elapsed  = self.start.elapsed();
        let done     = self.done.load(Ordering::Relaxed);
        let total    = self.total.load(Ordering::Relaxed);
        let findings = self.findings.load(Ordering::Relaxed);
        let errors   = self.errors.load(Ordering::Relaxed);
        let mins     = elapsed.as_secs() / 60;
        let secs     = elapsed.as_secs() % 60;

        // Header spinner
        let spin = {
            let idx = self.spin_idx.fetch_add(1, Ordering::Relaxed);
            BRAILLE[idx % BRAILLE.len()]
        };

        let pct    = if total > 0 { ((done * 100) / total).min(100) } else { 0 };
        let filled = ((pct * 20) / 100).min(20);
        let bar    = render_scan_bar(pct, filled, &self.light_pos, self.active.load(Ordering::Relaxed));

        let vuln_s = if findings > 0 {
            format!("\x1B[91;1m{}\x1B[0m", findings)
        } else {
            format!("\x1B[90m{}\x1B[0m", findings)
        };
        let err_s = if errors > 0 {
            format!("\x1B[93m{}\x1B[0m", errors)
        } else {
            format!("\x1B[90m{}\x1B[0m", errors)
        };

        // Header line (always present)
        let header = format!(
            "\x1B[2K{} {}  [{}]  \x1B[97m{}/{}\x1B[0m \x1B[90m({}%)\x1B[0m  \
             \x1B[91mVULN:\x1B[0m{}  \x1B[90merr:\x1B[0m{}  \x1B[90m{:02}:{:02}\x1B[0m",
            Colors::warning(spin),
            Colors::brand("OXIDE"),
            bar,
            done, total, pct,
            vuln_s, err_s,
            mins, secs,
        );

        // Always render ALL slots — even idle are shown as dim placeholders.
        // This guarantees block height = 1 + worker_count, always the same.
        let row_count = slots.len();
        let mut out = header;
        let last = row_count.saturating_sub(1);
        for (id, slot) in slots.iter().enumerate() {
            out.push('\n');
            out.push_str(&slot.render_row(id, id == last));
        }

        self.lines_on_screen.store(1 + row_count, Ordering::Relaxed);
        out
    }

    pub async fn print_finding_live(&self, severity: &str, title: &str, url: &str) {
        let sev   = sev_badge(severity);
        let url_s = truncate_url(url, 55);
        let prev  = self.lines_on_screen.load(Ordering::Relaxed);

        if prev > 0 { print!("\x1B[{}A\x1B[0G", prev); }
        print!("\x1B[2K");
        println!("  {} \x1B[97m{}\x1B[0m  \x1B[90m{}\x1B[0m", sev, title, url_s);

        let block = self.render_block().await;
        println!("{}", block);
        std::io::Write::flush(&mut std::io::stdout()).ok();
    }

    pub async fn render_height(&self) -> usize {
        self.lines_on_screen.load(Ordering::Relaxed)
    }
    pub async fn render(&self)      -> String { self.render_block().await }
}

// ── AgentBar ──────────────────────────────────────────────────────────────────
//
// Fixed N-line block for AgentPool — same in-place redraw as ScanBoard but
// dedicated to the agent scan phase. Supports up to 8 agents.
//
//   ⠹ AGENTS  [========------------]  42/100 (42%)  done:38  err:2  01:23
//   ├ ⠙ A0  scan   https://target.com/admin          0:04
//   └ ⠸ A1  scan   https://target.com/login          0:02

pub struct AgentBar {
    slots:           RwLock<Vec<WorkerSlot>>,
    start:           Instant,
    total:           AtomicUsize,
    done:            AtomicUsize,
    errors:          AtomicUsize,
    findings:        AtomicUsize,
    spin_idx:        AtomicUsize,
    lines_on_screen: AtomicUsize,
    light_pos:       AtomicUsize,
    active:          AtomicBool,
}

impl AgentBar {
    pub fn new(agent_count: usize) -> Arc<Self> {
        let n = agent_count.min(MAX_WORKERS);
        let slots = (0..n).map(WorkerSlot::new).collect();
        Arc::new(Self {
            slots:           RwLock::new(slots),
            start:           Instant::now(),
            total:           AtomicUsize::new(0),
            done:            AtomicUsize::new(0),
            errors:          AtomicUsize::new(0),
            findings:        AtomicUsize::new(0),
            spin_idx:        AtomicUsize::new(0),
            lines_on_screen: AtomicUsize::new(0),
            light_pos:       AtomicUsize::new(0),
            active:          AtomicBool::new(false),
        })
    }

    pub fn set_active(&self) { self.active.store(true, Ordering::Relaxed); }

    pub fn set_total(&self, n: usize) { self.total.store(n, Ordering::Relaxed); }

    pub async fn agent_start_with_phase(&self, id: usize, phase: &str, url: &str) {
        let mut slots = self.slots.write().await;
        if let Some(s) = slots.get_mut(id) {
            s.state  = SlotState::Active;
            s.phase  = phase.to_string();
            s.target = url.to_string();
            if s.elapsed.is_none() { s.elapsed = Some(Instant::now()); }
        }
    }

    pub async fn agent_done(&self, id: usize, found: usize) {
        let mut slots = self.slots.write().await;
        if let Some(s) = slots.get_mut(id) { s.state = SlotState::Done; }
        self.findings.fetch_add(found, Ordering::Relaxed);
    }

    pub async fn agent_error(&self, id: usize) {
        let mut slots = self.slots.write().await;
        if let Some(s) = slots.get_mut(id) { s.state = SlotState::Error; }
        self.errors.fetch_add(1, Ordering::Relaxed);
    }

    pub async fn add_finding(&self) {
        self.findings.fetch_add(1, Ordering::Relaxed);
    }

    pub fn progress_tick(&self) {
        self.done.fetch_add(1, Ordering::Relaxed);
    }

    async fn render_block(&self) -> String {
        let slots    = self.slots.read().await;
        let elapsed  = self.start.elapsed();
        let done     = self.done.load(Ordering::Relaxed);
        let total    = self.total.load(Ordering::Relaxed);
        let errors   = self.errors.load(Ordering::Relaxed);
        let findings = self.findings.load(Ordering::Relaxed);
        let mins     = elapsed.as_secs() / 60;
        let secs     = elapsed.as_secs() % 60;

        let spin_idx = self.spin_idx.fetch_add(1, Ordering::Relaxed);
        let cw = BRAILLE_CW[spin_idx % 10];
        let ccw = BRAILLE_CCW[spin_idx % 10];

        let pct    = if total > 0 { ((done * 100) / total).min(100) } else { 0 };
        let filled = ((pct * 20) / 100).min(20);
        let bar    = render_scan_bar(pct, filled, &self.light_pos, self.active.load(Ordering::Relaxed));

        let vuln_s = if findings > 0 {
            format!("\x1B[91;1m{}\x1B[0m", findings)
        } else {
            format!("\x1B[90m{}\x1B[0m", findings)
        };

        let header = format!(
            "\x1B[2K\x1B[92m{}\x1B[0m\x1B[92m{}\x1B[0m \x1B[38;2;255;140;0m[+]\x1B[0m\x1B[97mAGENTS\x1B[0m  [{}]  \
             \x1B[97m{}/{}\x1B[0m \x1B[90m({}%)\x1B[0m  \
             \x1B[91mVULN:\x1B[0m{}  \x1B[90merr:{}\x1B[0m  \x1B[90m{:02}:{:02}\x1B[0m",
            cw, ccw, bar, done, total, pct, vuln_s, errors, mins, secs,
        );

        // Always render ALL slots for deterministic height
        let row_count = slots.len();
        let mut out = header;
        let last = row_count.saturating_sub(1);
        for (id, slot) in slots.iter().enumerate() {
            out.push('\n');
            out.push_str(&slot.render_row(id, id == last));
        }

        self.lines_on_screen.store(1 + row_count, Ordering::Relaxed);
        out
    }

    pub async fn draw_initial(&self) {
        let block = self.render_block().await;
        print!("{}\n", block);
        std::io::Write::flush(&mut std::io::stdout()).ok();
    }

    pub async fn redraw(&self) {
        let prev = self.lines_on_screen.load(Ordering::Relaxed);
        if prev > 0 { print!("\x1B[{}A\x1B[0G", prev); }
        let block = self.render_block().await;
        println!("{}", block);
        std::io::Write::flush(&mut std::io::stdout()).ok();
    }

    /// Print a finding above the agent block.
    pub async fn print_finding(&self, severity: &str, title: &str, url: &str) {
        let sev   = sev_badge(severity);
        let url_s = truncate_url(url, 55);
        let prev  = self.lines_on_screen.load(Ordering::Relaxed);
        if prev > 0 { print!("\x1B[{}A\x1B[0G", prev); }
        print!("\x1B[2K");
        println!("  {} \x1B[97m{}\x1B[0m  \x1B[90m{}\x1B[0m", sev, title, url_s);
        let block = self.render_block().await;
        println!("{}", block);
        std::io::Write::flush(&mut std::io::stdout()).ok();
    }

    pub fn finish(&self) {
        let elapsed  = self.start.elapsed();
        let done     = self.done.load(Ordering::Relaxed);
        let findings = self.findings.load(Ordering::Relaxed);
        let errors   = self.errors.load(Ordering::Relaxed);
        println!();
        println!(
            "\x1B[38;2;255;140;0m[+]\x1B[0m\x1B[97mAGENTS\x1B[0m  \
             \x1B[97m{} scanned\x1B[0m  \x1B[91mVULN:{}\x1B[0m  \
             \x1B[90merr:{}  {:02}:{:02}\x1B[0m",
            done, findings, errors,
            elapsed.as_secs() / 60, elapsed.as_secs() % 60,
        );
    }
}

fn sev_badge(severity: &str) -> &'static str {
    match severity.to_uppercase().as_str() {
        "CRITICAL" => "\x1B[91;1m[CRIT]\x1B[0m",
        "HIGH"     => "\x1B[91m[HIGH]\x1B[0m",
        "MEDIUM"   => "\x1B[93m[MED ]\x1B[0m",
        "LOW"      => "\x1B[92m[LOW ]\x1B[0m",
        _          => "\x1B[90m[INFO]\x1B[0m",
    }
}

// ── Output ────────────────────────────────────────────────────────────────────

pub struct Output;

impl Output {
    pub fn print_header(title: &str) {
        let rule = "═".repeat(BORDER_WIDTH);
        println!("\n{}", rule.truecolor(GB_YLW_B.0, GB_YLW_B.1, GB_YLW_B.2));
        println!("  {}", title.truecolor(GB_FG0.0, GB_FG0.1, GB_FG0.2).bold());
        println!("{}", rule.truecolor(GB_YLW_B.0, GB_YLW_B.1, GB_YLW_B.2));
    }
    pub fn print_section(title: &str) {
        println!("  {}", title.truecolor(GB_BLU_B.0, GB_BLU_B.1, GB_BLU_B.2).underline());
    }
    pub fn print_line() {
        println!("{}", "─".repeat(BORDER_WIDTH).truecolor(GB_GRY.0, GB_GRY.1, GB_GRY.2));
    }
    pub fn print_progress(current: usize, total: usize, vulns: usize, elapsed: &str) {
        let pct    = if total > 0 { (current * 100) / total } else { 0 };
        let filled = (pct * 30) / 100;
        let bar    = format!("{}{}", "=".repeat(filled), "·".repeat(30usize.saturating_sub(filled)));
        println!("  {} {}%  {}  {} vulns  {}",
            format!("[{:.>30}]", bar).truecolor(GB_AQU_B.0, GB_AQU_B.1, GB_AQU_B.2),
            format!("{:>3}", pct).truecolor(GB_YLW.0, GB_YLW.1, GB_YLW.2),
            format!("{:>4}/{}", current, total).truecolor(GB_FG.0, GB_FG.1, GB_FG.2),
            vulns.to_string().truecolor(GB_RED_B.0, GB_RED_B.1, GB_RED_B.2).bold(),
            elapsed.truecolor(GB_GRY.0, GB_GRY.1, GB_GRY.2));
    }
    pub fn print_finding_stylish(severity: &str, title: &str, url: &str, evidence: &str) {
        let (sev_col, badge) = match severity {
            "Critical" => (GB_RED_B, "▌CRITICAL▐"),
            "High"     => (GB_RED,   "▌ HIGH   ▐"),
            "Medium"   => (GB_YLW,   "▌ MEDIUM ▐"),
            "Low"      => (GB_AQU,   "▌ LOW    ▐"),
            "Info"     => (GB_BLU,   "▌ INFO   ▐"),
            _          => (GB_GRY,   "▌ UNKNOWN▐"),
        };
        println!("  {} {}",
            badge.truecolor(sev_col.0, sev_col.1, sev_col.2).bold(),
            title.truecolor(GB_FG0.0, GB_FG0.1, GB_FG0.2));
        println!("    {} {}", "└─".truecolor(GB_GRY.0, GB_GRY.1, GB_GRY.2),
            url.truecolor(GB_BLU_B.0, GB_BLU_B.1, GB_BLU_B.2).italic());
        if !evidence.is_empty() {
            println!("      {}", evidence.truecolor(GB_GRY.0, GB_GRY.1, GB_GRY.2));
        }
    }
    pub fn print_scan_complete(duration: &str, total_requests: usize, findings: &[crate::detection::analyzer::Finding]) {
        let rule = "━".repeat(BORDER_WIDTH);
        println!("\n{}", rule.truecolor(GB_GRN_B.0, GB_GRN_B.1, GB_GRN_B.2));
        println!("  {}  {}",
            "◈".truecolor(RP_GOLD.0, RP_GOLD.1, RP_GOLD.2),
            "SCAN COMPLETE".truecolor(GB_FG0.0, GB_FG0.1, GB_FG0.2).bold());
        println!("{}", rule.truecolor(GB_GRN_B.0, GB_GRN_B.1, GB_GRN_B.2));

        let critical = findings.iter().filter(|f| matches!(f.severity, crate::detection::analyzer::Severity::Critical)).count();
        let high     = findings.iter().filter(|f| matches!(f.severity, crate::detection::analyzer::Severity::High)).count();
        let medium   = findings.iter().filter(|f| matches!(f.severity, crate::detection::analyzer::Severity::Medium)).count();
        let low      = findings.iter().filter(|f| matches!(f.severity, crate::detection::analyzer::Severity::Low)).count();
        let info     = findings.iter().filter(|f| matches!(f.severity, crate::detection::analyzer::Severity::Info)).count();

        println!("  {} {}  {} {}  {} {}  {} {}  {} {}",
            "◉".truecolor(GB_RED_B.0, GB_RED_B.1, GB_RED_B.2),
            format!("{:>2} critical", critical).truecolor(GB_RED_B.0, GB_RED_B.1, GB_RED_B.2),
            "◉".truecolor(GB_RED.0, GB_RED.1, GB_RED.2),
            format!("{:>2} high", high).truecolor(GB_RED.0, GB_RED.1, GB_RED.2),
            "◉".truecolor(GB_YLW.0, GB_YLW.1, GB_YLW.2),
            format!("{:>2} medium", medium).truecolor(GB_YLW.0, GB_YLW.1, GB_YLW.2),
            "◉".truecolor(GB_AQU.0, GB_AQU.1, GB_AQU.2),
            format!("{:>2} low", low).truecolor(GB_AQU.0, GB_AQU.1, GB_AQU.2),
            "◉".truecolor(GB_BLU.0, GB_BLU.1, GB_BLU.2),
            format!("{:>2} info", info).truecolor(GB_BLU.0, GB_BLU.1, GB_BLU.2),
        );
        println!("  {} {}  {} {}",
            "⏱".truecolor(RP_GOLD.0, RP_GOLD.1, RP_GOLD.2),
            format!("Duration: {}", duration).truecolor(GB_FG.0, GB_FG.1, GB_FG.2),
            "⚑".truecolor(GB_GRN_B.0, GB_GRN_B.1, GB_GRN_B.2),
            format!("Requests: {}", total_requests).truecolor(GB_FG.0, GB_FG.1, GB_FG.2),
        );
        println!("{}\n", rule.truecolor(GB_GRN_B.0, GB_GRN_B.1, GB_GRN_B.2));
    }
}
