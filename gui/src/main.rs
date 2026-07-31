//! **SOV Red Team** — a STANDALONE desktop application for the adversarial harness.
//!
//! This is its OWN app, deliberately separate from the wallet / node daemon. It reuses
//! the `sov-redteam` engine library (`run_all()`) — the exact same attacks the CLI runs
//! — and renders them as a live security console. Run it, hit "Run red team", and watch
//! it build a real in-process chain and attack the actual consensus code.
//!
//!   cargo run -p sov-redteam-gui        (or: sov-redteam-gui)
//!
//! The GUI is presentation only. Every verdict on screen is the `Verdict` the engine
//! returned for that attack; the app never invents, upgrades or suppresses one.

#![forbid(unsafe_code)]
// egui's API is uniformly f32; the fallback on float literals is intentional here.
#![allow(unknown_lints)]
#![allow(float_literal_f32_fallback)]

mod theme;
mod viz;

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use eframe::egui::{self, Align2, Color32, FontId, Margin, RichText, Rounding, Sense, Stroke};

use theme::{alpha, BORDER, GOLD, GROUND, HOLD, INK, MUTED, ON_ACCENT, PANEL, PQ, SURFACE, THREAT};
use viz::{Fate, Viz};

/// One attack, snapshotted out from under the report mutex so the drawing code
/// never holds a lock. Exactly the engine's four fields — nothing derived.
type Snap = Vec<(&'static str, &'static str, sov_redteam::Verdict, String)>;

fn snap(outcomes: &[sov_redteam::Outcome]) -> Snap {
    outcomes
        .iter()
        .map(|o| (o.category, o.name, o.verdict, o.detail.clone()))
        .collect()
}

/// Which probe the content area is showing. The Gauntlet is first — it attacks the real
/// live pot.
#[derive(Clone, Copy, PartialEq, Eq)]
enum View {
    Gauntlet,
    Funded,
    FrontDoor,
    BackDoor,
    InProcess,
}

impl View {
    const ALL: [View; 5] = [
        View::Gauntlet,
        View::Funded,
        View::FrontDoor,
        View::BackDoor,
        View::InProcess,
    ];
    fn icon(self) -> &'static str {
        match self {
            View::Gauntlet => "🏆",
            View::Funded => "₿",
            View::FrontDoor => "⌁",
            View::BackDoor => "⛒",
            View::InProcess => "⚔",
        }
    }
    fn label(self) -> &'static str {
        match self {
            View::Gauntlet => "The Gauntlet",
            View::Funded => "Funded adversary",
            View::FrontDoor => "Front door",
            View::BackDoor => "Back door",
            View::InProcess => "In-process",
        }
    }
    fn accent(self) -> Color32 {
        match self {
            View::Gauntlet | View::Funded => GOLD,
            View::FrontDoor => PQ,
            View::BackDoor => THREAT,
            View::InProcess => HOLD,
        }
    }
}

struct RedTeamApp {
    /// The probe currently shown in the content area.
    view: View,
    /// Index of the attack card the theatre is showing, within the active view.
    /// Cleared when the view changes or results are reset.
    selected: Option<usize>,
    // The Gauntlet: attack the live steal-the-pot account, no key.
    gauntlet_report: Arc<Mutex<Option<sov_redteam::GauntletReport>>>,
    gauntlet_running: Arc<AtomicBool>,
    // In-process battery: attack a private replica of consensus.
    results: Arc<Mutex<Option<Vec<sov_redteam::Outcome>>>>,
    running: Arc<AtomicBool>,
    // Live front-door probe: submit adversarial txs to a REAL node's RPC.
    target: String,
    live_report: Arc<Mutex<Option<sov_redteam::LiveReport>>>,
    live_running: Arc<AtomicBool>,
    // Live back-door probe: join P2P as a hostile peer and gossip forged blocks/txs.
    backdoor_report: Arc<Mutex<Option<sov_redteam::P2pReport>>>,
    backdoor_running: Arc<AtomicBool>,
    // Funded-adversary probe: attack AS a real funded account (key pasted at runtime).
    funded_key_input: String,
    funded_seed: Option<[u8; 32]>,
    funded_account: String,
    funded_status: String,
    funded_report: Arc<Mutex<Option<sov_redteam::FundedReport>>>,
    funded_running: Arc<AtomicBool>,
    themed: bool,
    // ── node link ──
    /// The last link result: status, chain, height, latency, and — when the typed
    /// endpoint was wrong — every candidate that was tried.
    link: Arc<Mutex<Option<sov_redteam::NodeLink>>>,
    link_checking: Arc<AtomicBool>,
    /// The endpoint discovery adopted, handed back so the text field can follow it.
    link_adopt: Arc<Mutex<Option<String>>>,
    /// Consecutive failed heartbeats. The pill only falls to DOWN after several, so
    /// a single dropped call on a node that is busy serving the XUS Miner does not
    /// flap the display.
    link_misses: Arc<AtomicUsize>,
    /// Bumped by the polling thread on every SUCCESSFUL liveness call. This is the
    /// only thing that makes the heartbeat beat: no poll, no beat.
    beat_seq: Arc<AtomicUsize>,
    /// The last `beat_seq` the UI has already turned into a beat.
    seen_beat: usize,
    /// Wall-clock of each real beat still inside the trace window.
    beats: VecDeque<Instant>,
    /// Wall-clock of the last heartbeat, to pace the poll.
    last_beat: Option<Instant>,
    /// Whether the heartbeat polls on its own.
    heartbeat: bool,
    /// Whether to show the candidate sweep detail.
    show_attempts: bool,
}

impl Default for RedTeamApp {
    fn default() -> Self {
        Self {
            view: View::Gauntlet,
            selected: None,
            gauntlet_report: Arc::new(Mutex::new(None)),
            gauntlet_running: Arc::new(AtomicBool::new(false)),
            results: Arc::new(Mutex::new(None)),
            running: Arc::new(AtomicBool::new(false)),
            target: "64.225.10.34:8645".to_string(),
            live_report: Arc::new(Mutex::new(None)),
            live_running: Arc::new(AtomicBool::new(false)),
            backdoor_report: Arc::new(Mutex::new(None)),
            backdoor_running: Arc::new(AtomicBool::new(false)),
            funded_key_input: String::new(),
            funded_seed: None,
            funded_account: String::new(),
            funded_status: String::new(),
            funded_report: Arc::new(Mutex::new(None)),
            funded_running: Arc::new(AtomicBool::new(false)),
            themed: false,
            link: Arc::new(Mutex::new(None)),
            link_checking: Arc::new(AtomicBool::new(false)),
            link_adopt: Arc::new(Mutex::new(None)),
            link_misses: Arc::new(AtomicUsize::new(0)),
            beat_seq: Arc::new(AtomicUsize::new(0)),
            seen_beat: 0,
            beats: VecDeque::new(),
            last_beat: None,
            heartbeat: true,
            show_attempts: false,
        }
    }
}

/// The accent colour of an attack CLASS — post-quantum reads blue, the
/// foreign-chain class (an outsider's whole chain pushed at ours) reads gold, and
/// everything else reads threat-red.
fn class_accent(category: &str) -> Color32 {
    match category {
        "post-quantum" => PQ,
        "foreign-chain" => GOLD,
        _ => THREAT,
    }
}

/// One line saying what a class is actually testing, shown under its heading so a
/// reader knows what a DEFENDED verdict there is worth.
fn class_blurb(category: &str) -> &'static str {
    match category {
        "time" => "timestamp rules: median-time-past, the lower bound, and the EDA easing cap",
        "tamper" => "the PoW seal binds EVERY header field — change one byte, the seal dies",
        "forgery" => "signatures fail closed; checked arithmetic; a failed transfer moves nothing",
        "post-quantum" => {
            "the hybrid signature is a CONJUNCTION: break Ed25519 and ML-DSA-65 still stops you"
        }
        "replay" => "a block or a nonce cannot be spent twice",
        "consensus" => "equal-work forks converge on one tip regardless of arrival order",
        "flood" => "the elastic block-size cap bounds a block no matter the demand",
        "foreign-chain" => {
            "build your OWN chain and try to spend it onto the honest one: a foreign genesis, a \
             foreign balance, fabricated proof of work, and a private branch that tries to erase \
             a confirmed payment"
        }
        _ => "",
    }
}

/// How many consecutive heartbeat misses before the pill drops to DOWN. A node
/// running SOV Station's embedded RPC while the XUS Miner pulls templates from it
/// WILL occasionally drop a call — that is load, not death.
const MISS_TOLERANCE: usize = 3;

/// Seconds of heartbeat history the ECG trace shows.
const TRACE_WINDOW: f32 = 12.0;

// ── row metrics: the numbers that make the collision impossible ─────────────
/// Reserved, fixed-width column for the verdict chip. Text is laid out into
/// `available - CHIP_COL`, so the two regions can never share a pixel.
const CHIP_COL: f32 = 124.0;
const CHIP_SIZE: egui::Vec2 = egui::vec2(112.0, 24.0);
/// The inline attack diagram carried by every row.
const GLYPH: egui::Vec2 = egui::vec2(62.0, 40.0);
/// The widest the content column ever gets. Prose past ~90 characters a line is
/// hard to track, and the cards want one shared right edge to line the chips up.
const CONTENT_W: f32 = 980.0;

impl RedTeamApp {
    /// Check the node link off the UI thread.
    ///
    /// `sweep` = full discovery: if the typed endpoint is silent, try the same host
    /// on the RPC port, loopback, and this machine's real LAN addresses, then adopt
    /// whichever answers. Otherwise it is a plain heartbeat against what is typed.
    fn check_link(&self, sweep: bool) {
        if self.link_checking.swap(true, Ordering::SeqCst) {
            return;
        }
        let target = self.target.clone();
        let link = Arc::clone(&self.link);
        let checking = Arc::clone(&self.link_checking);
        let adopt = Arc::clone(&self.link_adopt);
        let misses = Arc::clone(&self.link_misses);
        let beat_seq = Arc::clone(&self.beat_seq);
        std::thread::spawn(move || {
            // A 2.5s budget: long enough for a node that is busy mining, short
            // enough that a black-holed VPN address fails fast instead of hanging
            // the panel. Retried, so one dropped call is not a verdict.
            let timeout = sov_redteam::link::DEFAULT_TIMEOUT;
            let result = if sweep {
                sov_redteam::discover_node(&target, timeout)
            } else {
                sov_redteam::check_endpoint_resilient(
                    &target,
                    timeout,
                    sov_redteam::link::DEFAULT_TRIES,
                )
            };
            if result.status.is_live() {
                misses.store(0, Ordering::SeqCst);
                // THE beat. It exists because a real RPC call to a real node came
                // back — there is no other path that increments this.
                beat_seq.fetch_add(1, Ordering::SeqCst);
                if result.redirected {
                    if let Ok(mut a) = adopt.lock() {
                        *a = Some(result.endpoint.clone());
                    }
                }
            } else {
                misses.fetch_add(1, Ordering::SeqCst);
            }
            if let Ok(mut slot) = link.lock() {
                *slot = Some(result);
            }
            checking.store(false, Ordering::SeqCst);
        });
    }

    /// Adopt an endpoint discovery found, pace the automatic heartbeat, and fold
    /// each successful poll into the ECG trace. Called once per frame.
    fn tick_link(&mut self, ctx: &egui::Context) {
        if let Ok(mut a) = self.link_adopt.lock() {
            if let Some(endpoint) = a.take() {
                self.target = endpoint;
            }
        }

        // Turn any new successful poll into a beat, and retire beats that have
        // scrolled off the trace.
        let seq = self.beat_seq.load(Ordering::SeqCst);
        if seq != self.seen_beat {
            self.seen_beat = seq;
            self.beats.push_back(Instant::now());
        }
        while self
            .beats
            .front()
            .is_some_and(|b| b.elapsed().as_secs_f32() > TRACE_WINDOW)
        {
            self.beats.pop_front();
        }

        if !self.heartbeat {
            return;
        }
        let due = self
            .last_beat
            .map(|t| t.elapsed() >= Duration::from_secs(2))
            .unwrap_or(true);
        if due && !self.link_checking.load(Ordering::SeqCst) {
            self.last_beat = Some(Instant::now());
            // The first beat sweeps, so a wrong port or an unreachable VPN address
            // is corrected before the operator ever presses a probe button.
            let first = self.link.lock().ok().map(|l| l.is_none()).unwrap_or(false);
            self.check_link(first);
        }
        // Repaint fast enough to scroll the trace ONLY while there is a trace to
        // scroll; when the node is down the panel is static and we just keep the
        // poll paced.
        if self.beats.is_empty() {
            ctx.request_repaint_after(Duration::from_millis(400));
        } else {
            ctx.request_repaint_after(Duration::from_millis(40));
        }
    }

    /// Kick the harness off the UI thread and publish its outcomes when done.
    fn run(&self) {
        if self.running.swap(true, Ordering::SeqCst) {
            return;
        }
        let results = Arc::clone(&self.results);
        let running = Arc::clone(&self.running);
        std::thread::spawn(move || {
            let outcomes = sov_redteam::run_all();
            if let Ok(mut slot) = results.lock() {
                *slot = Some(outcomes);
            }
            running.store(false, Ordering::SeqCst);
        });
    }

    /// Fire the live front-door probe at `self.target`, off the UI thread.
    fn run_live(&self) {
        if self.live_running.swap(true, Ordering::SeqCst) {
            return;
        }
        let target = self.target.clone();
        let report = Arc::clone(&self.live_report);
        let running = Arc::clone(&self.live_running);
        std::thread::spawn(move || {
            let r = sov_redteam::probe_frontdoor(&target);
            if let Ok(mut slot) = report.lock() {
                *slot = Some(r);
            }
            running.store(false, Ordering::SeqCst);
        });
    }

    /// Clear every result panel so the app returns to its initial state. Disabled while
    /// any probe is running (we don't interrupt a live attack mid-flight).
    fn reset(&mut self) {
        if let Ok(mut r) = self.gauntlet_report.lock() {
            *r = None;
        }
        if let Ok(mut r) = self.results.lock() {
            *r = None;
        }
        if let Ok(mut r) = self.live_report.lock() {
            *r = None;
        }
        if let Ok(mut r) = self.backdoor_report.lock() {
            *r = None;
        }
        if let Ok(mut r) = self.funded_report.lock() {
            *r = None;
        }
        self.selected = None;
    }

    /// Load the funded key the operator pasted: derive the seed (mnemonic or hex),
    /// remember it in memory, show which account it controls, and scrub the input.
    fn load_funded(&mut self) {
        use zeroize::Zeroize;
        match sov_redteam::seed_from_secret(&self.funded_key_input) {
            Ok(seed) => {
                let kp = sov_crypto::Keypair::hybrid_from_seed(seed);
                self.funded_account = sov_redteam::account_of(&kp).to_string();
                self.funded_seed = Some(seed);
                self.funded_status = "key loaded — held in memory only".to_string();
            }
            Err(e) => {
                self.funded_seed = None;
                self.funded_account.clear();
                self.funded_status = e;
            }
        }
        // Scrub the pasted secret from the text field's buffer.
        self.funded_key_input.zeroize();
        self.funded_key_input.clear();
    }

    /// Run the funded-adversary probe with the loaded seed, off the UI thread.
    fn run_funded(&self) {
        let Some(seed) = self.funded_seed else {
            return;
        };
        if self.funded_running.swap(true, Ordering::SeqCst) {
            return;
        }
        let target = self.target.clone();
        let report = Arc::clone(&self.funded_report);
        let running = Arc::clone(&self.funded_running);
        std::thread::spawn(move || {
            let kp = sov_crypto::Keypair::hybrid_from_seed(seed);
            // Leg 1 moves 0.001 XUS to itself (net-zero); a tiny fee is the only cost.
            let r = sov_redteam::probe_funded(&target, &kp, 100_000);
            if let Ok(mut slot) = report.lock() {
                *slot = Some(r);
            }
            running.store(false, Ordering::SeqCst);
        });
    }

    /// Fire the live back-door probe at `self.target`, off the UI thread.
    fn run_backdoor(&self) {
        if self.backdoor_running.swap(true, Ordering::SeqCst) {
            return;
        }
        let target = self.target.clone();
        let report = Arc::clone(&self.backdoor_report);
        let running = Arc::clone(&self.backdoor_running);
        std::thread::spawn(move || {
            let r = sov_redteam::probe_backdoor(&target);
            if let Ok(mut slot) = report.lock() {
                *slot = Some(r);
            }
            running.store(false, Ordering::SeqCst);
        });
    }

    /// Fire the Gauntlet probe at the live pot, off the UI thread.
    fn run_gauntlet(&self) {
        if self.gauntlet_running.swap(true, Ordering::SeqCst) {
            return;
        }
        let target = self.target.clone();
        let report = Arc::clone(&self.gauntlet_report);
        let running = Arc::clone(&self.gauntlet_running);
        std::thread::spawn(move || {
            let r = sov_redteam::probe_gauntlet(&target);
            if let Ok(mut slot) = report.lock() {
                *slot = Some(r);
            }
            running.store(false, Ordering::SeqCst);
        });
    }

    fn theme(&mut self, ctx: &egui::Context) {
        if self.themed {
            return;
        }
        self.themed = true;
        theme::install(ctx);
    }
}

// ── text hygiene ────────────────────────────────────────────────────────────

/// Shorten long hex runs — account ids, block hashes — inside an engine message.
///
/// The pot's 64-character id appears in EVERY rejection the node sends back; in
/// full it drowns the one thing the row is for (WHY it was refused). This elides
/// it to `8d670310…1953a`. The message is not otherwise touched, and the full
/// text is kept for the hover tooltip and click-to-copy, so nothing is lost.
fn elide_ids(s: &str) -> String {
    const KEEP_HEAD: usize = 8;
    const KEEP_TAIL: usize = 5;
    const MIN_RUN: usize = 24;
    let chars: Vec<char> = s.chars().collect();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < chars.len() {
        let start = i;
        while i < chars.len() && chars[i].is_ascii_hexdigit() {
            i += 1;
        }
        if i - start >= MIN_RUN {
            out.extend(&chars[start..start + KEEP_HEAD]);
            out.push('…');
            out.extend(&chars[i - KEEP_TAIL..i]);
        } else {
            out.extend(&chars[start..i]);
        }
        if i < chars.len() {
            out.push(chars[i]);
            i += 1;
        }
    }
    out
}

/// Force a container to the content column width.
///
/// egui frames shrink to their contents; a page of panels that each stop at a
/// different x reads as noise. Allocating a zero-height, full-width strip inside
/// a frame pins every card to one right edge.
fn stretch(ui: &mut egui::Ui, margin_x: f32) {
    let w = ui.available_width().min(CONTENT_W - 2.0 * margin_x);
    ui.allocate_exact_size(egui::vec2(w, 0.0), Sense::hover());
}

/// Chip text + colour for a verdict. The ONLY place a verdict becomes pixels.
fn verdict_style(v: sov_redteam::Verdict) -> (&'static str, Color32) {
    match v {
        sov_redteam::Verdict::Defended => ("DEFENDED", HOLD),
        sov_redteam::Verdict::Vulnerable => ("VULNERABLE", THREAT),
        sov_redteam::Verdict::Info => ("DISCLOSED", GOLD),
    }
}

/// The verdict chip: a fixed-size, painted badge. DEFENDED is a calm outline,
/// VULNERABLE is a filled alarm that breathes so one of them cannot hide in a
/// screen of green.
fn verdict_chip(ui: &mut egui::Ui, v: sov_redteam::Verdict) {
    let (rect, _) = ui.allocate_exact_size(CHIP_SIZE, Sense::hover());
    paint_chip(ui, rect, v);
}

/// Paint a verdict chip into an exact rect.
fn paint_chip(ui: &egui::Ui, rect: egui::Rect, v: sov_redteam::Verdict) {
    let (text, col) = verdict_style(v);
    let alarm = v == sov_redteam::Verdict::Vulnerable;
    let round = Rounding::same(rect.height() / 2.0);
    let p = ui.painter();
    if alarm {
        // A slow 1 Hz breath — noticeable, never a strobe.
        let t = ui.input(|i| i.time) as f32;
        let g = 0.5 + 0.5 * (t * 2.0).sin();
        ui.ctx().request_repaint_after(Duration::from_millis(40));
        p.rect_filled(rect, round, col);
        p.rect_stroke(
            rect.expand(1.0 + 1.5 * g),
            Rounding::same(round.nw + 2.0),
            Stroke::new(1.0, alpha(col, (60.0 + 120.0 * g) as u8)),
        );
        p.circle_filled(
            egui::pos2(rect.left() + 13.0, rect.center().y),
            3.6,
            ON_ACCENT,
        );
        p.text(
            egui::pos2(rect.left() + 23.0, rect.center().y),
            Align2::LEFT_CENTER,
            text,
            FontId::proportional(11.5),
            ON_ACCENT,
        );
    } else {
        p.rect_filled(rect, round, alpha(col, 26));
        p.rect_stroke(rect, round, Stroke::new(1.0, alpha(col, 130)));
        p.circle_filled(egui::pos2(rect.left() + 13.0, rect.center().y), 3.6, col);
        p.text(
            egui::pos2(rect.left() + 23.0, rect.center().y),
            Align2::LEFT_CENTER,
            text,
            FontId::proportional(11.5),
            col,
        );
    }
}

/// One attack card, laid out by hand so the geometry is exact:
///
/// ```text
///  ┌──────────────────────────────────────────────────────────────────────┐
///  │ ▍ [diagram]  attack name                              [ VERDICT ]    │
///  │              why it was refused (wrapped in its own column)          │
///  └──────────────────────────────────────────────────────────────────────┘
///  |<--------------- text column: row − chip − gutters --------------->|<chip>|
/// ```
///
/// The text is laid out into a galley of EXACTLY `text_w`, and the chip is
/// painted into its own reserved rect at the right edge. The two rects are
/// disjoint by construction at every window width — the old right-to-left row,
/// where a long wrapping label and a right-aligned chip shared one line box and
/// overpainted each other, is gone.
fn outcome_row(
    ui: &mut egui::Ui,
    category: &str,
    name: &str,
    verdict: sov_redteam::Verdict,
    detail: &str,
    accent: Color32,
    selected: bool,
) -> egui::Response {
    const PAD_X: f32 = 14.0;
    const PAD_Y: f32 = 12.0;
    const GUTTER: f32 = 12.0;

    let vz = Viz::of(category, name);
    let fate = Fate::of(verdict);
    let row_w = ui.available_width().min(CONTENT_W);
    // Where the prose starts, and how wide it may be. Everything after this point
    // is derived, so nothing can drift into the chip's column.
    let text_x = PAD_X + 3.0 + 10.0 + GLYPH.x + GUTTER;
    let text_w = (row_w - text_x - CHIP_COL - PAD_X).max(140.0);

    let short = elide_ids(detail);
    let elided = short != detail;
    let (name_g, det_g) = ui.fonts(|f| {
        (
            f.layout(name.to_owned(), FontId::proportional(14.0), INK, text_w),
            f.layout(short, FontId::proportional(12.0), MUTED, text_w),
        )
    });
    let name_h = name_g.size().y;
    let det_h = det_g.size().y;
    let content_h = name_h + 3.0 + det_h;
    let row_h = content_h.max(GLYPH.y) + 2.0 * PAD_Y;

    let (rect, resp) = ui.allocate_exact_size(egui::vec2(row_w, row_h), Sense::click());
    let hot = selected || resp.hovered();
    {
        let p = ui.painter();
        let round = Rounding::same(9.0);
        p.rect_filled(rect, round, if hot { SURFACE } else { PANEL });
        p.rect_stroke(
            rect,
            round,
            Stroke::new(1.0, if selected { alpha(accent, 170) } else { BORDER }),
        );

        // class rail
        let rail = egui::Rect::from_min_size(
            egui::pos2(rect.left() + PAD_X, rect.top() + PAD_Y),
            egui::vec2(3.0, row_h - 2.0 * PAD_Y),
        );
        p.rect_filled(rail, Rounding::same(2.0), alpha(accent, 210));

        // the attack's own diagram, drawn from the REAL verdict
        let g = egui::Rect::from_min_size(
            egui::pos2(rail.right() + 10.0, rect.center().y - GLYPH.y / 2.0),
            GLYPH,
        );
        viz::paint(p, g, vz, fate, 0.0);

        // prose column
        let ty = rect.top() + (row_h - content_h) / 2.0;
        p.galley(egui::pos2(rect.left() + text_x, ty), name_g, INK);
        p.galley(
            egui::pos2(rect.left() + text_x, ty + name_h + 3.0),
            det_g,
            MUTED,
        );

        // verdict column — its own rect, never shared with the text
        let chip = egui::Rect::from_min_size(
            egui::pos2(
                rect.right() - PAD_X - CHIP_SIZE.x,
                rect.center().y - CHIP_SIZE.y / 2.0,
            ),
            CHIP_SIZE,
        );
        paint_chip(ui, chip, verdict);
    }

    // The elided id stays reachable: hover for the full engine message, click to
    // copy it verbatim.
    if elided {
        let dr = egui::Rect::from_min_size(
            egui::pos2(
                rect.left() + text_x,
                rect.top() + (row_h - content_h) / 2.0 + name_h + 3.0,
            ),
            egui::vec2(text_w, det_h),
        );
        let r = ui
            .interact(
                dr,
                ui.make_persistent_id(("detail", category, name)),
                Sense::click(),
            )
            .on_hover_text(RichText::new(detail).monospace().size(11.0).color(INK));
        if r.clicked() {
            ui.ctx().copy_text(detail.to_owned());
        }
    }
    ui.add_space(6.0);
    resp
}

/// The theatre: one large diagram of what is happening.
///
/// While a battery is RUNNING it animates the classes being thrown, with no
/// verdict drawn — nothing is known yet. Once results exist it shows the selected
/// attack with the verdict the engine returned.
fn theater(ui: &mut egui::Ui, running: bool, sel: Option<(&str, &str, sov_redteam::Verdict)>) {
    let t = ui.input(|i| i.time) as f32;
    egui::Frame::none()
        .fill(PANEL)
        .rounding(Rounding::same(12.0))
        .stroke(Stroke::new(1.0, BORDER))
        .inner_margin(Margin::symmetric(16.0, 14.0))
        .show(ui, |ui| {
            stretch(ui, 16.0);
            ui.horizontal_top(|ui| {
                let (rect, _) = ui.allocate_exact_size(egui::vec2(300.0, 132.0), Sense::hover());
                let (vz, fate) = if running {
                    let i = ((t / 2.4) as usize) % viz::REEL.len();
                    (viz::REEL[i], Fate::InFlight)
                } else {
                    match sel {
                        Some((cat, name, v)) => (Viz::of(cat, name), Fate::of(v)),
                        None => (Viz::Shield, Fate::Noted),
                    }
                };
                viz::paint(ui.painter(), rect, vz, fate, t);
                if running {
                    ui.ctx().request_repaint_after(Duration::from_millis(40));
                }
                ui.add_space(16.0);
                ui.vertical(|ui| {
                    ui.set_max_width((ui.available_width() - 4.0).max(160.0));
                    if running {
                        ui.label(
                            RichText::new("ATTACK IN FLIGHT")
                                .size(12.0)
                                .strong()
                                .color(GOLD),
                        );
                        ui.add_space(4.0);
                        ui.add(
                            egui::Label::new(
                                RichText::new(
                                    "The battery is running against real consensus code. No \
                                     verdict is shown until the engine returns one.",
                                )
                                .size(12.0)
                                .color(MUTED),
                            )
                            .wrap(),
                        );
                    } else if let Some((cat, name, v)) = sel {
                        ui.horizontal(|ui| {
                            ui.label(
                                RichText::new(cat.to_uppercase())
                                    .size(11.0)
                                    .strong()
                                    .monospace()
                                    .color(class_accent(cat)),
                            );
                        });
                        ui.add_space(2.0);
                        ui.add(
                            egui::Label::new(RichText::new(name).size(16.0).strong().color(INK))
                                .wrap(),
                        );
                        ui.add_space(6.0);
                        ui.add(
                            egui::Label::new(
                                RichText::new(Viz::of(cat, name).caption())
                                    .size(12.0)
                                    .color(MUTED),
                            )
                            .wrap(),
                        );
                        ui.add_space(8.0);
                        verdict_chip(ui, v);
                    } else {
                        ui.label(
                            RichText::new("Pick an attack below to see how it was answered.")
                                .size(12.0)
                                .color(MUTED)
                                .italics(),
                        );
                    }
                });
            });
        });
    ui.add_space(12.0);
}

/// A section heading: title in the class accent, then the standing explanation.
fn section_head(ui: &mut egui::Ui, title: &str, accent: Color32, blurb: &str) {
    ui.label(RichText::new(title).size(20.0).strong().color(accent));
    ui.add_space(3.0);
    ui.add(egui::Label::new(RichText::new(blurb).size(12.5).color(MUTED)).wrap());
    ui.add_space(12.0);
}

impl eframe::App for RedTeamApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.theme(ctx);
        // Node link: adopt any endpoint discovery found, fold each successful poll
        // into the heartbeat, and pace the next one.
        self.tick_link(ctx);

        // Header bar: identity, liveness (pill + heartbeat), the node target, Reset.
        egui::TopBottomPanel::top("header")
            .frame(
                egui::Frame::none()
                    .fill(PANEL)
                    .inner_margin(Margin::symmetric(20.0, 12.0)),
            )
            .show(ctx, |ui| self.header(ui));

        // Bottom toolbar: the primary navigation, so the content gets the full width.
        egui::TopBottomPanel::bottom("nav")
            .frame(
                egui::Frame::none()
                    .fill(PANEL)
                    .inner_margin(Margin::symmetric(12.0, 8.0)),
            )
            .show(ctx, |ui| self.bottom_nav(ui));

        // Content area: the active probe.
        egui::CentralPanel::default()
            .frame(
                egui::Frame::none()
                    .fill(GROUND)
                    .inner_margin(Margin::symmetric(26.0, 20.0)),
            )
            .show(ctx, |ui| {
                egui::ScrollArea::vertical().show(ui, |ui| {
                    // Wide enough to breathe now the left rail is gone, capped so
                    // prose never runs to an unreadable line length.
                    ui.set_max_width(ui.available_width().min(CONTENT_W));
                    match self.view {
                        View::Gauntlet => self.gauntlet_section(ui),
                        View::Funded => self.funded_section(ui),
                        View::FrontDoor => self.live_section(ui),
                        View::BackDoor => self.backdoor_section(ui),
                        View::InProcess => self.inprocess_section(ui),
                    }
                });
            });
    }
}

impl RedTeamApp {
    /// The top bar: title, liveness, the shared node RPC field, and Reset.
    fn header(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.label(
                RichText::new("⚔ SOV Red Team")
                    .size(20.0)
                    .strong()
                    .color(GOLD),
            );
            ui.add_space(10.0);
            ui.label(RichText::new("adversarial harness").size(12.0).color(MUTED));
            ui.add_space(14.0);
            // The liveness zone: the real heartbeat, then the link chip.
            self.heartbeat_chip(ui);
            ui.add_space(8.0);
            self.link_pill(ui);
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                let any_busy = self.running.load(Ordering::SeqCst)
                    || self.live_running.load(Ordering::SeqCst)
                    || self.backdoor_running.load(Ordering::SeqCst)
                    || self.gauntlet_running.load(Ordering::SeqCst)
                    || self.funded_running.load(Ordering::SeqCst);
                let btn = egui::Button::new(RichText::new("↺ Reset").size(13.0).color(INK))
                    .fill(SURFACE)
                    .stroke(Stroke::new(1.0, BORDER))
                    .min_size(egui::vec2(74.0, 26.0));
                if ui
                    .add_enabled(!any_busy, btn)
                    .on_hover_text("Clear all results")
                    .clicked()
                {
                    self.reset();
                }
                ui.add_space(12.0);
                let recheck = egui::Button::new(RichText::new("⟳ Detect").size(12.5).color(INK))
                    .fill(SURFACE)
                    .stroke(Stroke::new(1.0, BORDER))
                    .min_size(egui::vec2(72.0, 26.0));
                if ui
                    .add_enabled(!self.link_checking.load(Ordering::SeqCst), recheck)
                    .on_hover_text(
                        "Probe this endpoint, and if it is silent try the RPC port, loopback, \
                         and this machine's LAN addresses — then adopt whichever answers",
                    )
                    .clicked()
                {
                    self.check_link(true);
                }
                ui.add_space(8.0);
                if ui
                    .add(
                        egui::TextEdit::singleline(&mut self.target)
                            .desired_width(150.0)
                            .hint_text("host:port"),
                    )
                    .changed()
                {
                    // Re-probe promptly when the operator edits the endpoint.
                    self.last_beat = None;
                }
                ui.label(RichText::new("node RPC").size(12.0).color(MUTED));
            });
        });
        self.link_banner(ui);
    }

    /// The heartbeat: an ECG trace where **every spike is one real successful RPC
    /// poll**. Beats are pushed by `check_link`'s worker only when the node
    /// actually answered; nothing here free-runs. When the node stops answering,
    /// the spikes scroll off and the trace goes flat and grey — a flatline, not a
    /// decorative loop.
    fn heartbeat_chip(&mut self, ui: &mut egui::Ui) {
        let now = Instant::now();
        let last = self
            .beats
            .back()
            .map(|b| now.duration_since(*b).as_secs_f32());
        let misses = self.link_misses.load(Ordering::SeqCst);
        // Flat once we have missed enough polls to call it down, or once no real
        // beat remains inside the window.
        let flat = self.beats.is_empty() || misses >= MISS_TOLERANCE;
        let col = if flat {
            MUTED
        } else if misses > 0 {
            GOLD
        } else {
            HOLD
        };

        egui::Frame::none()
            .fill(SURFACE)
            .rounding(Rounding::same(13.0))
            .stroke(Stroke::new(1.0, alpha(col, 120)))
            .inner_margin(Margin::symmetric(9.0, 4.0))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    let (rect, resp) =
                        ui.allocate_exact_size(egui::vec2(104.0, 20.0), Sense::hover());
                    let p = ui.painter();
                    let mid = rect.center().y;
                    let amp = rect.height() * 0.46;
                    // baseline
                    p.line_segment(
                        [egui::pos2(rect.left(), mid), egui::pos2(rect.right(), mid)],
                        Stroke::new(1.0, alpha(col, 55)),
                    );
                    if flat {
                        p.line_segment(
                            [egui::pos2(rect.left(), mid), egui::pos2(rect.right(), mid)],
                            Stroke::new(1.3, alpha(MUTED, 190)),
                        );
                    } else {
                        const N: usize = 72;
                        let pts: Vec<egui::Pos2> = (0..=N)
                            .map(|i| {
                                let f = i as f32 / N as f32;
                                let age = (1.0 - f) * TRACE_WINDOW;
                                let mut y = 0.0;
                                for b in &self.beats {
                                    let e = now.duration_since(*b).as_secs_f32() - age;
                                    y += qrs(e);
                                }
                                egui::pos2(
                                    rect.left() + rect.width() * f,
                                    mid - y.clamp(-1.2, 1.2) * amp,
                                )
                            })
                            .collect();
                        let head = *pts.last().unwrap_or(&rect.center());
                        p.add(egui::Shape::line(pts, Stroke::new(1.4, col)));
                        p.circle_filled(head, 2.2, col);
                    }
                    ui.add_space(4.0);
                    let text = match (flat, last) {
                        (true, _) => "FLATLINE".to_string(),
                        (false, Some(a)) if a < 1.0 => "BEAT".to_string(),
                        (false, Some(a)) => format!("{a:.0}s"),
                        (false, None) => "—".to_string(),
                    };
                    ui.label(
                        RichText::new(text)
                            .size(10.5)
                            .strong()
                            .monospace()
                            .color(col),
                    );
                    resp.on_hover_text(
                        "Every spike is one successful liveness call to the node's RPC. \
                         No answer, no spike — this flatlines when the node is actually down.",
                    );
                });
            });
    }

    /// The live link chip: a dot that flashes on each REAL beat, plus chain /
    /// height / latency. A still dot means "not talking to a node".
    fn link_pill(&mut self, ui: &mut egui::Ui) {
        let checking = self.link_checking.load(Ordering::SeqCst);
        let misses = self.link_misses.load(Ordering::SeqCst);
        let link = self.link.lock().ok().and_then(|l| l.clone());
        let (status, chain, height, latency) = match &link {
            Some(l) => (l.status, l.chain_id.clone(), l.height, l.latency),
            None => (sov_redteam::LinkStatus::Idle, None, None, None),
        };
        // Tolerate a few misses before declaring the link down: a node serving the
        // XUS Miner drops the occasional call.
        let busy = !status.is_live() && misses > 0 && misses < MISS_TOLERANCE && height.is_some();
        let live = status.is_live() || busy;
        let (color, label) = if checking && link.is_none() {
            (GOLD, "CHECKING")
        } else if busy {
            // The node answered before and is missing calls now: that is LOAD (a
            // miner pulling templates from the same RPC), not death. Say so instead
            // of flapping to a red DOWN and scaring the operator off a healthy node.
            (GOLD, "BUSY")
        } else if live {
            (HOLD, "LIVE")
        } else if status == sov_redteam::LinkStatus::Idle {
            (MUTED, "NOT CHECKED")
        } else {
            (THREAT, status.label())
        };

        // The flash decays from the last REAL beat, so the dot cannot look alive
        // while the node is silent.
        let since = self
            .beats
            .back()
            .map(|b| b.elapsed().as_secs_f32())
            .unwrap_or(f32::MAX);
        let flash = if live {
            (1.0 - since / 1.4).clamp(0.0, 1.0)
        } else {
            0.0
        };

        egui::Frame::none()
            .fill(SURFACE)
            .rounding(Rounding::same(13.0))
            .stroke(Stroke::new(1.0, alpha(color, 130)))
            .inner_margin(Margin::symmetric(11.0, 5.0))
            .show(ui, |ui| {
                // Reads dot → status → height → chain → latency, and sizes to its
                // content so it never stretches across the header.
                ui.horizontal(|ui| {
                    let (rect, _) = ui.allocate_exact_size(egui::vec2(11.0, 11.0), Sense::hover());
                    let c = rect.center();
                    if flash > 0.0 {
                        ui.painter().circle_filled(
                            c,
                            4.0 + 4.0 * flash,
                            alpha(color, (70.0 * flash) as u8),
                        );
                    }
                    ui.painter()
                        .circle_filled(c, 3.6, alpha(color, (140.0 + 115.0 * flash) as u8));
                    ui.add_space(3.0);
                    ui.label(
                        RichText::new(label)
                            .size(11.0)
                            .strong()
                            .monospace()
                            .color(color),
                    );
                    if let Some(h) = height {
                        ui.label(
                            RichText::new(format!("#{h}"))
                                .size(11.0)
                                .monospace()
                                .color(INK),
                        );
                    }
                    if let Some(ch) = &chain {
                        ui.label(RichText::new(ch).size(11.0).color(MUTED));
                    }
                    if let Some(l) = latency {
                        // Loopback answers in well under a millisecond; "0 ms" reads
                        // like a missing value, so say what it means.
                        let ms = l.as_millis();
                        ui.label(
                            RichText::new(if ms == 0 {
                                "<1 ms".to_string()
                            } else {
                                format!("{ms} ms")
                            })
                            .size(11.0)
                            .monospace()
                            .color(MUTED),
                        );
                    }
                });
            });
    }

    /// When the link is NOT live — or was silently redirected — say so loudly, with
    /// the fix. This is the panel that replaces a dead-end "node unreachable".
    fn link_banner(&mut self, ui: &mut egui::Ui) {
        let link = self.link.lock().ok().and_then(|l| l.clone());
        let Some(link) = link else { return };
        let misses = self.link_misses.load(Ordering::SeqCst);
        let live = link.status.is_live();
        if live && !link.redirected {
            return;
        }
        if !live && misses < MISS_TOLERANCE && link.height.is_some() {
            return; // transient miss under load — not worth alarming about yet
        }
        let color = if live { GOLD } else { THREAT };
        ui.add_space(6.0);
        egui::Frame::none()
            .fill(PANEL)
            .rounding(Rounding::same(9.0))
            .stroke(Stroke::new(1.0, alpha(color, 120)))
            .inner_margin(Margin::symmetric(13.0, 9.0))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new(if live {
                            "⟳ ENDPOINT CORRECTED"
                        } else {
                            "⚠ NO NODE LINK"
                        })
                        .size(11.5)
                        .strong()
                        .monospace()
                        .color(color),
                    );
                    if !link.attempts.is_empty() {
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            let label = if self.show_attempts {
                                "hide what was tried"
                            } else {
                                "show what was tried"
                            };
                            if ui
                                .add(egui::Button::new(
                                    RichText::new(label).size(11.0).color(MUTED),
                                ))
                                .clicked()
                            {
                                self.show_attempts = !self.show_attempts;
                            }
                        });
                    }
                });
                ui.add(egui::Label::new(RichText::new(&link.detail).size(11.5).color(INK)).wrap());
                if !live {
                    ui.add(
                        egui::Label::new(
                            RichText::new(format!(
                                "JSON-RPC is port {} — port {} is P2P (Noise-XX) and never \
                                 answers RPC. If SOV Station shows a 10.x address from a VPN \
                                 interface, use its LAN address or 127.0.0.1:{}.",
                                sov_redteam::RPC_PORT,
                                sov_redteam::P2P_PORT,
                                sov_redteam::RPC_PORT
                            ))
                            .size(11.0)
                            .color(MUTED)
                            .italics(),
                        )
                        .wrap(),
                    );
                }
                if self.show_attempts {
                    ui.add_space(5.0);
                    for a in &link.attempts {
                        let c = if a.status.is_live() { HOLD } else { MUTED };
                        ui.label(
                            RichText::new(format!(
                                "{:<22} {:<14} {}",
                                a.endpoint,
                                a.status.label(),
                                a.why
                            ))
                            .size(10.5)
                            .monospace()
                            .color(c),
                        );
                    }
                }
            });
        ui.add_space(2.0);
    }

    /// The primary navigation, along the BOTTOM of the window: one segment per
    /// probe, the active one filled and underlined in its class colour.
    fn bottom_nav(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            for view in View::ALL {
                self.nav_tab(ui, view);
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.label(
                    RichText::new("real attacks · live mainnet")
                        .size(10.5)
                        .color(MUTED),
                );
            });
        });
    }

    /// One bottom-toolbar segment.
    fn nav_tab(&mut self, ui: &mut egui::Ui, view: View) {
        let active = self.view == view;
        let accent = view.accent();
        let btn = egui::Button::new(
            RichText::new(format!("{}  {}", view.icon(), view.label()))
                .size(13.5)
                .strong()
                .color(if active { accent } else { INK }),
        )
        .fill(if active {
            alpha(accent, 28)
        } else {
            Color32::TRANSPARENT
        })
        .stroke(if active {
            Stroke::new(1.0, alpha(accent, 140))
        } else {
            Stroke::NONE
        })
        .rounding(Rounding::same(8.0))
        .min_size(egui::vec2(0.0, 32.0));
        let r = ui.add(btn);
        if active {
            // A solid underline so the active tab is unmistakable even at a glance.
            let bar = egui::Rect::from_min_max(
                egui::pos2(r.rect.left() + 8.0, r.rect.bottom() - 2.0),
                egui::pos2(r.rect.right() - 8.0, r.rect.bottom()),
            );
            ui.painter().rect_filled(bar, Rounding::same(1.0), accent);
        }
        if r.clicked() && !active {
            self.view = view;
            self.selected = None;
        }
        ui.add_space(2.0);
    }

    /// Draw a list of attack cards grouped by class, and keep the theatre's
    /// selection in sync. Returns nothing — selection lives on `self`.
    fn attack_list(&mut self, ui: &mut egui::Ui, rows: &Snap, group: bool, accent: Color32) {
        let mut last = "";
        for (i, (cat, name, verdict, detail)) in rows.iter().enumerate() {
            if group && *cat != last {
                ui.add_space(10.0);
                ui.label(
                    RichText::new(cat.to_uppercase())
                        .size(11.0)
                        .strong()
                        .monospace()
                        .color(class_accent(cat)),
                );
                let blurb = class_blurb(cat);
                if !blurb.is_empty() {
                    ui.add(
                        egui::Label::new(RichText::new(blurb).size(11.5).color(MUTED).italics())
                            .wrap(),
                    );
                }
                ui.add_space(5.0);
                last = cat;
            }
            let row_accent = if group { class_accent(cat) } else { accent };
            if outcome_row(
                ui,
                cat,
                name,
                *verdict,
                detail,
                row_accent,
                self.selected == Some(i),
            )
            .clicked()
            {
                self.selected = Some(i);
            }
        }
    }

    /// The selection the theatre should draw, clamped to the current list.
    fn theater_pick<'a>(&self, rows: &'a Snap) -> Option<(&'a str, &'a str, sov_redteam::Verdict)> {
        if rows.is_empty() {
            return None;
        }
        // Default to the first VULNERABLE if there is one — the thing that must not
        // be missed — otherwise the first attack.
        let idx = self
            .selected
            .filter(|i| *i < rows.len())
            .unwrap_or_else(|| {
                rows.iter()
                    .position(|(_, _, v, _)| *v == sov_redteam::Verdict::Vulnerable)
                    .unwrap_or(0)
            });
        let (cat, name, v, _) = &rows[idx];
        Some((cat, name, *v))
    }

    /// The Gauntlet: attack the real live steal-the-pot account every key-less way.
    fn gauntlet_section(&mut self, ui: &mut egui::Ui) {
        section_head(
            ui,
            "🏆 The Gauntlet — attack the live pot",
            GOLD,
            "The public steal-the-pot account holds real XUS on live mainnet, and its private \
             key is in cold storage. This is the outsider who wants it and has NO key: it throws \
             every key-less theft — forged signatures, wrong-key spends, RotateKey seizure, \
             overflow drains, malformed payloads, a brute-force sweep — over the real RPC, then \
             checks the pot balance. Every attempt must be refused and not a grain may move.",
        );

        let running = self.gauntlet_running.load(Ordering::SeqCst);
        let btn = egui::Button::new(
            RichText::new(if running {
                "🏆 attacking the pot…"
            } else {
                "🏆 Attack the pot"
            })
            .strong()
            .color(ON_ACCENT),
        )
        .fill(GOLD)
        .min_size(egui::vec2(200.0, 34.0));
        if ui.add_enabled(!running, btn).clicked() {
            self.run_gauntlet();
        }
        if running {
            ui.ctx().request_repaint_after(Duration::from_millis(150));
        }
        ui.add_space(14.0);

        // Snapshot everything the panel draws, then drop the lock.
        struct Head {
            error: Option<String>,
            pot: String,
            before: Option<u128>,
            after: Option<u128>,
            mainnet: bool,
            intact: bool,
        }
        let (head, rows): (Option<Head>, Snap) = match self.gauntlet_report.lock() {
            Ok(g) => match g.as_ref() {
                Some(r) => (
                    Some(Head {
                        error: r.error.clone(),
                        pot: r.pot.clone(),
                        before: r.balance_before,
                        after: r.balance_after,
                        mainnet: r.is_mainnet,
                        intact: r.pot_intact() && !sov_redteam::gauntlet_any_vulnerable(r),
                    }),
                    snap(&r.outcomes),
                ),
                None => (None, Vec::new()),
            },
            Err(_) => (None, Vec::new()),
        };

        let Some(head) = head else {
            if running {
                theater(ui, true, None);
            } else {
                ui.label(
                    RichText::new("Point at a node and attack the pot.")
                        .color(MUTED)
                        .italics(),
                );
            }
            return;
        };
        if let Some(err) = &head.error {
            ui.add(egui::Label::new(RichText::new(err).size(12.5).color(THREAT).italics()).wrap());
            return;
        }

        let tone = if head.intact { HOLD } else { THREAT };
        egui::Frame::none()
            .fill(SURFACE)
            .rounding(Rounding::same(12.0))
            .stroke(Stroke::new(1.0, alpha(tone, 120)))
            .inner_margin(Margin::symmetric(18.0, 14.0))
            .show(ui, |ui| {
                stretch(ui, 18.0);
                ui.label(
                    RichText::new(if head.intact {
                        "THE POT HELD"
                    } else {
                        "THE POT IS IN DANGER"
                    })
                    .size(23.0)
                    .strong()
                    .color(tone),
                );
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    let short = elide_ids(&head.pot);
                    ui.label(RichText::new("pot").size(11.0).color(MUTED));
                    let r = ui
                        .add(
                            egui::Label::new(
                                RichText::new(&short).size(12.0).monospace().color(INK),
                            )
                            .sense(Sense::click()),
                        )
                        .on_hover_text(RichText::new(&head.pot).monospace().size(11.0));
                    if r.clicked() {
                        ui.ctx().copy_text(head.pot.clone());
                    }
                    ui.add_space(14.0);
                    ui.label(
                        RichText::new(format!(
                            "{} → {} XUS",
                            sov_redteam::GauntletReport::xus(head.before),
                            sov_redteam::GauntletReport::xus(head.after),
                        ))
                        .size(13.0)
                        .strong()
                        .monospace()
                        .color(tone),
                    );
                    if head.mainnet {
                        ui.add_space(14.0);
                        ui.label(
                            RichText::new("LIVE MAINNET")
                                .size(11.5)
                                .strong()
                                .monospace()
                                .color(GOLD),
                        );
                    }
                });
            });
        ui.add_space(14.0);

        let pick = self.theater_pick(&rows);
        theater(ui, running, pick);
        self.attack_list(ui, &rows, false, GOLD);
    }

    /// The in-process battery: attacks against a private replica of consensus.
    fn inprocess_section(&mut self, ui: &mut egui::Ui) {
        section_head(
            ui,
            "⚔ In-process battery",
            HOLD,
            "Builds a real chain and throws a battery of attacks at produce_block / \
             import_block — the same path a node runs. Each is judged DEFENDED, VULNERABLE, or \
             DISCLOSED — a property disclosed rather than dressed up as a pass. Standalone: this \
             is not the wallet.",
        );

        let running = self.running.load(Ordering::SeqCst);
        ui.horizontal(|ui| {
            let label = if running {
                "⚔ attacking consensus…"
            } else {
                "⚔ Run red team"
            };
            let btn = egui::Button::new(RichText::new(label).strong().color(ON_ACCENT))
                .fill(GOLD)
                .min_size(egui::vec2(180.0, 34.0));
            if ui.add_enabled(!running, btn).clicked() {
                self.run();
            }
            if running {
                ui.spinner();
            }
        });
        if running {
            ui.ctx().request_repaint_after(Duration::from_millis(120));
        }
        ui.add_space(14.0);

        let rows: Snap = self
            .results
            .lock()
            .ok()
            .and_then(|g| g.as_ref().map(|v| snap(v)))
            .unwrap_or_default();
        if rows.is_empty() {
            if running {
                theater(ui, true, None);
            } else {
                ui.label(
                    RichText::new("Press “Run red team” to attack the chain live.")
                        .color(MUTED)
                        .italics(),
                );
            }
            return;
        }

        let total = rows.len();
        let count =
            |want: sov_redteam::Verdict| rows.iter().filter(|(_, _, v, _)| *v == want).count();
        let defended = count(sov_redteam::Verdict::Defended);
        let vulnerable = count(sov_redteam::Verdict::Vulnerable);
        // INFO outcomes are DISCLOSURES: a defense that could not be exercised
        // without a mock, or a real property that is not a free win for the
        // attacker. They are never folded into the DEFENDED count and never hidden
        // behind the all-clear banner — that would be exactly the dishonesty this
        // tool exists to prevent.
        let disclosures: Vec<_> = rows
            .iter()
            .filter(|(_, _, v, _)| *v == sov_redteam::Verdict::Info)
            .collect();
        let classes = {
            let mut seen: Vec<&str> = Vec::new();
            for (c, ..) in &rows {
                if !seen.contains(c) {
                    seen.push(c);
                }
            }
            seen.len()
        };
        let clear = vulnerable == 0;

        // verdict banner
        egui::Frame::none()
            .fill(SURFACE)
            .rounding(Rounding::same(12.0))
            .stroke(Stroke::new(
                1.0,
                alpha(if clear { HOLD } else { THREAT }, 110),
            ))
            .inner_margin(Margin::symmetric(18.0, 15.0))
            .show(ui, |ui| {
                stretch(ui, 18.0);
                ui.label(
                    RichText::new(if !clear {
                        "VULNERABILITIES FOUND"
                    } else if disclosures.is_empty() {
                        "EVERY DEFENSE HELD"
                    } else {
                        "EVERY DEFENSE HELD — WITH DISCLOSURES"
                    })
                    .size(24.0)
                    .strong()
                    .color(if clear { HOLD } else { THREAT }),
                );
                ui.add_space(10.0);
                ui.horizontal(|ui| {
                    let stat = |ui: &mut egui::Ui, n: usize, label: &str, c: Color32| {
                        ui.vertical(|ui| {
                            ui.label(
                                RichText::new(n.to_string())
                                    .size(26.0)
                                    .strong()
                                    .monospace()
                                    .color(c),
                            );
                            ui.label(RichText::new(label).size(10.0).color(MUTED));
                        });
                    };
                    stat(ui, total, "ATTACKS", GOLD);
                    ui.add_space(24.0);
                    stat(ui, defended, "DEFENDED", HOLD);
                    ui.add_space(24.0);
                    stat(ui, vulnerable, "VULNERABLE", THREAT);
                    ui.add_space(24.0);
                    stat(ui, disclosures.len(), "DISCLOSED", GOLD);
                    ui.add_space(24.0);
                    stat(ui, classes, "CLASSES", INK);
                });
            });
        ui.add_space(14.0);

        // ── the theatre ──
        let pick = self.theater_pick(&rows);
        theater(ui, running, pick);

        // ── disclosures, up front ──
        // Surfaced ABOVE the per-class rows, because the whole point of an INFO
        // verdict is that a reader must not have to scroll to find it.
        if !disclosures.is_empty() {
            egui::Frame::none()
                .fill(PANEL)
                .rounding(Rounding::same(10.0))
                .stroke(Stroke::new(1.0, alpha(GOLD, 120)))
                .inner_margin(Margin::symmetric(15.0, 12.0))
                .show(ui, |ui| {
                    stretch(ui, 15.0);
                    ui.label(
                        RichText::new("DISCLOSED — not a pass, not a vulnerability")
                            .size(11.5)
                            .strong()
                            .monospace()
                            .color(GOLD),
                    );
                    ui.add_space(6.0);
                    for (cat, name, _, detail) in &disclosures {
                        ui.label(
                            RichText::new(format!("{cat} · {name}"))
                                .size(12.5)
                                .strong()
                                .color(INK),
                        );
                        ui.add(
                            egui::Label::new(
                                RichText::new(elide_ids(detail)).size(11.5).color(MUTED),
                            )
                            .wrap(),
                        );
                        ui.add_space(5.0);
                    }
                });
            ui.add_space(14.0);
        }

        self.attack_list(ui, &rows, true, HOLD);

        ui.add_space(12.0);
        ui.add(
            egui::Label::new(
                RichText::new(
                    "Honest scope: we can't run Shor's / Grover's or forge BLAKE3 — this proves \
                     the chain fails CLOSED. The hybrid signature needs BOTH halves, so a future \
                     break of Ed25519 alone still leaves ML-DSA-65 (FIPS-204) stopping the \
                     forgery.",
                )
                .size(11.5)
                .color(MUTED)
                .italics(),
            )
            .wrap(),
        );
    }

    /// The live front-door probe: point at a running node and submit adversarial txs
    /// that are rejected at admission (nothing lands on the chain).
    fn live_section(&mut self, ui: &mut egui::Ui) {
        section_head(
            ui,
            "⌁ Live front-door probe",
            PQ,
            "Attack a REAL running node the only way an outsider can — through \
             sov_submitTransaction. Every probe is designed to be REJECTED at admission, so \
             nothing lands in the mempool: no tx, no fee, no state change.",
        );

        let live_running = self.live_running.load(Ordering::SeqCst);
        ui.horizontal(|ui| {
            let label = if live_running {
                "⌁ probing…"
            } else {
                "⌁ Probe front door"
            };
            let btn = egui::Button::new(RichText::new(label).strong().color(ON_ACCENT))
                .fill(PQ)
                .min_size(egui::vec2(170.0, 34.0));
            if ui.add_enabled(!live_running, btn).clicked() {
                self.run_live();
            }
            if live_running {
                ui.spinner();
            }
        });
        if live_running {
            ui.ctx().request_repaint_after(Duration::from_millis(150));
        }
        ui.add_space(14.0);

        struct Head {
            reachable: bool,
            target: String,
            chain: String,
            height: String,
            mainnet: bool,
            mempool: Option<(usize, usize)>,
            no_residue: bool,
            admitted: usize,
        }
        let (head, rows): (Option<Head>, Snap) = match self.live_report.lock() {
            Ok(g) => match g.as_ref() {
                Some(r) => (
                    Some(Head {
                        reachable: r.reachable,
                        target: r.target.clone(),
                        chain: r.chain_id.clone().unwrap_or_else(|| "unknown".into()),
                        height: r
                            .height
                            .map(|h| h.to_string())
                            .unwrap_or_else(|| "?".into()),
                        mainnet: r.is_mainnet,
                        mempool: r.mempool_before.zip(r.mempool_after),
                        no_residue: r.no_residue(),
                        admitted: r
                            .outcomes
                            .iter()
                            .filter(|o| o.verdict == sov_redteam::Verdict::Vulnerable)
                            .count(),
                    }),
                    snap(&r.outcomes),
                ),
                None => (None, Vec::new()),
            },
            Err(_) => (None, Vec::new()),
        };

        let Some(head) = head else {
            if live_running {
                theater(ui, true, None);
            } else {
                ui.label(
                    RichText::new("Enter a node's RPC address and probe its front door.")
                        .color(MUTED)
                        .italics(),
                );
            }
            return;
        };

        if !head.reachable {
            egui::Frame::none()
                .fill(SURFACE)
                .rounding(Rounding::same(10.0))
                .stroke(Stroke::new(1.0, alpha(THREAT, 120)))
                .inner_margin(Margin::symmetric(16.0, 13.0))
                .show(ui, |ui| {
                    ui.label(
                        RichText::new("UNREACHABLE")
                            .size(16.0)
                            .strong()
                            .color(THREAT),
                    );
                    ui.add(
                        egui::Label::new(
                            RichText::new(format!(
                                "Could not reach {} — is the node running with RPC exposed?",
                                head.target
                            ))
                            .size(12.0)
                            .color(MUTED),
                        )
                        .wrap(),
                    );
                });
            return;
        }

        // connectivity + identity banner
        egui::Frame::none()
            .fill(SURFACE)
            .rounding(Rounding::same(10.0))
            .stroke(Stroke::new(
                1.0,
                alpha(if head.mainnet { GOLD } else { PQ }, 120),
            ))
            .inner_margin(Margin::symmetric(16.0, 12.0))
            .show(ui, |ui| {
                stretch(ui, 16.0);
                ui.horizontal(|ui| {
                    ui.label(RichText::new("● connected").size(12.0).strong().color(HOLD));
                    ui.add_space(14.0);
                    ui.label(
                        RichText::new(&head.target)
                            .size(12.0)
                            .monospace()
                            .color(INK),
                    );
                    ui.add_space(14.0);
                    if head.mainnet {
                        ui.label(
                            RichText::new("LIVE MAINNET")
                                .size(11.5)
                                .strong()
                                .monospace()
                                .color(GOLD),
                        );
                    } else {
                        ui.label(RichText::new(&head.chain).size(12.0).monospace().color(PQ));
                    }
                    ui.add_space(14.0);
                    ui.label(
                        RichText::new(format!("height {}", head.height))
                            .size(12.0)
                            .monospace()
                            .color(MUTED),
                    );
                });
            });
        ui.add_space(12.0);

        ui.label(
            RichText::new(if head.admitted == 0 {
                "FRONT DOOR HELD — every adversarial tx rejected before admission"
            } else {
                "AN ADVERSARIAL TX WAS ADMITTED"
            })
            .size(14.5)
            .strong()
            .color(if head.admitted == 0 { HOLD } else { THREAT }),
        );

        // No-residue proof: the mempool must be unchanged if nothing was admitted.
        if let Some((b, a)) = head.mempool {
            let ok = head.no_residue;
            ui.label(
                RichText::new(format!(
                    "mempool {b} → {a}  ·  {}",
                    if ok {
                        "no residue — nothing landed"
                    } else {
                        "RESIDUE — a tx was admitted!"
                    }
                ))
                .size(11.5)
                .monospace()
                .color(if ok { HOLD } else { THREAT }),
            );
        }
        ui.add_space(12.0);

        let pick = self.theater_pick(&rows);
        theater(ui, live_running, pick);
        self.attack_list(ui, &rows, true, PQ);
    }

    /// The live back-door probe: join the P2P network as a hostile peer and gossip forged
    /// blocks/txs over the encrypted wire, proving the node's tip never adopts them.
    fn backdoor_section(&mut self, ui: &mut egui::Ui) {
        section_head(
            ui,
            "⛒ Live back-door probe",
            THREAT,
            "Join the P2P network as a HOSTILE peer and gossip forged blocks + txs over the \
             encrypted Noise-XX + ML-KEM wire — the nation-state surface. No wire-forged block \
             can carry valid RandomX PoW, so each is rejected at the seal or parent gate and the \
             tip never moves; after a few the node BANS us. Nothing lands.",
        );

        let running = self.backdoor_running.load(Ordering::SeqCst);
        ui.horizontal(|ui| {
            let label = if running {
                "⛒ attacking P2P…"
            } else {
                "⛒ Probe back door"
            };
            let btn = egui::Button::new(RichText::new(label).strong().color(ON_ACCENT))
                .fill(THREAT)
                .min_size(egui::vec2(170.0, 34.0));
            if ui.add_enabled(!running, btn).clicked() {
                self.run_backdoor();
            }
            if running {
                ui.spinner();
            }
        });
        if running {
            ui.ctx().request_repaint_after(Duration::from_millis(200));
        }
        ui.add_space(14.0);

        struct Head {
            error: Option<String>,
            authenticated: bool,
            target: String,
            mainnet: bool,
            heads: Option<(String, String)>,
            ejected: bool,
        }
        let (head, rows): (Option<Head>, Snap) = match self.backdoor_report.lock() {
            Ok(g) => match g.as_ref() {
                Some(r) => (
                    Some(Head {
                        error: r.error.clone(),
                        authenticated: r.authenticated,
                        target: r.p2p_target.clone(),
                        mainnet: r.is_mainnet,
                        heads: r
                            .head_before
                            .as_ref()
                            .zip(r.head_after.as_ref())
                            .map(|(b, a)| (b.1.clone(), a.1.clone())),
                        ejected: r.ejected,
                    }),
                    snap(&r.outcomes),
                ),
                None => (None, Vec::new()),
            },
            Err(_) => (None, Vec::new()),
        };

        let Some(head) = head else {
            if running {
                theater(ui, true, None);
            } else {
                ui.label(
                    RichText::new("Point it at a node to gossip forged blocks over the real wire.")
                        .color(MUTED)
                        .italics(),
                );
            }
            return;
        };

        if let Some(err) = &head.error {
            egui::Frame::none()
                .fill(SURFACE)
                .rounding(Rounding::same(10.0))
                .stroke(Stroke::new(1.0, alpha(GOLD, 120)))
                .inner_margin(Margin::symmetric(16.0, 12.0))
                .show(ui, |ui| {
                    ui.label(
                        RichText::new("could not run")
                            .size(14.0)
                            .strong()
                            .color(GOLD),
                    );
                    ui.add(egui::Label::new(RichText::new(err).size(12.0).color(MUTED)).wrap());
                });
            return;
        }

        // connectivity + identity banner
        egui::Frame::none()
            .fill(SURFACE)
            .rounding(Rounding::same(10.0))
            .stroke(Stroke::new(
                1.0,
                alpha(if head.mainnet { GOLD } else { THREAT }, 120),
            ))
            .inner_margin(Margin::symmetric(16.0, 12.0))
            .show(ui, |ui| {
                stretch(ui, 16.0);
                ui.horizontal(|ui| {
                    let (txt, col) = if head.authenticated {
                        ("● hostile peer authenticated", HOLD)
                    } else {
                        ("○ not authenticated", THREAT)
                    };
                    ui.label(RichText::new(txt).size(12.0).strong().color(col));
                    ui.add_space(12.0);
                    ui.label(
                        RichText::new(&head.target)
                            .size(12.0)
                            .monospace()
                            .color(INK),
                    );
                    ui.add_space(12.0);
                    if head.mainnet {
                        ui.label(
                            RichText::new("LIVE MAINNET")
                                .size(11.5)
                                .strong()
                                .monospace()
                                .color(GOLD),
                        );
                    }
                });
                if let Some((hb, ha)) = &head.heads {
                    let moved = ha != hb;
                    ui.label(
                        RichText::new(format!(
                            "head {} → {}  ·  {}",
                            elide_ids(hb),
                            elide_ids(ha),
                            if moved {
                                "advanced only by the node's own honest mining"
                            } else {
                                "tip unmoved"
                            }
                        ))
                        .size(11.5)
                        .monospace()
                        .color(HOLD),
                    );
                }
                if head.ejected {
                    ui.label(
                        RichText::new("the node BANNED our peer — attacker ejected")
                            .size(11.5)
                            .strong()
                            .color(HOLD),
                    );
                }
            });
        ui.add_space(12.0);

        let pick = self.theater_pick(&rows);
        theater(ui, running, pick);
        self.attack_list(ui, &rows, true, THREAT);
    }

    /// The funded-adversary probe: attack AS a REAL funded account. The operator pastes
    /// the key (held in memory only); the probe attempts a double-spend of that account's
    /// own XUS and proves the chain refuses it.
    fn funded_section(&mut self, ui: &mut egui::Ui) {
        section_head(
            ui,
            "₿ Funded adversary",
            GOLD,
            "Attack as a REAL, funded account — probe it like a thief. Paste its key (mnemonic \
             or 32-byte hex seed), held in memory only, never on disk. After proving control \
             with an honest net-zero self-transfer, it tries to STEAL: double-spend the whole \
             balance, front-run/replace, replay to drain twice, rewind the nonce, drain an \
             account it doesn't own, and mint from thin air (from throwaway empty accounts, so \
             it can never wedge your funds). Every theft is refused — no coins move. Only the \
             honest tx lands (a small gas fee).",
        );

        // Key entry (password-style) + Load.
        ui.horizontal(|ui| {
            ui.label(RichText::new("funded key").size(12.0).color(MUTED));
            ui.add(
                egui::TextEdit::singleline(&mut self.funded_key_input)
                    .password(true)
                    .desired_width(260.0)
                    .hint_text("mnemonic  or  32-byte hex seed"),
            );
            if ui.button(RichText::new("Load").strong()).clicked() {
                self.load_funded();
            }
        });
        if !self.funded_account.is_empty() {
            ui.horizontal(|ui| {
                ui.label(RichText::new("account").size(11.5).color(MUTED));
                let short = elide_ids(&self.funded_account);
                let r = ui
                    .add(
                        egui::Label::new(RichText::new(&short).size(11.5).monospace().color(HOLD))
                            .sense(Sense::click()),
                    )
                    .on_hover_text(RichText::new(&self.funded_account).monospace().size(11.0));
                if r.clicked() {
                    ui.ctx().copy_text(self.funded_account.clone());
                }
            });
        }
        if !self.funded_status.is_empty() {
            let ok = self.funded_seed.is_some();
            ui.label(RichText::new(&self.funded_status).size(11.0).color(if ok {
                MUTED
            } else {
                THREAT
            }));
        }
        ui.add_space(10.0);

        // Run.
        let running = self.funded_running.load(Ordering::SeqCst);
        let has_key = self.funded_seed.is_some();
        let btn = egui::Button::new(
            RichText::new(if running {
                "₿ attacking…"
            } else {
                "₿ Run funded double-spend (spends a real fee)"
            })
            .strong()
            .color(ON_ACCENT),
        )
        .fill(GOLD)
        .min_size(egui::vec2(310.0, 34.0));
        if ui.add_enabled(has_key && !running, btn).clicked() {
            self.run_funded();
        }
        if running {
            ui.ctx().request_repaint_after(Duration::from_millis(200));
        }
        ui.add_space(14.0);

        struct Head {
            error: Option<String>,
            balance: String,
            nonce: u64,
            mainnet: bool,
            empty: bool,
        }
        let (head, rows): (Option<Head>, Snap) = match self.funded_report.lock() {
            Ok(g) => match g.as_ref() {
                Some(r) => (
                    Some(Head {
                        error: r.error.clone(),
                        balance: r.balance.clone(),
                        nonce: r.nonce,
                        mainnet: r.is_mainnet,
                        empty: r.balance_grains == 0,
                    }),
                    snap(&r.outcomes),
                ),
                None => (None, Vec::new()),
            },
            Err(_) => (None, Vec::new()),
        };

        let Some(head) = head else {
            if running {
                theater(ui, true, None);
            }
            return;
        };
        if let Some(err) = &head.error {
            ui.add(egui::Label::new(RichText::new(err).size(12.5).color(THREAT).italics()).wrap());
            return;
        }

        // Balance / identity banner.
        egui::Frame::none()
            .fill(SURFACE)
            .rounding(Rounding::same(10.0))
            .stroke(Stroke::new(1.0, alpha(GOLD, 120)))
            .inner_margin(Margin::symmetric(16.0, 12.0))
            .show(ui, |ui| {
                stretch(ui, 16.0);
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new(format!("balance {}", head.balance))
                            .size(13.0)
                            .strong()
                            .monospace()
                            .color(GOLD),
                    );
                    ui.add_space(14.0);
                    ui.label(
                        RichText::new(format!("nonce {}", head.nonce))
                            .size(12.0)
                            .monospace()
                            .color(MUTED),
                    );
                    ui.add_space(14.0);
                    if head.mainnet {
                        ui.label(
                            RichText::new("LIVE MAINNET")
                                .size(11.5)
                                .strong()
                                .monospace()
                                .color(GOLD),
                        );
                    }
                });
                if head.empty {
                    ui.label(
                        RichText::new(
                            "account shows no balance — fund it first for leg 1 to confirm",
                        )
                        .size(11.0)
                        .color(THREAT),
                    );
                }
            });
        ui.add_space(12.0);

        let pick = self.theater_pick(&rows);
        theater(ui, running, pick);
        self.attack_list(ui, &rows, false, GOLD);
    }
}

/// One heartbeat waveform: P wave, QRS complex, T wave, over ~0.6 s. `e` is the
/// seconds elapsed since the beat at the sample being drawn.
fn qrs(e: f32) -> f32 {
    if !(0.0..0.62).contains(&e) {
        return 0.0;
    }
    let seg = |x0: f32, x1: f32, a: f32| -> f32 {
        if e >= x0 && e < x1 {
            a * (((e - x0) / (x1 - x0)) * std::f32::consts::PI).sin()
        } else {
            0.0
        }
    };
    seg(0.0, 0.10, 0.18)
        + seg(0.12, 0.16, -0.35)
        + seg(0.16, 0.22, 1.0)
        + seg(0.22, 0.28, -0.45)
        + seg(0.36, 0.58, 0.30)
}

fn main() -> eframe::Result<()> {
    // `--run` starts the in-process battery the moment the window opens, instead
    // of waiting for a click: what you want for a demo, a kiosk, or a release
    // screenshot. It runs the SAME `run_all()` the button runs — nothing about
    // the attacks or the verdicts changes.
    let autorun = std::env::args().any(|a| a == "--run" || a == "--autorun");
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1120.0, 940.0])
            .with_min_inner_size([900.0, 580.0])
            .with_title("SOV Red Team"),
        ..Default::default()
    };
    eframe::run_native(
        "SOV Red Team",
        options,
        Box::new(move |_cc| {
            let mut app = RedTeamApp::default();
            if autorun {
                app.view = View::InProcess;
                app.run();
            }
            Ok(Box::new(app))
        }),
    )
}
