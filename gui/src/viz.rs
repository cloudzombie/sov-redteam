//! Attack visualisations — small custom-painted diagrams that SHOW the mechanic
//! of an attack and where the chain stopped it.
//!
//! Strictly presentational. A diagram is chosen from the attack's engine-supplied
//! `category` + `name`, and its outcome state is derived ONLY from the
//! `sov_redteam::Verdict` the engine returned:
//!
//!   * `Defended`  → the projectile is stopped at the gate, ✗, hold-green
//!   * `Vulnerable`→ the projectile lands on the target, alarm-red, ringed
//!   * `Info`      → muted, disclosed, no claim either way
//!   * in-flight   → animated with NO outcome mark at all
//!
//! Nothing here can invent a verdict: `Fate::of` is a total mapping from the
//! engine's enum, and the in-flight state is only used while a probe is actually
//! running.

use eframe::egui::{self, Align2, Color32, FontId, Pos2, Rect, Shape, Stroke, Vec2};

use crate::theme::{alpha, mix, BORDER, GOLD, HOLD, INK, MUTED, PQ, SURFACE, THREAT};

/// Which diagram illustrates an attack.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Viz {
    /// A key that does not hash to the account it is spending from.
    WrongKey,
    /// A signature seal that does not verify (forged, empty, spliced, corrupted).
    ForgedSeal,
    /// The hybrid signature: Ed25519 AND ML-DSA-65, breaking one is not enough.
    PqConjunction,
    /// The amount edited after signing — the seal binds it.
    Malleability,
    /// RotateKey / SetMultisig: swapping the key that controls an account.
    KeySeize,
    /// Arithmetic that would wrap a balance.
    Overflow,
    /// A whole foreign chain pushed at the honest one.
    ForeignChain,
    /// Competing branches; the heavier honest one wins.
    Reorg,
    /// Timestamp games: backdating under MTP, pre-genesis, future leaps.
    Timewarp,
    /// A sealed header edited after the fact.
    HeaderTamper,
    /// The same block or nonce spent twice.
    Replay,
    /// More demand than a block may carry.
    Flood,
    /// A nonce rewound or leapt to re-spend.
    NonceRewind,
    /// Value moved out of an account the attacker does not own.
    Drain,
    /// A payload the decoder must refuse.
    Malformed,
    /// Anything else: a shield taking a hit.
    Shield,
}

impl Viz {
    /// Pick the diagram from the attack's REAL engine identity. Substring match on
    /// the name first (most specific), then the class.
    pub fn of(category: &str, name: &str) -> Viz {
        let n = name.to_ascii_lowercase();
        let has = |k: &str| n.contains(k);

        if has("rotatekey") || has("rotate key") || has("multisig") || has("seize") {
            return Viz::KeySeize;
        }
        if has("malleab") || has("edit amount") || has("edit the amount") {
            return Viz::Malleability;
        }
        if has("overflow") {
            return Viz::Overflow;
        }
        if has("post-quantum")
            || has("ml-dsa")
            || has("downgrade")
            || has("both signature halves")
            || has("halves")
            || has("ed25519")
        {
            return Viz::PqConjunction;
        }
        if has("private branch") || has("reorg") || has("tie-break") || has("fork") {
            return Viz::Reorg;
        }
        if has("foreign") || has("fabricated-pow") || has("orphan") || has("foreign genesis") {
            return Viz::ForeignChain;
        }
        if has("timewarp") || has("timestamp") || has("pre-genesis") || has("future-height") {
            return Viz::Timewarp;
        }
        if has("replay") || has("duplicate") || has("twice") || has("re-import") {
            return Viz::Replay;
        }
        if has("flood") {
            return Viz::Flood;
        }
        if has("nonce") {
            return Viz::NonceRewind;
        }
        if has("wrong key")
            || has("wrong signer")
            || has("impersonat")
            || has("brute-force")
            || has("implicit-id")
            || has("keyless")
        {
            return Viz::WrongKey;
        }
        if has("forge") || has("signature") || has("splice") || has("corrupt") || has("empty") {
            return Viz::ForgedSeal;
        }
        if has("malformed")
            || has("not-a-")
            || has("type confusion")
            || has("unknown method")
            || has("missing signature")
            || has("payload")
        {
            return Viz::Malformed;
        }
        if has("drain")
            || has("double-spend")
            || has("steal")
            || has("mint")
            || has("coinbase")
            || has("exit via")
            || has("spend")
            || has("transfer")
            || has("front-run")
        {
            return Viz::Drain;
        }

        match category {
            "time" => Viz::Timewarp,
            "tamper" => Viz::HeaderTamper,
            "forgery" | "crypto" => Viz::ForgedSeal,
            "post-quantum" => Viz::PqConjunction,
            "replay" => Viz::Replay,
            "consensus" => Viz::Reorg,
            "flood" => Viz::Flood,
            "foreign-chain" => Viz::ForeignChain,
            "encoding" | "rpc" => Viz::Malformed,
            "authz" | "theft" | "keyless" => Viz::WrongKey,
            _ => Viz::Shield,
        }
    }

    /// One line naming the mechanic the diagram is drawing.
    pub fn caption(self) -> &'static str {
        match self {
            Viz::WrongKey => "attacker key → blake3 → hash ≠ account id",
            Viz::ForgedSeal => "the signature seal must verify against the account's key",
            Viz::PqConjunction => {
                "hybrid = Ed25519 AND ML-DSA-65 — breaking one half is not enough"
            }
            Viz::Malleability => "the signature binds the amount: edit it and the seal dies",
            Viz::KeySeize => "changing who controls an account needs that account's own key",
            Viz::Overflow => "checked arithmetic: a wrapping credit is refused, not truncated",
            Viz::ForeignChain => {
                "a foreign block has no parent on the honest chain — it can't attach"
            }
            Viz::Reorg => "heaviest work wins; the honest branch outweighs the private one",
            Viz::Timewarp => "median-time-past and the lower bound pin the clock",
            Viz::HeaderTamper => "the PoW seal binds every header field",
            Viz::Replay => "a block, or a nonce, cannot be spent twice",
            Viz::Flood => "the elastic size cap bounds a block no matter the demand",
            Viz::NonceRewind => "the account nonce only moves forward",
            Viz::Drain => "value only leaves an account its owner authorised",
            Viz::Malformed => "the decoder refuses what it cannot parse",
            Viz::Shield => "the attack meets the consensus rule that answers it",
        }
    }
}

/// The reel shown in the theatre while a battery is actually running: the classes
/// of attack that battery throws. No verdict is drawn over it — it illustrates
/// what is being attempted, never what happened.
pub const REEL: [Viz; 6] = [
    Viz::WrongKey,
    Viz::ForgedSeal,
    Viz::PqConjunction,
    Viz::HeaderTamper,
    Viz::Reorg,
    Viz::Flood,
];

/// What actually happened — derived from the engine verdict, or "still running".
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Fate {
    /// The engine returned `Defended`: the chain refused it.
    Held,
    /// The engine returned `Vulnerable`: it got through. Alarm.
    Breached,
    /// The engine returned `Info`: disclosed, no pass and no break.
    Noted,
    /// A probe is running right now — no outcome is claimed.
    InFlight,
}

impl Fate {
    /// Total mapping from the engine's verdict. There is no other constructor for
    /// a finished attack, so a card can never show an outcome the engine did not
    /// return.
    pub fn of(v: sov_redteam::Verdict) -> Fate {
        match v {
            sov_redteam::Verdict::Defended => Fate::Held,
            sov_redteam::Verdict::Vulnerable => Fate::Breached,
            sov_redteam::Verdict::Info => Fate::Noted,
        }
    }

    fn color(self) -> Color32 {
        match self {
            Fate::Held => HOLD,
            Fate::Breached => THREAT,
            Fate::Noted => MUTED,
            Fate::InFlight => GOLD,
        }
    }

    /// Whether the diagram should show the attack being stopped at the gate.
    fn stopped(self) -> bool {
        matches!(self, Fate::Held | Fate::Noted)
    }

    fn animated(self) -> bool {
        self == Fate::InFlight
    }
}

// ── canvas ──────────────────────────────────────────────────────────────────

/// Normalised drawing surface: every diagram is authored in 0..1 space and
/// scales to whatever rect it is handed (a 44px row glyph or a 280px theatre).
struct Canvas {
    rect: Rect,
    big: bool,
}

impl Canvas {
    fn p(&self, x: f32, y: f32) -> Pos2 {
        egui::pos2(
            self.rect.left() + x * self.rect.width(),
            self.rect.top() + y * self.rect.height(),
        )
    }
    /// A length scaled off the short side, so shapes stay proportional.
    fn u(&self, v: f32) -> f32 {
        v * self.rect.height().min(self.rect.width())
    }
    fn line_w(&self) -> f32 {
        if self.big {
            1.7
        } else {
            1.1
        }
    }
    fn font(&self) -> FontId {
        FontId::monospace(if self.big { 9.5 } else { 7.0 })
    }
    /// Small mode drops every label — a 44px glyph has no room for text.
    fn label(&self, p: &egui::Painter, at: Pos2, text: &str, col: Color32) {
        if self.big {
            p.text(at, Align2::CENTER_CENTER, text, self.font(), col);
        }
    }
}

/// Paint one attack diagram.
///
/// `t` is wall-clock seconds; it only matters when `fate` is `InFlight` or the
/// caller is hovering, so a static screen of results costs nothing to redraw.
pub fn paint(p: &egui::Painter, rect: Rect, viz: Viz, fate: Fate, t: f32) {
    let c = Canvas {
        rect,
        big: rect.width() >= 110.0,
    };
    p.rect_filled(
        rect,
        egui::Rounding::same(if c.big { 10.0 } else { 6.0 }),
        alpha(SURFACE, if c.big { 190 } else { 110 }),
    );
    if c.big {
        p.rect_stroke(
            rect,
            egui::Rounding::same(10.0),
            Stroke::new(1.0, alpha(BORDER, 200)),
        );
    }
    match viz {
        Viz::WrongKey => wrong_key(p, &c, fate, t),
        Viz::ForgedSeal => forged_seal(p, &c, fate, t),
        Viz::PqConjunction => pq_conjunction(p, &c, fate, t),
        Viz::Malleability => malleability(p, &c, fate, t),
        Viz::KeySeize => key_seize(p, &c, fate, t),
        Viz::Overflow => overflow(p, &c, fate, t),
        Viz::ForeignChain => foreign_chain(p, &c, fate, t),
        Viz::Reorg => reorg(p, &c, fate, t),
        Viz::Timewarp => timewarp(p, &c, fate, t),
        Viz::HeaderTamper => header_tamper(p, &c, fate, t),
        Viz::Replay => replay(p, &c, fate, t),
        Viz::Flood => flood(p, &c, fate, t),
        Viz::NonceRewind => nonce_rewind(p, &c, fate, t),
        Viz::Drain => drain(p, &c, fate, t),
        Viz::Malformed => malformed(p, &c, fate, t),
        Viz::Shield => shield(p, &c, fate, t),
    }
}

// ── primitives ──────────────────────────────────────────────────────────────

fn stroke(c: &Canvas, col: Color32) -> Stroke {
    Stroke::new(c.line_w(), col)
}

fn arrow(p: &egui::Painter, c: &Canvas, a: Pos2, b: Pos2, col: Color32) {
    p.line_segment([a, b], stroke(c, col));
    let d = (b - a).normalized();
    let n = Vec2::new(-d.y, d.x);
    let h = c.u(0.07);
    p.add(Shape::convex_polygon(
        vec![
            b,
            b - d * h * 1.6 + n * h * 0.7,
            b - d * h * 1.6 - n * h * 0.7,
        ],
        col,
        Stroke::NONE,
    ));
}

fn dashed(p: &egui::Painter, c: &Canvas, a: Pos2, b: Pos2, col: Color32) {
    let steps = 9;
    for i in 0..steps {
        if i % 2 == 1 {
            continue;
        }
        let f0 = i as f32 / steps as f32;
        let f1 = (i as f32 + 1.0) / steps as f32;
        p.line_segment([a + (b - a) * f0, a + (b - a) * f1], stroke(c, col));
    }
}

fn cross(p: &egui::Painter, c: &Canvas, at: Pos2, r: f32, col: Color32) {
    let s = Stroke::new(c.line_w() * 1.35, col);
    p.line_segment([at + Vec2::new(-r, -r), at + Vec2::new(r, r)], s);
    p.line_segment([at + Vec2::new(r, -r), at + Vec2::new(-r, r)], s);
}

fn tick(p: &egui::Painter, c: &Canvas, at: Pos2, r: f32, col: Color32) {
    let s = Stroke::new(c.line_w() * 1.35, col);
    p.line_segment(
        [at + Vec2::new(-r, 0.0), at + Vec2::new(-r * 0.2, r * 0.8)],
        s,
    );
    p.line_segment(
        [
            at + Vec2::new(-r * 0.2, r * 0.8),
            at + Vec2::new(r, -r * 0.9),
        ],
        s,
    );
}

/// A rounded "block"/record box.
fn box_glyph(
    p: &egui::Painter,
    c: &Canvas,
    center: Pos2,
    size: Vec2,
    col: Color32,
    fill: Option<Color32>,
) {
    let r = Rect::from_center_size(center, size);
    let round = egui::Rounding::same(c.u(0.05));
    if let Some(f) = fill {
        p.rect_filled(r, round, f);
    }
    p.rect_stroke(r, round, stroke(c, col));
}

/// A key: bow, shaft, two teeth.
fn key_glyph(p: &egui::Painter, c: &Canvas, at: Pos2, r: f32, col: Color32) {
    let s = stroke(c, col);
    p.circle_stroke(at - Vec2::new(r * 0.9, 0.0), r * 0.55, s);
    p.line_segment(
        [at - Vec2::new(r * 0.35, 0.0), at + Vec2::new(r * 1.1, 0.0)],
        s,
    );
    p.line_segment(
        [
            at + Vec2::new(r * 0.45, 0.0),
            at + Vec2::new(r * 0.45, r * 0.55),
        ],
        s,
    );
    p.line_segment(
        [
            at + Vec2::new(r * 1.05, 0.0),
            at + Vec2::new(r * 1.05, r * 0.55),
        ],
        s,
    );
}

/// A padlock. `broken` draws the shackle snapped open.
fn lock_glyph(p: &egui::Painter, c: &Canvas, at: Pos2, r: f32, col: Color32, broken: bool) {
    let body = Rect::from_center_size(at + Vec2::new(0.0, r * 0.45), Vec2::new(r * 1.5, r * 1.1));
    p.rect_stroke(body, egui::Rounding::same(c.u(0.03)), stroke(c, col));
    let top = at - Vec2::new(0.0, r * 0.25);
    let arc = |from: f32, to: f32, painter: &egui::Painter| {
        let n = 10;
        let pts: Vec<Pos2> = (0..=n)
            .map(|i| {
                let a = from + (to - from) * i as f32 / n as f32;
                top + Vec2::new(a.cos() * r * 0.55, -a.sin() * r * 0.55)
            })
            .collect();
        painter.add(Shape::line(pts, stroke(c, col)));
    };
    if broken {
        arc(0.35, std::f32::consts::PI * 0.55, p);
        // the snapped half, tilted away
        p.line_segment(
            [
                top + Vec2::new(r * 0.55, r * 0.05),
                top + Vec2::new(r * 1.05, -r * 0.35),
            ],
            stroke(c, col),
        );
    } else {
        arc(0.0, std::f32::consts::PI, p);
    }
}

/// A wax seal over a signature. `cracked` splits it.
fn seal_glyph(p: &egui::Painter, c: &Canvas, at: Pos2, r: f32, col: Color32, cracked: bool) {
    p.circle_stroke(at, r, stroke(c, col));
    p.circle_filled(at, r * 0.72, alpha(col, 34));
    if cracked {
        let s = stroke(c, col);
        p.add(Shape::line(
            vec![
                at + Vec2::new(0.0, -r),
                at + Vec2::new(r * 0.28, -r * 0.2),
                at + Vec2::new(-r * 0.25, r * 0.2),
                at + Vec2::new(0.05 * r, r),
            ],
            s,
        ));
    } else {
        for i in 0..3 {
            let y = -r * 0.4 + i as f32 * r * 0.4;
            p.line_segment(
                [at + Vec2::new(-r * 0.45, y), at + Vec2::new(r * 0.45, y)],
                Stroke::new(c.line_w() * 0.8, alpha(col, 190)),
            );
        }
    }
}

/// The shared "attack lane": a track from the attacker to the target, a gate the
/// rule sits on, and the projectile — stopped at the gate when the chain held,
/// through it (alarmed) when it did not, and travelling while in flight.
struct Lane {
    from: f32,
    to: f32,
    y: f32,
    gate: f32,
}

fn lane(p: &egui::Painter, c: &Canvas, l: Lane, fate: Fate, t: f32, tint: Color32) {
    let col = fate.color();
    let a = c.p(l.from, l.y);
    let b = c.p(l.to, l.y);
    dashed(p, c, a, b, alpha(tint, 90));

    // the gate: the consensus rule standing in the way
    let gx = c.p(l.gate, l.y).x;
    let gate_col = if fate.stopped() { col } else { alpha(col, 150) };
    let top = c.p(l.gate, l.y - 0.24).y;
    let bot = c.p(l.gate, l.y + 0.24).y;
    p.line_segment(
        [egui::pos2(gx, top), egui::pos2(gx, bot)],
        Stroke::new(c.line_w() * 1.6, gate_col),
    );

    // the projectile
    let (px, alarm) = match fate {
        Fate::InFlight => {
            let ph = (t * 0.75).fract();
            // charge up to the gate, then recoil — an attempt, not an outcome
            let f = if ph < 0.7 {
                ph / 0.7
            } else {
                1.0 - (ph - 0.7) / 0.3
            };
            (l.from + (l.gate - l.from) * f, false)
        }
        Fate::Breached => (l.to, true),
        _ => (l.gate - (l.gate - l.from) * 0.16, false),
    };
    let pos = c.p(px, l.y);
    let r = c.u(0.075);
    if alarm {
        let ring = 1.0 + 0.35 * (t * 4.0).sin();
        p.circle_stroke(
            pos,
            r * 2.1 * ring,
            Stroke::new(c.line_w(), alpha(col, 130)),
        );
    }
    p.circle_filled(pos, r, col);

    // the outcome mark, only once there IS an outcome
    match fate {
        Fate::Held => cross(p, c, c.p(l.gate, l.y), c.u(0.11), col),
        Fate::Breached => tick(p, c, c.p(l.to, l.y - 0.26), c.u(0.1), col),
        Fate::Noted => {
            p.circle_filled(c.p(l.gate, l.y), c.u(0.045), col);
        }
        Fate::InFlight => {}
    }
}

// ── the diagrams ────────────────────────────────────────────────────────────

fn wrong_key(p: &egui::Painter, c: &Canvas, fate: Fate, t: f32) {
    key_glyph(p, c, c.p(0.13, 0.36), c.u(0.13), THREAT);
    box_glyph(
        p,
        c,
        c.p(0.45, 0.36),
        Vec2::new(c.u(0.34), c.u(0.24)),
        alpha(INK, 170),
        None,
    );
    c.label(p, c.p(0.45, 0.36), "blake3", alpha(INK, 200));
    arrow(p, c, c.p(0.24, 0.36), c.p(0.33, 0.36), alpha(THREAT, 200));
    box_glyph(
        p,
        c,
        c.p(0.83, 0.36),
        Vec2::new(c.u(0.36), c.u(0.24)),
        alpha(GOLD, 200),
        Some(alpha(GOLD, 22)),
    );
    c.label(p, c.p(0.83, 0.36), "pot id", GOLD);
    c.label(p, c.p(0.5, 0.9), "hash ≠ id", alpha(MUTED, 220));
    lane(
        p,
        c,
        Lane {
            from: 0.58,
            to: 0.83,
            y: 0.36,
            gate: 0.68,
        },
        fate,
        t,
        MUTED,
    );
}

fn forged_seal(p: &egui::Painter, c: &Canvas, fate: Fate, t: f32) {
    // the signed record …
    box_glyph(
        p,
        c,
        c.p(0.27, 0.42),
        Vec2::new(c.u(0.4), c.u(0.5)),
        alpha(INK, 150),
        Some(alpha(INK, 12)),
    );
    for i in 0..3 {
        let y = 0.28 + i as f32 * 0.1;
        p.line_segment(
            [c.p(0.14, y), c.p(0.34, y)],
            Stroke::new(c.line_w() * 0.8, alpha(MUTED, 150)),
        );
    }
    // … and its seal, which the verifier breaks
    let cracked = fate.stopped();
    seal_glyph(p, c, c.p(0.27, 0.72), c.u(0.13), fate.color(), cracked);
    c.label(p, c.p(0.27, 0.05), "forged tx", alpha(THREAT, 220));
    box_glyph(
        p,
        c,
        c.p(0.88, 0.45),
        Vec2::new(c.u(0.2), c.u(0.42)),
        alpha(GOLD, 190),
        Some(alpha(GOLD, 18)),
    );
    c.label(p, c.p(0.88, 0.88), "chain", alpha(GOLD, 200));
    lane(
        p,
        c,
        Lane {
            from: 0.5,
            to: 0.88,
            y: 0.45,
            gate: 0.68,
        },
        fate,
        t,
        MUTED,
    );
    c.label(p, c.p(0.68, 0.12), "verify", alpha(INK, 190));
}

fn pq_conjunction(p: &egui::Painter, c: &Canvas, fate: Fate, t: f32) {
    // Two locks in series. The engine's PQ attacks break ONE half; the AND still
    // stops the spend — so the intact lock carries the verdict colour.
    let broken_col = THREAT;
    lock_glyph(p, c, c.p(0.22, 0.4), c.u(0.19), broken_col, true);
    lock_glyph(p, c, c.p(0.55, 0.4), c.u(0.19), fate.color(), false);
    c.label(p, c.p(0.22, 0.86), "Ed25519", alpha(broken_col, 220));
    c.label(p, c.p(0.55, 0.86), "ML-DSA-65", alpha(fate.color(), 230));
    c.label(p, c.p(0.385, 0.14), "AND", alpha(INK, 210));
    p.line_segment(
        [c.p(0.33, 0.4), c.p(0.44, 0.4)],
        Stroke::new(c.line_w() * 1.4, alpha(INK, 170)),
    );
    lane(
        p,
        c,
        Lane {
            from: 0.68,
            to: 0.94,
            y: 0.4,
            gate: 0.78,
        },
        fate,
        t,
        MUTED,
    );
}

fn malleability(p: &egui::Painter, c: &Canvas, fate: Fate, t: f32) {
    // A signed record whose amount bar is being stretched after the fact.
    box_glyph(
        p,
        c,
        c.p(0.36, 0.42),
        Vec2::new(c.u(0.62), c.u(0.5)),
        alpha(INK, 150),
        Some(alpha(INK, 12)),
    );
    let grow = if fate.animated() {
        0.5 + 0.5 * (t * 2.2).sin()
    } else {
        1.0
    };
    let base = 0.12;
    let full = 0.30 + 0.28 * grow;
    p.rect_filled(
        Rect::from_min_max(c.p(base, 0.28), c.p(base + full * 0.6, 0.38)),
        egui::Rounding::same(c.u(0.02)),
        alpha(GOLD, 200),
    );
    c.label(p, c.p(0.36, 0.55), "amount edited", alpha(THREAT, 220));
    seal_glyph(
        p,
        c,
        c.p(0.36, 0.78),
        c.u(0.11),
        fate.color(),
        fate.stopped(),
    );
    lane(
        p,
        c,
        Lane {
            from: 0.7,
            to: 0.94,
            y: 0.42,
            gate: 0.8,
        },
        fate,
        t,
        MUTED,
    );
}

fn key_seize(p: &egui::Painter, c: &Canvas, fate: Fate, t: f32) {
    box_glyph(
        p,
        c,
        c.p(0.75, 0.42),
        Vec2::new(c.u(0.42), c.u(0.46)),
        alpha(GOLD, 200),
        Some(alpha(GOLD, 20)),
    );
    c.label(p, c.p(0.75, 0.88), "account", alpha(GOLD, 210));
    key_glyph(p, c, c.p(0.75, 0.42), c.u(0.1), alpha(HOLD, 220));
    key_glyph(p, c, c.p(0.13, 0.42), c.u(0.11), THREAT);
    c.label(p, c.p(0.36, 0.14), "RotateKey", alpha(THREAT, 220));
    lane(
        p,
        c,
        Lane {
            from: 0.26,
            to: 0.75,
            y: 0.42,
            gate: 0.53,
        },
        fate,
        t,
        THREAT,
    );
}

fn overflow(p: &egui::Painter, c: &Canvas, fate: Fate, t: f32) {
    // A value bar that runs past the end of its container.
    let bar = Rect::from_min_max(c.p(0.08, 0.3), c.p(0.62, 0.46));
    p.rect_stroke(
        bar,
        egui::Rounding::same(c.u(0.03)),
        stroke(c, alpha(INK, 170)),
    );
    let f = if fate.animated() {
        (t * 0.8).fract()
    } else {
        1.0
    };
    p.rect_filled(
        Rect::from_min_max(
            bar.left_top(),
            egui::pos2(bar.left() + bar.width() * f, bar.bottom()),
        ),
        egui::Rounding::same(c.u(0.03)),
        alpha(GOLD, 200),
    );
    // the part that would wrap
    p.rect_filled(
        Rect::from_min_max(c.p(0.63, 0.32), c.p(0.63 + 0.08 * f, 0.44)),
        egui::Rounding::same(c.u(0.02)),
        alpha(THREAT, 210),
    );
    c.label(p, c.p(0.35, 0.66), "u64 + amount → wrap", alpha(MUTED, 220));
    lane(
        p,
        c,
        Lane {
            from: 0.66,
            to: 0.94,
            y: 0.38,
            gate: 0.78,
        },
        fate,
        t,
        MUTED,
    );
}

/// The honest chain along the top; the attacker's own chain below, trying to
/// attach. The joining link is the thing that fails.
fn foreign_chain(p: &egui::Painter, c: &Canvas, fate: Fate, t: f32) {
    let bw = c.u(0.17);
    let bh = c.u(0.2);
    for i in 0..4 {
        let x = 0.14 + i as f32 * 0.24;
        box_glyph(
            p,
            c,
            c.p(x, 0.24),
            Vec2::new(bw, bh),
            alpha(HOLD, 210),
            Some(alpha(HOLD, 20)),
        );
        if i < 3 {
            p.line_segment(
                [c.p(x + 0.06, 0.24), c.p(x + 0.18, 0.24)],
                stroke(c, alpha(HOLD, 170)),
            );
        }
    }
    c.label(p, c.p(0.14, 0.04), "honest", alpha(HOLD, 210));
    for i in 0..2 {
        let x = 0.16 + i as f32 * 0.24;
        box_glyph(
            p,
            c,
            c.p(x, 0.76),
            Vec2::new(bw, bh),
            alpha(THREAT, 210),
            Some(alpha(THREAT, 22)),
        );
        if i < 1 {
            p.line_segment(
                [c.p(x + 0.06, 0.76), c.p(x + 0.18, 0.76)],
                stroke(c, alpha(THREAT, 170)),
            );
        }
    }
    c.label(p, c.p(0.18, 0.96), "foreign genesis", alpha(THREAT, 210));
    // the attach attempt
    let col = fate.color();
    dashed(p, c, c.p(0.46, 0.68), c.p(0.62, 0.34), alpha(col, 160));
    match fate {
        Fate::Held => cross(p, c, c.p(0.54, 0.51), c.u(0.1), col),
        Fate::Breached => {
            let ring = 1.0 + 0.3 * (t * 4.0).sin();
            p.circle_stroke(
                c.p(0.62, 0.28),
                c.u(0.16) * ring,
                Stroke::new(c.line_w(), col),
            );
            tick(p, c, c.p(0.54, 0.51), c.u(0.09), col);
        }
        Fate::Noted => {
            p.circle_filled(c.p(0.54, 0.51), c.u(0.045), col);
        }
        Fate::InFlight => {
            let f = (t * 0.9).fract();
            p.circle_filled(
                c.p(0.46 + 0.16 * f, 0.68 - 0.34 * f),
                c.u(0.06),
                alpha(col, 230),
            );
        }
    }
}

/// Competing branches from a shared prefix: the honest one is heavier.
fn reorg(p: &egui::Painter, c: &Canvas, fate: Fate, t: f32) {
    let bw = c.u(0.15);
    let bh = c.u(0.18);
    for i in 0..2 {
        let x = 0.1 + i as f32 * 0.18;
        box_glyph(
            p,
            c,
            c.p(x, 0.5),
            Vec2::new(bw, bh),
            alpha(INK, 190),
            Some(alpha(INK, 14)),
        );
    }
    p.line_segment([c.p(0.15, 0.5), c.p(0.23, 0.5)], stroke(c, alpha(INK, 150)));
    // honest branch (heavier: more blocks, brighter)
    for i in 0..3 {
        let x = 0.48 + i as f32 * 0.18;
        box_glyph(
            p,
            c,
            c.p(x, 0.26),
            Vec2::new(bw, bh),
            alpha(HOLD, 220),
            Some(alpha(HOLD, 26)),
        );
    }
    p.line_segment(
        [c.p(0.34, 0.46), c.p(0.42, 0.3)],
        stroke(c, alpha(HOLD, 190)),
    );
    c.label(p, c.p(0.66, 0.06), "heavier — wins", alpha(HOLD, 220));
    // attacker's private branch
    let col = fate.color();
    let fade = if fate.animated() {
        0.5 + 0.5 * (t * 1.6).sin()
    } else {
        1.0
    };
    for i in 0..2 {
        let x = 0.48 + i as f32 * 0.18;
        box_glyph(
            p,
            c,
            c.p(x, 0.76),
            Vec2::new(bw, bh),
            alpha(THREAT, (150.0 * fade) as u8 + 60),
            Some(alpha(THREAT, 20)),
        );
    }
    p.line_segment(
        [c.p(0.34, 0.54), c.p(0.42, 0.72)],
        stroke(c, alpha(THREAT, 180)),
    );
    c.label(p, c.p(0.66, 0.95), "private branch", alpha(THREAT, 200));
    match fate {
        Fate::Held => cross(p, c, c.p(0.84, 0.76), c.u(0.1), col),
        Fate::Breached => tick(p, c, c.p(0.84, 0.76), c.u(0.1), col),
        Fate::Noted => {
            p.circle_filled(c.p(0.84, 0.76), c.u(0.045), col);
        }
        Fate::InFlight => {}
    }
}

fn timewarp(p: &egui::Painter, c: &Canvas, fate: Fate, t: f32) {
    let ctr = c.p(0.24, 0.45);
    let r = c.u(0.24);
    p.circle_stroke(ctr, r, stroke(c, alpha(INK, 190)));
    // the hand, shoved backwards
    let ang = if fate.animated() {
        -0.9 - 1.2 * (0.5 + 0.5 * (t * 1.8).sin())
    } else {
        -2.1
    };
    p.line_segment(
        [
            ctr,
            ctr + Vec2::new(ang.cos() * r * 0.8, ang.sin() * r * 0.8),
        ],
        Stroke::new(c.line_w() * 1.3, THREAT),
    );
    p.line_segment(
        [ctr, ctr + Vec2::new(0.0, -r * 0.55)],
        Stroke::new(c.line_w(), alpha(MUTED, 200)),
    );
    c.label(p, c.p(0.24, 0.94), "backdated", alpha(THREAT, 210));
    c.label(p, c.p(0.72, 0.06), "median-time-past", alpha(INK, 200));
    lane(
        p,
        c,
        Lane {
            from: 0.5,
            to: 0.94,
            y: 0.45,
            gate: 0.72,
        },
        fate,
        t,
        MUTED,
    );
}

/// A sealed header whose fields are being edited under the seal.
fn header_tamper(p: &egui::Painter, c: &Canvas, fate: Fate, t: f32) {
    let x0 = 0.09;
    for i in 0..4 {
        let y = 0.2 + i as f32 * 0.13;
        let hot = i == 1;
        let col = if hot { THREAT } else { alpha(MUTED, 170) };
        let w = if hot { 0.3 } else { 0.24 };
        let wob = if hot && fate.animated() {
            0.04 * (t * 3.0).sin()
        } else {
            0.0
        };
        p.rect_filled(
            Rect::from_min_max(c.p(x0, y), c.p(x0 + w + wob, y + 0.075)),
            egui::Rounding::same(c.u(0.02)),
            col,
        );
    }
    box_glyph(
        p,
        c,
        c.p(0.26, 0.44),
        Vec2::new(c.u(0.52), c.u(0.66)),
        alpha(INK, 140),
        None,
    );
    seal_glyph(
        p,
        c,
        c.p(0.52, 0.78),
        c.u(0.12),
        fate.color(),
        fate.stopped(),
    );
    c.label(p, c.p(0.52, 0.06), "PoW seal", alpha(INK, 200));
    lane(
        p,
        c,
        Lane {
            from: 0.66,
            to: 0.94,
            y: 0.4,
            gate: 0.8,
        },
        fate,
        t,
        MUTED,
    );
}

fn replay(p: &egui::Painter, c: &Canvas, fate: Fate, t: f32) {
    box_glyph(
        p,
        c,
        c.p(0.2, 0.3),
        Vec2::new(c.u(0.3), c.u(0.26)),
        alpha(HOLD, 200),
        Some(alpha(HOLD, 20)),
    );
    c.label(p, c.p(0.2, 0.08), "first — lands", alpha(HOLD, 210));
    let off = if fate.animated() {
        0.02 * (t * 3.0).sin()
    } else {
        0.0
    };
    box_glyph(
        p,
        c,
        c.p(0.2 + off, 0.68),
        Vec2::new(c.u(0.3), c.u(0.26)),
        THREAT,
        Some(alpha(THREAT, 20)),
    );
    c.label(p, c.p(0.2, 0.95), "same, again", alpha(THREAT, 210));
    lane(
        p,
        c,
        Lane {
            from: 0.36,
            to: 0.94,
            y: 0.68,
            gate: 0.62,
        },
        fate,
        t,
        MUTED,
    );
    box_glyph(
        p,
        c,
        c.p(0.9, 0.3),
        Vec2::new(c.u(0.16), c.u(0.5)),
        alpha(GOLD, 180),
        Some(alpha(GOLD, 16)),
    );
}

fn flood(p: &egui::Painter, c: &Canvas, fate: Fate, t: f32) {
    // a swarm of txs against a block with a hard cap line
    let n = if c.big { 26 } else { 12 };
    for i in 0..n {
        let f = i as f32 / n as f32;
        let drift = if fate.animated() {
            ((t * 0.9) + f * 3.0).fract()
        } else {
            f
        };
        let x = 0.06 + 0.42 * drift;
        let y = 0.16 + 0.68 * ((f * 7.3).fract());
        p.circle_filled(c.p(x, y), c.u(0.028), alpha(THREAT, 190));
    }
    let cap = Rect::from_min_max(c.p(0.62, 0.2), c.p(0.93, 0.8));
    p.rect_stroke(
        cap,
        egui::Rounding::same(c.u(0.04)),
        stroke(c, alpha(GOLD, 210)),
    );
    p.rect_filled(
        Rect::from_min_max(c.p(0.62, 0.56), c.p(0.93, 0.8)),
        egui::Rounding::same(c.u(0.04)),
        alpha(GOLD, 40),
    );
    p.line_segment(
        [c.p(0.62, 0.56), c.p(0.93, 0.56)],
        Stroke::new(c.line_w() * 1.4, fate.color()),
    );
    c.label(p, c.p(0.775, 0.08), "size cap", alpha(GOLD, 220));
    if fate.stopped() {
        cross(p, c, c.p(0.56, 0.5), c.u(0.09), fate.color());
    } else if fate == Fate::Breached {
        tick(p, c, c.p(0.775, 0.36), c.u(0.09), fate.color());
    }
}

fn nonce_rewind(p: &egui::Painter, c: &Canvas, fate: Fate, t: f32) {
    // a counter with a backwards arrow
    for i in 0..3 {
        let x = 0.12 + i as f32 * 0.16;
        box_glyph(
            p,
            c,
            c.p(x, 0.38),
            Vec2::new(c.u(0.13), c.u(0.22)),
            alpha(if i == 2 { HOLD } else { MUTED }, 200),
            None,
        );
    }
    c.label(p, c.p(0.28, 0.06), "n-1  n  n+1", alpha(INK, 200));
    let back = if fate.animated() {
        0.44 - 0.1 * (0.5 + 0.5 * (t * 2.4).sin())
    } else {
        0.34
    };
    arrow(p, c, c.p(0.44, 0.66), c.p(back, 0.66), THREAT);
    c.label(p, c.p(0.3, 0.9), "rewind", alpha(THREAT, 210));
    lane(
        p,
        c,
        Lane {
            from: 0.58,
            to: 0.94,
            y: 0.38,
            gate: 0.74,
        },
        fate,
        t,
        MUTED,
    );
}

fn drain(p: &egui::Painter, c: &Canvas, fate: Fate, t: f32) {
    // coins leaving a vault toward a thief
    let vault = c.p(0.15, 0.45);
    box_glyph(
        p,
        c,
        vault,
        Vec2::new(c.u(0.3), c.u(0.44)),
        alpha(GOLD, 210),
        Some(alpha(GOLD, 22)),
    );
    for i in 0..3 {
        p.circle_stroke(
            vault + Vec2::new(0.0, c.u(-0.1 + i as f32 * 0.1)),
            c.u(0.06),
            Stroke::new(c.line_w() * 0.9, alpha(GOLD, 220)),
        );
    }
    c.label(p, c.p(0.15, 0.93), "pot", alpha(GOLD, 220));
    key_glyph(p, c, c.p(0.92, 0.78), c.u(0.1), THREAT);
    lane(
        p,
        c,
        Lane {
            from: 0.32,
            to: 0.9,
            y: 0.45,
            gate: 0.6,
        },
        fate,
        t,
        GOLD,
    );
    c.label(p, c.p(0.6, 0.1), "authz", alpha(INK, 200));
}

fn malformed(p: &egui::Painter, c: &Canvas, fate: Fate, t: f32) {
    // garbled bytes hitting a decoder
    for i in 0..6 {
        let x = 0.07 + (i % 3) as f32 * 0.1;
        let y = 0.28 + (i / 3) as f32 * 0.22;
        let jit = if fate.animated() {
            0.015 * ((t * 6.0) + i as f32).sin()
        } else {
            0.0
        };
        p.rect_filled(
            Rect::from_min_max(c.p(x + jit, y), c.p(x + 0.075 + jit, y + 0.14)),
            egui::Rounding::same(c.u(0.02)),
            alpha(THREAT, 170),
        );
    }
    c.label(p, c.p(0.2, 0.06), "0x??", alpha(THREAT, 210));
    box_glyph(
        p,
        c,
        c.p(0.78, 0.45),
        Vec2::new(c.u(0.26), c.u(0.5)),
        alpha(PQ, 210),
        Some(alpha(PQ, 20)),
    );
    c.label(p, c.p(0.78, 0.92), "decoder", alpha(PQ, 220));
    lane(
        p,
        c,
        Lane {
            from: 0.4,
            to: 0.78,
            y: 0.45,
            gate: 0.63,
        },
        fate,
        t,
        MUTED,
    );
}

fn shield(p: &egui::Painter, c: &Canvas, fate: Fate, t: f32) {
    let col = fate.color();
    let ctr = c.p(0.72, 0.46);
    let r = c.u(0.3);
    let pts = vec![
        ctr + Vec2::new(-r * 0.7, -r * 0.75),
        ctr + Vec2::new(r * 0.7, -r * 0.75),
        ctr + Vec2::new(r * 0.7, r * 0.2),
        ctr + Vec2::new(0.0, r * 0.95),
        ctr + Vec2::new(-r * 0.7, r * 0.2),
    ];
    p.add(Shape::convex_polygon(
        pts,
        alpha(col, 26),
        Stroke::new(c.line_w(), mix(col, INK, 0.15)),
    ));
    lane(
        p,
        c,
        Lane {
            from: 0.08,
            to: 0.86,
            y: 0.46,
            gate: 0.55,
        },
        fate,
        t,
        MUTED,
    );
}
