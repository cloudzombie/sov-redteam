//! The console's palette and typography — shared by the app shell and by the
//! attack visualisations, so one change moves both.
//!
//! Purely presentational. Nothing here reads or decides a verdict.

use eframe::egui::{
    self, Color32,
    FontFamily::{Monospace, Proportional},
    FontId, TextStyle,
};

// ── palette (gold-on-black security console) ────────────────────────────────
pub const GROUND: Color32 = Color32::from_rgb(10, 12, 9);
pub const PANEL: Color32 = Color32::from_rgb(16, 19, 9);
pub const SURFACE: Color32 = Color32::from_rgb(22, 26, 16);
pub const BORDER: Color32 = Color32::from_rgb(40, 44, 30);
pub const INK: Color32 = Color32::from_rgb(233, 229, 214);
pub const MUTED: Color32 = Color32::from_rgb(141, 139, 121);
pub const GOLD: Color32 = Color32::from_rgb(230, 189, 84);
pub const HOLD: Color32 = Color32::from_rgb(99, 211, 154);
pub const THREAT: Color32 = Color32::from_rgb(232, 98, 74);
pub const PQ: Color32 = Color32::from_rgb(125, 176, 244);
/// Ink for text sitting on a filled GOLD/HOLD/THREAT surface.
pub const ON_ACCENT: Color32 = Color32::from_rgb(17, 16, 13);

pub fn alpha(c: Color32, a: u8) -> Color32 {
    Color32::from_rgba_unmultiplied(c.r(), c.g(), c.b(), a)
}

/// Linear blend, `t` = 0 → `a`, 1 → `b`. Used to fade a diagram's live parts.
pub fn mix(a: Color32, b: Color32, t: f32) -> Color32 {
    let t = t.clamp(0.0, 1.0);
    let f = |x: u8, y: u8| (x as f32 + (y as f32 - x as f32) * t) as u8;
    Color32::from_rgb(f(a.r(), b.r()), f(a.g(), b.g()), f(a.b(), b.b()))
}

/// Install the dark console theme: a real type scale (prose proportional,
/// hashes monospace), calm borders, and generous spacing.
pub fn install(ctx: &egui::Context) {
    let mut v = egui::Visuals::dark();
    v.override_text_color = Some(INK);
    v.panel_fill = GROUND;
    v.window_fill = GROUND;
    v.extreme_bg_color = GROUND;
    v.faint_bg_color = SURFACE;
    v.widgets.noninteractive.bg_stroke = egui::Stroke::new(1.0, BORDER);
    v.widgets.inactive.bg_fill = SURFACE;
    v.widgets.hovered.bg_fill = alpha(GOLD, 26);
    v.widgets.hovered.bg_stroke = egui::Stroke::new(1.0, alpha(GOLD, 90));
    v.widgets.active.bg_fill = alpha(GOLD, 40);
    v.selection.bg_fill = alpha(GOLD, 46);
    v.selection.stroke = egui::Stroke::new(1.0, GOLD);
    ctx.set_visuals(v);

    ctx.style_mut(|s| {
        s.text_styles = [
            (TextStyle::Heading, FontId::new(19.0, Proportional)),
            (TextStyle::Body, FontId::new(13.0, Proportional)),
            (TextStyle::Button, FontId::new(13.0, Proportional)),
            (TextStyle::Monospace, FontId::new(12.0, Monospace)),
            (TextStyle::Small, FontId::new(11.0, Proportional)),
        ]
        .into();
        s.spacing.item_spacing = egui::vec2(8.0, 6.0);
        s.spacing.button_padding = egui::vec2(10.0, 6.0);
        s.spacing.scroll.bar_width = 8.0;
        s.visuals.window_rounding = egui::Rounding::same(10.0);
    });
}
