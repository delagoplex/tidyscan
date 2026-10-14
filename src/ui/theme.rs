//! Visual theme: palette, egui style overrides and small drawing helpers shared by all tabs.

use eframe::egui::{self, Color32, CornerRadius, Margin, Response, Sense, Stroke, Ui, vec2};

use crate::analysis::Category;

pub const BG: Color32 = Color32::from_rgb(18, 20, 25);
pub const SURFACE: Color32 = Color32::from_rgb(27, 30, 37);
pub const SURFACE_2: Color32 = Color32::from_rgb(36, 40, 49);
pub const SURFACE_3: Color32 = Color32::from_rgb(46, 51, 62);
pub const BORDER: Color32 = Color32::from_rgb(50, 55, 66);
pub const TEXT: Color32 = Color32::from_rgb(228, 231, 236);
pub const TEXT_DIM: Color32 = Color32::from_rgb(148, 155, 168);
pub const ACCENT: Color32 = Color32::from_rgb(86, 146, 255);
pub const GREEN: Color32 = Color32::from_rgb(82, 196, 126);
pub const AMBER: Color32 = Color32::from_rgb(236, 176, 66);
pub const RED: Color32 = Color32::from_rgb(232, 98, 98);

pub fn category_color(c: Category) -> Color32 {
    match c {
        Category::Image => Color32::from_rgb(96, 176, 240),
        Category::Video => Color32::from_rgb(170, 122, 255),
        Category::Audio => Color32::from_rgb(255, 140, 100),
        Category::Document => Color32::from_rgb(252, 204, 90),
        Category::Archive => Color32::from_rgb(126, 200, 134),
        Category::Code => Color32::from_rgb(80, 210, 220),
        Category::Installer => Color32::from_rgb(240, 100, 150),
        Category::DiskImage => Color32::from_rgb(170, 140, 125),
        Category::Other => Color32::from_rgb(125, 135, 150),
    }
}

/// Install the palette and typography on the context. Call once at start-up.
pub fn apply(ctx: &egui::Context) {
    use egui::{FontFamily, FontId, TextStyle};

    let mut visuals = egui::Visuals::dark();
    visuals.panel_fill = BG;
    visuals.window_fill = SURFACE;
    visuals.window_stroke = Stroke::new(1.0, BORDER);
    visuals.window_corner_radius = CornerRadius::same(10);
    visuals.menu_corner_radius = CornerRadius::same(8);
    visuals.extreme_bg_color = Color32::from_rgb(13, 15, 19);
    visuals.faint_bg_color = Color32::from_rgb(31, 34, 42);
    visuals.hyperlink_color = ACCENT;
    visuals.override_text_color = Some(TEXT);
    visuals.striped = true;
    visuals.selection.bg_fill = ACCENT.gamma_multiply(0.35);
    visuals.selection.stroke = Stroke::new(1.0, ACCENT);

    let w = &mut visuals.widgets;
    let r = CornerRadius::same(6);
    w.noninteractive.bg_fill = SURFACE;
    w.noninteractive.weak_bg_fill = SURFACE;
    w.noninteractive.bg_stroke = Stroke::new(1.0, BORDER);
    w.noninteractive.fg_stroke = Stroke::new(1.0, TEXT_DIM);
    w.noninteractive.corner_radius = r;
    w.inactive.bg_fill = SURFACE_2;
    w.inactive.weak_bg_fill = SURFACE_2;
    w.inactive.bg_stroke = Stroke::NONE;
    w.inactive.fg_stroke = Stroke::new(1.0, TEXT);
    w.inactive.corner_radius = r;
    w.hovered.bg_fill = SURFACE_3;
    w.hovered.weak_bg_fill = SURFACE_3;
    w.hovered.bg_stroke = Stroke::new(1.0, Color32::from_rgb(70, 78, 92));
    w.hovered.fg_stroke = Stroke::new(1.0, Color32::WHITE);
    w.hovered.corner_radius = r;
    w.active.bg_fill = ACCENT.gamma_multiply(0.5);
    w.active.weak_bg_fill = ACCENT.gamma_multiply(0.5);
    w.active.bg_stroke = Stroke::new(1.0, ACCENT);
    w.active.fg_stroke = Stroke::new(1.0, Color32::WHITE);
    w.active.corner_radius = r;
    w.open.bg_fill = SURFACE_2;
    w.open.weak_bg_fill = SURFACE_2;
    w.open.bg_stroke = Stroke::new(1.0, BORDER);
    w.open.fg_stroke = Stroke::new(1.0, TEXT);
    w.open.corner_radius = r;

    ctx.set_visuals(visuals);
    ctx.all_styles_mut(|style| {
        style.spacing.item_spacing = vec2(8.0, 6.0);
        style.spacing.button_padding = vec2(12.0, 5.0);
        style.spacing.interact_size = vec2(40.0, 24.0);
        style.spacing.indent = 18.0;
        style.spacing.window_margin = Margin::same(14);
        style.text_styles = [
            (
                TextStyle::Small,
                FontId::new(11.5, FontFamily::Proportional),
            ),
            (TextStyle::Body, FontId::new(14.5, FontFamily::Proportional)),
            (
                TextStyle::Button,
                FontId::new(14.5, FontFamily::Proportional),
            ),
            (
                TextStyle::Heading,
                FontId::new(21.0, FontFamily::Proportional),
            ),
            (
                TextStyle::Monospace,
                FontId::new(13.0, FontFamily::Monospace),
            ),
        ]
        .into();
    });
}

/// A rounded, bordered container for a group of controls or a result block.
pub fn card<R>(ui: &mut Ui, add_contents: impl FnOnce(&mut Ui) -> R) -> R {
    egui::Frame::new()
        .fill(SURFACE)
        .stroke(Stroke::new(1.0, BORDER))
        .corner_radius(CornerRadius::same(10))
        .inner_margin(Margin::same(14))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            add_contents(ui)
        })
        .inner
}

/// Small uppercase caption used above groups of controls.
pub fn caption(ui: &mut Ui, text: &str) {
    ui.label(
        egui::RichText::new(text.to_uppercase())
            .small()
            .color(TEXT_DIM)
            .strong(),
    );
}

/// A big number with a label below, for key figures.
pub fn stat_tile(ui: &mut Ui, label: &str, value: &str) {
    egui::Frame::new()
        .fill(SURFACE_2)
        .corner_radius(CornerRadius::same(8))
        .inner_margin(Margin::symmetric(14, 10))
        .show(ui, |ui| {
            ui.vertical(|ui| {
                ui.label(egui::RichText::new(value).size(19.0).strong().color(TEXT));
                ui.label(egui::RichText::new(label).small().color(TEXT_DIM));
            });
        });
}

/// Horizontal bar with a dark track, drawn with the painter so it can take any color.
pub fn bar(ui: &mut Ui, frac: f32, color: Color32, width: f32, height: f32) -> Response {
    let (rect, resp) = ui.allocate_exact_size(vec2(width, height), Sense::hover());
    let p = ui.painter();
    let r = CornerRadius::same((height / 2.0) as u8);
    p.rect_filled(rect, r, Color32::from_rgb(13, 15, 19));
    let w = (rect.width() * frac.clamp(0.0, 1.0)).max(if frac > 0.0 { height } else { 0.0 });
    if w > 0.0 {
        let fill = egui::Rect::from_min_size(rect.min, vec2(w, rect.height()));
        p.rect_filled(fill, r, color);
    }
    resp
}

/// A small colored chip with text.
pub fn pill(ui: &mut Ui, text: &str, color: Color32) -> Response {
    egui::Frame::new()
        .fill(color.gamma_multiply(0.18))
        .stroke(Stroke::new(1.0, color.gamma_multiply(0.5)))
        .corner_radius(CornerRadius::same(10))
        .inner_margin(Margin::symmetric(9, 3))
        .show(ui, |ui| {
            ui.label(egui::RichText::new(text).small().color(color).strong());
        })
        .response
}

/// Filled accent button for the main action of a panel.
pub fn primary_button(ui: &mut Ui, text: &str) -> Response {
    ui.add(
        egui::Button::new(egui::RichText::new(text).color(Color32::WHITE).strong())
            .fill(ACCENT)
            .corner_radius(CornerRadius::same(7))
            .min_size(vec2(0.0, 30.0)),
    )
}

/// Full-width variant of [`primary_button`].
pub fn primary_button_wide(ui: &mut Ui, text: &str) -> Response {
    ui.add_sized(
        [ui.available_width(), 32.0],
        egui::Button::new(egui::RichText::new(text).color(Color32::WHITE).strong())
            .fill(ACCENT)
            .corner_radius(CornerRadius::same(7)),
    )
}

/// Button for destructive actions.
pub fn danger_button(ui: &mut Ui, text: &str) -> Response {
    ui.add(
        egui::Button::new(egui::RichText::new(text).color(RED))
            .fill(RED.gamma_multiply(0.12))
            .stroke(Stroke::new(1.0, RED.gamma_multiply(0.5)))
            .corner_radius(CornerRadius::same(6)),
    )
}

/// One entry of the top tab bar: text with an accent underline when selected.
pub fn tab(ui: &mut Ui, selected: bool, text: &str) -> Response {
    let font = egui::FontId::proportional(15.0);
    let color = if selected { TEXT } else { TEXT_DIM };
    let galley = ui.painter().layout_no_wrap(text.to_owned(), font, color);
    let size = galley.size() + vec2(22.0, 16.0);
    let (rect, resp) = ui.allocate_exact_size(size, Sense::click());
    let p = ui.painter();
    if resp.hovered() && !selected {
        p.rect_filled(
            rect.shrink2(vec2(2.0, 4.0)),
            CornerRadius::same(6),
            SURFACE_2,
        );
    }
    p.galley(rect.min + vec2(11.0, 8.0), galley, color);
    if selected {
        let underline = egui::Rect::from_min_size(
            egui::pos2(rect.min.x + 11.0, rect.max.y - 3.0),
            vec2(rect.width() - 22.0, 3.0),
        );
        p.rect_filled(underline, CornerRadius::same(2), ACCENT);
    }
    resp
}

/// Colored heading for a result section (e.g. green "Sicher", amber "Unsicher").
pub fn section_heading(ui: &mut Ui, text: &str, color: Color32) {
    ui.horizontal(|ui| {
        let (rect, _) = ui.allocate_exact_size(vec2(4.0, 20.0), Sense::hover());
        ui.painter().rect_filled(rect, CornerRadius::same(2), color);
        ui.label(egui::RichText::new(text).size(17.0).strong().color(TEXT));
    });
}

/// Expand/collapse toggle drawn with the painter (the UI font lacks solid triangles).
/// A `leaf` only takes up the space, so rows stay aligned.
pub fn disclosure(ui: &mut Ui, open: bool, leaf: bool) -> Response {
    let (rect, resp) = ui.allocate_exact_size(vec2(16.0, 16.0), Sense::click());
    if leaf {
        return resp;
    }
    let c = rect.center();
    let color = if resp.hovered() { TEXT } else { TEXT_DIM };
    let pts = if open {
        vec![
            c + vec2(-4.5, -2.5),
            c + vec2(4.5, -2.5),
            c + vec2(0.0, 3.0),
        ]
    } else {
        vec![
            c + vec2(-2.5, -4.5),
            c + vec2(3.0, 0.0),
            c + vec2(-2.5, 4.5),
        ]
    };
    ui.painter()
        .add(egui::Shape::convex_polygon(pts, color, Stroke::NONE));
    resp
}

/// What the user did with a confirmation dialog this frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Answer {
    Pending,
    Cancelled,
    Confirmed,
}

/// A modal question with a cancel button and one action button. `danger` paints the
/// action red, for things that cannot be undone.
pub fn confirm(
    ctx: &egui::Context,
    id: &str,
    title: &str,
    action: &str,
    danger: bool,
    body: impl FnOnce(&mut Ui),
) -> Answer {
    let mut answer = Answer::Pending;
    let modal = egui::Modal::new(egui::Id::new(id)).show(ctx, |ui| {
        ui.set_width(460.0);
        ui.heading(title);
        body(ui);
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            if ui.button("Abbrechen").clicked() {
                answer = Answer::Cancelled;
            }
            let clicked = if danger {
                danger_button(ui, action).clicked()
            } else {
                primary_button(ui, action).clicked()
            };
            if clicked {
                answer = Answer::Confirmed;
            }
        });
    });
    if answer == Answer::Pending && modal.should_close() {
        answer = Answer::Cancelled;
    }
    answer
}
