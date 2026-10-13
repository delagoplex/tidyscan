//! Squarified treemap of the selected folder, nested up to a chosen depth.

use eframe::egui::{self, Color32, CornerRadius, Pos2, Rect, Sense, Stroke, Ui, pos2, vec2};

use super::{App, theme};
use crate::analysis::{Category, human};
use crate::model::{DirId, FileId, ScanResult};

const LABEL_H: f32 = 18.0;
const MIN_LABEL_W: f32 = 56.0;
const MIN_NEST: f32 = 34.0;
const GAP: f32 = 2.0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Item {
    Dir(DirId),
    File(FileId),
}

pub struct TreemapState {
    /// Folder shown as the whole area.
    pub zoom: DirId,
    /// Nesting depth, 1 = only direct children.
    pub depth: usize,
    /// Rectangles drawn in the last frame, deepest last, for hit testing.
    drawn: Vec<(Rect, Item, usize)>,
}

impl Default for TreemapState {
    fn default() -> Self {
        Self {
            zoom: 0,
            depth: 3,
            drawn: Vec::new(),
        }
    }
}

impl TreemapState {
    pub fn reset(&mut self) {
        self.zoom = 0;
        self.drawn.clear();
    }
}

const HUES: [Color32; 10] = [
    Color32::from_rgb(86, 146, 255),
    Color32::from_rgb(96, 196, 160),
    Color32::from_rgb(240, 150, 80),
    Color32::from_rgb(200, 120, 240),
    Color32::from_rgb(240, 110, 130),
    Color32::from_rgb(90, 200, 220),
    Color32::from_rgb(230, 200, 90),
    Color32::from_rgb(150, 170, 255),
    Color32::from_rgb(170, 200, 110),
    Color32::from_rgb(210, 140, 190),
];

/// Squarified layout (Bruls et al.): returns one rect per weight, in input order.
fn squarify(weights: &[f32], rect: Rect) -> Vec<Rect> {
    let total: f32 = weights.iter().sum();
    let mut out = vec![Rect::NOTHING; weights.len()];
    if total <= 0.0 || rect.width() <= 0.0 || rect.height() <= 0.0 {
        return out;
    }
    let scale = rect.area() / total;
    let mut free = rect;
    let mut i = 0;
    while i < weights.len() {
        // Grow a row while the worst aspect ratio improves.
        let side = free.width().min(free.height());
        let mut row_end = i + 1;
        let mut best = worst(&weights[i..row_end], side, scale);
        while row_end < weights.len() {
            let w = worst(&weights[i..row_end + 1], side, scale);
            if w > best {
                break;
            }
            best = w;
            row_end += 1;
        }
        // Lay the row out along the shorter side.
        let row_area: f32 = weights[i..row_end].iter().sum::<f32>() * scale;
        let horizontal = free.width() >= free.height();
        let thickness = if horizontal {
            row_area / free.height()
        } else {
            row_area / free.width()
        };
        let mut cursor = if horizontal { free.min.y } else { free.min.x };
        for (k, w) in weights[i..row_end].iter().enumerate() {
            let len = w * scale / thickness.max(1e-6);
            let r = if horizontal {
                Rect::from_min_size(pos2(free.min.x, cursor), vec2(thickness, len))
            } else {
                Rect::from_min_size(pos2(cursor, free.min.y), vec2(len, thickness))
            };
            out[i + k] = r;
            cursor += len;
        }
        if horizontal {
            free.min.x += thickness;
        } else {
            free.min.y += thickness;
        }
        i = row_end;
    }
    out
}

fn worst(ws: &[f32], side: f32, scale: f32) -> f32 {
    let s: f32 = ws.iter().sum::<f32>() * scale;
    if s <= 0.0 || side <= 0.0 {
        return f32::INFINITY;
    }
    let (mut mn, mut mx) = (f32::INFINITY, 0f32);
    for &w in ws {
        let a = w * scale;
        mn = mn.min(a);
        mx = mx.max(a);
    }
    let side2 = side * side;
    ((side2 * mx) / (s * s)).max((s * s) / (side2 * mn.max(1e-6)))
}

fn shade(base: Color32, depth: usize) -> Color32 {
    // Deeper levels get darker so nesting reads at a glance.
    let f = 1.0 - 0.18 * depth as f32;
    Color32::from_rgb(
        (base.r() as f32 * f) as u8,
        (base.g() as f32 * f) as u8,
        (base.b() as f32 * f) as u8,
    )
}

fn layout_dir(
    result: &ScanResult,
    dir: DirId,
    rect: Rect,
    depth: usize,
    max_depth: usize,
    base: Option<Color32>,
    out: &mut Vec<(Rect, Item, usize, Color32)>,
) {
    let node = &result.dirs[dir];
    let mut items: Vec<(Item, f32)> = node
        .children
        .iter()
        .map(|&c| (Item::Dir(c), result.dirs[c].total_size as f32))
        .chain(
            node.files
                .iter()
                .map(|&f| (Item::File(f), result.files[f].size as f32)),
        )
        .filter(|(_, w)| *w > 0.0)
        .collect();
    if items.is_empty() {
        return;
    }
    items.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    // Tiny tail entries are merged visually by dropping them below one pixel of area.
    let total: f32 = items.iter().map(|(_, w)| *w).sum();
    let min_w = total / rect.area().max(1.0) * 2.0;
    let weights: Vec<f32> = items.iter().map(|(_, w)| w.max(min_w)).collect();
    let rects = squarify(&weights, rect);
    for (idx, ((item, _), r)) in items.iter().zip(rects).enumerate() {
        if r.width() < 1.0 || r.height() < 1.0 {
            continue;
        }
        let color = match item {
            Item::Dir(_) => base.unwrap_or(HUES[idx % HUES.len()]),
            Item::File(f) => theme::category_color(Category::of_file(&result.files[*f])),
        };
        let r = r.shrink(GAP / 2.0);
        out.push((r, *item, depth, shade(color, depth)));
        if let Item::Dir(d) = item
            && depth + 1 < max_depth
            && r.width() > MIN_NEST
            && r.height() > MIN_NEST + LABEL_H
        {
            let inner = Rect::from_min_max(r.min + vec2(GAP, LABEL_H), r.max - vec2(GAP, GAP));
            layout_dir(result, *d, inner, depth + 1, max_depth, Some(color), out);
        }
    }
}

fn breadcrumb(app: &mut App, result: &ScanResult, ui: &mut Ui) {
    let mut chain = vec![app.treemap.zoom];
    while let Some(p) = result.dirs[*chain.last().unwrap()].parent {
        chain.push(p);
    }
    chain.reverse();
    ui.horizontal_wrapped(|ui| {
        theme::caption(ui, "Treemap");
        for (i, d) in chain.iter().enumerate() {
            if i > 0 {
                ui.label(egui::RichText::new("›").color(theme::TEXT_DIM));
            }
            let name = result.dirs[*d].name();
            let last = i + 1 == chain.len();
            if last {
                ui.label(egui::RichText::new(name).strong());
            } else if ui.link(name).clicked() {
                app.treemap.zoom = *d;
            }
        }
        ui.separator();
        ui.label(egui::RichText::new("Ebenen").small().color(theme::TEXT_DIM));
        for lvl in 1..=4 {
            if ui
                .selectable_label(app.treemap.depth == lvl, lvl.to_string())
                .clicked()
            {
                app.treemap.depth = lvl;
            }
        }
        ui.separator();
        ui.label(
            egui::RichText::new("Klick wählt aus, Doppelklick zoomt hinein")
                .small()
                .color(theme::TEXT_DIM),
        );
    });
}

pub fn show(app: &mut App, result: &ScanResult, ui: &mut Ui) {
    if app.treemap.zoom >= result.dirs.len() {
        app.treemap.zoom = 0;
    }
    breadcrumb(app, result, ui);

    let avail = ui.available_size();
    let (area, resp) = ui.allocate_exact_size(avail, Sense::click());
    let painter = ui.painter_at(area);
    painter.rect_filled(area, CornerRadius::same(6), Color32::from_rgb(13, 15, 19));

    let mut drawn: Vec<(Rect, Item, usize, Color32)> = Vec::new();
    layout_dir(
        result,
        app.treemap.zoom,
        area.shrink(GAP),
        0,
        app.treemap.depth,
        None,
        &mut drawn,
    );

    let pointer: Option<Pos2> = resp.hover_pos();
    let hovered = pointer.and_then(|p| {
        drawn
            .iter()
            .filter(|(r, _, _, _)| r.contains(p))
            .max_by_key(|(_, _, d, _)| *d)
            .map(|(_, item, _, _)| *item)
    });

    for (r, item, _depth, color) in &drawn {
        let is_hover = Some(*item) == hovered;
        let is_sel = matches!(item, Item::Dir(d) if *d == app.selected_dir);
        let fill = if is_hover {
            color.gamma_multiply(1.25)
        } else {
            *color
        };
        painter.rect_filled(*r, CornerRadius::same(3), fill);
        if is_sel {
            painter.rect_stroke(
                *r,
                CornerRadius::same(3),
                Stroke::new(2.0, Color32::WHITE),
                egui::StrokeKind::Inside,
            );
        } else {
            painter.rect_stroke(
                *r,
                CornerRadius::same(3),
                Stroke::new(1.0, Color32::from_black_alpha(90)),
                egui::StrokeKind::Inside,
            );
        }
        if r.width() >= MIN_LABEL_W && r.height() >= LABEL_H {
            let (name, size) = match item {
                Item::Dir(d) => (result.dirs[*d].name(), result.dirs[*d].total_size),
                Item::File(f) => (result.files[*f].name(), result.files[*f].size),
            };
            let text = if r.width() > 140.0 {
                format!("{name}  {}", human(size))
            } else {
                name
            };
            let font = egui::FontId::proportional(12.0);
            let galley = painter.layout(text, font, Color32::WHITE, r.width() - 8.0);
            if galley.rows.len() == 1 || r.height() > 2.0 * LABEL_H {
                let clip = Rect::from_min_size(
                    r.min + vec2(4.0, 2.0),
                    vec2(r.width() - 8.0, LABEL_H - 2.0),
                );
                painter
                    .with_clip_rect(clip)
                    .galley(clip.min, galley, Color32::WHITE);
            }
        }
    }

    if let Some(item) = hovered {
        let (path, size, extra) = match item {
            Item::Dir(d) => {
                let n = &result.dirs[d];
                (
                    n.path.clone(),
                    n.total_size,
                    format!("{} Dateien, {} Ordner", n.total_files, n.total_dirs),
                )
            }
            Item::File(f) => {
                let n = &result.files[f];
                (
                    n.path.clone(),
                    n.size,
                    Category::of_file(n).label().to_string(),
                )
            }
        };
        resp.clone().on_hover_ui(|ui| {
            ui.label(egui::RichText::new(result.relative(&path).to_string_lossy()).strong());
            ui.label(format!("{}   {extra}", human(size)));
        });
        if resp.double_clicked() {
            if let Item::Dir(d) = item {
                app.treemap.zoom = d;
                app.selected_dir = d;
                app.tree.reveal(result, d);
            }
        } else if resp.clicked() {
            let d = match item {
                Item::Dir(d) => d,
                Item::File(f) => result.files[f].parent,
            };
            app.selected_dir = d;
            app.tree.reveal(result, d);
        }
    }
    app.treemap.drawn = drawn.into_iter().map(|(r, i, d, _)| (r, i, d)).collect();
}
