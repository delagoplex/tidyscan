//! TreeSize-style tree table: expandable folders and files with sortable columns.

use std::collections::HashSet;

use eframe::egui::{self, Ui};
use egui_extras::{Column, TableBuilder};

use super::{App, theme};
use crate::analysis::{Category, fmt_count, fmt_date, human};
use crate::model::{DirId, FileId, ScanResult};

const ROW: f32 = 24.0;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortKey {
    Name,
    Size,
    Files,
    Dirs,
    Modified,
}

#[derive(Debug, Clone, Copy)]
pub enum Row {
    Dir(DirId, u16),
    File(FileId, u16),
}

pub struct TreeState {
    pub expanded: HashSet<DirId>,
    pub sort: SortKey,
    pub desc: bool,
    pub show_files: bool,
    rows: Vec<Row>,
    dirty: bool,
    built_for: usize,
}

impl Default for TreeState {
    fn default() -> Self {
        Self {
            expanded: HashSet::from([0]),
            sort: SortKey::Size,
            desc: true,
            show_files: true,
            rows: Vec::new(),
            dirty: true,
            built_for: usize::MAX,
        }
    }
}

impl TreeState {
    pub fn reset(&mut self) {
        self.expanded = HashSet::from([0]);
        self.dirty = true;
    }

    pub fn toggle(&mut self, d: DirId) {
        if !self.expanded.remove(&d) {
            self.expanded.insert(d);
        }
        self.dirty = true;
    }

    pub fn set_sort(&mut self, key: SortKey) {
        if self.sort == key {
            self.desc = !self.desc;
        } else {
            self.sort = key;
            self.desc = !matches!(key, SortKey::Name);
        }
        self.dirty = true;
    }

    /// Expand every ancestor so that `d` becomes visible.
    pub fn reveal(&mut self, result: &ScanResult, mut d: DirId) {
        while let Some(p) = result.dirs[d].parent {
            self.expanded.insert(p);
            d = p;
        }
        self.dirty = true;
    }

    fn rebuild(&mut self, result: &ScanResult) {
        self.rows.clear();
        if !result.dirs.is_empty() {
            self.push_dir(result, 0, 0);
        }
        self.dirty = false;
        self.built_for = result.dirs.len() + result.files.len();
    }

    fn push_dir(&mut self, result: &ScanResult, d: DirId, depth: u16) {
        self.rows.push(Row::Dir(d, depth));
        if !self.expanded.contains(&d) {
            return;
        }
        let node = &result.dirs[d];
        let mut kids: Vec<DirId> = node.children.clone();
        let (sort, desc) = (self.sort, self.desc);
        kids.sort_by(|&a, &b| {
            let (x, y) = (&result.dirs[a], &result.dirs[b]);
            let ord = match sort {
                SortKey::Name => x.name().to_lowercase().cmp(&y.name().to_lowercase()),
                SortKey::Size => x.total_size.cmp(&y.total_size),
                SortKey::Files => x.total_files.cmp(&y.total_files),
                SortKey::Dirs => x.total_dirs.cmp(&y.total_dirs),
                SortKey::Modified => x.newest.cmp(&y.newest),
            };
            if desc { ord.reverse() } else { ord }
        });
        for k in kids {
            self.push_dir(result, k, depth + 1);
        }
        if self.show_files {
            let mut files: Vec<FileId> = node.files.clone();
            files.sort_by(|&a, &b| {
                let (x, y) = (&result.files[a], &result.files[b]);
                let ord = match sort {
                    SortKey::Name => x.name().to_lowercase().cmp(&y.name().to_lowercase()),
                    SortKey::Modified => x.modified.cmp(&y.modified),
                    _ => x.size.cmp(&y.size),
                };
                if desc { ord.reverse() } else { ord }
            });
            for f in files {
                self.rows.push(Row::File(f, depth + 1));
            }
        }
    }
}

fn header_cell(ui: &mut Ui, state: &TreeState, key: SortKey, text: &str, right: bool) -> bool {
    let label = egui::RichText::new(text)
        .small()
        .strong()
        .color(if state.sort == key {
            theme::TEXT
        } else {
            theme::TEXT_DIM
        });
    let layout = if right {
        egui::Layout::right_to_left(egui::Align::Center)
    } else {
        egui::Layout::left_to_right(egui::Align::Center)
    };
    ui.with_layout(layout, |ui| {
        let clicked = ui
            .add(egui::Label::new(label).sense(egui::Sense::click()))
            .clicked();
        if state.sort == key {
            sort_marker(ui, state.desc);
        }
        clicked
    })
    .inner
}

/// Draw the tree table. Returns the directory the user clicked, if any.
pub fn show(app: &mut App, result: &ScanResult, ui: &mut Ui) {
    if app.tree.dirty || app.tree.built_for != result.dirs.len() + result.files.len() {
        app.tree.rebuild(result);
    }
    let root_size = result.total_size().max(1) as f32;
    let selected = app.selected_dir;
    let n = app.tree.rows.len();

    let mut toggle: Option<DirId> = None;
    let mut select: Option<DirId> = None;
    let mut sort: Option<SortKey> = None;
    let mut reveal: Option<std::path::PathBuf> = None;

    ui.horizontal(|ui| {
        ui.label(
            egui::RichText::new(format!("{} Zeilen", fmt_count(n as u64)))
                .small()
                .color(theme::TEXT_DIM),
        );
        if ui
            .checkbox(&mut app.tree.show_files, "Dateien anzeigen")
            .changed()
        {
            app.tree.dirty = true;
        }
        if ui.small_button("Alles einklappen").clicked() {
            app.tree.reset();
        }
        if ui.small_button("Zwei Ebenen öffnen").clicked() {
            app.tree.reset();
            for &c in &result.dirs[0].children {
                app.tree.expanded.insert(c);
            }
        }
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            let label = if app.show_details {
                "Details ausblenden"
            } else {
                "Details einblenden"
            };
            if ui.small_button(label).clicked() {
                app.show_details = !app.show_details;
            }
        });
    });

    TableBuilder::new(ui)
        .striped(true)
        .resizable(true)
        .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
        .column(Column::remainder().at_least(260.0).clip(true))
        .column(Column::initial(95.0).at_least(70.0))
        .column(Column::initial(150.0).at_least(90.0))
        .column(Column::initial(80.0).at_least(60.0))
        .column(Column::initial(70.0).at_least(50.0))
        .column(Column::initial(95.0).at_least(80.0))
        .header(ROW, |mut h| {
            h.col(|ui| {
                if header_cell(ui, &app.tree, SortKey::Name, "Name", false) {
                    sort = Some(SortKey::Name);
                }
            });
            h.col(|ui| {
                if header_cell(ui, &app.tree, SortKey::Size, "Größe", true) {
                    sort = Some(SortKey::Size);
                }
            });
            h.col(|ui| {
                ui.label(
                    egui::RichText::new("Anteil")
                        .small()
                        .strong()
                        .color(theme::TEXT_DIM),
                );
            });
            h.col(|ui| {
                if header_cell(ui, &app.tree, SortKey::Files, "Dateien", true) {
                    sort = Some(SortKey::Files);
                }
            });
            h.col(|ui| {
                if header_cell(ui, &app.tree, SortKey::Dirs, "Ordner", true) {
                    sort = Some(SortKey::Dirs);
                }
            });
            h.col(|ui| {
                if header_cell(ui, &app.tree, SortKey::Modified, "Geändert", true) {
                    sort = Some(SortKey::Modified);
                }
            });
        })
        .body(|body| {
            body.rows(ROW, n, |mut row| {
                let r = app.tree.rows[row.index()];
                match r {
                    Row::Dir(d, depth) => {
                        let node = &result.dirs[d];
                        let is_sel = d == selected;
                        let expanded = app.tree.expanded.contains(&d);
                        let frac = node.total_size as f32 / root_size;
                        row.col(|ui| {
                            ui.add_space(depth as f32 * 16.0);
                            let leaf = node.children.is_empty()
                                && (node.files.is_empty() || !app.tree.show_files);
                            if theme::disclosure(ui, expanded, leaf).clicked() {
                                toggle = Some(d);
                            }
                            folder_icon(ui, theme::ACCENT);
                            let text = egui::RichText::new(node.name());
                            let text = if is_sel {
                                text.strong().color(theme::TEXT)
                            } else {
                                text
                            };
                            let resp = ui.add(
                                egui::Label::new(text)
                                    .truncate()
                                    .sense(egui::Sense::click()),
                            );
                            if resp.clicked() {
                                select = Some(d);
                            }
                            if resp.double_clicked() {
                                toggle = Some(d);
                            }
                            resp.on_hover_text(node.path.to_string_lossy());
                        });
                        row.col(|ui| right(ui, &human(node.total_size), true));
                        row.col(|ui| share_cell(ui, frac));
                        row.col(|ui| right(ui, &fmt_count(node.total_files), false));
                        row.col(|ui| right(ui, &fmt_count(node.total_dirs), false));
                        row.col(|ui| {
                            right(ui, &node.newest.map(fmt_date).unwrap_or_default(), false)
                        });
                    }
                    Row::File(f, depth) => {
                        let file = &result.files[f];
                        let frac = file.size as f32 / root_size;
                        row.col(|ui| {
                            ui.add_space(depth as f32 * 16.0 + 24.0);
                            file_icon(ui, theme::category_color(Category::of_file(file)));
                            let resp = ui.add(
                                egui::Label::new(
                                    egui::RichText::new(file.name()).color(theme::TEXT_DIM),
                                )
                                .truncate()
                                .sense(egui::Sense::click()),
                            );
                            if resp.double_clicked() {
                                reveal = Some(file.path.clone());
                            }
                            resp.on_hover_text(file.path.to_string_lossy());
                        });
                        row.col(|ui| right(ui, &human(file.size), false));
                        row.col(|ui| share_cell(ui, frac));
                        row.col(|ui| right(ui, "", false));
                        row.col(|ui| right(ui, "", false));
                        row.col(|ui| {
                            right(ui, &file.modified.map(fmt_date).unwrap_or_default(), false)
                        });
                    }
                }
            });
        });

    if let Some(k) = sort {
        app.tree.set_sort(k);
    }
    if let Some(d) = toggle {
        app.tree.toggle(d);
    }
    if let Some(d) = select {
        app.selected_dir = d;
    }
    if let Some(p) = reveal {
        super::reveal(&p);
    }
}

fn right(ui: &mut Ui, text: &str, strong: bool) {
    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
        let t = egui::RichText::new(text);
        ui.label(if strong {
            t.strong()
        } else {
            t.color(theme::TEXT_DIM)
        });
    });
}

fn share_cell(ui: &mut Ui, frac: f32) {
    let w = (ui.available_width() - 52.0).max(30.0);
    theme::bar(ui, frac, theme::ACCENT.gamma_multiply(0.85), w, 10.0);
    ui.label(
        egui::RichText::new(format!("{:.1} %", frac * 100.0))
            .small()
            .color(theme::TEXT_DIM),
    );
}

fn folder_icon(ui: &mut Ui, color: egui::Color32) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(16.0, 14.0), egui::Sense::hover());
    let p = ui.painter();
    let body =
        egui::Rect::from_min_max(rect.left_top() + egui::vec2(0.0, 3.0), rect.right_bottom());
    p.rect_filled(
        body,
        egui::CornerRadius::same(2),
        color.gamma_multiply(0.75),
    );
    let tab = egui::Rect::from_min_size(rect.left_top(), egui::vec2(7.0, 4.0));
    p.rect_filled(tab, egui::CornerRadius::same(1), color.gamma_multiply(0.75));
}

fn file_icon(ui: &mut Ui, color: egui::Color32) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(16.0, 14.0), egui::Sense::hover());
    let r = egui::Rect::from_center_size(rect.center(), egui::vec2(9.0, 12.0));
    ui.painter()
        .rect_filled(r, egui::CornerRadius::same(2), color.gamma_multiply(0.7));
}

fn sort_marker(ui: &mut Ui, desc: bool) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(10.0, 10.0), egui::Sense::hover());
    let c = rect.center();
    let pts = if desc {
        vec![
            c + egui::vec2(-3.5, -2.0),
            c + egui::vec2(3.5, -2.0),
            c + egui::vec2(0.0, 2.5),
        ]
    } else {
        vec![
            c + egui::vec2(-3.5, 2.0),
            c + egui::vec2(3.5, 2.0),
            c + egui::vec2(0.0, -2.5),
        ]
    };
    ui.painter().add(egui::Shape::convex_polygon(
        pts,
        theme::ACCENT,
        egui::Stroke::NONE,
    ));
}
