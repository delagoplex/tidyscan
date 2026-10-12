//! Overview tab: directory tree on the left, details of the selected folder on the right.

use eframe::egui::{self, Ui};

use super::{App, file_action, reveal};
use crate::analysis::{self, AgeBucket, Category, human};
use crate::model::{DirId, FileId, ScanResult};

const MAX_CHILDREN_SHOWN: usize = 400;
const TOP_FILES: usize = 25;

pub(crate) struct DetailCache {
    pub dir: DirId,
    pub largest: Vec<FileId>,
    pub ages: Vec<AgeBucket>,
}

pub fn show(app: &mut App, ui: &mut Ui) {
    let Some(result) = app.result.clone() else {
        return;
    };
    let root_size = result.total_size().max(1);

    egui::Panel::left("tree_panel")
        .resizable(true)
        .default_size(ui.available_width() * 0.45)
        .show(ui, |ui| {
            egui::ScrollArea::both()
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    tree_node(ui, &result, 0, root_size, &mut app.selected_dir, 0);
                });
        });

    egui::CentralPanel::default().show(ui, |ui| {
        details(app, &result, ui);
    });
}

fn tree_node(
    ui: &mut Ui,
    result: &ScanResult,
    id: DirId,
    root_size: u64,
    selected: &mut DirId,
    depth: usize,
) {
    let d = &result.dirs[id];
    let pct = d.total_size as f64 * 100.0 / root_size as f64;
    let label = format!(
        "{}   {}   {:.1} %   {} Dateien",
        d.name(),
        human(d.total_size),
        pct,
        d.total_files
    );
    let text = if *selected == id {
        egui::RichText::new(label).strong()
    } else {
        egui::RichText::new(label)
    };

    if d.children.is_empty() {
        ui.horizontal(|ui| {
            ui.add_space(18.0);
            if ui.selectable_label(*selected == id, text).clicked() {
                *selected = id;
            }
        });
        return;
    }

    let mut children: Vec<DirId> = d.children.clone();
    children.sort_by(|a, b| result.dirs[*b].total_size.cmp(&result.dirs[*a].total_size));

    let resp = egui::CollapsingHeader::new(text)
        .id_salt(id)
        .default_open(depth == 0)
        .show(ui, |ui| {
            for &c in children.iter().take(MAX_CHILDREN_SHOWN) {
                tree_node(ui, result, c, root_size, selected, depth + 1);
            }
            if children.len() > MAX_CHILDREN_SHOWN {
                ui.weak(format!(
                    "… {} weitere Unterordner (zu viele zum Anzeigen)",
                    children.len() - MAX_CHILDREN_SHOWN
                ));
            }
        });
    if resp.header_response.clicked() {
        *selected = id;
    }
}

fn details(app: &mut App, result: &ScanResult, ui: &mut Ui) {
    let id = app.selected_dir.min(result.dirs.len().saturating_sub(1));
    let d = &result.dirs[id];

    if app.detail_cache.as_ref().map(|c| c.dir) != Some(id) {
        let mut files = analysis::files_under(result, id);
        files.sort_unstable_by(|a, b| result.files[*b].size.cmp(&result.files[*a].size));
        files.truncate(TOP_FILES);
        app.detail_cache = Some(DetailCache {
            dir: id,
            largest: files,
            ages: analysis::age_histogram(result, id, app.now),
        });
    }

    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.heading(d.name());
                if ui.small_button("Im Dateimanager").clicked() {
                    reveal(&d.path);
                }
            });
            ui.label(egui::RichText::new(d.path.to_string_lossy()).weak().small());
            ui.label(format!(
                "{}   {} Dateien   {} Unterordner",
                human(d.total_size),
                d.total_files,
                d.total_dirs
            ));
            if !result.errors.is_empty() && id == 0 {
                ui.colored_label(
                    egui::Color32::from_rgb(220, 160, 60),
                    format!(
                        "{} Pfade konnten nicht gelesen werden.",
                        result.errors.len()
                    ),
                );
            }

            ui.add_space(10.0);
            ui.strong("Nach Kategorie");
            let sizes = &app.cat_sizes[id];
            let mut cats: Vec<(Category, u64)> = Category::ALL
                .iter()
                .map(|c| (*c, sizes[*c as usize]))
                .collect();
            cats.sort_by_key(|a| std::cmp::Reverse(a.1));
            let total = d.total_size.max(1) as f32;
            egui::Grid::new("cats")
                .num_columns(3)
                .spacing([12.0, 4.0])
                .show(ui, |ui| {
                    for (c, b) in cats.into_iter().filter(|(_, b)| *b > 0) {
                        ui.label(c.label());
                        ui.add(
                            egui::ProgressBar::new(b as f32 / total)
                                .desired_width(220.0)
                                .text(format!("{:.1} %", b as f32 * 100.0 / total)),
                        );
                        ui.label(human(b));
                        ui.end_row();
                    }
                });

            ui.add_space(10.0);
            ui.strong("Nach Alter (Änderungsdatum)");
            let ages = app
                .detail_cache
                .as_ref()
                .map(|c| c.ages.clone())
                .unwrap_or_default();
            egui::Grid::new("ages")
                .num_columns(4)
                .spacing([12.0, 4.0])
                .show(ui, |ui| {
                    for b in ages {
                        ui.label(b.label);
                        ui.add(egui::ProgressBar::new(b.bytes as f32 / total).desired_width(220.0));
                        ui.label(human(b.bytes));
                        ui.label(format!("{} Dateien", b.files));
                        ui.end_row();
                    }
                });

            ui.add_space(10.0);
            ui.strong("Größte Dateien");
            let largest = app
                .detail_cache
                .as_ref()
                .map(|c| c.largest.clone())
                .unwrap_or_default();
            // Grid columns size to their content, so give the path column an explicit width.
            let path_width = (ui.available_width() - 260.0).max(200.0);
            egui::Grid::new("largest")
                .num_columns(4)
                .spacing([8.0, 2.0])
                .striped(true)
                .show(ui, |ui| {
                    for fid in largest {
                        let f = &result.files[fid];
                        let mut checked = app.selection.contains(&f.path);
                        if ui.checkbox(&mut checked, "").changed() {
                            app.selection
                                .toggle(file_action(result, fid, "Große Datei"));
                        }
                        ui.label(human(f.size));
                        ui.allocate_ui_with_layout(
                            egui::vec2(path_width, 18.0),
                            egui::Layout::left_to_right(egui::Align::Center),
                            |ui| {
                                ui.add(
                                    egui::Label::new(result.relative(&f.path).to_string_lossy())
                                        .truncate(),
                                );
                            },
                        );
                        if ui.small_button("Anzeigen").clicked() {
                            reveal(&f.path);
                        }
                        ui.end_row();
                    }
                });
            ui.weak("Häkchen = in Quarantäne-Plan aufnehmen.");
        });
}
