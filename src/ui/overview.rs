//! Overview tab: directory tree on the left, details of the selected folder on the right.

use eframe::egui::{self, Ui};

use super::{App, file_action, reveal, theme, tree, tree_action, treemap};
use crate::analysis::{self, AgeBucket, Category, human};
use crate::model::{DirId, FileId, ScanResult};

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

    if app.show_details {
        egui::Panel::right("details_panel")
            .resizable(true)
            .default_size(360.0)
            .show(ui, |ui| {
                details(app, &result, ui);
            });
    }

    egui::Panel::bottom("treemap_panel")
        .resizable(true)
        .default_size(300.0)
        .show(ui, |ui| {
            treemap::show(app, &result, ui);
        });

    egui::CentralPanel::default().show(ui, |ui| {
        tree::show(app, &result, ui);
    });
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
                if id != 0 {
                    let in_plan = app.selection.contains(&d.path);
                    let label = if in_plan {
                        "Ordner aus dem Plan entfernen"
                    } else {
                        "Ganzen Ordner in Quarantäne (Plan)"
                    };
                    if ui.small_button(label).clicked() {
                        app.selection
                            .toggle(tree_action(result, id, "Ganzer Ordner"));
                    }
                }
            });
            ui.label(egui::RichText::new(d.path.to_string_lossy()).weak().small());
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                theme::stat_tile(ui, "Größe", &human(d.total_size));
                theme::stat_tile(ui, "Dateien", &d.total_files.to_string());
                theme::stat_tile(ui, "Unterordner", &d.total_dirs.to_string());
            });
            if !result.errors.is_empty() && id == 0 {
                ui.colored_label(
                    egui::Color32::from_rgb(220, 160, 60),
                    format!(
                        "{} Pfade konnten nicht gelesen werden.",
                        result.errors.len()
                    ),
                );
            }

            ui.add_space(14.0);
            theme::caption(ui, "Nach Kategorie");
            let sizes = &app.cat_sizes[id];
            let mut cats: Vec<(Category, u64)> = Category::ALL
                .iter()
                .map(|c| (*c, sizes[*c as usize]))
                .collect();
            cats.sort_by_key(|a| std::cmp::Reverse(a.1));
            let total = d.total_size.max(1) as f32;
            egui::Grid::new("cats")
                .num_columns(4)
                .spacing([12.0, 6.0])
                .show(ui, |ui| {
                    for (c, b) in cats.into_iter().filter(|(_, b)| *b > 0) {
                        ui.horizontal(|ui| {
                            let (dot, _) = ui
                                .allocate_exact_size(egui::vec2(10.0, 10.0), egui::Sense::hover());
                            ui.painter()
                                .circle_filled(dot.center(), 5.0, theme::category_color(c));
                            ui.label(c.label());
                        });
                        theme::bar(ui, b as f32 / total, theme::category_color(c), 220.0, 10.0);
                        ui.label(
                            egui::RichText::new(format!("{:.1} %", b as f32 * 100.0 / total))
                                .color(theme::TEXT_DIM),
                        );
                        ui.label(human(b));
                        ui.end_row();
                    }
                });

            ui.add_space(14.0);
            theme::caption(ui, "Nach Alter (Änderungsdatum)");
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
                        theme::bar(ui, b.bytes as f32 / total, theme::ACCENT, 220.0, 10.0);
                        ui.label(human(b.bytes));
                        ui.label(format!("{} Dateien", b.files));
                        ui.end_row();
                    }
                });

            ui.add_space(14.0);
            theme::caption(ui, "Größte Dateien");
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
