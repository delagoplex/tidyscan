//! Old files, duplicates and empty folders tabs.

use eframe::egui::{self, Ui};
use egui_extras::{Column, TableBuilder};

use super::{App, dir_action, file_action, reveal};
use crate::age::AgeBasis;
use crate::analysis::human;

const ROW: f32 = 20.0;
const MAX_GROUPS_SHOWN: usize = 500;

pub fn show_old(app: &mut App, ui: &mut Ui) {
    let Some(result) = app.result.clone() else {
        return;
    };

    ui.horizontal(|ui| {
        ui.label("Unverändert seit");
        if ui
            .add(
                egui::Slider::new(&mut app.old_days, 7..=3650)
                    .logarithmic(true)
                    .suffix(" Tagen"),
            )
            .changed()
        {
            app.old_dirty = true;
        }
        ui.separator();
        let reliable = app.atime.as_ref().map(|r| r.reliable).unwrap_or(false);
        if ui
            .radio_value(&mut app.old_basis, AgeBasis::Modified, "Änderungsdatum")
            .changed()
        {
            app.old_dirty = true;
        }
        if ui
            .add_enabled(
                reliable,
                egui::RadioButton::new(app.old_basis == AgeBasis::Accessed, "Zugriffsdatum"),
            )
            .clicked()
        {
            app.old_basis = AgeBasis::Accessed;
            app.old_dirty = true;
        }
        ui.separator();
        ui.label("Filter");
        ui.add(egui::TextEdit::singleline(&mut app.old_filter).desired_width(180.0));
    });
    if let Some(rep) = &app.atime {
        ui.label(egui::RichText::new(rep.explain()).small().weak());
    }

    if app.old_dirty {
        app.refresh_old();
    }
    let filter = app.old_filter.trim().to_lowercase();
    if app.old_filter_applied.as_deref() != Some(filter.as_str()) {
        app.old_filtered = app
            .old_list
            .iter()
            .enumerate()
            .filter(|(_, o)| {
                filter.is_empty()
                    || result.files[o.file]
                        .path
                        .to_string_lossy()
                        .to_lowercase()
                        .contains(&filter)
            })
            .map(|(i, _)| i)
            .collect();
        app.old_filter_applied = Some(filter);
    }

    let total: u64 = app
        .old_filtered
        .iter()
        .map(|&i| result.files[app.old_list[i].file].size)
        .sum();
    ui.horizontal(|ui| {
        ui.label(format!(
            "{} Dateien, {}",
            app.old_filtered.len(),
            human(total)
        ));
        if ui.button("Alle sichtbaren in den Plan").clicked() {
            for &i in &app.old_filtered {
                app.selection
                    .insert(file_action(&result, app.old_list[i].file, "Alt"));
            }
        }
        if ui.button("Alle sichtbaren aus dem Plan").clicked() {
            for &i in &app.old_filtered {
                app.selection
                    .remove(&result.files[app.old_list[i].file].path);
            }
        }
    });
    ui.add_space(4.0);

    let n = app.old_filtered.len();
    TableBuilder::new(ui)
        .striped(true)
        .resizable(true)
        .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
        .column(Column::exact(28.0))
        .column(Column::initial(70.0))
        .column(Column::initial(90.0))
        .column(Column::remainder().clip(true))
        .column(Column::exact(80.0))
        .header(ROW, |mut h| {
            h.col(|_| {});
            h.col(|ui| {
                ui.strong("Alter");
            });
            h.col(|ui| {
                ui.strong("Größe");
            });
            h.col(|ui| {
                ui.strong("Pfad");
            });
            h.col(|_| {});
        })
        .body(|body| {
            body.rows(ROW, n, |mut row| {
                let o = &app.old_list[app.old_filtered[row.index()]];
                let f = &result.files[o.file];
                row.col(|ui| {
                    let mut checked = app.selection.contains(&f.path);
                    if ui.checkbox(&mut checked, "").changed() {
                        app.selection.toggle(file_action(&result, o.file, "Alt"));
                    }
                });
                row.col(|ui| {
                    ui.label(format!("{} d", o.age_days));
                });
                row.col(|ui| {
                    ui.label(human(f.size));
                });
                row.col(|ui| {
                    ui.add(egui::Label::new(result.relative(&f.path).to_string_lossy()).truncate());
                });
                row.col(|ui| {
                    if ui.small_button("Anzeigen").clicked() {
                        reveal(&f.path);
                    }
                });
            });
        });
}

pub fn show_dupes(app: &mut App, ui: &mut Ui) {
    let Some(result) = app.result.clone() else {
        return;
    };

    ui.horizontal(|ui| {
        ui.label("Mindestgröße");
        ui.add(egui::TextEdit::singleline(&mut app.dupe_min_size).desired_width(70.0));
        if app.dupes_running() {
            ui.add(egui::Spinner::new());
            if let Some((files, bytes)) = app.dupe_progress() {
                ui.label(format!("{files} Dateien gehasht, {}", human(bytes)));
            }
        } else if ui.button("Duplikate suchen").clicked() {
            app.start_dupes();
        }
    });
    ui.weak("Dateien werden erst nach Größe, dann über die ersten 64 KiB und zuletzt vollständig per BLAKE3 verglichen.");
    ui.add_space(6.0);

    let Some(groups) = app.dupes.clone() else {
        ui.label("Noch nicht gesucht.");
        return;
    };
    let wasted: u64 = groups.iter().map(|g| g.wasted()).sum();
    ui.horizontal(|ui| {
        ui.label(format!(
            "{} Gruppen, {} könnten frei werden.",
            groups.len(),
            human(wasted)
        ));
        if ui
            .button("Überall alle außer der ersten Datei markieren")
            .clicked()
        {
            for g in &groups {
                for &fid in g.files.iter().skip(1) {
                    app.selection.insert(file_action(&result, fid, "Duplikat"));
                }
            }
        }
        if ui.button("Duplikat-Markierungen aufheben").clicked() {
            for g in &groups {
                for &fid in &g.files {
                    app.selection.remove(&result.files[fid].path);
                }
            }
        }
    });
    ui.add_space(4.0);

    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            for (gi, g) in groups.iter().take(MAX_GROUPS_SHOWN).enumerate() {
                let title = format!(
                    "{} × {}   verschwendet {}",
                    g.files.len(),
                    human(g.size),
                    human(g.wasted())
                );
                egui::CollapsingHeader::new(title)
                    .id_salt(("dupe", gi))
                    .default_open(gi < 15)
                    .show(ui, |ui| {
                        if ui.small_button("Alle außer der ersten markieren").clicked() {
                            for &fid in g.files.iter().skip(1) {
                                app.selection.insert(file_action(&result, fid, "Duplikat"));
                            }
                        }
                        for &fid in &g.files {
                            let f = &result.files[fid];
                            ui.horizontal(|ui| {
                                let mut checked = app.selection.contains(&f.path);
                                if ui.checkbox(&mut checked, "").changed() {
                                    app.selection.toggle(file_action(&result, fid, "Duplikat"));
                                }
                                ui.add(
                                    egui::Label::new(result.relative(&f.path).to_string_lossy())
                                        .truncate(),
                                );
                                if ui.small_button("Anzeigen").clicked() {
                                    reveal(&f.path);
                                }
                            });
                        }
                    });
            }
            if groups.len() > MAX_GROUPS_SHOWN {
                ui.weak(format!(
                    "… {} weitere Gruppen. Die Schaltfläche oben markiert trotzdem alle.",
                    groups.len() - MAX_GROUPS_SHOWN
                ));
            }
        });
}

pub fn show_empty(app: &mut App, ui: &mut Ui) {
    let Some(result) = app.result.clone() else {
        return;
    };

    ui.horizontal(|ui| {
        ui.strong(format!("{} leere Ordner", app.empty_dirs.len()));
        if ui.button("Alle markieren").clicked() {
            for &d in &app.empty_dirs {
                app.selection
                    .insert(dir_action(&result, d, "Leerer Ordner"));
            }
        }
        if ui.button("Markierung aufheben").clicked() {
            for &d in &app.empty_dirs {
                app.selection.remove(&result.dirs[d].path);
            }
        }
    });
    ui.weak("Ein Ordner gilt als leer, wenn er auf keiner Ebene Dateien enthält. Beim Aufräumen werden auch seine leeren Unterordner entfernt.");

    let half = (ui.available_height() * 0.5).max(120.0);
    egui::ScrollArea::vertical()
        .id_salt("empty_dirs")
        .max_height(half)
        .auto_shrink([false, false])
        .show(ui, |ui| {
            for &d in &app.empty_dirs.clone() {
                let node = &result.dirs[d];
                ui.horizontal(|ui| {
                    let mut checked = app.selection.contains(&node.path);
                    if ui.checkbox(&mut checked, "").changed() {
                        app.selection
                            .toggle(dir_action(&result, d, "Leerer Ordner"));
                    }
                    let extra = if node.total_dirs > 0 {
                        format!("  (+{} leere Unterordner)", node.total_dirs)
                    } else {
                        String::new()
                    };
                    ui.add(
                        egui::Label::new(format!(
                            "{}{extra}",
                            result.relative(&node.path).to_string_lossy()
                        ))
                        .truncate(),
                    );
                });
            }
        });

    ui.separator();
    ui.horizontal(|ui| {
        ui.strong(format!("{} Dateien mit 0 Byte", app.zero_files.len()));
        if ui.button("Alle markieren").clicked() {
            for &f in &app.zero_files {
                app.selection.insert(file_action(&result, f, "0 Byte"));
            }
        }
    });
    let n = app.zero_files.len();
    TableBuilder::new(ui)
        .striped(true)
        .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
        .column(Column::exact(28.0))
        .column(Column::remainder().clip(true))
        .body(|body| {
            body.rows(ROW, n, |mut row| {
                let fid = app.zero_files[row.index()];
                let f = &result.files[fid];
                row.col(|ui| {
                    let mut checked = app.selection.contains(&f.path);
                    if ui.checkbox(&mut checked, "").changed() {
                        app.selection.toggle(file_action(&result, fid, "0 Byte"));
                    }
                });
                row.col(|ui| {
                    ui.add(egui::Label::new(result.relative(&f.path).to_string_lossy()).truncate());
                });
            });
        });
}
