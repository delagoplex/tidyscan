//! Cleanup tab: review the plan, apply rule files, execute into quarantine.

use std::path::PathBuf;
use std::time::SystemTime;

use eframe::egui::{self, Ui};
use egui_extras::{Column, TableBuilder};

use super::{App, theme};
use crate::analysis::human;
use crate::rules;
use crate::scan::QUARANTINE_DIR_NAME;

const ROW: f32 = 20.0;

pub fn show(app: &mut App, ui: &mut Ui, ctx: &egui::Context) {
    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            plan_section(app, ui);
            ui.separator();
            rules_section(app, ui);
            if let Some(rep) = &app.last_report {
                ui.separator();
                ui.strong("Letzter Lauf");
                ui.label(rep);
            }
        });
    confirm_modal(app, ctx);
}

fn plan_section(app: &mut App, ui: &mut Ui) {
    theme::section_heading(ui, "Plan", theme::ACCENT);
    ui.weak(
        "Nichts wird gelöscht. Einträge wandern in <Ordner>/.tidyscan-quarantine/<Zeitstempel>/ \
         (oder in das Regel-Ziel) und können im Tab Quarantäne jederzeit zurückgeholt werden.",
    );
    // The plan belongs to the scanned folder; without a scan there is nothing to plan.
    let Some(root) = app.scanned_root().filter(|_| !app.selection.is_empty()) else {
        ui.label(
            "Der Plan ist leer. In den anderen Tabs Häkchen setzen oder unten Regeln anwenden.",
        );
        return;
    };
    let plan = app.selection.plan(&root);
    ui.horizontal(|ui| {
        ui.label(format!(
            "{} Einträge, {}",
            plan.len(),
            human(plan.total_bytes())
        ));
        if ui.button("Plan leeren").clicked() {
            app.selection.clear();
        }
        if ui
            .add_enabled(!app.scanning(), egui::Button::new("Ausführen …"))
            .clicked()
        {
            app.confirm_execute = true;
        }
    });

    let mut remove: Option<PathBuf> = None;
    TableBuilder::new(ui)
        .striped(true)
        .resizable(true)
        .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
        .column(Column::initial(110.0))
        .column(Column::initial(80.0))
        .column(Column::remainder().clip(true))
        .column(Column::remainder().clip(true))
        .column(Column::exact(60.0))
        .max_scroll_height(360.0)
        .header(ROW, |mut h| {
            h.col(|ui| {
                ui.strong("Grund");
            });
            h.col(|ui| {
                ui.strong("Größe");
            });
            h.col(|ui| {
                ui.strong("Quelle");
            });
            h.col(|ui| {
                ui.strong("Ziel");
            });
            h.col(|_| {});
        })
        .body(|body| {
            body.rows(ROW, plan.len(), |mut row| {
                let a = &plan.actions[row.index()];
                row.col(|ui| {
                    ui.label(&a.reason);
                });
                row.col(|ui| {
                    ui.label(a.size_label());
                });
                row.col(|ui| {
                    ui.add(egui::Label::new(a.source.to_string_lossy()).truncate());
                });
                row.col(|ui| {
                    let text = match plan.move_target(a) {
                        Some(dest) => dest.to_string_lossy().into_owned(),
                        None => "Quarantäne".to_string(),
                    };
                    ui.add(egui::Label::new(text).truncate());
                });
                row.col(|ui| {
                    if ui.small_button("✕").clicked() {
                        remove = Some(a.source.clone());
                    }
                });
            });
        });
    if let Some(p) = remove {
        app.selection.remove(&p);
    }
}

fn rules_section(app: &mut App, ui: &mut Ui) {
    theme::section_heading(ui, "Regeln", theme::ACCENT);
    ui.weak(
        "TOML-Regeldatei: Treffer werden dem Plan hinzugefügt. Erste passende Regel gewinnt. \
         Geschützte Bereiche bleiben außen vor, Projektordner ohne include_projects ebenfalls.",
    );
    ui.horizontal(|ui| {
        ui.add(
            egui::TextEdit::singleline(&mut app.rules_path)
                .desired_width(360.0)
                .hint_text("rules.toml"),
        );
        if ui.button("Datei wählen …").clicked()
            && let Some(p) = rfd::FileDialog::new()
                .add_filter("TOML", &["toml"])
                .pick_file()
        {
            app.rules_path = p.to_string_lossy().into_owned();
        }
        if ui.button("Beispiel speichern …").clicked()
            && let Some(p) = rfd::FileDialog::new()
                .add_filter("TOML", &["toml"])
                .set_file_name("rules.toml")
                .save_file()
        {
            match std::fs::write(&p, rules::EXAMPLE_RULES) {
                Ok(()) => app.rules_path = p.to_string_lossy().into_owned(),
                Err(e) => app.rules_error = Some(e.to_string()),
            }
        }
        let enabled = app.result.is_some() && !app.rules_path.trim().is_empty();
        if ui
            .add_enabled(enabled, egui::Button::new("Regeln anwenden"))
            .clicked()
        {
            apply_rules(app);
        }
    });
    if let Some(e) = &app.rules_error {
        ui.colored_label(theme::RED, e);
    }
}

fn apply_rules(app: &mut App) {
    let (Some(result), Some(ctx)) = (app.result.clone(), app.ctx.clone()) else {
        return;
    };
    app.rules_error = None;
    match rules::load_rules(std::path::Path::new(app.rules_path.trim())) {
        Ok(compiled) => {
            let matches = rules::apply_rules(&result, &ctx, &compiled, SystemTime::now());
            let n = matches.plan.len();
            let note = matches.left_out().unwrap_or_default();
            for a in matches.plan.actions {
                app.selection.insert(a);
            }
            app.status = format!(
                "{n} Treffer aus {} Regeln in den Plan übernommen. {note}",
                compiled.len()
            );
        }
        Err(e) => app.rules_error = Some(format!("{e:#}")),
    }
}

fn confirm_modal(app: &mut App, ctx: &egui::Context) {
    if !app.confirm_execute {
        return;
    }
    let Some(root) = app.scanned_root() else {
        app.confirm_execute = false;
        return;
    };
    let plan = app.selection.plan(&root);
    let answer = theme::confirm(
        ctx,
        "confirm_execute",
        "Plan ausführen?",
        "Ja, verschieben",
        false,
        |ui| {
            ui.label(format!(
                "{} Einträge ({}) werden verschoben. Ziel für Quarantäne:\n{}",
                plan.len(),
                human(plan.total_bytes()),
                root.join(QUARANTINE_DIR_NAME).display()
            ));
        },
    );
    match answer {
        theme::Answer::Pending => {}
        theme::Answer::Cancelled => app.confirm_execute = false,
        theme::Answer::Confirmed => {
            app.confirm_execute = false;
            app.execute_plan((*plan).clone());
        }
    }
}
