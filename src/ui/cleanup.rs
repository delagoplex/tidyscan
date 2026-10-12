//! Cleanup tab: review the plan, apply rule files, execute into quarantine, undo.

use std::path::PathBuf;
use std::time::SystemTime;

use eframe::egui::{self, Ui};
use egui_extras::{Column, TableBuilder};

use super::{App, reveal};
use crate::actions::{self, ActionKind};
use crate::analysis::human;
use crate::rules;

const ROW: f32 = 20.0;

pub fn show(app: &mut App, ui: &mut Ui, ctx: &egui::Context) {
    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            plan_section(app, ui);
            ui.separator();
            rules_section(app, ui);
            ui.separator();
            undo_section(app, ui);
            if let Some(rep) = &app.last_report {
                ui.separator();
                ui.strong("Letzter Lauf");
                ui.label(rep);
            }
        });
    confirm_modal(app, ctx);
}

fn plan_section(app: &mut App, ui: &mut Ui) {
    ui.heading("Plan");
    ui.weak(
        "Nichts wird gelöscht. Einträge wandern in <Ordner>/.tidyscan-quarantine/<Zeitstempel>/ \
         (oder in das Regel-Ziel) und können jederzeit zurückgeholt werden.",
    );
    if app.selection.is_empty() {
        ui.label(
            "Der Plan ist leer. In den anderen Tabs Häkchen setzen oder unten Regeln anwenden.",
        );
        return;
    }
    let root = app.root();
    let plan = app.selection.to_plan(&root);
    ui.horizontal(|ui| {
        ui.label(format!(
            "{} Einträge, {}",
            plan.len(),
            human(plan.total_bytes())
        ));
        if ui.button("Plan leeren").clicked() {
            app.selection.clear();
        }
        let can_run = !app.scanning() && app.result.is_some();
        if ui
            .add_enabled(can_run, egui::Button::new("Ausführen …"))
            .clicked()
        {
            app.confirm_execute = true;
        }
    });

    let preview = plan.preview();
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
                let i = row.index();
                let a = &plan.actions[i];
                let (_, dest) = &preview[i];
                row.col(|ui| {
                    ui.label(&a.reason);
                });
                row.col(|ui| {
                    ui.label(if a.is_dir {
                        "Ordner".into()
                    } else {
                        human(a.size)
                    });
                });
                row.col(|ui| {
                    ui.add(egui::Label::new(a.source.to_string_lossy()).truncate());
                });
                row.col(|ui| {
                    let text = match &a.kind {
                        ActionKind::Quarantine => "Quarantäne".to_string(),
                        ActionKind::MoveTo(_) => dest.to_string_lossy().into_owned(),
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
    ui.heading("Regeln");
    ui.weak("TOML-Regeldatei: Treffer werden dem Plan hinzugefügt. Erste passende Regel gewinnt.");
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
        ui.colored_label(egui::Color32::from_rgb(220, 80, 80), e);
    }
}

fn apply_rules(app: &mut App) {
    let Some(result) = app.result.clone() else {
        return;
    };
    app.rules_error = None;
    match rules::load_rules(std::path::Path::new(app.rules_path.trim())) {
        Ok(compiled) => {
            let plan = rules::apply_rules(&result, &compiled, SystemTime::now());
            let n = plan.len();
            for a in plan.actions {
                app.selection.insert(a);
            }
            app.status = format!(
                "{n} Treffer aus {} Regeln in den Plan übernommen.",
                compiled.len()
            );
        }
        Err(e) => app.rules_error = Some(format!("{e:#}")),
    }
}

fn undo_section(app: &mut App, ui: &mut Ui) {
    ui.horizontal(|ui| {
        ui.heading("Rückgängig");
        if ui.small_button("Liste aktualisieren").clicked() {
            app.journals = actions::list_journals(&app.root());
        }
    });
    if app.journals.is_empty() {
        ui.label("Keine Quarantäne-Sitzungen für diesen Ordner.");
        return;
    }
    let mut undo_path: Option<PathBuf> = None;
    for j in app.journals.clone() {
        let session = j.parent().map(|p| p.to_path_buf()).unwrap_or_default();
        let name = session
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let info = actions::Journal::load(&j).ok();
        ui.horizontal(|ui| {
            ui.monospace(&name);
            match &info {
                Some(jr) if jr.undone => {
                    ui.weak("bereits zurückgenommen");
                }
                Some(jr) => {
                    ui.label(format!("{} Einträge", jr.entries.len()));
                    if ui.button("Wiederherstellen").clicked() {
                        undo_path = Some(j.clone());
                    }
                }
                None => {
                    ui.weak("Journal nicht lesbar");
                }
            }
            if ui.small_button("Anzeigen").clicked() {
                reveal(&session);
            }
        });
    }
    if let Some(j) = undo_path {
        match actions::undo(&j) {
            Ok(rep) => {
                let mut msg = format!("{} Einträge wiederhergestellt.", rep.restored);
                if !rep.conflicts.is_empty() {
                    msg.push_str(&format!(" {} Konflikte:", rep.conflicts.len()));
                    for (p, e) in rep.conflicts.iter().take(10) {
                        msg.push_str(&format!("\n  {}: {e}", p.display()));
                    }
                }
                app.last_report = Some(msg);
                app.start_scan();
                app.journals = actions::list_journals(&app.root());
            }
            Err(e) => app.last_report = Some(format!("Rückgängig fehlgeschlagen: {e:#}")),
        }
    }
}

fn confirm_modal(app: &mut App, ctx: &egui::Context) {
    if !app.confirm_execute {
        return;
    }
    let root = app.root();
    let plan = app.selection.to_plan(&root);
    let mut run = false;
    let modal = egui::Modal::new(egui::Id::new("confirm_execute")).show(ctx, |ui| {
        ui.set_width(420.0);
        ui.heading("Plan ausführen?");
        ui.label(format!(
            "{} Einträge ({}) werden verschoben. Ziel für Quarantäne:\n{}",
            plan.len(),
            human(plan.total_bytes()),
            root.join(crate::scan::QUARANTINE_DIR_NAME).display()
        ));
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            if ui.button("Abbrechen").clicked() {
                app.confirm_execute = false;
            }
            if ui.add(egui::Button::new("Ja, verschieben")).clicked() {
                run = true;
            }
        });
    });
    if modal.should_close() {
        app.confirm_execute = false;
    }
    if run {
        app.confirm_execute = false;
        execute(app, plan);
    }
}

fn execute(app: &mut App, plan: actions::Plan) {
    let msg = match actions::execute(&plan, false) {
        Ok(rep) => {
            let mut m = format!(
                "{} Einträge verschoben ({}), {} fehlgeschlagen.",
                rep.moved,
                human(rep.bytes),
                rep.failed.len()
            );
            for (p, e) in rep.failed.iter().take(10) {
                m.push_str(&format!("\n  {}: {e}", p.display()));
            }
            if let Some(j) = rep.journal_path {
                m.push_str(&format!("\nJournal: {}", j.display()));
            }
            m
        }
        Err(e) => format!("Ausführen fehlgeschlagen: {e:#}"),
    };
    app.selection.clear();
    app.start_scan();
    app.last_report = Some(msg);
    app.journals = actions::list_journals(&app.root());
}
