//! Quarantäne tab: list sessions, restore everything or single entries, and the only
//! place where data is deleted for good.

use std::path::{Path, PathBuf};

use eframe::egui::{self, Ui};

use super::{App, reveal};
use crate::actions::{self, JournalEntry, SessionInfo};
use crate::analysis::human;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Purge {
    Session(PathBuf),
    Entry(PathBuf, usize),
    All,
}

#[derive(Default)]
pub struct QuarantineState {
    pub sessions: Vec<SessionInfo>,
    pub expanded: Option<PathBuf>,
    pub entries: Vec<JournalEntry>,
    pub stale: bool,
    pub confirm: Option<Purge>,
    pub message: Option<String>,
}

impl QuarantineState {
    pub fn refresh(&mut self, root: &Path) {
        self.sessions = actions::list_journals(root)
            .iter()
            .filter_map(|j| actions::session_info(j))
            .collect();
        if let Some(j) = &self.expanded {
            self.entries = actions::Journal::load(j)
                .map(|j| j.entries)
                .unwrap_or_default();
            if !self.sessions.iter().any(|s| &s.journal_path == j) {
                self.expanded = None;
                self.entries.clear();
            }
        }
        self.stale = false;
    }

    pub fn total_bytes(&self) -> u64 {
        self.sessions.iter().map(|s| s.bytes).sum()
    }
}

fn after_change(app: &mut App, msg: String) {
    app.quarantine.message = Some(msg);
    app.quarantine.stale = true;
    if app.result.is_some() && !app.scanning() {
        app.start_scan();
    }
}

pub fn show(app: &mut App, ui: &mut Ui, ctx: &egui::Context) {
    let root = app.root();
    if app.quarantine.stale
        || app.quarantine.sessions.is_empty() && app.quarantine.message.is_none()
    {
        app.quarantine.refresh(&root);
    }

    ui.horizontal(|ui| {
        ui.heading("Quarantäne");
        ui.label(format!(
            "{} Sitzungen, {} auf der Platte",
            app.quarantine.sessions.len(),
            human(app.quarantine.total_bytes())
        ));
        if ui.small_button("Aktualisieren").clicked() {
            app.quarantine.refresh(&root);
        }
        if ui.small_button("Ordner anzeigen").clicked() {
            reveal(&root.join(crate::scan::QUARANTINE_DIR_NAME));
        }
    });
    ui.weak(format!(
        "Alles unter {}. Wiederherstellen legt die Einträge an ihren Originalpfad zurück und überschreibt nichts. \
         Endgültig löschen ist die einzige Stelle, an der tidyscan Daten entfernt.",
        root.join(crate::scan::QUARANTINE_DIR_NAME).display()
    ));
    if let Some(m) = &app.quarantine.message {
        ui.label(egui::RichText::new(m).small());
    }
    ui.separator();

    if app.quarantine.sessions.is_empty() {
        ui.label("Keine Quarantäne-Sitzungen für diesen Ordner.");
        return;
    }

    let active = app
        .quarantine
        .sessions
        .iter()
        .filter(|s| s.files > 0)
        .count();
    ui.horizontal(|ui| {
        if ui
            .add_enabled(
                active > 0,
                egui::Button::new("Alle Sitzungen endgültig löschen …"),
            )
            .clicked()
        {
            app.quarantine.confirm = Some(Purge::All);
        }
    });
    ui.add_space(6.0);

    let sessions = app.quarantine.sessions.clone();
    let mut restore_session: Option<PathBuf> = None;
    let mut restore_entry: Option<(PathBuf, usize)> = None;
    let mut toggle_expand: Option<PathBuf> = None;

    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            for s in &sessions {
                let expanded = app.quarantine.expanded.as_ref() == Some(&s.journal_path);
                ui.horizontal(|ui| {
                    if ui.small_button(if expanded { "▼" } else { "▶" }).clicked() {
                        toggle_expand = Some(s.journal_path.clone());
                    }
                    ui.monospace(&s.name);
                    if s.undone && s.files == 0 {
                        ui.weak("wiederhergestellt, leer");
                    } else {
                        ui.label(format!(
                            "{} Einträge, {} Dateien, {}",
                            s.entries,
                            s.files,
                            human(s.bytes)
                        ));
                        if s.purged > 0 {
                            ui.weak(format!("{} gelöscht", s.purged));
                        }
                        if s.entries > 0 && ui.button("Alles wiederherstellen").clicked() {
                            restore_session = Some(s.journal_path.clone());
                        }
                        if ui
                            .button(
                                egui::RichText::new("Endgültig löschen …")
                                    .color(egui::Color32::from_rgb(230, 110, 100)),
                            )
                            .clicked()
                        {
                            app.quarantine.confirm = Some(Purge::Session(s.journal_path.clone()));
                        }
                    }
                    if ui.small_button("Anzeigen").clicked() {
                        reveal(&s.session_dir);
                    }
                });
                if expanded {
                    let entries = app.quarantine.entries.clone();
                    if entries.is_empty() {
                        ui.horizontal(|ui| {
                            ui.add_space(24.0);
                            ui.weak("keine Einträge mehr im Journal");
                        });
                    }
                    for (i, e) in entries.iter().enumerate() {
                        ui.horizontal(|ui| {
                            ui.add_space(24.0);
                            ui.label(if e.is_dir { "Ordner" } else { "Datei" });
                            ui.add(
                                egui::Label::new(
                                    e.from
                                        .strip_prefix(&root)
                                        .unwrap_or(&e.from)
                                        .to_string_lossy(),
                                )
                                .truncate(),
                            );
                            if ui.small_button("Wiederherstellen").clicked() {
                                restore_entry = Some((s.journal_path.clone(), i));
                            }
                            if ui
                                .small_button(
                                    egui::RichText::new("Löschen")
                                        .color(egui::Color32::from_rgb(230, 110, 100)),
                                )
                                .clicked()
                            {
                                app.quarantine.confirm =
                                    Some(Purge::Entry(s.journal_path.clone(), i));
                            }
                        });
                    }
                }
                ui.separator();
            }
        });

    if let Some(j) = toggle_expand {
        if app.quarantine.expanded.as_ref() == Some(&j) {
            app.quarantine.expanded = None;
            app.quarantine.entries.clear();
        } else {
            app.quarantine.entries = actions::Journal::load(&j)
                .map(|j| j.entries)
                .unwrap_or_default();
            app.quarantine.expanded = Some(j);
        }
    }
    if let Some(j) = restore_session {
        let msg = match actions::undo(&j) {
            Ok(r) => format!(
                "{} Einträge wiederhergestellt, {} Konflikte.",
                r.restored,
                r.conflicts.len()
            ),
            Err(e) => format!("Wiederherstellen fehlgeschlagen: {e:#}"),
        };
        after_change(app, msg);
    }
    if let Some((j, i)) = restore_entry {
        let msg = match actions::undo_entry(&j, i) {
            Ok(()) => "Eintrag wiederhergestellt.".to_string(),
            Err(e) => format!("Wiederherstellen fehlgeschlagen: {e:#}"),
        };
        after_change(app, msg);
    }
    confirm_modal(app, ctx);
}

fn confirm_modal(app: &mut App, ctx: &egui::Context) {
    let Some(purge) = app.quarantine.confirm.clone() else {
        return;
    };
    let (title, detail) = match &purge {
        Purge::Session(j) => {
            let s = app
                .quarantine
                .sessions
                .iter()
                .find(|s| &s.journal_path == j);
            (
                "Sitzung endgültig löschen?".to_string(),
                s.map(|s| format!("{}: {} Dateien, {}", s.name, s.files, human(s.bytes)))
                    .unwrap_or_default(),
            )
        }
        Purge::Entry(_, i) => (
            "Eintrag endgültig löschen?".to_string(),
            app.quarantine
                .entries
                .get(*i)
                .map(|e| e.from.to_string_lossy().into_owned())
                .unwrap_or_default(),
        ),
        Purge::All => (
            "Alle Sitzungen endgültig löschen?".to_string(),
            format!(
                "{} Sitzungen, {} insgesamt",
                app.quarantine.sessions.len(),
                human(app.quarantine.total_bytes())
            ),
        ),
    };
    let mut run = false;
    let modal = egui::Modal::new(egui::Id::new("purge_confirm")).show(ctx, |ui| {
        ui.set_width(440.0);
        ui.heading(title);
        ui.label(detail);
        ui.colored_label(
            egui::Color32::from_rgb(230, 110, 100),
            "Das lässt sich nicht rückgängig machen. Die Dateien werden ohne Papierkorb gelöscht.",
        );
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            if ui.button("Abbrechen").clicked() {
                app.quarantine.confirm = None;
            }
            if ui.button("Ja, endgültig löschen").clicked() {
                run = true;
            }
        });
    });
    if modal.should_close() {
        app.quarantine.confirm = None;
    }
    if !run {
        return;
    }
    app.quarantine.confirm = None;
    let msg = match purge {
        Purge::Session(j) => match actions::purge_session(&j) {
            Ok(r) => format!(
                "Sitzung gelöscht: {} Dateien, {} freigegeben.",
                r.removed,
                human(r.bytes)
            ),
            Err(e) => format!("Löschen fehlgeschlagen: {e:#}"),
        },
        Purge::Entry(j, i) => match actions::purge_entry(&j, i) {
            Ok(r) => format!("Eintrag gelöscht, {} freigegeben.", human(r.bytes)),
            Err(e) => format!("Löschen fehlgeschlagen: {e:#}"),
        },
        Purge::All => {
            let mut n = 0;
            let mut bytes = 0;
            let mut errors = Vec::new();
            for s in app.quarantine.sessions.clone() {
                match actions::purge_session(&s.journal_path) {
                    Ok(r) => {
                        n += r.removed;
                        bytes += r.bytes;
                    }
                    Err(e) => errors.push(format!("{}: {e:#}", s.name)),
                }
            }
            let mut m = format!("{n} Dateien gelöscht, {} freigegeben.", human(bytes));
            for e in errors {
                m.push_str(&format!("\n{e}"));
            }
            m
        }
    };
    app.quarantine.message = Some(msg);
    app.quarantine.expanded = None;
    app.quarantine.entries.clear();
    app.quarantine.stale = true;
}
