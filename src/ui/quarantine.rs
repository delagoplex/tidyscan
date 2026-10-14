//! Quarantäne tab: list sessions, restore everything or single entries, and the only
//! place where data is deleted for good.

use std::path::{Path, PathBuf};

use eframe::egui::{self, Ui};

use super::{AfterWork, App, reveal, theme};
use crate::actions::{self, JournalEntry, SessionInfo};
use crate::analysis::human;
use crate::scan::QUARANTINE_DIR_NAME;

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
    /// The disk changed; reload on the next frame.
    pub stale: bool,
    /// Root the listing was loaded for. A different root means a different quarantine.
    loaded_for: Option<PathBuf>,
    /// Quarantine folders below the root that belong to scans of subfolders:
    /// (folder, files, bytes).
    pub nested: Vec<(PathBuf, u64, u64)>,
    pub confirm: Option<Purge>,
    pub message: Option<String>,
}

impl QuarantineState {
    pub fn refresh(&mut self, root: &Path, nested: &[PathBuf]) {
        self.nested = nested
            .iter()
            .filter(|p| p.is_dir())
            .map(|p| {
                let (files, bytes) = actions::dir_stats(p);
                (p.clone(), files, bytes)
            })
            .collect();
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
        self.loaded_for = Some(root.to_path_buf());
    }

    pub fn total_bytes(&self) -> u64 {
        self.sessions.iter().map(|s| s.bytes).sum()
    }
}

/// Up to ten conflict lines for a message.
fn conflict_lines(conflicts: &[(PathBuf, String)]) -> String {
    let mut out = String::new();
    for (p, why) in conflicts.iter().take(10) {
        out.push_str(&format!("\n  {}: {why}", p.display()));
    }
    if conflicts.len() > 10 {
        out.push_str(&format!("\n  … und {} weitere", conflicts.len() - 10));
    }
    out
}

fn restore_session(app: &mut App, journal: PathBuf) {
    app.run_work(
        "Sitzung wird wiederhergestellt",
        AfterWork::Quarantine { tree_changed: true },
        move |progress| match actions::undo_with(&journal, &mut |d, t| progress.set(d, t)) {
            Ok(r) => format!(
                "{} Einträge wiederhergestellt, {} Konflikte.{}",
                r.restored,
                r.conflicts.len(),
                conflict_lines(&r.conflicts)
            ),
            Err(e) => format!("Wiederherstellen fehlgeschlagen: {e:#}"),
        },
    );
}

fn restore_entry(app: &mut App, journal: PathBuf, index: usize) {
    app.run_work(
        "Eintrag wird wiederhergestellt",
        AfterWork::Quarantine { tree_changed: true },
        move |_| match actions::undo_entry(&journal, index) {
            Ok(()) => "Eintrag wiederhergestellt.".to_string(),
            Err(e) => format!("Wiederherstellen fehlgeschlagen: {e:#}"),
        },
    );
}

fn purge(app: &mut App, what: Purge) {
    let sessions: Vec<(String, PathBuf)> = app
        .quarantine
        .sessions
        .iter()
        .map(|s| (s.name.clone(), s.journal_path.clone()))
        .collect();
    app.quarantine.expanded = None;
    app.quarantine.entries.clear();
    app.run_work(
        "Quarantäne wird gelöscht",
        AfterWork::Quarantine {
            tree_changed: false,
        },
        move |progress| match what {
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
                let (mut n, mut bytes, mut errors) = (0, 0, Vec::new());
                for (i, (name, journal)) in sessions.iter().enumerate() {
                    progress.set(i, sessions.len());
                    match actions::purge_session(journal) {
                        Ok(r) => {
                            n += r.removed;
                            bytes += r.bytes;
                        }
                        Err(e) => errors.push(format!("{name}: {e:#}")),
                    }
                }
                let mut m = format!("{n} Dateien gelöscht, {} freigegeben.", human(bytes));
                for e in errors {
                    m.push_str(&format!("\n{e}"));
                }
                m
            }
        },
    );
}

pub fn show(app: &mut App, ui: &mut Ui, ctx: &egui::Context) {
    let Some(root) = app.quarantine_root() else {
        ui.heading("Quarantäne");
        ui.label("Der Ordner im Feld links existiert nicht.");
        return;
    };
    let nested: Vec<PathBuf> = app
        .result
        .as_ref()
        .map(|r| r.nested_quarantines.clone())
        .unwrap_or_default();
    if app.quarantine.stale || app.quarantine.loaded_for.as_deref() != Some(root.as_path()) {
        app.quarantine.refresh(&root, &nested);
    }
    let quarantine_dir = root.join(QUARANTINE_DIR_NAME);

    ui.horizontal(|ui| {
        ui.heading("Quarantäne");
        ui.label(format!(
            "{} Sitzungen, {} auf der Platte",
            app.quarantine.sessions.len(),
            human(app.quarantine.total_bytes())
        ));
        if ui.small_button("Aktualisieren").clicked() {
            app.quarantine.refresh(&root, &nested);
        }
        if ui.small_button("Ordner anzeigen").clicked() {
            reveal(&quarantine_dir);
        }
    });
    ui.weak(format!(
        "Alles unter {}. Wiederherstellen legt die Einträge an ihren Originalpfad zurück und überschreibt nichts. \
         Endgültig löschen ist die einzige Stelle, an der tidyscan Daten entfernt.",
        quarantine_dir.display()
    ));
    if let Some(m) = &app.quarantine.message {
        ui.label(egui::RichText::new(m).small());
    }
    ui.separator();
    nested_section(app, &root, ui);

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

    enum Click {
        Expand(PathBuf),
        RestoreSession(PathBuf),
        RestoreEntry(PathBuf, usize),
        /// An empty session: nothing is lost, so no question is asked.
        Discard(PathBuf),
    }
    let mut click: Option<Click> = None;
    let state = &mut app.quarantine;

    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            for s in &state.sessions {
                let expanded = state.expanded.as_ref() == Some(&s.journal_path);
                let journal = || s.journal_path.clone();
                ui.horizontal(|ui| {
                    if theme::disclosure(ui, expanded, false).clicked() {
                        click = Some(Click::Expand(journal()));
                    }
                    ui.monospace(&s.name);
                    if s.entries == 0 && s.files == 0 {
                        ui.weak(if s.purged > 0 {
                            "geleert"
                        } else {
                            "wiederhergestellt, leer"
                        });
                        if ui.small_button("Entfernen").clicked() {
                            click = Some(Click::Discard(journal()));
                        }
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
                            click = Some(Click::RestoreSession(journal()));
                        }
                        if theme::danger_button(ui, "Endgültig löschen …").clicked() {
                            state.confirm = Some(Purge::Session(journal()));
                        }
                    }
                    if ui.small_button("Anzeigen").clicked() {
                        reveal(&s.session_dir);
                    }
                });
                if expanded {
                    if state.entries.is_empty() {
                        ui.horizontal(|ui| {
                            ui.add_space(24.0);
                            ui.weak("keine Einträge mehr im Journal");
                        });
                    }
                    for (i, e) in state.entries.iter().enumerate() {
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
                                click = Some(Click::RestoreEntry(journal(), i));
                            }
                            if theme::danger_button(ui, "Löschen").clicked() {
                                state.confirm = Some(Purge::Entry(journal(), i));
                            }
                        });
                    }
                }
                ui.separator();
            }
        });

    match click {
        Some(Click::Expand(j)) => {
            if state.expanded.as_ref() == Some(&j) {
                state.expanded = None;
                state.entries.clear();
            } else {
                state.entries = actions::Journal::load(&j)
                    .map(|j| j.entries)
                    .unwrap_or_default();
                state.expanded = Some(j);
            }
        }
        Some(Click::RestoreSession(j)) => restore_session(app, j),
        Some(Click::RestoreEntry(j, i)) => restore_entry(app, j, i),
        Some(Click::Discard(j)) => purge(app, Purge::Session(j)),
        None => {}
    }
    confirm_modal(app, ctx);
}

/// Quarantines that belong to scans of subfolders. They are managed from there; here
/// they are only pointed out, because their content appears in no size of this scan.
fn nested_section(app: &mut App, root: &Path, ui: &mut Ui) {
    if app.quarantine.nested.is_empty() {
        return;
    }
    let mut scan: Option<PathBuf> = None;
    ui.label(
        "Quarantänen aus Scans von Unterordnern (in keiner Größenangabe dieses Scans enthalten):",
    );
    for (dir, files, bytes) in &app.quarantine.nested {
        let owner = dir.parent().unwrap_or(dir);
        ui.horizontal(|ui| {
            ui.add_space(24.0);
            ui.add(
                egui::Label::new(owner.strip_prefix(root).unwrap_or(owner).to_string_lossy())
                    .truncate(),
            );
            ui.weak(format!("{files} Dateien, {}", human(*bytes)));
            if ui.small_button("Diesen Ordner scannen").clicked() {
                scan = Some(owner.to_path_buf());
            }
            if ui.small_button("Anzeigen").clicked() {
                reveal(dir);
            }
        });
    }
    ui.separator();
    if let Some(dir) = scan
        && !app.scanning()
    {
        app.root_text = dir.to_string_lossy().into_owned();
        app.start_scan();
    }
}

fn confirm_modal(app: &mut App, ctx: &egui::Context) {
    let Some(what) = app.quarantine.confirm.clone() else {
        return;
    };
    let state = &app.quarantine;
    let (title, detail) = match &what {
        Purge::Session(j) => (
            "Sitzung endgültig löschen?",
            state
                .sessions
                .iter()
                .find(|s| &s.journal_path == j)
                .map(|s| format!("{}: {} Dateien, {}", s.name, s.files, human(s.bytes)))
                .unwrap_or_default(),
        ),
        Purge::Entry(_, i) => (
            "Eintrag endgültig löschen?",
            state
                .entries
                .get(*i)
                .map(|e| e.from.to_string_lossy().into_owned())
                .unwrap_or_default(),
        ),
        Purge::All => (
            "Alle Sitzungen endgültig löschen?",
            format!(
                "{} Sitzungen, {} insgesamt",
                state.sessions.len(),
                human(state.total_bytes())
            ),
        ),
    };
    let answer = theme::confirm(
        ctx,
        "purge_confirm",
        title,
        "Ja, endgültig löschen",
        true,
        |ui| {
            ui.label(detail);
            ui.colored_label(
                theme::RED,
                "Das lässt sich nicht rückgängig machen. Die Dateien werden ohne Papierkorb gelöscht.",
            );
        },
    );
    match answer {
        theme::Answer::Pending => {}
        theme::Answer::Cancelled => app.quarantine.confirm = None,
        theme::Answer::Confirmed => {
            app.quarantine.confirm = None;
            purge(app, what);
        }
    }
}
