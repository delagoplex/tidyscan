//! Automatik tab: one click computes a proposal (quarantine or sorting), the user
//! reviews safe and unsure entries, re-checks the unsure ones, then confirms.

use std::path::Path;
use std::sync::Arc;

use crossbeam_channel::{Receiver, TryRecvError, unbounded};
use eframe::egui::{self, Ui};

use super::{App, Tab, theme};
use crate::actions::Plan;
use crate::analysis::human;
use crate::dupes::DupeGroup;
use crate::model::ScanResult;
use crate::organize::{self, AfterTree, FolderProfile, OrganizeOptions, OrganizePlan};
use crate::triage::{self, Candidate, Recheck, Risk, Triage, TriageOptions};

const MAX_ROWS_PER_GROUP: usize = 300;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Quarantine,
    Organize,
}

impl Mode {
    fn title(self) -> &'static str {
        match self {
            Mode::Quarantine => "Quarantäne-Vorschlag",
            Mode::Organize => "Sortier-Vorschlag",
        }
    }
}

pub struct Item {
    pub cand: Candidate,
    pub checked: bool,
    pub rechecked: Option<Recheck>,
}

impl Item {
    /// Whether the item may be ticked at all.
    fn selectable(&self) -> bool {
        self.cand.risk != Risk::Blocked
    }

    /// Ticked and allowed to run.
    fn chosen(&self) -> bool {
        self.checked && self.selectable()
    }
}

enum JobResult {
    Triage(Triage),
    Organize(OrganizePlan),
}

struct RecheckJob {
    rx: Receiver<(usize, Candidate, Recheck)>,
    total: usize,
    done: usize,
}

#[derive(Default)]
pub struct AutoState {
    pub by_year: bool,
    pub include_dupes: bool,
    pub mode: Option<Mode>,
    job: Option<Receiver<JobResult>>,
    waiting_for_dupes: Option<Mode>,
    /// The duplicate search for this proposal was already started once.
    dupes_requested: bool,
    pub items: Vec<Item>,
    pub profiles: Vec<FolderProfile>,
    pub after: Option<AfterTree>,
    pub notes: Vec<String>,
    pub protected: usize,
    recheck: Option<RecheckJob>,
    pub confirm: bool,
}

impl AutoState {
    pub fn new() -> Self {
        Self {
            include_dupes: true,
            ..Default::default()
        }
    }

    /// Forget results (after a rescan), keep the options.
    pub fn reset(&mut self) {
        *self = Self {
            by_year: self.by_year,
            include_dupes: self.include_dupes,
            ..Default::default()
        };
    }

    pub fn busy(&self) -> bool {
        self.job.is_some() || self.waiting_for_dupes.is_some() || self.recheck.is_some()
    }

    pub(super) fn checked_plan(&self, root: &Path) -> Plan {
        let mut plan = Plan::new(root);
        for i in self.items.iter().filter(|i| i.chosen()) {
            plan.push(i.cand.action.clone());
        }
        plan.dedup();
        plan
    }
}

/// The duplicate groups are fine-grained enough for the automatic mode.
fn dupes_usable(app: &App) -> bool {
    app.dupes.is_some() && app.dupes_min <= TriageOptions::default().dupes_min_size
}

/// Kick off the computation for `mode`. Duplicates are searched first when needed.
pub fn start(app: &mut App, mode: Mode) {
    let Some(result) = app.result.clone() else {
        return;
    };
    if result.cancelled {
        return;
    }
    app.auto.reset();
    app.auto.mode = Some(mode);

    // Groups from the Duplikate tab may have been searched with a larger minimum
    // size and would silently miss everything below it.
    if mode == Mode::Quarantine && app.auto.include_dupes && !dupes_usable(app) {
        if !app.dupes_running() {
            app.start_dupes_min(TriageOptions::default().dupes_min_size);
            app.auto.dupes_requested = true;
        }
        app.auto.waiting_for_dupes = Some(mode);
        return;
    }
    spawn(app, mode, result);
}

fn spawn(app: &mut App, mode: Mode, result: Arc<ScanResult>) {
    let dupes: Option<Arc<Vec<DupeGroup>>> = if app.auto.include_dupes && dupes_usable(app) {
        app.dupes.clone()
    } else {
        None
    };
    if mode == Mode::Quarantine && app.auto.include_dupes && dupes.is_none() {
        app.auto.notes.push(
            "Die Duplikatsuche lieferte kein Ergebnis, der Vorschlag enthält keine Duplikate."
                .into(),
        );
    }
    let opts = OrganizeOptions {
        by_year: app.auto.by_year,
        ..Default::default()
    };
    let Some(ctx) = app.ctx.clone() else {
        return;
    };
    let now = app.now;
    let (tx, rx) = unbounded();
    std::thread::spawn(move || {
        let out = match mode {
            Mode::Quarantine => JobResult::Triage(triage::assess(
                &result,
                &ctx,
                dupes.as_ref().map(|d| d.as_slice()),
                &TriageOptions::default(),
                now,
            )),
            Mode::Organize => {
                JobResult::Organize(organize::plan_organize(&result, &ctx, &opts, now))
            }
        };
        let _ = tx.send(out);
    });
    app.auto.job = Some(rx);
}

/// Called every frame from the app.
pub fn poll(app: &mut App) {
    if let Some(mode) = app.auto.waiting_for_dupes
        && !app.dupes_running()
    {
        if !dupes_usable(app) && !app.auto.dupes_requested {
            // The search that just ended was someone else's, with a coarser minimum.
            app.auto.dupes_requested = true;
            app.start_dupes_min(TriageOptions::default().dupes_min_size);
        } else {
            app.auto.waiting_for_dupes = None;
            if let Some(r) = app.result.clone() {
                spawn(app, mode, r);
            }
        }
    }

    if let Some(job) = &app.auto.job {
        match job.try_recv() {
            Ok(out) => {
                app.auto.job = None;
                let (safe, unsure) = match out {
                    JobResult::Triage(t) => {
                        app.auto.protected = t.protected;
                        app.auto.notes.extend(t.notes);
                        (t.safe, t.unsure)
                    }
                    JobResult::Organize(p) => {
                        app.auto.notes.extend(p.notes);
                        app.auto.profiles = p.profiles;
                        app.auto.after = Some(p.after);
                        (p.safe, p.unsure)
                    }
                };
                let item = |checked: bool| {
                    move |cand: Candidate| Item {
                        cand,
                        checked,
                        rechecked: None,
                    }
                };
                app.auto.items = safe
                    .into_iter()
                    .map(item(true))
                    .chain(unsure.into_iter().map(item(false)))
                    .collect();
            }
            Err(TryRecvError::Empty) => {}
            // The worker is gone without an answer: it panicked.
            Err(TryRecvError::Disconnected) => {
                app.auto.job = None;
                app.auto.mode = None;
                app.error = Some("Der Vorschlag konnte nicht berechnet werden.".into());
            }
        }
    }

    if let Some(job) = &mut app.auto.recheck {
        let mut finished = false;
        loop {
            match job.rx.try_recv() {
                Ok((idx, cand, outcome)) => {
                    job.done += 1;
                    if let Some(item) = app.auto.items.get_mut(idx) {
                        // A re-check settles what it found out and nothing else:
                        // "still unsure" leaves the user's own tick alone.
                        match outcome {
                            Recheck::Promoted(_) => item.checked = true,
                            Recheck::Blocked(_) => item.checked = false,
                            Recheck::StillUnsure(_) => {}
                        }
                        item.cand = cand;
                        item.rechecked = Some(outcome);
                    }
                    finished |= job.done >= job.total;
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    finished = true;
                    break;
                }
            }
        }
        if finished {
            app.auto.recheck = None;
        }
    }
}

fn start_recheck(app: &mut App, indices: Vec<usize>) {
    if indices.is_empty() || app.auto.busy() {
        return;
    }
    let work: Vec<(usize, Candidate)> = indices
        .iter()
        .map(|&i| (i, app.auto.items[i].cand.clone()))
        .collect();
    let (tx, rx) = unbounded();
    let total = work.len();
    std::thread::spawn(move || {
        for (idx, mut cand) in work {
            let outcome = triage::recheck(&mut cand);
            let _ = tx.send((idx, cand, outcome));
        }
    });
    app.auto.recheck = Some(RecheckJob { rx, total, done: 0 });
}

pub fn show(app: &mut App, ui: &mut Ui, ctx: &egui::Context) {
    let Some(result) = app.result.clone() else {
        return;
    };
    let busy = app.auto.busy();
    // A partial tree says nothing reliable about what is empty, loose or duplicated.
    let usable = !result.cancelled;
    if !usable {
        ui.colored_label(
            theme::AMBER,
            "Der Scan wurde abgebrochen. Für die Automatik bitte vollständig scannen.",
        );
    }

    ui.horizontal_wrapped(|ui| {
        ui.add_enabled_ui(!busy && usable, |ui| {
            if theme::primary_button(ui, "Quarantäne-Vorschlag berechnen").clicked() {
                start(app, Mode::Quarantine);
            }
            if theme::primary_button(ui, "Sortier-Vorschlag berechnen").clicked() {
                start(app, Mode::Organize);
            }
        });
        ui.separator();
        ui.checkbox(&mut app.auto.include_dupes, "Duplikate einbeziehen");
        ui.checkbox(&mut app.auto.by_year, "Jahres-Unterordner beim Sortieren");
        if busy {
            ui.add(egui::Spinner::new());
            if app.auto.waiting_for_dupes.is_some() {
                ui.label("Duplikate werden gesucht …");
            } else if let Some(r) = &app.auto.recheck {
                ui.label(format!("Nachprüfen {}/{}", r.done, r.total));
            } else {
                ui.label("Vorschlag wird berechnet …");
            }
        }
    });
    ui.weak(
        "Sicher = wird ohne Nachfrage verschoben (immer in die Quarantäne bzw. den Zielordner, nie gelöscht). \
         Unsicher = Entscheidung liegt bei dir, Nachprüfen liefert weitere Hinweise.",
    );

    let Some(mode) = app.auto.mode else {
        ui.add_space(12.0);
        ui.label("Noch kein Vorschlag berechnet.");
        return;
    };
    if app.auto.job.is_some() || app.auto.waiting_for_dupes.is_some() {
        return;
    }

    ui.separator();
    for n in &app.auto.notes {
        ui.colored_label(theme::AMBER, n);
    }

    // One pass over the items for everything the header and the sections need.
    let mut groups = Groups::default();
    let (mut safe_n, mut safe_b, mut unsure_n, mut checked_n, mut checked_b) =
        (0, 0u64, 0, 0, 0u64);
    for (i, it) in app.auto.items.iter().enumerate() {
        let safe = it.cand.risk == Risk::Safe;
        if safe {
            safe_n += 1;
            safe_b += it.cand.size();
        } else {
            unsure_n += 1;
        }
        if it.chosen() {
            checked_n += 1;
            checked_b += it.cand.size();
        }
        groups.add(safe, it.cand.kind.label(), i);
    }

    ui.horizontal(|ui| {
        ui.label(egui::RichText::new(mode.title()).size(17.0).strong());
        theme::pill(
            ui,
            &format!("{safe_n} sicher · {}", human(safe_b)),
            theme::GREEN,
        );
        theme::pill(ui, &format!("{unsure_n} unsicher"), theme::AMBER);
        theme::pill(
            ui,
            &format!("{} geschützt", app.auto.protected),
            theme::TEXT_DIM,
        );
    });

    // Bottom action bar first so it stays visible.
    egui::Panel::bottom("auto_actions").show(ui, |ui| {
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            let can_run = checked_n > 0 && !busy && !app.scanning();
            if ui
                .add_enabled(
                    can_run,
                    egui::Button::new(format!(
                        "Ausgewählte ausführen ({checked_n}, {})",
                        human(checked_b)
                    )),
                )
                .clicked()
            {
                app.auto.confirm = true;
            }
            if ui
                .add_enabled(
                    checked_n > 0 && !busy,
                    egui::Button::new("In Plan übernehmen"),
                )
                .clicked()
            {
                for i in app.auto.items.iter().filter(|i| i.chosen()) {
                    app.selection.insert(i.cand.action.clone());
                }
                app.tab = Tab::Cleanup;
            }
            // Blocked entries are settled; asking again would only repeat the answer.
            let open: Vec<usize> = app
                .auto
                .items
                .iter()
                .enumerate()
                .filter(|(_, i)| i.cand.risk == Risk::Unsure)
                .map(|(i, _)| i)
                .collect();
            if ui
                .add_enabled(
                    !busy && !open.is_empty(),
                    egui::Button::new("Alle Unsicheren nachprüfen"),
                )
                .clicked()
            {
                start_recheck(app, open);
            }
        });
        ui.add_space(4.0);
    });

    egui::ScrollArea::vertical()
        .id_salt("auto_scroll")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            if mode == Mode::Organize {
                before_after(app, &result, ui);
            }
            section(app, &result, ui, &groups.safe, true, busy);
            ui.add_space(10.0);
            section(app, &result, ui, &groups.unsure, false, busy);
        });

    confirm_modal(app, &result, ctx);
}

/// Item indices per kind label, in order of first appearance.
type Grouped = Vec<(&'static str, Vec<usize>)>;

#[derive(Default)]
struct Groups {
    safe: Grouped,
    unsure: Grouped,
}

impl Groups {
    fn add(&mut self, safe: bool, label: &'static str, index: usize) {
        let list = if safe {
            &mut self.safe
        } else {
            &mut self.unsure
        };
        match list.iter_mut().find(|(l, _)| *l == label) {
            Some((_, v)) => v.push(index),
            None => list.push((label, vec![index])),
        }
    }
}

fn before_after(app: &App, result: &ScanResult, ui: &mut Ui) {
    let Some(after) = &app.auto.after else {
        return;
    };
    let profiles = &app.auto.profiles;
    egui::CollapsingHeader::new("Vorher / Nachher (nur sichere Aktionen)")
        .default_open(true)
        .show(ui, |ui| {
            ui.columns(2, |cols| {
                cols[0].strong("Vorher");
                egui::ScrollArea::vertical()
                    .id_salt("before")
                    .max_height(260.0)
                    .show(&mut cols[0], |ui| {
                        let root = &result.dirs[0];
                        ui.label(format!("(lose im Ordner)   {} Dateien", root.files.len()));
                        let mut children: Vec<usize> = root.children.clone();
                        children.sort_by_key(|&c| result.dirs[c].name().to_lowercase());
                        for c in children {
                            let d = &result.dirs[c];
                            let verdict = profiles
                                .iter()
                                .find(|p| p.dir == c)
                                .map(|p| p.verdict.describe())
                                .unwrap_or_default();
                            ui.label(format!(
                                "{}/   {} Dateien, {}   {}",
                                d.name(),
                                d.total_files,
                                human(d.total_size),
                                verdict
                            ));
                        }
                    });

                cols[1].strong("Nachher");
                egui::ScrollArea::vertical()
                    .id_salt("after")
                    .max_height(260.0)
                    .show(&mut cols[1], |ui| {
                        for f in &after.folders {
                            let name = if f.rel.is_empty() {
                                "(lose im Ordner)".to_string()
                            } else {
                                format!("{}/", f.rel)
                            };
                            let label = format!(
                                "{name}   {} Dateien, {}   (+{} neu)",
                                f.files(),
                                human(f.bytes()),
                                f.incoming.len()
                            );
                            if f.incoming.is_empty() {
                                ui.label(label);
                            } else {
                                egui::CollapsingHeader::new(label)
                                    .id_salt(("after", &f.rel))
                                    .show(ui, |ui| {
                                        for inc in f.incoming.iter().take(MAX_ROWS_PER_GROUP) {
                                            let from = match inc.from.as_deref() {
                                                Some("") | None => "(lose)".to_string(),
                                                Some(s) => format!("{s}/"),
                                            };
                                            ui.label(format!("+ {}   aus {from}", inc.name));
                                        }
                                        if f.incoming.len() > MAX_ROWS_PER_GROUP {
                                            ui.weak(format!(
                                                "… {} weitere",
                                                f.incoming.len() - MAX_ROWS_PER_GROUP
                                            ));
                                        }
                                    });
                            }
                        }
                    });
            });
        });
    ui.add_space(8.0);
}

fn row(app: &mut App, result: &ScanResult, ui: &mut Ui, idx: usize, busy: bool, unsure: bool) {
    let mut recheck = false;
    let it = &mut app.auto.items[idx];
    ui.horizontal(|ui| {
        // Locked while a re-check runs, so its answer cannot collide with a click.
        ui.add_enabled(
            it.selectable() && !busy,
            egui::Checkbox::without_text(&mut it.checked),
        );
        ui.label(it.cand.action.size_label());
        ui.add(
            egui::Label::new(
                egui::RichText::new(result.relative(&it.cand.action.source).to_string_lossy())
                    .strong(),
            )
            .truncate(),
        );
        ui.label(it.cand.action.target_label());
        if unsure
            && it.cand.risk == Risk::Unsure
            && ui
                .add_enabled(!busy, egui::Button::new("Nachprüfen").small())
                .clicked()
        {
            recheck = true;
        }
        if ui.small_button("Anzeigen").clicked() {
            super::reveal(&it.cand.action.source);
        }
    });
    let note = |ui: &mut Ui, text: egui::RichText| {
        ui.horizontal(|ui| {
            ui.add_space(28.0);
            ui.label(text.small());
        });
    };
    note(ui, egui::RichText::new(&it.cand.reason).weak());
    for h in &it.cand.hints {
        note(ui, egui::RichText::new(h).weak());
    }
    if let Some(r) = &it.rechecked {
        let (color, text) = match r {
            Recheck::Promoted(m) => (theme::GREEN, format!("Jetzt sicher: {m}")),
            Recheck::StillUnsure(m) => (theme::AMBER, format!("Weiter unsicher: {m}")),
            Recheck::Blocked(m) => (theme::RED, format!("Nicht anfassen: {m}")),
        };
        note(ui, egui::RichText::new(text).color(color));
    }
    if recheck {
        start_recheck(app, vec![idx]);
    }
}

fn section(
    app: &mut App,
    result: &ScanResult,
    ui: &mut Ui,
    groups: &Grouped,
    safe: bool,
    busy: bool,
) {
    if safe {
        theme::section_heading(ui, "Sicher", theme::GREEN);
    } else {
        theme::section_heading(ui, "Unsicher", theme::AMBER);
    }
    if groups.is_empty() {
        ui.label(if safe {
            "Nichts, was sich gefahrlos automatisch erledigen lässt."
        } else {
            "Keine unsicheren Einträge."
        });
    }
    for (label, idx) in groups {
        let bytes: u64 = idx.iter().map(|&i| app.auto.items[i].cand.size()).sum();
        let chosen = idx.iter().filter(|&&i| app.auto.items[i].chosen()).count();
        let title = format!(
            "{label}   {} Einträge, {}   ({chosen} ausgewählt)",
            idx.len(),
            human(bytes)
        );
        egui::CollapsingHeader::new(title)
            // The title changes with every tick; the id must not.
            .id_salt((safe, *label))
            .default_open(!safe || idx.len() <= 40)
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.add_enabled_ui(!busy, |ui| {
                        if !safe && ui.small_button("Diese nachprüfen").clicked() {
                            let open = idx
                                .iter()
                                .copied()
                                .filter(|&i| app.auto.items[i].cand.risk == Risk::Unsure)
                                .collect();
                            start_recheck(app, open);
                        }
                        if ui.small_button("Alle an").clicked() {
                            for &i in idx {
                                let it = &mut app.auto.items[i];
                                it.checked = it.selectable();
                            }
                        }
                        if ui.small_button("Alle aus").clicked() {
                            for &i in idx {
                                app.auto.items[i].checked = false;
                            }
                        }
                    });
                });
                for &i in idx.iter().take(MAX_ROWS_PER_GROUP) {
                    row(app, result, ui, i, busy, !safe);
                }
                if idx.len() > MAX_ROWS_PER_GROUP {
                    ui.weak(format!(
                        "… {} weitere Einträge dieser Art (Auswahl gilt für alle)",
                        idx.len() - MAX_ROWS_PER_GROUP
                    ));
                }
            });
    }
}

fn confirm_modal(app: &mut App, result: &ScanResult, ctx: &egui::Context) {
    if !app.auto.confirm {
        return;
    }
    // The plan belongs to the folder that was scanned, not to whatever the folder
    // field says by now.
    let plan = app.auto.checked_plan(&result.root);
    let unsure_chosen = app
        .auto
        .items
        .iter()
        .filter(|i| i.chosen() && i.cand.risk != Risk::Safe)
        .count();
    let answer = theme::confirm(
        ctx,
        "auto_confirm",
        "Vorschlag ausführen?",
        "Ja, ausführen",
        false,
        |ui| {
            ui.label(format!(
                "{} Einträge ({}) werden verschoben.",
                plan.len(),
                human(plan.total_bytes())
            ));
            if unsure_chosen > 0 {
                ui.colored_label(
                    theme::AMBER,
                    format!("Darunter {unsure_chosen} als unsicher markierte Einträge."),
                );
            }
            ui.label("Alles landet in der Quarantäne oder im Zielordner und kann im Tab Quarantäne rückgängig gemacht werden.");
        },
    );
    match answer {
        theme::Answer::Pending => {}
        theme::Answer::Cancelled => app.auto.confirm = false,
        theme::Answer::Confirmed => {
            app.auto.confirm = false;
            app.execute_plan(plan);
        }
    }
}
