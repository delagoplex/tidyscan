//! Automatik tab: one click computes a proposal (quarantine or sorting), the user
//! reviews safe and unsure entries, re-checks the unsure ones, then confirms.

use std::sync::Arc;

use crossbeam_channel::{Receiver, unbounded};
use eframe::egui::{self, Ui};

use super::{App, Tab};
use crate::actions::{ActionKind, Plan};
use crate::analysis::human;
use crate::context::{self, DirContext};
use crate::dupes::DupeGroup;
use crate::model::ScanResult;
use crate::organize::{
    self, AfterTree, FolderProfile, FolderVerdict, OrganizeOptions, OrganizePlan,
};
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

enum JobResult {
    Triage(Triage),
    Organize(OrganizePlan),
}

struct AutoJob {
    mode: Mode,
    rx: Receiver<(DirContext, JobResult)>,
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
    job: Option<AutoJob>,
    waiting_for_dupes: Option<Mode>,
    pub items: Vec<Item>,
    pub profiles: Vec<FolderProfile>,
    pub after: Option<AfterTree>,
    pub notes: Vec<String>,
    pub protected: usize,
    pub ctx: Option<Arc<DirContext>>,
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
        let (by_year, include_dupes) = (self.by_year, self.include_dupes);
        *self = Self::default();
        self.by_year = by_year;
        self.include_dupes = include_dupes;
    }

    pub fn busy(&self) -> bool {
        self.job.is_some() || self.waiting_for_dupes.is_some() || self.recheck.is_some()
    }

    fn safe_items(&self) -> impl Iterator<Item = (usize, &Item)> {
        self.items
            .iter()
            .enumerate()
            .filter(|(_, i)| i.cand.risk == Risk::Safe)
    }

    fn unsure_items(&self) -> impl Iterator<Item = (usize, &Item)> {
        self.items
            .iter()
            .enumerate()
            .filter(|(_, i)| i.cand.risk != Risk::Safe)
    }

    fn checked_plan(&self, root: &std::path::Path) -> Plan {
        let mut plan = Plan::new(root);
        for i in self.items.iter().filter(|i| i.checked) {
            plan.push(i.cand.action.clone());
        }
        plan.dedup();
        plan
    }
}

/// Kick off the computation for `mode`. Duplicates are searched first when needed.
pub fn start(app: &mut App, mode: Mode) {
    let Some(result) = app.result.clone() else {
        return;
    };
    app.auto.reset_results();
    app.auto.mode = Some(mode);

    if mode == Mode::Quarantine && app.auto.include_dupes && app.dupes.is_none() {
        if !app.dupes_running() {
            app.start_dupes_min(TriageOptions::default().dupes_min_size);
        }
        app.auto.waiting_for_dupes = Some(mode);
        return;
    }
    spawn(app, mode, result);
}

impl AutoState {
    fn reset_results(&mut self) {
        self.items.clear();
        self.profiles.clear();
        self.after = None;
        self.notes.clear();
        self.protected = 0;
        self.ctx = None;
        self.recheck = None;
        self.job = None;
        self.waiting_for_dupes = None;
        self.confirm = false;
    }
}

fn spawn(app: &mut App, mode: Mode, result: Arc<ScanResult>) {
    let dupes: Option<Vec<DupeGroup>> = if app.auto.include_dupes {
        app.dupes.clone()
    } else {
        None
    };
    let opts = OrganizeOptions {
        by_year: app.auto.by_year,
        ..Default::default()
    };
    let now = app.now;
    let (tx, rx) = unbounded();
    std::thread::spawn(move || {
        let ctx = context::build(&result);
        let out = match mode {
            Mode::Quarantine => JobResult::Triage(triage::assess(
                &result,
                &ctx,
                dupes.as_deref(),
                &TriageOptions::default(),
                now,
            )),
            Mode::Organize => {
                JobResult::Organize(organize::plan_organize(&result, &ctx, &opts, now))
            }
        };
        let _ = tx.send((ctx, out));
    });
    app.auto.job = Some(AutoJob { mode, rx });
}

/// Called every frame from the app.
pub fn poll(app: &mut App) {
    if let Some(mode) = app.auto.waiting_for_dupes
        && !app.dupes_running()
    {
        app.auto.waiting_for_dupes = None;
        if let Some(r) = app.result.clone() {
            spawn(app, mode, r);
        }
    }
    if let Some(job) = &app.auto.job
        && let Ok((ctx, out)) = job.rx.try_recv()
    {
        let mode = job.mode;
        app.auto.job = None;
        app.auto.ctx = Some(Arc::new(ctx));
        app.auto.mode = Some(mode);
        let (safe, unsure) = match out {
            JobResult::Triage(t) => {
                app.auto.protected = t.protected;
                app.auto.notes = t.notes;
                (t.safe, t.unsure)
            }
            JobResult::Organize(p) => {
                app.auto.notes = p.notes;
                app.auto.profiles = p.profiles;
                app.auto.after = Some(p.after);
                (p.safe, p.unsure)
            }
        };
        app.auto.items = safe
            .into_iter()
            .map(|c| Item {
                cand: c,
                checked: true,
                rechecked: None,
            })
            .chain(unsure.into_iter().map(|c| Item {
                cand: c,
                checked: false,
                rechecked: None,
            }))
            .collect();
    }
    if let Some(job) = &mut app.auto.recheck {
        let mut finished = false;
        while let Ok((idx, cand, outcome)) = job.rx.try_recv() {
            job.done += 1;
            if let Some(item) = app.auto.items.get_mut(idx) {
                item.checked = matches!(outcome, Recheck::Promoted(_));
                item.cand = cand;
                item.rechecked = Some(outcome);
            }
            if job.done >= job.total {
                finished = true;
            }
        }
        if finished {
            app.auto.recheck = None;
        }
    }
}

fn start_recheck(app: &mut App, indices: Vec<usize>) {
    let (Some(result), Some(ctx)) = (app.result.clone(), app.auto.ctx.clone()) else {
        return;
    };
    if indices.is_empty() {
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
            let outcome = triage::recheck(&mut cand, &result, &ctx);
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

    ui.horizontal_wrapped(|ui| {
        if ui
            .add_enabled(!busy, egui::Button::new("Quarantäne-Vorschlag berechnen"))
            .clicked()
        {
            start(app, Mode::Quarantine);
        }
        if ui
            .add_enabled(!busy, egui::Button::new("Sortier-Vorschlag berechnen"))
            .clicked()
        {
            start(app, Mode::Organize);
        }
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
    for n in app.auto.notes.clone() {
        ui.colored_label(egui::Color32::from_rgb(220, 160, 60), n);
    }

    let safe_n = app.auto.safe_items().count();
    let safe_b: u64 = app.auto.safe_items().map(|(_, i)| i.cand.size()).sum();
    let unsure_n = app.auto.unsure_items().count();
    let checked_n = app.auto.items.iter().filter(|i| i.checked).count();
    let checked_b: u64 = app
        .auto
        .items
        .iter()
        .filter(|i| i.checked)
        .map(|i| i.cand.size())
        .sum();
    ui.horizontal(|ui| {
        ui.strong(mode.title());
        ui.label(format!(
            "{safe_n} sicher ({}) · {unsure_n} unsicher · {} geschützt übersprungen",
            human(safe_b),
            app.auto.protected
        ));
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
                .add_enabled(checked_n > 0, egui::Button::new("In Plan übernehmen"))
                .clicked()
            {
                for i in app.auto.items.iter().filter(|i| i.checked) {
                    app.selection.insert(i.cand.action.clone());
                }
                app.tab = Tab::Cleanup;
            }
            let unsure_idx: Vec<usize> = app.auto.unsure_items().map(|(i, _)| i).collect();
            if ui
                .add_enabled(
                    !busy && !unsure_idx.is_empty(),
                    egui::Button::new("Alle Unsicheren nachprüfen"),
                )
                .clicked()
            {
                start_recheck(app, unsure_idx);
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
            safe_section(app, &result, ui);
            unsure_section(app, &result, ui, busy);
        });

    confirm_modal(app, ctx);
}

fn before_after(app: &mut App, result: &ScanResult, ui: &mut Ui) {
    let Some(after) = app.auto.after.clone() else {
        return;
    };
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
                        let mut children: Vec<_> =
                            root.children.iter().map(|&c| &result.dirs[c]).collect();
                        children.sort_by_key(|d| d.name().to_lowercase());
                        for d in children {
                            let verdict = app
                                .auto
                                .profiles
                                .iter()
                                .find(|p| result.dirs[p.dir].path == d.path)
                                .map(|p| match &p.verdict {
                                    FolderVerdict::Keep(w) if w.is_empty() => "bleibt".to_string(),
                                    FolderVerdict::Keep(w) => format!("bleibt: {w}"),
                                    FolderVerdict::MoveWhole(c) => format!("nach {}", c.label()),
                                    FolderVerdict::Distribute => "gemischt (unsicher)".into(),
                                    FolderVerdict::Unsure(w) => format!("unsicher: {w}"),
                                })
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

fn row(
    app: &mut App,
    result: &ScanResult,
    ui: &mut Ui,
    idx: usize,
    busy: bool,
    show_recheck: bool,
) {
    let (source, size, is_dir, target, reason, hints, rechecked) = {
        let it = &app.auto.items[idx];
        let target = match &it.cand.action.kind {
            ActionKind::Quarantine => "Quarantäne".to_string(),
            ActionKind::MoveTo(t) => format!("nach {}", t.display()),
        };
        (
            result
                .relative(&it.cand.action.source)
                .to_string_lossy()
                .into_owned(),
            it.cand.size(),
            it.cand.action.is_dir,
            target,
            it.cand.reason.clone(),
            it.cand.hints.clone(),
            it.rechecked.clone(),
        )
    };
    ui.horizontal(|ui| {
        ui.checkbox(&mut app.auto.items[idx].checked, "");
        ui.label(if is_dir {
            "Ordner".to_string()
        } else {
            human(size)
        });
        ui.add(egui::Label::new(egui::RichText::new(source).strong()).truncate());
        ui.label(target);
        if show_recheck
            && ui
                .add_enabled(!busy, egui::Button::new("Nachprüfen").small())
                .clicked()
        {
            start_recheck(app, vec![idx]);
        }
        if ui.small_button("Anzeigen").clicked() {
            super::reveal(&app.auto.items[idx].cand.action.source);
        }
    });
    ui.horizontal(|ui| {
        ui.add_space(28.0);
        ui.label(egui::RichText::new(reason).small().weak());
    });
    for h in hints {
        ui.horizontal(|ui| {
            ui.add_space(28.0);
            ui.label(egui::RichText::new(h).small().weak());
        });
    }
    if let Some(r) = rechecked {
        let (color, text) = match r {
            Recheck::Promoted(m) => (
                egui::Color32::from_rgb(90, 190, 110),
                format!("Jetzt sicher: {m}"),
            ),
            Recheck::StillUnsure(m) => (
                egui::Color32::from_rgb(220, 160, 60),
                format!("Weiter unsicher: {m}"),
            ),
            Recheck::Blocked(m) => (
                egui::Color32::from_rgb(220, 80, 80),
                format!("Nicht anfassen: {m}"),
            ),
        };
        ui.horizontal(|ui| {
            ui.add_space(28.0);
            ui.colored_label(color, egui::RichText::new(text).small());
        });
    }
}

fn group_indices(app: &AutoState, safe: bool) -> Vec<(&'static str, Vec<usize>)> {
    let mut groups: Vec<(&'static str, Vec<usize>)> = Vec::new();
    for (i, it) in app.items.iter().enumerate() {
        if (it.cand.risk == Risk::Safe) != safe {
            continue;
        }
        let label = it.cand.kind.label();
        match groups.iter_mut().find(|(l, _)| *l == label) {
            Some((_, v)) => v.push(i),
            None => groups.push((label, vec![i])),
        }
    }
    groups
}

fn safe_section(app: &mut App, result: &ScanResult, ui: &mut Ui) {
    ui.heading("Sicher");
    let groups = group_indices(&app.auto, true);
    if groups.is_empty() {
        ui.label("Nichts, was sich gefahrlos automatisch erledigen lässt.");
    }
    for (label, idx) in groups {
        let bytes: u64 = idx.iter().map(|&i| app.auto.items[i].cand.size()).sum();
        let checked = idx.iter().filter(|&&i| app.auto.items[i].checked).count();
        let title = format!(
            "{label}   {} Einträge, {}   ({checked} ausgewählt)",
            idx.len(),
            human(bytes)
        );
        egui::CollapsingHeader::new(title)
            .id_salt(("safe", label))
            .default_open(idx.len() <= 40)
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    if ui.small_button("Alle an").clicked() {
                        for &i in &idx {
                            app.auto.items[i].checked = true;
                        }
                    }
                    if ui.small_button("Alle aus").clicked() {
                        for &i in &idx {
                            app.auto.items[i].checked = false;
                        }
                    }
                });
                for &i in idx.iter().take(MAX_ROWS_PER_GROUP) {
                    row(app, result, ui, i, false, false);
                }
                if idx.len() > MAX_ROWS_PER_GROUP {
                    ui.weak(format!(
                        "… {} weitere Einträge dieser Art (Auswahl gilt für alle)",
                        idx.len() - MAX_ROWS_PER_GROUP
                    ));
                }
            });
    }
    ui.add_space(10.0);
}

fn unsure_section(app: &mut App, result: &ScanResult, ui: &mut Ui, busy: bool) {
    ui.heading("Unsicher");
    let groups = group_indices(&app.auto, false);
    if groups.is_empty() {
        ui.label("Keine unsicheren Einträge.");
    }
    for (label, idx) in groups {
        let bytes: u64 = idx.iter().map(|&i| app.auto.items[i].cand.size()).sum();
        let title = format!("{label}   {} Einträge, {}", idx.len(), human(bytes));
        egui::CollapsingHeader::new(title)
            .id_salt(("unsure", label))
            .default_open(true)
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    if ui
                        .add_enabled(!busy, egui::Button::new("Diese nachprüfen").small())
                        .clicked()
                    {
                        start_recheck(app, idx.clone());
                    }
                    if ui.small_button("Alle an").clicked() {
                        for &i in &idx {
                            app.auto.items[i].checked = true;
                        }
                    }
                    if ui.small_button("Alle aus").clicked() {
                        for &i in &idx {
                            app.auto.items[i].checked = false;
                        }
                    }
                });
                for &i in idx.iter().take(MAX_ROWS_PER_GROUP) {
                    row(app, result, ui, i, busy, true);
                }
                if idx.len() > MAX_ROWS_PER_GROUP {
                    ui.weak(format!("… {} weitere", idx.len() - MAX_ROWS_PER_GROUP));
                }
            });
    }
}

fn confirm_modal(app: &mut App, ctx: &egui::Context) {
    if !app.auto.confirm {
        return;
    }
    let root = app.root();
    let plan = app.auto.checked_plan(&root);
    let unsure_checked = app
        .auto
        .items
        .iter()
        .filter(|i| i.checked && i.cand.risk != Risk::Safe)
        .count();
    let mut run = false;
    let modal = egui::Modal::new(egui::Id::new("auto_confirm")).show(ctx, |ui| {
        ui.set_width(460.0);
        ui.heading("Vorschlag ausführen?");
        ui.label(format!(
            "{} Einträge ({}) werden verschoben.",
            plan.len(),
            human(plan.total_bytes())
        ));
        if unsure_checked > 0 {
            ui.colored_label(
                egui::Color32::from_rgb(220, 160, 60),
                format!("Darunter {unsure_checked} als unsicher markierte Einträge."),
            );
        }
        ui.label("Alles landet in der Quarantäne oder im Zielordner und kann im Tab Aufräumen rückgängig gemacht werden.");
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            if ui.button("Abbrechen").clicked() {
                app.auto.confirm = false;
            }
            if ui.button("Ja, ausführen").clicked() {
                run = true;
            }
        });
    });
    if modal.should_close() {
        app.auto.confirm = false;
    }
    if run {
        app.auto.confirm = false;
        app.execute_plan(plan);
    }
}
