//! egui front-end. All heavy work runs on background threads; the UI only polls.

mod auto;
mod cleanup;
mod lists;
mod overview;
mod quarantine;
pub(crate) mod theme;
mod tree;
mod treemap;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, SystemTime};

use crossbeam_channel::{Receiver, TryRecvError, unbounded};
use eframe::egui;

use crate::actions::{Action, Plan};
use crate::age::{AgeBasis, AtimeReport, OldFile};
use crate::analysis::{self, CategorySizes, human};
use crate::context::DirContext;
use crate::dupes::DupeGroup;
use crate::model::{DirId, FileId, ScanResult};
use crate::scan::{self, ScanOptions, ScanProgress};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Overview,
    Old,
    Dupes,
    Empty,
    Auto,
    Cleanup,
    Quarantine,
}

struct ScanJob {
    progress_rx: Receiver<ScanProgress>,
    done_rx: Receiver<anyhow::Result<(ScanResult, DirContext)>>,
    cancel: Arc<AtomicBool>,
    last: ScanProgress,
}

struct DupeJob {
    done_rx: Receiver<Vec<DupeGroup>>,
    cancel: Arc<AtomicBool>,
    counters: Arc<(AtomicU64, AtomicU64)>,
    min_size: u64,
}

/// Progress of a disk operation, written by the worker and read by the UI.
#[derive(Clone, Default)]
pub(crate) struct WorkProgress(Arc<(AtomicUsize, AtomicUsize)>);

impl WorkProgress {
    pub(crate) fn set(&self, done: usize, total: usize) {
        self.0.0.store(done, Ordering::Relaxed);
        self.0.1.store(total, Ordering::Relaxed);
    }

    fn get(&self) -> (usize, usize) {
        (
            self.0.0.load(Ordering::Relaxed),
            self.0.1.load(Ordering::Relaxed),
        )
    }
}

/// What the UI does once a disk operation has finished.
pub(crate) enum AfterWork {
    /// A plan ran: show the report in the Aufräumen tab and scan `root` again.
    Executed { root: PathBuf },
    /// The quarantine changed. `tree_changed` when something came back into the
    /// scanned folder, which makes the current scan outdated.
    Quarantine { tree_changed: bool },
}

/// A disk operation running on a background thread. While it runs, a modal keeps
/// the rest of the UI from starting something that would overlap with it.
struct Work {
    title: String,
    progress: WorkProgress,
    rx: Receiver<String>,
    then: AfterWork,
}

/// The set of actions the user has ticked, keyed by source path.
#[derive(Default)]
pub struct Selection {
    items: HashMap<PathBuf, Action>,
    /// The sorted plan for the current items, built on demand and reused across
    /// frames until the selection changes.
    plan: Option<Arc<Plan>>,
}

impl Selection {
    pub fn contains(&self, p: &Path) -> bool {
        self.items.contains_key(p)
    }
    pub fn toggle(&mut self, action: Action) {
        self.plan = None;
        if self.items.remove(&action.source).is_none() {
            self.items.insert(action.source.clone(), action);
        }
    }
    pub fn insert(&mut self, action: Action) {
        self.plan = None;
        self.items.insert(action.source.clone(), action);
    }
    pub fn remove(&mut self, p: &Path) {
        self.plan = None;
        self.items.remove(p);
    }
    pub fn clear(&mut self) {
        self.plan = None;
        self.items.clear();
    }
    pub fn len(&self) -> usize {
        self.items.len()
    }
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
    pub fn total_bytes(&self) -> u64 {
        self.items.values().map(|a| a.size).sum()
    }
    /// The selection as a plan for `root`, sorted by source path.
    pub fn plan(&mut self, root: &Path) -> Arc<Plan> {
        if let Some(p) = &self.plan
            && p.root == root
        {
            return p.clone();
        }
        let mut plan = Plan::new(root);
        plan.actions = self.items.values().cloned().collect();
        plan.actions.sort_by(|a, b| a.source.cmp(&b.source));
        let plan = Arc::new(plan);
        self.plan = Some(plan.clone());
        plan
    }
}

/// Quarantine a file as the scan saw it; a file changed since then is skipped at run time.
pub fn file_action(result: &ScanResult, id: FileId, reason: &str) -> Action {
    Action::quarantine_file(&result.files[id], reason)
}

/// Quarantine a duplicate on the condition that the copy `keep` is still there, unchanged.
pub fn dupe_action(result: &ScanResult, id: FileId, keep: FileId) -> Action {
    file_action(result, id, "Duplikat").keeping(&result.files[keep])
}

/// Quarantine a folder the scan found empty; it is skipped if it has content at run time.
pub fn empty_dir_action(result: &ScanResult, id: DirId, reason: &str) -> Action {
    Action::quarantine_empty_dir(result.dirs[id].path.clone(), reason)
}

/// Quarantine a folder with everything in it.
pub fn tree_action(result: &ScanResult, id: DirId, reason: &str) -> Action {
    let d = &result.dirs[id];
    Action::quarantine_tree(d.path.clone(), d.total_size, reason)
}

pub struct App {
    pub(crate) root_text: String,
    pub(crate) skip_hidden: bool,
    pub(crate) exclude_text: String,
    scan_job: Option<ScanJob>,
    pub(crate) result: Option<Arc<ScanResult>>,
    /// Projects, protected areas and folder roles of `result`, computed with the scan.
    pub(crate) ctx: Option<Arc<DirContext>>,
    pub(crate) cat_sizes: CategorySizes,
    pub(crate) now: SystemTime,
    pub(crate) tab: Tab,
    pub(crate) status: String,
    pub(crate) error: Option<String>,
    /// Start a scan on the first frame (set when a folder was passed on the command line).
    auto_scan: bool,
    /// Development hook: `TIDYSCAN_AUTO=quarantine|organize` computes that proposal
    /// right after the first scan and opens the Automatik tab.
    auto_after_scan: Option<auto::Mode>,

    // Overview
    pub(crate) selected_dir: DirId,
    pub(crate) detail_cache: Option<overview::DetailCache>,
    pub(crate) tree: tree::TreeState,
    pub(crate) treemap: treemap::TreemapState,
    pub(crate) show_details: bool,

    // Old files
    pub(crate) old_days: u64,
    pub(crate) old_basis: AgeBasis,
    pub(crate) atime: Option<AtimeReport>,
    pub(crate) old_list: Vec<OldFile>,
    pub(crate) old_dirty: bool,
    pub(crate) old_filter: String,
    /// Indices into `old_list` matching `old_filter_applied`.
    pub(crate) old_filtered: Vec<usize>,
    pub(crate) old_filter_applied: Option<String>,

    // Duplicates / empties
    pub(crate) dupe_min_size: String,
    pub(crate) dupes: Option<Arc<Vec<DupeGroup>>>,
    /// Minimum file size the groups in `dupes` were searched with.
    pub(crate) dupes_min: u64,
    dupe_job: Option<DupeJob>,
    pub(crate) empty_dirs: Vec<DirId>,
    pub(crate) zero_files: Vec<FileId>,

    // Cleanup
    pub(crate) selection: Selection,
    pub(crate) rules_path: String,
    pub(crate) rules_error: Option<String>,
    pub(crate) confirm_execute: bool,
    pub(crate) last_report: Option<String>,
    work: Option<Work>,
    /// Something was restored into the scanned folder since the scan.
    pub(crate) scan_outdated: bool,
    /// Resolved form of the folder field, for the quarantine tab without a scan.
    typed_root: Option<(String, Option<PathBuf>)>,

    // Automatik
    pub(crate) auto: auto::AutoState,
    pub(crate) quarantine: quarantine::QuarantineState,
}

impl App {
    fn new(cc: &eframe::CreationContext<'_>, preset: Option<PathBuf>) -> Self {
        theme::apply(&cc.egui_ctx);
        let auto_scan = preset.is_some();
        let auto_after_scan = match std::env::var("TIDYSCAN_AUTO").as_deref() {
            Ok("quarantine") => Some(auto::Mode::Quarantine),
            Ok("organize") => Some(auto::Mode::Organize),
            _ => None,
        };
        let root_text = preset
            .or_else(dirs::download_dir)
            .or_else(dirs::home_dir)
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();
        Self {
            root_text,
            skip_hidden: false,
            exclude_text: "**/node_modules\n**/.git".into(),
            scan_job: None,
            result: None,
            ctx: None,
            cat_sizes: Vec::new(),
            now: SystemTime::now(),
            tab: match std::env::var("TIDYSCAN_TAB").as_deref() {
                Ok("quarantine") => Tab::Quarantine,
                Ok("cleanup") => Tab::Cleanup,
                Ok("auto") => Tab::Auto,
                _ => Tab::Overview,
            },
            status: "Ordner wählen und Scan starten.".into(),
            error: None,
            auto_scan,
            auto_after_scan,
            selected_dir: 0,
            detail_cache: None,
            tree: tree::TreeState::default(),
            treemap: treemap::TreemapState::default(),
            show_details: true,
            old_days: 365,
            old_basis: AgeBasis::Modified,
            atime: None,
            old_list: Vec::new(),
            old_dirty: true,
            old_filter: String::new(),
            old_filtered: Vec::new(),
            old_filter_applied: None,
            dupe_min_size: "1M".into(),
            dupes: None,
            dupes_min: 0,
            dupe_job: None,
            empty_dirs: Vec::new(),
            zero_files: Vec::new(),
            selection: Selection::default(),
            rules_path: String::new(),
            rules_error: None,
            confirm_execute: false,
            last_report: None,
            work: None,
            scan_outdated: false,
            typed_root: None,
            auto: auto::AutoState::new(),
            quarantine: quarantine::QuarantineState::default(),
        }
    }

    /// The folder typed into the field. Only this starts a scan; plans and the
    /// quarantine always refer to the folder that was actually scanned.
    pub(crate) fn root(&self) -> PathBuf {
        PathBuf::from(self.root_text.trim())
    }

    /// Root of the current scan, in the canonical form all its paths start with.
    pub(crate) fn scanned_root(&self) -> Option<PathBuf> {
        self.result.as_ref().map(|r| r.root.clone())
    }

    /// Whose quarantine the Quarantäne tab shows: the scanned folder, or before any
    /// scan the folder typed into the field.
    pub(crate) fn quarantine_root(&mut self) -> Option<PathBuf> {
        if let Some(r) = self.scanned_root() {
            return Some(r);
        }
        let text = self.root_text.trim();
        if self.typed_root.as_ref().is_none_or(|(t, _)| t != text) {
            let resolved = dunce::canonicalize(text).ok().filter(|p| p.is_dir());
            self.typed_root = Some((text.to_string(), resolved));
        }
        self.typed_root.as_ref().and_then(|(_, p)| p.clone())
    }

    pub(crate) fn working(&self) -> bool {
        self.work.is_some()
    }

    pub(crate) fn scanning(&self) -> bool {
        self.scan_job.is_some()
    }

    pub(crate) fn dupes_running(&self) -> bool {
        self.dupe_job.is_some()
    }

    pub(crate) fn scan_options(&self) -> ScanOptions {
        ScanOptions {
            skip_hidden: self.skip_hidden,
            exclude_globs: self
                .exclude_text
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .map(String::from)
                .collect(),
            max_depth: None,
        }
    }

    pub(crate) fn start_scan(&mut self) {
        self.start_scan_at(self.root());
    }

    /// Scan the folder of the current result again, whatever the field says by now.
    pub(crate) fn rescan(&mut self) {
        match self.scanned_root() {
            Some(root) => self.start_scan_at(root),
            None => self.start_scan(),
        }
    }

    fn start_scan_at(&mut self, root: PathBuf) {
        if !root.is_dir() {
            self.error = Some(format!("{} ist kein Ordner.", root.display()));
            return;
        }
        self.error = None;
        self.cancel_dupes();
        self.result = None;
        self.ctx = None;
        self.dupes = None;
        self.selection.clear();
        self.last_report = None;
        self.scan_outdated = false;
        self.auto.reset();
        self.status = format!("Scanne {} …", root.display());

        let opts = self.scan_options();
        let (ptx, prx) = unbounded();
        let (dtx, drx) = unbounded();
        let cancel = Arc::new(AtomicBool::new(false));
        let c2 = cancel.clone();
        std::thread::spawn(move || {
            // The context costs disk lookups, so it is built here and not on the UI thread.
            let r = scan::scan(&root, &opts, Some(ptx), c2).map(|r| {
                let ctx = crate::context::build(&r);
                (r, ctx)
            });
            let _ = dtx.send(r);
        });
        self.scan_job = Some(ScanJob {
            progress_rx: prx,
            done_rx: drx,
            cancel,
            last: ScanProgress::default(),
        });
    }

    pub(crate) fn cancel_scan(&mut self) {
        if let Some(j) = &self.scan_job {
            j.cancel.store(true, Ordering::Relaxed);
        }
    }

    fn poll_scan(&mut self) {
        let Some(job) = &mut self.scan_job else {
            return;
        };
        while let Ok(p) = job.progress_rx.try_recv() {
            job.last = p;
        }
        let res = match job.done_rx.try_recv() {
            Ok(res) => res,
            Err(TryRecvError::Empty) => return,
            // The worker is gone without an answer: it panicked.
            Err(TryRecvError::Disconnected) => {
                Err(anyhow::anyhow!("der Scan wurde unerwartet beendet"))
            }
        };
        {
            self.scan_job = None;
            match res {
                Ok((r, ctx)) => {
                    self.ctx = Some(Arc::new(ctx));
                    self.now = SystemTime::now();
                    self.status = format!(
                        "{}{} Dateien, {} Ordner, {} in {:.1?}. {} Fehler, {} übersprungen.",
                        if r.cancelled {
                            "Abgebrochen, das Ergebnis ist unvollständig. "
                        } else {
                            ""
                        },
                        r.files.len(),
                        r.dirs.len(),
                        human(r.total_size()),
                        r.duration,
                        r.errors.len(),
                        r.skipped
                    );
                    self.cat_sizes = analysis::category_sizes(&r);
                    self.atime = Some(crate::age::atime_report(&r));
                    self.empty_dirs = crate::dupes::empty_dirs_toplevel(&r);
                    self.zero_files = crate::dupes::zero_byte_files(&r);
                    self.quarantine.stale = true;
                    self.selected_dir = 0;
                    self.detail_cache = None;
                    self.tree.reset();
                    self.treemap.reset();
                    self.old_dirty = true;
                    self.old_filter_applied = None;
                    self.result = Some(Arc::new(r));
                    if let Some(mode) = self.auto_after_scan.take() {
                        self.tab = Tab::Auto;
                        auto::start(self, mode);
                    }
                }
                Err(e) => {
                    self.error = Some(format!("Scan fehlgeschlagen: {e:#}"));
                    self.status = "Scan fehlgeschlagen.".into();
                }
            }
        }
    }

    pub(crate) fn refresh_old(&mut self) {
        let Some(r) = &self.result else { return };
        let basis = match (self.old_basis, &self.atime) {
            (AgeBasis::Accessed, Some(rep)) if !rep.reliable => AgeBasis::Modified,
            (b, _) => b,
        };
        self.old_list = crate::age::find_old(r, self.old_days, basis, self.now);
        self.old_dirty = false;
        self.old_filter_applied = None;
    }

    pub(crate) fn start_dupes(&mut self) {
        match crate::rules::parse_size(&self.dupe_min_size) {
            Ok(m) => self.start_dupes_min(m),
            Err(e) => self.error = Some(e.to_string()),
        }
    }

    /// Run the duplicate search in the background with an explicit minimum size.
    pub(crate) fn start_dupes_min(&mut self, min: u64) {
        let Some(r) = &self.result else { return };
        self.error = None;
        let r = r.clone();
        let cancel = Arc::new(AtomicBool::new(false));
        let counters = Arc::new((AtomicU64::new(0), AtomicU64::new(0)));
        let (tx, rx) = unbounded();
        let c2 = cancel.clone();
        let k2 = counters.clone();
        std::thread::spawn(move || {
            let groups = crate::dupes::find_duplicates(&r, min, c2, Some(&k2));
            let _ = tx.send(groups);
        });
        self.dupe_job = Some(DupeJob {
            done_rx: rx,
            cancel,
            counters,
            min_size: min,
        });
    }

    fn cancel_dupes(&mut self) {
        if let Some(j) = &self.dupe_job {
            j.cancel.store(true, Ordering::Relaxed);
        }
        self.dupe_job = None;
    }

    fn poll_dupes(&mut self) {
        let Some(job) = &self.dupe_job else { return };
        match job.done_rx.try_recv() {
            Ok(groups) => {
                self.dupes = Some(Arc::new(groups));
                self.dupes_min = job.min_size;
                self.dupe_job = None;
            }
            Err(TryRecvError::Empty) => {}
            Err(TryRecvError::Disconnected) => {
                self.dupe_job = None;
                self.error = Some("Die Duplikatsuche wurde unerwartet beendet.".into());
            }
        }
    }

    pub(crate) fn dupe_progress(&self) -> Option<(u64, u64)> {
        self.dupe_job.as_ref().map(|j| {
            (
                j.counters.0.load(Ordering::Relaxed),
                j.counters.1.load(Ordering::Relaxed),
            )
        })
    }

    /// Run a disk operation in the background. `job` returns the message to show.
    pub(crate) fn run_work(
        &mut self,
        title: impl Into<String>,
        then: AfterWork,
        job: impl FnOnce(&WorkProgress) -> String + Send + 'static,
    ) {
        if self.work.is_some() {
            return;
        }
        let progress = WorkProgress::default();
        let (tx, rx) = unbounded();
        let p = progress.clone();
        std::thread::spawn(move || {
            let _ = tx.send(job(&p));
        });
        self.work = Some(Work {
            title: title.into(),
            progress,
            rx,
            then,
        });
    }

    fn poll_work(&mut self) {
        let Some(work) = &self.work else { return };
        let msg = match work.rx.try_recv() {
            Ok(msg) => msg,
            Err(TryRecvError::Empty) => return,
            Err(TryRecvError::Disconnected) => {
                "Der Vorgang wurde unerwartet beendet. Was bis dahin verschoben wurde, steht im Journal der Sitzung (Tab Quarantäne)."
                    .to_string()
            }
        };
        let Some(work) = self.work.take() else { return };
        self.quarantine.stale = true;
        match work.then {
            AfterWork::Executed { root } => {
                self.selection.clear();
                self.start_scan_at(root);
                self.last_report = Some(msg);
            }
            AfterWork::Quarantine { tree_changed } => {
                self.quarantine.message = Some(msg);
                self.scan_outdated |= tree_changed && self.result.is_some();
            }
        }
    }

    /// Execute a plan in the background, report, and rescan. Shared by the Aufräumen
    /// and Automatik tabs.
    pub(crate) fn execute_plan(&mut self, plan: Plan) {
        let total = plan.len();
        let then = AfterWork::Executed {
            root: plan.root.clone(),
        };
        self.run_work("Plan wird ausgeführt", then, move |progress| {
            progress.set(0, total);
            let run =
                crate::actions::execute_with(&plan, false, &mut |done| progress.set(done, total));
            match run {
                Ok(rep) => rep.summary(15),
                Err(e) => format!("Ausführen fehlgeschlagen: {e:#}"),
            }
        });
    }

    /// Development hook, debug builds only: with `TIDYSCAN_AUTORUN` set, the first
    /// computed proposal is executed without a click, so the whole path from plan to
    /// report can be watched without a pointing device.
    #[cfg(debug_assertions)]
    fn debug_autorun(&mut self) {
        if self.auto.items.is_empty() || self.auto.busy() || self.working() {
            return;
        }
        if std::env::var_os("TIDYSCAN_AUTORUN").is_none() || self.last_report.is_some() {
            return;
        }
        if let Some(root) = self.scanned_root() {
            let plan = self.auto.checked_plan(&root);
            self.tab = Tab::Cleanup;
            self.execute_plan(plan);
        }
    }

    fn work_modal(&self, ctx: &egui::Context) {
        let Some(work) = &self.work else { return };
        let (done, total) = work.progress.get();
        egui::Modal::new(egui::Id::new("work")).show(ctx, |ui| {
            ui.set_width(380.0);
            ui.heading(&work.title);
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.add(egui::Spinner::new().color(theme::ACCENT));
                if total > 0 {
                    ui.label(format!("{done} von {total}"));
                } else {
                    ui.label("läuft …");
                }
            });
            if total > 0 {
                ui.add(egui::ProgressBar::new(done as f32 / total as f32));
            }
            ui.add_space(4.0);
            ui.label(
                egui::RichText::new(
                    "Bitte das Fenster geöffnet lassen, bis der Vorgang fertig ist.",
                )
                .small()
                .color(theme::TEXT_DIM),
            );
        });
    }

    pub(crate) fn pick_folder(&mut self) {
        let mut dlg = rfd::FileDialog::new();
        let cur = self.root();
        if cur.is_dir() {
            dlg = dlg.set_directory(cur);
        }
        if let Some(p) = dlg.pick_folder() {
            self.root_text = p.to_string_lossy().into_owned();
        }
    }

    fn left_panel(&mut self, ui: &mut egui::Ui) {
        ui.add_space(6.0);
        ui.horizontal(|ui| {
            ui.label(
                egui::RichText::new("tidyscan")
                    .size(24.0)
                    .strong()
                    .color(theme::TEXT),
            );
            ui.label(
                egui::RichText::new(env!("CARGO_PKG_VERSION"))
                    .small()
                    .color(theme::TEXT_DIM),
            );
        });
        ui.add_space(10.0);

        theme::card(ui, |ui| {
            theme::caption(ui, "Ordner");
            ui.add(egui::TextEdit::singleline(&mut self.root_text).desired_width(f32::INFINITY));
            if ui.button("Ordner wählen …").clicked() {
                self.pick_folder();
            }
            ui.add_space(10.0);
            theme::caption(ui, "Optionen");
            ui.checkbox(&mut self.skip_hidden, "Versteckte überspringen");
            ui.label(
                egui::RichText::new("Ausschlüsse (Glob, eine je Zeile)")
                    .small()
                    .color(theme::TEXT_DIM),
            );
            ui.add(
                egui::TextEdit::multiline(&mut self.exclude_text)
                    .desired_rows(3)
                    .desired_width(f32::INFINITY)
                    .font(egui::TextStyle::Monospace),
            );
            ui.add_space(12.0);
            if self.scanning() {
                if ui
                    .add_sized([ui.available_width(), 32.0], egui::Button::new("Abbrechen"))
                    .clicked()
                {
                    self.cancel_scan();
                }
                if let Some(j) = &self.scan_job {
                    ui.add_space(6.0);
                    ui.horizontal(|ui| {
                        ui.add(egui::Spinner::new().color(theme::ACCENT));
                        ui.label(format!(
                            "{} Dateien, {} Ordner, {}",
                            j.last.files,
                            j.last.dirs,
                            human(j.last.bytes)
                        ));
                    });
                    ui.add(
                        egui::Label::new(
                            egui::RichText::new(j.last.current.to_string_lossy())
                                .small()
                                .color(theme::TEXT_DIM),
                        )
                        .truncate(),
                    );
                }
            } else if theme::primary_button_wide(ui, "Scannen").clicked() {
                self.start_scan();
            }
        });

        ui.add_space(10.0);
        theme::card(ui, |ui| {
            theme::caption(ui, "Status");
            ui.label(
                egui::RichText::new(&self.status)
                    .small()
                    .color(theme::TEXT_DIM),
            );
            if let Some(e) = &self.error {
                ui.colored_label(theme::RED, e);
            }
            if let Some(root) = self.scanned_root() {
                ui.add_space(4.0);
                ui.add(
                    egui::Label::new(
                        egui::RichText::new(format!("Gescannt: {}", root.display()))
                            .small()
                            .color(theme::TEXT_DIM),
                    )
                    .truncate(),
                );
            }
            if self.scan_outdated {
                ui.add_space(6.0);
                theme::pill(
                    ui,
                    "Scan veraltet: es wurde etwas wiederhergestellt",
                    theme::AMBER,
                );
                if ui
                    .add_enabled(!self.scanning(), egui::Button::new("Neu scannen"))
                    .clicked()
                {
                    self.rescan();
                }
            }
            if !self.selection.is_empty() {
                ui.add_space(6.0);
                theme::pill(
                    ui,
                    &format!(
                        "Im Plan: {} Einträge, {}",
                        self.selection.len(),
                        human(self.selection.total_bytes())
                    ),
                    theme::ACCENT,
                );
                if ui.button("Zum Aufräumen-Tab").clicked() {
                    self.tab = Tab::Cleanup;
                }
            }
        });
    }
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        if std::mem::take(&mut self.auto_scan) {
            self.start_scan();
        }
        self.poll_scan();
        self.poll_dupes();
        self.poll_work();
        auto::poll(self);
        #[cfg(debug_assertions)]
        self.debug_autorun();
        if self.scanning() || self.dupes_running() || self.auto.busy() || self.working() {
            ctx.request_repaint_after(Duration::from_millis(100));
        }

        egui::Panel::left("left")
            .resizable(true)
            .default_size(260.0)
            .show(ui, |ui| self.left_panel(ui));

        egui::Panel::top("tabs")
            .frame(
                egui::Frame::new()
                    .fill(theme::SURFACE)
                    .inner_margin(egui::Margin::symmetric(6, 0)),
            )
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    let plan_label = if self.selection.is_empty() {
                        "Aufräumen".to_string()
                    } else {
                        format!("Aufräumen ({})", self.selection.len())
                    };
                    let tabs = [
                        (Tab::Overview, "Übersicht".to_string()),
                        (Tab::Old, "Alte Dateien".to_string()),
                        (Tab::Dupes, "Duplikate".to_string()),
                        (Tab::Empty, "Leere Ordner".to_string()),
                        (Tab::Auto, "Automatik".to_string()),
                        (Tab::Cleanup, plan_label),
                        (Tab::Quarantine, "Quarantäne".to_string()),
                    ];
                    for (t, label) in tabs {
                        if theme::tab(ui, self.tab == t, &label).clicked() {
                            self.tab = t;
                        }
                    }
                });
            });

        egui::CentralPanel::default().show(ui, |ui| {
            if self.result.is_none() && !matches!(self.tab, Tab::Cleanup | Tab::Quarantine) {
                ui.centered_and_justified(|ui| {
                    ui.label(if self.scanning() {
                        "Scan läuft …"
                    } else {
                        "Noch kein Scan. Links einen Ordner wählen und auf Scannen klicken."
                    });
                });
                return;
            }
            match self.tab {
                Tab::Overview => overview::show(self, ui),
                Tab::Old => lists::show_old(self, ui),
                Tab::Dupes => lists::show_dupes(self, ui),
                Tab::Empty => lists::show_empty(self, ui),
                Tab::Auto => auto::show(self, ui, &ctx),
                Tab::Cleanup => cleanup::show(self, ui, &ctx),
                Tab::Quarantine => quarantine::show(self, ui, &ctx),
            }
        });
        self.work_modal(&ctx);
    }
}

#[cfg(windows)]
fn detach_console() {
    unsafe extern "system" {
        fn FreeConsole() -> i32;
    }
    // Running from a terminal keeps printing until here; afterwards the GUI owns the process.
    unsafe {
        FreeConsole();
    }
}

#[cfg(not(windows))]
fn detach_console() {}

pub fn run(preset: Option<PathBuf>) -> anyhow::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1500.0, 900.0])
            .with_min_inner_size([800.0, 500.0])
            .with_title("tidyscan"),
        ..Default::default()
    };
    eframe::run_native(
        "tidyscan",
        options,
        Box::new(move |cc| {
            // Only now is it certain that a window exists. Detaching earlier would
            // swallow the message when the GUI cannot start at all.
            detach_console();
            Ok(Box::new(App::new(cc, preset)))
        }),
    )
    .map_err(|e| anyhow::anyhow!("{e}"))
}

/// Reveal a path in the platform file manager. Best effort, errors are ignored.
pub fn reveal(path: &Path) {
    use std::process::Command;
    #[cfg(windows)]
    {
        let _ = Command::new("explorer")
            .arg(format!("/select,{}", path.display()))
            .spawn();
    }
    #[cfg(target_os = "macos")]
    {
        let _ = Command::new("open").arg("-R").arg(path).spawn();
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let dir = if path.is_dir() {
            path
        } else {
            path.parent().unwrap_or(path)
        };
        let _ = Command::new("xdg-open").arg(dir).spawn();
    }
}
