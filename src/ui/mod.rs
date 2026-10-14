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
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

use crossbeam_channel::{Receiver, unbounded};
use eframe::egui;

use crate::actions::{Action, Plan};
use crate::age::{AgeBasis, AtimeReport, OldFile};
use crate::analysis::{self, CategorySizes, human};
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
    done_rx: Receiver<anyhow::Result<ScanResult>>,
    cancel: Arc<AtomicBool>,
    last: ScanProgress,
}

struct DupeJob {
    done_rx: Receiver<Vec<DupeGroup>>,
    cancel: Arc<AtomicBool>,
    counters: Arc<(AtomicU64, AtomicU64)>,
}

/// The set of actions the user has ticked, keyed by source path.
#[derive(Default)]
pub struct Selection {
    items: HashMap<PathBuf, Action>,
}

impl Selection {
    pub fn contains(&self, p: &Path) -> bool {
        self.items.contains_key(p)
    }
    pub fn toggle(&mut self, action: Action) {
        if self.items.remove(&action.source).is_none() {
            self.items.insert(action.source.clone(), action);
        }
    }
    pub fn insert(&mut self, action: Action) {
        self.items.insert(action.source.clone(), action);
    }
    pub fn remove(&mut self, p: &Path) {
        self.items.remove(p);
    }
    pub fn clear(&mut self) {
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
    pub fn to_plan(&self, root: &Path) -> Plan {
        let mut plan = Plan::new(root);
        let mut actions: Vec<Action> = self.items.values().cloned().collect();
        actions.sort_by(|a, b| a.source.cmp(&b.source));
        for a in actions {
            plan.push(a);
        }
        plan
    }
}

/// Quarantine a file as the scan saw it; a file changed since then is skipped at run time.
pub fn file_action(result: &ScanResult, id: FileId, reason: &str) -> Action {
    Action::quarantine_file(&result.files[id], reason)
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
    pub(crate) dupes: Option<Vec<DupeGroup>>,
    dupe_job: Option<DupeJob>,
    pub(crate) empty_dirs: Vec<DirId>,
    pub(crate) zero_files: Vec<FileId>,

    // Cleanup
    pub(crate) selection: Selection,
    pub(crate) rules_path: String,
    pub(crate) rules_error: Option<String>,
    pub(crate) confirm_execute: bool,
    pub(crate) last_report: Option<String>,
    pub(crate) journals: Vec<PathBuf>,

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
            dupe_job: None,
            empty_dirs: Vec::new(),
            zero_files: Vec::new(),
            selection: Selection::default(),
            rules_path: String::new(),
            rules_error: None,
            confirm_execute: false,
            last_report: None,
            journals: Vec::new(),
            auto: auto::AutoState::new(),
            quarantine: quarantine::QuarantineState::default(),
        }
    }

    pub(crate) fn root(&self) -> PathBuf {
        PathBuf::from(self.root_text.trim())
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
        let root = self.root();
        if !root.is_dir() {
            self.error = Some(format!("{} ist kein Ordner.", root.display()));
            return;
        }
        self.error = None;
        self.cancel_dupes();
        self.result = None;
        self.dupes = None;
        self.selection.clear();
        self.last_report = None;
        self.auto.reset();
        self.status = format!("Scanne {} …", root.display());

        let opts = self.scan_options();
        let (ptx, prx) = unbounded();
        let (dtx, drx) = unbounded();
        let cancel = Arc::new(AtomicBool::new(false));
        let c2 = cancel.clone();
        std::thread::spawn(move || {
            let r = scan::scan(&root, &opts, Some(ptx), c2);
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
        if let Ok(res) = job.done_rx.try_recv() {
            self.scan_job = None;
            match res {
                Ok(r) => {
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
                    self.journals = crate::actions::list_journals(&r.root);
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
        if let Ok(groups) = job.done_rx.try_recv() {
            self.dupes = Some(groups);
            self.dupe_job = None;
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

    /// Execute a plan, report, and rescan. Shared by the Aufräumen and Automatik tabs.
    pub(crate) fn execute_plan(&mut self, plan: Plan) {
        let msg = match crate::actions::execute(&plan, false) {
            Ok(rep) => rep.summary(15),
            Err(e) => format!("Ausführen fehlgeschlagen: {e:#}"),
        };
        self.selection.clear();
        self.start_scan();
        self.last_report = Some(msg);
        self.journals = crate::actions::list_journals(&self.root());
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
        auto::poll(self);
        if self.scanning() || self.dupes_running() || self.auto.busy() {
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
    detach_console();
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
        Box::new(move |cc| Ok(Box::new(App::new(cc, preset)))),
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
