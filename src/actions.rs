//! Cleanup plans, their execution into a quarantine folder, and undo.
//!
//! Nothing here ever deletes user data. Files and directories are *moved* into
//! `<root>/.tidyscan-quarantine/<timestamp>/` (or to a user-chosen target), and every
//! move is journaled so it can be reversed. Only the `purge_*` functions delete, and
//! only inside a quarantine session.

use std::collections::HashSet;
use std::fs;
use std::io::{self, Write};
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

use anyhow::{Context, bail};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::macros::format_description;

use crate::analysis::human;
use crate::model::{FileEntry, serde_time};
use crate::scan::QUARANTINE_DIR_NAME;

pub const JOURNAL_FILE: &str = "undo.json";
/// Append-only record of the moves of a running execution, one JSON entry per line.
/// It is folded into the journal on the next load, so a crash never loses a move.
const JOURNAL_LOG: &str = "undo.log";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ActionKind {
    /// Move into the quarantine folder, preserving the path relative to the root.
    Quarantine,
    /// Move to an explicit directory (absolute, or relative to the root).
    MoveTo(PathBuf),
}

/// Expectations checked right before a move. Anything that no longer holds means
/// the world changed since the scan, and the action is skipped instead of executed.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Guard {
    pub size: u64,
    #[serde(default, with = "serde_time")]
    pub modified: Option<SystemTime>,
    /// For duplicates: the copy that stays behind must still exist unchanged.
    #[serde(default)]
    pub keep: Option<PathBuf>,
    #[serde(default, with = "serde_time")]
    pub keep_modified: Option<SystemTime>,
    /// For directories: there must be no file at any depth when the plan runs.
    #[serde(default)]
    pub expect_empty: bool,
}

impl Guard {
    pub fn for_file(file: &FileEntry) -> Self {
        Self {
            size: file.size,
            modified: file.modified,
            ..Default::default()
        }
    }

    pub fn empty_dir() -> Self {
        Self {
            expect_empty: true,
            ..Default::default()
        }
    }

    /// Require that `keep`, the copy that stays behind, is still what the scan saw.
    pub fn with_keep(mut self, keep: &FileEntry) -> Self {
        self.keep = Some(keep.path.clone());
        self.keep_modified = keep.modified;
        self
    }

    /// `Err(reason)` when the guard no longer holds.
    pub fn check(&self, source: &Path) -> Result<(), String> {
        let md = fs::symlink_metadata(source).map_err(|e| format!("nicht mehr lesbar: {e}"))?;
        if md.is_file() {
            if md.len() != self.size {
                return Err("seit dem Scan verändert (Größe)".into());
            }
            if let (Some(expected), Ok(actual)) = (self.modified, md.modified())
                && !same_instant(expected, actual)
            {
                return Err("seit dem Scan verändert (Datum)".into());
            }
        } else if md.is_dir() && self.expect_empty {
            match first_file_below(source) {
                Ok(None) => {}
                Ok(Some(p)) => {
                    let name = p.file_name().unwrap_or_default().to_string_lossy();
                    return Err(format!("ist nicht mehr leer (enthält {name})"));
                }
                Err(e) => return Err(format!("Inhalt nicht prüfbar: {e}")),
            }
        }
        if let Some(keep) = &self.keep {
            if keep == source {
                return Err("Original-Kopie und Duplikat sind dieselbe Datei".into());
            }
            match fs::symlink_metadata(keep) {
                Ok(k) if !k.is_file() => return Err("Original-Kopie ist keine Datei mehr".into()),
                Ok(k) if k.len() != self.size => {
                    return Err("Original-Kopie hat jetzt eine andere Größe".into());
                }
                Ok(k) => {
                    if let (Some(expected), Ok(actual)) = (self.keep_modified, k.modified())
                        && !same_instant(expected, actual)
                    {
                        return Err("Original-Kopie wurde seit dem Scan verändert".into());
                    }
                }
                Err(_) => return Err("Original-Kopie fehlt".into()),
            }
        }
        Ok(())
    }
}

fn same_instant(a: SystemTime, b: SystemTime) -> bool {
    // Filesystems round timestamps differently; a two-second window covers FAT.
    let d = a
        .duration_since(b)
        .or_else(|_| b.duration_since(a))
        .unwrap_or_default();
    d <= Duration::from_secs(2)
}

/// The first entry below `dir` that is not a directory (symlinks count), if any.
fn first_file_below(dir: &Path) -> io::Result<Option<PathBuf>> {
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for entry in fs::read_dir(&d)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                stack.push(entry.path());
            } else {
                return Ok(Some(entry.path()));
            }
        }
    }
    Ok(None)
}

/// A quarantine folder somewhere below `dir`, left by a scan that used a subfolder as root.
fn nested_quarantine(dir: &Path) -> Option<PathBuf> {
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(rd) = fs::read_dir(&d) else { continue };
        for entry in rd.flatten() {
            if !entry.file_type().is_ok_and(|t| t.is_dir()) {
                continue;
            }
            if entry.file_name() == QUARANTINE_DIR_NAME {
                return Some(entry.path());
            }
            stack.push(entry.path());
        }
    }
    None
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Action {
    pub source: PathBuf,
    pub is_dir: bool,
    pub size: u64,
    pub kind: ActionKind,
    pub reason: String,
    #[serde(default)]
    pub guard: Option<Guard>,
}

impl Action {
    /// Quarantine a file, provided it is still what the scan saw.
    pub fn quarantine_file(file: &FileEntry, reason: impl Into<String>) -> Self {
        Self {
            source: file.path.clone(),
            is_dir: false,
            size: file.size,
            kind: ActionKind::Quarantine,
            reason: reason.into(),
            guard: Some(Guard::for_file(file)),
        }
    }

    /// Move a file into `target_dir`, provided it is still what the scan saw.
    pub fn move_file(file: &FileEntry, target_dir: PathBuf, reason: impl Into<String>) -> Self {
        Self {
            kind: ActionKind::MoveTo(target_dir),
            ..Self::quarantine_file(file, reason)
        }
    }

    /// Quarantine a directory that must still be free of files when the plan runs.
    pub fn quarantine_empty_dir(path: PathBuf, reason: impl Into<String>) -> Self {
        Self {
            source: path,
            is_dir: true,
            size: 0,
            kind: ActionKind::Quarantine,
            reason: reason.into(),
            guard: Some(Guard::empty_dir()),
        }
    }

    /// Quarantine a directory with everything inside it, on the user's explicit request.
    pub fn quarantine_tree(path: PathBuf, size: u64, reason: impl Into<String>) -> Self {
        Self {
            source: path,
            is_dir: true,
            size,
            kind: ActionKind::Quarantine,
            reason: reason.into(),
            guard: None,
        }
    }

    /// Additionally require the kept duplicate to be unchanged.
    pub fn keeping(mut self, keep: &FileEntry) -> Self {
        let guard = self.guard.take().unwrap_or_default();
        self.guard = Some(guard.with_keep(keep));
        self
    }

    /// Size column for listings: empty directories have no meaningful size.
    pub fn size_label(&self) -> String {
        if self.is_dir && self.size == 0 {
            "Ordner".into()
        } else {
            human(self.size)
        }
    }

    /// Target column for listings.
    pub fn target_label(&self) -> String {
        match &self.kind {
            ActionKind::Quarantine => "Quarantäne".into(),
            ActionKind::MoveTo(t) => format!("nach {}", t.display()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Plan {
    pub root: PathBuf,
    pub actions: Vec<Action>,
}

impl Plan {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            actions: Vec::new(),
        }
    }

    pub fn push(&mut self, action: Action) {
        self.actions.push(action);
    }

    pub fn len(&self) -> usize {
        self.actions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.actions.is_empty()
    }

    pub fn total_bytes(&self) -> u64 {
        self.actions.iter().map(|a| a.size).sum()
    }

    /// Drop repeated sources, keeping the first occurrence.
    pub fn dedup(&mut self) {
        let mut seen = HashSet::new();
        self.actions.retain(|a| seen.insert(a.source.clone()));
    }

    pub fn quarantine_dir(&self) -> PathBuf {
        self.root.join(QUARANTINE_DIR_NAME)
    }

    /// Where a `MoveTo` action aims, before any renaming on name collisions.
    /// `None` for quarantine actions, whose session folder only exists at run time.
    pub fn move_target(&self, action: &Action) -> Option<PathBuf> {
        let ActionKind::MoveTo(dir) = &action.kind else {
            return None;
        };
        let dir = if dir.is_absolute() {
            dir.clone()
        } else {
            self.root.join(dir)
        };
        Some(dir.join(action.source.file_name().unwrap_or_default()))
    }

    fn destination(&self, action: &Action, session: &Path) -> PathBuf {
        if let Some(target) = self.move_target(action) {
            return target;
        }
        let rel = match action.source.strip_prefix(&self.root) {
            Ok(r) => r.to_path_buf(),
            Err(_) => Path::new("_external").join(
                action
                    .source
                    .file_name()
                    .map(PathBuf::from)
                    .unwrap_or_else(|| PathBuf::from("unnamed")),
            ),
        };
        session.join(rel)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JournalEntry {
    pub from: PathBuf,
    pub to: PathBuf,
    pub is_dir: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Journal {
    pub created: String,
    pub root: PathBuf,
    pub session_dir: PathBuf,
    pub entries: Vec<JournalEntry>,
    /// Nothing is left to restore.
    #[serde(default)]
    pub undone: bool,
    /// Entries that were deleted for good from this session.
    #[serde(default)]
    pub purged: usize,
}

fn has_parent_component(p: &Path) -> bool {
    p.components().any(|c| c == Component::ParentDir)
}

fn rebase(p: &Path, old: &Path, new: &Path) -> Option<PathBuf> {
    p.strip_prefix(old).ok().map(|rel| new.join(rel))
}

impl Journal {
    /// Read a journal. Its location on disk decides which session and root it belongs
    /// to: the paths stored inside are data, and a journal outside a quarantine folder
    /// is refused. When the scanned folder was renamed or moved, entries follow it.
    pub fn load(path: &Path) -> anyhow::Result<Journal> {
        let text = fs::read_to_string(path)
            .with_context(|| format!("Journal {} lesen", path.display()))?;
        let mut journal: Journal = serde_json::from_str(&text)
            .with_context(|| format!("Journal {} ist beschädigt", path.display()))?;

        let dir = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let dir = dunce::canonicalize(dir)
            .with_context(|| format!("Sitzungsordner von {} auflösen", path.display()))?;
        let root = dir
            .parent()
            .filter(|q| q.file_name().is_some_and(|n| n == QUARANTINE_DIR_NAME))
            .and_then(Path::parent)
            .with_context(|| {
                format!(
                    "{} liegt nicht in einem Quarantäne-Ordner von tidyscan",
                    path.display()
                )
            })?
            .to_path_buf();

        // Moves of an execution that never reached its final save.
        if let Ok(log) = fs::read_to_string(dir.join(JOURNAL_LOG)) {
            let mut known: HashSet<PathBuf> =
                journal.entries.iter().map(|e| e.to.clone()).collect();
            for line in log.lines() {
                // A crash can cut the last line short; everything before it is intact.
                let Ok(entry) = serde_json::from_str::<JournalEntry>(line) else {
                    break;
                };
                if known.insert(entry.to.clone()) {
                    journal.entries.push(entry);
                }
            }
        }

        if journal.session_dir != dir || journal.root != root {
            let (old_session, old_root) = (journal.session_dir.clone(), journal.root.clone());
            for e in &mut journal.entries {
                if let Some(p) =
                    rebase(&e.to, &old_session, &dir).or_else(|| rebase(&e.to, &old_root, &root))
                {
                    e.to = p;
                }
                if let Some(p) = rebase(&e.from, &old_root, &root) {
                    e.from = p;
                }
            }
            journal.session_dir = dir;
            journal.root = root;
        }
        if journal
            .entries
            .iter()
            .any(|e| has_parent_component(&e.from) || has_parent_component(&e.to))
        {
            bail!(
                "Journal {} enthält Pfade mit \"..\" und wird nicht verwendet",
                path.display()
            );
        }
        Ok(journal)
    }

    /// Write the journal atomically: a crash leaves either the old or the new file.
    fn save(&self, path: &Path) -> anyhow::Result<()> {
        let text = serde_json::to_string_pretty(self)?;
        let tmp = path.with_extension("json.tmp");
        fs::write(&tmp, text)
            .and_then(|()| fs::rename(&tmp, path))
            .with_context(|| format!("Journal {} schreiben", path.display()))?;
        // Everything the log held is part of the file now.
        let _ = fs::remove_file(path.with_file_name(JOURNAL_LOG));
        Ok(())
    }

    fn settle(&mut self) {
        self.undone = self.entries.is_empty();
    }
}

struct JournalLog(fs::File);

impl JournalLog {
    fn create(session: &Path) -> io::Result<Self> {
        fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(session.join(JOURNAL_LOG))
            .map(Self)
    }

    fn append(&mut self, line: &str) -> io::Result<()> {
        self.0.write_all(line.as_bytes())
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExecReport {
    pub journal_path: Option<PathBuf>,
    pub moved: usize,
    pub bytes: u64,
    /// Left alone on purpose: the disk no longer matches what the plan assumed.
    pub skipped: Vec<(PathBuf, String)>,
    /// Attempted and failed.
    pub failed: Vec<(PathBuf, String)>,
}

impl ExecReport {
    /// Human-readable result, listing at most `max_lines` problem entries.
    pub fn summary(&self, max_lines: usize) -> String {
        let mut m = format!(
            "{} Einträge verschoben ({}), {} übersprungen, {} fehlgeschlagen.",
            self.moved,
            human(self.bytes),
            self.skipped.len(),
            self.failed.len()
        );
        let lines = self
            .failed
            .iter()
            .map(|x| ("FEHLER", x))
            .chain(self.skipped.iter().map(|x| ("übersprungen", x)));
        for (label, (p, why)) in lines.take(max_lines) {
            m.push_str(&format!("\n  {label} {}: {why}", p.display()));
        }
        let total = self.failed.len() + self.skipped.len();
        if total > max_lines {
            m.push_str(&format!("\n  … und {} weitere", total - max_lines));
        }
        if let Some(j) = &self.journal_path {
            m.push_str(&format!("\nJournal: {}", j.display()));
        }
        m
    }
}

/// Ensure `dest` does not clobber an existing path by appending ` (n)`: before the
/// extension for files, to the whole name for directories.
fn unique_destination(dest: PathBuf, is_dir: bool) -> PathBuf {
    if fs::symlink_metadata(&dest).is_err() {
        return dest;
    }
    let parent = dest.parent().map(Path::to_path_buf).unwrap_or_default();
    let full = dest
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let (stem, ext) = match (is_dir, dest.file_stem(), dest.extension()) {
        (false, Some(stem), Some(ext)) => (
            stem.to_string_lossy().into_owned(),
            Some(ext.to_string_lossy().into_owned()),
        ),
        _ => (full, None),
    };
    for n in 1u32.. {
        let name = match &ext {
            Some(e) => format!("{stem} ({n}).{e}"),
            None => format!("{stem} ({n})"),
        };
        let candidate = parent.join(name);
        if fs::symlink_metadata(&candidate).is_err() {
            return candidate;
        }
    }
    unreachable!()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Transfer {
    /// One rename; the source is gone.
    Renamed,
    /// Copied across devices; the source still exists and is removed once the
    /// move is on record.
    Copied,
}

fn copy_file_verified(from: &Path, to: &Path) -> io::Result<()> {
    let md = fs::symlink_metadata(from)?;
    let copied = fs::copy(from, to)?;
    if copied != md.len() {
        return Err(io::Error::other(format!(
            "unvollständig kopiert ({copied} von {} Bytes)",
            md.len()
        )));
    }
    // `fs::copy` does not keep the timestamp everywhere; restoring must not change it.
    if let Ok(mtime) = md.modified()
        && let Ok(f) = fs::OpenOptions::new().write(true).open(to)
    {
        let _ = f.set_modified(mtime);
    }
    Ok(())
}

/// Copy a directory into a fresh `to`. Links and special files are an error: silently
/// leaving them out would lose them when the source is removed afterwards.
fn copy_tree(from: &Path, to: &Path) -> io::Result<()> {
    fs::create_dir(to)?;
    for entry in fs::read_dir(from)? {
        let entry = entry?;
        let src = entry.path();
        let dst = to.join(entry.file_name());
        let ft = entry.file_type()?;
        if ft.is_dir() {
            copy_tree(&src, &dst)?;
        } else if ft.is_file() {
            copy_file_verified(&src, &dst)?;
        } else {
            return Err(io::Error::other(format!(
                "{} ist eine Verknüpfung oder Spezialdatei und lässt sich nicht auf ein anderes Laufwerk verschieben",
                src.display()
            )));
        }
    }
    Ok(())
}

/// Bring `from` to the not yet existing `to`: one rename on the same device, a verified
/// copy across devices. A failed copy is removed again, the source is never touched here.
fn transfer(from: &Path, to: &Path, is_dir: bool) -> io::Result<Transfer> {
    if let Some(p) = to.parent() {
        fs::create_dir_all(p)?;
    }
    // `rename` replaces existing files, so an occupied target is an error up front.
    if fs::symlink_metadata(to).is_ok() {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "Ziel existiert bereits",
        ));
    }
    match fs::rename(from, to) {
        Ok(()) => Ok(Transfer::Renamed),
        Err(e) if e.kind() == io::ErrorKind::CrossesDevices => {
            let copied = if is_dir {
                copy_tree(from, to)
            } else {
                copy_file_verified(from, to)
            };
            if let Err(e) = copied {
                let _ = if is_dir {
                    fs::remove_dir_all(to)
                } else {
                    fs::remove_file(to)
                };
                return Err(e);
            }
            Ok(Transfer::Copied)
        }
        Err(e) => Err(e),
    }
}

fn remove_source(from: &Path, is_dir: bool) -> io::Result<()> {
    if is_dir {
        fs::remove_dir_all(from)
    } else {
        fs::remove_file(from)
    }
}

/// Files and bytes below a directory, for quarantine statistics. The journal itself is not counted.
pub fn dir_stats(dir: &Path) -> (u64, u64) {
    let mut files = 0;
    let mut bytes = 0;
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(rd) = fs::read_dir(&d) else { continue };
        for e in rd.flatten() {
            let Ok(md) = e.metadata() else { continue };
            let name = e.file_name();
            if md.is_dir() {
                stack.push(e.path());
            } else if md.is_file() && name != JOURNAL_FILE && name != JOURNAL_LOG {
                files += 1;
                bytes += md.len();
            }
        }
    }
    (files, bytes)
}

fn session_stamp() -> String {
    let now = OffsetDateTime::now_local().unwrap_or_else(|_| OffsetDateTime::now_utc());
    let fmt = format_description!("[year][month][day]-[hour][minute][second]");
    now.format(fmt).unwrap_or_else(|_| "session".into())
}

/// Create a session folder that did not exist before, so two runs within the same
/// second never share (and overwrite) a journal.
fn create_session_dir(root: &Path) -> anyhow::Result<PathBuf> {
    let quarantine = root.join(QUARANTINE_DIR_NAME);
    fs::create_dir_all(&quarantine)
        .with_context(|| format!("Quarantäne-Ordner {} anlegen", quarantine.display()))?;
    let stamp = session_stamp();
    for n in 1..1000 {
        let name = if n == 1 {
            stamp.clone()
        } else {
            format!("{stamp}-{n:02}")
        };
        let dir = quarantine.join(name);
        match fs::create_dir(&dir) {
            Ok(()) => return Ok(dir),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => {
                return Err(e).with_context(|| format!("Sitzungsordner {} anlegen", dir.display()));
            }
        }
    }
    bail!(
        "Kein freier Sitzungsordner unter {} gefunden",
        quarantine.display()
    )
}

/// Everything that must hold before `action` is touched. `Ok` carries the final,
/// collision-free destination, `Err` the reason to leave the source alone.
fn precheck(plan: &Plan, action: &Action, session: &Path) -> Result<PathBuf, String> {
    let quarantine = plan.quarantine_dir();
    let src = &action.source;
    if src.starts_with(&quarantine) {
        return Err("liegt bereits in der Quarantäne".into());
    }
    if quarantine.starts_with(src) {
        return Err("enthält den Quarantäne-Ordner selbst".into());
    }
    let md = fs::symlink_metadata(src).map_err(|e| format!("nicht mehr vorhanden: {e}"))?;
    if md.file_type().is_symlink() {
        return Err("ist inzwischen eine Verknüpfung".into());
    }
    if md.is_dir() != action.is_dir {
        return Err(if action.is_dir {
            "ist kein Ordner mehr".into()
        } else {
            "ist keine Datei mehr".into()
        });
    }
    if let Some(g) = &action.guard {
        g.check(src)?;
    }
    if action.is_dir
        && let Some(q) = nested_quarantine(src)
    {
        return Err(format!(
            "enthält eine eigene Quarantäne ({}), die zuerst geleert oder wiederhergestellt werden sollte",
            q.display()
        ));
    }
    let dest = plan.destination(action, session);
    if matches!(action.kind, ActionKind::MoveTo(_)) {
        if dest.starts_with(&quarantine) {
            return Err("Ziel liegt in der Quarantäne".into());
        }
        if dest == *src || dest.parent() == src.parent() {
            return Err("liegt bereits im Zielordner".into());
        }
        if action.is_dir && dest.starts_with(src) {
            return Err("Ziel liegt im Ordner selbst".into());
        }
    }
    Ok(unique_destination(dest, action.is_dir))
}

/// Execute the plan. With `dry_run` nothing is touched and the report lists what would happen.
pub fn execute(plan: &Plan, dry_run: bool) -> anyhow::Result<ExecReport> {
    execute_with(plan, dry_run, &mut |_| {})
}

/// [`execute`] with a callback that receives the number of actions handled so far.
pub fn execute_with(
    plan: &Plan,
    dry_run: bool,
    on_progress: &mut dyn FnMut(usize),
) -> anyhow::Result<ExecReport> {
    let mut report = ExecReport::default();
    if plan.is_empty() {
        return Ok(report);
    }
    if dry_run {
        report.moved = plan.len();
        report.bytes = plan.total_bytes();
        return Ok(report);
    }
    if !plan.root.is_dir() {
        bail!("{} ist kein Ordner", plan.root.display());
    }

    let session = create_session_dir(&plan.root)?;
    let journal_path = session.join(JOURNAL_FILE);
    let mut journal = Journal {
        created: OffsetDateTime::now_utc().to_string(),
        root: plan.root.clone(),
        session_dir: session.clone(),
        entries: Vec::new(),
        undone: false,
        purged: 0,
    };
    journal.save(&journal_path)?;
    let mut log = JournalLog::create(&session).context("Journal-Log anlegen")?;

    // Directories last, deepest first, so that files inside them are gone before
    // we try to move the (then empty) directory.
    let mut order: Vec<&Action> = plan.actions.iter().collect();
    order.sort_by_key(|a| (a.is_dir, std::cmp::Reverse(a.source.components().count())));

    for (done, action) in order.into_iter().enumerate() {
        on_progress(done);
        let dest = match precheck(plan, action, &session) {
            Ok(d) => d,
            Err(why) => {
                report.skipped.push((action.source.clone(), why));
                continue;
            }
        };
        let entry = JournalEntry {
            from: action.source.clone(),
            to: dest.clone(),
            is_dir: action.is_dir,
        };
        // A move that cannot be written down could never be undone, so check first.
        let Ok(mut line) = serde_json::to_string(&entry) else {
            report.skipped.push((
                action.source.clone(),
                "Pfad lässt sich nicht im Journal festhalten (kein gültiges Unicode)".into(),
            ));
            continue;
        };
        line.push('\n');

        let how = match transfer(&action.source, &dest, action.is_dir) {
            Ok(how) => how,
            Err(e) => {
                report.failed.push((action.source.clone(), e.to_string()));
                continue;
            }
        };
        if let Err(e) = log.append(&line) {
            // Take the unrecorded move back and stop: the journal is the safety net.
            let _ = match how {
                Transfer::Renamed => fs::rename(&dest, &action.source),
                Transfer::Copied => remove_source(&dest, action.is_dir),
            };
            drop(log);
            let _ = journal.save(&journal_path);
            return Err(e).context("Journal schreiben fehlgeschlagen, Lauf abgebrochen");
        }
        journal.entries.push(entry);
        if how == Transfer::Copied
            && let Err(e) = remove_source(&action.source, action.is_dir)
        {
            report.failed.push((
                action.source.clone(),
                format!("kopiert, aber das Original ließ sich nicht entfernen: {e}"),
            ));
            continue;
        }
        report.moved += 1;
        report.bytes += action.size;
    }
    on_progress(plan.len());
    drop(log);

    if journal.entries.is_empty() {
        // Nothing happened: do not leave an empty session behind.
        let _ = fs::remove_file(&journal_path);
        let _ = fs::remove_file(session.join(JOURNAL_LOG));
        prune_empty_dirs(&session);
        let _ = fs::remove_dir(&session);
        let _ = fs::remove_dir(plan.quarantine_dir());
        return Ok(report);
    }
    if let Err(e) = journal.save(&journal_path) {
        // The log still holds every move and is folded in on the next load.
        report.failed.push((journal_path.clone(), format!("{e:#}")));
    }
    report.journal_path = Some(journal_path);
    Ok(report)
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UndoReport {
    pub restored: usize,
    pub conflicts: Vec<(PathBuf, String)>,
}

/// Reverse every move recorded in the journal. Entries whose original path is
/// occupied again are skipped and reported, never overwritten.
pub fn undo(journal_path: &Path) -> anyhow::Result<UndoReport> {
    undo_with(journal_path, &mut |_, _| {})
}

/// [`undo`] with a callback receiving (entries handled, entries in total).
pub fn undo_with(
    journal_path: &Path,
    on_progress: &mut dyn FnMut(usize, usize),
) -> anyhow::Result<UndoReport> {
    let mut journal = Journal::load(journal_path)?;
    if journal.entries.is_empty() {
        bail!("Dieses Journal enthält nichts mehr zum Wiederherstellen.");
    }
    let mut report = UndoReport::default();
    let total = journal.entries.len();
    // Newest first. `kept` collects the entries that could not be restored.
    let mut kept: Vec<JournalEntry> = Vec::new();
    let mut last_save = Instant::now();

    while let Some(entry) = journal.entries.pop() {
        match restore_entry(&entry) {
            Ok(()) => {
                report.restored += 1;
                remove_empty_parents(&entry.to, &journal.root);
            }
            Err(why) => {
                report.conflicts.push((entry.from.clone(), why));
                kept.push(entry);
            }
        }
        on_progress(total - journal.entries.len(), total);
        // Keep the file close to reality so an interruption does not leave entries
        // behind that were restored long ago.
        if last_save.elapsed() >= Duration::from_secs(1) {
            let mut snapshot = journal.clone();
            snapshot.entries.extend(kept.iter().rev().cloned());
            snapshot.save(journal_path)?;
            last_save = Instant::now();
        }
    }
    kept.reverse();
    journal.entries = kept;
    journal.settle();
    journal.save(journal_path)?;

    if journal.undone {
        // Leave only the journal behind; prune empty directories of the session.
        prune_empty_dirs(&journal.session_dir);
    }
    Ok(report)
}

/// Remove now-empty directories that a move left behind, walking up towards `root`
/// but never removing `root` itself. `remove_dir` fails on non-empty dirs, so this is safe.
fn remove_empty_parents(path: &Path, root: &Path) {
    let mut cur = path.parent();
    while let Some(dir) = cur {
        if dir == root || !dir.starts_with(root) || fs::remove_dir(dir).is_err() {
            break;
        }
        cur = dir.parent();
    }
}

fn prune_empty_dirs(dir: &Path) {
    let Ok(rd) = fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        if e.file_type().is_ok_and(|t| t.is_dir()) {
            let p = e.path();
            prune_empty_dirs(&p);
            let _ = fs::remove_dir(&p); // only succeeds when empty
        }
    }
}

/// Move one journal entry back to its original place. `Err` explains why it stays.
fn restore_entry(entry: &JournalEntry) -> Result<(), String> {
    if fs::symlink_metadata(&entry.from).is_ok() {
        return Err("Originalpfad ist inzwischen wieder belegt".into());
    }
    // A missing copy is not something to paper over with an empty folder or a
    // success message: the data is simply not there any more.
    let md = fs::symlink_metadata(&entry.to)
        .map_err(|_| format!("{} ist nicht mehr vorhanden", entry.to.display()))?;
    match transfer(&entry.to, &entry.from, md.is_dir()) {
        Ok(Transfer::Renamed) => Ok(()),
        Ok(Transfer::Copied) => {
            // The original is back. A copy that will not go away stays in the session.
            let _ = remove_source(&entry.to, md.is_dir());
            Ok(())
        }
        Err(e) => Err(e.to_string()),
    }
}

/// Restore a single entry (by index into `Journal::entries`) and drop it from the journal.
pub fn undo_entry(journal_path: &Path, index: usize) -> anyhow::Result<()> {
    let mut journal = Journal::load(journal_path)?;
    let entry = journal
        .entries
        .get(index)
        .cloned()
        .context("Eintrag existiert nicht mehr im Journal")?;
    if let Err(why) = restore_entry(&entry) {
        bail!("{}: {why}", entry.from.display());
    }
    remove_empty_parents(&entry.to, &journal.root);
    journal.entries.remove(index);
    journal.settle();
    journal.save(journal_path)?;
    Ok(())
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PurgeReport {
    pub removed: usize,
    pub bytes: u64,
}

/// `path` lies strictly inside the session folder, also after resolving links.
fn assert_inside_session(path: &Path, session: &Path) -> anyhow::Result<()> {
    let inside = path.starts_with(session) && path != session && !has_parent_component(path);
    let resolved = path
        .parent()
        .and_then(|p| dunce::canonicalize(p).ok())
        .is_some_and(|p| p.starts_with(session));
    if !inside || !resolved {
        bail!(
            "{} liegt nicht in der Quarantäne, wird nicht gelöscht",
            path.display()
        );
    }
    Ok(())
}

/// Permanently delete a whole quarantine session, including its journal.
/// The folder to delete is the one the journal file lies in, never a path read from it,
/// and [`Journal::load`] only accepts journals inside `<root>/.tidyscan-quarantine/`.
pub fn purge_session(journal_path: &Path) -> anyhow::Result<PurgeReport> {
    let journal = Journal::load(journal_path)?;
    let (removed, bytes) = dir_stats(&journal.session_dir);
    fs::remove_dir_all(&journal.session_dir)
        .with_context(|| format!("{} löschen", journal.session_dir.display()))?;
    // Drop the quarantine folder too once the last session is gone.
    if let Some(q) = journal.session_dir.parent() {
        let _ = fs::remove_dir(q);
    }
    Ok(PurgeReport {
        removed: removed as usize,
        bytes,
    })
}

/// Permanently delete one entry's quarantined copy and drop it from the journal.
pub fn purge_entry(journal_path: &Path, index: usize) -> anyhow::Result<PurgeReport> {
    let mut journal = Journal::load(journal_path)?;
    let entry = journal
        .entries
        .get(index)
        .cloned()
        .context("Eintrag existiert nicht mehr im Journal")?;
    let report = match fs::symlink_metadata(&entry.to) {
        // Already gone: only the journal needs to forget it.
        Err(_) => PurgeReport::default(),
        Ok(md) => {
            assert_inside_session(&entry.to, &journal.session_dir)?;
            if md.is_dir() {
                let (n, b) = dir_stats(&entry.to);
                fs::remove_dir_all(&entry.to)?;
                PurgeReport {
                    removed: n as usize,
                    bytes: b,
                }
            } else {
                fs::remove_file(&entry.to)?;
                PurgeReport {
                    removed: 1,
                    bytes: md.len(),
                }
            }
        }
    };
    remove_empty_parents(&entry.to, &journal.session_dir);
    journal.entries.remove(index);
    journal.purged += 1;
    journal.settle();
    journal.save(journal_path)?;
    Ok(report)
}

/// Overview of one quarantine session for listings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInfo {
    pub journal_path: PathBuf,
    pub session_dir: PathBuf,
    pub name: String,
    pub created: String,
    pub entries: usize,
    pub purged: usize,
    pub undone: bool,
    pub files: u64,
    pub bytes: u64,
}

pub fn session_info(journal_path: &Path) -> Option<SessionInfo> {
    let j = Journal::load(journal_path).ok()?;
    let (files, bytes) = dir_stats(&j.session_dir);
    Some(SessionInfo {
        journal_path: journal_path.to_path_buf(),
        name: j
            .session_dir
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default(),
        session_dir: j.session_dir,
        created: j.created,
        entries: j.entries.len(),
        purged: j.purged,
        undone: j.undone,
        files,
        bytes,
    })
}

/// All journals under `<root>/.tidyscan-quarantine`, newest first.
pub fn list_journals(root: &Path) -> Vec<PathBuf> {
    let q = root.join(QUARANTINE_DIR_NAME);
    let Ok(rd) = fs::read_dir(&q) else {
        return Vec::new();
    };
    let mut v: Vec<PathBuf> = rd
        .flatten()
        .map(|e| e.path().join(JOURNAL_FILE))
        .filter(|p| p.is_file())
        .collect();
    v.sort();
    v.reverse();
    v
}
