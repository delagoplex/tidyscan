//! Cleanup plans, their execution into a quarantine folder, and undo.
//!
//! Nothing here ever deletes user data. Files and empty directories are *moved*
//! into `<root>/.tidyscan-quarantine/<timestamp>/` (or to a user-chosen target),
//! and every move is journaled so it can be reversed.

use std::collections::HashSet;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::macros::format_description;

use crate::scan::QUARANTINE_DIR_NAME;

pub const JOURNAL_FILE: &str = "undo.json";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ActionKind {
    /// Move into the quarantine folder, preserving the path relative to the root.
    Quarantine,
    /// Move to an explicit directory (absolute, or relative to the root).
    MoveTo(PathBuf),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Action {
    pub source: PathBuf,
    pub is_dir: bool,
    pub size: u64,
    pub kind: ActionKind,
    pub reason: String,
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

    /// Where each action would end up, without touching the disk.
    pub fn preview(&self) -> Vec<(PathBuf, PathBuf)> {
        let session = self.quarantine_session_dir();
        self.actions
            .iter()
            .map(|a| (a.source.clone(), self.destination(a, &session)))
            .collect()
    }

    fn quarantine_session_dir(&self) -> PathBuf {
        let now = OffsetDateTime::now_local().unwrap_or_else(|_| OffsetDateTime::now_utc());
        let fmt = format_description!("[year][month][day]-[hour][minute][second]");
        let stamp = now.format(fmt).unwrap_or_else(|_| "session".into());
        self.root.join(QUARANTINE_DIR_NAME).join(stamp)
    }

    fn destination(&self, action: &Action, session: &Path) -> PathBuf {
        match &action.kind {
            ActionKind::Quarantine => {
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
            ActionKind::MoveTo(dir) => {
                let dir = if dir.is_absolute() {
                    dir.clone()
                } else {
                    self.root.join(dir)
                };
                dir.join(action.source.file_name().unwrap_or_default())
            }
        }
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
    #[serde(default)]
    pub undone: bool,
}

impl Journal {
    pub fn load(path: &Path) -> anyhow::Result<Journal> {
        let text = fs::read_to_string(path)
            .with_context(|| format!("Journal {} lesen", path.display()))?;
        Ok(serde_json::from_str(&text)?)
    }

    fn save(&self, path: &Path) -> anyhow::Result<()> {
        let text = serde_json::to_string_pretty(self)?;
        fs::write(path, text).with_context(|| format!("Journal {} schreiben", path.display()))
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExecReport {
    pub journal_path: Option<PathBuf>,
    pub moved: usize,
    pub bytes: u64,
    pub failed: Vec<(PathBuf, String)>,
}

/// Ensure `dest` does not clobber an existing path by appending ` (n)` to the stem.
fn unique_destination(dest: PathBuf) -> PathBuf {
    if !dest.exists() {
        return dest;
    }
    let stem = dest
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let ext = dest.extension().map(|e| e.to_string_lossy().into_owned());
    let parent = dest.parent().map(Path::to_path_buf).unwrap_or_default();
    for n in 1.. {
        let name = match &ext {
            Some(e) => format!("{stem} ({n}).{e}"),
            None => format!("{stem} ({n})"),
        };
        let candidate = parent.join(name);
        if !candidate.exists() {
            return candidate;
        }
    }
    unreachable!()
}

/// Move a file, falling back to copy + remove across devices.
fn move_file(from: &Path, to: &Path) -> io::Result<()> {
    if let Some(p) = to.parent() {
        fs::create_dir_all(p)?;
    }
    match fs::rename(from, to) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::CrossesDevices || e.raw_os_error() == Some(17) => {
            fs::copy(from, to)?;
            fs::remove_file(from)
        }
        Err(e) => Err(e),
    }
}

/// "Move" an empty directory: create the destination, remove the (empty) source.
fn move_empty_dir(from: &Path, to: &Path) -> io::Result<()> {
    fs::create_dir_all(to)?;
    fs::remove_dir(from)
}

/// Execute the plan. With `dry_run` nothing is touched and the report lists what would happen.
pub fn execute(plan: &Plan, dry_run: bool) -> anyhow::Result<ExecReport> {
    let mut report = ExecReport::default();
    if plan.is_empty() {
        return Ok(report);
    }
    let session = plan.quarantine_session_dir();
    if dry_run {
        report.moved = plan.len();
        report.bytes = plan.total_bytes();
        return Ok(report);
    }

    fs::create_dir_all(&session)
        .with_context(|| format!("Quarantäne-Ordner {} anlegen", session.display()))?;
    let journal_path = session.join(JOURNAL_FILE);
    let mut journal = Journal {
        created: OffsetDateTime::now_utc().to_string(),
        root: plan.root.clone(),
        session_dir: session.clone(),
        entries: Vec::new(),
        undone: false,
    };
    journal.save(&journal_path)?;

    // Directories last, deepest first, so that files inside them are gone before
    // we try to remove the (then empty) directory.
    let mut order: Vec<&Action> = plan.actions.iter().collect();
    order.sort_by_key(|a| (a.is_dir, std::cmp::Reverse(a.source.components().count())));

    for action in order {
        if action
            .source
            .starts_with(plan.root.join(QUARANTINE_DIR_NAME))
        {
            report.failed.push((
                action.source.clone(),
                "liegt bereits in der Quarantäne".into(),
            ));
            continue;
        }
        let dest = unique_destination(plan.destination(action, &session));
        let res = if action.is_dir {
            move_empty_dir(&action.source, &dest)
        } else {
            move_file(&action.source, &dest)
        };
        match res {
            Ok(()) => {
                journal.entries.push(JournalEntry {
                    from: action.source.clone(),
                    to: dest,
                    is_dir: action.is_dir,
                });
                report.moved += 1;
                report.bytes += action.size;
                // Persist after every move so a crash never loses track of a file.
                journal.save(&journal_path)?;
            }
            Err(e) => report.failed.push((action.source.clone(), e.to_string())),
        }
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
    let mut journal = Journal::load(journal_path)?;
    if journal.undone {
        bail!("Dieses Journal wurde bereits rückgängig gemacht.");
    }
    let mut report = UndoReport::default();
    let mut remaining = Vec::new();

    for entry in journal.entries.iter().rev() {
        if entry.from.exists() {
            report.conflicts.push((
                entry.from.clone(),
                "Originalpfad ist inzwischen wieder belegt".into(),
            ));
            remaining.push(entry.clone());
            continue;
        }
        let res = if entry.is_dir {
            fs::create_dir_all(&entry.from).and_then(|_| {
                if entry.to.exists() {
                    fs::remove_dir(&entry.to)
                } else {
                    Ok(())
                }
            })
        } else {
            move_file(&entry.to, &entry.from)
        };
        match res {
            Ok(()) => {
                report.restored += 1;
                remove_empty_parents(&entry.to, &journal.root);
            }
            Err(e) => {
                report.conflicts.push((entry.to.clone(), e.to_string()));
                remaining.push(entry.clone());
            }
        }
    }
    remaining.reverse();
    journal.entries = remaining;
    journal.undone = journal.entries.is_empty();
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
        let p = e.path();
        if p.is_dir() {
            prune_empty_dirs(&p);
            let _ = fs::remove_dir(&p); // only succeeds when empty
        }
    }
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
