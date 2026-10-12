//! Risk classification for the automatic quarantine mode.
//!
//! Every candidate is either *safe* (moved without asking), *unsure* (shown with a
//! reason, the user decides or asks for a re-check) or *protected* (never touched).

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use serde::{Deserialize, Serialize};

use crate::actions::{Action, ActionKind, Guard, Plan};
use crate::analysis::Category;
use crate::context::DirContext;
use crate::dupes::{DupeGroup, empty_dirs_toplevel, zero_byte_files};
use crate::model::{DirId, FileEntry, FileId, ScanResult, age_days};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Risk {
    Safe,
    Unsure,
    Protected,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Kind {
    Junk,
    OfficeLock,
    PartialDownload,
    ZeroByte,
    Duplicate {
        keep: PathBuf,
    },
    EmptyDir,
    OldInstaller,
    ExtractedArchive,
    OldArchive,
    /// Sorting: a loose file moves into its category folder.
    Sort {
        category: Category,
    },
    /// Sorting: a coherent folder moves as a whole under its category folder.
    MoveFolder {
        category: Category,
    },
    /// Sorting: a mixed folder whose files would be distributed by category.
    Distribute,
    /// Sorting: the now-empty source folder of a moved folder.
    LeftoverDir,
}

impl Kind {
    pub fn label(&self) -> &'static str {
        match self {
            Kind::Junk => "Müll- und Temporärdateien",
            Kind::OfficeLock => "Office-Sperrdateien",
            Kind::PartialDownload => "Abgebrochene Downloads",
            Kind::ZeroByte => "0-Byte-Dateien",
            Kind::Duplicate { .. } => "Duplikate",
            Kind::EmptyDir => "Leere Ordner",
            Kind::OldInstaller => "Alte Installer",
            Kind::ExtractedArchive => "Bereits entpackte Archive",
            Kind::OldArchive => "Alte Archive",
            Kind::Sort { .. } => "Lose Dateien einsortieren",
            Kind::MoveFolder { .. } => "Ordner als Ganzes einsortieren",
            Kind::Distribute => "Gemischte Ordner verteilen",
            Kind::LeftoverDir => "Leere Quellordner",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Candidate {
    pub action: Action,
    pub kind: Kind,
    pub risk: Risk,
    pub reason: String,
    pub hints: Vec<String>,
    pub file: Option<FileId>,
    pub dir: Option<DirId>,
}

impl Candidate {
    pub fn size(&self) -> u64 {
        self.action.size
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Triage {
    pub safe: Vec<Candidate>,
    pub unsure: Vec<Candidate>,
    /// Candidates dropped because they live in protected areas.
    pub protected: usize,
    pub notes: Vec<String>,
}

impl Triage {
    pub fn safe_bytes(&self) -> u64 {
        self.safe.iter().map(Candidate::size).sum()
    }

    pub fn unsure_bytes(&self) -> u64 {
        self.unsure.iter().map(Candidate::size).sum()
    }

    fn push(&mut self, c: Candidate) {
        match c.risk {
            Risk::Safe => self.safe.push(c),
            Risk::Unsure => self.unsure.push(c),
            Risk::Protected => self.protected += 1,
        }
    }

    /// Build a plan from the safe candidates (and optionally the unsure ones).
    pub fn to_plan(&self, root: &Path, include_unsure: bool) -> Plan {
        let mut plan = Plan::new(root);
        for c in &self.safe {
            plan.push(c.action.clone());
        }
        if include_unsure {
            for c in &self.unsure {
                plan.push(c.action.clone());
            }
        }
        plan.dedup();
        plan
    }

    /// Candidates grouped by kind label, in a stable order: (label, count, bytes).
    pub fn summary(list: &[Candidate]) -> Vec<(&'static str, usize, u64)> {
        let mut out: Vec<(&'static str, usize, u64)> = Vec::new();
        for c in list {
            let l = c.kind.label();
            match out.iter_mut().find(|(k, _, _)| *k == l) {
                Some(e) => {
                    e.1 += 1;
                    e.2 += c.size();
                }
                None => out.push((l, 1, c.size())),
            }
        }
        out
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriageOptions {
    pub junk_min_age_days: u64,
    pub lock_min_age_days: u64,
    pub partial_min_age_days: u64,
    pub zero_byte_min_age_days: u64,
    pub installer_min_age_days: u64,
    pub archive_unsure_age_days: u64,
    pub empty_dir_min_age_days: u64,
    pub dupe_recent_days: u64,
    /// Duplicates smaller than this are ignored: tiny identical files are usually harmless.
    pub dupes_min_size: u64,
    pub include_duplicates: bool,
    pub include_empty_dirs: bool,
    pub include_installers: bool,
}

impl Default for TriageOptions {
    fn default() -> Self {
        Self {
            junk_min_age_days: 7,
            lock_min_age_days: 1,
            partial_min_age_days: 7,
            zero_byte_min_age_days: 7,
            installer_min_age_days: 90,
            archive_unsure_age_days: 365,
            empty_dir_min_age_days: 7,
            dupe_recent_days: 1,
            dupes_min_size: 1024,
            include_duplicates: true,
            include_empty_dirs: true,
            include_installers: true,
        }
    }
}

const JUNK_NAMES: &[&str] = &["thumbs.db", "ehthumbs.db", ".ds_store", ".localized"];
const ZERO_BYTE_KEEP: &[&str] = &[".gitkeep", ".keep", "__init__.py", ".nomedia"];
const ZERO_BYTE_KEEP_EXT: &[&str] = &["lock", "pid"];

/// True for names the sorter must ignore (temp files, locks, partial downloads).
pub fn is_junk_name(name: &str) -> bool {
    junk_kind(name, &TriageOptions::default()).is_some()
}

/// Junk classification by name alone: (kind, minimum age in days).
fn junk_kind(name: &str, opts: &TriageOptions) -> Option<(Kind, u64)> {
    let lower = name.to_lowercase();
    if JUNK_NAMES.contains(&lower.as_str()) || lower.starts_with("._") {
        return Some((Kind::Junk, 0));
    }
    if lower.starts_with("~$") || (lower.starts_with(".~lock.") && lower.ends_with('#')) {
        return Some((Kind::OfficeLock, opts.lock_min_age_days));
    }
    let ext = lower.rsplit('.').next().unwrap_or("");
    match ext {
        "tmp" | "temp" => Some((Kind::Junk, opts.junk_min_age_days)),
        "dmp" => Some((Kind::Junk, 30)),
        "crdownload" | "part" | "partial" | "download" | "!ut" => {
            Some((Kind::PartialDownload, opts.partial_min_age_days))
        }
        _ => None,
    }
}

fn file_candidate(
    result: &ScanResult,
    id: FileId,
    kind: Kind,
    risk: Risk,
    reason: impl Into<String>,
    keep: Option<PathBuf>,
) -> Candidate {
    let f = &result.files[id];
    let mut guard = Guard::for_file(f);
    guard.keep = keep;
    Candidate {
        action: Action {
            source: f.path.clone(),
            is_dir: false,
            size: f.size,
            kind: ActionKind::Quarantine,
            reason: kind.label().to_string(),
            guard: Some(guard),
        },
        kind,
        risk,
        reason: reason.into(),
        hints: Vec::new(),
        file: Some(id),
        dir: None,
    }
}

fn dir_candidate(
    result: &ScanResult,
    id: DirId,
    kind: Kind,
    risk: Risk,
    reason: impl Into<String>,
) -> Candidate {
    Candidate {
        action: Action {
            source: result.dirs[id].path.clone(),
            is_dir: true,
            size: 0,
            kind: ActionKind::Quarantine,
            reason: kind.label().to_string(),
            guard: None,
        },
        kind,
        risk,
        reason: reason.into(),
        hints: Vec::new(),
        file: None,
        dir: Some(id),
    }
}

fn project_hint(result: &ScanResult, ctx: &DirContext, dir: DirId) -> String {
    match ctx.project_root_of(result, dir) {
        Some(p) => format!(
            "liegt im Projekt {}",
            result.relative(&result.dirs[p].path).display()
        ),
        None => "liegt in einem Projektordner".into(),
    }
}

/// Stem of an archive name, so `foo.tar.gz` and `foo.zip` both map to `foo`.
pub fn archive_stem(name: &str) -> String {
    let lower = name.to_lowercase();
    let mut stem = match lower.rfind('.') {
        Some(i) => lower[..i].to_string(),
        None => lower,
    };
    if let Some(s) = stem.strip_suffix(".tar") {
        stem = s.to_string();
    }
    stem
}

/// A sibling directory that looks like the extracted contents of `file`.
fn extracted_sibling(result: &ScanResult, file: &FileEntry) -> Option<DirId> {
    let stem = archive_stem(&file.name());
    result.dirs[file.parent]
        .children
        .iter()
        .copied()
        .find(|&d| result.dirs[d].name().to_lowercase() == stem && result.dirs[d].total_files > 0)
}

fn dir_age_days(path: &Path, now: SystemTime) -> Option<u64> {
    fs::metadata(path)
        .ok()?
        .modified()
        .ok()
        .and_then(|m| age_days(m, now))
}

pub fn assess(
    result: &ScanResult,
    ctx: &DirContext,
    dupes: Option<&[DupeGroup]>,
    opts: &TriageOptions,
    now: SystemTime,
) -> Triage {
    let mut t = Triage::default();
    if ctx.root_protected {
        t.notes.push(
            "Der gescannte Ordner liegt in einem geschützten Bereich (System, Programme, AppData, Projekt-Tooling). Die Automatik fasst hier nichts an."
                .into(),
        );
        return t;
    }
    let mut taken: HashSet<FileId> = HashSet::new();

    // 1. Junk, locks, partial downloads, installers, archives: one pass over all files.
    for (id, f) in result.files.iter().enumerate() {
        let parent = f.parent;
        let name = f.name();
        let age = f.age_days(now);

        if let Some((kind, min_age)) = junk_kind(&name, opts) {
            if ctx.protected[parent] {
                t.protected += 1;
                continue;
            }
            let c = if ctx.project[parent] {
                let hint = project_hint(result, ctx, parent);
                file_candidate(result, id, kind, Risk::Unsure, hint, None)
            } else if age.is_some_and(|a| a >= min_age) {
                file_candidate(
                    result,
                    id,
                    kind.clone(),
                    Risk::Safe,
                    kind_reason(&kind),
                    None,
                )
            } else {
                let why = match kind {
                    Kind::OfficeLock => {
                        "jünger als ein Tag, die Datei ist vielleicht gerade geöffnet".to_string()
                    }
                    _ => format!("jünger als {min_age} Tage"),
                };
                file_candidate(result, id, kind, Risk::Unsure, why, None)
            };
            taken.insert(id);
            t.push(c);
            continue;
        }

        if !opts.include_installers {
            continue;
        }
        match Category::of_file(f) {
            Category::Installer => {
                let Some(a) = age else { continue };
                if a < opts.installer_min_age_days {
                    continue;
                }
                if ctx.protected[parent] || ctx.project[parent] {
                    continue; // installers inside projects/tools are build artefacts, leave them
                }
                let c = if ctx.downloads[parent] {
                    file_candidate(
                        result,
                        id,
                        Kind::OldInstaller,
                        Risk::Safe,
                        format!("Installer in Downloads, seit {a} Tagen unverändert"),
                        None,
                    )
                } else {
                    file_candidate(
                        result,
                        id,
                        Kind::OldInstaller,
                        Risk::Unsure,
                        "liegt außerhalb von Downloads und könnte eine portable Anwendung sein",
                        None,
                    )
                };
                taken.insert(id);
                t.push(c);
            }
            Category::Archive => {
                if ctx.protected[parent] || ctx.project[parent] || !ctx.downloads[parent] {
                    continue;
                }
                if let Some(d) = extracted_sibling(result, f) {
                    let mut c = file_candidate(
                        result,
                        id,
                        Kind::ExtractedArchive,
                        Risk::Safe,
                        format!(
                            "bereits entpackt nach {} ({} Dateien)",
                            result.relative(&result.dirs[d].path).display(),
                            result.dirs[d].total_files
                        ),
                        None,
                    );
                    c.dir = Some(d);
                    taken.insert(id);
                    t.push(c);
                } else if age.is_some_and(|a| a >= opts.archive_unsure_age_days) {
                    taken.insert(id);
                    t.push(file_candidate(
                        result,
                        id,
                        Kind::OldArchive,
                        Risk::Unsure,
                        format!(
                            "seit {} Tagen in Downloads, kein entpackter Ordner gefunden",
                            age.unwrap_or(0)
                        ),
                        None,
                    ));
                }
            }
            _ => {}
        }
    }

    // 2. Zero-byte files.
    for id in zero_byte_files(result) {
        if taken.contains(&id) {
            continue;
        }
        let f = &result.files[id];
        let name = f.name();
        let lower = name.to_lowercase();
        if ctx.protected[f.parent] {
            t.protected += 1;
            continue;
        }
        let keep_name = ZERO_BYTE_KEEP.contains(&lower.as_str())
            || ZERO_BYTE_KEEP_EXT
                .iter()
                .any(|e| lower.rsplit('.').next() == Some(e));
        let c = if ctx.project[f.parent] {
            file_candidate(
                result,
                id,
                Kind::ZeroByte,
                Risk::Unsure,
                project_hint(result, ctx, f.parent),
                None,
            )
        } else if keep_name || name.starts_with('.') {
            file_candidate(
                result,
                id,
                Kind::ZeroByte,
                Risk::Unsure,
                "Platzhalter- oder Sperrdatei, die Programme absichtlich leer anlegen",
                None,
            )
        } else if f
            .age_days(now)
            .is_some_and(|a| a >= opts.zero_byte_min_age_days)
        {
            file_candidate(
                result,
                id,
                Kind::ZeroByte,
                Risk::Safe,
                "leere Datei, seit über einer Woche unverändert",
                None,
            )
        } else {
            file_candidate(
                result,
                id,
                Kind::ZeroByte,
                Risk::Unsure,
                format!(
                    "jünger als {} Tage, wird vielleicht noch geschrieben",
                    opts.zero_byte_min_age_days
                ),
                None,
            )
        };
        taken.insert(id);
        t.push(c);
    }

    // 3. Duplicates.
    if opts.include_duplicates
        && let Some(groups) = dupes
    {
        for g in groups {
            if g.size < opts.dupes_min_size {
                continue;
            }
            let members: Vec<FileId> = g
                .files
                .iter()
                .copied()
                .filter(|&id| {
                    if ctx.protected[result.files[id].parent] {
                        t.protected += 1;
                        false
                    } else {
                        !taken.contains(&id)
                    }
                })
                .collect();
            if members.len() < 2 {
                continue;
            }
            let in_project: Vec<FileId> = members
                .iter()
                .copied()
                .filter(|&id| ctx.project[result.files[id].parent])
                .collect();
            let recent = members.iter().any(|&id| {
                result.files[id]
                    .age_days(now)
                    .is_none_or(|a| a < opts.dupe_recent_days)
            });

            // Keep: outside Downloads first, then oldest, then shortest path.
            let mut order = members.clone();
            order.sort_by_key(|&id| {
                let f = &result.files[id];
                (
                    ctx.downloads[f.parent],
                    f.modified.unwrap_or(SystemTime::UNIX_EPOCH),
                    f.path.as_os_str().len(),
                )
            });
            let keep = order[0];
            let keep_path = result.files[keep].path.clone();
            let keep_rel = result.relative(&keep_path).display().to_string();

            for &id in order.iter().skip(1) {
                let (risk, reason) = if !in_project.is_empty() {
                    let d = result.files[in_project[0]].parent;
                    (
                        Risk::Unsure,
                        format!("eine Kopie {}", project_hint(result, ctx, d)),
                    )
                } else if recent {
                    (
                        Risk::Unsure,
                        "eine Kopie wurde innerhalb des letzten Tages geändert".to_string(),
                    )
                } else {
                    (
                        Risk::Safe,
                        format!("identisch mit {keep_rel}, die bleibt erhalten"),
                    )
                };
                let mut c = file_candidate(
                    result,
                    id,
                    Kind::Duplicate {
                        keep: keep_path.clone(),
                    },
                    risk,
                    reason,
                    Some(keep_path.clone()),
                );
                c.hints.push(format!("behalten: {keep_rel}"));
                taken.insert(id);
                t.push(c);
            }
        }
    }

    // 4. Empty directories.
    if opts.include_empty_dirs {
        for d in empty_dirs_toplevel(result) {
            let node = &result.dirs[d];
            if ctx.protected[d] {
                t.protected += 1;
                continue;
            }
            let name = node.name();
            let c = if ctx.project[d] {
                dir_candidate(
                    result,
                    d,
                    Kind::EmptyDir,
                    Risk::Unsure,
                    project_hint(result, ctx, d),
                )
            } else if name.starts_with('.') {
                dir_candidate(
                    result,
                    d,
                    Kind::EmptyDir,
                    Risk::Unsure,
                    "versteckter Ordner, oft von Programmen angelegt",
                )
            } else {
                match dir_age_days(&node.path, now) {
                    Some(a) if a >= opts.empty_dir_min_age_days => dir_candidate(
                        result,
                        d,
                        Kind::EmptyDir,
                        Risk::Safe,
                        format!("leer, seit {a} Tagen unverändert"),
                    ),
                    Some(a) => dir_candidate(
                        result,
                        d,
                        Kind::EmptyDir,
                        Risk::Unsure,
                        format!("erst vor {a} Tagen angelegt oder geändert"),
                    ),
                    None => dir_candidate(
                        result,
                        d,
                        Kind::EmptyDir,
                        Risk::Unsure,
                        "Ordnerdatum nicht lesbar",
                    ),
                }
            };
            t.push(c);
        }
    }

    t.safe.sort_by(|a, b| a.action.source.cmp(&b.action.source));
    t.unsure
        .sort_by(|a, b| a.action.source.cmp(&b.action.source));
    t
}

fn kind_reason(kind: &Kind) -> String {
    match kind {
        Kind::Junk => "Temporär- oder Systemdatei, wird bei Bedarf neu erzeugt".into(),
        Kind::OfficeLock => "Sperrdatei einer geschlossenen Office-Datei".into(),
        Kind::PartialDownload => "abgebrochener Download, seit über einer Woche unverändert".into(),
        other => other.label().into(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Recheck {
    /// The candidate is now considered safe.
    Promoted(String),
    /// Still needs a human decision.
    StillUnsure(String),
    /// Must not be touched right now.
    Blocked(String),
}

/// Whether a file is currently opened by another process. `None` when unknown.
#[cfg(windows)]
pub fn in_use(path: &Path) -> Option<bool> {
    use std::os::windows::fs::OpenOptionsExt;
    const ERROR_SHARING_VIOLATION: i32 = 32;
    match fs::OpenOptions::new().read(true).share_mode(0).open(path) {
        Ok(_) => Some(false),
        Err(e) if e.raw_os_error() == Some(ERROR_SHARING_VIOLATION) => Some(true),
        Err(_) => None,
    }
}

#[cfg(not(windows))]
pub fn in_use(_path: &Path) -> Option<bool> {
    None
}

fn hash_file(path: &Path) -> Option<blake3::Hash> {
    use std::io::Read;
    let mut f = fs::File::open(path).ok()?;
    let mut h = blake3::Hasher::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = f.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Some(h.finalize())
}

/// Re-examine an unsure candidate with checks that cost I/O. Updates `risk` and `hints`.
pub fn recheck(c: &mut Candidate, result: &ScanResult, ctx: &DirContext) -> Recheck {
    let outcome = recheck_inner(c, result, ctx);
    match &outcome {
        Recheck::Promoted(msg) => {
            c.risk = Risk::Safe;
            c.hints.push(format!("Nachgeprüft: {msg}"));
        }
        Recheck::StillUnsure(msg) => c.hints.push(format!("Nachgeprüft: {msg}")),
        Recheck::Blocked(msg) => {
            c.risk = Risk::Unsure;
            c.hints.push(format!("Nachgeprüft: {msg}"));
        }
    }
    outcome
}

fn recheck_inner(c: &Candidate, result: &ScanResult, ctx: &DirContext) -> Recheck {
    let src = &c.action.source;
    if !c.action.is_dir {
        if let Some(g) = &c.action.guard
            && let Err(e) = g.check(src)
        {
            return Recheck::Blocked(e);
        }
        if in_use(src) == Some(true) {
            return Recheck::Blocked("Datei ist gerade von einem Programm geöffnet".into());
        }
    }
    let in_project = c
        .file
        .map(|f| ctx.project[result.files[f].parent])
        .or_else(|| c.dir.map(|d| ctx.project[d]))
        .unwrap_or(false);

    match &c.kind {
        Kind::Duplicate { keep } => {
            if in_project {
                return Recheck::StillUnsure(
                    "Inhalt ist identisch, aber eine Kopie gehört zu einem Projekt. Bitte selbst entscheiden.".into(),
                );
            }
            match (hash_file(src), hash_file(keep)) {
                (Some(a), Some(b)) if a == b => {
                    Recheck::Promoted("Inhalt erneut verglichen, byte-identisch mit der erhaltenen Kopie".into())
                }
                (Some(_), Some(_)) => Recheck::Blocked("Inhalt unterscheidet sich inzwischen von der erhaltenen Kopie".into()),
                _ => Recheck::Blocked("eine der beiden Dateien ist nicht mehr lesbar".into()),
            }
        }
        Kind::ExtractedArchive | Kind::OldArchive => {
            let stem = archive_stem(&src.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default());
            let sibling = src.parent().map(|p| p.join(&stem));
            match sibling {
                Some(dir) if dir.is_dir() => {
                    let n = fs::read_dir(&dir).map(|rd| rd.count()).unwrap_or(0);
                    if n > 0 {
                        Recheck::Promoted(format!("entpackter Ordner {} vorhanden ({n} Einträge)", dir.display()))
                    } else {
                        Recheck::StillUnsure("ein gleichnamiger Ordner existiert, ist aber leer".into())
                    }
                }
                _ => Recheck::StillUnsure("kein entpackter Ordner gefunden, Inhalt wäre nur über das Archiv erreichbar".into()),
            }
        }
        Kind::OfficeLock | Kind::PartialDownload => {
            if in_project {
                return Recheck::StillUnsure("gehört zu einem Projekt".into());
            }
            match in_use(src) {
                Some(false) => Recheck::Promoted("von keinem Programm geöffnet".into()),
                Some(true) => Recheck::Blocked("gerade geöffnet".into()),
                None => Recheck::StillUnsure("Benutzungsprüfung auf diesem System nicht verfügbar".into()),
            }
        }
        Kind::Junk | Kind::ZeroByte => {
            if in_project {
                Recheck::StillUnsure("liegt in einem Projekt, könnte versioniert sein".into())
            } else if in_use(src) == Some(false) {
                Recheck::Promoted("von keinem Programm geöffnet".into())
            } else {
                Recheck::StillUnsure("Alter unter dem Schwellwert, kein weiterer Hinweis".into())
            }
        }
        Kind::EmptyDir => {
            if in_project {
                Recheck::StillUnsure("leerer Ordner in einem Projekt, Werkzeuge erwarten ihn vielleicht".into())
            } else if fs::read_dir(src).map(|rd| rd.count()).unwrap_or(1) == 0 {
                Recheck::Promoted("auf der Platte weiterhin leer".into())
            } else {
                Recheck::Blocked("ist inzwischen nicht mehr leer".into())
            }
        }
        Kind::OldInstaller => Recheck::StillUnsure(
            "ob eine .exe ein Installer oder ein portables Programm ist, lässt sich nicht automatisch entscheiden".into(),
        ),
        Kind::Sort { .. } | Kind::MoveFolder { .. } | Kind::Distribute | Kind::LeftoverDir => {
            if in_project {
                Recheck::StillUnsure("gehört zu einem Projekt".into())
            } else {
                match in_use(src) {
                    Some(true) => Recheck::Blocked("gerade geöffnet".into()),
                    _ => Recheck::Promoted("nicht in Benutzung, kann verschoben werden".into()),
                }
            }
        }
    }
}
