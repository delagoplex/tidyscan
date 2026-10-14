//! Risk classification for the automatic quarantine mode.
//!
//! Every candidate is either *safe* (moved without asking), *unsure* (shown with a
//! reason, the user decides or asks for a re-check) or *protected* (never touched).
//! A re-check can additionally *block* a candidate that must not be touched right now.

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use serde::{Deserialize, Serialize};

use crate::actions::{Action, Plan};
use crate::analysis::Category;
use crate::context::DirContext;
use crate::dupes::{DupeGroup, empty_dirs_toplevel, hash_full, zero_byte_files};
use crate::model::{DirId, FileEntry, FileId, ScanResult, age_days};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Risk {
    Safe,
    Unsure,
    Protected,
    /// A re-check found a reason not to touch it now (in use, changed since the scan).
    /// Never part of a plan, whatever the user ticks.
    Blocked,
}

/// Why a candidate is unsure. This, not the wording of the reason, decides what a
/// re-check may conclude.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Doubt {
    /// Changed recently and may still be in use. Settled by an in-use test.
    Recent,
    /// Belongs to a software project. Only the user can tell.
    Project,
    /// A question of intent (portable program or installer?). Only the user can tell.
    Judgement,
    /// Can be confirmed on disk: identical content, an extracted folder, emptiness.
    Verifiable,
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
    /// Set for unsure candidates.
    #[serde(default)]
    pub doubt: Option<Doubt>,
    pub reason: String,
    pub hints: Vec<String>,
    pub file: Option<FileId>,
    pub dir: Option<DirId>,
}

impl Candidate {
    /// A candidate that is moved without asking.
    pub fn safe(action: Action, kind: Kind, reason: impl Into<String>) -> Self {
        Self {
            action,
            kind,
            risk: Risk::Safe,
            doubt: None,
            reason: reason.into(),
            hints: Vec::new(),
            file: None,
            dir: None,
        }
    }

    /// A candidate the user has to decide on.
    pub fn unsure(action: Action, kind: Kind, doubt: Doubt, reason: impl Into<String>) -> Self {
        Self {
            risk: Risk::Unsure,
            doubt: Some(doubt),
            ..Self::safe(action, kind, reason)
        }
    }

    pub fn size(&self) -> u64 {
        self.action.size
    }
}

/// Build a plan from the safe candidates and, on explicit request, the unsure ones.
/// Blocked candidates never make it into a plan.
pub fn plan_from(
    root: &Path,
    safe: &[Candidate],
    unsure: &[Candidate],
    include_unsure: bool,
) -> Plan {
    let mut plan = Plan::new(root);
    let unsure = if include_unsure { unsure } else { &[] };
    for c in safe.iter().chain(unsure) {
        if matches!(c.risk, Risk::Safe | Risk::Unsure) {
            plan.push(c.action.clone());
        }
    }
    plan.dedup();
    plan
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
    fn push(&mut self, c: Candidate) {
        match c.risk {
            Risk::Safe => self.safe.push(c),
            Risk::Unsure | Risk::Blocked => self.unsure.push(c),
            Risk::Protected => self.protected += 1,
        }
    }

    /// Build a plan from the safe candidates (and optionally the unsure ones).
    pub fn to_plan(&self, root: &Path, include_unsure: bool) -> Plan {
        plan_from(root, &self.safe, &self.unsure, include_unsure)
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

/// Extension of an (already lowercased) file name. A name without a dot has none:
/// a file called `download` or `temp` is not a partial download or a temp file.
fn extension_of(lower: &str) -> &str {
    Path::new(lower)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
}

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
    match extension_of(&lower) {
        "tmp" | "temp" => Some((Kind::Junk, opts.junk_min_age_days)),
        "dmp" => Some((Kind::Junk, 30)),
        "crdownload" | "part" | "partial" | "download" | "!ut" => {
            Some((Kind::PartialDownload, opts.partial_min_age_days))
        }
        _ => None,
    }
}

/// How sure we are about one candidate while it is being assessed.
enum Verdict {
    Safe(String),
    Unsure(Doubt, String),
}

fn safe(reason: impl Into<String>) -> Verdict {
    Verdict::Safe(reason.into())
}

fn unsure(doubt: Doubt, reason: impl Into<String>) -> Verdict {
    Verdict::Unsure(doubt, reason.into())
}

fn candidate(action: Action, kind: Kind, verdict: Verdict) -> Candidate {
    match verdict {
        Verdict::Safe(reason) => Candidate::safe(action, kind, reason),
        Verdict::Unsure(doubt, reason) => Candidate::unsure(action, kind, doubt, reason),
    }
}

fn file_candidate(result: &ScanResult, id: FileId, kind: Kind, verdict: Verdict) -> Candidate {
    let action = Action::quarantine_file(&result.files[id], kind.label());
    let mut c = candidate(action, kind, verdict);
    c.file = Some(id);
    c
}

fn dir_candidate(result: &ScanResult, id: DirId, kind: Kind, verdict: Verdict) -> Candidate {
    let action = Action::quarantine_empty_dir(result.dirs[id].path.clone(), kind.label());
    let mut c = candidate(action, kind, verdict);
    c.dir = Some(id);
    c
}

fn project_hint(result: &ScanResult, ctx: &DirContext, dir: DirId) -> String {
    match ctx.project_root_of(result, dir) {
        Some(p) => format!(
            "liegt im Projekt {}",
            result.relative(&result.dirs[p].path).display()
        ),
        None => match &ctx.enclosing_project {
            Some(p) => format!("liegt im Projekt {}", p.display()),
            None => "liegt in einem Projektordner".into(),
        },
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
    if result.cancelled {
        t.notes.push(
            "Der Scan wurde abgebrochen. Aus einem unvollständigen Ergebnis wird kein Vorschlag abgeleitet."
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
            let verdict = if ctx.project[parent] {
                unsure(Doubt::Project, project_hint(result, ctx, parent))
            } else if age.is_some_and(|a| a >= min_age) {
                safe(kind_reason(&kind))
            } else if kind == Kind::OfficeLock {
                unsure(
                    Doubt::Recent,
                    "jünger als ein Tag, die Datei ist vielleicht gerade geöffnet",
                )
            } else {
                unsure(Doubt::Recent, format!("jünger als {min_age} Tage"))
            };
            taken.insert(id);
            t.push(file_candidate(result, id, kind, verdict));
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
                // Only a file lying loose in Downloads is clearly a leftover installer.
                // One level down it may be part of an unpacked program.
                let verdict = if ctx.downloads_root[parent] {
                    safe(format!(
                        "Installer in Downloads, seit {a} Tagen unverändert"
                    ))
                } else if ctx.downloads[parent] {
                    unsure(
                        Doubt::Judgement,
                        "liegt in einem Unterordner von Downloads und könnte zu einem entpackten Programm gehören",
                    )
                } else {
                    unsure(
                        Doubt::Judgement,
                        "liegt außerhalb von Downloads und könnte eine portable Anwendung sein",
                    )
                };
                taken.insert(id);
                t.push(file_candidate(result, id, Kind::OldInstaller, verdict));
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
                        safe(format!(
                            "bereits entpackt nach {} ({} Dateien)",
                            result.relative(&result.dirs[d].path).display(),
                            result.dirs[d].total_files
                        )),
                    );
                    c.dir = Some(d);
                    taken.insert(id);
                    t.push(c);
                } else if let Some(a) = age.filter(|&a| a >= opts.archive_unsure_age_days) {
                    taken.insert(id);
                    t.push(file_candidate(
                        result,
                        id,
                        Kind::OldArchive,
                        unsure(
                            Doubt::Verifiable,
                            format!("seit {a} Tagen in Downloads, kein entpackter Ordner gefunden"),
                        ),
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
            || ZERO_BYTE_KEEP_EXT.contains(&extension_of(&lower));
        let verdict = if ctx.project[f.parent] {
            unsure(Doubt::Project, project_hint(result, ctx, f.parent))
        } else if keep_name || name.starts_with('.') {
            unsure(
                Doubt::Judgement,
                "Platzhalter- oder Sperrdatei, die Programme absichtlich leer anlegen",
            )
        } else if f
            .age_days(now)
            .is_some_and(|a| a >= opts.zero_byte_min_age_days)
        {
            safe("leere Datei, seit über einer Woche unverändert")
        } else {
            unsure(
                Doubt::Recent,
                format!(
                    "jünger als {} Tage, wird vielleicht noch geschrieben",
                    opts.zero_byte_min_age_days
                ),
            )
        };
        taken.insert(id);
        t.push(file_candidate(result, id, Kind::ZeroByte, verdict));
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
            let in_project = members
                .iter()
                .copied()
                .find(|&id| ctx.project[result.files[id].parent]);
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
                let verdict = if let Some(p) = in_project {
                    let d = result.files[p].parent;
                    unsure(
                        Doubt::Project,
                        format!("eine Kopie {}", project_hint(result, ctx, d)),
                    )
                } else if recent {
                    unsure(
                        Doubt::Verifiable,
                        "eine Kopie wurde innerhalb des letzten Tages geändert",
                    )
                } else {
                    safe(format!("identisch mit {keep_rel}, die bleibt erhalten"))
                };
                let kind = Kind::Duplicate {
                    keep: keep_path.clone(),
                };
                let mut c = file_candidate(result, id, kind, verdict);
                // The plan only runs while the kept copy is still what the scan saw.
                c.action = c.action.keeping(&result.files[keep]);
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
            let verdict = if ctx.project[d] {
                unsure(Doubt::Project, project_hint(result, ctx, d))
            } else if node.name().starts_with('.') {
                unsure(
                    Doubt::Judgement,
                    "versteckter Ordner, oft von Programmen angelegt",
                )
            } else {
                match dir_age_days(&node.path, now) {
                    Some(a) if a >= opts.empty_dir_min_age_days => {
                        safe(format!("leer, seit {a} Tagen unverändert"))
                    }
                    Some(a) => unsure(
                        Doubt::Verifiable,
                        format!("erst vor {a} Tagen angelegt oder geändert"),
                    ),
                    None => unsure(Doubt::Verifiable, "Ordnerdatum nicht lesbar"),
                }
            };
            t.push(dir_candidate(result, d, Kind::EmptyDir, verdict));
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

/// Re-examine an unsure candidate with checks that cost I/O. Updates `risk` and `hints`.
///
/// What a re-check may conclude depends on why the candidate is unsure: "recently
/// changed" is settled by an in-use test, "can be verified" by looking at the disk.
/// Questions of intent and project membership stay with the user, whatever the disk says.
pub fn recheck(c: &mut Candidate) -> Recheck {
    let outcome = recheck_inner(c);
    let msg = match &outcome {
        Recheck::Promoted(msg) => {
            c.risk = Risk::Safe;
            c.doubt = None;
            msg
        }
        Recheck::StillUnsure(msg) => {
            c.risk = Risk::Unsure;
            msg
        }
        Recheck::Blocked(msg) => {
            c.risk = Risk::Blocked;
            msg
        }
    };
    c.hints.push(format!("Nachgeprüft: {msg}"));
    outcome
}

fn recheck_inner(c: &Candidate) -> Recheck {
    let src = &c.action.source;
    if let Some(g) = &c.action.guard
        && let Err(e) = g.check(src)
    {
        return Recheck::Blocked(e);
    }
    let used = if c.action.is_dir { None } else { in_use(src) };
    if used == Some(true) {
        return Recheck::Blocked("Datei ist gerade von einem Programm geöffnet".into());
    }

    match c.doubt {
        // Nothing was in doubt, and the checks above found nothing either.
        None => Recheck::Promoted("unverändert und nicht in Benutzung".into()),
        Some(Doubt::Project) => Recheck::StillUnsure(
            "gehört zu einem Projekt und könnte versioniert oder von Werkzeugen erwartet sein. Bitte selbst entscheiden.".into(),
        ),
        Some(Doubt::Judgement) => Recheck::StillUnsure(match c.kind {
            Kind::OldInstaller => "ob eine ausführbare Datei ein Installer oder ein portables Programm ist, lässt sich nicht automatisch entscheiden".into(),
            Kind::Distribute => "ob die Dateien dieses Ordners zusammengehören, lässt sich nicht automatisch entscheiden".into(),
            _ => "das lässt sich nicht automatisch entscheiden".into(),
        }),
        Some(Doubt::Recent) => match used {
            Some(false) => Recheck::Promoted(
                "seit dem Scan unverändert und von keinem Programm geöffnet".into(),
            ),
            _ => Recheck::StillUnsure(
                "ob die Datei gerade benutzt wird, lässt sich auf diesem System nicht prüfen".into(),
            ),
        },
        Some(Doubt::Verifiable) => verify(c),
    }
}

/// Settle a [`Doubt::Verifiable`] candidate by looking at the disk.
fn verify(c: &Candidate) -> Recheck {
    let src = &c.action.source;
    match &c.kind {
        Kind::Duplicate { keep } => match (hash_full(src), hash_full(keep)) {
            (Ok(a), Ok(b)) if a == b => Recheck::Promoted(
                "Inhalt erneut verglichen, byte-identisch mit der erhaltenen Kopie".into(),
            ),
            (Ok(_), Ok(_)) => Recheck::Blocked(
                "Inhalt unterscheidet sich inzwischen von der erhaltenen Kopie".into(),
            ),
            _ => Recheck::Blocked("eine der beiden Dateien ist nicht mehr lesbar".into()),
        },
        Kind::ExtractedArchive | Kind::OldArchive => {
            let name = src.file_name().unwrap_or_default().to_string_lossy();
            match src.parent().map(|p| p.join(archive_stem(&name))) {
                Some(dir) if dir.is_dir() => {
                    let n = fs::read_dir(&dir).map(|rd| rd.count()).unwrap_or(0);
                    if n > 0 {
                        Recheck::Promoted(format!(
                            "entpackter Ordner {} vorhanden ({n} Einträge)",
                            dir.display()
                        ))
                    } else {
                        Recheck::StillUnsure(
                            "ein gleichnamiger Ordner existiert, ist aber leer".into(),
                        )
                    }
                }
                _ => Recheck::StillUnsure(
                    "kein entpackter Ordner gefunden, der Inhalt wäre nur über das Archiv erreichbar"
                        .into(),
                ),
            }
        }
        // The guard has just confirmed that there is no file below it.
        Kind::EmptyDir | Kind::LeftoverDir => {
            Recheck::Promoted("auf der Platte weiterhin leer".into())
        }
        _ => Recheck::StillUnsure("dafür gibt es keine automatische Prüfung".into()),
    }
}
