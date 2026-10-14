//! Sorting planner: loose files go into category folders, coherent folders move as a
//! whole under their category, mixed folders are flagged for the user.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use serde::{Deserialize, Serialize};

use crate::actions::{Action, ActionKind, Plan};
use crate::analysis::{CATEGORY_COUNT, Category, files_under};
use crate::context::{DirContext, category_folder_name};
use crate::model::{DirId, FileId, ScanResult, local_datetime};
use crate::scan::QUARANTINE_DIR_NAME;
use crate::triage::{Candidate, Kind, Risk, is_junk_name};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrganizeOptions {
    /// Add a year subfolder below the category folder.
    pub by_year: bool,
    /// Files modified more recently than this are flagged instead of moved.
    pub min_age_days: u64,
    /// Share of files and bytes one category needs for a folder to count as coherent.
    pub coherent_share: f32,
    /// Mixed folders with more files than this are not offered for distribution.
    pub max_distribute_files: usize,
}

impl Default for OrganizeOptions {
    fn default() -> Self {
        Self {
            by_year: false,
            min_age_days: 1,
            coherent_share: 0.8,
            max_distribute_files: 20,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum FolderVerdict {
    Keep(String),
    MoveWhole(Category),
    Distribute,
    Unsure(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FolderProfile {
    pub dir: DirId,
    pub files: u64,
    pub bytes: u64,
    pub dominant: Category,
    pub share: f32,
    pub composition: String,
    pub verdict: FolderVerdict,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AfterFile {
    pub name: String,
    pub size: u64,
    /// Source directory relative to the root, when the file is moved here.
    pub from: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AfterFolder {
    /// Path relative to the root; empty string for loose files in the root.
    pub rel: String,
    pub staying_files: u64,
    pub staying_bytes: u64,
    pub incoming: Vec<AfterFile>,
}

impl AfterFolder {
    pub fn files(&self) -> u64 {
        self.staying_files + self.incoming.len() as u64
    }
    pub fn bytes(&self) -> u64 {
        self.staying_bytes + self.incoming.iter().map(|f| f.size).sum::<u64>()
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AfterTree {
    pub folders: Vec<AfterFolder>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OrganizePlan {
    pub safe: Vec<Candidate>,
    pub unsure: Vec<Candidate>,
    pub profiles: Vec<FolderProfile>,
    pub after: AfterTree,
    pub notes: Vec<String>,
}

impl OrganizePlan {
    pub fn safe_bytes(&self) -> u64 {
        self.safe.iter().map(Candidate::size).sum()
    }

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
}

const SHORTCUT_EXT: &[&str] = &["lnk", "url", "desktop", "webloc"];

fn is_shortcut(f: &crate::model::FileEntry) -> bool {
    f.extension()
        .map(|e| SHORTCUT_EXT.contains(&e.as_str()))
        .unwrap_or(false)
}

/// Year subfolder for a file; files without a usable date are collected separately
/// instead of being filed under the current year.
fn year_of(f: &crate::model::FileEntry) -> String {
    f.modified
        .and_then(local_datetime)
        .map_or("Ohne Datum".to_string(), |t| t.year().to_string())
}

/// Names of the top-level target folders per category: an existing folder in the root
/// that already represents the category (e.g. `Documents`, `Pictures`) wins over the
/// default German name.
struct Targets {
    names: [Option<String>; CATEGORY_COUNT],
}

impl Targets {
    fn new(result: &ScanResult, ctx: &DirContext) -> Self {
        let mut names: [Option<String>; CATEGORY_COUNT] = Default::default();
        for c in Category::ALL {
            names[c as usize] = category_folder_name(c).map(String::from);
        }
        if let Some(root) = result.dirs.first() {
            for &d in &root.children {
                if let Some(c) = ctx.category_folder[d]
                    && category_folder_name(c).is_some()
                {
                    names[c as usize] = Some(result.dirs[d].name());
                }
            }
        }
        Self { names }
    }

    /// Target directory (relative to the root) for a file of `category`, or `None`
    /// when the category is never sorted automatically.
    fn dir(
        &self,
        category: Category,
        f: &crate::model::FileEntry,
        opts: &OrganizeOptions,
    ) -> Option<PathBuf> {
        let mut p = PathBuf::from(self.names[category as usize].as_ref()?);
        if opts.by_year {
            p.push(year_of(f));
        }
        Some(p)
    }
}

/// Files the sorter never moves on its own: junk, empty files, shortcuts, dotfiles.
fn ignorable(f: &crate::model::FileEntry) -> bool {
    let name = f.name();
    f.size == 0 || is_junk_name(&name) || is_shortcut(f) || name.starts_with('.')
}

/// Group files of one directory with their companions (same stem, or sidecar like
/// `x.zip.sha256` next to `x.zip`). Each group gets the category of its largest
/// member that has a sortable category.
fn companion_groups(result: &ScanResult, files: &[FileId]) -> Vec<Vec<FileId>> {
    let names: HashMap<String, FileId> = files
        .iter()
        .map(|&id| (result.files[id].name().to_lowercase(), id))
        .collect();
    let mut key_of: HashMap<FileId, String> = HashMap::new();
    for &id in files {
        let name = result.files[id].name().to_lowercase();
        let stem = Path::new(&name)
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| name.clone());
        // Sidecar: "x.zip.sha256" -> stem "x.zip" is itself a sibling file.
        let key = if names.contains_key(&stem) && stem != name {
            Path::new(&stem)
                .file_stem()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or(stem)
        } else {
            stem
        };
        key_of.insert(id, key);
    }
    let mut groups: BTreeMap<String, Vec<FileId>> = BTreeMap::new();
    for &id in files {
        groups.entry(key_of[&id].clone()).or_default().push(id);
    }
    groups.into_values().collect()
}

fn group_category(result: &ScanResult, group: &[FileId]) -> Option<Category> {
    group
        .iter()
        .map(|&id| &result.files[id])
        .filter(|f| category_folder_name(Category::of_file(f)).is_some())
        .max_by_key(|f| f.size)
        .map(Category::of_file)
}

fn move_candidate(
    result: &ScanResult,
    id: FileId,
    target: PathBuf,
    kind: Kind,
    risk: Risk,
    reason: impl Into<String>,
) -> Candidate {
    Candidate {
        action: Action::move_file(&result.files[id], target, kind.label()),
        kind,
        risk,
        reason: reason.into(),
        hints: Vec::new(),
        file: Some(id),
        dir: None,
    }
}

fn leftover_dir_candidate(result: &ScanResult, d: DirId) -> Candidate {
    Candidate {
        action: Action::quarantine_empty_dir(
            result.dirs[d].path.clone(),
            Kind::LeftoverDir.label(),
        ),
        kind: Kind::LeftoverDir,
        risk: Risk::Safe,
        reason: "Quellordner ist nach dem Verschieben leer".into(),
        hints: Vec::new(),
        file: None,
        dir: Some(d),
    }
}

fn composition(result: &ScanResult, files: &[FileId]) -> (Vec<(Category, u64, u64)>, u64, u64) {
    let mut counts = [0u64; CATEGORY_COUNT];
    let mut bytes = [0u64; CATEGORY_COUNT];
    for &id in files {
        let f = &result.files[id];
        let c = Category::of_file(f) as usize;
        counts[c] += 1;
        bytes[c] += f.size;
    }
    let mut v: Vec<(Category, u64, u64)> = Category::ALL
        .iter()
        .map(|c| (*c, counts[*c as usize], bytes[*c as usize]))
        .filter(|(_, n, _)| *n > 0)
        .collect();
    v.sort_by_key(|(_, n, b)| std::cmp::Reverse((*n, *b)));
    (v, counts.iter().sum(), bytes.iter().sum())
}

fn describe(comp: &[(Category, u64, u64)]) -> String {
    comp.iter()
        .map(|(c, n, _)| format!("{n} {}", c.label()))
        .collect::<Vec<_>>()
        .join(", ")
}

fn recent(result: &ScanResult, id: FileId, opts: &OrganizeOptions, now: SystemTime) -> bool {
    result.files[id]
        .age_days(now)
        .is_none_or(|a| a < opts.min_age_days)
}

pub fn plan_organize(
    result: &ScanResult,
    ctx: &DirContext,
    opts: &OrganizeOptions,
    now: SystemTime,
) -> OrganizePlan {
    let mut plan = OrganizePlan::default();
    if result.dirs.is_empty() {
        return plan;
    }
    if ctx.root_protected {
        plan.notes.push("Der gescannte Ordner liegt in einem geschützten Bereich. Sortieren ist hier nicht sinnvoll.".into());
        return plan;
    }
    if ctx.project[0] {
        plan.notes.push(
            "Der gescannte Ordner ist ein Projekt. Projektdateien werden nicht umsortiert.".into(),
        );
        return plan;
    }

    let targets = Targets::new(result, ctx);

    // 1. Loose files directly in the root.
    let root_files: Vec<FileId> = result.dirs[0].files.clone();
    sort_loose_files(result, &root_files, &targets, opts, now, &mut plan, "");

    // 2. Subfolders, top-down. Children are only visited when the parent is left alone.
    let mut stack: Vec<DirId> = result.dirs[0].children.clone();
    stack.sort_by(|a, b| result.dirs[*b].path.cmp(&result.dirs[*a].path));
    while let Some(d) = stack.pop() {
        let node = &result.dirs[d];
        let name = node.name();
        let rel = result
            .relative(&node.path)
            .to_string_lossy()
            .replace('\\', "/");

        let keep = if ctx.protected[d] {
            Some("geschützter Bereich")
        } else if ctx.project[d] {
            Some("Projektordner")
        } else if name == QUARANTINE_DIR_NAME || name.starts_with('.') {
            Some("versteckter Ordner")
        } else if node.total_files == 0 {
            Some("leer")
        } else {
            None
        };
        if let Some(why) = keep {
            plan.profiles.push(FolderProfile {
                dir: d,
                files: node.total_files,
                bytes: node.total_size,
                dominant: Category::Other,
                share: 0.0,
                composition: String::new(),
                verdict: FolderVerdict::Keep(why.into()),
            });
            continue;
        }

        // A downloads folder is a dumping ground: its direct files count as loose,
        // its subfolders are judged on their own.
        if ctx.downloads[d] && ctx.category_folder[d].is_none() && node.parent == Some(0) {
            sort_loose_files(
                result,
                &node.files,
                &targets,
                opts,
                now,
                &mut plan,
                &format!(" (in {rel})"),
            );
            stack.extend(node.children.iter().copied());
            plan.profiles.push(FolderProfile {
                dir: d,
                files: node.total_files,
                bytes: node.total_size,
                dominant: Category::Other,
                share: 0.0,
                composition: String::new(),
                verdict: FolderVerdict::Keep(
                    "Downloads: Dateien werden einzeln einsortiert".into(),
                ),
            });
            continue;
        }

        if let Some(cat) = ctx.category_folder[d] {
            // Existing category folder: it is a destination. Flag files that clearly
            // do not belong, leave everything else (including subfolders) alone.
            for &id in &node.files {
                let f = &result.files[id];
                let fc = Category::of_file(f);
                if fc == cat || category_folder_name(fc).is_none() || ignorable(f) {
                    continue;
                }
                if let Some(t) = targets.dir(fc, f, opts) {
                    plan.unsure.push(move_candidate(
                        result,
                        id,
                        t,
                        Kind::Sort { category: fc },
                        Risk::Unsure,
                        format!(
                            "{} in einem {}-Ordner, passt nicht dazu",
                            fc.label(),
                            cat.label()
                        ),
                    ));
                }
            }
            plan.profiles.push(FolderProfile {
                dir: d,
                files: node.total_files,
                bytes: node.total_size,
                dominant: cat,
                share: 1.0,
                composition: String::new(),
                verdict: FolderVerdict::Keep(format!("Kategorie-Ordner für {}", cat.label())),
            });
            continue;
        }

        let all_raw = files_under(result, d);
        let (junk, all): (Vec<FileId>, Vec<FileId>) = all_raw
            .iter()
            .partition(|&&id| ignorable(&result.files[id]));
        if all.is_empty() {
            plan.profiles.push(FolderProfile {
                dir: d,
                files: node.total_files,
                bytes: node.total_size,
                dominant: Category::Other,
                share: 0.0,
                composition: String::new(),
                verdict: FolderVerdict::Keep("nur Hilfs- oder Leerdateien".into()),
            });
            continue;
        }
        let (comp, n_files, n_bytes) = composition(result, &all);
        let (dominant, dom_files, dom_bytes) = comp[0];
        let share_files = dom_files as f32 / n_files.max(1) as f32;
        let share_bytes = dom_bytes as f32 / n_bytes.max(1) as f32;
        let coherent = share_files >= opts.coherent_share && share_bytes >= opts.coherent_share;
        let mut profile = FolderProfile {
            dir: d,
            files: n_files,
            bytes: n_bytes,
            dominant,
            share: share_files,
            composition: describe(&comp),
            verdict: FolderVerdict::Keep(String::new()),
        };

        if coherent {
            let Some(folder) = targets.names[dominant as usize].clone() else {
                profile.verdict = FolderVerdict::Keep(format!("überwiegend {}", dominant.label()));
                plan.profiles.push(profile);
                continue;
            };
            if ctx.enclosing_category(result, d) == Some(dominant) {
                profile.verdict =
                    FolderVerdict::Keep("liegt bereits im passenden Kategorie-Ordner".into());
                plan.profiles.push(profile);
                continue;
            }
            // Move the folder as a unit: Root/<Kategorie>/<Ordnername>/<Unterstruktur>.
            let base = PathBuf::from(folder).join(&name);
            let has_recent = all.iter().any(|&id| recent(result, id, opts, now));
            let portable = dominant == Category::Installer && !ctx.downloads[d];
            let risk = if has_recent || portable {
                Risk::Unsure
            } else {
                Risk::Safe
            };
            let reason = if portable {
                format!(
                    "{} ({rel}): ausführbare Dateien außerhalb von Downloads könnten ein portables Programm sein",
                    profile.composition
                )
            } else if has_recent {
                format!(
                    "{} ({rel}), enthält innerhalb des letzten Tages geänderte Dateien",
                    profile.composition
                )
            } else {
                format!("zusammenhängender Ordner: {}", profile.composition)
            };
            for &id in &all {
                let f = &result.files[id];
                let inner = f
                    .path
                    .parent()
                    .and_then(|p| p.strip_prefix(&node.path).ok())
                    .unwrap_or(Path::new(""));
                let target = if inner.as_os_str().is_empty() {
                    base.clone()
                } else {
                    base.join(inner)
                };
                let mut c = move_candidate(
                    result,
                    id,
                    target,
                    Kind::MoveFolder { category: dominant },
                    risk,
                    reason.clone(),
                );
                c.dir = Some(d);
                push(&mut plan, c);
            }
            // Junk inside a moved folder goes to quarantine so the source ends up empty.
            if risk == Risk::Safe {
                for &id in &junk {
                    let mut c = move_candidate(
                        result,
                        id,
                        PathBuf::new(),
                        Kind::Junk,
                        Risk::Safe,
                        "Hilfsdatei im verschobenen Ordner",
                    );
                    c.action.kind = ActionKind::Quarantine;
                    c.action.reason = Kind::Junk.label().to_string();
                    c.dir = Some(d);
                    plan.safe.push(c);
                }
            }
            // Source folder and its subfolders are empty afterwards: quarantine them, deepest first.
            if risk == Risk::Safe {
                let mut dirs = vec![d];
                let mut i = 0;
                while i < dirs.len() {
                    dirs.extend(result.dirs[dirs[i]].children.iter().copied());
                    i += 1;
                }
                for &sd in dirs.iter().rev() {
                    plan.safe.push(leftover_dir_candidate(result, sd));
                }
            }
            profile.verdict = FolderVerdict::MoveWhole(dominant);
            plan.profiles.push(profile);
            continue;
        }

        // Mixed folder: offer distribution, but only as an unsure suggestion.
        let too_many = all.len() > opts.max_distribute_files;
        let reason = format!("gemischter Ordner {rel}: {}", profile.composition);
        for group in companion_groups(result, &all) {
            let Some(cat) = group_category(result, &group) else {
                continue;
            };
            for &id in &group {
                let f = &result.files[id];
                let Some(t) = targets.dir(cat, f, opts) else {
                    continue;
                };
                let mut c = move_candidate(
                    result,
                    id,
                    t,
                    Kind::Distribute,
                    Risk::Unsure,
                    reason.clone(),
                );
                c.dir = Some(d);
                if too_many {
                    c.hints.push(format!(
                        "{} Dateien, zu viele für eine automatische Verteilung",
                        all.len()
                    ));
                }
                plan.unsure.push(c);
            }
        }
        profile.verdict = if too_many {
            FolderVerdict::Unsure("gemischt und groß, besser manuell sortieren".into())
        } else {
            FolderVerdict::Distribute
        };
        plan.profiles.push(profile);
    }

    plan.after = after_tree(result, ctx, &plan);
    plan
}

fn push(plan: &mut OrganizePlan, c: Candidate) {
    match c.risk {
        Risk::Safe => plan.safe.push(c),
        _ => plan.unsure.push(c),
    }
}

fn sort_loose_files(
    result: &ScanResult,
    files: &[FileId],
    targets: &Targets,
    opts: &OrganizeOptions,
    now: SystemTime,
    plan: &mut OrganizePlan,
    where_: &str,
) {
    let files: Vec<FileId> = files
        .iter()
        .copied()
        .filter(|&id| !ignorable(&result.files[id]))
        .collect();
    for group in companion_groups(result, &files) {
        let cat = group_category(result, &group);
        for &id in &group {
            let f = &result.files[id];
            let Some(cat) = cat else {
                let own = Category::of_file(f);
                if matches!(own, Category::Code | Category::Other) {
                    // Nothing sensible to do automatically; mention it once per file.
                    let mut c = move_candidate(
                        result,
                        id,
                        PathBuf::from("Sonstiges"),
                        Kind::Sort { category: own },
                        Risk::Unsure,
                        format!(
                            "Kategorie {}: keine automatische Zuordnung{}",
                            own.label(),
                            where_
                        ),
                    );
                    c.hints.push("Ziel 'Sonstiges' nur als Vorschlag".into());
                    plan.unsure.push(c);
                }
                continue;
            };
            let Some(t) = targets.dir(cat, f, opts) else {
                continue;
            };
            let c = if recent(result, id, opts, now) {
                move_candidate(
                    result,
                    id,
                    t,
                    Kind::Sort { category: cat },
                    Risk::Unsure,
                    "innerhalb des letzten Tages geändert, vielleicht noch in Benutzung",
                )
            } else {
                move_candidate(
                    result,
                    id,
                    t,
                    Kind::Sort { category: cat },
                    Risk::Safe,
                    format!("lose Datei, Kategorie {}", cat.label()),
                )
            };
            push(plan, c);
        }
    }
}

/// The resulting top-level structure if the safe actions were executed.
fn after_tree(result: &ScanResult, _ctx: &DirContext, plan: &OrganizePlan) -> AfterTree {
    let root = &result.root;
    let rel_of = |p: &Path| -> String {
        p.strip_prefix(root)
            .map(|r| r.to_string_lossy().replace('\\', "/"))
            .unwrap_or_else(|_| p.to_string_lossy().into_owned())
    };
    let moved: HashMap<&Path, &Candidate> = plan
        .safe
        .iter()
        .filter(|c| !c.action.is_dir)
        .map(|c| (c.action.source.as_path(), c))
        .collect();
    let emptied: std::collections::HashSet<&Path> = plan
        .safe
        .iter()
        .filter(|c| c.action.is_dir)
        .map(|c| c.action.source.as_path())
        .collect();

    let mut folders: BTreeMap<String, AfterFolder> = BTreeMap::new();
    // Staying: root loose files and every top-level folder that is not emptied.
    let root_node = &result.dirs[0];
    let mut root_entry = AfterFolder::default();
    for &id in &root_node.files {
        let f = &result.files[id];
        if !moved.contains_key(f.path.as_path()) {
            root_entry.staying_files += 1;
            root_entry.staying_bytes += f.size;
        }
    }
    folders.insert(String::new(), root_entry);
    for &d in &root_node.children {
        let node = &result.dirs[d];
        if emptied.contains(node.path.as_path()) {
            continue;
        }
        let all = files_under(result, d);
        let staying: Vec<&crate::model::FileEntry> = all
            .iter()
            .map(|&id| &result.files[id])
            .filter(|f| !moved.contains_key(f.path.as_path()))
            .collect();
        folders.insert(
            rel_of(&node.path),
            AfterFolder {
                rel: rel_of(&node.path),
                staying_files: staying.len() as u64,
                staying_bytes: staying.iter().map(|f| f.size).sum(),
                incoming: Vec::new(),
            },
        );
    }
    // Incoming: group by the top-level component of the target.
    for c in plan.safe.iter().filter(|c| !c.action.is_dir) {
        let ActionKind::MoveTo(t) = &c.action.kind else {
            continue;
        };
        let top = t
            .components()
            .next()
            .map(|x| x.as_os_str().to_string_lossy().into_owned())
            .unwrap_or_default();
        let entry = folders.entry(top.clone()).or_insert_with(|| AfterFolder {
            rel: top,
            ..Default::default()
        });
        entry.incoming.push(AfterFile {
            name: t
                .strip_prefix(
                    t.components()
                        .next()
                        .map(|x| PathBuf::from(x.as_os_str()))
                        .unwrap_or_default(),
                )
                .map(|rest| rest.join(c.action.source.file_name().unwrap_or_default()))
                .unwrap_or_default()
                .to_string_lossy()
                .replace('\\', "/"),
            size: c.action.size,
            from: c.action.source.parent().map(rel_of),
        });
    }
    for f in folders.values_mut() {
        f.incoming.sort_by(|a, b| a.name.cmp(&b.name));
    }
    AfterTree {
        folders: folders.into_values().collect(),
    }
}
