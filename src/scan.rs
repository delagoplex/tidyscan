//! Parallel directory walk that builds a [`ScanResult`].

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime};

use crossbeam_channel::Sender;
use globset::{Glob, GlobSet, GlobSetBuilder};
use jwalk::WalkDirGeneric;

use crate::model::{DirNode, FileEntry, ScanError, ScanResult};

/// Directory names that are never worth scanning (OS internals, our own quarantine).
pub const DEFAULT_EXCLUDED_NAMES: &[&str] = &[
    "$RECYCLE.BIN",
    "System Volume Information",
    ".Trashes",
    ".Spotlight-V100",
    ".fseventsd",
    QUARANTINE_DIR_NAME,
];

pub const QUARANTINE_DIR_NAME: &str = ".tidyscan-quarantine";

/// Absolute paths that are virtual filesystems on Linux.
const EXCLUDED_ABSOLUTE: &[&str] = &["/proc", "/sys", "/dev", "/run"];

#[derive(Debug, Clone, Default)]
pub struct ScanOptions {
    pub skip_hidden: bool,
    /// Additional glob patterns matched against the full path (e.g. `**/node_modules`).
    pub exclude_globs: Vec<String>,
    pub max_depth: Option<usize>,
}

#[derive(Debug, Clone, Default)]
pub struct ScanProgress {
    pub files: u64,
    pub dirs: u64,
    pub bytes: u64,
    pub current: PathBuf,
}

#[derive(Debug, Clone, Copy, Default)]
struct Meta {
    size: u64,
    modified: Option<SystemTime>,
    accessed: Option<SystemTime>,
    /// Set for entries we decided to skip after looking at metadata.
    skip: bool,
    /// Metadata could not be read; the entry is reported as an error, not as a file.
    unreadable: bool,
}

type Walk = WalkDirGeneric<((), Meta)>;

fn build_globset(patterns: &[String]) -> Result<GlobSet, globset::Error> {
    let mut b = GlobSetBuilder::new();
    for p in patterns {
        b.add(Glob::new(p)?);
    }
    b.build()
}

#[cfg(windows)]
fn windows_skip(md: &std::fs::Metadata, skip_hidden: bool) -> bool {
    use std::os::windows::fs::MetadataExt;
    const HIDDEN: u32 = 0x2;
    const OFFLINE: u32 = 0x1000;
    const RECALL_ON_OPEN: u32 = 0x40000;
    const RECALL_ON_DATA_ACCESS: u32 = 0x400000;
    let attrs = md.file_attributes();
    if attrs & (OFFLINE | RECALL_ON_OPEN | RECALL_ON_DATA_ACCESS) != 0 {
        return true; // cloud placeholder: not actually on disk
    }
    skip_hidden && attrs & HIDDEN != 0
}

#[cfg(not(windows))]
fn windows_skip(_md: &std::fs::Metadata, _skip_hidden: bool) -> bool {
    false
}

fn is_excluded_absolute(path: &Path) -> bool {
    EXCLUDED_ABSOLUTE.iter().any(|p| Path::new(p) == path)
}

fn new_dir(path: PathBuf, parent: Option<usize>, depth: usize) -> DirNode {
    DirNode {
        path,
        parent,
        depth: depth.min(u16::MAX as usize) as u16,
        ..Default::default()
    }
}

/// Walk `root` and build the arena tree. `progress` receives periodic updates,
/// `cancel` aborts the walk and returns what was collected so far, flagged as
/// [`ScanResult::cancelled`].
pub fn scan(
    root: &Path,
    opts: &ScanOptions,
    progress: Option<Sender<ScanProgress>>,
    cancel: Arc<AtomicBool>,
) -> anyhow::Result<ScanResult> {
    let started = Instant::now();
    let root = dunce::canonicalize(root)?;
    if !root.is_dir() {
        anyhow::bail!("{} is not a directory", root.display());
    }

    let globs = Arc::new(build_globset(&opts.exclude_globs)?);
    let skip_hidden = opts.skip_hidden;
    let cancel_walk = cancel.clone();
    // Directories whose listing is known to be partial. Filled from the worker threads.
    let partial: Arc<Mutex<HashSet<PathBuf>>> = Arc::default();
    let partial_walk = partial.clone();

    let mut walk = Walk::new(&root)
        .follow_links(false)
        // Hidden entries are filtered below so that they still count as skipped.
        .skip_hidden(false)
        .sort(false)
        .process_read_dir(move |depth, dir, _state, children| {
            // `depth == None` is the call for the scan root itself: the user chose it,
            // so no filter applies to it.
            if depth.is_none() {
                return;
            }
            if cancel_walk.load(Ordering::Relaxed) {
                children.clear();
                return;
            }
            let mut any_unreadable = children.iter().any(|c| c.is_err());
            for child in children.iter_mut().flatten() {
                let path = child.path();
                let name = child.file_name.to_string_lossy();
                let excluded = DEFAULT_EXCLUDED_NAMES
                    .iter()
                    .any(|n| name.eq_ignore_ascii_case(n))
                    || (skip_hidden && name.starts_with('.'))
                    || globs.is_match(&path)
                    || is_excluded_absolute(&path);
                if excluded || child.file_type.is_symlink() {
                    child.read_children = None;
                    child.client_state.skip = true;
                    continue;
                }
                match child.metadata() {
                    Ok(md) => {
                        if windows_skip(&md, skip_hidden) {
                            child.read_children = None;
                            child.client_state.skip = true;
                            continue;
                        }
                        if md.is_file() {
                            child.client_state = Meta {
                                size: md.len(),
                                modified: md.modified().ok(),
                                accessed: md.accessed().ok(),
                                ..Default::default()
                            };
                        }
                    }
                    Err(_) => {
                        // Without metadata we know neither size nor kind. Treating it as
                        // an empty file would make it a cleanup candidate.
                        child.read_children = None;
                        child.client_state.unreadable = true;
                        any_unreadable = true;
                    }
                }
            }
            if any_unreadable && let Ok(mut set) = partial_walk.lock() {
                set.insert(dir.to_path_buf());
            }
        });
    if let Some(d) = opts.max_depth {
        walk = walk.max_depth(d);
    }

    let mut result = ScanResult {
        root: root.clone(),
        ..Default::default()
    };
    // The root node exists no matter what the walk yields, so `dirs[0]` is always valid.
    result.dirs.push(new_dir(root.clone(), None, 0));
    let mut dir_index: HashMap<PathBuf, usize> = HashMap::new();
    dir_index.insert(root.clone(), 0);
    let mut prog = ScanProgress {
        dirs: 1,
        ..Default::default()
    };
    let mut since_report = 0u32;

    for entry in walk {
        if cancel.load(Ordering::Relaxed) {
            break;
        }
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                let path = e.path().map(Path::to_path_buf).unwrap_or_default();
                if let Some(&p) = path.parent().and_then(|p| dir_index.get(p)) {
                    result.dirs[p].own_unread = true;
                }
                result.errors.push(ScanError {
                    path,
                    message: e.to_string(),
                });
                continue;
            }
        };
        let path = entry.path();
        if entry.depth == 0 {
            if let Some(rc) = &entry.read_children
                && let Some(err) = rc.error()
            {
                result.dirs[0].own_unread = true;
                result.errors.push(ScanError {
                    path,
                    message: err.to_string(),
                });
            }
            if opts.max_depth == Some(0) {
                result.dirs[0].own_unread = true;
            }
            continue;
        }
        let Some(&parent) = dir_index.get(entry.parent_path()) else {
            // Parent was skipped or errored; it already accounts for this entry.
            continue;
        };
        if entry.client_state.unreadable {
            result.dirs[parent].own_unread = true;
            result.errors.push(ScanError {
                path,
                message: "Metadaten nicht lesbar".into(),
            });
            continue;
        }
        if entry.client_state.skip {
            result.skipped += 1;
            result.dirs[parent].own_skipped += 1;
            continue;
        }

        if entry.file_type.is_dir() {
            let id = result.dirs.len();
            let mut node = new_dir(path.clone(), Some(parent), entry.depth);
            // At the depth limit the directory is listed but never read.
            node.own_unread = opts.max_depth == Some(entry.depth);
            if let Some(rc) = &entry.read_children
                && let Some(err) = rc.error()
            {
                node.own_unread = true;
                result.errors.push(ScanError {
                    path: path.clone(),
                    message: err.to_string(),
                });
            }
            result.dirs.push(node);
            result.dirs[parent].children.push(id);
            dir_index.insert(path, id);
            prog.dirs += 1;
        } else if entry.file_type.is_file() {
            let m = entry.client_state;
            let id = result.files.len();
            result.files.push(FileEntry {
                path,
                size: m.size,
                modified: m.modified,
                accessed: m.accessed,
                parent,
            });
            result.dirs[parent].files.push(id);
            prog.files += 1;
            prog.bytes += m.size;
        } else {
            // Sockets, devices and the like.
            result.skipped += 1;
            result.dirs[parent].own_skipped += 1;
            continue;
        }

        since_report += 1;
        if since_report >= 500
            && let Some(tx) = &progress
        {
            since_report = 0;
            prog.current = entry.parent_path().to_path_buf();
            let _ = tx.send(prog.clone());
        }
    }
    result.cancelled = cancel.load(Ordering::Relaxed);
    if let Ok(set) = partial.lock() {
        for p in set.iter() {
            if let Some(&d) = dir_index.get(p) {
                result.dirs[d].own_unread = true;
            }
        }
    }

    result.aggregate();
    result.duration = started.elapsed();
    if let Some(tx) = &progress {
        prog.current = root;
        let _ = tx.send(prog);
    }
    Ok(result)
}

/// Convenience wrapper without progress reporting or cancellation.
pub fn scan_simple(root: &Path, opts: &ScanOptions) -> anyhow::Result<ScanResult> {
    scan(root, opts, None, Arc::new(AtomicBool::new(false)))
}
