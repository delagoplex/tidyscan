//! Core data model: an arena-based directory tree produced by a scan.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};

/// Index into `ScanResult::dirs`.
pub type DirId = usize;
/// Index into `ScanResult::files`.
pub type FileId = usize;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEntry {
    pub path: PathBuf,
    pub size: u64,
    pub modified: Option<SystemTime>,
    pub accessed: Option<SystemTime>,
    pub parent: DirId,
}

impl FileEntry {
    pub fn name(&self) -> String {
        self.path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default()
    }

    pub fn extension(&self) -> Option<String> {
        self.path
            .extension()
            .map(|e| e.to_string_lossy().to_ascii_lowercase())
    }

    /// Age in whole days relative to `now`, based on the modification time.
    /// Returns `None` when no timestamp is available or it lies in the future.
    pub fn age_days(&self, now: SystemTime) -> Option<u64> {
        age_days(self.modified?, now)
    }
}

pub fn age_days(ts: SystemTime, now: SystemTime) -> Option<u64> {
    now.duration_since(ts).ok().map(|d| d.as_secs() / 86_400)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirNode {
    pub path: PathBuf,
    pub parent: Option<DirId>,
    pub depth: u16,
    pub children: Vec<DirId>,
    pub files: Vec<FileId>,
    /// Recursive byte total.
    pub total_size: u64,
    /// Recursive file count.
    pub total_files: u64,
    /// Recursive directory count (not including self).
    pub total_dirs: u64,
    /// Newest modification time of any file below this directory.
    #[serde(default)]
    pub newest: Option<SystemTime>,
}

impl DirNode {
    pub fn name(&self) -> String {
        self.path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| self.path.to_string_lossy().into_owned())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanError {
    pub path: PathBuf,
    pub message: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScanResult {
    pub root: PathBuf,
    pub dirs: Vec<DirNode>,
    pub files: Vec<FileEntry>,
    pub errors: Vec<ScanError>,
    /// Entries skipped on purpose (symlinks, cloud placeholders, excluded names).
    pub skipped: u64,
    pub duration: Duration,
}

impl ScanResult {
    pub const ROOT: DirId = 0;

    pub fn root_node(&self) -> Option<&DirNode> {
        self.dirs.first()
    }

    pub fn total_size(&self) -> u64 {
        self.root_node().map(|d| d.total_size).unwrap_or(0)
    }

    pub fn total_files(&self) -> u64 {
        self.files.len() as u64
    }

    /// Path relative to the scan root, falling back to the full path.
    pub fn relative(&self, path: &Path) -> PathBuf {
        path.strip_prefix(&self.root)
            .map(Path::to_path_buf)
            .unwrap_or_else(|_| path.to_path_buf())
    }

    /// Recompute recursive totals. Parents always have a smaller index than
    /// their children, so a single reverse pass suffices.
    pub fn aggregate(&mut self) {
        for d in &mut self.dirs {
            d.total_size = 0;
            d.total_files = 0;
            d.total_dirs = 0;
            d.newest = None;
        }
        for f in &self.files {
            let d = &mut self.dirs[f.parent];
            d.total_size += f.size;
            d.total_files += 1;
            if f.modified > d.newest {
                d.newest = f.modified;
            }
        }
        for i in (1..self.dirs.len()).rev() {
            let (size, files, dirs, newest) = {
                let d = &self.dirs[i];
                (d.total_size, d.total_files, d.total_dirs, d.newest)
            };
            if let Some(p) = self.dirs[i].parent {
                let parent = &mut self.dirs[p];
                parent.total_size += size;
                parent.total_files += files;
                parent.total_dirs += dirs + 1;
                if newest > parent.newest {
                    parent.newest = newest;
                }
            }
        }
    }
}
