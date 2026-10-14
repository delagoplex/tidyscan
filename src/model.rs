//! Core data model: an arena-based directory tree produced by a scan.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use time::{OffsetDateTime, UtcOffset};

/// Index into `ScanResult::dirs`.
pub type DirId = usize;
/// Index into `ScanResult::files`.
pub type FileId = usize;

/// `Option<SystemTime>` as signed milliseconds since the Unix epoch. The derived
/// `SystemTime` encoding refuses timestamps before 1970, which real files do carry.
pub mod serde_time {
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn to_millis(t: SystemTime) -> i64 {
        match t.duration_since(UNIX_EPOCH) {
            Ok(d) => i64::try_from(d.as_millis()).unwrap_or(i64::MAX),
            Err(e) => i64::try_from(e.duration().as_millis())
                .map(|m| -m)
                .unwrap_or(i64::MIN),
        }
    }

    pub fn from_millis(ms: i64) -> Option<SystemTime> {
        let d = Duration::from_millis(ms.unsigned_abs());
        if ms >= 0 {
            UNIX_EPOCH.checked_add(d)
        } else {
            UNIX_EPOCH.checked_sub(d)
        }
    }

    pub fn serialize<S: Serializer>(t: &Option<SystemTime>, s: S) -> Result<S::Ok, S::Error> {
        t.map(to_millis).serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<SystemTime>, D::Error> {
        Ok(Option::<i64>::deserialize(d)?.and_then(from_millis))
    }
}

/// Local calendar time for a timestamp, `None` when it lies outside the representable
/// range (broken clocks produce mtimes far in the future or the past).
pub fn local_datetime(t: SystemTime) -> Option<OffsetDateTime> {
    let secs = match t.duration_since(UNIX_EPOCH) {
        Ok(d) => i64::try_from(d.as_secs()).ok()?,
        Err(e) => -i64::try_from(e.duration().as_secs()).ok()?,
    };
    let utc = OffsetDateTime::from_unix_timestamp(secs).ok()?;
    let offset = UtcOffset::local_offset_at(utc).unwrap_or(UtcOffset::UTC);
    utc.checked_to_offset(offset)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEntry {
    pub path: PathBuf,
    pub size: u64,
    #[serde(with = "serde_time")]
    pub modified: Option<SystemTime>,
    #[serde(with = "serde_time")]
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

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
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
    #[serde(default, with = "serde_time")]
    pub newest: Option<SystemTime>,
    /// Entries directly inside this directory that the scan left out on purpose
    /// (symlinks, cloud placeholders, hidden or excluded names).
    #[serde(default)]
    pub own_skipped: u64,
    /// The listing of this directory itself is not complete (read error, depth limit).
    #[serde(default)]
    pub own_unread: bool,
    /// Recursive count of skipped entries.
    #[serde(default)]
    pub skipped: u64,
    /// This directory or something below it was not fully read.
    #[serde(default)]
    pub incomplete: bool,
}

impl DirNode {
    pub fn name(&self) -> String {
        self.path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| self.path.to_string_lossy().into_owned())
    }

    /// The scan saw everything below this directory and found no file at any depth.
    /// Skipped or unread content means we do not know, which is never "empty".
    pub fn known_empty(&self) -> bool {
        self.total_files == 0 && self.skipped == 0 && !self.incomplete
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
    /// The walk was aborted; the tree is a partial view of the disk.
    #[serde(default)]
    pub cancelled: bool,
    /// Quarantine folders of earlier scans that used a subfolder as their root. They
    /// are skipped like the root's own, so their content shows up in no total.
    #[serde(default)]
    pub nested_quarantines: Vec<PathBuf>,
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

    /// [`Self::relative`] with forward slashes, for display and portable patterns.
    pub fn relative_slashed(&self, path: &Path) -> String {
        self.relative(path).to_string_lossy().replace('\\', "/")
    }

    /// Recompute recursive totals. Parents always have a smaller index than
    /// their children, so a single reverse pass suffices.
    pub fn aggregate(&mut self) {
        for d in &mut self.dirs {
            d.total_size = 0;
            d.total_files = 0;
            d.total_dirs = 0;
            d.newest = None;
            d.skipped = d.own_skipped;
            d.incomplete = d.own_unread || self.cancelled;
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
            let (size, files, dirs, newest, skipped, incomplete) = {
                let d = &self.dirs[i];
                (
                    d.total_size,
                    d.total_files,
                    d.total_dirs,
                    d.newest,
                    d.skipped,
                    d.incomplete,
                )
            };
            if let Some(p) = self.dirs[i].parent {
                let parent = &mut self.dirs[p];
                parent.total_size += size;
                parent.total_files += files;
                parent.total_dirs += dirs + 1;
                parent.skipped += skipped;
                parent.incomplete |= incomplete;
                if newest > parent.newest {
                    parent.newest = newest;
                }
            }
        }
    }
}
