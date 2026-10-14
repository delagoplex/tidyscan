//! Duplicate detection (size → prefix hash → full hash) plus empty directories and files.

use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use rayon::prelude::*;
use serde::{Deserialize, Serialize};

use crate::model::{DirId, FileId, ScanResult};

const PREFIX_LEN: usize = 64 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DupeGroup {
    pub size: u64,
    pub hash: String,
    /// At least two file ids. Sorted by path so the first one is a stable "keep" candidate.
    pub files: Vec<FileId>,
}

impl DupeGroup {
    /// Bytes that would be freed by keeping one copy.
    pub fn wasted(&self) -> u64 {
        self.size * (self.files.len() as u64 - 1)
    }
}

#[derive(Debug, Clone, Default)]
pub struct DupeProgress {
    pub hashed_files: u64,
    pub hashed_bytes: u64,
    pub candidates: u64,
}

fn hash_prefix(path: &Path) -> io::Result<blake3::Hash> {
    let mut f = File::open(path)?;
    let mut buf = vec![0u8; PREFIX_LEN];
    let mut read = 0;
    while read < PREFIX_LEN {
        let n = f.read(&mut buf[read..])?;
        if n == 0 {
            break;
        }
        read += n;
    }
    Ok(blake3::hash(&buf[..read]))
}

pub(crate) fn hash_full(path: &Path) -> io::Result<blake3::Hash> {
    let mut f = File::open(path)?;
    let mut hasher = blake3::Hasher::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize())
}

/// What identifies a file on disk regardless of its name: (volume, file number).
/// `None` when it cannot be determined.
#[cfg(unix)]
fn file_identity(path: &Path) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    let md = std::fs::metadata(path).ok()?;
    Some((md.dev(), md.ino()))
}

#[cfg(windows)]
fn file_identity(path: &Path) -> Option<(u64, u64)> {
    let handle = winapi_util::Handle::from_path_any(path).ok()?;
    let info = winapi_util::file::information(&handle).ok()?;
    Some((info.volume_serial_number(), info.file_index()))
}

#[cfg(not(any(unix, windows)))]
fn file_identity(_path: &Path) -> Option<(u64, u64)> {
    None
}

/// Drop further names of a file that is already in the list. Hard links are one file
/// under several names, not copies: moving one away frees nothing.
fn without_hard_links(result: &ScanResult, files: Vec<FileId>) -> Vec<FileId> {
    let mut seen = std::collections::HashSet::new();
    files
        .into_iter()
        .filter(|&id| match file_identity(&result.files[id].path) {
            Some(identity) => seen.insert(identity),
            None => true,
        })
        .collect()
}

/// Find byte-identical files of at least `min_size` bytes. Files that cannot be read
/// are silently dropped from their group, as are additional hard links to a file
/// already in it. Sorted by wasted bytes, descending.
pub fn find_duplicates(
    result: &ScanResult,
    min_size: u64,
    cancel: Arc<AtomicBool>,
    progress: Option<&(AtomicU64, AtomicU64)>,
) -> Vec<DupeGroup> {
    let min_size = min_size.max(1);
    let mut by_size: HashMap<u64, Vec<FileId>> = HashMap::new();
    for (id, f) in result.files.iter().enumerate() {
        if f.size >= min_size {
            by_size.entry(f.size).or_default().push(id);
        }
    }
    let candidates: Vec<(u64, Vec<FileId>)> = by_size
        .into_iter()
        .filter(|(_, ids)| ids.len() > 1)
        .collect();

    let report = |bytes: u64| {
        if let Some((files, total)) = progress {
            files.fetch_add(1, Ordering::Relaxed);
            total.fetch_add(bytes, Ordering::Relaxed);
        }
    };

    let mut groups: Vec<DupeGroup> = candidates
        .par_iter()
        .flat_map_iter(|(size, ids)| {
            if cancel.load(Ordering::Relaxed) {
                return Vec::new();
            }
            // Stage 1: prefix hash.
            let mut by_prefix: HashMap<blake3::Hash, Vec<FileId>> = HashMap::new();
            for &id in ids {
                if let Ok(h) = hash_prefix(&result.files[id].path) {
                    by_prefix.entry(h).or_default().push(id);
                }
                report((*size).min(PREFIX_LEN as u64));
            }
            let mut out = Vec::new();
            for (prefix_hash, ids) in by_prefix {
                if ids.len() < 2 {
                    continue;
                }
                // Small files are fully covered by the prefix hash.
                if *size <= PREFIX_LEN as u64 {
                    out.push((*size, prefix_hash, ids));
                    continue;
                }
                // Stage 2: full hash.
                let mut by_full: HashMap<blake3::Hash, Vec<FileId>> = HashMap::new();
                for id in ids {
                    if cancel.load(Ordering::Relaxed) {
                        break;
                    }
                    if let Ok(h) = hash_full(&result.files[id].path) {
                        by_full.entry(h).or_default().push(id);
                    }
                    report(*size);
                }
                for (h, ids) in by_full {
                    if ids.len() > 1 {
                        out.push((*size, h, ids));
                    }
                }
            }
            out
        })
        .map(|(size, hash, mut files)| {
            files.sort_by(|a, b| result.files[*a].path.cmp(&result.files[*b].path));
            DupeGroup {
                size,
                hash: hash.to_hex().to_string(),
                files: without_hard_links(result, files),
            }
        })
        .filter(|g| g.files.len() > 1)
        .collect();

    groups.sort_by(|a, b| {
        b.wasted()
            .cmp(&a.wasted())
            .then_with(|| a.hash.cmp(&b.hash))
    });
    groups
}

/// Directories that contain no files at any depth (recursively empty).
/// Folders with skipped or unread content are not reported: the scan cannot vouch for
/// them. The scan root itself is never reported. Sorted by path.
pub fn empty_dirs(result: &ScanResult) -> Vec<DirId> {
    let mut ids: Vec<DirId> = result
        .dirs
        .iter()
        .enumerate()
        .skip(1)
        .filter(|(_, d)| d.known_empty())
        .map(|(i, _)| i)
        .collect();
    ids.sort_by(|a, b| result.dirs[*a].path.cmp(&result.dirs[*b].path));
    ids
}

/// Only the top-most empty directories (an empty parent subsumes its empty children).
pub fn empty_dirs_toplevel(result: &ScanResult) -> Vec<DirId> {
    empty_dirs(result)
        .into_iter()
        .filter(|&id| {
            result.dirs[id]
                .parent
                .map(|p| p == ScanResult::ROOT || !result.dirs[p].known_empty())
                .unwrap_or(true)
        })
        .collect()
}

pub fn zero_byte_files(result: &ScanResult) -> Vec<FileId> {
    result
        .files
        .iter()
        .enumerate()
        .filter(|(_, f)| f.size == 0)
        .map(|(i, _)| i)
        .collect()
}
