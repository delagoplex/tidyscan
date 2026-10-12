//! Finding files that have not been touched for a long time.

use std::time::{Duration, SystemTime};

use serde::{Deserialize, Serialize};

use crate::model::{FileId, ScanResult, age_days};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OldFile {
    pub file: FileId,
    pub age_days: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgeBasis {
    Modified,
    Accessed,
}

/// Report on whether access times on this filesystem carry information.
///
/// Windows NTFS stops updating last-access time by default, Linux usually mounts with
/// `relatime`. In both cases `atime` collapses onto `mtime` for most files, which is what
/// this heuristic detects.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AtimeReport {
    pub sampled: usize,
    /// Files whose access time is at most two seconds after the modification time.
    pub collapsed: usize,
    pub reliable: bool,
}

impl AtimeReport {
    pub fn explain(&self) -> String {
        if self.sampled == 0 {
            return "Keine Dateien mit Zeitstempeln gefunden.".into();
        }
        let pct = self.collapsed as f64 * 100.0 / self.sampled as f64;
        if self.reliable {
            format!(
                "Zugriffszeiten sehen brauchbar aus ({pct:.0} % der {} Dateien haben atime ≈ mtime).",
                self.sampled
            )
        } else {
            format!(
                "Zugriffszeiten sind unzuverlässig: bei {pct:.0} % von {} Dateien ist atime ≈ mtime. \
                 Das Dateisystem aktualisiert sie vermutlich nicht. Es wird das Änderungsdatum verwendet.",
                self.sampled
            )
        }
    }
}

pub fn atime_report(result: &ScanResult) -> AtimeReport {
    let tolerance = Duration::from_secs(2);
    let mut sampled = 0;
    let mut collapsed = 0;
    // Sample at most ~5000 files spread across the scan.
    let step = (result.files.len() / 5000).max(1);
    for f in result.files.iter().step_by(step) {
        let (Some(m), Some(a)) = (f.modified, f.accessed) else {
            continue;
        };
        sampled += 1;
        if a <= m + tolerance {
            collapsed += 1;
        }
    }
    let reliable = sampled > 0 && (collapsed as f64) < (sampled as f64) * 0.95;
    AtimeReport {
        sampled,
        collapsed,
        reliable,
    }
}

/// Files older than `min_days`, sorted oldest first.
pub fn find_old(
    result: &ScanResult,
    min_days: u64,
    basis: AgeBasis,
    now: SystemTime,
) -> Vec<OldFile> {
    let mut out: Vec<OldFile> = result
        .files
        .iter()
        .enumerate()
        .filter_map(|(id, f)| {
            let ts = match basis {
                AgeBasis::Modified => f.modified,
                // Fall back to mtime for files without atime; never report a file as
                // older than its own last modification.
                AgeBasis::Accessed => match (f.accessed, f.modified) {
                    (Some(a), Some(m)) => Some(a.max(m)),
                    (a, m) => a.or(m),
                },
            }?;
            let days = age_days(ts, now)?;
            (days >= min_days).then_some(OldFile {
                file: id,
                age_days: days,
            })
        })
        .collect();
    out.sort_by(|a, b| {
        b.age_days
            .cmp(&a.age_days)
            .then_with(|| result.files[b.file].size.cmp(&result.files[a.file].size))
    });
    out
}
