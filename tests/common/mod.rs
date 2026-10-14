#![allow(dead_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use tempfile::TempDir;
use tidyscan::context::{self, DirContext, Environment};
use tidyscan::model::ScanResult;

/// Context from the scanned tree alone, independent of the machine the tests run on
/// (what lies above the temp folder, which system areas exist).
pub fn ctx(result: &ScanResult) -> DirContext {
    context::build_in(result, &Environment::isolated())
}

pub struct Fixture {
    pub dir: TempDir,
}

impl Fixture {
    pub fn new() -> Self {
        Self {
            dir: tempfile::tempdir().expect("tempdir"),
        }
    }

    pub fn root(&self) -> PathBuf {
        dunce::canonicalize(self.dir.path()).unwrap()
    }

    pub fn file(&self, rel: &str, content: &[u8]) -> PathBuf {
        let p = self.root().join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(&p, content).unwrap();
        p
    }

    pub fn dir_(&self, rel: &str) -> PathBuf {
        let p = self.root().join(rel);
        fs::create_dir_all(&p).unwrap();
        p
    }

    /// Set mtime (and atime) to `days` days in the past.
    pub fn age(&self, path: &Path, days: u64) {
        let t = SystemTime::now() - Duration::from_secs(days * 86_400);
        let ft = filetime::FileTime::from_system_time(t);
        filetime::set_file_times(path, ft, ft).unwrap();
    }
}

/// Collect every path under `root` relative to it, sorted, for snapshot-style comparisons.
pub fn snapshot(root: &Path) -> Vec<(String, Option<Vec<u8>>)> {
    let mut out = Vec::new();
    fn walk(base: &Path, dir: &Path, out: &mut Vec<(String, Option<Vec<u8>>)>) {
        for e in fs::read_dir(dir).unwrap().flatten() {
            let p = e.path();
            let rel = p
                .strip_prefix(base)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            if p.is_dir() {
                out.push((rel, None));
                walk(base, &p, out);
            } else {
                out.push((rel, Some(fs::read(&p).unwrap())));
            }
        }
    }
    walk(root, root, &mut out);
    out.sort();
    out
}
