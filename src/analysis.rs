//! Derived statistics over a [`ScanResult`]: categories, age histogram, largest files.

use std::time::SystemTime;

use serde::{Deserialize, Serialize};

use crate::model::{DirId, FileEntry, FileId, ScanResult, local_datetime};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(usize)]
pub enum Category {
    Image = 0,
    Video,
    Audio,
    Document,
    Archive,
    Code,
    Installer,
    DiskImage,
    Other,
}

pub const CATEGORY_COUNT: usize = 9;

impl Category {
    pub const ALL: [Category; CATEGORY_COUNT] = [
        Category::Image,
        Category::Video,
        Category::Audio,
        Category::Document,
        Category::Archive,
        Category::Code,
        Category::Installer,
        Category::DiskImage,
        Category::Other,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Category::Image => "Bilder",
            Category::Video => "Videos",
            Category::Audio => "Audio",
            Category::Document => "Dokumente",
            Category::Archive => "Archive",
            Category::Code => "Code",
            Category::Installer => "Installer",
            Category::DiskImage => "Disk-Images",
            Category::Other => "Sonstiges",
        }
    }

    pub fn of_extension(ext: &str) -> Category {
        match ext {
            "jpg" | "jpeg" | "png" | "gif" | "bmp" | "webp" | "heic" | "heif" | "tif" | "tiff"
            | "svg" | "raw" | "cr2" | "nef" | "arw" | "dng" | "psd" | "ico" | "avif" => {
                Category::Image
            }
            "mp4" | "mkv" | "mov" | "avi" | "wmv" | "webm" | "m4v" | "flv" | "mpg" | "mpeg"
            | "ts" | "3gp" => Category::Video,
            "mp3" | "flac" | "wav" | "aac" | "ogg" | "m4a" | "wma" | "opus" | "aiff" | "alac" => {
                Category::Audio
            }
            "pdf" | "doc" | "docx" | "xls" | "xlsx" | "ppt" | "pptx" | "odt" | "ods" | "odp"
            | "txt" | "md" | "rtf" | "csv" | "epub" | "mobi" | "pages" | "numbers" | "key"
            | "tex" => Category::Document,
            "zip" | "rar" | "7z" | "tar" | "gz" | "bz2" | "xz" | "zst" | "tgz" | "cab" | "lz"
            | "lzma" => Category::Archive,
            "rs" | "py" | "js" | "mjs" | "cjs" | "jsx" | "tsx" | "java" | "kt" | "c" | "h"
            | "cpp" | "hpp" | "cc" | "cs" | "go" | "rb" | "php" | "swift" | "m" | "scala"
            | "lua" | "sh" | "ps1" | "bat" | "cmd" | "html" | "htm" | "css" | "scss" | "json"
            | "yaml" | "yml" | "toml" | "xml" | "sql" | "gd" | "dart" | "vue" | "svelte" => {
                Category::Code
            }
            "exe" | "msi" | "msix" | "appx" | "pkg" | "deb" | "rpm" | "appimage" | "apk"
            | "snap" | "flatpak" => Category::Installer,
            "iso" | "dmg" | "img" | "vhd" | "vhdx" | "vmdk" | "qcow2" | "wim" => {
                Category::DiskImage
            }
            _ => Category::Other,
        }
    }

    pub fn of_file(file: &FileEntry) -> Category {
        file.extension()
            .map(|e| Category::of_extension(&e))
            .unwrap_or(Category::Other)
    }
}

/// Byte totals per category, recursive per directory. Indexed by `DirId`.
pub type CategorySizes = Vec<[u64; CATEGORY_COUNT]>;

pub fn category_sizes(result: &ScanResult) -> CategorySizes {
    let mut sizes: CategorySizes = vec![[0; CATEGORY_COUNT]; result.dirs.len()];
    for f in &result.files {
        sizes[f.parent][Category::of_file(f) as usize] += f.size;
    }
    for i in (1..result.dirs.len()).rev() {
        if let Some(p) = result.dirs[i].parent {
            let child = sizes[i];
            for (k, v) in child.iter().enumerate() {
                sizes[p][k] += v;
            }
        }
    }
    sizes
}

/// Age buckets by modification time.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct AgeBucket {
    pub label: &'static str,
    pub max_days: u64,
    pub files: u64,
    pub bytes: u64,
}

pub fn age_histogram(result: &ScanResult, dir: DirId, now: SystemTime) -> Vec<AgeBucket> {
    let mut buckets = vec![
        AgeBucket {
            label: "< 30 Tage",
            max_days: 30,
            ..Default::default()
        },
        AgeBucket {
            label: "30–180 Tage",
            max_days: 180,
            ..Default::default()
        },
        AgeBucket {
            label: "180–365 Tage",
            max_days: 365,
            ..Default::default()
        },
        AgeBucket {
            label: "1–2 Jahre",
            max_days: 730,
            ..Default::default()
        },
        AgeBucket {
            label: "> 2 Jahre",
            max_days: u64::MAX,
            ..Default::default()
        },
    ];
    for_each_file_under(result, dir, |f| {
        let days = f.age_days(now).unwrap_or(0);
        let b = buckets
            .iter_mut()
            .find(|b| days < b.max_days)
            .expect("last bucket is unbounded");
        b.files += 1;
        b.bytes += f.size;
    });
    buckets
}

/// Visit every file below `dir` (inclusive) without allocating a path list.
pub fn for_each_file_under(result: &ScanResult, dir: DirId, mut f: impl FnMut(&FileEntry)) {
    let mut stack = vec![dir];
    while let Some(d) = stack.pop() {
        let node = &result.dirs[d];
        for &fi in &node.files {
            f(&result.files[fi]);
        }
        stack.extend(node.children.iter().copied());
    }
}

/// File ids below `dir`, recursively.
pub fn files_under(result: &ScanResult, dir: DirId) -> Vec<FileId> {
    let mut out = Vec::new();
    let mut stack = vec![dir];
    while let Some(d) = stack.pop() {
        let node = &result.dirs[d];
        out.extend(node.files.iter().copied());
        stack.extend(node.children.iter().copied());
    }
    out
}

/// The `n` largest files, descending.
pub fn largest_files(result: &ScanResult, n: usize) -> Vec<FileId> {
    let mut ids: Vec<FileId> = (0..result.files.len()).collect();
    ids.sort_unstable_by(|a, b| result.files[*b].size.cmp(&result.files[*a].size));
    ids.truncate(n);
    ids
}

/// Thousands separator in German style: 1.234.567.
pub fn fmt_count(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    for (i, ch) in s.chars().enumerate() {
        if i > 0 && (s.len() - i).is_multiple_of(3) {
            out.push('.');
        }
        out.push(ch);
    }
    out
}

/// Date as dd.mm.yyyy in local time, "?" for timestamps outside the calendar range.
pub fn fmt_date(t: SystemTime) -> String {
    match local_datetime(t) {
        Some(dt) => format!("{:02}.{:02}.{}", dt.day(), dt.month() as u8, dt.year()),
        None => "?".into(),
    }
}

pub fn human(bytes: u64) -> String {
    humansize::format_size(bytes, humansize::BINARY)
}
