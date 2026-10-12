//! Per-directory knowledge used by the automatic modes: is this a project, a protected
//! system area, a downloads folder, or a folder that already represents a category?

use std::path::Path;

use crate::analysis::Category;
use crate::model::{DirId, ScanResult};

/// Files whose presence marks a directory as a software project.
const PROJECT_FILE_MARKERS: &[&str] = &[
    "Cargo.toml",
    "package.json",
    "pyproject.toml",
    "setup.py",
    "requirements.txt",
    "go.mod",
    "composer.json",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "CMakeLists.txt",
    "Makefile",
    "project.godot",
    "Gemfile",
    "mix.exs",
    "deno.json",
    ".gitignore",
];
const PROJECT_FILE_SUFFIXES: &[&str] = &[".sln", ".csproj", ".uproject", ".xcodeproj"];
/// Directories whose presence marks the parent as a project.
const PROJECT_DIR_MARKERS: &[&str] = &[".git", ".hg", ".svn", ".idea", ".vs", "ProjectSettings"];

/// Directory names that are never touched, wherever they are.
const PROTECTED_NAMES: &[&str] = &[
    "node_modules",
    ".git",
    ".hg",
    ".svn",
    "__pycache__",
    "venv",
    ".venv",
    "target",
    "steamapps",
    "Steam",
    "Epic Games",
    "GOG Galaxy",
    "Windows",
    "Program Files",
    "Program Files (x86)",
    "ProgramData",
    "System32",
    "$Recycle.Bin",
    "System Volume Information",
    "WindowsApps",
];

/// Absolute roots that are system areas.
const PROTECTED_ROOTS: &[&str] = &[
    "/usr",
    "/etc",
    "/var",
    "/opt",
    "/bin",
    "/sbin",
    "/lib",
    "/boot",
    "/System",
    "/Library",
    "/Applications",
    "/private",
];

const DOWNLOAD_NAMES: &[&str] = &["downloads", "download", "herunterladen", "téléchargements"];

/// Folder-name synonyms that identify an already existing category folder.
const CATEGORY_FOLDER_NAMES: &[(&str, Category)] = &[
    ("bilder", Category::Image),
    ("pictures", Category::Image),
    ("images", Category::Image),
    ("fotos", Category::Image),
    ("photos", Category::Image),
    ("screenshots", Category::Image),
    ("videos", Category::Video),
    ("video", Category::Video),
    ("movies", Category::Video),
    ("filme", Category::Video),
    ("musik", Category::Audio),
    ("music", Category::Audio),
    ("audio", Category::Audio),
    ("podcasts", Category::Audio),
    ("dokumente", Category::Document),
    ("documents", Category::Document),
    ("docs", Category::Document),
    ("ebooks", Category::Document),
    ("archive", Category::Archive),
    ("archives", Category::Archive),
    ("installer", Category::Installer),
    ("installers", Category::Installer),
    ("setups", Category::Installer),
    ("programme", Category::Installer),
    ("programs", Category::Installer),
    ("disk-images", Category::DiskImage),
    ("isos", Category::DiskImage),
    ("iso", Category::DiskImage),
];

/// German target folder name for each category when sorting.
pub fn category_folder_name(c: Category) -> Option<&'static str> {
    Some(match c {
        Category::Image => "Bilder",
        Category::Video => "Videos",
        Category::Audio => "Audio",
        Category::Document => "Dokumente",
        Category::Archive => "Archive",
        Category::Installer => "Installer",
        Category::DiskImage => "Disk-Images",
        Category::Code | Category::Other => return None,
    })
}

pub fn category_of_folder_name(name: &str) -> Option<Category> {
    let n = name.to_lowercase();
    CATEGORY_FOLDER_NAMES
        .iter()
        .find(|(k, _)| *k == n)
        .map(|(_, c)| *c)
}

#[derive(Debug, Clone, Default)]
pub struct DirContext {
    /// Directory is a project or lies inside one.
    pub project: Vec<bool>,
    /// Directory is the project root itself (for messages).
    pub project_root: Vec<bool>,
    /// Directory is a protected system or tooling area, or lies inside one.
    pub protected: Vec<bool>,
    /// Directory is a downloads folder or a plain subfolder of one.
    pub downloads: Vec<bool>,
    /// Directory is recognised as a category folder by name (own name only).
    pub category_folder: Vec<Option<Category>>,
    /// The whole scan root lies inside a protected area.
    pub root_protected: bool,
}

impl DirContext {
    pub fn is_touchable(&self, dir: DirId) -> bool {
        !self.protected[dir] && !self.project[dir]
    }

    /// Nearest enclosing project root for a directory, for messages.
    pub fn project_root_of(&self, result: &ScanResult, mut dir: DirId) -> Option<DirId> {
        loop {
            if self.project_root[dir] {
                return Some(dir);
            }
            dir = result.dirs[dir].parent?;
        }
    }

    /// Nearest enclosing category folder (walking up), if the directory lies inside one.
    pub fn enclosing_category(&self, result: &ScanResult, mut dir: DirId) -> Option<Category> {
        loop {
            if let Some(c) = self.category_folder[dir] {
                return Some(c);
            }
            dir = result.dirs[dir].parent?;
        }
    }
}

fn is_protected_name(name: &str) -> bool {
    PROTECTED_NAMES.iter().any(|n| n.eq_ignore_ascii_case(name)) || name.ends_with(".app")
}

fn path_is_protected_root(path: &Path) -> bool {
    let s = path.to_string_lossy().replace('\\', "/");
    if PROTECTED_ROOTS
        .iter()
        .any(|r| s == *r || s.starts_with(&format!("{r}/")))
    {
        return true;
    }
    // Windows system areas and per-user AppData (except the temp folder).
    let lower = s.to_lowercase();
    if lower.contains("/windows/") || lower.ends_with("/windows") {
        return true;
    }
    if lower.contains("/appdata/") && !lower.contains("/appdata/local/temp") {
        return true;
    }
    if lower.contains("/library/") && !lower.contains("/library/caches") {
        return true;
    }
    false
}

fn has_project_marker(result: &ScanResult, dir: DirId) -> bool {
    let node = &result.dirs[dir];
    let file_hit = node.files.iter().any(|&f| {
        let name = result.files[f].name();
        PROJECT_FILE_MARKERS
            .iter()
            .any(|m| m.eq_ignore_ascii_case(&name))
            || PROJECT_FILE_SUFFIXES
                .iter()
                .any(|s| name.to_lowercase().ends_with(s))
    });
    if file_hit {
        return true;
    }
    let dir_hit = node.children.iter().any(|&c| {
        let name = result.dirs[c].name();
        PROJECT_DIR_MARKERS
            .iter()
            .any(|m| m.eq_ignore_ascii_case(&name))
    });
    if dir_hit {
        return true;
    }
    // Markers like `.git` are usually excluded from the scan, so look at the disk.
    PROJECT_DIR_MARKERS
        .iter()
        .take(3)
        .any(|m| node.path.join(m).is_dir())
}

pub fn build(result: &ScanResult) -> DirContext {
    let n = result.dirs.len();
    let mut ctx = DirContext {
        project: vec![false; n],
        project_root: vec![false; n],
        protected: vec![false; n],
        downloads: vec![false; n],
        category_folder: vec![None; n],
        root_protected: false,
    };
    if n == 0 {
        return ctx;
    }
    ctx.root_protected = path_is_protected_root(&result.root)
        || result
            .root
            .components()
            .any(|c| is_protected_name(&c.as_os_str().to_string_lossy()));

    // Parents precede children, so one forward pass inherits flags correctly.
    for i in 0..n {
        let node = &result.dirs[i];
        let name = node.name();
        let parent = node.parent;
        let inherited = |v: &Vec<bool>| parent.map(|p| v[p]).unwrap_or(false);

        let root_marker = has_project_marker(result, i);
        ctx.project_root[i] = root_marker && !inherited(&ctx.project);
        ctx.project[i] = inherited(&ctx.project) || root_marker;

        ctx.protected[i] =
            ctx.root_protected || inherited(&ctx.protected) || (i != 0 && is_protected_name(&name));

        let is_dl_name = DOWNLOAD_NAMES.iter().any(|d| d.eq_ignore_ascii_case(&name));
        ctx.downloads[i] = is_dl_name || (inherited(&ctx.downloads) && !ctx.project[i]);

        if i != 0 {
            ctx.category_folder[i] = category_of_folder_name(&name);
        }
    }
    ctx
}
