//! Per-directory knowledge used by the automatic modes: is this a project, a protected
//! system area, a downloads folder, or a folder that already represents a category?

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use crate::analysis::Category;
use crate::model::{DirId, ScanResult};

/// Files whose presence marks a directory as a software project.
const PROJECT_FILE_MARKERS: &[&str] = &[
    "Cargo.toml",
    "package.json",
    "pyproject.toml",
    "setup.py",
    "go.mod",
    "composer.json",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "CMakeLists.txt",
    "project.godot",
    "Gemfile",
    "mix.exs",
    "deno.json",
];
const PROJECT_FILE_SUFFIXES: &[&str] = &[".sln", ".csproj", ".uproject", ".xcodeproj"];
/// Directories whose presence marks the parent as a project.
const PROJECT_DIR_MARKERS: &[&str] = &[".git", ".hg", ".svn", "ProjectSettings"];
/// The version-control ones are usually excluded from the scan and looked up on disk.
const VCS_DIRS: &[&str] = &[".git", ".hg", ".svn"];
/// Hints that also turn up in ordinary folders (an editor was pointed at Downloads once,
/// a lone Makefile). One alone proves nothing, two together do.
const WEAK_PROJECT_MARKERS: &[&str] = &[
    ".gitignore",
    "Makefile",
    "requirements.txt",
    ".idea",
    ".vs",
    ".vscode",
    ".editorconfig",
];

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

/// System areas on Unix-like systems.
const UNIX_SYSTEM_ROOTS: &[&str] = &[
    "/usr",
    "/etc",
    "/var",
    "/opt",
    "/bin",
    "/sbin",
    "/lib",
    "/lib64",
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

/// `path` is `base` or lies below it. Windows paths compare without regard to case.
fn path_within(path: &Path, base: &Path) -> bool {
    if cfg!(windows) {
        let mut p = path.components();
        base.components().all(|b| {
            p.next().is_some_and(|c| {
                c.as_os_str()
                    .to_string_lossy()
                    .eq_ignore_ascii_case(&b.as_os_str().to_string_lossy())
            })
        })
    } else {
        path.starts_with(base)
    }
}

/// What the machine looks like outside the scanned tree. Kept separate from the tree
/// analysis so that it can be stated explicitly instead of being guessed from path
/// fragments.
#[derive(Debug, Clone, Default)]
pub struct Environment {
    /// Directories whose content the automatic modes never touch.
    pub protected: Vec<PathBuf>,
    /// Directories inside a protected one that are fair game after all (the temp folder).
    pub unprotected: Vec<PathBuf>,
    /// Look at the directories above the scan root for project markers, up to but not
    /// including this one. `None` disables the look upwards.
    pub ancestors_until: Option<PathBuf>,
}

fn existing(paths: impl IntoIterator<Item = PathBuf>) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = paths
        .into_iter()
        .filter(|p| !p.as_os_str().is_empty())
        // Resolved, so that they compare against the canonical paths of a scan.
        .map(|p| dunce::canonicalize(&p).unwrap_or(p))
        .collect();
    out.sort();
    out.dedup();
    out
}

impl Environment {
    /// No protected areas, no look upwards: only what the scanned tree itself shows.
    pub fn isolated() -> Self {
        Self::default()
    }

    /// The areas of this machine: system and program folders, per-user application
    /// data, with the temp folder as the one exception.
    pub fn detect() -> Self {
        let home = dirs::home_dir();
        let mut protected: Vec<PathBuf> = Vec::new();
        if cfg!(windows) {
            for var in [
                "SystemRoot",
                "ProgramFiles",
                "ProgramFiles(x86)",
                "ProgramW6432",
                "ProgramData",
            ] {
                protected.extend(std::env::var_os(var).map(PathBuf::from));
            }
            protected.extend(home.as_ref().map(|h| h.join("AppData")));
        } else {
            protected.extend(UNIX_SYSTEM_ROOTS.iter().map(PathBuf::from));
            protected.extend(home.as_ref().map(|h| h.join("Library")));
        }
        protected.extend(dirs::data_local_dir());
        protected.extend(dirs::data_dir());
        protected.extend(dirs::config_dir());
        protected.extend(dirs::cache_dir());
        Self {
            protected: existing(protected),
            unprotected: existing([std::env::temp_dir()]),
            // Markers in the home folder itself (a dotfiles repository) would turn
            // everything the user owns into "a project".
            ancestors_until: home.map(|h| dunce::canonicalize(&h).unwrap_or(h)),
        }
    }

    /// The detected environment of this machine, computed once.
    pub fn system() -> &'static Environment {
        static ENV: OnceLock<Environment> = OnceLock::new();
        ENV.get_or_init(Environment::detect)
    }

    /// The innermost matching area decides, so the temp folder inside AppData is free
    /// while a program's folder inside the temp folder would be protected again.
    pub fn is_protected(&self, path: &Path) -> bool {
        let deepest = |list: &[PathBuf]| {
            list.iter()
                .filter(|base| path_within(path, base))
                .map(|base| base.components().count())
                .max()
        };
        match (deepest(&self.protected), deepest(&self.unprotected)) {
            (Some(p), Some(u)) => p > u,
            (Some(_), None) => true,
            (None, _) => false,
        }
    }

    /// A project that the scan root lies inside of, found by looking upwards on disk.
    fn enclosing_project(&self, root: &Path) -> Option<PathBuf> {
        let stop = self.ancestors_until.as_deref()?;
        root.ancestors()
            .skip(1)
            // Never judge the stop directory, anything above it, or a drive root.
            .take_while(|a| *a != stop && !path_within(stop, a) && a.parent().is_some())
            .find(|a| has_project_marker_on_disk(a))
            .map(Path::to_path_buf)
    }
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
    /// Directory is a downloads folder itself, recognised by its own name.
    pub downloads_root: Vec<bool>,
    /// Directory is recognised as a category folder by name (own name only).
    pub category_folder: Vec<Option<Category>>,
    /// The whole scan root lies inside a protected area.
    pub root_protected: bool,
    /// The scan root lies inside this project, which starts above it.
    pub enclosing_project: Option<PathBuf>,
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

fn is_marker(list: &[&str], name: &str) -> bool {
    list.iter().any(|m| m.eq_ignore_ascii_case(name))
}

fn is_project_file(name: &str) -> bool {
    is_marker(PROJECT_FILE_MARKERS, name) || {
        let lower = name.to_lowercase();
        PROJECT_FILE_SUFFIXES.iter().any(|s| lower.ends_with(s))
    }
}

fn has_project_marker(result: &ScanResult, dir: DirId) -> bool {
    let node = &result.dirs[dir];
    let mut weak = 0;
    for &f in &node.files {
        let name = result.files[f].name();
        if is_project_file(&name) {
            return true;
        }
        weak += usize::from(is_marker(WEAK_PROJECT_MARKERS, &name));
    }
    for &c in &node.children {
        let name = result.dirs[c].name();
        if is_marker(PROJECT_DIR_MARKERS, &name) {
            return true;
        }
        weak += usize::from(is_marker(WEAK_PROJECT_MARKERS, &name));
    }
    if weak >= 2 {
        return true;
    }
    // Markers like `.git` are usually excluded from the scan, so look at the disk.
    // That is only needed where the scan actually left something out.
    (node.own_skipped > 0 || node.own_unread) && VCS_DIRS.iter().any(|m| node.path.join(m).is_dir())
}

/// Like [`has_project_marker`] for a directory the scan did not cover.
fn has_project_marker_on_disk(dir: &Path) -> bool {
    if PROJECT_DIR_MARKERS.iter().any(|m| dir.join(m).is_dir())
        || PROJECT_FILE_MARKERS.iter().any(|m| dir.join(m).is_file())
    {
        return true;
    }
    let Ok(rd) = std::fs::read_dir(dir) else {
        return false;
    };
    rd.flatten()
        .any(|e| is_project_file(&e.file_name().to_string_lossy()))
}

/// Analyse the scanned tree with the areas of this machine.
pub fn build(result: &ScanResult) -> DirContext {
    build_in(result, Environment::system())
}

pub fn build_in(result: &ScanResult, env: &Environment) -> DirContext {
    let n = result.dirs.len();
    let mut ctx = DirContext {
        project: vec![false; n],
        project_root: vec![false; n],
        protected: vec![false; n],
        downloads: vec![false; n],
        downloads_root: vec![false; n],
        category_folder: vec![None; n],
        root_protected: false,
        enclosing_project: None,
    };
    if n == 0 {
        return ctx;
    }
    ctx.root_protected = env.is_protected(&result.root)
        || result
            .root
            .components()
            .any(|c| is_protected_name(&c.as_os_str().to_string_lossy()));
    ctx.enclosing_project = env.enclosing_project(&result.root);

    // Protection by folder name (node_modules, .git) covers everything below it.
    // Protection by area is decided per path, because an area can have exceptions.
    let mut tooling = vec![false; n];

    // Parents precede children, so one forward pass inherits flags correctly.
    for i in 0..n {
        let node = &result.dirs[i];
        let name = node.name();
        let parent = node.parent;
        let inherited = |v: &Vec<bool>| parent.map(|p| v[p]).unwrap_or(false);

        let in_project = inherited(&ctx.project) || (i == 0 && ctx.enclosing_project.is_some());
        // Inside a project nothing changes any more, so the lookups can be skipped.
        let root_marker = !in_project && has_project_marker(result, i);
        ctx.project_root[i] = root_marker;
        ctx.project[i] = in_project || root_marker;

        tooling[i] = inherited(&tooling) || (i != 0 && is_protected_name(&name));
        ctx.protected[i] = ctx.root_protected
            || tooling[i]
            // Scanning the home folder must not open up AppData below it.
            || env.is_protected(&node.path);

        ctx.downloads_root[i] = DOWNLOAD_NAMES.iter().any(|d| d.eq_ignore_ascii_case(&name));
        ctx.downloads[i] = ctx.downloads_root[i] || (inherited(&ctx.downloads) && !ctx.project[i]);

        ctx.category_folder[i] = category_of_folder_name(&name);
    }
    ctx
}
