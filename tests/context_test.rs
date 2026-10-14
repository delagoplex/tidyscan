mod common;

use common::Fixture;
use tidyscan::analysis::Category;
use tidyscan::context::{self, Environment, category_folder_name, category_of_folder_name};
use tidyscan::scan::{ScanOptions, scan_simple};

fn dir_id(r: &tidyscan::model::ScanResult, name: &str) -> usize {
    r.dirs
        .iter()
        .position(|d| d.name() == name)
        .unwrap_or_else(|| panic!("dir {name}"))
}

#[test]
fn project_markers_from_scan_and_from_git_dir_on_disk() {
    let fx = Fixture::new();
    fx.file("app/Cargo.toml", b"[package]");
    fx.file("app/src/main.rs", b"fn main(){}");
    fx.file("repo/readme.txt", b"x");
    fx.file("repo/.git/HEAD", b"ref");
    fx.file("repo/sub/x.txt", b"x");
    fx.file("plain/a.txt", b"x");

    // Exclude .git like the GUI does: the marker must still be found via the disk.
    let opts = ScanOptions {
        exclude_globs: vec!["**/.git".into()],
        ..Default::default()
    };
    let r = scan_simple(&fx.root(), &opts).unwrap();
    let ctx = common::ctx(&r);

    let app = dir_id(&r, "app");
    let src = dir_id(&r, "src");
    let repo = dir_id(&r, "repo");
    let sub = dir_id(&r, "sub");
    let plain = dir_id(&r, "plain");
    assert!(ctx.project_root[app] && ctx.project[app]);
    assert!(ctx.project[src] && !ctx.project_root[src]);
    assert!(ctx.project_root[repo]);
    assert!(ctx.project[sub]);
    assert_eq!(ctx.project_root_of(&r, sub), Some(repo));
    assert!(!ctx.project[plain]);
    assert!(!ctx.project[0], "root itself is not a project");
}

#[test]
fn protected_names_and_downloads_and_category_folders() {
    let fx = Fixture::new();
    fx.file("node_modules/pkg/index.js", b"x");
    fx.file("Downloads/a.zip", b"x");
    fx.file("Downloads/misc/b.zip", b"x");
    fx.file("Downloads/proj/package.json", b"{}");
    fx.file("Bilder/x.jpg", b"x");
    fx.file("Bilder/Urlaub/y.jpg", b"x");

    let r = scan_simple(&fx.root(), &ScanOptions::default()).unwrap();
    let ctx = common::ctx(&r);

    let nm = dir_id(&r, "node_modules");
    let pkg = dir_id(&r, "pkg");
    assert!(ctx.protected[nm] && ctx.protected[pkg]);
    assert!(!ctx.is_touchable(pkg));

    let dl = dir_id(&r, "Downloads");
    let misc = dir_id(&r, "misc");
    let proj = dir_id(&r, "proj");
    assert!(ctx.downloads[dl] && ctx.downloads[misc]);
    assert!(ctx.downloads_root[dl] && !ctx.downloads_root[misc]);
    assert!(
        !ctx.downloads[proj],
        "projects inside Downloads are not loose downloads"
    );

    let bilder = dir_id(&r, "Bilder");
    let urlaub = dir_id(&r, "Urlaub");
    assert_eq!(ctx.category_folder[bilder], Some(Category::Image));
    assert_eq!(ctx.category_folder[urlaub], None);
    assert_eq!(ctx.enclosing_category(&r, urlaub), Some(Category::Image));
    assert!(!ctx.root_protected);
}

#[test]
fn folder_name_mapping() {
    assert_eq!(category_of_folder_name("Pictures"), Some(Category::Image));
    assert_eq!(category_of_folder_name("MUSIK"), Some(Category::Audio));
    assert_eq!(category_of_folder_name("Urlaub"), None);
    assert_eq!(category_folder_name(Category::Document), Some("Dokumente"));
    assert_eq!(category_folder_name(Category::Code), None);
}

#[test]
fn weak_markers_alone_do_not_make_a_project() {
    let fx = Fixture::new();
    fx.file("Downloads/.gitignore", b"*.log");
    fx.file("Downloads/a.zip", b"x");
    fx.file("notizen/Makefile", b"all:");
    fx.file("skripte/requirements.txt", b"requests");
    fx.dir_("geoeffnet/.idea");
    fx.file("geoeffnet/x.txt", b"x");
    // Two of them together are a different matter.
    fx.file("echt/Makefile", b"all:");
    fx.file("echt/.gitignore", b"build/");

    let r = scan_simple(&fx.root(), &ScanOptions::default()).unwrap();
    let ctx = common::ctx(&r);
    for name in ["Downloads", "notizen", "skripte", "geoeffnet"] {
        assert!(!ctx.project[dir_id(&r, name)], "{name} is not a project");
    }
    assert!(ctx.project_root[dir_id(&r, "echt")]);
}

#[test]
fn protected_areas_apply_below_the_scan_root_too() {
    let fx = Fixture::new();
    fx.file("home/AppData/Roaming/app/settings.tmp", b"x");
    fx.file("home/AppData/Local/Temp/alt.tmp", b"x");
    fx.file("home/Dokumente/Library/buch.pdf", b"x");
    fx.file("home/Windows-Tipps/x.txt", b"x");
    let home = fx.root().join("home");
    let env = Environment {
        protected: vec![home.join("AppData")],
        unprotected: vec![home.join("AppData/Local/Temp")],
        ancestors_until: None,
    };

    // Scanning the whole home folder: AppData below it stays off limits.
    let r = scan_simple(&home, &ScanOptions::default()).unwrap();
    let ctx = context::build_in(&r, &env);
    assert!(!ctx.root_protected);
    assert!(ctx.protected[dir_id(&r, "AppData")]);
    assert!(ctx.protected[dir_id(&r, "app")], "inherited downwards");
    assert!(
        !ctx.protected[dir_id(&r, "Temp")],
        "the temp folder is the exception"
    );
    // Lookalikes are ordinary folders: no substring guessing.
    assert!(!ctx.protected[dir_id(&r, "Library")]);
    assert!(!ctx.protected[dir_id(&r, "Windows-Tipps")]);

    // Scanning inside the protected area marks the root itself.
    let r = scan_simple(&home.join("AppData/Roaming"), &ScanOptions::default()).unwrap();
    assert!(context::build_in(&r, &env).root_protected);
    let r = scan_simple(&home.join("AppData/Local/Temp"), &ScanOptions::default()).unwrap();
    assert!(!context::build_in(&r, &env).root_protected);
}

#[test]
fn detected_environment_knows_this_machine() {
    let env = Environment::system();
    let fx = Fixture::new();
    assert!(
        !env.is_protected(&fx.root()),
        "the temp folder is fair game: {:?}",
        fx.root()
    );
    if let Some(data) = dirs::config_dir() {
        assert!(env.is_protected(&data.join("irgendeine-app")));
    }
    if let Some(home) = dirs::home_dir() {
        assert!(!env.is_protected(&home.join("Documents")));
        assert!(!env.is_protected(&home));
    }
}

#[test]
fn scan_root_inside_a_project_counts_as_project() {
    let fx = Fixture::new();
    fx.file("arbeit/spiel/Cargo.toml", b"[package]");
    fx.file("arbeit/spiel/assets/bilder/logo.png", b"x");
    fx.file("arbeit/lose/foto.png", b"x");
    let env = Environment {
        ancestors_until: Some(fx.root()),
        ..Environment::isolated()
    };

    let r = scan_simple(
        &fx.root().join("arbeit/spiel/assets"),
        &ScanOptions::default(),
    )
    .unwrap();
    let ctx = context::build_in(&r, &env);
    assert_eq!(
        ctx.enclosing_project,
        Some(fx.root().join("arbeit/spiel")),
        "found by looking upwards"
    );
    assert!(ctx.project[0] && ctx.project[dir_id(&r, "bilder")]);
    assert!(!ctx.project_root[0], "the project starts above the scan");

    let r = scan_simple(&fx.root().join("arbeit/lose"), &ScanOptions::default()).unwrap();
    let ctx = context::build_in(&r, &env);
    assert!(ctx.enclosing_project.is_none() && !ctx.project[0]);
}

#[test]
fn scan_root_itself_can_be_a_category_or_downloads_folder() {
    let fx = Fixture::new();
    fx.file("Pictures/a.jpg", b"x");
    fx.file("Pictures/Urlaub/b.jpg", b"x");
    fx.file("Downloads/sub/c.zip", b"x");

    let r = scan_simple(&fx.root().join("Pictures"), &ScanOptions::default()).unwrap();
    let ctx = common::ctx(&r);
    assert_eq!(ctx.category_folder[0], Some(Category::Image));
    assert_eq!(
        ctx.enclosing_category(&r, dir_id(&r, "Urlaub")),
        Some(Category::Image)
    );

    let r = scan_simple(&fx.root().join("Downloads"), &ScanOptions::default()).unwrap();
    let ctx = common::ctx(&r);
    assert!(ctx.downloads_root[0]);
    let sub = dir_id(&r, "sub");
    assert!(ctx.downloads[sub] && !ctx.downloads_root[sub]);
}
