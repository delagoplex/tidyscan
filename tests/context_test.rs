mod common;

use common::Fixture;
use tidyscan::analysis::Category;
use tidyscan::context::{self, category_folder_name, category_of_folder_name};
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
    let ctx = context::build(&r);

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
    let ctx = context::build(&r);

    let nm = dir_id(&r, "node_modules");
    let pkg = dir_id(&r, "pkg");
    assert!(ctx.protected[nm] && ctx.protected[pkg]);
    assert!(!ctx.is_touchable(pkg));

    let dl = dir_id(&r, "Downloads");
    let misc = dir_id(&r, "misc");
    let proj = dir_id(&r, "proj");
    assert!(ctx.downloads[dl] && ctx.downloads[misc]);
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
