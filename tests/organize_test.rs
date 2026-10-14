mod common;

use std::time::SystemTime;

use common::Fixture;
use tidyscan::actions::ActionKind;
use tidyscan::analysis::Category;
use tidyscan::organize::{self, FolderVerdict, OrganizeOptions};
use tidyscan::scan::{ScanOptions, scan_simple};
use tidyscan::triage::{Candidate, Kind, Risk};

fn rel(c: &Candidate, root: &std::path::Path) -> String {
    c.action
        .source
        .strip_prefix(root)
        .unwrap()
        .to_string_lossy()
        .replace('\\', "/")
}

fn target(c: &Candidate) -> String {
    match &c.action.kind {
        ActionKind::MoveTo(t) => t.to_string_lossy().replace('\\', "/"),
        ActionKind::Quarantine => "QUARANTINE".into(),
    }
}

fn plan(
    fx: &Fixture,
    opts: &OrganizeOptions,
) -> (tidyscan::model::ScanResult, organize::OrganizePlan) {
    let r = scan_simple(&fx.root(), &ScanOptions::default()).unwrap();
    let ctx = common::ctx(&r);
    let p = organize::plan_organize(&r, &ctx, opts, SystemTime::now());
    (r, p)
}

#[test]
fn loose_files_go_to_category_folders_with_companions() {
    let fx = Fixture::new();
    for name in [
        "foto.jpg",
        "foto.xmp",
        "video.mp4",
        "video.srt",
        "bericht.pdf",
        "setup.exe",
        "notes.unknownext",
        "script.py",
        "link.lnk",
    ] {
        let p = fx.file(name, b"x");
        fx.age(&p, 5);
    }
    fx.file("fresh.png", b"x"); // modified today -> unsure

    let (r, p) = plan(&fx, &OrganizeOptions::default());
    let mut safe: Vec<(String, String)> = p
        .safe
        .iter()
        .map(|c| (rel(c, &r.root), target(c)))
        .collect();
    safe.sort();
    assert_eq!(
        safe,
        vec![
            ("bericht.pdf".to_string(), "Dokumente".to_string()),
            ("foto.jpg".to_string(), "Bilder".to_string()),
            ("foto.xmp".to_string(), "Bilder".to_string()),
            ("setup.exe".to_string(), "Installer".to_string()),
            ("video.mp4".to_string(), "Videos".to_string()),
            ("video.srt".to_string(), "Videos".to_string()),
        ]
    );
    let unsure: Vec<String> = p.unsure.iter().map(|c| rel(c, &r.root)).collect();
    assert!(unsure.contains(&"fresh.png".to_string()));
    assert!(unsure.contains(&"notes.unknownext".to_string()));
    assert!(unsure.contains(&"script.py".to_string()));
    assert!(
        !unsure.contains(&"link.lnk".to_string()),
        "shortcuts are never touched"
    );
    assert!(p.safe.iter().all(|c| c.action.guard.is_some()));

    // After-tree: Bilder receives two files, root keeps the unsure ones.
    let bilder = p.after.folders.iter().find(|f| f.rel == "Bilder").unwrap();
    assert_eq!(bilder.incoming.len(), 2);
    assert_eq!(bilder.incoming[0].from.as_deref(), Some(""));
    let root = p.after.folders.iter().find(|f| f.rel.is_empty()).unwrap();
    assert_eq!(
        root.staying_files, 4,
        "fresh.png, notes.unknownext, script.py, link.lnk"
    );
}

#[test]
fn by_year_adds_subfolder() {
    let fx = Fixture::new();
    let p = fx.file("alt.jpg", b"x");
    fx.age(&p, 800);
    let (_r, plan) = plan(
        &fx,
        &OrganizeOptions {
            by_year: true,
            ..Default::default()
        },
    );
    let t = target(&plan.safe[0]);
    assert!(t.starts_with("Bilder/20"), "{t}");
    assert_eq!(t.matches('/').count(), 1);
}

#[test]
fn coherent_folder_moves_whole_and_leaves_empty_source() {
    let fx = Fixture::new();
    for name in [
        "Urlaub/a.jpg",
        "Urlaub/b.jpg",
        "Urlaub/c.png",
        "Urlaub/Tag2/d.jpg",
        "Urlaub/liste.txt",
    ] {
        let p = fx.file(name, &[1u8; 100]);
        fx.age(&p, 40);
    }
    let (r, p) = plan(&fx, &OrganizeOptions::default());
    let prof = p
        .profiles
        .iter()
        .find(|f| r.dirs[f.dir].name() == "Urlaub")
        .unwrap();
    assert_eq!(prof.verdict, FolderVerdict::MoveWhole(Category::Image));

    let files: Vec<(String, String)> = p
        .safe
        .iter()
        .filter(|c| !c.action.is_dir)
        .map(|c| (rel(c, &r.root), target(c)))
        .collect();
    assert_eq!(files.len(), 5, "all files move, including the txt");
    assert!(files.contains(&("Urlaub/a.jpg".into(), "Bilder/Urlaub".into())));
    assert!(files.contains(&("Urlaub/Tag2/d.jpg".into(), "Bilder/Urlaub/Tag2".into())));
    assert!(files.contains(&("Urlaub/liste.txt".into(), "Bilder/Urlaub".into())));

    let dirs: Vec<String> = p
        .safe
        .iter()
        .filter(|c| c.action.is_dir)
        .map(|c| rel(c, &r.root))
        .collect();
    assert_eq!(dirs, vec!["Urlaub/Tag2", "Urlaub"], "deepest first");
    assert!(
        dirs.iter()
            .zip(p.safe.iter().filter(|c| c.action.is_dir))
            .all(|(_, c)| c.kind == Kind::LeftoverDir)
    );

    assert!(
        p.after.folders.iter().all(|f| f.rel != "Urlaub"),
        "source folder gone in after-view"
    );
    let bilder = p.after.folders.iter().find(|f| f.rel == "Bilder").unwrap();
    assert_eq!(bilder.incoming.len(), 5);
    assert!(
        bilder
            .incoming
            .iter()
            .any(|f| f.name == "Urlaub/Tag2/d.jpg")
    );
}

#[test]
fn mixed_folder_is_unsure_and_category_folders_are_kept() {
    let fx = Fixture::new();
    for name in ["misc/a.jpg", "misc/b.pdf", "misc/c.exe", "misc/d.mp3"] {
        let p = fx.file(name, b"x");
        fx.age(&p, 40);
    }
    for name in ["Bilder/x.jpg", "Bilder/Urlaub/y.jpg", "Bilder/falsch.exe"] {
        let p = fx.file(name, b"x");
        fx.age(&p, 40);
    }
    fx.file("proj/Cargo.toml", b"[package]");
    let pj = fx.file("proj/img.png", b"x");
    fx.age(&pj, 40);

    let (r, p) = plan(&fx, &OrganizeOptions::default());
    assert!(
        p.safe.is_empty(),
        "{:?}",
        p.safe.iter().map(|c| rel(c, &r.root)).collect::<Vec<_>>()
    );

    let misc = p
        .profiles
        .iter()
        .find(|f| r.dirs[f.dir].name() == "misc")
        .unwrap();
    assert_eq!(misc.verdict, FolderVerdict::Distribute);
    let distributed: Vec<(String, String)> = p
        .unsure
        .iter()
        .filter(|c| c.kind == Kind::Distribute)
        .map(|c| (rel(c, &r.root), target(c)))
        .collect();
    assert_eq!(distributed.len(), 4);
    assert!(distributed.contains(&("misc/c.exe".into(), "Installer".into())));

    let bilder = p
        .profiles
        .iter()
        .find(|f| r.dirs[f.dir].name() == "Bilder")
        .unwrap();
    assert!(matches!(bilder.verdict, FolderVerdict::Keep(_)));
    let mismatch: Vec<_> = p
        .unsure
        .iter()
        .filter(|c| rel(c, &r.root) == "Bilder/falsch.exe")
        .collect();
    assert_eq!(mismatch.len(), 1);
    assert_eq!(target(mismatch[0]), "Installer");
    assert!(
        p.unsure
            .iter()
            .all(|c| rel(c, &r.root) != "Bilder/Urlaub/y.jpg")
    );

    let proj = p
        .profiles
        .iter()
        .find(|f| r.dirs[f.dir].name() == "proj")
        .unwrap();
    assert_eq!(proj.verdict, FolderVerdict::Keep("Projektordner".into()));
    assert!(p.unsure.iter().all(|c| c.risk == Risk::Unsure));
}

#[test]
fn project_root_is_never_sorted() {
    let fx = Fixture::new();
    fx.file("Cargo.toml", b"[package]");
    let p = fx.file("logo.png", b"x");
    fx.age(&p, 40);
    let (_r, plan) = plan(&fx, &OrganizeOptions::default());
    assert!(plan.safe.is_empty() && plan.unsure.is_empty());
    assert_eq!(plan.notes.len(), 1);
}
