mod common;

use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::SystemTime;

use common::Fixture;
use tidyscan::dupes::find_duplicates;
use tidyscan::scan::{ScanOptions, scan_simple};
use tidyscan::triage::{self, Kind, Recheck, Risk, Triage, TriageOptions, archive_stem};

fn names(list: &[triage::Candidate]) -> Vec<String> {
    let mut v: Vec<String> = list
        .iter()
        .map(|c| {
            c.action
                .source
                .file_name()
                .unwrap()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    v.sort();
    v
}

fn run(fx: &Fixture, with_dupes: bool) -> (tidyscan::model::ScanResult, Triage) {
    let r = scan_simple(&fx.root(), &ScanOptions::default()).unwrap();
    let ctx = common::ctx(&r);
    let dupes = with_dupes.then(|| find_duplicates(&r, 1, Arc::new(AtomicBool::new(false)), None));
    let t = triage::assess(
        &r,
        &ctx,
        dupes.as_deref(),
        &TriageOptions::default(),
        SystemTime::now(),
    );
    (r, t)
}

#[test]
fn junk_locks_partials_and_zero_bytes() {
    let fx = Fixture::new();
    fx.file("Thumbs.db", b"x"); // safe regardless of age
    let old_tmp = fx.file("a.tmp", b"x");
    fx.age(&old_tmp, 30);
    fx.file("fresh.tmp", b"x"); // too young -> unsure
    let old_lock = fx.file("~$report.docx", b"x");
    fx.age(&old_lock, 3);
    fx.file("~$open.docx", b"x"); // young lock -> unsure
    let part = fx.file("movie.mkv.crdownload", b"x");
    fx.age(&part, 10);
    let zero = fx.file("empty.txt", b"");
    fx.age(&zero, 10);
    fx.file("new-empty.txt", b"");
    let keep = fx.file(".gitkeep", b"");
    fx.age(&keep, 100);
    let proj_junk = fx.file("proj/Thumbs.db", b"x");
    fx.file("proj/package.json", b"{}");
    fx.age(&proj_junk, 100);

    let (_r, t) = run(&fx, false);
    assert_eq!(
        names(&t.safe),
        vec![
            "Thumbs.db",
            "a.tmp",
            "empty.txt",
            "movie.mkv.crdownload",
            "~$report.docx"
        ]
    );
    assert_eq!(
        names(&t.unsure),
        vec![
            ".gitkeep",
            "Thumbs.db",
            "fresh.tmp",
            "new-empty.txt",
            "~$open.docx"
        ]
    );
    let proj = t
        .unsure
        .iter()
        .find(|c| {
            c.action.source.ends_with("proj/Thumbs.db")
                || c.action.source.ends_with("proj\\Thumbs.db")
        })
        .unwrap();
    assert!(proj.reason.contains("Projekt"), "{}", proj.reason);
    assert!(t.safe.iter().all(|c| c.action.guard.is_some()));
}

#[test]
fn duplicates_keep_selection_and_project_exclusion() {
    let fx = Fixture::new();
    let data = vec![7u8; 5000];
    let a = fx.file("Dokumente/report.pdf", &data);
    let b = fx.file("Downloads/report.pdf", &data);
    let c = fx.file("Downloads/report (1).pdf", &data);
    for p in [&a, &b, &c] {
        fx.age(p, 30);
    }
    fx.age(&a, 300); // oldest and outside Downloads -> keep

    let other = vec![9u8; 4000];
    let p1 = fx.file("proj/assets/logo.png", &other);
    fx.file("proj/Cargo.toml", b"[package]");
    let p2 = fx.file("misc/logo.png", &other);
    fx.age(&p1, 50);
    fx.age(&p2, 50);

    let (r, t) = run(&fx, true);
    let safe_dupes: Vec<_> = t
        .safe
        .iter()
        .filter(|c| matches!(c.kind, Kind::Duplicate { .. }))
        .collect();
    assert_eq!(safe_dupes.len(), 2);
    for c in &safe_dupes {
        let Kind::Duplicate { keep } = &c.kind else {
            unreachable!()
        };
        assert_eq!(keep, &a);
        assert_eq!(c.action.guard.as_ref().unwrap().keep.as_ref(), Some(&a));
        assert!(c.action.source.starts_with(r.root.join("Downloads")));
    }
    let unsure_dupes: Vec<_> = t
        .unsure
        .iter()
        .filter(|c| matches!(c.kind, Kind::Duplicate { .. }))
        .collect();
    assert_eq!(unsure_dupes.len(), 1, "project group is unsure");
    assert!(unsure_dupes[0].reason.contains("Projekt"));
}

#[test]
fn empty_dirs_installers_and_archives() {
    let fx = Fixture::new();
    let old_empty = fx.dir_("alt-leer");
    fx.age(&old_empty, 30);
    fx.dir_("neu-leer");
    let setup = fx.file("Downloads/setup-1.2.exe", b"MZ");
    fx.age(&setup, 120);
    let tool = fx.file("Tools/tool.exe", b"MZ");
    fx.age(&tool, 120);
    let young = fx.file("Downloads/young.msi", b"MZ");
    fx.age(&young, 10);
    let extracted = fx.file("Downloads/foo.tar.gz", b"gz");
    fx.age(&extracted, 5);
    fx.file("Downloads/foo/readme.txt", b"hi");
    let lonely = fx.file("Downloads/bar.zip", b"zip");
    fx.age(&lonely, 400);
    let recent_zip = fx.file("Downloads/baz.zip", b"zip");
    fx.age(&recent_zip, 5);

    let (_r, t) = run(&fx, false);
    let safe = names(&t.safe);
    assert!(safe.contains(&"alt-leer".to_string()));
    assert!(safe.contains(&"setup-1.2.exe".to_string()));
    assert!(safe.contains(&"foo.tar.gz".to_string()));
    assert!(!safe.contains(&"young.msi".to_string()));
    assert!(!safe.contains(&"baz.zip".to_string()));

    let unsure = names(&t.unsure);
    assert!(unsure.contains(&"neu-leer".to_string()));
    assert!(unsure.contains(&"tool.exe".to_string()));
    assert!(unsure.contains(&"bar.zip".to_string()));
    assert_eq!(archive_stem("Foo.TAR.gz"), "foo");
    assert_eq!(archive_stem("x.zip"), "x");

    let summary = Triage::summary(&t.safe);
    assert!(
        summary
            .iter()
            .any(|(l, n, _)| *l == "Alte Installer" && *n == 1)
    );
}

#[test]
fn protected_root_yields_nothing() {
    let fx = Fixture::new();
    fx.file("node_modules/pkg/Thumbs.db", b"x");
    let root = fx.root().join("node_modules");
    let r = scan_simple(&root, &ScanOptions::default()).unwrap();
    let ctx = common::ctx(&r);
    assert!(ctx.root_protected);
    let t = triage::assess(&r, &ctx, None, &TriageOptions::default(), SystemTime::now());
    assert!(t.safe.is_empty() && t.unsure.is_empty());
    assert_eq!(t.notes.len(), 1);
}

#[test]
fn recheck_promotes_duplicates_and_blocks_changed_files() {
    let fx = Fixture::new();
    let data = vec![3u8; 3000];
    let a = fx.file("keep/x.bin", &data);
    let b = fx.file("proj/x.bin", &data);
    fx.file("proj/go.mod", b"module x");
    fx.age(&a, 20);
    fx.age(&b, 20);

    let (r, mut t) = run(&fx, true);
    let ctx = common::ctx(&r);
    let c = t
        .unsure
        .iter_mut()
        .find(|c| matches!(c.kind, Kind::Duplicate { .. }))
        .unwrap();
    // Project membership keeps it unsure even though the content matches.
    assert!(matches!(
        triage::recheck(c, &r, &ctx),
        Recheck::StillUnsure(_)
    ));
    assert_eq!(c.risk, Risk::Unsure);

    // A young lock file promoted once it is not in use, blocked once it changed.
    let fx2 = Fixture::new();
    let lock = fx2.file("~$doc.docx", b"x");
    let (r2, mut t2) = run(&fx2, false);
    let ctx2 = common::ctx(&r2);
    let c = &mut t2.unsure[0];
    let outcome = triage::recheck(c, &r2, &ctx2);
    if cfg!(windows) {
        assert!(matches!(outcome, Recheck::Promoted(_)), "{outcome:?}");
        assert_eq!(c.risk, Risk::Safe);
    }
    std::fs::write(&lock, b"changed!").unwrap();
    assert!(matches!(
        triage::recheck(c, &r2, &ctx2),
        Recheck::Blocked(_)
    ));
    assert_eq!(c.risk, Risk::Unsure);
}

#[cfg(windows)]
#[test]
fn in_use_detects_open_handles() {
    use std::os::windows::fs::OpenOptionsExt;
    let fx = Fixture::new();
    let p = fx.file("busy.txt", b"x");
    assert_eq!(triage::in_use(&p), Some(false));
    let _h = std::fs::OpenOptions::new()
        .write(true)
        .share_mode(0)
        .open(&p)
        .unwrap();
    assert_eq!(triage::in_use(&p), Some(true));
}
