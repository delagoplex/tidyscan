mod common;

use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, SystemTime};

use common::Fixture;
use tidyscan::age::{AgeBasis, find_old};
use tidyscan::analysis::{Category, age_histogram, category_sizes, fmt_date, largest_files};
use tidyscan::dupes::empty_dirs;
use tidyscan::model::local_datetime;
use tidyscan::scan::{ScanOptions, scan, scan_simple};

#[test]
fn builds_tree_with_aggregated_totals() {
    let fx = Fixture::new();
    fx.file("a.txt", b"hello");
    fx.file("sub/b.jpg", &[0u8; 100]);
    fx.file("sub/deep/c.mp4", &[0u8; 1000]);
    fx.dir_("empty");

    let r = scan_simple(&fx.root(), &ScanOptions::default()).unwrap();
    let root = r.root_node().unwrap();
    assert_eq!(root.total_files, 3);
    assert_eq!(root.total_size, 1105);
    assert_eq!(root.total_dirs, 3, "sub, sub/deep, empty");
    assert_eq!(r.files.len(), 3);
    assert!(r.errors.is_empty());

    let sub = r.dirs.iter().find(|d| d.name() == "sub").unwrap();
    assert_eq!(sub.total_files, 2);
    assert_eq!(sub.total_size, 1100);
    assert_eq!(sub.total_dirs, 1);

    // Parents always precede children in the arena.
    for (i, d) in r.dirs.iter().enumerate() {
        if let Some(p) = d.parent {
            assert!(p < i);
        }
    }
}

#[test]
fn excludes_default_names_and_globs() {
    let fx = Fixture::new();
    fx.file("keep/x.bin", b"1");
    fx.file("$RECYCLE.BIN/junk.bin", b"1");
    fx.file(".tidyscan-quarantine/old/junk.bin", b"1");
    fx.file("node_modules/pkg/index.js", b"1");

    let opts = ScanOptions {
        exclude_globs: vec!["**/node_modules".into()],
        ..Default::default()
    };
    let r = scan_simple(&fx.root(), &opts).unwrap();
    assert_eq!(r.files.len(), 1);
    assert_eq!(r.files[0].name(), "x.bin");
    assert_eq!(r.skipped, 3);
}

#[test]
fn skip_hidden_drops_dotfiles() {
    let fx = Fixture::new();
    fx.file(".hidden/secret", b"1");
    fx.file("visible", b"1");
    let r = scan_simple(
        &fx.root(),
        &ScanOptions {
            skip_hidden: true,
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(r.files.len(), 1);
    assert_eq!(r.files[0].name(), "visible");
}

#[test]
fn categories_and_largest() {
    let fx = Fixture::new();
    fx.file("p.PNG", &[0u8; 10]);
    fx.file("v.mkv", &[0u8; 300]);
    fx.file("sub/d.pdf", &[0u8; 20]);
    fx.file("sub/x.unknownext", &[0u8; 5]);

    let r = scan_simple(&fx.root(), &ScanOptions::default()).unwrap();
    let sizes = category_sizes(&r);
    assert_eq!(sizes[0][Category::Image as usize], 10);
    assert_eq!(sizes[0][Category::Video as usize], 300);
    assert_eq!(sizes[0][Category::Document as usize], 20);
    assert_eq!(sizes[0][Category::Other as usize], 5);

    let top = largest_files(&r, 2);
    assert_eq!(r.files[top[0]].name(), "v.mkv");
    assert_eq!(
        r.files[top[1]].name(),
        "sub/d.pdf".rsplit('/').next().unwrap()
    );
}

#[test]
fn old_files_and_histogram() {
    let fx = Fixture::new();
    let fresh = fx.file("fresh.txt", b"1");
    let old = fx.file("old.txt", b"22");
    let ancient = fx.file("ancient.txt", b"333");
    fx.age(&fresh, 1);
    fx.age(&old, 400);
    fx.age(&ancient, 900);

    let r = scan_simple(&fx.root(), &ScanOptions::default()).unwrap();
    let now = SystemTime::now();
    let old_files = find_old(&r, 365, AgeBasis::Modified, now);
    let names: Vec<_> = old_files.iter().map(|o| r.files[o.file].name()).collect();
    assert_eq!(names, vec!["ancient.txt", "old.txt"], "oldest first");

    let h = age_histogram(&r, 0, now);
    assert_eq!(h[0].files, 1, "< 30 days");
    assert_eq!(h[3].files, 1, "1-2 years");
    assert_eq!(h[4].files, 1, "> 2 years");
}

#[test]
fn filters_never_remove_the_scan_root() {
    let fx = Fixture::new();
    fx.file(".cfg/a.txt", b"1");
    fx.file(".cfg/.verborgen", b"1");
    let root = fx.root().join(".cfg");
    let opts = ScanOptions {
        skip_hidden: true,
        exclude_globs: vec!["**/.cfg".into()],
        ..Default::default()
    };
    let r = scan_simple(&root, &opts).unwrap();
    assert_eq!(r.dirs[0].path, root, "the root node always exists");
    assert_eq!(r.files.len(), 1);
    assert_eq!(r.files[0].name(), "a.txt");
    assert_eq!(
        r.dirs[0].own_skipped, 1,
        "the hidden file is counted as skipped"
    );
}

#[test]
fn cancelled_scan_is_flagged_and_vouches_for_nothing() {
    let fx = Fixture::new();
    fx.dir_("leer");
    fx.file("voll/x", b"1");
    let r = scan(
        &fx.root(),
        &ScanOptions::default(),
        None,
        Arc::new(AtomicBool::new(true)),
    )
    .unwrap();
    assert!(r.cancelled);
    assert_eq!(r.dirs.len(), 1, "only the root, nothing was walked");
    assert!(r.dirs[0].incomplete);
    assert!(empty_dirs(&r).is_empty());
}

#[test]
fn depth_limit_marks_unread_folders_as_incomplete() {
    let fx = Fixture::new();
    fx.file("a/b/c.txt", b"1");
    fx.dir_("wirklich-leer");
    let opts = ScanOptions {
        max_depth: Some(1),
        ..Default::default()
    };
    let r = scan_simple(&fx.root(), &opts).unwrap();
    let a = r.dirs.iter().find(|d| d.name() == "a").unwrap();
    assert_eq!(a.total_files, 0, "its content was never read");
    assert!(a.incomplete && !a.known_empty());
    assert!(empty_dirs(&r).is_empty(), "unread is not empty");
}

#[test]
fn absurd_timestamps_do_not_panic() {
    let far = SystemTime::UNIX_EPOCH + Duration::from_secs(900_000_000_000);
    assert!(local_datetime(far).is_none());
    assert_eq!(fmt_date(far), "?");
    let early = SystemTime::UNIX_EPOCH - Duration::from_secs(300_000_000);
    assert!(fmt_date(early).ends_with("1960"));
}

#[test]
fn quarantines_of_subfolder_scans_are_recorded() {
    let fx = Fixture::new();
    fx.file(".tidyscan-quarantine/s1/own.txt", b"x");
    fx.file("sub/.tidyscan-quarantine/s2/nested.txt", b"x");
    fx.file("sub/keep.txt", b"x");
    let r = scan_simple(&fx.root(), &ScanOptions::default()).unwrap();
    assert_eq!(r.files.len(), 1, "no quarantine content in the tree");
    assert_eq!(
        r.nested_quarantines,
        vec![fx.root().join("sub").join(".tidyscan-quarantine")],
        "the root's own quarantine is not a nested one"
    );
}
