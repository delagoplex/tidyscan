mod common;

use std::time::SystemTime;

use common::Fixture;
use tidyscan::age::{AgeBasis, find_old};
use tidyscan::analysis::{Category, age_histogram, category_sizes, largest_files};
use tidyscan::scan::{ScanOptions, scan_simple};

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
