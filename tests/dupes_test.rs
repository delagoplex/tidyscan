mod common;

use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use common::Fixture;
use tidyscan::dupes::{empty_dirs, empty_dirs_toplevel, find_duplicates, zero_byte_files};
use tidyscan::scan::{ScanOptions, scan_simple};

fn no_cancel() -> Arc<AtomicBool> {
    Arc::new(AtomicBool::new(false))
}

#[test]
fn finds_exact_duplicates_only() {
    let fx = Fixture::new();
    let big: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
    let mut big_tail_differs = big.clone();
    *big_tail_differs.last_mut().unwrap() ^= 0xff;

    fx.file("a/one.bin", &big);
    fx.file("b/two.bin", &big);
    fx.file("c/three.bin", &big);
    fx.file("d/almost.bin", &big_tail_differs); // same size + prefix, different tail
    fx.file("small1.txt", b"same");
    fx.file("small2.txt", b"same");
    fx.file("other.txt", b"diff");

    let r = scan_simple(&fx.root(), &ScanOptions::default()).unwrap();
    let groups = find_duplicates(&r, 1, no_cancel(), None);
    assert_eq!(groups.len(), 2);

    let big_group = &groups[0];
    assert_eq!(big_group.size, big.len() as u64);
    assert_eq!(big_group.files.len(), 3);
    assert_eq!(big_group.wasted(), 2 * big.len() as u64);
    let names: Vec<_> = big_group.files.iter().map(|&i| r.files[i].name()).collect();
    assert_eq!(names, vec!["one.bin", "two.bin", "three.bin"]);

    assert_eq!(groups[1].size, 4);
    assert_eq!(groups[1].files.len(), 2);

    // min_size filters out the small group.
    let groups = find_duplicates(&r, 1000, no_cancel(), None);
    assert_eq!(groups.len(), 1);
}

#[test]
fn empty_directories_are_recursive() {
    let fx = Fixture::new();
    fx.dir_("e1");
    fx.dir_("e2/inner/deeper");
    fx.file("full/x", b"1");
    fx.dir_("full/empty_child");

    let r = scan_simple(&fx.root(), &ScanOptions::default()).unwrap();
    let all: Vec<_> = empty_dirs(&r)
        .iter()
        .map(|&i| {
            r.relative(&r.dirs[i].path)
                .to_string_lossy()
                .replace('\\', "/")
        })
        .collect();
    assert_eq!(
        all,
        vec![
            "e1",
            "e2",
            "e2/inner",
            "e2/inner/deeper",
            "full/empty_child"
        ]
    );

    let top: Vec<_> = empty_dirs_toplevel(&r)
        .iter()
        .map(|&i| {
            r.relative(&r.dirs[i].path)
                .to_string_lossy()
                .replace('\\', "/")
        })
        .collect();
    assert_eq!(top, vec!["e1", "e2", "full/empty_child"]);
}

#[test]
fn zero_byte_files_are_listed() {
    let fx = Fixture::new();
    fx.file("z1", b"");
    fx.file("z2", b"");
    fx.file("nz", b"x");
    let r = scan_simple(&fx.root(), &ScanOptions::default()).unwrap();
    assert_eq!(zero_byte_files(&r).len(), 2);
}
