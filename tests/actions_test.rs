mod common;

use std::fs;
use std::time::SystemTime;

use common::{Fixture, snapshot};
use tidyscan::actions::{self, ActionKind, Plan};
use tidyscan::cli::quarantine_action;
use tidyscan::rules::{apply_rules, parse_rules, parse_size};
use tidyscan::scan::{QUARANTINE_DIR_NAME, ScanOptions, scan_simple};

#[test]
fn size_parsing() {
    assert_eq!(parse_size("500").unwrap(), 500);
    assert_eq!(parse_size("10K").unwrap(), 10 * 1024);
    assert_eq!(parse_size("1.5M").unwrap(), 1_572_864);
    assert_eq!(parse_size("2g").unwrap(), 2 << 30);
    assert!(parse_size("abc").is_err());
}

#[test]
fn rules_match_ext_age_glob_and_size() {
    let fx = Fixture::new();
    let old_exe = fx.file("Downloads/setup.EXE", &[0u8; 10]);
    fx.age(&old_exe, 120);
    fx.file("Downloads/new.exe", &[0u8; 10]);
    let shot = fx.file("Pictures/Screenshot 2024.png", &[0u8; 10]);
    fx.age(&shot, 60);
    fx.file("Pictures/photo.png", &[0u8; 10]);
    let big = fx.file("big.zip", &[0u8; 5000]);
    fx.age(&big, 400);

    let rules = parse_rules(
        r#"
[[rule]]
name = "installer"
ext = ["exe", "msi"]
older_than_days = 90
action = "quarantine"

[[rule]]
name = "shots"
glob = "**/Screenshot*"
action = "move"
move_to = "Archiv/{year}"

[[rule]]
name = "archives"
category = "archive"
min_size = "4K"
action = "quarantine"
"#,
    )
    .unwrap();
    assert_eq!(rules.len(), 3);

    let r = scan_simple(&fx.root(), &ScanOptions::default()).unwrap();
    let plan = apply_rules(&r, &rules, SystemTime::now());
    let mut hits: Vec<(String, String)> = plan
        .actions
        .iter()
        .map(|a| {
            (
                a.reason.clone(),
                a.source.file_name().unwrap().to_string_lossy().into_owned(),
            )
        })
        .collect();
    hits.sort();
    assert_eq!(
        hits,
        vec![
            ("archives".to_string(), "big.zip".to_string()),
            ("installer".to_string(), "setup.EXE".to_string()),
            ("shots".to_string(), "Screenshot 2024.png".to_string()),
        ]
    );
    let shot_action = plan.actions.iter().find(|a| a.reason == "shots").unwrap();
    match &shot_action.kind {
        ActionKind::MoveTo(p) => {
            let s = p.to_string_lossy().replace('\\', "/");
            assert!(s.starts_with("Archiv/20"), "year placeholder resolved: {s}");
        }
        _ => panic!("expected move"),
    }
}

#[test]
fn invalid_rules_are_rejected() {
    assert!(
        parse_rules("[[rule]]\nname = \"x\"\naction = \"move\"\nglob = \"*\"").is_err(),
        "move without move_to"
    );
    assert!(
        parse_rules("[[rule]]\nname = \"x\"\naction = \"quarantine\"").is_err(),
        "no condition"
    );
}

#[test]
fn quarantine_and_undo_roundtrip() {
    let fx = Fixture::new();
    fx.file("docs/a.txt", b"A");
    fx.file("docs/b.txt", b"B");
    fx.file("keep.txt", b"K");
    fx.dir_("empty/inner");
    let before = snapshot(&fx.root());

    let r = scan_simple(&fx.root(), &ScanOptions::default()).unwrap();
    let mut plan = Plan::new(r.root.clone());
    for f in r.files.iter().filter(|f| f.name() != "keep.txt") {
        plan.push(quarantine_action(f.path.clone(), false, f.size, "test"));
    }
    for d in r
        .dirs
        .iter()
        .filter(|d| d.name() == "empty" || d.name() == "inner")
    {
        plan.push(quarantine_action(d.path.clone(), true, 0, "empty"));
    }
    assert_eq!(plan.len(), 4);

    // Dry run touches nothing.
    let dry = actions::execute(&plan, true).unwrap();
    assert_eq!(dry.moved, 4);
    assert!(dry.journal_path.is_none());
    assert_eq!(snapshot(&fx.root()), before);

    let rep = actions::execute(&plan, false).unwrap();
    assert_eq!(rep.moved, 4, "failed: {:?}", rep.failed);
    assert!(rep.failed.is_empty());
    let journal = rep.journal_path.unwrap();
    assert!(journal.exists());

    assert!(!fx.root().join("docs/a.txt").exists());
    assert!(!fx.root().join("empty").exists());
    assert!(fx.root().join("keep.txt").exists());
    let q = fx.root().join(QUARANTINE_DIR_NAME);
    assert!(q.exists());
    // Relative structure is preserved inside the session folder.
    let session = journal.parent().unwrap();
    assert_eq!(fs::read(session.join("docs/a.txt")).unwrap(), b"A");
    assert!(session.join("empty/inner").is_dir());

    let undo = actions::undo(&journal).unwrap();
    assert_eq!(undo.restored, 4, "conflicts: {:?}", undo.conflicts);
    assert!(undo.conflicts.is_empty());

    // Everything is back, byte for byte. Only the journal itself remains.
    let mut after = snapshot(&fx.root());
    after.retain(|(p, _)| !p.starts_with(QUARANTINE_DIR_NAME));
    assert_eq!(after, before);
    assert!(session.join("undo.json").exists());
    assert!(!session.join("docs").exists(), "empty session dirs pruned");

    // A second undo is refused.
    assert!(actions::undo(&journal).is_err());
}

#[test]
fn undo_never_overwrites() {
    let fx = Fixture::new();
    let a = fx.file("a.txt", b"original");
    let r = scan_simple(&fx.root(), &ScanOptions::default()).unwrap();
    let mut plan = Plan::new(r.root.clone());
    plan.push(quarantine_action(a.clone(), false, 8, "t"));
    let rep = actions::execute(&plan, false).unwrap();
    let journal = rep.journal_path.unwrap();

    // Something new appears at the original location.
    fs::write(&a, b"newer").unwrap();
    let undo = actions::undo(&journal).unwrap();
    assert_eq!(undo.restored, 0);
    assert_eq!(undo.conflicts.len(), 1);
    assert_eq!(fs::read(&a).unwrap(), b"newer");
    // The quarantined copy is still there for manual recovery.
    assert_eq!(
        fs::read(journal.parent().unwrap().join("a.txt")).unwrap(),
        b"original"
    );
}

#[test]
fn move_to_target_and_name_collisions() {
    let fx = Fixture::new();
    let f1 = fx.file("x/report.pdf", b"1");
    let f2 = fx.file("y/report.pdf", b"2");
    let r = scan_simple(&fx.root(), &ScanOptions::default()).unwrap();
    let mut plan = Plan::new(r.root.clone());
    for p in [f1, f2] {
        plan.push(actions::Action {
            source: p,
            is_dir: false,
            size: 1,
            kind: ActionKind::MoveTo("Archiv".into()),
            reason: "t".into(),
            guard: None,
        });
    }
    let rep = actions::execute(&plan, false).unwrap();
    assert_eq!(rep.moved, 2);
    let archiv = fx.root().join("Archiv");
    assert!(archiv.join("report.pdf").exists());
    assert!(archiv.join("report (1).pdf").exists());

    let undo = actions::undo(&rep.journal_path.unwrap()).unwrap();
    assert_eq!(undo.restored, 2);
    assert_eq!(fs::read(fx.root().join("x/report.pdf")).unwrap(), b"1");
    assert_eq!(fs::read(fx.root().join("y/report.pdf")).unwrap(), b"2");
}

#[test]
fn guard_skips_changed_files_and_missing_keep_copy() {
    let fx = Fixture::new();
    let a = fx.file("a.txt", b"aaaa");
    let b = fx.file("b.txt", b"bbbb");
    let keep = fx.file("keep.txt", b"bbbb");
    let r = scan_simple(&fx.root(), &ScanOptions::default()).unwrap();
    let fa = r.files.iter().find(|f| f.name() == "a.txt").unwrap();
    let fb = r.files.iter().find(|f| f.name() == "b.txt").unwrap();

    let mut plan = Plan::new(r.root.clone());
    let mut act_a = quarantine_action(a.clone(), false, fa.size, "t");
    act_a.guard = Some(actions::Guard::for_file(fa));
    let mut act_b = quarantine_action(b.clone(), false, fb.size, "dupe");
    act_b.guard = Some(actions::Guard::for_file(fb).with_keep(keep.clone()));
    plan.push(act_a);
    plan.push(act_b);

    // The world changes after the scan: a grows, the keep copy of b disappears.
    fs::write(&a, b"aaaa-changed").unwrap();
    fs::remove_file(&keep).unwrap();

    let rep = actions::execute(&plan, false).unwrap();
    assert_eq!(rep.moved, 0);
    assert_eq!(rep.failed.len(), 2);
    assert!(a.exists() && b.exists(), "nothing was moved");
    let reasons: Vec<&str> = rep.failed.iter().map(|(_, m)| m.as_str()).collect();
    assert!(reasons.iter().any(|m| m.contains("verändert")));
    assert!(reasons.iter().any(|m| m.contains("Original-Kopie fehlt")));
}
