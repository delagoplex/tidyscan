mod common;

use std::fs;
use std::path::PathBuf;
use std::time::SystemTime;

use common::{Fixture, snapshot};
use tidyscan::actions::{self, Action, ActionKind, Journal, Plan};
use tidyscan::rules::{apply_rules, parse_rules, parse_size};
use tidyscan::scan::{QUARANTINE_DIR_NAME, ScanOptions, scan_simple};

/// An action without any guard, as an older plan or a hand-written one would carry.
fn quarantine_action(source: PathBuf, is_dir: bool, size: u64, reason: &str) -> Action {
    Action {
        source,
        is_dir,
        size,
        kind: ActionKind::Quarantine,
        reason: reason.into(),
        guard: None,
    }
}

fn move_action(source: PathBuf, is_dir: bool, target: &str) -> Action {
    Action {
        kind: ActionKind::MoveTo(target.into()),
        ..quarantine_action(source, is_dir, 1, "t")
    }
}

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
    assert_eq!(rep.moved, 4, "failed: {:?} {:?}", rep.failed, rep.skipped);
    assert!(rep.failed.is_empty() && rep.skipped.is_empty());
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
        plan.push(move_action(p, false, "Archiv"));
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
    let fkeep = r.files.iter().find(|f| f.name() == "keep.txt").unwrap();

    let mut plan = Plan::new(r.root.clone());
    plan.push(Action::quarantine_file(fa, "t"));
    plan.push(Action::quarantine_file(fb, "dupe").keeping(fkeep));

    // The world changes after the scan: a grows, the keep copy of b disappears.
    fs::write(&a, b"aaaa-changed").unwrap();
    fs::remove_file(&keep).unwrap();

    let rep = actions::execute(&plan, false).unwrap();
    assert_eq!(rep.moved, 0);
    assert_eq!(rep.skipped.len(), 2);
    assert!(rep.failed.is_empty(), "a guard is not an I/O failure");
    assert!(a.exists() && b.exists(), "nothing was moved");
    assert!(
        !fx.root().join(QUARANTINE_DIR_NAME).exists(),
        "a run that moved nothing leaves no session behind"
    );
    let reasons: Vec<&str> = rep.skipped.iter().map(|(_, m)| m.as_str()).collect();
    assert!(reasons.iter().any(|m| m.contains("verändert")));
    assert!(reasons.iter().any(|m| m.contains("Original-Kopie fehlt")));
}

#[test]
fn whole_folder_quarantine_roundtrip() {
    let fx = Fixture::new();
    fx.file("Projekt alt/a.txt", b"A");
    fx.file("Projekt alt/sub/b.bin", &[1u8; 300]);
    fx.dir_("Projekt alt/sub/leer");
    fx.file("keep.txt", b"K");
    let before = snapshot(&fx.root());

    let r = scan_simple(&fx.root(), &ScanOptions::default()).unwrap();
    let d = r.dirs.iter().find(|d| d.name() == "Projekt alt").unwrap();
    let mut plan = Plan::new(r.root.clone());
    plan.push(quarantine_action(
        d.path.clone(),
        true,
        d.total_size,
        "Ganzer Ordner",
    ));

    let rep = actions::execute(&plan, false).unwrap();
    assert_eq!(rep.moved, 1, "{:?}", rep.failed);
    assert_eq!(rep.bytes, 301);
    assert!(!d.path.exists());
    let session = rep
        .journal_path
        .clone()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();
    assert_eq!(
        fs::read(session.join("Projekt alt/sub/b.bin")).unwrap(),
        vec![1u8; 300]
    );
    assert!(session.join("Projekt alt/sub/leer").is_dir());

    let undo = actions::undo(&rep.journal_path.unwrap()).unwrap();
    assert_eq!(undo.restored, 1);
    let mut after = snapshot(&fx.root());
    after.retain(|(p, _)| !p.starts_with(QUARANTINE_DIR_NAME));
    assert_eq!(after, before);
}

#[test]
fn root_and_quarantine_are_never_moved() {
    let fx = Fixture::new();
    fx.file("x.txt", b"x");
    let r = scan_simple(&fx.root(), &ScanOptions::default()).unwrap();
    let mut plan = Plan::new(r.root.clone());
    plan.push(quarantine_action(r.root.clone(), true, 1, "root"));
    let rep = actions::execute(&plan, false).unwrap();
    assert_eq!(rep.moved, 0);
    assert!(rep.skipped[0].1.contains("Quarantäne"));
    assert!(fx.root().join("x.txt").exists());
}

#[test]
fn purge_entry_and_session_and_single_restore() {
    let fx = Fixture::new();
    let a = fx.file("a.txt", b"aaaa");
    let b = fx.file("b.txt", b"bbbb");
    let c = fx.file("c.txt", b"cccc");
    let r = scan_simple(&fx.root(), &ScanOptions::default()).unwrap();
    let mut plan = Plan::new(r.root.clone());
    for p in [&a, &b, &c] {
        plan.push(quarantine_action(p.clone(), false, 4, "t"));
    }
    let rep = actions::execute(&plan, false).unwrap();
    let journal = rep.journal_path.unwrap();
    let session = journal.parent().unwrap().to_path_buf();
    assert_eq!(actions::session_info(&journal).unwrap().files, 3);

    // Restore only b.
    let idx_b = actions::Journal::load(&journal)
        .unwrap()
        .entries
        .iter()
        .position(|e| e.from == b)
        .unwrap();
    actions::undo_entry(&journal, idx_b).unwrap();
    assert_eq!(fs::read(&b).unwrap(), b"bbbb");
    assert!(!session.join("b.txt").exists());
    assert_eq!(actions::Journal::load(&journal).unwrap().entries.len(), 2);

    // Delete a for good.
    let idx_a = actions::Journal::load(&journal)
        .unwrap()
        .entries
        .iter()
        .position(|e| e.from == a)
        .unwrap();
    let pr = actions::purge_entry(&journal, idx_a).unwrap();
    assert_eq!((pr.removed, pr.bytes), (1, 4));
    assert!(!session.join("a.txt").exists() && !a.exists());
    let j = actions::Journal::load(&journal).unwrap();
    assert_eq!((j.entries.len(), j.purged), (1, 1));

    // Delete the rest of the session.
    let pr = actions::purge_session(&journal).unwrap();
    assert_eq!(pr.removed, 1, "c.txt");
    assert!(!session.exists());
    assert!(actions::list_journals(&fx.root()).is_empty());
    assert!(!c.exists());
}

#[test]
fn runs_within_the_same_second_get_separate_sessions() {
    let fx = Fixture::new();
    let a = fx.file("a.txt", b"A");
    let b = fx.file("b.txt", b"B");
    let root = fx.root();

    let mut journals = Vec::new();
    for p in [&a, &b] {
        let mut plan = Plan::new(root.clone());
        plan.push(quarantine_action(p.clone(), false, 1, "t"));
        journals.push(
            actions::execute(&plan, false)
                .unwrap()
                .journal_path
                .unwrap(),
        );
    }
    assert_ne!(
        journals[0], journals[1],
        "the second run must not reuse the journal"
    );
    assert_eq!(Journal::load(&journals[0]).unwrap().entries.len(), 1);
    assert_eq!(Journal::load(&journals[1]).unwrap().entries.len(), 1);
    assert_eq!(actions::list_journals(&root).len(), 2);

    for j in &journals {
        assert_eq!(actions::undo(j).unwrap().restored, 1);
    }
    assert_eq!(fs::read(&a).unwrap(), b"A");
    assert_eq!(fs::read(&b).unwrap(), b"B");
}

#[test]
fn moves_of_an_interrupted_run_are_recovered_from_the_log() {
    let fx = Fixture::new();
    let a = fx.file("a.txt", b"A");
    let b = fx.file("b.txt", b"B");
    let mut plan = Plan::new(fx.root());
    plan.push(quarantine_action(a.clone(), false, 1, "t"));
    plan.push(quarantine_action(b.clone(), false, 1, "t"));
    let journal = actions::execute(&plan, false)
        .unwrap()
        .journal_path
        .unwrap();
    let session = journal.parent().unwrap();

    // Recreate the state right before the final save: the journal file is still the
    // empty one written at the start, the moves only exist as log lines. The last
    // line is cut off, as a crash in the middle of a write would leave it.
    let full = Journal::load(&journal).unwrap();
    let mut log = String::new();
    for e in &full.entries {
        log.push_str(&serde_json::to_string(e).unwrap());
        log.push('\n');
    }
    log.push_str("{\"from\":\"C:/half");
    let mut empty = full.clone();
    empty.entries.clear();
    fs::write(&journal, serde_json::to_string(&empty).unwrap()).unwrap();
    fs::write(session.join("undo.log"), log).unwrap();

    assert_eq!(Journal::load(&journal).unwrap().entries.len(), 2);
    let undo = actions::undo(&journal).unwrap();
    assert_eq!(undo.restored, 2, "{:?}", undo.conflicts);
    assert!(a.exists() && b.exists());
    assert!(
        !session.join("undo.log").exists(),
        "log folded into the journal"
    );
}

#[test]
fn purge_only_deletes_inside_its_own_session() {
    let fx = Fixture::new();
    let a = fx.file("a.txt", b"aaaa");
    let victim = fx.file("docs/wichtig.txt", b"keep me");
    let mut plan = Plan::new(fx.root());
    plan.push(quarantine_action(a.clone(), false, 4, "t"));
    let journal = actions::execute(&plan, false)
        .unwrap()
        .journal_path
        .unwrap();
    let session = journal.parent().unwrap().to_path_buf();

    // A tampered journal entry points at user data.
    let mut j: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&journal).unwrap()).unwrap();
    j["entries"][0]["to"] = serde_json::json!(victim);
    fs::write(&journal, j.to_string()).unwrap();
    assert!(actions::purge_entry(&journal, 0).is_err());
    assert!(victim.exists());

    // So does the recorded session folder. The location of the journal wins.
    j["session_dir"] = serde_json::json!(fx.root().join("docs"));
    fs::write(&journal, j.to_string()).unwrap();
    let _ = actions::purge_entry(&journal, 0);
    assert!(victim.exists());
    actions::purge_session(&journal).unwrap();
    assert!(
        !session.exists(),
        "the folder the journal lies in is what gets deleted"
    );
    assert_eq!(fs::read(&victim).unwrap(), b"keep me");

    // A journal outside any quarantine folder is not accepted at all.
    let stray = fx.file("docs/undo.json", j.to_string().as_bytes());
    assert!(Journal::load(&stray).is_err());
    assert!(actions::purge_session(&stray).is_err());
    assert!(victim.exists());
}

#[test]
fn journal_with_parent_components_is_rejected() {
    let fx = Fixture::new();
    let a = fx.file("a.txt", b"aaaa");
    let mut plan = Plan::new(fx.root());
    plan.push(quarantine_action(a, false, 4, "t"));
    let journal = actions::execute(&plan, false)
        .unwrap()
        .journal_path
        .unwrap();
    let session = journal.parent().unwrap();

    let mut j: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&journal).unwrap()).unwrap();
    j["entries"][0]["to"] = serde_json::json!(session.join("..").join("..").join("a.txt"));
    fs::write(&journal, j.to_string()).unwrap();
    assert!(Journal::load(&journal).is_err());
    assert!(actions::undo(&journal).is_err());
}

#[test]
fn moving_into_the_folder_it_is_already_in_is_skipped() {
    let fx = Fixture::new();
    let inside = fx.file("Archiv/report.pdf", b"1");
    let mut plan = Plan::new(fx.root());
    plan.push(move_action(inside.clone(), false, "Archiv"));
    let rep = actions::execute(&plan, false).unwrap();
    assert_eq!(rep.moved, 0);
    assert_eq!(rep.skipped.len(), 1);
    assert!(inside.exists(), "not renamed to 'report (1).pdf'");
    assert!(!fx.root().join("Archiv/report (1).pdf").exists());
}

#[test]
fn moving_into_the_quarantine_folder_is_refused() {
    let fx = Fixture::new();
    let a = fx.file("a.txt", b"1");
    let mut plan = Plan::new(fx.root());
    plan.push(move_action(
        a.clone(),
        false,
        ".tidyscan-quarantine/versteck",
    ));
    let rep = actions::execute(&plan, false).unwrap();
    assert_eq!((rep.moved, rep.skipped.len()), (0, 1));
    assert!(a.exists());
}

#[test]
fn directory_collisions_keep_dots_in_the_name() {
    let fx = Fixture::new();
    fx.file("x/v1.2/a", b"1");
    fx.file("y/v1.2/b", b"2");
    let mut plan = Plan::new(fx.root());
    plan.push(move_action(fx.root().join("x/v1.2"), true, "Archiv"));
    plan.push(move_action(fx.root().join("y/v1.2"), true, "Archiv"));
    let rep = actions::execute(&plan, false).unwrap();
    assert_eq!(rep.moved, 2, "{:?} {:?}", rep.failed, rep.skipped);
    assert!(fx.root().join("Archiv/v1.2").is_dir());
    assert!(
        fx.root().join("Archiv/v1.2 (1)").is_dir(),
        "suffix goes after the whole folder name, not before '.2'"
    );
}

#[test]
fn empty_folder_action_leaves_a_folder_that_got_content() {
    let fx = Fixture::new();
    let dir = fx.dir_("leer/innen");
    let top = fx.root().join("leer");
    let mut plan = Plan::new(fx.root());
    plan.push(Action::quarantine_empty_dir(top.clone(), "Leerer Ordner"));

    // Between scan and execution a file lands in the folder.
    let late = dir.join("neu.txt");
    fs::write(&late, b"wichtig").unwrap();

    let rep = actions::execute(&plan, false).unwrap();
    assert_eq!(rep.moved, 0);
    assert!(
        rep.skipped[0].1.contains("nicht mehr leer"),
        "{:?}",
        rep.skipped
    );
    assert_eq!(fs::read(&late).unwrap(), b"wichtig");

    // Still empty (only empty subfolders): it moves.
    fs::remove_file(&late).unwrap();
    let rep = actions::execute(&plan, false).unwrap();
    assert_eq!(rep.moved, 1);
    assert!(!top.exists());
}

#[test]
fn a_lost_quarantine_copy_is_reported_not_faked() {
    let fx = Fixture::new();
    fx.file("Alt/a.txt", b"A");
    let dir = fx.root().join("Alt");
    let mut plan = Plan::new(fx.root());
    plan.push(Action::quarantine_tree(dir.clone(), 1, "Ganzer Ordner"));
    let journal = actions::execute(&plan, false)
        .unwrap()
        .journal_path
        .unwrap();

    // The copy disappears from the quarantine behind our back.
    fs::remove_dir_all(journal.parent().unwrap().join("Alt")).unwrap();

    let undo = actions::undo(&journal).unwrap();
    assert_eq!(undo.restored, 0);
    assert_eq!(undo.conflicts.len(), 1);
    assert!(!dir.exists(), "no empty stand-in folder is created");
    assert_eq!(Journal::load(&journal).unwrap().entries.len(), 1);
    assert!(actions::undo_entry(&journal, 0).is_err());
}

#[test]
fn quarantine_follows_a_renamed_root() {
    let fx = Fixture::new();
    fx.file("work/sub/a.txt", b"A");
    let old_root = fx.root().join("work");
    let mut plan = Plan::new(old_root.clone());
    plan.push(quarantine_action(old_root.join("sub/a.txt"), false, 1, "t"));
    let journal = actions::execute(&plan, false)
        .unwrap()
        .journal_path
        .unwrap();
    let rel = journal.strip_prefix(&old_root).unwrap().to_path_buf();

    let new_root = fx.root().join("work-umbenannt");
    fs::rename(&old_root, &new_root).unwrap();

    let undo = actions::undo(&new_root.join(rel)).unwrap();
    assert_eq!(undo.restored, 1, "{:?}", undo.conflicts);
    assert_eq!(fs::read(new_root.join("sub/a.txt")).unwrap(), b"A");
    assert!(
        !old_root.exists(),
        "nothing is recreated at the old location"
    );
}

#[test]
fn folders_holding_their_own_quarantine_are_not_moved() {
    let fx = Fixture::new();
    fx.file("sub/a.txt", b"A");
    fx.file("sub/.tidyscan-quarantine/20240101-000000/b.txt", b"B");
    let sub = fx.root().join("sub");
    let mut plan = Plan::new(fx.root());
    plan.push(Action::quarantine_tree(sub.clone(), 1, "Ganzer Ordner"));
    let rep = actions::execute(&plan, false).unwrap();
    assert_eq!((rep.moved, rep.skipped.len()), (0, 1));
    assert!(sub.join("a.txt").exists());
}

#[test]
fn actions_with_dates_before_1970_serialize() {
    let fx = Fixture::new();
    let old = fx.file("uralt.txt", b"x");
    let ft = filetime::FileTime::from_unix_time(-300_000_000, 0);
    if filetime::set_file_times(&old, ft, ft).is_err() {
        return; // filesystem cannot store such a date
    }
    let r = scan_simple(&fx.root(), &ScanOptions::default()).unwrap();
    let action = Action::quarantine_file(&r.files[0], "t");
    let json = serde_json::to_string(&action).expect("pre-epoch mtime must not break JSON");
    let back: Action = serde_json::from_str(&json).unwrap();
    assert_eq!(back.guard, action.guard);
    serde_json::to_string(&r).expect("scan result serializes as well");
}
