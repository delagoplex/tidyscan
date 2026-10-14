//! Command-line interface. Every subcommand except `clean --apply` and `undo` is read-only.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::SystemTime;

use anyhow::Context;
use clap::{Args, Parser, Subcommand};

use crate::actions::{self, ActionKind, Plan};
use crate::age::{self, AgeBasis};
use crate::analysis::{self, Category, human};
use crate::context;
use crate::dupes;
use crate::model::ScanResult;
use crate::organize::{self, AfterTree, FolderVerdict, OrganizeOptions, OrganizePlan};
use crate::rules;
use crate::scan::{self, ScanOptions};
use crate::triage::{self, Candidate, Triage, TriageOptions};

#[derive(Parser, Debug)]
#[command(
    name = "tidyscan",
    version,
    about = "Ordner analysieren und sicher aufräumen"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Args, Debug, Clone)]
pub struct ScanArgs {
    /// Zu scannender Ordner
    pub path: PathBuf,
    /// Versteckte Dateien und Ordner überspringen
    #[arg(long)]
    pub skip_hidden: bool,
    /// Glob-Muster, die übersprungen werden (mehrfach möglich), z. B. "**/node_modules"
    #[arg(long = "exclude", value_name = "GLOB")]
    pub excludes: Vec<String>,
    /// Maximale Tiefe
    #[arg(long)]
    pub max_depth: Option<usize>,
}

impl ScanArgs {
    fn options(&self) -> ScanOptions {
        ScanOptions {
            skip_hidden: self.skip_hidden,
            exclude_globs: self.excludes.clone(),
            max_depth: self.max_depth,
        }
    }

    fn run(&self) -> anyhow::Result<ScanResult> {
        let cancel = Arc::new(AtomicBool::new(false));
        let result = scan::scan(&self.path, &self.options(), None, cancel)?;
        eprintln!(
            "Gescannt: {} Dateien, {} Ordner, {} in {:.1?} ({} Fehler, {} übersprungen)",
            result.files.len(),
            result.dirs.len(),
            human(result.total_size()),
            result.duration,
            result.errors.len(),
            result.skipped
        );
        if result.cancelled {
            eprintln!("Der Scan wurde abgebrochen, das Ergebnis ist unvollständig.");
        }
        Ok(result)
    }
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Grafische Oberfläche starten (Standard ohne Unterbefehl)
    Gui {
        /// Ordner, der direkt vorausgewählt wird
        path: Option<PathBuf>,
    },
    /// Ordner scannen und Struktur, Kategorien und größte Dateien ausgeben
    Scan {
        #[command(flatten)]
        scan: ScanArgs,
        /// Ergebnis als JSON ausgeben
        #[arg(long)]
        json: bool,
        /// Anzahl der größten Dateien und Unterordner
        #[arg(long, default_value_t = 15)]
        top: usize,
    },
    /// Dateien finden, die seit N Tagen unverändert sind
    Old {
        #[command(flatten)]
        scan: ScanArgs,
        #[arg(long, default_value_t = 365)]
        days: u64,
        /// Zugriffszeit statt Änderungszeit verwenden (wird auf Zuverlässigkeit geprüft)
        #[arg(long)]
        use_atime: bool,
        #[arg(long, default_value_t = 50)]
        limit: usize,
        #[arg(long)]
        json: bool,
    },
    /// Byte-identische Duplikate finden
    Dupes {
        #[command(flatten)]
        scan: ScanArgs,
        /// Mindestgröße, z. B. 1M
        #[arg(long, default_value = "1")]
        min_size: String,
        #[arg(long)]
        json: bool,
    },
    /// Leere Ordner und 0-Byte-Dateien finden
    Empty {
        #[command(flatten)]
        scan: ScanArgs,
        #[arg(long)]
        json: bool,
    },
    /// Regeln anwenden. Ohne --apply nur Vorschau.
    Clean {
        #[command(flatten)]
        scan: ScanArgs,
        /// Regeldatei (TOML)
        #[arg(long)]
        rules: PathBuf,
        /// Wirklich verschieben (in Quarantäne bzw. Zielordner)
        #[arg(long)]
        apply: bool,
    },
    /// Eine Quarantäne-Sitzung rückgängig machen
    Undo {
        /// Pfad zum undo.json oder zum Sitzungsordner; ohne Angabe: neueste Sitzung unter --root
        journal: Option<PathBuf>,
        /// Scan-Root, dessen neueste Quarantäne-Sitzung zurückgenommen wird
        #[arg(long)]
        root: Option<PathBuf>,
    },
    /// Automatik: alles Sichere in Quarantäne, Unsicheres nur auflisten. Ohne --apply Vorschau.
    Auto {
        #[command(flatten)]
        scan: ScanArgs,
        /// Wirklich verschieben
        #[arg(long)]
        apply: bool,
        /// Auch die unsicheren Einträge verschieben (ausdrückliche Entscheidung)
        #[arg(long)]
        include_unsure: bool,
        /// Duplikatsuche überspringen (schneller)
        #[arg(long)]
        no_dupes: bool,
        #[arg(long)]
        json: bool,
    },
    /// Sortier-Automatik: lose Dateien und zusammenhängende Ordner nach Kategorie einsortieren
    Organize {
        #[command(flatten)]
        scan: ScanArgs,
        /// Jahres-Unterordner anlegen (Bilder/2024/…)
        #[arg(long)]
        by_year: bool,
        /// Wirklich verschieben
        #[arg(long)]
        apply: bool,
        /// Auch die unsicheren Einträge verschieben
        #[arg(long)]
        include_unsure: bool,
        #[arg(long)]
        json: bool,
    },
    /// Quarantäne-Sitzungen eines Ordners auflisten
    Quarantine {
        /// Scan-Root, dessen Quarantäne gezeigt wird
        root: PathBuf,
    },
    /// Quarantäne endgültig löschen (die einzige löschende Operation)
    Purge {
        /// Pfad zum undo.json oder zum Sitzungsordner
        journal: Option<PathBuf>,
        /// Scan-Root; mit --all alle Sitzungen, sonst die älteste
        #[arg(long)]
        root: Option<PathBuf>,
        #[arg(long)]
        all: bool,
        /// Ohne diese Angabe wird nur angezeigt, was gelöscht würde
        #[arg(long)]
        yes: bool,
    },
    /// Beispiel-Regeldatei ausgeben
    ExampleRules,
}

/// Returns `Some(path)` when the GUI should start (with an optional preselected folder),
/// `None` when a CLI command ran to completion.
pub fn run(cli: Cli) -> anyhow::Result<Option<Option<PathBuf>>> {
    let now = SystemTime::now();
    match cli.command {
        None => return Ok(Some(None)),
        Some(Command::Gui { path }) => return Ok(Some(path)),
        Some(Command::Scan { scan, json, top }) => {
            let result = scan.run()?;
            if json {
                print_json(&result)?;
            } else {
                print_overview(&result, top, now);
            }
        }
        Some(Command::Old {
            scan,
            days,
            use_atime,
            limit,
            json,
        }) => {
            let result = scan.run()?;
            let mut basis = AgeBasis::Modified;
            if use_atime {
                let rep = age::atime_report(&result);
                eprintln!("{}", rep.explain());
                if rep.reliable {
                    basis = AgeBasis::Accessed;
                }
            }
            let old = age::find_old(&result, days, basis, now);
            if json {
                let rows: Vec<_> = old
                    .iter()
                    .map(|o| {
                        let f = &result.files[o.file];
                        serde_json::json!({"path": f.path, "size": f.size, "age_days": o.age_days})
                    })
                    .collect();
                println!("{}", serde_json::to_string_pretty(&rows)?);
            } else {
                let total: u64 = old.iter().map(|o| result.files[o.file].size).sum();
                println!(
                    "{} Dateien seit mindestens {days} Tagen unverändert, zusammen {}",
                    old.len(),
                    human(total)
                );
                for o in old.iter().take(limit) {
                    let f = &result.files[o.file];
                    println!(
                        "{:>5} Tage  {:>10}  {}",
                        o.age_days,
                        human(f.size),
                        f.path.display()
                    );
                }
                if old.len() > limit {
                    println!("... und {} weitere (--limit erhöhen)", old.len() - limit);
                }
            }
        }
        Some(Command::Dupes {
            scan,
            min_size,
            json,
        }) => {
            let result = scan.run()?;
            let min = rules::parse_size(&min_size)?;
            let groups =
                dupes::find_duplicates(&result, min, Arc::new(AtomicBool::new(false)), None);
            if json {
                let rows: Vec<_> = groups
                    .iter()
                    .map(|g| {
                        let paths: Vec<_> = g.files.iter().map(|&i| &result.files[i].path).collect();
                        serde_json::json!({"size": g.size, "hash": g.hash, "wasted": g.wasted(), "files": paths})
                    })
                    .collect();
                println!("{}", serde_json::to_string_pretty(&rows)?);
            } else {
                let wasted: u64 = groups.iter().map(|g| g.wasted()).sum();
                println!(
                    "{} Duplikat-Gruppen, {} könnten frei werden",
                    groups.len(),
                    human(wasted)
                );
                for g in &groups {
                    println!(
                        "\n{} × {} (verschwendet {})",
                        g.files.len(),
                        human(g.size),
                        human(g.wasted())
                    );
                    for &i in &g.files {
                        println!("    {}", result.files[i].path.display());
                    }
                }
            }
        }
        Some(Command::Empty { scan, json }) => {
            let result = scan.run()?;
            let dirs = dupes::empty_dirs_toplevel(&result);
            let files = dupes::zero_byte_files(&result);
            if json {
                let d: Vec<_> = dirs.iter().map(|&i| &result.dirs[i].path).collect();
                let f: Vec<_> = files.iter().map(|&i| &result.files[i].path).collect();
                println!(
                    "{}",
                    serde_json::to_string_pretty(
                        &serde_json::json!({"empty_dirs": d, "empty_files": f})
                    )?
                );
            } else {
                println!("{} leere Ordner (oberste Ebene):", dirs.len());
                for &i in &dirs {
                    println!("    {}", result.dirs[i].path.display());
                }
                println!("\n{} Dateien mit 0 Byte:", files.len());
                for &i in &files {
                    println!("    {}", result.files[i].path.display());
                }
            }
        }
        Some(Command::Clean {
            scan,
            rules: rules_path,
            apply,
        }) => {
            let compiled = rules::load_rules(&rules_path)?;
            let result = scan.run()?;
            let ctx = context::build(&result);
            let matches = rules::apply_rules(&result, &ctx, &compiled, now);
            let plan = matches.plan.clone();
            print_plan(&plan);
            if let Some(note) = matches.left_out() {
                println!("{note}");
            }
            finish_auto(&plan, apply)?;
        }
        Some(Command::Undo { journal, root }) => {
            let path = match (journal, root) {
                (Some(j), _) if j.is_dir() => j.join(actions::JOURNAL_FILE),
                (Some(j), _) => j,
                (None, Some(r)) => actions::list_journals(&r)
                    .into_iter()
                    .next()
                    .context("Keine Quarantäne-Sitzung unter diesem Root gefunden")?,
                (None, None) => anyhow::bail!("Bitte Journal-Pfad oder --root angeben"),
            };
            let rep = actions::undo(&path)?;
            println!(
                "{} Einträge wiederhergestellt, {} Konflikte.",
                rep.restored,
                rep.conflicts.len()
            );
            for (p, e) in &rep.conflicts {
                println!("    KONFLIKT {}: {e}", p.display());
            }
        }
        Some(Command::Auto {
            scan,
            apply,
            include_unsure,
            no_dupes,
            json,
        }) => {
            let result = scan.run()?;
            let ctx = context::build(&result);
            let groups = if no_dupes {
                None
            } else {
                Some(dupes::find_duplicates(
                    &result,
                    1,
                    Arc::new(AtomicBool::new(false)),
                    None,
                ))
            };
            let t = triage::assess(
                &result,
                &ctx,
                groups.as_deref(),
                &TriageOptions::default(),
                now,
            );
            if json {
                println!("{}", serde_json::to_string_pretty(&t)?);
                return Ok(None);
            }
            for n in &t.notes {
                println!("{n}");
            }
            print_candidates("Sicher (wird verschoben)", &t.safe, &result);
            print_candidates("Unsicher (bitte entscheiden)", &t.unsure, &result);
            if t.protected > 0 {
                println!(
                    "\n{} Einträge in geschützten Bereichen übersprungen.",
                    t.protected
                );
            }
            let plan = t.to_plan(&result.root, include_unsure);
            finish_auto(&plan, apply)?;
        }
        Some(Command::Organize {
            scan,
            by_year,
            apply,
            include_unsure,
            json,
        }) => {
            let result = scan.run()?;
            let ctx = context::build(&result);
            let opts = OrganizeOptions {
                by_year,
                ..Default::default()
            };
            let p = organize::plan_organize(&result, &ctx, &opts, now);
            if json {
                println!("{}", serde_json::to_string_pretty(&p)?);
                return Ok(None);
            }
            for n in &p.notes {
                println!("{n}");
            }
            print_profiles(&p, &result);
            print_candidates("Sicher (wird verschoben)", &p.safe, &result);
            print_candidates("Unsicher (bitte entscheiden)", &p.unsure, &result);
            print_after(&p.after);
            let plan = p.to_plan(&result.root, include_unsure);
            finish_auto(&plan, apply)?;
        }
        Some(Command::Quarantine { root }) => {
            let sessions: Vec<_> = actions::list_journals(&root)
                .iter()
                .filter_map(|j| actions::session_info(j))
                .collect();
            if sessions.is_empty() {
                println!("Keine Quarantäne-Sitzungen unter {}", root.display());
            }
            for s in &sessions {
                println!(
                    "{}  {:>4} Einträge  {:>6} Dateien  {:>10}  {}",
                    s.name,
                    s.entries,
                    s.files,
                    human(s.bytes),
                    if s.undone { "wiederhergestellt" } else { "" }
                );
            }
        }
        Some(Command::Purge {
            journal,
            root,
            all,
            yes,
        }) => {
            let targets: Vec<PathBuf> = match (journal, root) {
                (Some(j), _) if j.is_dir() => vec![j.join(actions::JOURNAL_FILE)],
                (Some(j), _) => vec![j],
                (None, Some(r)) => {
                    let mut js = actions::list_journals(&r);
                    if !all {
                        js.truncate(1);
                    }
                    js
                }
                (None, None) => anyhow::bail!("Bitte Journal-Pfad oder --root angeben"),
            };
            for j in &targets {
                let Some(s) = actions::session_info(j) else {
                    continue;
                };
                if yes {
                    let r = actions::purge_session(j)?;
                    println!(
                        "{} gelöscht: {} Dateien, {}",
                        s.name,
                        r.removed,
                        human(r.bytes)
                    );
                } else {
                    println!(
                        "Würde löschen: {} ({} Dateien, {})",
                        s.name,
                        s.files,
                        human(s.bytes)
                    );
                }
            }
            if !yes {
                println!("Mit --yes wird endgültig gelöscht.");
            }
        }
        Some(Command::ExampleRules) => print!("{}", rules::EXAMPLE_RULES),
    }
    Ok(None)
}

fn print_json(result: &ScanResult) -> anyhow::Result<()> {
    let sizes = analysis::category_sizes(result);
    let dirs: Vec<_> = result
        .dirs
        .iter()
        .enumerate()
        .map(|(i, d)| {
            let cats: serde_json::Map<String, serde_json::Value> = Category::ALL
                .iter()
                .map(|c| {
                    (
                        c.label().to_string(),
                        serde_json::json!(sizes[i][*c as usize]),
                    )
                })
                .collect();
            serde_json::json!({
                "path": d.path, "depth": d.depth, "size": d.total_size,
                "files": d.total_files, "dirs": d.total_dirs, "categories": cats
            })
        })
        .collect();
    let out = serde_json::json!({
        "root": result.root,
        "total_size": result.total_size(),
        "total_files": result.total_files(),
        "errors": result.errors,
        "skipped": result.skipped,
        "dirs": dirs,
    });
    println!("{}", serde_json::to_string_pretty(&out)?);
    Ok(())
}

fn print_overview(result: &ScanResult, top: usize, now: SystemTime) {
    let Some(root) = result.root_node() else {
        println!("Leeres Ergebnis.");
        return;
    };
    println!("\n{}", root.path.display());
    println!(
        "  {} Dateien, {} Ordner, {}",
        root.total_files,
        root.total_dirs,
        human(root.total_size)
    );

    let sizes = analysis::category_sizes(result);
    println!("\nNach Kategorie:");
    let mut cats: Vec<_> = Category::ALL
        .iter()
        .map(|c| (c, sizes[0][*c as usize]))
        .collect();
    cats.sort_by_key(|a| std::cmp::Reverse(a.1));
    for (c, b) in cats.into_iter().filter(|(_, b)| *b > 0) {
        println!(
            "  {:<12} {:>10}  {}",
            c.label(),
            human(b),
            bar(b, root.total_size, 30)
        );
    }

    println!("\nNach Alter (Änderungsdatum):");
    for b in analysis::age_histogram(result, 0, now) {
        println!(
            "  {:<12} {:>7} Dateien {:>10}  {}",
            b.label,
            b.files,
            human(b.bytes),
            bar(b.bytes, root.total_size, 30)
        );
    }

    println!("\nGrößte Unterordner:");
    let mut children: Vec<_> = root.children.iter().map(|&c| &result.dirs[c]).collect();
    children.sort_by_key(|a| std::cmp::Reverse(a.total_size));
    for d in children.iter().take(top) {
        println!(
            "  {:>10}  {:>7} Dateien  {}",
            human(d.total_size),
            d.total_files,
            d.name()
        );
    }

    println!("\nGrößte Dateien:");
    for id in analysis::largest_files(result, top) {
        let f = &result.files[id];
        println!(
            "  {:>10}  {}",
            human(f.size),
            result.relative(&f.path).display()
        );
    }

    if !result.errors.is_empty() {
        println!("\n{} Pfade nicht lesbar, z. B.:", result.errors.len());
        for e in result.errors.iter().take(5) {
            println!("  {}: {}", e.path.display(), e.message);
        }
    }
}

fn bar(value: u64, total: u64, width: usize) -> String {
    if total == 0 {
        return String::new();
    }
    let n = ((value as f64 / total as f64) * width as f64).round() as usize;
    "█".repeat(n.min(width))
}

fn print_plan(plan: &Plan) {
    println!(
        "Plan: {} Einträge, {}",
        plan.len(),
        human(plan.total_bytes())
    );
    for a in &plan.actions {
        let what = match plan.move_target(a) {
            Some(dest) => format!("→ {}", dest.display()),
            None => "Quarantäne".to_string(),
        };
        println!(
            "  [{}] {:>10}  {}  {}",
            a.reason,
            human(a.size),
            a.source.display(),
            what
        );
    }
}

fn print_candidates(title: &str, list: &[Candidate], result: &ScanResult) {
    let bytes: u64 = list.iter().map(Candidate::size).sum();
    println!("\n== {title}: {} Einträge, {}", list.len(), human(bytes));
    for (label, n, b) in Triage::summary(list) {
        println!("   {label}: {n} ({})", human(b));
    }
    for c in list {
        let what = match &c.action.kind {
            ActionKind::Quarantine => "Quarantäne".to_string(),
            ActionKind::MoveTo(t) => format!("→ {}", t.display()),
        };
        println!(
            "  {:>10}  {}  {}",
            if c.action.is_dir {
                "Ordner".into()
            } else {
                human(c.size())
            },
            result.relative(&c.action.source).display(),
            what
        );
        println!("              {}", c.reason);
        for h in &c.hints {
            println!("              {h}");
        }
    }
}

fn print_profiles(p: &OrganizePlan, result: &ScanResult) {
    if p.profiles.is_empty() {
        return;
    }
    println!("\n== Unterordner");
    for f in &p.profiles {
        let verdict = match &f.verdict {
            FolderVerdict::Keep(why) if why.is_empty() => "bleibt".to_string(),
            FolderVerdict::Keep(why) => format!("bleibt ({why})"),
            FolderVerdict::MoveWhole(c) => format!("wird als Ganzes nach {} verschoben", c.label()),
            FolderVerdict::Distribute => "gemischt, Verteilung vorgeschlagen (unsicher)".into(),
            FolderVerdict::Unsure(why) => format!("unsicher ({why})"),
        };
        println!(
            "  {:<32} {:>6} Dateien {:>10}  {}",
            result.relative(&result.dirs[f.dir].path).display(),
            f.files,
            human(f.bytes),
            verdict
        );
        if !f.composition.is_empty() {
            println!("  {:<32} {}", "", f.composition);
        }
    }
}

fn print_after(after: &AfterTree) {
    println!("\n== Struktur danach (nur sichere Aktionen)");
    for f in &after.folders {
        let name = if f.rel.is_empty() {
            "(lose im Ordner)"
        } else {
            f.rel.as_str()
        };
        println!(
            "  {:<32} {:>6} Dateien {:>10}  (+{} eingehend)",
            name,
            f.files(),
            human(f.bytes()),
            f.incoming.len()
        );
        for inc in f.incoming.iter().take(8) {
            println!(
                "      + {}  ← {}",
                inc.name,
                inc.from.as_deref().unwrap_or("?")
            );
        }
        if f.incoming.len() > 8 {
            println!("      … und {} weitere", f.incoming.len() - 8);
        }
    }
}

fn finish_auto(plan: &Plan, apply: bool) -> anyhow::Result<()> {
    if plan.is_empty() {
        println!("\nNichts zu tun.");
        return Ok(());
    }
    if !apply {
        println!(
            "\nVorschau: {} Einträge, {}. Mit --apply wird verschoben.",
            plan.len(),
            human(plan.total_bytes())
        );
        return Ok(());
    }
    let report = actions::execute(plan, false)?;
    println!("\n{}", report.summary(usize::MAX));
    if let Some(j) = &report.journal_path {
        println!("Rückgängig mit: tidyscan undo \"{}\"", j.display());
    }
    Ok(())
}
