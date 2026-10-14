//! Declarative cleanup rules loaded from TOML.
//!
//! ```toml
//! [[rule]]
//! name = "Alte Installer"
//! ext = ["exe", "msi", "dmg"]
//! older_than_days = 90
//! action = "quarantine"
//!
//! [[rule]]
//! name = "Screenshots archivieren"
//! glob = "**/Screenshot*.png"
//! action = "move"
//! move_to = "Archiv/Screenshots/{year}"
//! ```
//!
//! Rules never reach into protected areas, and into projects only when a rule says
//! `include_projects = true`.

use std::path::{Path, PathBuf};
use std::time::SystemTime;

use anyhow::{Context, bail};
use globset::{GlobBuilder, GlobMatcher};
use serde::{Deserialize, Serialize};

use crate::actions::{Action, Plan};
use crate::analysis::Category;
use crate::context::DirContext;
use crate::model::{FileEntry, ScanResult, local_datetime};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleAction {
    Quarantine,
    Move,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub name: String,
    #[serde(default)]
    pub ext: Vec<String>,
    #[serde(default)]
    pub glob: Option<String>,
    #[serde(default)]
    pub category: Option<String>,
    #[serde(default)]
    pub older_than_days: Option<u64>,
    #[serde(default)]
    pub min_size: Option<String>,
    #[serde(default)]
    pub max_size: Option<String>,
    pub action: RuleAction,
    #[serde(default)]
    pub move_to: Option<String>,
    /// Also apply inside software projects. Off by default: a rule like "old archives"
    /// should not pull release artefacts out of a repository.
    #[serde(default)]
    pub include_projects: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RuleFile {
    #[serde(default)]
    pub rule: Vec<Rule>,
}

/// A rule with its patterns compiled and sizes parsed.
pub struct CompiledRule {
    pub rule: Rule,
    glob: Option<GlobMatcher>,
    category: Option<Category>,
    min_size: Option<u64>,
    max_size: Option<u64>,
}

/// Parse sizes like `500`, `10K`, `1.5M`, `2G` (binary multiples).
pub fn parse_size(s: &str) -> anyhow::Result<u64> {
    let s = s.trim();
    let (num, mult) = match s.chars().last() {
        Some(c) if c.is_ascii_alphabetic() => {
            let m = match c.to_ascii_uppercase() {
                'K' => 1u64 << 10,
                'M' => 1 << 20,
                'G' => 1 << 30,
                'T' => 1 << 40,
                _ => bail!("Unbekannte Größeneinheit in '{s}'"),
            };
            (&s[..s.len() - 1], m)
        }
        _ => (s, 1),
    };
    let n: f64 = num
        .trim()
        .parse()
        .with_context(|| format!("Ungültige Größe '{s}'"))?;
    Ok((n * mult as f64) as u64)
}

fn parse_category(s: &str) -> anyhow::Result<Category> {
    let s = s.to_ascii_lowercase();
    Category::ALL
        .into_iter()
        .find(|c| c.label().to_ascii_lowercase() == s || format!("{c:?}").to_ascii_lowercase() == s)
        .with_context(|| format!("Unbekannte Kategorie '{s}'"))
}

impl CompiledRule {
    pub fn compile(rule: Rule) -> anyhow::Result<Self> {
        if rule.action == RuleAction::Move && rule.move_to.is_none() {
            bail!("Regel '{}': action = \"move\" braucht move_to", rule.name);
        }
        if rule.ext.is_empty()
            && rule.glob.is_none()
            && rule.category.is_none()
            && rule.older_than_days.is_none()
            && rule.min_size.is_none()
            && rule.max_size.is_none()
        {
            bail!(
                "Regel '{}' hat keine Bedingung und würde alles treffen",
                rule.name
            );
        }
        let glob = match &rule.glob {
            Some(g) => Some(
                // `*` stays within one folder, only `**` crosses folder boundaries.
                // Otherwise "Screenshot*" would swallow everything below "Screenshots/".
                GlobBuilder::new(g)
                    .literal_separator(true)
                    .build()
                    .with_context(|| format!("Regel '{}': ungültiges Glob", rule.name))?
                    .compile_matcher(),
            ),
            None => None,
        };
        let category = rule.category.as_deref().map(parse_category).transpose()?;
        let min_size = rule.min_size.as_deref().map(parse_size).transpose()?;
        let max_size = rule.max_size.as_deref().map(parse_size).transpose()?;
        Ok(Self {
            rule,
            glob,
            category,
            min_size,
            max_size,
        })
    }

    pub fn matches(&self, file: &FileEntry, relative: &Path, now: SystemTime) -> bool {
        if !self.rule.ext.is_empty() {
            let Some(ext) = file.extension() else {
                return false;
            };
            if !self.rule.ext.iter().any(|e| e.eq_ignore_ascii_case(&ext)) {
                return false;
            }
        }
        if let Some(g) = &self.glob {
            // Match against a forward-slashed relative path so rules are portable.
            let rel = relative.to_string_lossy().replace('\\', "/");
            if !g.is_match(&rel) {
                return false;
            }
        }
        if let Some(c) = self.category
            && Category::of_file(file) != c
        {
            return false;
        }
        if let Some(days) = self.rule.older_than_days {
            match file.age_days(now) {
                Some(age) if age >= days => {}
                _ => return false,
            }
        }
        if let Some(min) = self.min_size
            && file.size < min
        {
            return false;
        }
        if let Some(max) = self.max_size
            && file.size > max
        {
            return false;
        }
        true
    }

    /// Resolve `{year}`, `{month}`, `{ext}`, `{name}` in `move_to`.
    pub fn target_for(&self, file: &FileEntry) -> Option<PathBuf> {
        let template = self.rule.move_to.as_ref()?;
        let ts = file.modified.and_then(local_datetime);
        let year = ts.map_or("unbekannt".to_string(), |t| t.year().to_string());
        let month = ts.map_or("unbekannt".to_string(), |t| {
            format!("{:02}", t.month() as u8)
        });
        let out = template
            .replace("{year}", &year)
            .replace("{month}", &month)
            .replace("{ext}", &file.extension().unwrap_or_default())
            .replace("{name}", &file.name());
        // Templates use forward slashes. A relative target is rebuilt from its
        // components so it uses the platform separator; an absolute one (another
        // drive, a network share) must keep its root and is taken as written.
        let native = if cfg!(windows) {
            out.replace('/', "\\")
        } else {
            out.clone()
        };
        if Path::new(&native).is_absolute() || native.starts_with(['/', '\\']) {
            return Some(PathBuf::from(native));
        }
        Some(
            out.split(['/', '\\'])
                .filter(|c| !c.is_empty())
                .collect::<PathBuf>(),
        )
    }
}

pub fn load_rules(path: &Path) -> anyhow::Result<Vec<CompiledRule>> {
    let text = fs_read(path)?;
    parse_rules(&text)
}

fn fs_read(path: &Path) -> anyhow::Result<String> {
    std::fs::read_to_string(path).with_context(|| format!("Regeldatei {} lesen", path.display()))
}

pub fn parse_rules(text: &str) -> anyhow::Result<Vec<CompiledRule>> {
    let file: RuleFile = toml::from_str(text).context("Regeldatei parsen")?;
    file.rule.into_iter().map(CompiledRule::compile).collect()
}

/// Result of applying rules: the plan, and how many matches were left alone.
#[derive(Debug, Clone)]
pub struct RuleMatches {
    pub plan: Plan,
    /// Matches inside protected areas, which no rule can reach.
    pub protected: usize,
    /// Matches inside projects for rules without `include_projects`.
    pub in_projects: usize,
}

/// Build a plan by applying the first matching rule to every file.
pub fn apply_rules(
    result: &ScanResult,
    ctx: &DirContext,
    rules: &[CompiledRule],
    now: SystemTime,
) -> RuleMatches {
    let mut out = RuleMatches {
        plan: Plan::new(&result.root),
        protected: 0,
        in_projects: 0,
    };
    for file in &result.files {
        let rel = result.relative(&file.path);
        let Some(rule) = rules.iter().find(|r| r.matches(file, &rel, now)) else {
            continue;
        };
        if ctx.protected[file.parent] {
            out.protected += 1;
            continue;
        }
        if ctx.project[file.parent] && !rule.rule.include_projects {
            out.in_projects += 1;
            continue;
        }
        let action = match rule.rule.action {
            RuleAction::Quarantine => Action::quarantine_file(file, &rule.rule.name),
            RuleAction::Move => match rule.target_for(file) {
                Some(t) => Action::move_file(file, t, &rule.rule.name),
                None => continue,
            },
        };
        out.plan.push(action);
    }
    out
}

impl RuleMatches {
    /// One line about what was left out, or `None` when nothing was.
    pub fn left_out(&self) -> Option<String> {
        let mut parts = Vec::new();
        if self.protected > 0 {
            parts.push(format!("{} in geschützten Bereichen", self.protected));
        }
        if self.in_projects > 0 {
            parts.push(format!(
                "{} in Projektordnern (include_projects = true schließt sie ein)",
                self.in_projects
            ));
        }
        (!parts.is_empty()).then(|| format!("Nicht übernommen: {}.", parts.join(", ")))
    }
}

pub const EXAMPLE_RULES: &str = r#"# Beispielregeln für tidyscan. Die erste passende Regel gewinnt.
# Größen: 500, 10K, 1.5M, 2G. Platzhalter in move_to: {year} {month} {ext} {name}.
# Globs sind relativ zum gescannten Ordner: * bleibt innerhalb eines Ordners,
# ** geht über Ordnergrenzen. Geschützte Bereiche werden nie angefasst, Projektordner
# nur mit include_projects = true.

[[rule]]
name = "Alte Installer in Quarantäne"
ext = ["exe", "msi", "msix", "dmg", "pkg", "deb", "rpm", "appimage"]
older_than_days = 90
action = "quarantine"

[[rule]]
name = "Alte Archive in Quarantäne"
category = "archive"
older_than_days = 365
min_size = "10M"
action = "quarantine"

[[rule]]
name = "Screenshots nach Jahr archivieren"
glob = "**/Screenshot*.png"
older_than_days = 30
action = "move"
move_to = "Archiv/Screenshots/{year}"

# Greift nur, wenn direkt im gescannten Ordner ein Ordner "Downloads" liegt.
[[rule]]
name = "Alte Downloads sortieren"
glob = "Downloads/**"
older_than_days = 180
action = "move"
move_to = "Archiv/Downloads/{year}-{month}"
"#;
