//! Importable rule sets.
//!
//! # Why this exists
//!
//! Two problems with one shape.
//!
//! A rule that grants the camera at the KERNEL layer needs an `exe_path`, and
//! `SetRule` over D-Bus cannot carry one. So the only way to allowlist a binary
//! was to stop the daemon and hand-edit `config.toml` — a file the daemon
//! rewrites wholesale, destroying comments and ordering.
//!
//! And a fresh install has no camera at all: `/usr/bin/pipewire` is denied
//! `/dev/video0`, so PipeWire never creates a camera node and the device
//! vanishes from `hwprivacy-ctl devices`. The fix is a rule with an `exe_path`,
//! which is the first problem again.
//!
//! # Why data and not code
//!
//! `d-executable-is-the-principal` rules out per-application coupling. So the
//! MECHANISM is generic and the CONTENT is data the user opts into: a third
//! party contributes a file, never a patch. The shipped desktop baseline is
//! itself just a preset that `hwprivacy-daemon install` imports.
//!
//! # Why candidate LISTS
//!
//! `/usr/lib/firefox-esr/firefox-esr` is Debian's path. A preset that named one
//! path would be wrong everywhere else, and a preset that named none would be
//! useless for the kernel layer. Each entry carries several candidates; the
//! first that exists wins and the import says which.

use crate::config::{sanitize_rule_name, AppRule, Permission};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// A named set of rules that can be imported into a config.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Preset {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default, rename = "app")]
    pub apps: Vec<PresetApp>,
}

/// One application's proposed rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresetApp {
    pub name: String,
    #[serde(default = "deny")]
    pub microphone: Permission,
    #[serde(default = "deny")]
    pub camera: Permission,
    #[serde(default = "deny")]
    pub monitor: Permission,
    /// Absolute paths to try, in order. The first that exists wins.
    ///
    /// Only meaningful when the entry grants the camera — that is the one
    /// permission the kernel layer enforces, and the only one that needs an
    /// inode.
    #[serde(default)]
    pub exe_candidates: Vec<String>,
}

fn deny() -> Permission {
    Permission::Deny
}

/// What importing one entry would do, or did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Added, with the candidate that resolved (if any).
    Added { exe_path: Option<String> },
    /// A rule for this app already exists and was left completely alone.
    SkippedRuleExists,
    /// Wants the camera but no candidate resolved on this machine.
    SkippedNoBinary { tried: Vec<String> },
    /// The name could never become a usable rule key.
    SkippedBadName,
}

impl Outcome {
    pub fn added(&self) -> bool {
        matches!(self, Outcome::Added { .. })
    }

    /// One line, for `hwprivacy-ctl` and the D-Bus report.
    pub fn describe(&self) -> String {
        match self {
            Outcome::Added { exe_path: Some(p) } => format!("added, binary {p}"),
            Outcome::Added { exe_path: None } => {
                "added (PipeWire layer only — grants no camera, so needs no binary)".into()
            }
            Outcome::SkippedRuleExists => {
                "skipped — you already have a rule for this app, and an import never changes one"
                    .into()
            }
            Outcome::SkippedNoBinary { tried } => format!(
                "skipped — wants the camera but none of these exist here: {}",
                tried.join(", ")
            ),
            Outcome::SkippedBadName => "skipped — not a usable rule name".into(),
        }
    }
}

/// The result of planning an import. Identical whether or not it is applied,
/// so the preview cannot disagree with what happens.
#[derive(Debug, Clone)]
pub struct ImportPlan {
    pub preset: String,
    pub entries: Vec<(String, Outcome, Option<AppRule>)>,
}

impl ImportPlan {
    pub fn added_count(&self) -> usize {
        self.entries.iter().filter(|(_, o, _)| o.added()).count()
    }
}

impl Preset {
    pub fn parse(text: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(text)
    }

    /// Work out what importing this preset would do, without doing it.
    ///
    /// `exists` decides whether a candidate path is present — injected so the
    /// safety properties can be tested without touching the filesystem.
    /// `has_rule` reports whether the config already has a rule for a name.
    pub fn plan<E, H>(&self, exists: E, has_rule: H) -> ImportPlan
    where
        E: Fn(&str) -> bool,
        H: Fn(&str) -> bool,
    {
        let mut entries = Vec::new();

        for app in &self.apps {
            let Some(key) = sanitize_rule_name(&app.name) else {
                entries.push((app.name.clone(), Outcome::SkippedBadName, None));
                continue;
            };

            // Never widen a decision the user already made. Not "merge", not
            // "fill in the missing exe_path" — adding a path to an existing
            // `camera = allow` would grant kernel access nobody asked for.
            if has_rule(&key) {
                entries.push((key, Outcome::SkippedRuleExists, None));
                continue;
            }

            let resolved = app.exe_candidates.iter().find(|c| exists(c)).cloned();

            // A camera grant with no binary is the exact state
            // `kernel_camera_gaps()` exists to warn about: config reads
            // `allow`, the kernel denies it, and it looks like a broken
            // allowlist. Refuse to create one.
            if app.camera == Permission::Allow && resolved.is_none() {
                entries.push((
                    key,
                    Outcome::SkippedNoBinary {
                        tried: app.exe_candidates.clone(),
                    },
                    None,
                ));
                continue;
            }

            // A preset states all three categories (`PresetApp` defaults each
            // to deny), so every one is a deliberate opinion and is wrapped in
            // `Some`. This is the one place a full three-category rule is
            // still correct to write — a preset is a rule set, not a
            // single-category grant.
            let rule = AppRule {
                app_name: key.clone(),
                microphone: Some(app.microphone),
                camera: Some(app.camera),
                monitor: Some(app.monitor),
                exe_path: resolved.clone(),
            };
            entries.push((key, Outcome::Added { exe_path: resolved }, Some(rule)));
        }

        ImportPlan {
            preset: self.name.clone(),
            entries,
        }
    }
}

/// Directories searched for presets, most specific first.
///
/// A user file shadows a shipped one of the same name, so a preset with a wrong
/// path for this machine can be corrected without root and without editing a
/// packaged file that the next upgrade would overwrite.
pub fn preset_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Some(cfg) = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
    {
        dirs.push(cfg.join("hwprivacy").join("presets"));
    }
    dirs.push(PathBuf::from("/usr/share/hwprivacy/presets"));
    dirs
}

/// Every preset visible, as `(name, path)`, user files shadowing system ones.
pub fn discover(dirs: &[PathBuf]) -> Vec<(String, PathBuf)> {
    let mut found: Vec<(String, PathBuf)> = Vec::new();
    for dir in dirs {
        let Ok(entries) = std::fs::read_dir(dir) else {
            continue;
        };
        for e in entries.flatten() {
            let path = e.path();
            if path.extension().and_then(|x| x.to_str()) != Some("toml") {
                continue;
            }
            let Some(stem) = path.file_stem().and_then(|x| x.to_str()) else {
                continue;
            };
            if found.iter().any(|(n, _)| n == stem) {
                continue; // an earlier (more specific) directory already won
            }
            found.push((stem.to_string(), path));
        }
    }
    found.sort_by(|a, b| a.0.cmp(&b.0));
    found
}

/// Load a preset by name from the given directories.
pub fn load(name: &str, dirs: &[PathBuf]) -> anyhow::Result<Preset> {
    let (_, path) = discover(dirs)
        .into_iter()
        .find(|(n, _)| n == name)
        .ok_or_else(|| anyhow::anyhow!("no preset named '{name}'"))?;
    let text = std::fs::read_to_string(&path)
        .map_err(|e| anyhow::anyhow!("cannot read {}: {e}", path.display()))?;
    Preset::parse(&text).map_err(|e| anyhow::anyhow!("{} is not a valid preset: {e}", path.display()))
}

/// Does this path exist as a regular file? The real `exists` for [`Preset::plan`].
pub fn path_exists(p: &str) -> bool {
    Path::new(p).is_file()
}

#[cfg(test)]
mod tests {
    use super::*;

    const BROWSERS: &str = r#"
name = "browsers"
description = "Common web browsers"

[[app]]
name = "firefox"
microphone = "ask_each"
camera = "allow"
monitor = "deny"
exe_candidates = ["/usr/lib/firefox-esr/firefox-esr", "/usr/lib/firefox/firefox"]
"#;

    fn nothing_exists(_: &str) -> bool {
        false
    }
    fn no_rules(_: &str) -> bool {
        false
    }

    #[test]
    fn a_preset_parses_into_entries() {
        let p = Preset::parse(BROWSERS).expect("parses");
        assert_eq!(p.name, "browsers");
        assert_eq!(p.apps.len(), 1);
        assert_eq!(p.apps[0].camera, Permission::Allow);
        assert_eq!(p.apps[0].exe_candidates.len(), 2);
    }

    /// The portability property: a preset names several paths and the machine
    /// decides. Second candidate here, because the first does not exist.
    #[test]
    fn the_first_candidate_that_exists_wins() {
        let p = Preset::parse(BROWSERS).unwrap();
        let plan = p.plan(|c| c == "/usr/lib/firefox/firefox", no_rules);
        assert_eq!(
            plan.entries[0].1,
            Outcome::Added {
                exe_path: Some("/usr/lib/firefox/firefox".into())
            }
        );
        assert_eq!(
            plan.entries[0].2.as_ref().unwrap().exe_path.as_deref(),
            Some("/usr/lib/firefox/firefox")
        );
    }

    #[test]
    fn candidates_are_tried_in_order() {
        let p = Preset::parse(BROWSERS).unwrap();
        let plan = p.plan(|_| true, no_rules); // both exist
        assert_eq!(
            plan.entries[0].1,
            Outcome::Added {
                exe_path: Some("/usr/lib/firefox-esr/firefox-esr".into())
            },
            "the first listed candidate must win"
        );
    }

    /// A camera grant with no binary reads `allow` in config.toml and is denied
    /// by the kernel — exactly what `kernel_camera_gaps()` exists to warn
    /// about, and exactly what looks like a broken allowlist. Refuse to create
    /// one, and say which paths were tried so the user can supply the right
    /// one.
    #[test]
    fn a_camera_grant_with_no_binary_is_refused_not_guessed() {
        let p = Preset::parse(BROWSERS).unwrap();
        let plan = p.plan(nothing_exists, no_rules);
        match &plan.entries[0].1 {
            Outcome::SkippedNoBinary { tried } => {
                assert_eq!(tried.len(), 2, "the report must name what it tried");
                assert!(tried[0].contains("firefox-esr"));
            }
            other => panic!("expected SkippedNoBinary, got {other:?}"),
        }
        assert_eq!(plan.added_count(), 0);
        assert!(plan.entries[0].2.is_none(), "nothing to write");
    }

    /// An entry that grants no camera is PipeWire-only and never needed a
    /// binary — refusing it would make presets useless for microphone rules.
    #[test]
    fn an_entry_without_a_camera_grant_imports_with_no_binary() {
        let p = Preset::parse(
            r#"
name = "audio"
[[app]]
name = "audacity"
microphone = "allow"
"#,
        )
        .unwrap();
        let plan = p.plan(nothing_exists, no_rules);
        assert_eq!(plan.entries[0].1, Outcome::Added { exe_path: None });
        let rule = plan.entries[0].2.as_ref().unwrap();
        assert_eq!(rule.microphone, Some(Permission::Allow));
        // A preset states every category, so an omitted one is a deliberate
        // deny written by PresetApp's default — NOT the `None` that a
        // single-category `set_rule` now leaves behind.
        assert_eq!(
            rule.camera,
            Some(Permission::Deny),
            "a category omitted from a preset is a deliberate deny"
        );
    }

    /// **The property that matters most.** An import must never broaden a
    /// decision the user already made — not overwrite it, not merge into it,
    /// and above all not quietly add an `exe_path` to an existing
    /// `camera = allow`, which would grant kernel access nobody asked for.
    #[test]
    fn an_existing_rule_is_never_touched() {
        let p = Preset::parse(BROWSERS).unwrap();
        let plan = p.plan(|_| true, |name| name == "firefox");
        assert_eq!(plan.entries[0].1, Outcome::SkippedRuleExists);
        assert!(
            plan.entries[0].2.is_none(),
            "there must be nothing for the caller to write"
        );
        assert_eq!(plan.added_count(), 0);
    }

    /// The existence check is against the SANITISED key, so a preset cannot
    /// slip past it by spelling the app differently.
    #[test]
    fn the_existing_rule_check_uses_the_normalised_key() {
        let p = Preset::parse(
            r#"
name = "x"
[[app]]
name = "Firefox [pipewire-pulse]"
microphone = "allow"
"#,
        )
        .unwrap();
        let plan = p.plan(nothing_exists, |name| name == "firefox");
        assert_eq!(plan.entries[0].1, Outcome::SkippedRuleExists);
    }

    /// A preset must not be able to introduce the dead-rule shapes b4 closed.
    #[test]
    fn a_name_that_cannot_become_a_key_is_refused() {
        for bad in ["", "   ", "(pid:9)"] {
            let p = Preset::parse(&format!(
                "name = \"x\"\n[[app]]\nname = \"{bad}\"\nmicrophone = \"allow\"\n"
            ))
            .unwrap();
            let plan = p.plan(nothing_exists, no_rules);
            assert_eq!(plan.entries[0].1, Outcome::SkippedBadName, "{bad:?}");
        }
    }

    /// Stored names are the sanitised key, so an imported rule actually
    /// matches the app it was written for.
    #[test]
    fn imported_rules_are_stored_under_a_key_that_matches() {
        let p = Preset::parse(
            r#"
name = "x"
[[app]]
name = "OBS [pipewire-pulse]"
monitor = "allow"
"#,
        )
        .unwrap();
        let plan = p.plan(nothing_exists, no_rules);
        assert_eq!(plan.entries[0].2.as_ref().unwrap().app_name, "obs");
    }

    #[test]
    fn a_user_preset_shadows_a_system_one_of_the_same_name() {
        let base = std::env::temp_dir().join(format!("hwp-preset-{}", std::process::id()));
        let user = base.join("user");
        let system = base.join("system");
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&user).unwrap();
        std::fs::create_dir_all(&system).unwrap();
        std::fs::write(user.join("browsers.toml"), "name = \"mine\"\n").unwrap();
        std::fs::write(system.join("browsers.toml"), "name = \"theirs\"\n").unwrap();
        std::fs::write(system.join("extra.toml"), "name = \"extra\"\n").unwrap();

        let dirs = vec![user.clone(), system.clone()];
        let found = discover(&dirs);
        assert_eq!(found.len(), 2, "shadowed, not duplicated: {found:?}");

        let loaded = load("browsers", &dirs).unwrap();
        assert_eq!(loaded.name, "mine", "the user's file must win");
        assert!(load("extra", &dirs).is_ok(), "system-only presets still load");
        assert!(load("nope", &dirs).is_err());

        let _ = std::fs::remove_dir_all(&base);
    }

    /// A malformed preset must be a legible error, not a panic and not a
    /// half-import.
    #[test]
    fn a_malformed_preset_is_an_error() {
        assert!(Preset::parse("this is not toml {{{").is_err());
        assert!(
            Preset::parse("name = \"x\"\n[[app]]\nmicrophone = \"allow\"\n").is_err(),
            "an entry with no name cannot be imported"
        );
    }
}
