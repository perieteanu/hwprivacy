//! One program, one rule.
//!
//! A PipeWire prompt names a rule after what the application declares
//! (`firefox developer edition`), and a kernel prompt names it after the binary
//! (`firefox-bin`). One program can so end up with two rules that disagree, and
//! the model already has the fix: one rule carries both identities, `app_name`
//! for layer 1 and `exe_path` for layer 2.
//!
//! # Evidence, never authority
//!
//! What joins the two identities is what a stream says about itself: its name,
//! process id and binary. That can tell the user two rules look like one program.
//! It must never join them unasked: a process could claim a trusted name and
//! inherit that rule's kernel grants, including direct ALSA capture through
//! `microphone = allow`, because the kernel allowlists read `exe_path`.
//!
//! So [`Config::find_rule_splits`] only reports, the merge is an explicit act, a
//! preview comes first because a merge can be a grant (the `d-presets-are-data`
//! precedent), and a disagreement is the user's to settle. It is never an OR.

use crate::config::{Config, Permission};
use crate::DeviceCategory;
use std::collections::BTreeSet;

/// Two rules that look like one program.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleSplit {
    /// The rule matching the name the application declares. It has to survive a
    /// merge, because layer 1 matches by name and nothing else.
    pub name_rule: String,
    /// The rule that owns the binary.
    pub exe_rule: String,
    pub exe_path: String,
    /// The devices the two rules disagree about, e.g. `camera`.
    pub conflicts: Vec<String>,
}

/// The user's answer for a device the two rules disagree about.
#[derive(Debug, Clone, Copy, Default)]
pub struct MergeChoices {
    pub microphone: Option<Permission>,
    pub camera: Option<Permission>,
    pub monitor: Option<Permission>,
}

impl MergeChoices {
    fn get(&self, category: DeviceCategory) -> Option<Permission> {
        match category {
            DeviceCategory::Microphone => self.microphone,
            DeviceCategory::Camera => self.camera,
            DeviceCategory::Monitor => self.monitor,
        }
    }
}

fn opinion(permission: Option<Permission>) -> String {
    permission.map_or_else(|| "no opinion".to_string(), |p| p.to_string())
}

/// What the kernel allowlist gains and loses, in words.
fn allowlist_change(label: &str, before: Vec<(String, Permission)>, after: Vec<(String, Permission)>) -> String {
    let before: BTreeSet<String> = before.into_iter().map(|e| e.0).collect();
    let after: BTreeSet<String> = after.into_iter().map(|e| e.0).collect();
    let gains: Vec<&String> = after.difference(&before).collect();
    let loses: Vec<&String> = before.difference(&after).collect();
    match (gains.is_empty(), loses.is_empty()) {
        (true, true) => format!("Kernel {label} allowlist: no change"),
        _ => {
            let mut parts = Vec::new();
            for path in gains {
                parts.push(format!("GAINS {path}"));
            }
            for path in loses {
                parts.push(format!("loses {path}"));
            }
            format!("Kernel {label} allowlist: {}", parts.join(", "))
        }
    }
}

impl Config {
    /// Which rules look like one program, given observed (normalised name,
    /// executable) pairs.
    ///
    /// A split needs the named rule to have NO binary of its own. A rule that
    /// already has a different one is a different claim, and there is nothing to
    /// merge: two binaries can declare one name (two Firefox builds), and two
    /// paths can be one inode (`pipewire` / `pipewire-pulse`).
    pub fn find_rule_splits(&self, observed: &[(String, String)]) -> Vec<RuleSplit> {
        let mut splits: Vec<RuleSplit> = observed
            .iter()
            .filter_map(|(name, exe_path)| {
                let name_rule = self.find_rule(name)?;
                let exe_rule = self.find_rule_by_exe(exe_path)?;
                if name_rule.exe_path.is_some() || name_rule.app_name == exe_rule.app_name {
                    return None;
                }
                let conflicts = DeviceCategory::all()
                    .iter()
                    .filter(|category| {
                        matches!(
                            (name_rule.get_permission(category), exe_rule.get_permission(category)),
                            (Some(a), Some(b)) if a != b
                        )
                    })
                    .map(|category| category.to_string())
                    .collect();
                Some(RuleSplit {
                    name_rule: name_rule.app_name.clone(),
                    exe_rule: exe_rule.app_name.clone(),
                    exe_path: exe_path.clone(),
                    conflicts,
                })
            })
            .collect();
        splits.sort_by(|a, b| (&a.name_rule, &a.exe_rule).cmp(&(&b.name_rule, &b.exe_rule)));
        splits.dedup();
        splits
    }

    /// Fold rule `from` into rule `into`, on a copy. Returns the resulting config
    /// and a description of the result, or why it was refused. Nothing is changed
    /// here, so the same call serves the preview and the real thing.
    pub fn merge_rules(
        &self,
        from: &str,
        into: &str,
        choices: &MergeChoices,
    ) -> Result<(Config, String), String> {
        let source = self
            .find_rule(from)
            .ok_or_else(|| format!("no rule for '{from}'"))?;
        let target = self
            .find_rule(into)
            .ok_or_else(|| format!("no rule for '{into}'"))?;
        if source.app_name == target.app_name {
            return Err(format!("'{from}' and '{into}' are the same rule"));
        }
        if choices.camera == Some(Permission::WhileInUse) {
            return Err("the camera takes allow or deny, not while_in_use".to_string());
        }
        let exe_path = match (&source.exe_path, &target.exe_path) {
            (Some(a), Some(b)) if a != b => {
                return Err(format!(
                    "'{from}' and '{into}' name different binaries ({a} and {b}), \
                     so they are not one program"
                ));
            }
            (a, b) => b.clone().or_else(|| a.clone()),
        };

        let mut merged = target.clone();
        merged.exe_path = exe_path.clone();
        let mut refused = Vec::new();
        let mut lines = vec![format!("Keeps rule: {}", target.app_name)];

        for category in DeviceCategory::all() {
            let (a, b) = (source.get_permission(category), target.get_permission(category));
            let choice = choices.get(*category);
            let conflict = matches!((a, b), (Some(x), Some(y)) if x != y);
            if choice.is_some() && !conflict {
                refused.push(format!(
                    "{category}: the two rules do not disagree, so there is nothing to choose"
                ));
                continue;
            }
            let result = if conflict {
                let Some(chosen) = choice else {
                    refused.push(format!(
                        "{category}: '{}' says {}, '{}' says {}. Choose one with --{category}",
                        source.app_name,
                        opinion(a),
                        target.app_name,
                        opinion(b),
                    ));
                    continue;
                };
                Some(chosen)
            } else {
                b.or(a)
            };
            merged.set_opinion(category, result);
            lines.push(format!(
                "  {category:<11} {}{}",
                opinion(result),
                if conflict { " (your choice)" } else { "" }
            ));
        }
        if !refused.is_empty() {
            return Err(refused.join("\n"));
        }

        lines.push(format!(
            "  {:<11} {}",
            "binary",
            exe_path.as_deref().unwrap_or("(none)")
        ));
        lines.push(format!("Removes rule: {}", source.app_name));

        let mut after = self.clone();
        let (source_name, target_name) = (source.app_name.clone(), target.app_name.clone());
        after.rules.retain(|r| r.app_name != source_name);
        if let Some(slot) = after.rules.iter_mut().find(|r| r.app_name == target_name) {
            *slot = merged;
        }
        lines.push(allowlist_change(
            "camera",
            self.kernel_camera_allowlist(),
            after.kernel_camera_allowlist(),
        ));
        lines.push(allowlist_change(
            "audio",
            self.kernel_audio_allowlist(),
            after.kernel_audio_allowlist(),
        ));
        Ok((after, lines.join("\n")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AppRule;

    const FIREFOX_BIN: &str = "/home/u/firefox-developer/firefox-bin";

    fn rule(
        name: &str,
        microphone: Option<Permission>,
        camera: Option<Permission>,
        exe: Option<&str>,
    ) -> AppRule {
        AppRule {
            app_name: name.into(),
            microphone,
            camera,
            monitor: None,
            exe_path: exe.map(str::to_string),
        }
    }

    /// The live config on 2026-10-31, as far as it matters here.
    fn live() -> Config {
        let mut c = Config::default();
        c.rules = vec![
            rule(
                "firefox",
                Some(Permission::Allow),
                Some(Permission::Allow),
                Some("/usr/lib/firefox-esr/firefox-esr"),
            ),
            rule(
                "firefox-bin",
                Some(Permission::Allow),
                Some(Permission::Deny),
                Some(FIREFOX_BIN),
            ),
            rule(
                "firefox developer edition",
                Some(Permission::Allow),
                Some(Permission::Allow),
                None,
            ),
            rule("pipewire", Some(Permission::Allow), None, Some("/usr/bin/pipewire")),
            rule(
                "pipewire-pulse",
                Some(Permission::Allow),
                None,
                Some("/usr/bin/pipewire-pulse"),
            ),
        ];
        c
    }

    fn seen(name: &str, exe: &str) -> Vec<(String, String)> {
        vec![(name.to_string(), exe.to_string())]
    }

    fn camera_choice(permission: Permission) -> MergeChoices {
        MergeChoices {
            camera: Some(permission),
            ..Default::default()
        }
    }

    #[test]
    fn the_measured_split_is_found_with_its_conflict() {
        let splits = live().find_rule_splits(&seen("firefox developer edition", FIREFOX_BIN));
        assert_eq!(
            splits,
            vec![RuleSplit {
                name_rule: "firefox developer edition".into(),
                exe_rule: "firefox-bin".into(),
                exe_path: FIREFOX_BIN.into(),
                conflicts: vec!["camera".into()],
            }]
        );
    }

    #[test]
    fn one_rule_with_both_identities_is_not_a_split() {
        let splits =
            live().find_rule_splits(&seen("firefox", "/usr/lib/firefox-esr/firefox-esr"));
        assert!(splits.is_empty());
    }

    /// `pipewire-pulse` is a symlink to `pipewire`, one inode and two rules on
    /// purpose. Both have their own binary, so neither is a half of a split.
    #[test]
    fn aliased_binaries_are_not_a_split() {
        let splits = live().find_rule_splits(&seen("pipewire-pulse", "/usr/bin/pipewire"));
        assert!(splits.is_empty());
    }

    /// Two builds of a browser can both declare `Firefox`.
    #[test]
    fn a_name_rule_with_its_own_binary_is_not_a_split() {
        let splits = live().find_rule_splits(&seen("firefox", FIREFOX_BIN));
        assert!(splits.is_empty());
    }

    #[test]
    fn nothing_is_a_split_without_both_rules() {
        assert!(live().find_rule_splits(&seen("audacity", "/usr/bin/audacity")).is_empty());
        assert!(live()
            .find_rule_splits(&seen("firefox developer edition", "/usr/bin/audacity"))
            .is_empty());
    }

    /// The same pair observed twice is one split.
    #[test]
    fn a_split_is_reported_once() {
        let mut observed = seen("firefox developer edition", FIREFOX_BIN);
        observed.extend(seen("Firefox Developer Edition [pipewire-pulse]", FIREFOX_BIN));
        assert_eq!(live().find_rule_splits(&observed).len(), 1);
    }

    #[test]
    fn a_disagreement_is_refused_until_chosen_and_names_the_device() {
        let c = live();
        let why = c
            .merge_rules("firefox-bin", "firefox developer edition", &MergeChoices::default())
            .unwrap_err();
        assert!(why.contains("camera"), "{why}");
        assert!(why.contains("--camera"), "{why}");
    }

    #[test]
    fn choosing_deny_keeps_the_binary_off_the_camera_and_on_the_microphone() {
        let (after, report) = live()
            .merge_rules(
                "firefox-bin",
                "firefox developer edition",
                &camera_choice(Permission::Deny),
            )
            .unwrap();

        assert!(after.find_rule("firefox-bin").is_none(), "the merged rule goes");
        let kept = after.find_rule("firefox developer edition").unwrap();
        assert_eq!(kept.camera, Some(Permission::Deny));
        assert_eq!(kept.microphone, Some(Permission::Allow));
        assert_eq!(kept.exe_path.as_deref(), Some(FIREFOX_BIN));

        let camera: Vec<String> =
            after.kernel_camera_allowlist().into_iter().map(|e| e.0).collect();
        assert!(!camera.contains(&FIREFOX_BIN.to_string()));
        let audio: Vec<String> =
            after.kernel_audio_allowlist().into_iter().map(|e| e.0).collect();
        assert!(audio.contains(&FIREFOX_BIN.to_string()), "direct ALSA is unchanged");

        assert!(report.contains("Kernel camera allowlist: no change"), "{report}");
        assert!(report.contains("Kernel audio allowlist: no change"), "{report}");
    }

    /// A merge can be a grant, and the preview has to say so.
    #[test]
    fn choosing_allow_is_announced_as_a_kernel_gain() {
        let (after, report) = live()
            .merge_rules(
                "firefox-bin",
                "firefox developer edition",
                &camera_choice(Permission::Allow),
            )
            .unwrap();
        let camera: Vec<String> =
            after.kernel_camera_allowlist().into_iter().map(|e| e.0).collect();
        assert!(camera.contains(&FIREFOX_BIN.to_string()));
        assert!(report.contains(&format!("GAINS {FIREFOX_BIN}")), "{report}");
    }

    /// One opinion survives. No opinion must stay no opinion: writing a default
    /// here would silently change what the category falls through to.
    #[test]
    fn one_opinion_is_kept_and_none_stays_none() {
        let mut c = live();
        c.find_rule_mut("firefox-bin").unwrap().monitor = Some(Permission::Deny);
        c.find_rule_mut("firefox developer edition").unwrap().microphone = None;
        let (after, _) = c
            .merge_rules(
                "firefox-bin",
                "firefox developer edition",
                &camera_choice(Permission::Deny),
            )
            .unwrap();
        let kept = after.find_rule("firefox developer edition").unwrap();
        assert_eq!(kept.monitor, Some(Permission::Deny));
        assert_eq!(kept.microphone, Some(Permission::Allow));

        let mut c = live();
        c.find_rule_mut("firefox-bin").unwrap().camera = None;
        c.find_rule_mut("firefox developer edition").unwrap().camera = None;
        let (after, _) = c
            .merge_rules("firefox-bin", "firefox developer edition", &MergeChoices::default())
            .unwrap();
        assert_eq!(after.find_rule("firefox developer edition").unwrap().monitor, None);
        assert_eq!(after.find_rule("firefox developer edition").unwrap().camera, None);
    }

    #[test]
    fn a_choice_where_nothing_conflicts_is_refused() {
        let choices = MergeChoices {
            camera: Some(Permission::Deny),
            microphone: Some(Permission::Deny),
            ..Default::default()
        };
        let why = live()
            .merge_rules("firefox-bin", "firefox developer edition", &choices)
            .unwrap_err();
        assert!(why.contains("microphone"), "{why}");
    }

    #[test]
    fn two_different_binaries_are_refused() {
        let why = live().merge_rules("firefox-bin", "firefox", &camera_choice(Permission::Deny));
        assert!(why.unwrap_err().contains("different binaries"));
    }

    #[test]
    fn the_camera_cannot_be_chosen_as_while_in_use() {
        let why = live().merge_rules(
            "firefox-bin",
            "firefox developer edition",
            &camera_choice(Permission::WhileInUse),
        );
        assert!(why.unwrap_err().contains("while_in_use"));
    }

    #[test]
    fn unknown_or_identical_rules_are_refused() {
        let none = MergeChoices::default();
        assert!(live().merge_rules("nope", "firefox", &none).is_err());
        assert!(live().merge_rules("firefox", "nope", &none).is_err());
        assert!(live().merge_rules("firefox", "FIREFOX", &none).is_err());
    }
}
