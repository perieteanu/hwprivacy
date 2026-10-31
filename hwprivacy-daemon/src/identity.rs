//! Which declared names have been seen running as which binaries.
//!
//! EVIDENCE, NEVER AUTHORITY. A pair here comes from what a stream says about
//! itself, checked only against `/proc`. It may tell the user that two rules look
//! like one program (`Config::find_rule_splits`). It must never reach a kernel
//! allowlist or write a rule: see `hwprivacy_common::rule_merge` for why.
//!
//! Persisted so a warning does not come and go with the application.

use crate::pipewire_monitor::NodeInfo;
use hwprivacy_common::config::AUDIO_SERVER_NAMES;
use hwprivacy_common::rule_merge::RuleSplit;
use hwprivacy_common::{normalize_app_name, short_name, Config};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use tracing::warn;

/// `/proc/<pid>/exe` carries this suffix once the file has been replaced, which
/// Firefox Developer Edition's updater does most days.
const DELETED_SUFFIX: &str = " (deleted)";

#[derive(Debug, Default, Serialize, Deserialize)]
struct Stored {
    pairs: BTreeSet<(String, String)>,
    /// Splits already announced as (name rule, exe rule), so a notification is
    /// shown once rather than at every login.
    announced: BTreeSet<(String, String)>,
}

#[derive(Debug, Default)]
pub struct Identities {
    stored: Stored,
    path: Option<PathBuf>,
    dirty: bool,
    /// (node id, declared pid) already looked up, so a graph update does not
    /// mean a `/proc` read for every live stream.
    checked: HashMap<(u32, u32), Option<(String, String)>>,
}

/// `$XDG_STATE_HOME/hwprivacy/identities.json`, beside `history.json`.
pub fn default_path() -> Option<PathBuf> {
    crate::history::default_path().map(|p| p.with_file_name("identities.json"))
}

/// The pair a stream's claims add up to, or `None` if they do not.
///
/// The declared binary has to match what is actually running at the declared
/// pid. That is not proof: a process can declare itself truthfully and lie about
/// its name. It does stop one program claiming to be another program's process.
pub fn identity_pair(
    app_name: &str,
    declared_pid: u32,
    process_binary: &str,
    read_exe: impl Fn(u32) -> Option<String>,
) -> Option<(String, String)> {
    if declared_pid == 0 || process_binary.is_empty() {
        return None;
    }
    if AUDIO_SERVER_NAMES.contains(&process_binary) {
        return None;
    }
    let name = normalize_app_name(app_name);
    if name.is_empty() || name == "unknown" {
        return None;
    }
    let exe = read_exe(declared_pid)?;
    let exe = exe.strip_suffix(DELETED_SUFFIX).unwrap_or(&exe).to_string();
    if short_name(&exe) != process_binary {
        return None;
    }
    Some((name, exe))
}

fn proc_exe(pid: u32) -> Option<String> {
    std::fs::read_link(format!("/proc/{pid}/exe"))
        .ok()
        .map(|p| p.to_string_lossy().into_owned())
}

impl Identities {
    pub fn load(path: Option<PathBuf>) -> Self {
        let stored = path
            .as_deref()
            .and_then(read_stored)
            .unwrap_or_default();
        Self {
            stored,
            path,
            ..Default::default()
        }
    }

    pub fn pairs(&self) -> Vec<(String, String)> {
        self.stored.pairs.iter().cloned().collect()
    }

    /// Record what the live streams say about themselves.
    ///
    /// Only a pair touching an existing rule is kept. The name is whatever a
    /// process chooses, and no other pair can ever matter, so a process cycling
    /// through names cannot grow this file.
    pub fn observe(&mut self, nodes: &HashMap<u32, NodeInfo>, config: &Config) {
        self.observe_with(nodes, config, proc_exe);
    }

    fn observe_with(
        &mut self,
        nodes: &HashMap<u32, NodeInfo>,
        config: &Config,
        read_exe: impl Fn(u32) -> Option<String>,
    ) {
        self.checked
            .retain(|(node_id, _), _| nodes.contains_key(node_id));
        for node in nodes.values() {
            if !node.media_class.starts_with("Stream") {
                continue;
            }
            let pair = self
                .checked
                .entry((node.id, node.declared_pid))
                .or_insert_with(|| {
                    identity_pair(
                        &node.app_name,
                        node.declared_pid,
                        &node.process_binary,
                        &read_exe,
                    )
                });
            let Some((name, exe)) = pair else {
                continue;
            };
            if (config.find_rule(name).is_some() || config.find_rule_by_exe(exe).is_some())
                && self.stored.pairs.insert((name.clone(), exe.clone()))
            {
                self.dirty = true;
            }
        }
    }

    /// The splits not announced yet, marked as announced.
    pub fn take_unannounced(&mut self, splits: Vec<RuleSplit>) -> Vec<RuleSplit> {
        let fresh: Vec<RuleSplit> = splits
            .into_iter()
            .filter(|s| {
                self.stored
                    .announced
                    .insert((s.name_rule.clone(), s.exe_rule.clone()))
            })
            .collect();
        if !fresh.is_empty() {
            self.dirty = true;
        }
        fresh
    }

    pub fn save_if_dirty(&mut self) {
        if !self.dirty {
            return;
        }
        let Some(path) = self.path.clone() else {
            return;
        };
        match write_stored(&path, &self.stored) {
            Ok(()) => self.dirty = false,
            Err(e) => warn!("Identities: cannot write {}: {e}", path.display()),
        }
    }
}

/// A file that cannot be read only costs a warning that will be re-learned.
fn read_stored(path: &Path) -> Option<Stored> {
    let text = std::fs::read_to_string(path).ok()?;
    match serde_json::from_str(&text) {
        Ok(stored) => Some(stored),
        Err(e) => {
            warn!("Identities: ignoring unreadable {}: {e}", path.display());
            None
        }
    }
}

fn write_stored(path: &Path, stored: &Stored) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, serde_json::to_string_pretty(stored)?)?;
    std::fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hwprivacy_common::config::AppRule;

    const EXE: &str = "/home/u/firefox-developer/firefox-bin";

    fn exe_is(path: &'static str) -> impl Fn(u32) -> Option<String> {
        move |_| Some(path.to_string())
    }

    #[test]
    fn the_measured_stream_adds_up() {
        let pair = identity_pair(
            "Firefox Developer Edition [pipewire-pulse]",
            3098,
            "firefox-bin",
            exe_is(EXE),
        );
        assert_eq!(pair, Some(("firefox developer edition".into(), EXE.into())));
    }

    /// One program claiming to be another program's process.
    #[test]
    fn a_binary_that_does_not_match_the_pid_is_not_recorded() {
        let pair = identity_pair("Firefox", 3098, "firefox-bin", exe_is("/tmp/evil"));
        assert_eq!(pair, None);
    }

    /// Firefox Developer Edition updates itself under a running process.
    #[test]
    fn a_replaced_binary_still_adds_up() {
        let pair = identity_pair(
            "Firefox Developer Edition",
            3098,
            "firefox-bin",
            exe_is("/home/u/firefox-developer/firefox-bin (deleted)"),
        );
        assert_eq!(pair, Some(("firefox developer edition".into(), EXE.into())));
    }

    #[test]
    fn a_process_that_is_gone_or_silent_is_not_recorded() {
        assert_eq!(identity_pair("Firefox", 3098, "firefox-bin", |_| None), None);
        assert_eq!(identity_pair("Firefox", 0, "firefox-bin", exe_is(EXE)), None);
        assert_eq!(identity_pair("Firefox", 3098, "", exe_is(EXE)), None);
        assert_eq!(identity_pair("unknown", 3098, "firefox-bin", exe_is(EXE)), None);
    }

    /// The audio server speaks for every pulse client, so it joins nothing.
    #[test]
    fn the_audio_server_is_not_recorded() {
        let pair = identity_pair("pipewire", 2100, "pipewire", exe_is("/usr/bin/pipewire"));
        assert_eq!(pair, None);
    }

    fn stream(id: u32, app: &str, binary: &str) -> NodeInfo {
        NodeInfo {
            id,
            media_class: "Stream/Output/Audio".into(),
            node_name: app.into(),
            app_name: app.into(),
            pid: 2100,
            media_name: String::new(),
            declared_pid: 3098,
            process_binary: binary.into(),
        }
    }

    fn config_with(name: &str) -> Config {
        let mut c = Config::default();
        c.rules.push(AppRule {
            app_name: name.into(),
            microphone: None,
            camera: None,
            monitor: None,
            exe_path: None,
        });
        c
    }

    #[test]
    fn only_a_pair_touching_a_rule_is_kept() {
        let mut ids = Identities::default();
        let nodes = HashMap::from([
            (1, stream(1, "Firefox Developer Edition", "firefox-bin")),
            (2, stream(2, "made up name", "firefox-bin")),
        ]);
        ids.observe_with(&nodes, &config_with("firefox developer edition"), exe_is(EXE));
        assert_eq!(ids.pairs(), vec![("firefox developer edition".to_string(), EXE.to_string())]);
    }

    #[test]
    fn playback_streams_count_and_devices_do_not() {
        let mut ids = Identities::default();
        let mut device = stream(1, "Firefox Developer Edition", "firefox-bin");
        device.media_class = "Audio/Sink".into();
        let config = config_with("firefox developer edition");

        ids.observe_with(&HashMap::from([(1, device)]), &config, exe_is(EXE));
        assert!(ids.pairs().is_empty());

        let nodes = HashMap::from([(2, stream(2, "Firefox Developer Edition", "firefox-bin"))]);
        ids.observe_with(&nodes, &config, exe_is(EXE));
        assert_eq!(ids.pairs().len(), 1);
    }

    /// Node ids are reused: a new stream on the same id with a new pid is new.
    #[test]
    fn a_lookup_is_cached_per_node_and_pid() {
        let mut ids = Identities::default();
        let calls = std::cell::Cell::new(0);
        let reader = |_: u32| {
            calls.set(calls.get() + 1);
            Some(EXE.to_string())
        };
        let config = config_with("firefox developer edition");
        let mut nodes = HashMap::from([(1, stream(1, "Firefox Developer Edition", "firefox-bin"))]);

        ids.observe_with(&nodes, &config, reader);
        ids.observe_with(&nodes, &config, reader);
        assert_eq!(calls.get(), 1);

        nodes.get_mut(&1).unwrap().declared_pid = 4000;
        ids.observe_with(&nodes, &config, reader);
        assert_eq!(calls.get(), 2);
    }

    fn split() -> RuleSplit {
        RuleSplit {
            name_rule: "firefox developer edition".into(),
            exe_rule: "firefox-bin".into(),
            exe_path: EXE.into(),
            conflicts: vec![],
        }
    }

    #[test]
    fn a_split_is_announced_once() {
        let mut ids = Identities::default();
        assert_eq!(ids.take_unannounced(vec![split()]).len(), 1);
        assert!(ids.take_unannounced(vec![split()]).is_empty());
    }

    #[test]
    fn pairs_and_announcements_survive_a_restart() {
        let dir = std::env::temp_dir().join(format!("hw-identities-{}", std::process::id()));
        let path = dir.join("identities.json");
        let mut ids = Identities::load(Some(path.clone()));
        let nodes = HashMap::from([(1, stream(1, "Firefox Developer Edition", "firefox-bin"))]);
        ids.observe_with(&nodes, &config_with("firefox developer edition"), exe_is(EXE));
        ids.take_unannounced(vec![split()]);
        ids.save_if_dirty();

        let mut again = Identities::load(Some(path));
        assert_eq!(again.pairs().len(), 1);
        assert!(again.take_unannounced(vec![split()]).is_empty());
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// On its own, with no new pair to mark the table dirty. Losing this would
    /// repeat the popup at every login.
    #[test]
    fn an_announcement_alone_is_saved() {
        let dir = std::env::temp_dir().join(format!("hw-announce-{}", std::process::id()));
        let path = dir.join("identities.json");
        let mut ids = Identities::load(Some(path.clone()));
        ids.take_unannounced(vec![split()]);
        ids.save_if_dirty();

        let mut again = Identities::load(Some(path));
        assert!(again.take_unannounced(vec![split()]).is_empty());
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// This table must stay evidence. The doc-check sentinel covers the source;
    /// this covers the behaviour.
    #[test]
    fn observing_never_changes_the_config_or_the_allowlists() {
        let mut ids = Identities::default();
        let config = config_with("firefox developer edition");
        let before = format!("{:?}", config.rules);
        let nodes = HashMap::from([(1, stream(1, "Firefox Developer Edition", "firefox-bin"))]);
        ids.observe_with(&nodes, &config, exe_is(EXE));
        assert_eq!(format!("{:?}", config.rules), before);
        assert!(config.kernel_camera_allowlist().is_empty());
        assert!(config.kernel_audio_allowlist().is_empty());
    }
}
