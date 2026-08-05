use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

/// Permission level for an app accessing a device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Permission {
    /// All streams auto-allowed (trusted app)
    Allow,
    /// Prompt for every new stream (ideal for browsers)
    AskEach,
    /// Allowed while app's PipeWire client is active
    WhileInUse,
    /// Prompt once, remember for session
    Ask,
    /// Always blocked
    Deny,
}

impl std::fmt::Display for Permission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Permission::Allow => write!(f, "allow"),
            Permission::AskEach => write!(f, "ask_each"),
            Permission::WhileInUse => write!(f, "while_in_use"),
            Permission::Ask => write!(f, "ask"),
            Permission::Deny => write!(f, "deny"),
        }
    }
}

impl std::str::FromStr for Permission {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "allow" => Ok(Permission::Allow),
            "ask_each" => Ok(Permission::AskEach),
            "while_in_use" => Ok(Permission::WhileInUse),
            "ask" => Ok(Permission::Ask),
            "deny" => Ok(Permission::Deny),
            _ => Err(format!("Unknown permission: '{}'. Valid: allow, ask_each, while_in_use, ask, deny", s)),
        }
    }
}

/// Per-app rule entry in config.
///
/// One rule governs both enforcement layers. `app_name` is matched against
/// PipeWire's self-declared `application.name`; `exe_path` is matched by the
/// kernel against the calling task's executable inode. They answer different
/// questions and neither replaces the other — see `docs-yaml/ARCHITECTURE.yaml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppRule {
    pub app_name: String,
    #[serde(default = "default_deny")]
    pub microphone: Permission,
    #[serde(default = "default_deny")]
    pub camera: Permission,
    #[serde(default = "default_deny")]
    pub monitor: Permission,

    /// Absolute path to the REAL executable, for the kernel (eBPF LSM) layer.
    ///
    /// Must be the binary that actually opens the device, not a launcher:
    /// `/usr/lib/firefox-esr/firefox-esr`, never `/usr/bin/firefox` — the
    /// latter is a shell script on Debian and would never match. Find it with
    /// `hwprivacy-lsm` in observe mode, which prints the resolved path.
    ///
    /// Absent means "this rule is PipeWire-only" — the kernel layer ignores it,
    /// and under kernel default-deny that application gets no camera.
    ///
    /// Named `exe_path` rather than `exe`: on a Linux tool `exe` reads like a
    /// Windows binary extension, which is exactly how it was first misread.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exe_path: Option<String>,
}

fn default_deny() -> Permission {
    Permission::Deny
}

impl AppRule {
    pub fn get_permission(&self, category: &super::DeviceCategory) -> Permission {
        match category {
            super::DeviceCategory::Microphone => self.microphone,
            super::DeviceCategory::Camera => self.camera,
            super::DeviceCategory::Monitor => self.monitor,
        }
    }

    pub fn set_permission(&mut self, category: &super::DeviceCategory, perm: Permission) {
        match category {
            super::DeviceCategory::Microphone => self.microphone = perm,
            super::DeviceCategory::Camera => self.camera = perm,
            super::DeviceCategory::Monitor => self.monitor = perm,
        }
    }
}

/// Global policy settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    /// Default action when no rule matches: "ask" (recommended) or "deny"
    #[serde(default = "default_ask")]
    pub default_action: Permission,
    /// Poll interval in milliseconds
    #[serde(default = "default_poll_interval")]
    pub poll_interval_ms: u64,
}

fn default_ask() -> Permission {
    Permission::Ask
}

fn default_poll_interval() -> u64 {
    500
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            default_action: Permission::Ask,
            poll_interval_ms: 500,
        }
    }
}

/// Device protection toggles.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DevicesConfig {
    #[serde(default = "default_true")]
    pub microphone: bool,
    #[serde(default = "default_true")]
    pub camera: bool,
    #[serde(default = "default_true")]
    pub monitor: bool,
}

fn default_true() -> bool {
    true
}

impl Default for DevicesConfig {
    fn default() -> Self {
        Self {
            microphone: true,
            camera: true,
            monitor: true,
        }
    }
}

impl DevicesConfig {
    pub fn is_guarded(&self, category: &super::DeviceCategory) -> bool {
        match category {
            super::DeviceCategory::Microphone => self.microphone,
            super::DeviceCategory::Camera => self.camera,
            super::DeviceCategory::Monitor => self.monitor,
        }
    }
}

/// Full configuration file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub policy: PolicyConfig,
    #[serde(default)]
    pub devices: DevicesConfig,
    #[serde(default)]
    pub rules: Vec<AppRule>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            policy: PolicyConfig::default(),
            devices: DevicesConfig::default(),
            rules: Vec::new(),
        }
    }
}

impl Config {
    /// User config path: ~/.config/hwprivacy/config.toml
    pub fn user_config_path() -> PathBuf {
        let config_dir = std::env::var("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|_| {
                let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
                PathBuf::from(home).join(".config")
            });
        config_dir.join("hwprivacy").join("config.toml")
    }

    /// System config path: /etc/hwprivacy/config.toml
    pub fn system_config_path() -> PathBuf {
        PathBuf::from("/etc/hwprivacy/config.toml")
    }

    /// Load config: user config overrides system config.
    pub fn load() -> Self {
        let user_path = Self::user_config_path();
        if user_path.exists() {
            if let Ok(content) = std::fs::read_to_string(&user_path) {
                if let Ok(config) = toml::from_str(&content) {
                    return config;
                }
            }
        }

        let sys_path = Self::system_config_path();
        if sys_path.exists() {
            if let Ok(content) = std::fs::read_to_string(&sys_path) {
                if let Ok(config) = toml::from_str(&content) {
                    return config;
                }
            }
        }

        Self::default()
    }

    /// Save config to user config path.
    pub fn save(&self) -> anyhow::Result<()> {
        let path = Self::user_config_path();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let content = toml::to_string_pretty(self)?;
        std::fs::write(path, content)?;
        Ok(())
    }

    /// Find rule for an app by name.
    pub fn find_rule(&self, app_name: &str) -> Option<&AppRule> {
        let key = normalize_app_name(app_name);
        self.rules
            .iter()
            .find(|r| normalize_app_name(&r.app_name) == key)
    }

    /// Find rule for an app (mutable).
    pub fn find_rule_mut(&mut self, app_name: &str) -> Option<&mut AppRule> {
        let key = normalize_app_name(app_name);
        self.rules
            .iter_mut()
            .find(|r| normalize_app_name(&r.app_name) == key)
    }

    /// Get effective permission for an app + device combo.
    pub fn get_permission(&self, app_name: &str, category: &super::DeviceCategory) -> Permission {
        if let Some(rule) = self.find_rule(app_name) {
            rule.get_permission(category)
        } else {
            self.policy.default_action
        }
    }

    /// Set a rule. Creates a new entry if app not found.
    pub fn set_rule(&mut self, app_name: &str, category: &super::DeviceCategory, perm: Permission) {
        if let Some(rule) = self.find_rule_mut(app_name) {
            rule.set_permission(category, perm);
        } else {
            let mut rule = AppRule {
                app_name: app_name.to_string(),
                microphone: Permission::Deny,
                camera: Permission::Deny,
                monitor: Permission::Deny,
                // A rule created from a PipeWire prompt knows no executable.
                // The kernel layer therefore ignores it until a path is added
                // by hand — which is correct: guessing a binary from a
                // self-declared application.name would be exactly the kind of
                // silent mismatch this project keeps getting bitten by.
                exe_path: None,
            };
            rule.set_permission(category, perm);
            self.rules.push(rule);
        }
    }

    /// Remove all rules for an app.
    pub fn remove_rule(&mut self, app_name: &str) -> bool {
        let key = normalize_app_name(app_name);
        let before = self.rules.len();
        self.rules
            .retain(|r| normalize_app_name(&r.app_name) != key);
        self.rules.len() < before
    }

    /// Normalized lookup key for an app name. Strips a trailing
    /// " [...]" annotation (e.g. "OBS [pipewire-pulse]") and lowercases,
    /// so that the binary `obs`, the PipeWire `application.name` "OBS",
    /// and the Pulse-bridge variant "OBS [pipewire-pulse]" all match the
    /// same rule.
    pub fn normalized_key(app_name: &str) -> String {
        normalize_app_name(app_name)
    }

    /// Build a fast lookup map: app_name → HashMap<DeviceCategory, Permission>
    pub fn rules_map(&self) -> HashMap<String, HashMap<super::DeviceCategory, Permission>> {
        let mut map = HashMap::new();
        for rule in &self.rules {
            let mut devmap = HashMap::new();
            devmap.insert(super::DeviceCategory::Microphone, rule.microphone);
            devmap.insert(super::DeviceCategory::Camera, rule.camera);
            devmap.insert(super::DeviceCategory::Monitor, rule.monitor);
            map.insert(normalize_app_name(&rule.app_name), devmap);
        }
        map
    }
}

impl Config {
    /// Executable paths this config allows to use the camera at the KERNEL
    /// layer, as `(exe_path, permission)` pairs.
    ///
    /// Only `Permission::Allow` qualifies. The kernel layer is binary — a
    /// process either may open `/dev/video0` or may not — so the prompting
    /// levels have no meaning there:
    ///
    /// * `ask` / `ask_each` cannot be honoured: an LSM hook returns a verdict
    ///   in nanoseconds and cannot wait for a human. Treated as deny.
    /// * `while_in_use` has no kernel equivalent either. Treated as deny.
    ///
    /// A rule with no `exe_path` is PipeWire-only and is skipped.
    pub fn kernel_camera_allowlist(&self) -> Vec<(String, Permission)> {
        self.rules
            .iter()
            .filter(|r| r.camera == Permission::Allow)
            .filter_map(|r| r.exe_path.clone().map(|p| (p, r.camera)))
            .collect()
    }

    /// Rules that ask for camera access but cannot get it at the kernel layer
    /// because they name no executable, with the reason.
    ///
    /// Worth surfacing rather than dropping: under kernel default-deny, a rule
    /// that reads `camera = "allow"` in config.toml but has no `exe_path`
    /// silently does nothing, which looks exactly like a broken allowlist.
    pub fn kernel_camera_gaps(&self) -> Vec<(String, &'static str)> {
        self.rules
            .iter()
            .filter(|r| r.exe_path.is_none())
            .filter_map(|r| match r.camera {
                Permission::Allow => Some((
                    r.app_name.clone(),
                    "camera = allow but no exe_path — the kernel layer will still deny it",
                )),
                Permission::Ask | Permission::AskEach | Permission::WhileInUse => Some((
                    r.app_name.clone(),
                    "prompting permissions have no kernel equivalent; treated as deny there",
                )),
                Permission::Deny => None,
            })
            .collect()
    }
}

/// See [`Config::normalized_key`]. Free function so internal callers can use
/// it without going through `Config`.
pub fn normalize_app_name(app_name: &str) -> String {
    let trimmed = match app_name.rfind(" [") {
        Some(idx) if app_name.ends_with(']') => &app_name[..idx],
        _ => app_name,
    };
    trimmed.trim().to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DeviceCategory;

    fn rule(app: &str, cam: Permission, exe: Option<&str>) -> AppRule {
        AppRule {
            app_name: app.into(),
            microphone: Permission::Deny,
            camera: cam,
            monitor: Permission::Deny,
            exe_path: exe.map(str::to_string),
        }
    }

    #[test]
    fn normalize_strips_one_bracket_suffix_and_lowercases() {
        assert_eq!(normalize_app_name("OBS [pipewire-pulse]"), "obs");
        assert_eq!(normalize_app_name("Firefox"), "firefox");
        assert_eq!(normalize_app_name("  Spaced  "), "spaced");
    }

    /// The live config has a rule named `Firefox [pipewire-pulse] (pid:2332)`.
    /// It ends with ')', not ']', so nothing is stripped and it can never
    /// match. This is the trap that produced three dead rules.
    #[test]
    fn a_pid_suffix_is_not_stripped_and_the_rule_is_dead() {
        let key = normalize_app_name("Firefox [pipewire-pulse] (pid:2332)");
        assert_ne!(key, "firefox", "must not accidentally match");
        assert!(key.contains("pid:2332"), "the pid survives normalization: {key}");
    }

    #[test]
    fn only_allow_with_an_exe_path_reaches_the_kernel_layer() {
        let mut c = Config::default();
        c.rules = vec![
            rule("firefox", Permission::Allow, Some("/usr/lib/firefox-esr/firefox-esr")),
            rule("obs", Permission::Allow, None),                 // no path -> skipped
            rule("discord", Permission::Deny, Some("/usr/bin/discord")),
            rule("zoom", Permission::AskEach, Some("/usr/bin/zoom")),
        ];
        let allow = c.kernel_camera_allowlist();
        assert_eq!(allow.len(), 1, "{allow:?}");
        assert_eq!(allow[0].0, "/usr/lib/firefox-esr/firefox-esr");
    }

    /// Prompting levels cannot be honoured by an LSM hook — it must answer in
    /// nanoseconds and cannot wait for a human. They must NOT silently become
    /// allow.
    #[test]
    fn prompting_permissions_never_become_a_kernel_allow() {
        for p in [Permission::Ask, Permission::AskEach, Permission::WhileInUse] {
            let mut c = Config::default();
            c.rules = vec![rule("x", p, Some("/usr/bin/x"))];
            assert!(
                c.kernel_camera_allowlist().is_empty(),
                "{p} must not reach the kernel allowlist"
            );
        }
    }

    #[test]
    fn a_rule_that_wants_the_camera_but_names_no_binary_is_reported() {
        let mut c = Config::default();
        c.rules = vec![rule("obs", Permission::Allow, None)];
        let gaps = c.kernel_camera_gaps();
        assert_eq!(gaps.len(), 1);
        assert!(gaps[0].1.contains("no exe_path"), "{:?}", gaps[0]);
    }

    #[test]
    fn a_plain_deny_rule_is_not_reported_as_a_gap() {
        let mut c = Config::default();
        c.rules = vec![rule("spyware", Permission::Deny, None)];
        assert!(c.kernel_camera_gaps().is_empty(), "deny needs no exe_path");
    }

    /// Existing configs have no exe_path. They must load unchanged, and must
    /// not gain a null field when the daemon rewrites the file.
    #[test]
    fn configs_without_exe_path_round_trip_cleanly() {
        let toml_in = r#"
[[rules]]
app_name = "firefox"
microphone = "ask_each"
camera = "deny"
monitor = "deny"
"#;
        let c: Config = toml::from_str(toml_in).expect("old config must still parse");
        assert_eq!(c.rules.len(), 1);
        assert!(c.rules[0].exe_path.is_none());

        let out = toml::to_string_pretty(&c).unwrap();
        assert!(!out.contains("exe_path"), "must not write a null field:\n{out}");
    }

    #[test]
    fn exe_path_survives_a_config_round_trip() {
        let mut c = Config::default();
        c.rules = vec![rule("firefox", Permission::Allow, Some("/usr/lib/firefox-esr/firefox-esr"))];
        let out = toml::to_string_pretty(&c).unwrap();
        let back: Config = toml::from_str(&out).unwrap();
        assert_eq!(
            back.rules[0].exe_path.as_deref(),
            Some("/usr/lib/firefox-esr/firefox-esr")
        );
    }

    #[test]
    fn get_permission_falls_back_to_the_default_action() {
        let c = Config::default();
        assert_eq!(
            c.get_permission("never-seen", &DeviceCategory::Camera),
            c.policy.default_action
        );
    }
}
