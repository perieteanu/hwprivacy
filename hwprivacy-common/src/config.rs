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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppRule {
    pub app_name: String,
    #[serde(default = "default_deny")]
    pub microphone: Permission,
    #[serde(default = "default_deny")]
    pub camera: Permission,
    #[serde(default = "default_deny")]
    pub monitor: Permission,
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

/// See [`Config::normalized_key`]. Free function so internal callers can use
/// it without going through `Config`.
pub fn normalize_app_name(app_name: &str) -> String {
    let trimmed = match app_name.rfind(" [") {
        Some(idx) if app_name.ends_with(']') => &app_name[..idx],
        _ => app_name,
    };
    trimmed.trim().to_lowercase()
}
