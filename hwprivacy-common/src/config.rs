use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

/// Permission level for an app accessing a device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Permission {
    /// All streams auto-allowed (trusted app)
    Allow,
    /// Allowed while app's PipeWire client is active
    WhileInUse,
    /// Prompt once, remember for session.
    ///
    /// `ask_each` is accepted as an alias so that configs and presets written
    /// before 2026-08-23 keep loading. It meant "prompt for every new stream"
    /// and was removed with the whole per-stream concept — the grant it
    /// produced could never be used, so answering it did nothing. Mapping it
    /// to `ask` preserves the user's evident intent (they wanted to be asked)
    /// rather than silently widening or narrowing the rule.
    #[serde(alias = "ask_each")]
    Ask,
    /// Always blocked
    Deny,
}

impl std::fmt::Display for Permission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Permission::Allow => write!(f, "allow"),
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
            // Accepted, not offered: see the `Ask` variant.
            "ask_each" => Ok(Permission::Ask),
            "while_in_use" => Ok(Permission::WhileInUse),
            "ask" => Ok(Permission::Ask),
            "deny" => Ok(Permission::Deny),
            _ => Err(format!("Unknown permission: '{}'. Valid: allow, while_in_use, ask, deny", s)),
        }
    }
}

/// Per-app rule entry in config.
///
/// One rule governs both enforcement layers. `app_name` is matched against
/// PipeWire's self-declared `application.name`; `exe_path` is matched by the
/// kernel against the calling task's executable inode. They answer different
/// questions and neither replaces the other — see `docs-yaml/ARCHITECTURE.yaml`.
///
/// # Why every category is optional
///
/// `None` means "this rule has no opinion here" and the category falls through
/// to `policy.default_action`. It is NOT the same as `Some(Deny)`.
///
/// Before 2026-08-23 the three fields were plain `Permission` defaulting to
/// `Deny`, so `set_rule()` could not express a one-category grant: allowing
/// firefox the camera also wrote `microphone = "deny"` and `monitor = "deny"`,
/// which the user never asked for and which silently downgraded the microphone
/// from `ask` to a hard deny. Measured live that day.
///
/// Existing config files are unaffected and deliberately so. An explicit
/// `microphone = "deny"` written by the old code still deserialises to
/// `Some(Deny)`, because a bare deny cannot be told apart from a deliberate
/// one — loosening it on load would relax a rule the user may have meant,
/// without asking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppRule {
    pub app_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub microphone: Option<Permission>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub camera: Option<Permission>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub monitor: Option<Permission>,

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

impl AppRule {
    /// This rule's opinion, or `None` if it has none for this category.
    ///
    /// Callers that need a decision want [`Config::get_permission`], which
    /// resolves `None` against `default_action`. Returning the `Option` here
    /// is deliberate: the two questions ("what did the user write" and "what
    /// happens now") have different answers and conflating them is the bug
    /// this type was changed to prevent.
    pub fn get_permission(&self, category: &super::DeviceCategory) -> Option<Permission> {
        match category {
            super::DeviceCategory::Microphone => self.microphone,
            super::DeviceCategory::Camera => self.camera,
            super::DeviceCategory::Monitor => self.monitor,
        }
    }

    pub fn set_permission(&mut self, category: &super::DeviceCategory, perm: Permission) {
        match category {
            super::DeviceCategory::Microphone => self.microphone = Some(perm),
            super::DeviceCategory::Camera => self.camera = Some(perm),
            super::DeviceCategory::Monitor => self.monitor = Some(perm),
        }
    }

    /// A rule with no opinion about anything. Used by [`Config::set_rule`], so
    /// that setting one category writes exactly one category.
    pub fn empty(app_name: String) -> Self {
        AppRule {
            app_name,
            microphone: None,
            camera: None,
            monitor: None,
            // A rule created from a PipeWire prompt knows no executable.
            // The kernel layer therefore ignores it until a path is attached —
            // which is correct: guessing a binary from a self-declared
            // application.name would be exactly the kind of silent mismatch
            // this project keeps getting bitten by. `set_rule_exe` is how a
            // path gets here; see `Config::set_rule_exe`.
            exe_path: None,
        }
    }
}

/// Global policy settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    /// Action when no rule matches. `deny` by default — settled 2026-08-21,
    /// resolving `DECISIONS.yaml > d-posture-unsettled`, which had README
    /// claiming deny-all while the shipped config said `ask`.
    ///
    /// An app with no rule is denied and gets the instant BLOCKED
    /// notification. `ask` still works and is still honoured; it is now opt-in
    /// per rule rather than the fallback for everything unknown.
    #[serde(default = "default_deny_action")]
    pub default_action: Permission,
    /// Poll interval in milliseconds
    #[serde(default = "default_poll_interval")]
    pub poll_interval_ms: u64,
    /// How long to stay quiet about one (app, device) after the user dismissed
    /// its prompt, in seconds. Was a `const` in stream_tracker.rs.
    #[serde(default = "default_dismiss_cooldown")]
    pub dismiss_cooldown_secs: u64,
    /// How often the daemon re-checks that the executables in the kernel
    /// allowlist are still the same files, in seconds.
    ///
    /// This is not a poll of the world — it is a handful of `stat()` calls on
    /// the paths already named in the config, and it exists because a package
    /// upgrade changes a binary's inode while the kernel map keeps the old one.
    /// Measured 2026-08-20: firefox-esr was upgraded two minutes after the
    /// policy push and lost the camera for sixteen hours while every status
    /// surface reported healthy.
    #[serde(default = "default_exe_recheck")]
    pub exe_recheck_secs: u64,

    /// How long a `while_in_use` session stays live after the device is
    /// released, in seconds.
    ///
    /// NOT a convenience. Enforcement destroys the link before the prompt is
    /// shown, so between the user answering and the application reconnecting
    /// there are legitimately zero links. Without this window the session would
    /// end in that gap and prompt again immediately, forever — which is exactly
    /// how the removed per-stream grant failed.
    ///
    /// Keep it short. It is the only period in which a released device is still
    /// granted, and it is the difference between `while_in_use` and `allow`.
    #[serde(default = "default_while_in_use_settle")]
    pub while_in_use_settle_secs: u64,

    /// Notify when access is ALLOWED, not only when it is denied.
    ///
    /// Measured 2026-08-21: firefox-esr opened the camera twice in one morning
    /// with no video call, because a website held a standing per-origin grant
    /// and a restored tab re-acquired on reload. hwprivacy allowed both
    /// correctly and said nothing — the deny path had a notification and a
    /// history row, the allow path had neither.
    #[serde(default = "default_true")]
    pub notify_on_allow: bool,

    /// Stay quiet about allowed access for this many seconds after the daemon
    /// starts.
    ///
    /// System components probe the camera at boot — `wireplumber` does it about
    /// eight seconds in, and `v4l_id` before that. A grace window suppresses
    /// them without naming any of them, which matters because naming
    /// applications is exactly what this project does not do
    /// (`d-executable-is-the-principal`). Cost: a real access in the first
    /// minute after login is silent.
    #[serde(default = "default_notify_allow_grace")]
    pub notify_allow_grace_secs: u64,

    /// Minimum gap between two "allowed" notifications for the same
    /// (app, device).
    ///
    /// Collapses one burst of activity into one notification, while still
    /// reporting the same app again later — the two firefox-esr camera opens
    /// that prompted this feature were 26 minutes apart and were two separate
    /// things worth knowing.
    #[serde(default = "default_notify_allow_cooldown")]
    pub notify_allow_cooldown_secs: u64,
}

fn default_deny_action() -> Permission {
    Permission::Deny
}

fn default_poll_interval() -> u64 {
    500
}

fn default_dismiss_cooldown() -> u64 {
    60
}

fn default_while_in_use_settle() -> u64 {
    10
}

fn default_exe_recheck() -> u64 {
    30
}

fn default_notify_allow_grace() -> u64 {
    60
}

fn default_notify_allow_cooldown() -> u64 {
    300
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            default_action: default_deny_action(),
            poll_interval_ms: default_poll_interval(),
            dismiss_cooldown_secs: default_dismiss_cooldown(),
            exe_recheck_secs: default_exe_recheck(),
            while_in_use_settle_secs: default_while_in_use_settle(),
            notify_on_allow: true,
            notify_allow_grace_secs: default_notify_allow_grace(),
            notify_allow_cooldown_secs: default_notify_allow_cooldown(),
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
    ///
    /// Two ways to reach `default_action`, and both must: no rule at all, and a
    /// rule that says nothing about this category. Collapsing the second into
    /// `Deny` is what made a camera grant silently mute the microphone.
    pub fn get_permission(&self, app_name: &str, category: &super::DeviceCategory) -> Permission {
        self.find_rule(app_name)
            .and_then(|rule| rule.get_permission(category))
            .unwrap_or(self.policy.default_action)
    }

    /// Set a rule. Creates a new entry if the app is not found.
    ///
    /// Returns `false` and writes nothing if the name cannot become a usable
    /// rule key. That is blocker b4: `set_rule` used to store whatever string
    /// it was handed, so a label copied out of a notification body —
    /// `Firefox [pipewire-pulse] (pid:2332)` — became a rule that can never
    /// match anything, because [`normalize_app_name`] only strips a trailing
    /// `[...]` and that string ends with `)`. Three such rules were sitting in
    /// the live config on 2026-08-21, one of them the empty string.
    ///
    /// Names are sanitised on WRITE, not on lookup — see [`sanitize_rule_name`]
    /// for why the matcher itself is deliberately left alone.
    pub fn set_rule(
        &mut self,
        app_name: &str,
        category: &super::DeviceCategory,
        perm: Permission,
    ) -> bool {
        let Some(key) = sanitize_rule_name(app_name) else {
            return false;
        };
        // The camera accepted `while_in_use` from 2026-08-23, once the LSM
        // program gained an `lsm/file_release` hook and the daemon could see a
        // camera being let go. Before that it was refused, because a rule that
        // silently behaves as `allow` is the defect this permission was
        // rewritten to remove.
        //
        // It still needs a binary: the session is enforced by adding and
        // removing the executable from the kernel allowlist, and there is
        // nothing to add without an exe_path. Unlike a plain `camera = allow`,
        // which is meaningful for a portal app on the PipeWire route, a
        // while_in_use camera rule with no binary can do nothing at all.
        if *category == super::DeviceCategory::Camera
            && perm == Permission::WhileInUse
            && self.find_rule(&key).and_then(|r| r.exe_path.clone()).is_none()
        {
            return false;
        }
        if let Some(rule) = self.find_rule_mut(&key) {
            rule.set_permission(category, perm);
        } else {
            let mut rule = AppRule::empty(key);
            rule.set_permission(category, perm);
            self.rules.push(rule);
        }
        true
    }

    /// Attach the kernel-layer executable to an existing rule, or clear it with
    /// an empty string.
    ///
    /// This is the only way `exe_path` reaches a rule from outside a preset.
    /// Until 2026-08-23 there was none: `hwprivacy-ctl rules set`, the GUI form
    /// and D-Bus `set_rule` all carried three fields, and
    /// [`Config::kernel_camera_allowlist`] keys purely on `exe_path` — so no
    /// string typeable in the app-name field could ever grant a camera, and
    /// the only route was hand-editing `config.toml` with the daemon stopped.
    ///
    /// Refuses rather than stores, the same way [`Config::set_rule`] refuses an
    /// unusable name (b4). A relative path can never match — the kernel
    /// resolves by inode from an absolute path — and a path that does not
    /// exist cannot be stat'ed into one. Both would sit in the config looking
    /// like protection.
    ///
    /// `Err` carries the reason so the caller can log or show it; the caller
    /// is expected to treat any `Err` as "nothing was written".
    pub fn set_rule_exe(&mut self, app_name: &str, exe_path: &str) -> Result<(), String> {
        let Some(rule) = self.find_rule_mut(app_name) else {
            return Err(format!("no rule for '{app_name}' — create one first"));
        };
        if exe_path.is_empty() {
            rule.exe_path = None;
            return Ok(());
        }
        if !exe_path.starts_with('/') {
            return Err(format!(
                "'{exe_path}' is not an absolute path; the kernel layer matches \
                 an executable by inode and cannot resolve a relative path"
            ));
        }
        if !super::preset::path_exists(exe_path) {
            return Err(format!(
                "'{exe_path}' does not exist; a path that cannot be stat'ed \
                 would sit in the config looking like protection"
            ));
        }
        rule.exe_path = Some(exe_path.to_string());
        Ok(())
    }

    /// Apply an import plan, returning how many rules were added.
    ///
    /// Only entries the plan marked `Added` are written, and the plan already
    /// refused to touch an app that has a rule. This re-checks anyway: the plan
    /// may have been computed for a preview and the config could have changed
    /// since. A preview that disagrees with the apply would be the worst
    /// possible bug in a feature whose whole safety story is "look before you
    /// commit".
    pub fn apply_preset(&mut self, plan: &super::preset::ImportPlan) -> usize {
        let mut added = 0;
        for (_, _, rule) in &plan.entries {
            let Some(rule) = rule else { continue };
            if self.find_rule(&rule.app_name).is_some() {
                continue; // appeared since the plan was made
            }
            self.rules.push(rule.clone());
            added += 1;
        }
        added
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
            // Only categories the rule has an opinion about. An absent entry
            // means "ask default_action", which is not the same as Deny.
            let mut devmap = HashMap::new();
            for cat in super::DeviceCategory::all() {
                if let Some(perm) = rule.get_permission(cat) {
                    devmap.insert(*cat, perm);
                }
            }
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
    /// * `ask` cannot be honoured: an LSM hook returns a verdict
    ///   in nanoseconds and cannot wait for a human. Treated as deny.
    /// * `while_in_use` has no kernel equivalent either. Treated as deny.
    ///
    /// A rule with no `exe_path` is PipeWire-only and is skipped.
    pub fn kernel_camera_allowlist(&self) -> Vec<(String, Permission)> {
        self.rules
            .iter()
            .filter(|r| r.camera == Some(Permission::Allow))
            .filter_map(|r| r.exe_path.clone().map(|p| (p, Permission::Allow)))
            .collect()
    }

    /// The camera allowlist including `while_in_use` rules whose session is
    /// currently live.
    ///
    /// `session_live` is injected rather than read, so the safety property —
    /// a while_in_use executable is allowlisted ONLY while its session is open
    /// — can be tested without a daemon, a kernel, or a clock.
    ///
    /// This is how a camera session is enforced. There is no way to hold an
    /// `open()` pending a human: the LSM hook must answer in nanoseconds. So
    /// the grant is expressed as presence in the allowlist, and ending the
    /// session means removing the entry — after which the next open is denied
    /// again, which is exactly what "only while in use" has to mean here.
    pub fn kernel_camera_allowlist_with_sessions<F>(&self, session_live: F) -> Vec<(String, Permission)>
    where
        F: Fn(&str) -> bool,
    {
        self.rules
            .iter()
            .filter(|r| match r.camera {
                Some(Permission::Allow) => true,
                Some(Permission::WhileInUse) => session_live(&r.app_name),
                _ => false,
            })
            .filter_map(|r| r.exe_path.clone().map(|p| (p, Permission::Allow)))
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
                Some(Permission::Allow) => Some((
                    r.app_name.clone(),
                    "camera = allow but no exe_path — the kernel layer will still deny it",
                )),
                Some(Permission::Ask | Permission::WhileInUse) => Some((
                    r.app_name.clone(),
                    "prompting permissions have no kernel equivalent; treated as deny there",
                )),
                // A rule with no opinion about the camera is not a gap: it
                // falls through to default_action like any unruled app, and
                // flagging it would put every mic-only rule in the warning.
                Some(Permission::Deny) | None => None,
            })
            .collect()
    }

    /// The one gap that is not per-rule: `default_action = "allow"` means every
    /// app without a camera rule is allowed at layer 1 and denied at layer 2,
    /// because the kernel allowlist is built from `exe_path` and an unruled app
    /// has none. Reported once at startup rather than once per rule.
    pub fn global_camera_gap(&self) -> Option<&'static str> {
        (self.policy.default_action == Permission::Allow).then_some(
            "default_action = allow: apps with no camera rule are allowed by the \
             PipeWire layer but still denied by the kernel layer, which has no \
             executable to allowlist for them",
        )
    }
}

/// Last path component of an executable. `/usr/lib/firefox-esr/firefox-esr`
/// becomes `firefox-esr`.
///
/// Lives here, beside [`normalize_app_name`], because the two are the project's
/// two identities and are easiest to keep straight when read together: the
/// PipeWire layer keys on a name an application declares about itself, the
/// kernel layer keys on an executable. `short_name` is only ever a *suggested*
/// rule name for a binary — never a match key.
pub fn short_name(exe_path: &str) -> String {
    exe_path
        .rsplit('/')
        .next()
        .filter(|s| !s.is_empty())
        .unwrap_or(exe_path)
        .to_string()
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

/// Turn a human-supplied string into a storable rule key, or `None` if it
/// cannot become one.
///
/// # Why this is separate from [`normalize_app_name`]
///
/// They run at different times and must stay different. `normalize_app_name` is
/// the MATCHER: it runs on every lookup, against names PipeWire reports, and it
/// is deliberately narrow — it exists to make `OBS`, `obs` and
/// `OBS [pipewire-pulse]` share one rule, and nothing more. Widening it would
/// make every future lookup fuzzier, which is the wrong direction for the
/// function that decides access.
///
/// This one runs once, on WRITE, on a string a human typed or pasted. It can
/// afford to be forgiving because a bad result is visible immediately in
/// `config.toml` rather than silently wrong forever.
///
/// What it repairs is the pid trap: notification bodies render
/// `{app} (pid:{n})`, users paste the whole thing, and the result ends with `)`
/// so the matcher strips nothing and the rule is dead on arrival.
pub fn sanitize_rule_name(app_name: &str) -> Option<String> {
    let mut s = app_name.trim();

    // Strip a trailing "(pid:N)". Only the pid form, and only at the end —
    // an app legitimately named "Foo (Beta)" must survive untouched.
    if s.ends_with(')') {
        if let Some(open) = s.rfind('(') {
            let inner = &s[open + 1..s.len() - 1];
            if let Some(digits) = inner.strip_prefix("pid:") {
                if !digits.is_empty() && digits.chars().all(|c| c.is_ascii_digit()) {
                    s = s[..open].trim_end();
                }
            }
        }
    }

    let key = normalize_app_name(s);
    if key.is_empty() {
        return None;
    }

    // A key that is nothing but a bracketed annotation — "[pipewire-pulse]" —
    // can never match either. `normalize_app_name` strips a trailing " [...]"
    // only when something precedes it, so no real application name ever
    // normalises to this shape. It is the residue of a label that lost its app
    // name, and one of the three dead rules found in the live config was
    // exactly this family.
    if key.starts_with('[') && key.ends_with(']') {
        return None;
    }

    Some(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DeviceCategory;

    fn rule(app: &str, cam: Permission, exe: Option<&str>) -> AppRule {
        AppRule {
            app_name: app.into(),
            microphone: Some(Permission::Deny),
            camera: Some(cam),
            monitor: Some(Permission::Deny),
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
            rule("zoom", Permission::Ask, Some("/usr/bin/zoom")),
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
        for p in [Permission::Ask, Permission::WhileInUse] {
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

    /// Settled 2026-08-21. README claimed deny-all for months while the shipped
    /// config said `ask`; the code honoured the config, so the effective
    /// behaviour was "prompt, then keep whatever you ignored".
    #[test]
    fn an_app_with_no_rule_is_denied_by_default() {
        let c = Config::default();
        assert_eq!(c.policy.default_action, Permission::Deny);
        assert_eq!(
            c.get_permission("never-seen", &DeviceCategory::Camera),
            Permission::Deny
        );
    }

    /// An existing config that predates the knob must not silently keep `ask`.
    #[test]
    fn a_config_without_default_action_deserialises_to_deny() {
        let c: Config = toml::from_str("[policy]\npoll_interval_ms = 500\n").unwrap();
        assert_eq!(c.policy.default_action, Permission::Deny);
        assert_eq!(c.policy.dismiss_cooldown_secs, 60);
        assert_eq!(c.policy.exe_recheck_secs, 30);
    }

    /// b4, the exact string found dead in the live config on 2026-08-21.
    /// A label pasted out of a notification body must become a rule that WORKS.
    #[test]
    fn a_pasted_notification_label_becomes_a_usable_rule() {
        let mut c = Config::default();
        assert!(c.set_rule(
            "Firefox [pipewire-pulse] (pid:2332)",
            &DeviceCategory::Camera,
            Permission::Allow
        ));
        assert_eq!(c.rules.len(), 1);
        assert_eq!(c.rules[0].app_name, "firefox", "stored key must be clean");
        assert!(
            c.find_rule("Firefox").is_some(),
            "and it must actually match the app it was written for"
        );
        assert_eq!(
            c.get_permission("Firefox [pipewire-pulse]", &DeviceCategory::Camera),
            Permission::Allow
        );
    }

    /// The empty-string rule was also live. It can never match — `parse_node`
    /// falls back to the literal "unknown", never to "".
    #[test]
    fn a_name_that_cannot_become_a_key_is_refused_and_writes_nothing() {
        let mut c = Config::default();
        for junk in ["", "   ", "(pid:99)", " [pipewire-pulse] "] {
            assert!(!c.set_rule(junk, &DeviceCategory::Camera, Permission::Allow),
                "{junk:?} must be refused");
        }
        assert!(c.rules.is_empty(), "nothing may be written: {:?}", c.rules);
    }

    /// Only the `(pid:N)` form is stripped, and only at the end. An app really
    /// called "Foo (Beta)" must keep its name — over-stripping would silently
    /// merge two different applications into one rule.
    #[test]
    fn sanitize_only_strips_a_trailing_pid_and_leaves_other_parentheses_alone() {
        assert_eq!(sanitize_rule_name("Firefox (pid:2332)").as_deref(), Some("firefox"));
        assert_eq!(sanitize_rule_name("Foo (Beta)").as_deref(), Some("foo (beta)"));
        assert_eq!(sanitize_rule_name("Foo (pid:)").as_deref(), Some("foo (pid:)"));
        assert_eq!(sanitize_rule_name("Foo (pid:abc)").as_deref(), Some("foo (pid:abc)"));
        assert_eq!(sanitize_rule_name("obs").as_deref(), Some("obs"));
    }

    fn preset(toml_src: &str) -> crate::preset::Preset {
        crate::preset::Preset::parse(toml_src).expect("preset parses")
    }

    const P: &str = r#"
name = "t"
[[app]]
name = "firefox"
microphone = "ask_each"
camera = "allow"
exe_candidates = ["/bin/sh"]
"#;

    #[test]
    fn applying_a_plan_writes_the_rule_with_its_resolved_binary() {
        let mut c = Config::default();
        let plan = preset(P).plan(|p| p == "/bin/sh", |a| c.find_rule(a).is_some());
        assert_eq!(c.apply_preset(&plan), 1);
        let r = c.find_rule("firefox").expect("imported");
        assert_eq!(r.camera, Some(Permission::Allow));
        assert_eq!(r.microphone, Some(Permission::Ask));
        assert_eq!(r.exe_path.as_deref(), Some("/bin/sh"));
    }

    /// The whole safety story of `preset import` is "look before you commit".
    /// A preview that added nothing and an apply that added something would be
    /// the worst possible bug in it.
    #[test]
    fn a_plan_that_adds_nothing_writes_nothing() {
        let mut c = Config::default();
        // camera = allow, no candidate resolves -> skipped
        let plan = preset(P).plan(|_| false, |a| c.find_rule(a).is_some());
        assert_eq!(plan.added_count(), 0);
        assert_eq!(c.apply_preset(&plan), 0);
        assert!(c.rules.is_empty());
    }

    /// Re-checked at apply time, not just at plan time: a preview may be
    /// minutes old and the user may have written a rule in between. An import
    /// must never overwrite a decision, however it arrived.
    #[test]
    fn a_rule_created_after_the_preview_is_still_not_overwritten() {
        let mut c = Config::default();
        let plan = preset(P).plan(|p| p == "/bin/sh", |_| false); // planned against an empty config

        // ...meanwhile the user decides firefox must never have the camera.
        assert!(c.set_rule("firefox", &DeviceCategory::Camera, Permission::Deny));

        assert_eq!(c.apply_preset(&plan), 0, "the plan is stale and must not win");
        assert_eq!(
            c.find_rule("firefox").unwrap().camera,
            Some(Permission::Deny),
            "the user's decision stands"
        );
        assert!(c.find_rule("firefox").unwrap().exe_path.is_none());
    }

    #[test]
    fn importing_twice_adds_nothing_the_second_time() {
        let mut c = Config::default();
        let p = preset(P);
        let plan1 = p.plan(|_| true, |a| c.find_rule(a).is_some());
        assert_eq!(c.apply_preset(&plan1), 1);
        let plan2 = p.plan(|_| true, |a| c.find_rule(a).is_some());
        assert_eq!(c.apply_preset(&plan2), 0);
        assert_eq!(c.rules.len(), 1);
    }

    /// Setting a second category on a pasted label must find the rule the first
    /// call created, not add a duplicate under a different spelling.
    #[test]
    fn two_writes_from_different_spellings_land_on_one_rule() {
        let mut c = Config::default();
        assert!(c.set_rule("Firefox [pipewire-pulse] (pid:1)", &DeviceCategory::Camera, Permission::Allow));
        assert!(c.set_rule("firefox", &DeviceCategory::Microphone, Permission::Deny));
        assert_eq!(c.rules.len(), 1, "{:?}", c.rules);
        assert_eq!(c.rules[0].camera, Some(Permission::Allow));
        assert_eq!(c.rules[0].microphone, Some(Permission::Deny));
    }

    // ---------------------------------------------------------------------
    // Optional categories, and the executable a camera grant needs.
    // Added 2026-08-23 after a live failure: deleting all rules and then
    // allowing firefox the camera produced a rule that read `allow` while the
    // kernel denied every open, and silently wrote two deny rules nobody
    // asked for. Every test below was run against the reintroduced defect and
    // observed to FAIL before being kept.
    // ---------------------------------------------------------------------

    /// Setting one category must write ONE category.
    ///
    /// The old constructor filled all three with `Deny`, so granting a camera
    /// also wrote `microphone = "deny"` and `monitor = "deny"` — which, with
    /// `default_action = "ask"`, silently downgraded the microphone from a
    /// prompt to a hard deny.
    #[test]
    fn set_rule_touches_exactly_one_category() {
        let mut c = Config::default();
        assert!(c.set_rule("firefox", &DeviceCategory::Camera, Permission::Allow));
        let r = c.find_rule("firefox").expect("created");
        assert_eq!(r.camera, Some(Permission::Allow));
        assert_eq!(r.microphone, None, "microphone was never asked about");
        assert_eq!(r.monitor, None, "monitor was never asked about");
    }

    /// A category the rule says nothing about follows `default_action`.
    /// Treating `None` as `Deny` is the same bug seen from the read side.
    #[test]
    fn an_unset_category_follows_the_default_action() {
        let mut c = Config::default();
        c.policy.default_action = Permission::Ask;
        assert!(c.set_rule("firefox", &DeviceCategory::Camera, Permission::Allow));
        assert_eq!(
            c.get_permission("firefox", &DeviceCategory::Microphone),
            Permission::Ask,
            "an unset category is not a deny"
        );
        assert_eq!(
            c.get_permission("firefox", &DeviceCategory::Camera),
            Permission::Allow
        );
    }

    /// What is not written must not appear in the FILE.
    ///
    /// The daemon rewrites `config.toml` wholesale on every rule change, so
    /// this is where a phantom deny would become permanent. Guards the same
    /// mechanism as `set_rule_touches_exactly_one_category` one layer out —
    /// proven by reintroducing that defect, not by touching serde: `toml`
    /// cannot represent `None` and omits it whatever `skip_serializing_if`
    /// says, so the attribute alone is not what this test is about.
    #[test]
    fn an_unset_category_is_not_serialised() {
        let mut c = Config::default();
        assert!(c.set_rule("firefox", &DeviceCategory::Camera, Permission::Allow));
        let text = toml::to_string_pretty(&c).expect("serialise");
        // Scoped to the rule block. `[devices]` legitimately carries
        // `microphone = true`, so searching the whole file would pass or fail
        // for the wrong reason.
        let rule_block = text
            .split("[[rules]]")
            .nth(1)
            .expect("a rule was written");
        assert!(rule_block.contains("camera = \"allow\""), "{rule_block}");
        assert!(
            !rule_block.contains("microphone"),
            "microphone leaked into the rule:\n{rule_block}"
        );
        assert!(
            !rule_block.contains("monitor"),
            "monitor leaked into the rule:\n{rule_block}"
        );
    }

    /// The agreed migration: existing files are left alone. A `deny` written
    /// by the old code cannot be told apart from a deliberate one, so it stays
    /// a deny — loosening it on load would relax a rule without asking.
    #[test]
    fn an_existing_explicit_deny_still_loads_as_a_deny() {
        let c: Config = toml::from_str(
            r#"
[[rules]]
app_name = "obs"
microphone = "deny"
camera = "allow"
monitor = "deny"
"#,
        )
        .expect("parse");
        let r = c.find_rule("obs").expect("loaded");
        assert_eq!(r.microphone, Some(Permission::Deny), "not silently unset");
        assert_eq!(r.camera, Some(Permission::Allow));
    }

    /// A rule with no opinion about the camera is not a kernel-layer gap — it
    /// falls through to `default_action` like any unruled app. Flagging it
    /// would put every microphone-only rule in the warning and make the
    /// warning worthless.
    #[test]
    fn a_rule_with_no_camera_opinion_is_not_a_gap() {
        let mut c = Config::default();
        assert!(c.set_rule("recorder", &DeviceCategory::Microphone, Permission::Allow));
        assert!(c.kernel_camera_gaps().is_empty(), "{:?}", c.kernel_camera_gaps());
    }

    /// The failure this whole change exists for: `camera = allow` with no
    /// binary reads as protection and denies at the kernel layer.
    #[test]
    fn a_camera_allow_without_a_binary_is_reported_as_a_gap() {
        let mut c = Config::default();
        assert!(c.set_rule("firefox", &DeviceCategory::Camera, Permission::Allow));
        let gaps = c.kernel_camera_gaps();
        assert_eq!(gaps.len(), 1, "{gaps:?}");
        assert_eq!(gaps[0].0, "firefox");
        assert!(c.kernel_camera_allowlist().is_empty(), "nothing to allowlist");
    }

    /// And once a binary is attached, the gap closes and the allowlist has it.
    #[test]
    fn attaching_a_binary_closes_the_gap() {
        let mut c = Config::default();
        assert!(c.set_rule("firefox", &DeviceCategory::Camera, Permission::Allow));
        // /bin/sh, because it exists everywhere this will ever be run and a
        // hardcoded inode has a half-life of one `apt upgrade`.
        c.set_rule_exe("firefox", "/bin/sh").expect("accepted");
        assert!(c.kernel_camera_gaps().is_empty());
        assert_eq!(
            c.kernel_camera_allowlist(),
            vec![("/bin/sh".to_string(), Permission::Allow)]
        );
    }

    // Refuse rather than store, the same way `set_rule` refuses an unusable
    // name (b4). Each guard gets its OWN test: the three overlap — a relative
    // path also fails to exist — so a single test asserting all three passes
    // with any one of them removed, and proves nothing about that one.

    #[test]
    fn set_rule_exe_refuses_an_app_with_no_rule() {
        let mut c = Config::default();
        assert!(c.set_rule_exe("firefox", "/bin/sh").is_err());
        assert!(c.find_rule("firefox").is_none(), "no rule conjured");
    }

    /// The kernel resolves an executable by inode from an absolute path. A
    /// relative one can never match. Uses a path that DOES exist relative to
    /// nothing in particular, so the existence guard cannot be what fails it.
    #[test]
    fn set_rule_exe_refuses_a_relative_path() {
        let mut c = Config::default();
        assert!(c.set_rule("firefox", &DeviceCategory::Camera, Permission::Allow));
        let err = c
            .set_rule_exe("firefox", "bin/sh")
            .expect_err("a relative path cannot be resolved to an inode");
        assert!(err.contains("absolute"), "wrong reason: {err}");
        assert_eq!(c.find_rule("firefox").unwrap().exe_path, None, "wrote nothing");
    }

    /// An absolute path that does not exist — so the absolute-path guard
    /// cannot be what fails it.
    #[test]
    fn set_rule_exe_refuses_a_path_that_does_not_exist() {
        let mut c = Config::default();
        assert!(c.set_rule("firefox", &DeviceCategory::Camera, Permission::Allow));
        let err = c
            .set_rule_exe("firefox", "/nonexistent/binary")
            .expect_err("a path that cannot be stat'ed is not a binary");
        assert!(err.contains("does not exist"), "wrong reason: {err}");
        assert_eq!(c.find_rule("firefox").unwrap().exe_path, None, "wrote nothing");
    }

    /// Clearing is explicit and separate from failing.
    #[test]
    fn set_rule_exe_clears_with_an_empty_string() {
        let mut c = Config::default();
        assert!(c.set_rule("firefox", &DeviceCategory::Camera, Permission::Allow));
        c.set_rule_exe("firefox", "/bin/sh").expect("accepted");
        c.set_rule_exe("firefox", "").expect("cleared");
        assert_eq!(c.find_rule("firefox").unwrap().exe_path, None);
    }

    /// `default_action = allow` allows every unruled app at the PipeWire layer
    /// and denies it at the kernel layer, which has no executable for it. That
    /// is one global gap, not one per rule.
    #[test]
    fn allow_by_default_is_reported_as_a_global_gap() {
        let mut c = Config::default();
        assert!(c.global_camera_gap().is_none(), "deny-by-default is no gap");
        c.policy.default_action = Permission::Allow;
        assert!(c.global_camera_gap().is_some());
    }

    /// Configs and presets written before 2026-08-23 say `ask_each`. The
    /// variant is gone; the STRING must still load, or the daemon refuses to
    /// start on an existing install. Mapped to `ask` — the user wanted to be
    /// asked, and that is the surviving way to be asked.
    #[test]
    fn an_old_ask_each_config_still_loads() {
        let c: Config = toml::from_str(
            r#"
[[rules]]
app_name = "firefox"
microphone = "ask_each"
"#,
        )
        .expect("a config with ask_each must not break the daemon");
        assert_eq!(
            c.find_rule("firefox").unwrap().microphone,
            Some(Permission::Ask)
        );
    }

    /// The same string, through the CLI/D-Bus parser rather than serde.
    #[test]
    fn the_ask_each_string_still_parses_to_ask() {
        assert_eq!("ask_each".parse::<Permission>().unwrap(), Permission::Ask);
    }

    /// And it is no longer OFFERED — the error message must not advertise a
    /// permission that no longer exists.
    #[test]
    fn ask_each_is_not_advertised_as_valid() {
        let err = "nonsense".parse::<Permission>().unwrap_err();
        assert!(!err.contains("ask_each"), "{err}");
        assert!(err.contains("while_in_use"), "{err}");
    }

    // -- camera sessions (d-camera-sessions-via-file-release) ---------------

    /// The safety property of a camera session, stated once.
    ///
    /// A `while_in_use` executable is in the kernel allowlist ONLY while its
    /// session is live. There is no way to hold an open() pending a human — the
    /// LSM hook answers in nanoseconds — so presence in the allowlist IS the
    /// grant, and ending the session has to mean removing the entry.
    #[test]
    fn a_while_in_use_camera_is_allowlisted_only_during_its_session() {
        let mut c = Config::default();
        assert!(c.set_rule("firefox", &DeviceCategory::Camera, Permission::Allow));
        c.set_rule_exe("firefox", "/bin/sh").expect("binary");
        assert!(c.set_rule("firefox", &DeviceCategory::Camera, Permission::WhileInUse));

        assert!(
            c.kernel_camera_allowlist_with_sessions(|_| false).is_empty(),
            "no session: the kernel must deny it"
        );
        assert_eq!(
            c.kernel_camera_allowlist_with_sessions(|_| true),
            vec![("/bin/sh".to_string(), Permission::Allow)],
            "session live: the kernel must allow it"
        );
    }

    /// A plain `allow` is unconditional and must not be dragged into the
    /// session logic — it has no session and must never depend on one.
    #[test]
    fn a_plain_allow_camera_ignores_sessions_entirely() {
        let mut c = Config::default();
        assert!(c.set_rule("obs", &DeviceCategory::Camera, Permission::Allow));
        c.set_rule_exe("obs", "/bin/sh").expect("binary");
        for live in [true, false] {
            assert_eq!(
                c.kernel_camera_allowlist_with_sessions(|_| live).len(),
                1,
                "allow does not depend on a session"
            );
        }
    }

    /// The session predicate is consulted PER RULE, so one app's live session
    /// must not allowlist another app's binary.
    #[test]
    fn one_apps_session_does_not_allowlist_another_app() {
        let mut c = Config::default();
        for app in ["firefox", "chrome"] {
            assert!(c.set_rule(app, &DeviceCategory::Camera, Permission::Allow));
            c.set_rule_exe(app, "/bin/sh").expect("binary");
            assert!(c.set_rule(app, &DeviceCategory::Camera, Permission::WhileInUse));
        }
        let allow = c.kernel_camera_allowlist_with_sessions(|app| app == "firefox");
        assert_eq!(allow.len(), 1, "only the app with a live session: {allow:?}");
    }

    /// A camera session is enforced by adding and removing an allowlist entry,
    /// and there is nothing to add without a binary. Unlike a plain
    /// `camera = allow`, which is meaningful for a portal app on the PipeWire
    /// route, this one can do nothing at all — so it is refused.
    #[test]
    fn a_camera_session_without_a_binary_is_refused() {
        let mut c = Config::default();
        assert!(c.set_rule("firefox", &DeviceCategory::Microphone, Permission::Allow));
        assert!(
            !c.set_rule("firefox", &DeviceCategory::Camera, Permission::WhileInUse),
            "no exe_path: nothing to add to the allowlist"
        );
        assert_eq!(c.find_rule("firefox").unwrap().camera, None, "nothing written");
    }

    /// And it IS accepted once a binary is attached.
    #[test]
    fn a_camera_session_with_a_binary_is_accepted() {
        let mut c = Config::default();
        assert!(c.set_rule("firefox", &DeviceCategory::Camera, Permission::Allow));
        c.set_rule_exe("firefox", "/bin/sh").expect("binary");
        assert!(c.set_rule("firefox", &DeviceCategory::Camera, Permission::WhileInUse));
    }

    /// The refusal is specific to the camera. Microphone and monitor go through
    /// PipeWire, where a vanishing link IS the release signal.
    #[test]
    fn the_microphone_and_monitor_accept_while_in_use() {
        let mut c = Config::default();
        assert!(c.set_rule("firefox", &DeviceCategory::Microphone, Permission::WhileInUse));
        assert!(c.set_rule("firefox", &DeviceCategory::Monitor, Permission::WhileInUse));
        assert_eq!(
            c.find_rule("firefox").unwrap().microphone,
            Some(Permission::WhileInUse)
        );
    }

    /// And it is specific to the PERMISSION — the camera still takes the others.
    #[test]
    fn the_camera_still_accepts_allow_and_deny() {
        let mut c = Config::default();
        assert!(c.set_rule("firefox", &DeviceCategory::Camera, Permission::Allow));
        assert!(c.set_rule("chrome", &DeviceCategory::Camera, Permission::Deny));
    }

    /// The suggested rule name for a binary. Only ever a suggestion — the
    /// PipeWire layer knows Firefox as `firefox` while the binary is
    /// `firefox-esr`, which is exactly why the GUI offers a choice.
    #[test]
    fn short_name_is_the_last_path_component() {
        assert_eq!(short_name("/usr/lib/firefox-esr/firefox-esr"), "firefox-esr");
        assert_eq!(short_name("/opt/google/chrome/chrome"), "chrome");
        assert_eq!(short_name("bare"), "bare");
        assert_eq!(short_name("/trailing/"), "/trailing/", "no empty name");
    }
}
