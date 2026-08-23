/// D-Bus constants
pub const DBUS_NAME: &str = "org.hwprivacy.Daemon";
pub const DBUS_PATH: &str = "/org/hwprivacy/Daemon";

/// D-Bus proxy for clients (CLI, TUI, GUI) to talk to the daemon.
#[zbus::proxy(
    interface = "org.hwprivacy.Daemon",
    default_service = "org.hwprivacy.Daemon",
    default_path = "/org/hwprivacy/Daemon"
)]
pub trait HwPrivacy {
    /// Get all discovered protected devices: (category, name, description, guarded)
    fn get_devices(&self) -> zbus::Result<Vec<(String, String, String, bool)>>;

    /// Get all rules, ONE ROW PER RULE:
    /// `(app_name, microphone, camera, monitor, exe_path, gap_note)`
    ///
    /// A permission is `""` when the rule has no opinion about that category,
    /// which means it follows `default_action` — not that it is denied.
    /// `exe_path` is `""` when absent. `gap_note` is `""` when the rule can
    /// reach every layer it names, and otherwise says why it cannot.
    ///
    /// This used to return three rows per rule with the categories flattened,
    /// so one rule rendered as three in every frontend and there was nowhere
    /// to put `exe_path` — which is the field that decides whether a camera
    /// grant does anything at all.
    fn get_rules(&self) -> zbus::Result<Vec<(String, String, String, String, String, String)>>;

    /// Set a rule for an app + device. Returns true on success.
    ///
    /// Touches ONLY the named category. The other two are left as they were,
    /// or absent on a new rule.
    fn set_rule(&self, app_name: &str, device: &str, permission: &str) -> zbus::Result<bool>;

    /// Attach the kernel-layer executable to an app's rule, or clear it with
    /// `""`. Returns `(ok, message)`; `message` says why on failure.
    ///
    /// The kernel layer allowlists by executable inode and never looks at
    /// `app_name`, so this — not [`set_rule`] — is what makes a camera grant
    /// take effect for a non-sandboxed application.
    fn set_rule_exe(&self, app_name: &str, exe_path: &str) -> zbus::Result<(bool, String)>;

    /// Grant a camera at BOTH layers in one step: `camera = allow` on the rule
    /// plus the executable the kernel layer matches on.
    ///
    /// One method rather than two calls, because the halfway state — a rule
    /// reading `allow` with no binary — is precisely the thing that warns, and
    /// doing it in two calls raises that warning for an operation that is
    /// about to complete successfully. Returns `(ok, message)`.
    fn allow_camera(&self, app_name: &str, exe_path: &str) -> zbus::Result<(bool, String)>;

    /// Remove all rules for an app. Returns true if rules existed.
    fn remove_rule(&self, app_name: &str) -> zbus::Result<bool>;

    /// Get active streams: (app_name, pid, device_category, node_name, media_name, permission, active)
    fn get_active_streams(&self) -> zbus::Result<Vec<(String, u32, String, String, String, String, bool)>>;

    /// Get daemon status: (running, guarded_devices, active_rules, blocked_count, active_streams)
    fn get_status(&self) -> zbus::Result<(bool, u32, u32, u32, u32)>;

    /// Get recent events: (timestamp, app_name, device_category, action)
    fn get_events(&self, last_n: u32) -> zbus::Result<Vec<(String, String, String, String)>>;

    /// Kernel (eBPF LSM) layer status:
    /// (connected, enforcing_camera, allowed_exes, unresolved, last_error)
    fn get_kernel_status(&self) -> zbus::Result<(bool, bool, u32, u32, String)>;

    /// Persistent denial counters, most persistent first:
    /// (identity, device, source, denied, first_seen, last_seen)
    ///
    /// Survives daemon restarts, unlike `get_events`, which reads an in-memory
    /// ring buffer.
    fn get_history(&self) -> zbus::Result<Vec<(String, String, String, u32, u32, String, String)>>;

    /// Importable presets: (name, description, entry_count, source_path)
    fn get_presets(&self) -> zbus::Result<Vec<(String, String, u32, String)>>;

    /// Plan (apply = false) or apply (apply = true) a preset import.
    /// Returns (app, outcome_line, was_added) per entry.
    ///
    /// `apply = false` writes NOTHING — a preset is a grant, so previewing is
    /// what you get by forgetting the flag.
    fn import_preset(&self, name: &str, apply: bool)
        -> zbus::Result<Vec<(String, String, bool)>>;

    /// Emergency: deny everything immediately
    fn block_all(&self) -> zbus::Result<bool>;

    /// Restore to saved rules
    fn unblock_all(&self) -> zbus::Result<bool>;

    // AllowStream / DenyStream removed 2026-08-23 with `ask_each`.

    // -- Signals --

    #[zbus(signal)]
    fn access_attempt(
        &self,
        app_name: &str,
        pid: u32,
        device: &str,
        node_name: &str,
        action: &str,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    fn rule_changed(
        &self,
        app_name: &str,
        device: &str,
        new_permission: &str,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    fn stream_event(
        &self,
        app_name: &str,
        device: &str,
        object_serial: u32,
        event_type: &str,
    ) -> zbus::Result<()>;
}
