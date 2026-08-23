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

    /// Get all rules: (app_name, device_category, permission)
    fn get_rules(&self) -> zbus::Result<Vec<(String, String, String)>>;

    /// Set a rule for an app + device. Returns true on success.
    fn set_rule(&self, app_name: &str, device: &str, permission: &str) -> zbus::Result<bool>;

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

    /// Emergency: deny everything immediately
    fn block_all(&self) -> zbus::Result<bool>;

    /// Restore to saved rules
    fn unblock_all(&self) -> zbus::Result<bool>;

    /// One-shot allow a pending stream.
    ///
    /// Both arguments are required: a PipeWire node id is reused once its node
    /// is gone, so the app name is what stops a grant migrating to an unrelated
    /// stream. `GetActiveStreams` returns both.
    fn allow_stream(&self, node_id: u32, app_name: &str) -> zbus::Result<bool>;

    /// One-shot deny a pending stream by node id
    fn deny_stream(&self, node_id: u32) -> zbus::Result<bool>;

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
