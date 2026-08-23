use hwprivacy_common::device::ProtectedDevice;
use hwprivacy_common::Config;
use crate::lsm_client::KernelLayerState;
use crate::history::History;
use crate::notify_allow::AllowNotifier;
use crate::stream_tracker::StreamTracker;
use std::collections::HashSet;
use std::time::Instant;

/// Full runtime state of the daemon.
pub struct DaemonState {
    /// Configuration (rules, policy, device toggles)
    pub config: Config,
    /// Discovered protected devices
    pub devices: Vec<ProtectedDevice>,
    /// Stream tracker (active connections, events, pending)
    pub tracker: StreamTracker,
    /// Known link IDs from last graph poll (for diff detection)
    pub known_link_ids: HashSet<u32>,
    /// Emergency block-all mode
    pub block_all: bool,
    /// What we know about the kernel (eBPF LSM) layer. Absent/disconnected is
    /// normal — it is an addition, never a dependency.
    pub kernel: KernelLayerState,
    /// Per-executable access counters that SURVIVE a restart, unlike
    /// `tracker.events` which is a 500-entry in-memory ring buffer.
    pub history: History,
    /// Rate-limits "X used your camera" so boot probes and repeat opens do not
    /// become a stream of popups.
    pub allow_notifier: AllowNotifier,
    /// When the daemon started. Only used for the notify-on-allow grace window,
    /// which suppresses the camera probes every boot produces.
    pub started_at: Instant,
}

impl DaemonState {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            devices: Vec::new(),
            tracker: StreamTracker::new(),
            known_link_ids: HashSet::new(),
            block_all: false,
            kernel: KernelLayerState::default(),
            history: History::load_with_legacy(
                crate::history::default_path(),
                crate::history::legacy_path(),
            ),
            allow_notifier: AllowNotifier::default(),
            started_at: Instant::now(),
        }
    }

    /// How long the daemon has been up.
    pub fn uptime(&self) -> std::time::Duration {
        self.started_at.elapsed()
    }

    /// Log a PipeWire-layer denial AND count it in the persistent table.
    ///
    /// One method rather than two calls at each of the three denial sites in
    /// `main.rs`: keeping them together is what stops the counters drifting
    /// away from the event log. The kernel layer has its own entry point
    /// (`lsm_client::record_offender`) because it counts coalesced bursts,
    /// which have no equivalent here — one PipeWire link is one denial.
    ///
    /// Identity is the NORMALISED app name, so `Firefox [pipewire-pulse]` and
    /// `Firefox` aggregate into one row instead of two. Note this identity is
    /// self-declared by the application and far weaker than the kernel layer's
    /// `exe_path`; the table records which source a row came from so the two
    /// are never mistaken for each other.
    pub fn log_denied(
        &mut self,
        app_name: &str,
        pid: u32,
        category: hwprivacy_common::DeviceCategory,
        instance: Option<&str>,
        node_name: &str,
    ) {
        use hwprivacy_common::stream::AccessAction;
        self.tracker
            .log_event(app_name, pid, category, instance, node_name, AccessAction::Denied);
        let now = chrono::Local::now()
            .format("%Y-%m-%d %H:%M:%S")
            .to_string();
        self.history.record_denied(
            &hwprivacy_common::config::normalize_app_name(app_name),
            &format!("{category:?}").to_lowercase(),
            crate::history::SOURCE_PIPEWIRE,
            1,
            &now,
        );
        self.history.save_if_dirty();
    }

    /// Log a PipeWire-layer ALLOW and count it in the persistent table.
    ///
    /// Mirrors [`Self::log_denied`] deliberately: the allow path used to write
    /// an event-log row and nothing else, so "did anything use my camera on
    /// Tuesday" was unanswerable for exactly the accesses that succeeded.
    pub fn log_allowed(
        &mut self,
        app_name: &str,
        pid: u32,
        category: hwprivacy_common::DeviceCategory,
        instance: Option<&str>,
        node_name: &str,
    ) {
        use hwprivacy_common::stream::AccessAction;
        self.tracker
            .log_event(app_name, pid, category, instance, node_name, AccessAction::Allowed);
        let now = chrono::Local::now()
            .format("%Y-%m-%d %H:%M:%S")
            .to_string();
        self.history.record_allowed(
            &hwprivacy_common::config::normalize_app_name(app_name),
            &format!("{category:?}").to_lowercase(),
            crate::history::SOURCE_PIPEWIRE,
            1,
            &now,
        );
        self.history.save_if_dirty();
    }
}
