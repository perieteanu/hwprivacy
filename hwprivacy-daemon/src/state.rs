use hwprivacy_common::device::ProtectedDevice;
use hwprivacy_common::Config;
use crate::lsm_client::KernelLayerState;
use crate::offenders::Offenders;
use crate::stream_tracker::StreamTracker;
use std::collections::HashSet;

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
    /// Per-executable denial counters that SURVIVE a restart, unlike
    /// `tracker.events` which is a 500-entry in-memory ring buffer.
    pub offenders: Offenders,
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
            offenders: Offenders::load(crate::offenders::default_path()),
        }
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
        node_name: &str,
    ) {
        use hwprivacy_common::stream::AccessAction;
        self.tracker
            .log_event(app_name, pid, category, node_name, AccessAction::Denied);
        let now = chrono::Local::now()
            .format("%Y-%m-%d %H:%M:%S")
            .to_string();
        self.offenders.record(
            &hwprivacy_common::config::normalize_app_name(app_name),
            &format!("{category:?}").to_lowercase(),
            crate::offenders::SOURCE_PIPEWIRE,
            1,
            &now,
        );
        self.offenders.save_if_dirty();
    }
}
