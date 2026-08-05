use hwprivacy_common::device::ProtectedDevice;
use hwprivacy_common::Config;
use crate::lsm_client::KernelLayerState;
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
        }
    }
}
