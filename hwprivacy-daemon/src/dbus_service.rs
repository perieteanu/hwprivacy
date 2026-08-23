use crate::state::DaemonState;
use hwprivacy_common::{DeviceCategory, Permission};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::info;
use zbus::object_server::SignalContext;

pub type SharedState = Arc<RwLock<DaemonState>>;

pub struct HwPrivacyService {
    pub state: SharedState,
}

#[zbus::interface(name = "org.hwprivacy.Daemon")]
impl HwPrivacyService {
    async fn get_devices(&self) -> Vec<(String, String, String, bool)> {
        let state = self.state.read().await;
        state
            .devices
            .iter()
            .map(|d| {
                (
                    d.category.to_string(),
                    d.node_name.clone(),
                    d.description.clone(),
                    d.guarded,
                )
            })
            .collect()
    }

    async fn get_rules(&self) -> Vec<(String, String, String)> {
        let state = self.state.read().await;
        let mut result = Vec::new();
        for rule in &state.config.rules {
            for cat in DeviceCategory::all() {
                let perm = rule.get_permission(cat);
                result.push((rule.app_name.clone(), cat.to_string(), perm.to_string()));
            }
        }
        result
    }

    async fn set_rule(
        &self,
        #[zbus(signal_context)] ctx: SignalContext<'_>,
        app_name: &str,
        device: &str,
        permission: &str,
    ) -> bool {
        let category: DeviceCategory = match device.parse() {
            Ok(c) => c,
            Err(_) => return false,
        };
        let perm: Permission = match permission.parse() {
            Ok(p) => p,
            Err(_) => return false,
        };

        let mut state = self.state.write().await;

        // Refuse names that could never match anything rather than writing a
        // rule that silently does nothing. Three such rules were sitting in the
        // live config — pasted notification labels ending in "(pid:2332)", and
        // one empty string (blocker b4).
        if !state.config.set_rule(app_name, &category, perm) {
            tracing::warn!(
                "Rejected rule for {:?}: not a usable rule key. Use the bare app name, \
                 e.g. 'firefox' — not a pasted notification label.",
                app_name
            );
            return false;
        }

        if let Err(e) = state.config.save() {
            tracing::error!("Failed to save config: {}", e);
        }

        let _ = Self::rule_changed(&ctx, app_name, device, permission).await;
        info!("Rule set: {} → {} = {}", app_name, device, permission);
        true
    }

    async fn remove_rule(
        &self,
        #[zbus(signal_context)] ctx: SignalContext<'_>,
        app_name: &str,
    ) -> bool {
        let mut state = self.state.write().await;
        let removed = state.config.remove_rule(app_name);
        if removed {
            if let Err(e) = state.config.save() {
                tracing::error!("Failed to save config: {}", e);
            }
            let _ = Self::rule_changed(&ctx, app_name, "*", "removed").await;
            info!("Rules removed for: {}", app_name);
        }
        removed
    }

    async fn get_active_streams(&self) -> Vec<(String, u32, String, String, String, String, bool)> {
        let state = self.state.read().await;
        state
            .tracker
            .active
            .values()
            .map(|c| {
                (
                    c.stream.app_name.clone(),
                    c.stream.pid,
                    c.device_category.to_string(),
                    c.stream.node_name.clone(),
                    c.stream.media_name.clone(),
                    c.permission.to_string(),
                    c.active,
                )
            })
            .collect()
    }

    async fn get_status(&self) -> (bool, u32, u32, u32, u32) {
        let state = self.state.read().await;
        (
            true, // running
            state.devices.iter().filter(|d| d.guarded).count() as u32,
            state.config.rules.len() as u32,
            state.tracker.blocked_count,
            state.tracker.active_count(),
        )
    }

    /// Kernel (eBPF LSM) layer status: (connected, enforcing_camera,
    /// allowed_executables, unresolved_entries, last_error).
    ///
    /// A NEW method rather than a change to GetStatus, whose signature three
    /// frontends already depend on. Additive keeps ctl/tui/gui working
    /// untouched — which was the whole point of routing kernel events through
    /// the existing StreamTracker.
    async fn get_kernel_status(&self) -> (bool, bool, u32, u32, String) {
        let state = self.state.read().await;
        let k = &state.kernel;
        (
            k.connected,
            k.enforcing_camera,
            k.allowed_exes,
            k.unresolved.len() as u32,
            k.last_error.clone().unwrap_or_default(),
        )
    }

    /// Persistent denial counters: (identity, device, source, denied,
    /// first_seen, last_seen), most persistent first.
    ///
    /// Unlike GetEvents, which reads a 500-entry in-memory ring buffer that
    /// dies with the daemon, this survives restarts — it is the answer to
    /// "who has been trying, over days".
    ///
    /// Additive, like GetKernelStatus: GetEvents keeps its signature so the
    /// three frontends stay working untouched.
    async fn get_offenders(&self) -> Vec<(String, String, String, u32, String, String)> {
        let state = self.state.read().await;
        state
            .offenders
            .sorted()
            .into_iter()
            .map(|o| {
                (
                    o.identity,
                    o.device,
                    o.source,
                    o.denied,
                    o.first_seen,
                    o.last_seen,
                )
            })
            .collect()
    }

    async fn get_events(&self, last_n: u32) -> Vec<(String, String, String, String)> {
        let state = self.state.read().await;
        state
            .tracker
            .recent_events(last_n as usize)
            .iter()
            .map(|e| {
                (
                    e.timestamp.clone(),
                    e.app_name.clone(),
                    // device_display(), not device_category: two rows for two
                    // different microphones were indistinguishable here, which
                    // is half of what made b3 read as duplicate prompts.
                    e.device_display(),
                    e.action.to_string(),
                )
            })
            .collect()
    }

    async fn block_all(&self) -> bool {
        let mut state = self.state.write().await;
        state.block_all = true;
        info!("EMERGENCY: Block-all mode enabled");
        true
    }

    async fn unblock_all(&self) -> bool {
        let mut state = self.state.write().await;
        state.block_all = false;
        info!("Block-all mode disabled, restoring saved rules");
        true
    }

    /// Grant a one-shot `ask_each` allow.
    ///
    /// Takes the app name as well as the node id, because a node id alone is
    /// not an identity: PipeWire reuses ids, so a grant keyed on the id only
    /// can land on an unrelated later stream (blocker b2). The caller already
    /// has the name — `GetActiveStreams` returns it beside the id.
    async fn allow_stream(&self, node_id: u32, app_name: &str) -> bool {
        let mut state = self.state.write().await;
        state.tracker.grant_one_shot(node_id, app_name);
        info!("One-shot allow granted: {} on node {}", app_name, node_id);
        true
    }

    async fn deny_stream(&self, _node_id: u32) -> bool {
        // Stream is already denied (link was destroyed); this is a no-op confirmation
        true
    }

    // -- Signals --

    #[zbus(signal)]
    async fn access_attempt(
        ctx: &SignalContext<'_>,
        app_name: &str,
        pid: u32,
        device: &str,
        node_name: &str,
        action: &str,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn rule_changed(
        ctx: &SignalContext<'_>,
        app_name: &str,
        device: &str,
        new_permission: &str,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn stream_event(
        ctx: &SignalContext<'_>,
        app_name: &str,
        device: &str,
        object_serial: u32,
        event_type: &str,
    ) -> zbus::Result<()>;
}
