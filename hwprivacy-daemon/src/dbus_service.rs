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
        state.config.set_rule(app_name, &category, perm);

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
                    e.device_category.to_string(),
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

    async fn allow_stream(&self, object_serial: u32) -> bool {
        let mut state = self.state.write().await;
        state.tracker.grant_one_shot(object_serial);
        info!("One-shot allow granted for stream serial={}", object_serial);
        true
    }

    async fn deny_stream(&self, _object_serial: u32) -> bool {
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
