use hwprivacy_common::stream::{AccessAction, AccessEvent, ActiveConnection, StreamInfo};
use hwprivacy_common::{DeviceCategory, Permission};
use std::collections::HashMap;
use std::time::Instant;
use tracing::info;

/// Notification cooldown duration after a dismiss (seconds).
const DISMISS_COOLDOWN_SECS: u64 = 60;

/// Tracks active streams, pending requests, and event log.
pub struct StreamTracker {
    /// Active connections: link_id → ActiveConnection
    pub active: HashMap<u32, ActiveConnection>,
    /// Streams allowed with "while_in_use": app_name → set of object_serials
    pub while_in_use_streams: HashMap<String, Vec<u32>>,
    /// Recent events log (ring buffer, max 500)
    pub events: Vec<AccessEvent>,
    /// Counter for blocked access attempts
    pub blocked_count: u32,
    /// Session-level one-shot allows (for ask_each): object_serial
    pub one_shot_allowed: Vec<u32>,
    /// Notification cooldown: (app_name, device_category) → last dismiss time.
    /// When a user dismisses a notification, suppress the same prompt
    /// for DISMISS_COOLDOWN_SECS to avoid notification spam.
    pub dismiss_cooldowns: HashMap<(String, DeviceCategory), Instant>,
}

impl StreamTracker {
    pub fn new() -> Self {
        Self {
            active: HashMap::new(),
            while_in_use_streams: HashMap::new(),
            events: Vec::new(),
            blocked_count: 0,
            one_shot_allowed: Vec::new(),
            dismiss_cooldowns: HashMap::new(),
        }
    }

    /// Record a dismiss for cooldown purposes.
    pub fn record_dismiss(&mut self, app_name: &str, category: DeviceCategory) {
        self.dismiss_cooldowns
            .insert((app_name.to_string(), category), Instant::now());
    }

    /// Check if a notification for this app+device is in cooldown.
    pub fn is_in_cooldown(&self, app_name: &str, category: DeviceCategory) -> bool {
        if let Some(dismissed_at) = self.dismiss_cooldowns.get(&(app_name.to_string(), category)) {
            dismissed_at.elapsed().as_secs() < DISMISS_COOLDOWN_SECS
        } else {
            false
        }
    }

    /// Record a new access event.
    pub fn log_event(
        &mut self,
        app_name: &str,
        pid: u32,
        category: DeviceCategory,
        node_name: &str,
        action: AccessAction,
    ) {
        let event = AccessEvent {
            timestamp: chrono::Local::now().format("%H:%M:%S").to_string(),
            app_name: app_name.to_string(),
            pid,
            device_category: category,
            node_name: node_name.to_string(),
            action: action.clone(),
        };

        info!(
            "Event: {} (pid:{}) → {:?} → {}",
            app_name, pid, category, action
        );

        // Keep max 500 events
        if self.events.len() >= 500 {
            self.events.remove(0);
        }
        self.events.push(event);

        if matches!(action, AccessAction::Denied | AccessAction::StreamDenied) {
            self.blocked_count += 1;
        }
    }

    /// Track an active connection.
    pub fn add_connection(
        &mut self,
        link_id: u32,
        stream: StreamInfo,
        device_node_name: &str,
        device_category: DeviceCategory,
        permission: Permission,
    ) {
        let conn = ActiveConnection {
            stream,
            device_node_name: device_node_name.to_string(),
            device_category,
            permission,
            link_id: Some(link_id),
            active: true,
        };
        self.active.insert(link_id, conn);
    }

    /// Remove a connection when its link is destroyed.
    pub fn remove_connection(&mut self, link_id: u32) {
        self.active.remove(&link_id);
    }

    /// Track a while_in_use stream.
    pub fn track_while_in_use(&mut self, app_name: &str, object_serial: u32) {
        self.while_in_use_streams
            .entry(app_name.to_string())
            .or_default()
            .push(object_serial);
    }

    /// Check if a stream was one-shot allowed (for ask_each).
    pub fn is_one_shot_allowed(&self, object_serial: u32) -> bool {
        self.one_shot_allowed.contains(&object_serial)
    }

    /// Grant one-shot allow for a stream.
    pub fn grant_one_shot(&mut self, object_serial: u32) {
        if !self.one_shot_allowed.contains(&object_serial) {
            self.one_shot_allowed.push(object_serial);
        }
    }

    /// Get recent events.
    pub fn recent_events(&self, n: usize) -> &[AccessEvent] {
        let start = self.events.len().saturating_sub(n);
        &self.events[start..]
    }

    /// Get active connection count.
    pub fn active_count(&self) -> u32 {
        self.active.values().filter(|c| c.active).count() as u32
    }
}
