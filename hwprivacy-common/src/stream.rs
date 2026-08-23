use serde::{Deserialize, Serialize};

/// Information about a PipeWire stream (app node) trying to access a device.
/// Extracted from PipeWire node properties via pw-dump.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamInfo {
    /// The PipeWire **node id** of this stream.
    ///
    /// Named `object_serial` until 2026-08-21, which was a lie with
    /// consequences: PipeWire's `object.serial` is monotonic and never reused,
    /// while a node id is reused freely once the node is gone. One-shot
    /// `ask_each` grants are keyed on this value, so under the old name the
    /// leak in blocker b2 read as a tuning problem instead of a grant landing
    /// on an unrelated later stream. `pw-dump`'s `object.serial` is not parsed
    /// here at all — see `pipewire_monitor::NodeInfo`.
    pub node_id: u32,
    /// Application name from PipeWire (e.g., "Firefox", "telegram-desktop")
    pub app_name: String,
    /// Process ID of the application
    pub pid: u32,
    /// PipeWire node name (unique per stream)
    pub node_name: String,
    /// Media name (sometimes tab/stream info)
    pub media_name: String,
    /// Media class (e.g., "Stream/Input/Audio", "Stream/Input/Video")
    pub media_class: String,
}

/// An active connection between an app stream and a protected device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveConnection {
    pub stream: StreamInfo,
    pub device_node_name: String,
    pub device_category: super::DeviceCategory,
    /// The permission that allowed/denied this connection
    pub permission: super::Permission,
    /// PipeWire link ID (if the link is currently active)
    pub link_id: Option<u32>,
    /// Is the link currently active (or was it destroyed)?
    pub active: bool,
}

/// An event in the access log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessEvent {
    pub timestamp: String,
    pub app_name: String,
    pub pid: u32,
    pub device_category: super::DeviceCategory,
    /// Which instance of the device, when the node presents more than one —
    /// `mic1`, `mic2`. `None` for the ordinary single-device case.
    ///
    /// Its own field rather than being folded into `node_name`: that one is the
    /// *stream's* node name and answers a different question.
    #[serde(default)]
    pub device_instance: Option<String>,
    pub node_name: String,
    pub action: AccessAction,
}

impl AccessEvent {
    /// The device as the user should read it: `microphone (mic2)`.
    pub fn device_display(&self) -> String {
        match &self.device_instance {
            Some(i) => format!("{} ({})", self.device_category, i),
            None => self.device_category.to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AccessAction {
    Allowed,
    Denied,
    AskedUser,
    StreamAllowed,  // one-shot allow for ask_each
    StreamDenied,   // one-shot deny for ask_each
    RevokedOnDisconnect, // while_in_use client disconnected
}

impl std::fmt::Display for AccessAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AccessAction::Allowed => write!(f, "ALLOWED"),
            AccessAction::Denied => write!(f, "DENIED"),
            AccessAction::AskedUser => write!(f, "ASKED"),
            AccessAction::StreamAllowed => write!(f, "STREAM_ALLOWED"),
            AccessAction::StreamDenied => write!(f, "STREAM_DENIED"),
            AccessAction::RevokedOnDisconnect => write!(f, "REVOKED"),
        }
    }
}
