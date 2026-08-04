use serde::{Deserialize, Serialize};

/// Information about a PipeWire stream (app node) trying to access a device.
/// Extracted from PipeWire node properties via pw-dump.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamInfo {
    /// PipeWire object serial (unique ID)
    pub object_serial: u32,
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
    pub node_name: String,
    pub action: AccessAction,
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
