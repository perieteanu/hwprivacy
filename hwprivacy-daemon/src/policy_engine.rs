use hwprivacy_common::device::ProtectedDevice;
use hwprivacy_common::stream::StreamInfo;
use hwprivacy_common::{Config, DeviceCategory, Permission};
use tracing::debug;

/// The decision made by the policy engine for a link attempt.
#[derive(Debug, Clone)]
pub enum PolicyDecision {
    /// Allow the link — it stays
    Allow,
    /// Deny the link — destroy it immediately
    Deny,
    /// Ask the user (first time for this app) — destroy link, send notification
    AskUser,
    /// Ask for this specific stream (browser mode) — destroy link, send notification
    AskEachStream,
}

/// Evaluate policy for a new link connecting a stream to a protected device.
pub fn evaluate(
    config: &Config,
    stream: &StreamInfo,
    device: &ProtectedDevice,
    is_one_shot_allowed: bool,
) -> PolicyDecision {
    // Check if device category is guarded
    if !config.devices.is_guarded(&device.category) {
        debug!(
            "Device {:?} is not guarded, allowing {} → {}",
            device.category, stream.app_name, device.node_name
        );
        return PolicyDecision::Allow;
    }

    // Check one-shot allows (for ask_each streams that were already approved)
    if is_one_shot_allowed {
        debug!(
            "Stream {} (serial:{}) has one-shot allow",
            stream.app_name, stream.object_serial
        );
        return PolicyDecision::Allow;
    }

    // Look up the rule for this app + device
    let permission = config.get_permission(&stream.app_name, &device.category);

    debug!(
        "Policy for {} → {:?}: {:?}",
        stream.app_name, device.category, permission
    );

    match permission {
        Permission::Allow => PolicyDecision::Allow,
        Permission::Deny => PolicyDecision::Deny,
        Permission::AskEach => PolicyDecision::AskEachStream,
        Permission::WhileInUse => {
            // For while_in_use, we allow but track the client lifecycle
            PolicyDecision::Allow
        }
        Permission::Ask => PolicyDecision::AskUser,
    }
}

/// Given a new link (output_node → input_node), determine which side is the
/// protected device and which is the app stream.
///
/// Returns (stream_info, protected_device) if this link involves a protected device,
/// or None if neither side is a protected device.
pub fn classify_link(
    output_node_id: u32,
    input_node_id: u32,
    nodes: &std::collections::HashMap<u32, super::pipewire_monitor::NodeInfo>,
    devices: &[ProtectedDevice],
) -> Option<(StreamInfo, ProtectedDevice)> {
    let output_node = nodes.get(&output_node_id)?;
    let input_node = nodes.get(&input_node_id)?;

    // Case 1: Monitor tap detection
    // Pattern: Audio/Sink (output) → Stream/Input/Audio (input)
    // This means an app is reading from the sink's monitor source
    // (recording what's playing). Normal playback is the opposite:
    // Stream/Output/Audio → Audio/Sink.
    if output_node.media_class == "Audio/Sink"
        && input_node.media_class == "Stream/Input/Audio"
    {
        if let Some(device) = find_device_by_node_id(output_node_id, nodes, devices) {
            let stream = node_to_stream_info(input_node);
            debug!(
                "Monitor tap detected: {} (pid:{}) reading from sink {}",
                stream.app_name, stream.pid, device.node_name
            );
            return Some((stream, device));
        }
    }

    // Case 2: Mic/Camera source → app capture
    // Pattern: Audio/Source or Video/Source (output) → Stream/Input/* (input)
    if let Some(device) = find_device_by_node_id(output_node_id, nodes, devices) {
        // Skip if this is a normal playback link (Stream/Output → Audio/Sink)
        if device.category != DeviceCategory::Monitor {
            let stream = node_to_stream_info(input_node);
            return Some((stream, device));
        }
    }

    // Case 3: App connecting to a protected device as input
    if let Some(device) = find_device_by_node_id(input_node_id, nodes, devices) {
        if device.category != DeviceCategory::Monitor {
            let stream = node_to_stream_info(output_node);
            return Some((stream, device));
        }
    }

    None
}

fn find_device_by_node_id(
    node_id: u32,
    nodes: &std::collections::HashMap<u32, super::pipewire_monitor::NodeInfo>,
    devices: &[ProtectedDevice],
) -> Option<ProtectedDevice> {
    let node = nodes.get(&node_id)?;
    devices
        .iter()
        .find(|d| d.node_name == node.node_name || d.object_serial == node_id)
        .cloned()
}

fn node_to_stream_info(node: &super::pipewire_monitor::NodeInfo) -> StreamInfo {
    StreamInfo {
        object_serial: node.id,
        app_name: node.app_name.clone(),
        pid: node.pid,
        node_name: node.node_name.clone(),
        media_name: node.media_name.clone(),
        media_class: node.media_class.clone(),
    }
}
