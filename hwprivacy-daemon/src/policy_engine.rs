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
            "Stream {} (node:{}) has one-shot allow",
            stream.app_name, stream.node_id
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

/// One new link, resolved into "who is asking" and "for what".
#[derive(Debug, Clone)]
pub struct LinkMatch {
    pub stream: StreamInfo,
    pub device: ProtectedDevice,
    /// Which instance of the device, when one node presents several — `mic1`,
    /// `mic2`. `None` when the node has only one port of that direction, which
    /// is the common case and needs no ordinal.
    ///
    /// Deliberately NOT a field on [`ProtectedDevice`]: that type is one row
    /// per node, is handed out over D-Bus, and does not know which port a
    /// particular link used.
    pub instance: Option<String>,
}

/// Given a new link (output_node → input_node), determine which side is the
/// protected device and which is the app stream.
///
/// Returns `None` if neither side is a protected device.
pub fn classify_link(
    output_node_id: u32,
    output_port_id: u32,
    input_node_id: u32,
    input_port_id: u32,
    nodes: &std::collections::HashMap<u32, super::pipewire_monitor::NodeInfo>,
    ports: &std::collections::HashMap<u32, super::pipewire_monitor::PortInfo>,
    devices: &[ProtectedDevice],
) -> Option<LinkMatch> {
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
            // No instance label. A sink's monitor_FL and monitor_FR are two
            // CHANNELS of one playback device, not two devices — labelling
            // them would invent a second speaker that does not exist. The two
            // links are coalesced into one prompt instead; see main.rs.
            return Some(LinkMatch {
                stream,
                device,
                instance: None,
            });
        }
    }

    // Case 2: Mic/Camera source → app capture
    // Pattern: Audio/Source or Video/Source (output) → Stream/Input/* (input)
    if let Some(device) = find_device_by_node_id(output_node_id, nodes, devices) {
        // Skip if this is a normal playback link (Stream/Output → Audio/Sink)
        if device.category != DeviceCategory::Monitor {
            let stream = node_to_stream_info(input_node);
            let instance = device_instance(output_node_id, output_port_id, ports, device.category);
            return Some(LinkMatch {
                stream,
                device,
                instance,
            });
        }
    }

    // Case 3: App connecting to a protected device as input
    if let Some(device) = find_device_by_node_id(input_node_id, nodes, devices) {
        if device.category != DeviceCategory::Monitor {
            let stream = node_to_stream_info(output_node);
            let instance = device_instance(input_node_id, input_port_id, ports, device.category);
            return Some(LinkMatch {
                stream,
                device,
                instance,
            });
        }
    }

    None
}

/// Which of a device node's several inputs this link used — `mic1`, `mic2`.
///
/// # Why ordinals and not left/right
///
/// Decided 2026-08-21 (`CONVENTIONS.yaml > multiple_devices_of_one_kind`).
/// Which physical microphone maps to `capture_FL` depends on codec wiring and
/// was never determined here. "mic1" claims only that it is the first one,
/// which is true by construction; "left microphone" is a claim about the
/// chassis that we would be making up.
///
/// # Why sorted by NAME
///
/// The ordinal has to survive a reboot or a rule referring to it silently moves
/// to a different microphone. PipeWire allocates port **ids** per session;
/// port **names** (`capture_FL`, `capture_FR`) persist. Never sort by id,
/// discovery order, or arrival order.
///
/// Returns `None` when there is nothing to disambiguate, or when the data is
/// not good enough to be sure — a missing ordinal is honest, a wrong one is
/// not.
pub fn device_instance(
    device_node_id: u32,
    port_id: u32,
    ports: &std::collections::HashMap<u32, super::pipewire_monitor::PortInfo>,
    category: DeviceCategory,
) -> Option<String> {
    // The monitor case never gets here (see classify_link), but state the rule
    // where the naming happens as well as where it is skipped.
    let prefix = match category {
        DeviceCategory::Microphone => "mic",
        DeviceCategory::Camera => "cam",
        DeviceCategory::Monitor => return None,
    };

    let used = ports.get(&port_id)?;

    // Only ports on the same node, facing the same way. A sink has both
    // playback_* and monitor_* ports and they are not the same population.
    let mut siblings: Vec<&super::pipewire_monitor::PortInfo> = ports
        .values()
        .filter(|p| p.node_id == device_node_id && p.direction == used.direction)
        .collect();

    if siblings.len() < 2 {
        return None; // nothing to disambiguate
    }

    siblings.sort_by(|a, b| a.name.cmp(&b.name));
    let idx = siblings.iter().position(|p| p.id == port_id)?;
    Some(format!("{prefix}{}", idx + 1))
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
        node_id: node.id,
        app_name: node.app_name.clone(),
        pid: node.pid,
        node_name: node.node_name.clone(),
        media_name: node.media_name.clone(),
        media_class: node.media_class.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pipewire_monitor::{NodeInfo, PortInfo};
    use std::collections::HashMap;

    // Node and port ids below are the REAL ones from this laptop's graph,
    // read out of pw-dump on 2026-08-21:
    //
    //   node=36 Audio/Sink    playback_FL(60) monitor_FL(61)
    //                         playback_FR(62) monitor_FR(63)
    //   node=46 Audio/Source  capture_FL(64)  capture_FR(65)
    //
    // Using the real numbers keeps the fixture honest about the shape the code
    // actually meets, including that a sink carries two DIFFERENT populations
    // of port facing opposite ways.

    fn node(id: u32, media_class: &str, node_name: &str, app: &str) -> NodeInfo {
        NodeInfo {
            id,
            media_class: media_class.into(),
            node_name: node_name.into(),
            app_name: app.into(),
            pid: 1234,
            media_name: String::new(),
        }
    }

    fn port(id: u32, node_id: u32, name: &str, direction: &str) -> PortInfo {
        PortInfo {
            id,
            node_id,
            name: name.into(),
            direction: direction.into(),
        }
    }

    fn dev(category: DeviceCategory, node_name: &str, serial: u32) -> ProtectedDevice {
        ProtectedDevice {
            category,
            node_name: node_name.into(),
            description: "Built-in Audio Analog Stereo".into(),
            object_serial: serial,
            guarded: true,
        }
    }

    /// The live graph: a stereo sink, a stereo capture device, and an app.
    fn graph() -> (HashMap<u32, NodeInfo>, HashMap<u32, PortInfo>, Vec<ProtectedDevice>) {
        let nodes = HashMap::from([
            (36, node(36, "Audio/Sink", "alsa_output.analog-stereo", "")),
            (46, node(46, "Audio/Source", "alsa_input.analog-stereo", "")),
            (99, node(99, "Stream/Input/Audio", "app-capture", "Firefox")),
            (98, node(98, "Stream/Output/Audio", "app-playback", "Firefox")),
            (70, node(70, "Video/Source", "v4l2_input.cam", "")),
            (97, node(97, "Stream/Input/Video", "app-video", "Firefox")),
        ]);
        let ports = HashMap::from([
            (60, port(60, 36, "playback_FL", "in")),
            (61, port(61, 36, "monitor_FL", "out")),
            (62, port(62, 36, "playback_FR", "in")),
            (63, port(63, 36, "monitor_FR", "out")),
            (64, port(64, 46, "capture_FL", "out")),
            (65, port(65, 46, "capture_FR", "out")),
            (71, port(71, 70, "capture_0", "out")),
        ]);
        let devices = vec![
            dev(DeviceCategory::Monitor, "alsa_output.analog-stereo", 36),
            dev(DeviceCategory::Microphone, "alsa_input.analog-stereo", 46),
            dev(DeviceCategory::Camera, "v4l2_input.cam", 70),
        ];
        (nodes, ports, devices)
    }

    /// **The test that matters most.** `d-monitor-tap-by-link-direction` rests
    /// entirely on direction being structural: an app writing INTO a sink is
    /// ordinary playback, an app reading OUT of one is eavesdropping. Nothing
    /// has ever checked that ordinary audio output is not classified as a tap.
    /// If this ever regresses, hwprivacy starts tearing down music playback.
    #[test]
    fn ordinary_playback_into_a_sink_is_not_a_monitor_tap() {
        let (nodes, ports, devices) = graph();
        // Stream/Output/Audio(98) --playback_FL--> Audio/Sink(36)
        let got = classify_link(98, 0, 36, 60, &nodes, &ports, &devices);
        assert!(
            got.is_none(),
            "playing audio must never be treated as recording it: {got:?}"
        );
    }

    #[test]
    fn reading_out_of_a_sink_is_a_monitor_tap() {
        let (nodes, ports, devices) = graph();
        // Audio/Sink(36) --monitor_FL--> Stream/Input/Audio(99)
        let m = classify_link(36, 61, 99, 0, &nodes, &ports, &devices).expect("tap");
        assert_eq!(m.device.category, DeviceCategory::Monitor);
        assert_eq!(m.stream.app_name, "Firefox");
        assert_eq!(
            m.instance, None,
            "monitor_FL/FR are two channels of ONE sink — labelling them would \
             invent a second speaker"
        );
    }

    /// b3. Two links, two microphones, two distinguishable labels.
    #[test]
    fn the_two_microphones_are_told_apart() {
        let (nodes, ports, devices) = graph();
        let fl = classify_link(46, 64, 99, 0, &nodes, &ports, &devices).expect("FL");
        let fr = classify_link(46, 65, 99, 0, &nodes, &ports, &devices).expect("FR");

        assert_eq!(fl.device.category, DeviceCategory::Microphone);
        assert_eq!(fr.device.category, DeviceCategory::Microphone);
        assert_eq!(fl.instance.as_deref(), Some("mic1"));
        assert_eq!(fr.instance.as_deref(), Some("mic2"));
        assert_ne!(
            fl.instance, fr.instance,
            "two prompts that read the same are what made b3 look broken"
        );
    }

    /// The stability constraint from CONVENTIONS. Port IDs are allocated per
    /// session; names persist. If the ordinal followed the id, a rule or a
    /// habit built around "mic2" would silently point at the other microphone
    /// after a reboot.
    #[test]
    fn ordinals_follow_the_port_name_not_the_port_id() {
        let (nodes, _, devices) = graph();
        // Same two microphones, ids swapped as a fresh session might allocate
        // them: capture_FL now has the HIGHER id.
        let ports = HashMap::from([
            (65, port(65, 46, "capture_FL", "out")),
            (64, port(64, 46, "capture_FR", "out")),
        ]);
        let fl = classify_link(46, 65, 99, 0, &nodes, &ports, &devices).expect("FL");
        let fr = classify_link(46, 64, 99, 0, &nodes, &ports, &devices).expect("FR");
        assert_eq!(fl.instance.as_deref(), Some("mic1"), "capture_FL is still mic1");
        assert_eq!(fr.instance.as_deref(), Some("mic2"), "capture_FR is still mic2");
    }

    /// A single-microphone machine must not be told about "mic1". An ordinal
    /// with nothing to disambiguate is noise.
    #[test]
    fn a_lone_port_gets_no_ordinal() {
        let (nodes, _, devices) = graph();
        let ports = HashMap::from([(64, port(64, 46, "capture_MONO", "out"))]);
        let m = classify_link(46, 64, 99, 0, &nodes, &ports, &devices).expect("mic");
        assert_eq!(m.instance, None);
    }

    /// A sink's playback_* and monitor_* ports face opposite ways and are not
    /// one population. Counting them together would make a stereo sink look
    /// like it had four of something.
    /// Only ports facing the SAME WAY as the one used may be counted. A duplex
    /// node has two populations and merging them shifts every ordinal.
    ///
    /// This test deliberately does NOT use this laptop's sink, even though that
    /// is the real duplex device in the graph. There, the in-ports are
    /// `playback_*` and the out-ports are `monitor_*` — and `monitor` sorts
    /// before `playback`, so mixing the two populations happens to produce the
    /// right answer anyway. A test built on that hardware passes whether or not
    /// the filter exists, which was the first version of this test and it was
    /// worthless. Verified: removing the direction filter did not fail it.
    ///
    /// So: an in-port whose name sorts FIRST, where the coincidence cannot save
    /// the wrong implementation.
    #[test]
    fn opposite_facing_ports_are_not_counted_together() {
        let ports = HashMap::from([
            (10, port(10, 46, "aux_in", "in")),      // sorts before both
            (11, port(11, 46, "capture_FL", "out")),
            (12, port(12, 46, "capture_FR", "out")),
        ]);
        assert_eq!(
            device_instance(46, 11, &ports, DeviceCategory::Microphone).as_deref(),
            Some("mic1"),
            "capture_FL is the FIRST capture port; aux_in faces the other way \
             and must not be counted, which would make this mic2"
        );
        assert_eq!(
            device_instance(46, 12, &ports, DeviceCategory::Microphone).as_deref(),
            Some("mic2")
        );
    }

    /// The single in-port must also not be given an ordinal of its own by
    /// borrowing the out-ports for the count.
    #[test]
    fn a_lone_port_facing_its_own_way_gets_no_ordinal() {
        let ports = HashMap::from([
            (10, port(10, 46, "aux_in", "in")),
            (11, port(11, 46, "capture_FL", "out")),
            (12, port(12, 46, "capture_FR", "out")),
        ]);
        assert_eq!(
            device_instance(46, 10, &ports, DeviceCategory::Microphone),
            None,
            "one port facing in — nothing to disambiguate it from"
        );
    }

    #[test]
    fn a_camera_capture_is_classified_and_needs_no_ordinal() {
        let (nodes, ports, devices) = graph();
        let m = classify_link(70, 71, 97, 0, &nodes, &ports, &devices).expect("camera");
        assert_eq!(m.device.category, DeviceCategory::Camera);
        assert_eq!(m.instance, None, "one capture port, nothing to disambiguate");
    }

    #[test]
    fn a_link_between_two_unprotected_nodes_is_ignored() {
        let (nodes, ports, devices) = graph();
        let got = classify_link(98, 0, 99, 0, &nodes, &ports, &devices);
        assert!(got.is_none(), "{got:?}");
    }

    /// An unguarded device is still CLASSIFIED here — `guarded` is checked by
    /// the caller. But a device the daemon never discovered must not match, or
    /// policy would be applied to hardware it knows nothing about.
    #[test]
    fn a_device_node_that_was_never_discovered_does_not_match() {
        let (nodes, ports, _) = graph();
        let devices = vec![dev(DeviceCategory::Microphone, "some.other.device", 1)];
        let got = classify_link(46, 64, 99, 0, &nodes, &ports, &devices);
        assert!(got.is_none(), "{got:?}");
    }

    /// A link whose endpoints are not in the snapshot must not panic or guess.
    #[test]
    fn a_link_to_an_unknown_node_is_ignored() {
        let (nodes, ports, devices) = graph();
        assert!(classify_link(4242, 0, 99, 0, &nodes, &ports, &devices).is_none());
        assert!(classify_link(46, 64, 4242, 0, &nodes, &ports, &devices).is_none());
    }

    /// The monitor category never carries an ordinal, stated at the naming
    /// function too — not only where classify_link skips it.
    #[test]
    fn the_monitor_category_is_never_given_an_ordinal() {
        let (_, ports, _) = graph();
        assert_eq!(
            device_instance(36, 61, &ports, DeviceCategory::Monitor),
            None
        );
    }
}
