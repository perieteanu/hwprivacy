use hwprivacy_common::device::ProtectedDevice;
use hwprivacy_common::stream::StreamInfo;
use hwprivacy_common::{Config, DeviceCategory, Permission};
use tracing::debug;

/// The decision made by the policy engine for a link attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyDecision {
    /// Allow the link — it stays
    Allow,
    /// Deny the link — destroy it immediately
    Deny,
    /// Ask the user (first time for this app) — destroy link, send notification
    AskUser,
    // AskEachStream removed 2026-08-23 with the per-stream concept.
}

/// Evaluate policy for a new link connecting a stream to a protected device.
pub fn evaluate(
    config: &Config,
    stream: &StreamInfo,
    device: &ProtectedDevice,
    // Whether a while_in_use session for this (app, device) is currently
    // live. Ignored for every other permission.
    session_live: bool,
) -> PolicyDecision {
    // Check if device category is guarded
    if !config.devices.is_guarded(&device.category) {
        debug!(
            "Device {:?} is not guarded, allowing {} → {}",
            device.category, stream.app_name, device.node_name
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
        // Allowed only while a session is live. The caller supplies that —
        // it is state, not policy, and keeping evaluate() a pure function of
        // its arguments is what makes every branch here testable.
        //
        // A session runs from the user's answer until the device is released.
        // With no session, this is a question, not a refusal: the prompt is
        // how a session begins. See d-while-in-use-is-a-session.
        Permission::WhileInUse => {
            if session_live {
                PolicyDecision::Allow
            } else {
                PolicyDecision::AskUser
            }
        }
        Permission::Ask => PolicyDecision::AskUser,
    }
}

/// One new link, resolved into "who is asking" and "for what".
#[derive(Debug, Clone)]
pub struct LinkMatch {
    pub stream: StreamInfo,
    pub device: ProtectedDevice,
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
            return Some(LinkMatch { stream, device });
        }
    }

    // Case 2: Mic/Camera source → app capture
    // Pattern: Audio/Source or Video/Source (output) → Stream/Input/* (input)
    if let Some(device) = find_device_by_node_id(output_node_id, nodes, devices) {
        // Skip if this is a normal playback link (Stream/Output → Audio/Sink)
        if device.category != DeviceCategory::Monitor {
            let stream = node_to_stream_info(input_node);
            return Some(LinkMatch { stream, device });
        }
    }

    // Case 3: App connecting to a protected device as input
    if let Some(device) = find_device_by_node_id(input_node_id, nodes, devices) {
        if device.category != DeviceCategory::Monitor {
            let stream = node_to_stream_info(output_node);
            return Some(LinkMatch { stream, device });
        }
    }

    None
}

// device_instance() lived here until 2026-08-23. It labelled a link `mic1` or
// `mic2` from the sorted port name, on the belief that a stereo capture device
// is two physical microphones.
//
// It was wrong twice over. It filtered sibling ports by `node_id`, so two
// PHYSICAL microphones — which are two different nodes, two ProtectedDevices,
// two rows in `hwprivacy-ctl devices` — could never reach it: the only thing it
// could ever label was two CHANNELS of one device. And the rules it decorated
// are per category, so `mic1`/`mic2` promised a precision no rule could
// express; clicking "Always Allow" on a popup headed `Microphone (mic1)` wrote
// `microphone = allow` for both.
//
// Costin, 2026-08-23: "no more mic1 or mic2 or mic left or mic right. just mic
// — the device." See DECISIONS d-one-device-one-prompt.

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
    }

    /// The reversal of b3, settled 2026-08-23 (`d-one-device-one-prompt`).
    ///
    /// `capture_FL` and `capture_FR` are two CHANNELS of one microphone. They
    /// used to be labelled `mic1`/`mic2` on the belief that they were two
    /// physical devices. Both links must now classify to the same device with
    /// nothing distinguishing them — `group_links` then collapses them into a
    /// single prompt.
    #[test]
    fn a_stereo_microphones_two_channels_are_one_device() {
        let (nodes, ports, devices) = graph();
        let fl = classify_link(46, 64, 99, 0, &nodes, &ports, &devices).expect("FL");
        let fr = classify_link(46, 65, 99, 0, &nodes, &ports, &devices).expect("FR");

        assert_eq!(fl.device.category, DeviceCategory::Microphone);
        assert_eq!(fr.device.category, DeviceCategory::Microphone);
        assert_eq!(
            fl.device.node_name, fr.device.node_name,
            "both channels belong to the same capture device"
        );
        assert_eq!(
            fl.stream.node_id, fr.stream.node_id,
            "and to the same asking stream — so they are one question"
        );
    }

    /// Two PHYSICAL microphones stay distinguishable, and always did — they are
    /// separate PipeWire nodes and separate ProtectedDevices. This is what the
    /// deleted ordinal could never have helped with: `device_instance` compared
    /// sibling ports *within one node*, so it could only ever see channels.
    #[test]
    fn two_real_microphones_are_still_two_devices() {
        let (nodes, ports, devices) = graph();
        let mut nodes = nodes;
        let mut ports = ports;
        let mut devices = devices;
        // A second capture device: its own node, its own port.
        nodes.insert(70, node(70, "Audio/Source", "alsa_input.usb-webcam", "usb mic"));
        ports.insert(80, port(80, 70, "capture_MONO", "out"));
        devices.push(ProtectedDevice {
            category: DeviceCategory::Microphone,
            node_name: "alsa_input.usb-webcam".into(),
            description: "USB webcam mic".into(),
            object_serial: 70,
            guarded: true,
        });

        let built_in = classify_link(46, 64, 99, 0, &nodes, &ports, &devices).expect("built-in");
        let usb = classify_link(70, 80, 99, 0, &nodes, &ports, &devices).expect("usb");
        assert_ne!(
            built_in.device.node_name, usb.device.node_name,
            "two microphones are two devices, told apart by node — never by an ordinal"
        );
    }

    /// A sink's playback_* and monitor_* ports face opposite ways and are not
    /// one population. Counting them together would make a stereo sink look
    /// like it had four of something.
    #[test]
    fn a_camera_capture_is_classified() {
        let (nodes, ports, devices) = graph();
        let m = classify_link(70, 71, 97, 0, &nodes, &ports, &devices).expect("camera");
        assert_eq!(m.device.category, DeviceCategory::Camera);
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


    // ---------------------------------------------------------------------
    // evaluate() — the core policy function, which had NO tests until
    // 2026-08-23. That absence is why `while_in_use` could map straight to
    // Allow for months without anyone noticing.
    // ---------------------------------------------------------------------

    use hwprivacy_common::Config;

    fn cfg(app: &str, cat: DeviceCategory, perm: Permission) -> Config {
        let mut c = Config::default();
        assert!(c.set_rule(app, &cat, perm), "fixture rule must be accepted");
        c
    }

    fn stream_of(app: &str) -> StreamInfo {
        StreamInfo {
            node_id: 99,
            app_name: app.into(),
            pid: 1234,
            node_name: "app-capture".into(),
            media_name: String::new(),
            media_class: "Stream/Input/Audio".into(),
        }
    }

    #[test]
    fn allow_and_deny_are_unconditional() {
        let mic = dev(DeviceCategory::Microphone, "alsa_input.analog-stereo", 46);
        for (perm, want) in [
            (Permission::Allow, PolicyDecision::Allow),
            (Permission::Deny, PolicyDecision::Deny),
        ] {
            let c = cfg("obs", DeviceCategory::Microphone, perm);
            for session in [true, false] {
                assert_eq!(
                    evaluate(&c, &stream_of("obs"), &mic, session),
                    want,
                    "{perm:?} must not depend on a session"
                );
            }
        }
    }

    /// `while_in_use` is a SESSION, and this is the assertion that would have
    /// caught it being a synonym for `allow`. With no session live it must ASK
    /// — the prompt is how a session begins — and with one live it must allow
    /// without asking again.
    #[test]
    fn while_in_use_allows_only_inside_a_live_session() {
        let mic = dev(DeviceCategory::Microphone, "alsa_input.analog-stereo", 46);
        let c = cfg("obs", DeviceCategory::Microphone, Permission::WhileInUse);

        assert_eq!(
            evaluate(&c, &stream_of("obs"), &mic, false),
            PolicyDecision::AskUser,
            "no session yet: ask, do not silently allow"
        );
        assert_eq!(
            evaluate(&c, &stream_of("obs"), &mic, true),
            PolicyDecision::Allow,
            "session live: allow without asking again"
        );
    }

    /// The whole point, stated as one assertion: `while_in_use` and `allow`
    /// must NOT behave the same. They did, silently, until 2026-08-23.
    #[test]
    fn while_in_use_is_not_a_synonym_for_allow() {
        let mic = dev(DeviceCategory::Microphone, "alsa_input.analog-stereo", 46);
        let wiu = cfg("obs", DeviceCategory::Microphone, Permission::WhileInUse);
        let allow = cfg("obs", DeviceCategory::Microphone, Permission::Allow);
        assert_ne!(
            evaluate(&wiu, &stream_of("obs"), &mic, false),
            evaluate(&allow, &stream_of("obs"), &mic, false),
            "with no session live these must differ, or while_in_use means nothing"
        );
    }

    /// An unguarded category short-circuits before any rule is consulted.
    #[test]
    fn an_unguarded_category_is_allowed_without_consulting_the_rule() {
        let mic = dev(DeviceCategory::Microphone, "alsa_input.analog-stereo", 46);
        let mut c = cfg("obs", DeviceCategory::Microphone, Permission::Deny);
        c.devices.microphone = false;
        assert_eq!(evaluate(&c, &stream_of("obs"), &mic, false), PolicyDecision::Allow);
    }

    /// An app with no rule follows default_action — both ways, so the test
    /// cannot pass by the default happening to match.
    #[test]
    fn an_app_with_no_rule_follows_the_default_action() {
        let mic = dev(DeviceCategory::Microphone, "alsa_input.analog-stereo", 46);
        let mut c = Config::default();
        c.policy.default_action = Permission::Deny;
        assert_eq!(evaluate(&c, &stream_of("nobody"), &mic, false), PolicyDecision::Deny);
        c.policy.default_action = Permission::Ask;
        assert_eq!(evaluate(&c, &stream_of("nobody"), &mic, false), PolicyDecision::AskUser);
    }
}
