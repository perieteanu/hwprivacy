mod dbus_service;
mod device_discovery;
mod history;
mod link_manager;
mod lsm_client;
mod notification;
mod notify_allow;
mod pipewire_monitor;
mod policy_engine;
mod state;
mod stream_tracker;

use clap::{Parser, Subcommand};
use dbus_service::{HwPrivacyService, SharedState};
use hwprivacy_common::stream::AccessAction;
use hwprivacy_common::{Config, DeviceCategory, Permission};
use policy_engine::PolicyDecision;
use state::DaemonState;
use std::collections::HashSet;
use std::io::Write;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

#[derive(Parser)]
#[command(
    name = "hwprivacy-daemon",
    about = "HWPrivacy — Hardware Permission Manager daemon\n\nMonitors PipeWire graph and enforces per-app device access policies\nfor microphones, cameras, and playback monitors.",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the daemon (default if no command given)
    Run,
    /// Install as a systemd user service and enable it
    Install,
    /// Uninstall the systemd user service
    Uninstall,
    /// Show service status
    ServiceStatus,
}

const SERVICE_UNIT: &str = r#"[Unit]
Description=HWPrivacy — Hardware Permission Manager
After=pipewire.service wireplumber.service
Wants=pipewire.service

[Service]
Type=simple
ExecStart=DAEMON_PATH
Restart=on-failure
RestartSec=3
Environment=RUST_LOG=info

[Install]
WantedBy=default.target
"#;

/// D-Bus activation delegates to systemd instead of forking its own process.
///
/// `Exec=DAEMON_PATH` looks right and is a trap: D-Bus then starts a SECOND
/// daemon that grabs the bus name, and the systemd unit crash-loops forever
/// with "name already taken on the bus". Observed 2026-08-05 with the restart
/// counter at 32 — and it only became possible once the Exec path was
/// corrected, since a broken path had been failing harmlessly.
///
/// `SystemdService=` makes D-Bus ask systemd to start the unit, so there is
/// exactly one way for the daemon to come up. `Exec=` must still be present
/// for the file to be valid, hence /bin/false.
const DBUS_SERVICE: &str = r#"[D-BUS Service]
Name=org.hwprivacy.Daemon
Exec=/bin/false
SystemdService=hwprivacy.service
"#;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Install) => return install_service(),
        Some(Commands::Uninstall) => return uninstall_service(),
        Some(Commands::ServiceStatus) => return service_status(),
        Some(Commands::Run) | None => {} // fall through to daemon startup
    }

    tracing_subscriber::fmt::init();
    info!("HWPrivacy daemon starting");

    // Load configuration
    let config = Config::load();
    info!(
        "Config loaded: default_action={}, poll={}ms, {} rules",
        config.policy.default_action,
        config.policy.poll_interval_ms,
        config.rules.len()
    );

    // Discover devices (retry a few times — at autostart PipeWire may still be initialising)
    let mut devices = Vec::new();
    for attempt in 1..=5 {
        match device_discovery::discover_devices().await {
            Ok(d) => {
                devices = d;
                if !devices.is_empty() {
                    info!("Device discovery succeeded on attempt {}", attempt);
                    break;
                }
                warn!("Attempt {}: pw-dump returned 0 devices, retrying...", attempt);
            }
            Err(e) => {
                warn!("Attempt {}: device discovery failed: {}", attempt, e);
            }
        }
        if attempt < 5 {
            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
        }
    }

    // Initialize state
    let mut daemon_state = DaemonState::new(config);
    daemon_state.devices = devices;

    let poll_interval = daemon_state.config.policy.poll_interval_ms;
    let state: SharedState = Arc::new(RwLock::new(daemon_state));

    // Register D-Bus service
    let service = HwPrivacyService {
        state: state.clone(),
    };

    let _connection = zbus::connection::Builder::session()?
        .name("org.hwprivacy.Daemon")?
        .serve_at("/org/hwprivacy/Daemon", service)?
        .build()
        .await?;

    info!("HWPrivacy daemon running on session D-Bus");

    // Kernel (eBPF LSM) layer client. Independent of the PipeWire loop: if the
    // helper is absent this task retries quietly forever and nothing else is
    // affected.
    let lsm_state = state.clone();
    let lsm_socket = std::env::var("HWPRIVACY_LSM_SOCKET").ok();
    tokio::spawn(async move {
        lsm_client::run(lsm_state, lsm_socket).await;
    });

    // Start monitoring loop
    let monitor_state = state.clone();
    let monitor_handle = tokio::spawn(async move {
        monitoring_loop(monitor_state, poll_interval).await;
    });

    // Wait for shutdown signal
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    tokio::select! {
        _ = tokio::signal::ctrl_c() => info!("Received SIGINT, shutting down"),
        _ = sigterm.recv() => info!("Received SIGTERM, shutting down"),
    }

    monitor_handle.abort();
    info!("HWPrivacy daemon stopped");
    Ok(())
}

/// One decision's worth of links.
///
/// Usually one link. For a playback monitor it is the sink's whole channel set
/// — see [`group_links`].
struct LinkGroup {
    link_ids: Vec<u32>,
    m: policy_engine::LinkMatch,
}

/// Collapse the links that represent ONE act of access, per category.
///
/// This is blocker b3, and the two categories need opposite treatment:
///
/// * **Microphone** — a stereo capture device is two PHYSICAL microphones,
///   exposed as `capture_FL` and `capture_FR`. Two prompts are correct, and
///   coalescing would destroy the only handle on which one is being asked for.
///   Measured 2026-08-19: cutting one channel mid-capture took its rms to 0.0
///   while the other kept recording. They are separately gateable, so they are
///   separately askable. Left alone here; `LinkMatch::instance` labels them.
///
/// * **Monitor** — a sink's `monitor_FL` and `monitor_FR` are two CHANNELS of
///   one playback device. Recording what the speakers are playing is one act
///   against one device, so two prompts are genuinely duplicates. Seen live on
///   2026-08-21: two identical `OBS → Monitor → ALLOWED` rows in the same
///   second. Grouped by (device, app).
///
/// * **Camera** — one link. Untouched.
///
/// The group carries EVERY link id, not just the representative. Callers must
/// enforce on all of them; collapsing the prompt must never collapse the
/// teardown, or one channel keeps flowing while the popup says BLOCKED.
fn group_links(matches: Vec<(u32, policy_engine::LinkMatch)>) -> Vec<LinkGroup> {
    let mut groups: Vec<LinkGroup> = Vec::new();

    for (link_id, m) in matches {
        let coalesce = m.device.category == DeviceCategory::Monitor;
        let existing = coalesce.then(|| {
            groups.iter_mut().find(|g| {
                g.m.device.category == DeviceCategory::Monitor
                    && g.m.device.node_name == m.device.node_name
                    && g.m.stream.node_id == m.stream.node_id
            })
        });

        match existing.flatten() {
            Some(g) => g.link_ids.push(link_id),
            None => groups.push(LinkGroup {
                link_ids: vec![link_id],
                m,
            }),
        }
    }

    groups
}

#[cfg(test)]
mod group_tests {
    use super::*;
    use hwprivacy_common::device::ProtectedDevice;
    use hwprivacy_common::stream::StreamInfo;

    fn m(category: DeviceCategory, device_node: &str, app_node_id: u32, instance: Option<&str>)
        -> policy_engine::LinkMatch
    {
        policy_engine::LinkMatch {
            stream: StreamInfo {
                node_id: app_node_id,
                app_name: "OBS".into(),
                pid: 2201,
                node_name: "app".into(),
                media_name: String::new(),
                media_class: "Stream/Input/Audio".into(),
            },
            device: ProtectedDevice {
                category,
                node_name: device_node.into(),
                description: String::new(),
                object_serial: 0,
                guarded: true,
            },
            instance: instance.map(str::to_string),
        }
    }

    /// Seen live 2026-08-21, twice in the same second:
    ///   09:00:27  OBS [pipewire-pulse] → Monitor → ALLOWED
    ///   09:00:27  OBS [pipewire-pulse] → Monitor → ALLOWED
    /// One sink, one app, one act of recording — one prompt.
    #[test]
    fn a_sinks_two_monitor_channels_become_one_decision() {
        let groups = group_links(vec![
            (100, m(DeviceCategory::Monitor, "alsa_output.analog", 99, None)),
            (101, m(DeviceCategory::Monitor, "alsa_output.analog", 99, None)),
        ]);
        assert_eq!(groups.len(), 1, "one prompt, not two");
    }

    /// **The trap.** Coalescing the prompt must not coalesce the teardown. If
    /// the group forgot a link id, that channel would keep flowing while the
    /// popup said BLOCKED — worse than the double prompt it replaces.
    #[test]
    fn a_coalesced_group_still_carries_every_link_to_destroy() {
        let groups = group_links(vec![
            (100, m(DeviceCategory::Monitor, "alsa_output.analog", 99, None)),
            (101, m(DeviceCategory::Monitor, "alsa_output.analog", 99, None)),
        ]);
        assert_eq!(groups[0].link_ids, vec![100, 101]);
    }

    /// b3 proper: two microphones are two decisions. Coalescing here would
    /// destroy the only handle on which mic is being requested.
    #[test]
    fn two_microphones_stay_two_decisions() {
        let groups = group_links(vec![
            (100, m(DeviceCategory::Microphone, "alsa_input.analog", 99, Some("mic1"))),
            (101, m(DeviceCategory::Microphone, "alsa_input.analog", 99, Some("mic2"))),
        ]);
        assert_eq!(groups.len(), 2, "one prompt per microphone");
        assert_eq!(groups[0].m.instance.as_deref(), Some("mic1"));
        assert_eq!(groups[1].m.instance.as_deref(), Some("mic2"));
    }

    /// Two different apps tapping the same sink are two separate decisions —
    /// grouping is per (device, app), never per device alone.
    #[test]
    fn two_apps_tapping_one_sink_are_not_merged() {
        let groups = group_links(vec![
            (100, m(DeviceCategory::Monitor, "alsa_output.analog", 99, None)),
            (101, m(DeviceCategory::Monitor, "alsa_output.analog", 77, None)),
        ]);
        assert_eq!(groups.len(), 2);
    }

    /// One app tapping two different sinks (analog and HDMI) is two decisions.
    #[test]
    fn one_app_tapping_two_sinks_is_not_merged() {
        let groups = group_links(vec![
            (100, m(DeviceCategory::Monitor, "alsa_output.analog", 99, None)),
            (101, m(DeviceCategory::Monitor, "alsa_output.hdmi", 99, None)),
        ]);
        assert_eq!(groups.len(), 2);
    }

    #[test]
    fn a_camera_link_is_its_own_group() {
        let groups = group_links(vec![
            (100, m(DeviceCategory::Camera, "v4l2_input.cam", 99, None)),
        ]);
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].link_ids, vec![100]);
    }
}

/// Main monitoring loop: poll PipeWire graph, detect new links, enforce policy.
async fn monitoring_loop(state: SharedState, poll_interval_ms: u64) {
    let interval = tokio::time::Duration::from_millis(poll_interval_ms);
    // Rescan devices every ~5s, but only during the first 2 minutes after start
    // (gives PipeWire/WirePlumber time to register all hardware at autostart).
    let rescan_every = std::cmp::max(1, 5_000 / poll_interval_ms);
    let rescan_deadline = std::cmp::max(1, 120_000 / poll_interval_ms);
    let mut poll_count: u64 = 0;

    // Initial graph capture to populate known links
    match pipewire_monitor::capture_graph().await {
        Ok(snapshot) => {
            let mut s = state.write().await;
            s.known_link_ids = snapshot.links.iter().map(|l| l.link_id).collect();
            info!(
                "Initial graph: {} nodes, {} links",
                snapshot.nodes.len(),
                snapshot.links.len()
            );
        }
        Err(e) => {
            error!("Failed initial graph capture: {}", e);
        }
    }

    loop {
        tokio::time::sleep(interval).await;
        poll_count += 1;

        // Device rescan during startup window to catch late-arriving devices
        if poll_count <= rescan_deadline && poll_count % rescan_every == 0 {
            let existing = {
                let s = state.read().await;
                s.devices.clone()
            };
            match device_discovery::rescan_devices(&existing).await {
                Ok(updated) => {
                    if updated.len() != existing.len() {
                        info!(
                            "Device rescan: {} → {} devices",
                            existing.len(),
                            updated.len()
                        );
                    }
                    let mut s = state.write().await;
                    s.devices = updated;
                }
                Err(e) => {
                    warn!("Device rescan failed: {}", e);
                }
            }
        }

        let snapshot = match pipewire_monitor::capture_graph().await {
            Ok(s) => s,
            Err(e) => {
                warn!("Graph capture failed: {}", e);
                continue;
            }
        };

        // Find new links since last poll
        let known_ids = {
            let s = state.read().await;
            s.known_link_ids.clone()
        };
        let new_links = pipewire_monitor::diff_links(&known_ids, &snapshot);

        // Update known link IDs
        {
            let mut s = state.write().await;
            s.known_link_ids = snapshot.links.iter().map(|l| l.link_id).collect();
        }

        // Classify every new link, then group them (see group_links). One
        // group = one decision, one prompt, but ALL of its links get enforced.
        let matches: Vec<(u32, policy_engine::LinkMatch)> = {
            let s = state.read().await;
            new_links
                .iter()
                .filter_map(|link| {
                    policy_engine::classify_link(
                        link.output_node,
                        link.output_port,
                        link.input_node,
                        link.input_port,
                        &snapshot.nodes,
                        &snapshot.ports,
                        &s.devices,
                    )
                    .map(|m| (link.link_id, m))
                })
                .collect()
        };

        for group in group_links(matches) {
            let s = state.read().await;
            let LinkGroup {
                ref link_ids,
                ref m,
            } = group;
            let stream = &m.stream;
            let device = &m.device;
            let instance = m.instance.as_deref();

            // Skip if device category is not guarded
            if !s.config.devices.is_guarded(&device.category) {
                continue;
            }

            // Check block-all mode
            if s.block_all {
                drop(s);
                link_manager::destroy_links(link_ids).await;
                let mut s = state.write().await;
                s.log_denied(
                    &stream.app_name,
                    stream.pid,
                    device.category,
                    instance,
                    &stream.node_name,
                );
                continue;
            }

            // Evaluate policy
            let is_one_shot = s
                .tracker
                .is_one_shot_allowed(stream.node_id, &stream.app_name);
            let decision = policy_engine::evaluate(&s.config, stream, device, is_one_shot);

            // Act on decision
            match decision {
                PolicyDecision::Allow => {
                    drop(s);
                    let mut s = state.write().await;
                    let perm = s.config.get_permission(&stream.app_name, &device.category);
                    // Every link in the group is tracked — the group exists to
                    // collapse the PROMPT, not the bookkeeping.
                    for lid in link_ids {
                        s.tracker.add_connection(
                            *lid,
                            stream.clone(),
                            &device.node_name,
                            device.category,
                            perm,
                        );
                    }
                    if perm == Permission::WhileInUse {
                        s.tracker
                            .track_while_in_use(&stream.app_name, stream.node_id);
                    }
                    s.log_allowed(
                        &stream.app_name,
                        stream.pid,
                        device.category,
                        instance,
                        &stream.node_name,
                    );

                    // Say so, if this one is worth saying. The gate is a pure
                    // function precisely so its rules can be tested; see
                    // notify_allow.rs for why each of them exists.
                    let access = notify_allow::AllowedAccess {
                        app: &stream.app_name,
                        device: device.category,
                        pid: stream.pid,
                    };
                    let now = std::time::Instant::now();
                    let announce = s.allow_notifier.should_notify(
                        access,
                        s.uptime(),
                        now,
                        &s.config.policy,
                    );
                    if announce {
                        s.allow_notifier.mark_notified(access, now);
                    }
                    let (app, pid, cat) =
                        (stream.app_name.clone(), stream.pid, device.category);
                    let inst = m.instance.clone();
                    drop(s);
                    if announce {
                        // Logged, symmetrically with the kernel layer's
                        // "Kernel layer ALLOWED". Whether a popup appeared is
                        // otherwise invisible to everything except a human
                        // watching the screen — which is not something a check
                        // can assert on, and this project has already been
                        // burned by verification that depended on someone
                        // seeing a notification (C4, scored wrong twice).
                        info!(
                            "Announced allowed access: {} → {}",
                            app,
                            notification::device_label_for(cat, inst.as_deref())
                        );
                        notification::notify_allowed(
                            &app,
                            pid,
                            cat,
                            inst.as_deref(),
                            "Allowed by your rules. hwprivacy cannot tell when access ends.",
                        )
                        .await;
                    }
                }

                PolicyDecision::Deny => {
                    let app = stream.app_name.clone();
                    let pid = stream.pid;
                    let cat = device.category;
                    let node = stream.node_name.clone();
                    let inst = m.instance.clone();

                    drop(s);
                    link_manager::destroy_links(link_ids).await;
                    let mut s = state.write().await;
                    s.log_denied(&app, pid, cat, inst.as_deref(), &node);
                    drop(s);

                    // Instant notification — rule already says deny
                    notification::notify_blocked(&app, pid, cat, inst.as_deref(), &node).await;
                }

                PolicyDecision::AskUser | PolicyDecision::AskEachStream => {
                    let is_per_stream = matches!(decision, PolicyDecision::AskEachStream);
                    let app = stream.app_name.clone();
                    let pid = stream.pid;
                    let cat = device.category;
                    let node = stream.node_name.clone();
                    let node_id = stream.node_id;
                    let inst = m.instance.clone();

                    // 1. Destroy the links immediately (security first).
                    //    ALL of them: coalescing the prompt must not leave a
                    //    channel flowing while the popup says BLOCKED.
                    drop(s);
                    link_manager::destroy_links(link_ids).await;

                    // 2. Check cooldown — if user recently dismissed the same
                    //    prompt, silently block without notification spam
                    let in_cooldown = {
                        let s = state.read().await;
                        let secs = s.config.policy.dismiss_cooldown_secs;
                        s.tracker.is_in_cooldown(&app, cat, secs)
                    };

                    // A prompt for this (app, device) may already be on screen
                    // waiting for an answer. Prompts do not expire — that is
                    // deliberate, a permission question is a to-do item — so a
                    // second stream must not stack a second identical popup
                    // asking the same question. Block it and stay quiet; the
                    // answer, when it comes, governs what follows. (b6)
                    let already_asking = !in_cooldown && {
                        let mut s = state.write().await;
                        !s.tracker.try_begin_prompt(&app, cat)
                    };
                    if already_asking {
                        let mut s = state.write().await;
                        s.log_denied(&app, pid, cat, inst.as_deref(), &node);
                        debug!(
                            "Blocked {} → {:?}; a prompt for it is already waiting for an answer",
                            app, cat
                        );
                        continue;
                    }

                    {
                        let mut s = state.write().await;
                        if in_cooldown {
                            // log_denied() -> log_event() increments
                            // blocked_count itself for a Denied action
                            // (stream_tracker.rs). An extra += 1 here counted
                            // every cooldown-suppressed block twice.
                            s.log_denied(&app, pid, cat, inst.as_deref(), &node);
                        } else {
                            s.tracker.log_event(
                                &app, pid, cat, inst.as_deref(), &node,
                                AccessAction::AskedUser,
                            );
                        }
                    }

                    if in_cooldown {
                        // Silently blocked — user dismissed recently, no spam
                        continue;
                    }

                    // 3. Stage 1: instant BLOCKED notification (fire-and-forget)
                    notification::notify_blocked(&app, pid, cat, inst.as_deref(), &node).await;

                    // 4. Stage 2: action notification for rule setting (async)
                    let notify_state = state.clone();
                    tokio::spawn(async move {
                        let response = notification::ask_user_permission(
                            &app, pid, cat, inst.as_deref(), &node, is_per_stream,
                        )
                        .await;

                        if let notification::PromptOutcome::Failed(e) = &response {
                            warn!(
                                "Could not prompt for {} → {:?} ({}). Access stayed blocked \
                                 and NO rule was saved.",
                                app, cat, e
                            );
                        }

                        let mut s = notify_state.write().await;
                        match notification::decide(&response, is_per_stream) {
                            notification::PromptAction::GrantThisStream => {
                                s.tracker.grant_one_shot(node_id, &app);
                                s.tracker.log_event(
                                    &app, pid, cat, inst.as_deref(), &node,
                                    AccessAction::StreamAllowed,
                                );
                            }
                            notification::PromptAction::DenyThisStream => {
                                s.tracker.log_event(
                                    &app, pid, cat, inst.as_deref(), &node,
                                    AccessAction::StreamDenied,
                                );
                            }
                            notification::PromptAction::SavePermanentRule(perm) => {
                                if s.config.set_rule(&app, &cat, perm) {
                                    if let Err(e) = s.config.save() {
                                        error!("Failed to save config after user decision: {}", e);
                                    }
                                    info!("User set rule: {} → {:?} = {}", app, cat, perm);
                                } else {
                                    // set_rule refuses names that could never
                                    // match. Saying so beats writing a rule
                                    // that silently does nothing — blocker b4.
                                    warn!(
                                        "Refused to save a rule for {:?} → {:?}: the name \
                                         cannot become a usable rule key",
                                        app, cat
                                    );
                                }
                            }
                            notification::PromptAction::SaveNothingAndCooldown => {
                                let secs = s.config.policy.dismiss_cooldown_secs;
                                info!(
                                    "No answer for {} → {:?}; nothing saved, quiet for {}s",
                                    app, cat, secs
                                );
                                s.tracker.record_dismiss(&app, cat);
                            }
                        }

                        // Release the claim on EVERY path out, including the
                        // ones above that return early in spirit. Leaking it
                        // would mean this (app, device) is never asked about
                        // again for the life of the daemon — a silent, total
                        // loss of prompting that would look like the tool
                        // having given up.
                        s.tracker.end_prompt(&app, cat);
                    });
                }
            }
        }

        // Clean up: drop connections for links that no longer exist, and
        // one-shot grants whose stream node is gone. The grants MUST expire
        // here — PipeWire reuses node ids, so a grant that outlives its node
        // eventually authorises somebody else (blocker b2).
        {
            let current_link_ids: HashSet<u32> =
                snapshot.links.iter().map(|l| l.link_id).collect();
            let current_node_ids: HashSet<u32> = snapshot.nodes.keys().copied().collect();
            let mut s = state.write().await;
            let stale: Vec<u32> = s
                .tracker
                .active
                .keys()
                .filter(|lid| !current_link_ids.contains(lid))
                .cloned()
                .collect();
            for lid in stale {
                s.tracker.remove_connection(lid);
            }
            s.tracker.prune_one_shot(&current_node_ids);
        }
    }
}

// ---- Service installation ----

fn daemon_path() -> String {
    std::env::current_exe()
        .unwrap_or_else(|_| std::path::PathBuf::from("/usr/bin/hwprivacy-daemon"))
        .to_string_lossy()
        .to_string()
}

fn systemd_user_dir() -> std::path::PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    std::path::PathBuf::from(home)
        .join(".config")
        .join("systemd")
        .join("user")
}

fn dbus_services_dir() -> std::path::PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    std::path::PathBuf::from(home)
        .join(".local")
        .join("share")
        .join("dbus-1")
        .join("services")
}

fn install_service() -> anyhow::Result<()> {
    let exe = daemon_path();

    // Install systemd user service
    let service_dir = systemd_user_dir();
    std::fs::create_dir_all(&service_dir)?;
    let service_path = service_dir.join("hwprivacy.service");
    let unit = SERVICE_UNIT.replace("DAEMON_PATH", &exe);
    std::fs::write(&service_path, &unit)?;
    println!("Installed: {}", service_path.display());

    // Install D-Bus activation service
    let dbus_dir = dbus_services_dir();
    std::fs::create_dir_all(&dbus_dir)?;
    let dbus_path = dbus_dir.join("org.hwprivacy.Daemon.service");
    std::fs::write(&dbus_path, DBUS_SERVICE)?;
    println!("Installed: {}", dbus_path.display());

    // Create default config if it doesn't exist, with the desktop baseline.
    //
    // The baseline is imported here rather than baked into Config::default()
    // because it is DATA — a preset anyone can read, correct, or replace — and
    // because Default is used throughout the tests, where an empty config is
    // the thing being asserted on.
    //
    // Auto-import at install, opt-in everywhere else. Without it, a fresh
    // install has no camera at all: the kernel layer denies /dev/video0 to
    // /usr/bin/pipewire, so PipeWire creates no camera node and the device
    // vanishes from `hwprivacy-ctl devices`. That reads as a broken install,
    // not as a policy decision.
    let config_path = hwprivacy_common::Config::user_config_path();
    if !config_path.exists() {
        let mut config = hwprivacy_common::Config::default();

        let dirs = hwprivacy_common::preset::preset_dirs();
        match hwprivacy_common::preset::load("desktop-baseline", &dirs) {
            Ok(preset) => {
                let plan = preset.plan(hwprivacy_common::preset::path_exists, |app| {
                    config.find_rule(app).is_some()
                });
                let added = config.apply_preset(&plan);
                config.save()?;
                println!("Created:   {}", config_path.display());
                println!(
                    "Baseline:  imported 'desktop-baseline' — {} rule(s):",
                    added
                );
                for (app, outcome, _) in &plan.entries {
                    println!("             {:<16} {}", app, outcome.describe());
                }
                if added == 0 {
                    println!(
                        "           NOTE: nothing resolved, so the camera will have no \
                         PipeWire node.\n           Cameras used directly (Firefox, Chrome) \
                         are unaffected."
                    );
                }
            }
            Err(e) => {
                // Not fatal: the daemon works, the camera just will not appear
                // as a PipeWire device. Saying so beats a silent gap.
                config.save()?;
                println!("Created:   {}", config_path.display());
                println!(
                    "Baseline:  SKIPPED — {e:#}\n\
                                Without it the camera has no PipeWire node. Fix with:\n\
                                hwprivacy-ctl preset import desktop-baseline --apply"
                );
            }
        }
    }

    // Reload and enable
    println!();
    let status = std::process::Command::new("systemctl")
        .args(["--user", "daemon-reload"])
        .status();
    if let Ok(s) = status {
        if s.success() {
            println!("systemd user daemon reloaded");
        }
    }

    let status = std::process::Command::new("systemctl")
        .args(["--user", "enable", "--now", "hwprivacy.service"])
        .status();
    match status {
        Ok(s) if s.success() => {
            println!("Service enabled and started!");
            println!();
            println!("Use:  hwprivacy-ctl status     — check daemon status");
            println!("      hwprivacy-tui             — terminal interface");
            println!("      hwprivacy-gui             — graphical interface");
            println!("      systemctl --user status hwprivacy  — service status");
        }
        _ => {
            println!("Could not auto-enable service. Run manually:");
            println!("  systemctl --user daemon-reload");
            println!("  systemctl --user enable --now hwprivacy.service");
        }
    }

    Ok(())
}

fn uninstall_service() -> anyhow::Result<()> {
    // Stop and disable
    let _ = std::process::Command::new("systemctl")
        .args(["--user", "disable", "--now", "hwprivacy.service"])
        .status();
    println!("Service stopped and disabled");

    // Remove files
    let service_path = systemd_user_dir().join("hwprivacy.service");
    if service_path.exists() {
        std::fs::remove_file(&service_path)?;
        println!("Removed: {}", service_path.display());
    }

    let dbus_path = dbus_services_dir().join("org.hwprivacy.Daemon.service");
    if dbus_path.exists() {
        std::fs::remove_file(&dbus_path)?;
        println!("Removed: {}", dbus_path.display());
    }

    let _ = std::process::Command::new("systemctl")
        .args(["--user", "daemon-reload"])
        .status();

    println!();
    println!("Service uninstalled. Config preserved at:");
    println!("  {}", hwprivacy_common::Config::user_config_path().display());

    Ok(())
}

fn service_status() -> anyhow::Result<()> {
    let status = std::process::Command::new("systemctl")
        .args(["--user", "status", "hwprivacy.service"])
        .status()?;

    if !status.success() {
        println!("\nService is not running. Install with:");
        println!("  hwprivacy-daemon install");
    }

    Ok(())
}
