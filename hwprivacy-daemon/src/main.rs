mod dbus_service;
mod device_discovery;
mod link_manager;
mod lsm_client;
mod notification;
mod pipewire_monitor;
mod policy_engine;
mod state;
mod stream_tracker;

use clap::{Parser, Subcommand};
use dbus_service::{HwPrivacyService, SharedState};
use hwprivacy_common::stream::AccessAction;
use hwprivacy_common::{Config, Permission};
use policy_engine::PolicyDecision;
use state::DaemonState;
use std::collections::HashSet;
use std::io::Write;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{error, info, warn};

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

        // Process each new link
        for link in &new_links {
            let s = state.read().await;

            // Check if this link involves a protected device
            let classification = policy_engine::classify_link(
                link.output_node,
                link.input_node,
                &snapshot.nodes,
                &s.devices,
            );

            let (stream, device) = match classification {
                Some((s, d)) => (s, d),
                None => continue, // Not a protected device link
            };

            // Skip if device category is not guarded
            if !s.config.devices.is_guarded(&device.category) {
                continue;
            }

            // Check block-all mode
            if s.block_all {
                drop(s);
                if let Err(e) = link_manager::destroy_link(link.link_id).await {
                    warn!("Failed to destroy link in block-all mode: {}", e);
                }
                let mut s = state.write().await;
                s.tracker.log_event(
                    &stream.app_name,
                    stream.pid,
                    device.category,
                    &stream.node_name,
                    AccessAction::Denied,
                );
                continue;
            }

            // Evaluate policy
            let is_one_shot = s.tracker.is_one_shot_allowed(stream.object_serial);
            let decision = policy_engine::evaluate(&s.config, &stream, &device, is_one_shot);

            // Act on decision
            match decision {
                PolicyDecision::Allow => {
                    drop(s);
                    let mut s = state.write().await;
                    let perm = s.config.get_permission(&stream.app_name, &device.category);
                    s.tracker.add_connection(
                        link.link_id,
                        stream.clone(),
                        &device.node_name,
                        device.category,
                        perm,
                    );
                    if perm == Permission::WhileInUse {
                        s.tracker
                            .track_while_in_use(&stream.app_name, stream.object_serial);
                    }
                    s.tracker.log_event(
                        &stream.app_name,
                        stream.pid,
                        device.category,
                        &stream.node_name,
                        AccessAction::Allowed,
                    );
                }

                PolicyDecision::Deny => {
                    let app = stream.app_name.clone();
                    let pid = stream.pid;
                    let cat = device.category;
                    let node = stream.node_name.clone();

                    drop(s);
                    if let Err(e) = link_manager::destroy_link(link.link_id).await {
                        warn!("Failed to destroy denied link: {}", e);
                    }
                    let mut s = state.write().await;
                    s.tracker.log_event(&app, pid, cat, &node, AccessAction::Denied);
                    drop(s);

                    // Instant notification — rule already says deny
                    notification::notify_blocked(&app, pid, cat, &node).await;
                }

                PolicyDecision::AskUser | PolicyDecision::AskEachStream => {
                    let is_per_stream = matches!(decision, PolicyDecision::AskEachStream);
                    let app = stream.app_name.clone();
                    let pid = stream.pid;
                    let cat = device.category;
                    let node = stream.node_name.clone();
                    let serial = stream.object_serial;
                    let lid = link.link_id;

                    // 1. Destroy link immediately (security first)
                    drop(s);
                    if let Err(e) = link_manager::destroy_link(lid).await {
                        warn!("Failed to destroy link while asking: {}", e);
                    }

                    // 2. Check cooldown — if user recently dismissed the same
                    //    prompt, silently block without notification spam
                    let in_cooldown = {
                        let s = state.read().await;
                        s.tracker.is_in_cooldown(&app, cat)
                    };

                    {
                        let mut s = state.write().await;
                        if in_cooldown {
                            // log_event() increments blocked_count itself for a
                            // Denied action (stream_tracker.rs). An extra += 1
                            // here counted every cooldown-suppressed block twice.
                            // The other two Denied paths in this file correctly
                            // rely on log_event alone.
                            s.tracker.log_event(&app, pid, cat, &node, AccessAction::Denied);
                        } else {
                            s.tracker.log_event(&app, pid, cat, &node, AccessAction::AskedUser);
                        }
                    }

                    if in_cooldown {
                        // Silently blocked — user dismissed recently, no spam
                        continue;
                    }

                    // 3. Stage 1: instant BLOCKED notification (fire-and-forget)
                    notification::notify_blocked(&app, pid, cat, &node).await;

                    // 4. Stage 2: action notification for rule setting (async)
                    let notify_state = state.clone();
                    tokio::spawn(async move {
                        let response = notification::ask_user_permission(
                            &app, pid, cat, &node, is_per_stream,
                        )
                        .await;

                        let mut s = notify_state.write().await;
                        match response {
                            Some(perm) => {
                                // User made a choice — save rule
                                if is_per_stream {
                                    if perm == Permission::Allow {
                                        s.tracker.grant_one_shot(serial);
                                        s.tracker.log_event(
                                            &app, pid, cat, &node,
                                            AccessAction::StreamAllowed,
                                        );
                                    } else {
                                        s.tracker.log_event(
                                            &app, pid, cat, &node,
                                            AccessAction::StreamDenied,
                                        );
                                    }
                                } else {
                                    s.config.set_rule(&app, &cat, perm);
                                    if let Err(e) = s.config.save() {
                                        error!("Failed to save config after user decision: {}", e);
                                    }
                                    info!("User set rule: {} → {:?} = {}", app, cat, perm);
                                }
                            }
                            None => {
                                // User dismissed — no rule saved, start cooldown
                                // to prevent notification spam for 60s.
                                // Access stays blocked, will ask again after cooldown.
                                info!(
                                    "Notification dismissed for {} → {:?}, cooldown 60s",
                                    app, cat
                                );
                                s.tracker.record_dismiss(&app, cat);
                            }
                        }
                    });
                }
            }
        }

        // Clean up: remove connections for links that no longer exist
        {
            let current_link_ids: HashSet<u32> =
                snapshot.links.iter().map(|l| l.link_id).collect();
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

    // Create default config if it doesn't exist
    let config_path = hwprivacy_common::Config::user_config_path();
    if !config_path.exists() {
        let config = hwprivacy_common::Config::default();
        config.save()?;
        println!("Created:   {}", config_path.display());
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
