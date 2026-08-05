//! Client for the root eBPF helper.
//!
//! Connects to `hwprivacy-lsm`'s unix socket, pushes the camera allowlist
//! derived from `config.toml`, and folds the kernel's access events into the
//! same [`StreamTracker`] the PipeWire layer writes to — so `hwprivacy-ctl`,
//! the TUI and the GUI display kernel denials with **no frontend changes**.
//!
//! # Why the daemon is the client and not the server
//!
//! The privileged side owns the kernel maps and must outlive any UI. The
//! daemon is the thing that restarts when a user logs out. A root server plus
//! an unprivileged client that reconnects is the arrangement that survives
//! that; the reverse would make the kernel layer depend on a session process.
//!
//! # If the helper is not running
//!
//! Nothing breaks. The daemon retries quietly and reports
//! `kernel layer: not connected` — the PipeWire layer is unaffected. The
//! kernel layer is an addition, never a dependency.

use crate::dbus_service::SharedState;
use hwprivacy_common::stream::AccessAction;
use hwprivacy_common::{DeviceCategory, Permission};
use hwprivacy_proto::{
    encode_line, AccessEvent, PolicyEntry, Reply, Request, DEFAULT_SOCKET, PERM_CAMERA,
    PROTO_VERSION,
};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tracing::{debug, error, info, warn};

/// What the daemon knows about the kernel layer, for `hwprivacy-ctl status`.
#[derive(Debug, Clone, Default)]
pub struct KernelLayerState {
    pub connected: bool,
    pub enforcing_camera: bool,
    /// Executables the kernel currently allows to use the camera.
    pub allowed_exes: u32,
    /// Allowlist entries the helper could not resolve — under default-deny
    /// these are applications silently losing their camera.
    pub unresolved: Vec<String>,
    pub last_error: Option<String>,
}

/// Reconnect delay. Deliberately unhurried: a missing helper is the normal
/// state on a machine where the kernel layer is not installed, and hammering
/// a non-existent socket every second would be noise in the journal forever.
const RECONNECT_SECS: u64 = 10;

/// Run forever: connect, serve, reconnect.
pub async fn run(state: SharedState, socket_path: Option<String>) {
    let path = socket_path.unwrap_or_else(|| DEFAULT_SOCKET.to_string());
    let mut announced_missing = false;

    loop {
        match UnixStream::connect(&path).await {
            Ok(stream) => {
                announced_missing = false;
                info!("Kernel layer: connected to {}", path);
                if let Err(e) = session(&state, stream).await {
                    warn!("Kernel layer session ended: {:#}", e);
                    let mut s = state.write().await;
                    s.kernel.last_error = Some(format!("{e:#}"));
                }
                {
                    let mut s = state.write().await;
                    s.kernel.connected = false;
                    s.kernel.enforcing_camera = false;
                }
                info!("Kernel layer: disconnected, will retry");
            }
            Err(e) => {
                // Log the first failure only. Repeating it every 10s for a
                // machine that simply has no kernel layer is pure noise.
                if !announced_missing {
                    info!(
                        "Kernel layer not available at {} ({}). The PipeWire layer \
                         is unaffected; retrying quietly.",
                        path, e
                    );
                    announced_missing = true;
                }
            }
        }
        tokio::time::sleep(Duration::from_secs(RECONNECT_SECS)).await;
    }
}

/// One connection: handshake, push policy, then stream events until it drops.
async fn session(state: &SharedState, stream: UnixStream) -> anyhow::Result<()> {
    let (rx, mut tx) = stream.into_split();
    let mut lines = BufReader::new(rx).lines();

    tx.write_all(
        encode_line(&Request::Hello {
            version: PROTO_VERSION,
        })?
        .as_bytes(),
    )
    .await?;

    // Push the allowlist immediately. Until this lands the helper is enforcing
    // whatever it was started with, which may be nothing.
    let (entries, enforce, gaps) = {
        let s = state.read().await;
        let entries: Vec<PolicyEntry> = s
            .config
            .kernel_camera_allowlist()
            .into_iter()
            .map(|(exe_path, _)| PolicyEntry {
                exe_path,
                perms: PERM_CAMERA,
            })
            .collect();
        // The kernel layer enforces only when the guard for cameras is on.
        let enforce = s.config.devices.is_guarded(&DeviceCategory::Camera);
        (entries, enforce, s.config.kernel_camera_gaps())
    };

    for (app, why) in &gaps {
        warn!("Kernel layer gap: rule '{}' — {}", app, why);
    }

    tx.write_all(
        encode_line(&Request::SetPolicy {
            entries: entries.clone(),
            enforce_camera: enforce,
        })?
        .as_bytes(),
    )
    .await?;

    while let Some(line) = lines.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
        let reply: Reply = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => {
                warn!("Kernel layer sent an unparseable line: {}", e);
                continue;
            }
        };

        match reply {
            Reply::Hello {
                version,
                enforcing_camera,
            } => {
                if version != PROTO_VERSION {
                    anyhow::bail!(
                        "protocol mismatch: helper {version}, daemon {PROTO_VERSION}"
                    );
                }
                let mut s = state.write().await;
                s.kernel.connected = true;
                s.kernel.enforcing_camera = enforcing_camera;
                s.kernel.last_error = None;
            }

            Reply::PolicyApplied {
                applied,
                unresolved,
            } => {
                info!(
                    "Kernel layer: {} executable(s) allowed the camera, {} unusable",
                    applied,
                    unresolved.len()
                );
                for u in &unresolved {
                    error!(
                        "Kernel layer: allowlist entry '{}' is unusable ({}). \
                         That application WILL be denied the camera.",
                        u.exe_path, u.reason
                    );
                }
                let mut s = state.write().await;
                s.kernel.allowed_exes = applied as u32;
                s.kernel.enforcing_camera = enforce;
                s.kernel.unresolved = unresolved
                    .iter()
                    .map(|u| format!("{}: {}", u.exe_path, u.reason))
                    .collect();
            }

            Reply::Event(ev) => handle_event(state, ev).await,

            Reply::Policy { entries } => {
                debug!("Kernel layer holds {} policy entries", entries.len());
            }
            Reply::Pong => {}
            Reply::Error { message } => {
                error!("Kernel layer error: {}", message);
                let mut s = state.write().await;
                s.kernel.last_error = Some(message);
            }
        }
    }

    Ok(())
}

/// Fold one kernel event into the daemon's own event log, and notify on denial.
async fn handle_event(state: &SharedState, ev: AccessEvent) {
    let category = match ev.role.as_str() {
        "CAMERA" => DeviceCategory::Camera,
        "MIC" => DeviceCategory::Microphone,
        // Playback and mixer-control opens are not privacy events. The helper
        // does not forward them by default; ignore them if it ever does.
        _ => return,
    };

    let action = if ev.denied {
        AccessAction::Denied
    } else {
        AccessAction::Allowed
    };

    // A short, stable label. The full path goes in node_name so the event log
    // keeps the identity that made the decision.
    let app = short_name(&ev.exe_path);

    {
        let mut s = state.write().await;
        s.tracker
            .log_event(&app, ev.pid, category, &ev.exe_path, action);

        // The kernel already collapsed a burst into one event; count the rest
        // so "blocked attempts" reflects reality rather than notifications.
        if ev.denied && ev.additional_opens > 0 {
            s.tracker.blocked_count += ev.additional_opens;
        }
    }

    if !ev.denied {
        return;
    }

    // A burst SUMMARY carries pid 0: it is the accounting for opens already
    // reported, not a fresh access. Notifying here would fire a second popup
    // for the same camera session and defeat the coalescing this summary
    // exists to support. It still counts toward blocked_count above — the
    // number must be right even though the notification must not repeat.
    if ev.pid == 0 {
        info!(
            "Kernel layer: {} further denied open(s) by {} (burst summary, no notification)",
            ev.additional_opens, app
        );
        return;
    }

    info!(
        "Kernel layer DENIED {} -> {} ({}), {} open(s) total",
        app,
        ev.device,
        ev.role,
        ev.total_opens()
    );

    // Informational only — no action buttons.
    //
    // Deliberate: the action-notification path (notification::ask_user_permission)
    // has defect b1, where dismissing writes a permanent deny rule. Wiring a new
    // event source into it would inherit that bug on day one. Kernel policy is
    // edited in config.toml until b1 is fixed.
    let detail = if category == DeviceCategory::Camera {
        // Measured 2026-08-05: WhatsApp reported "camera or microphone not
        // found" although only the camera was denied. getUserMedia({audio,
        // video}) fails as a unit, so a camera denial kills call audio too.
        // Saying so here prevents a phantom microphone bug hunt later.
        "Blocked by the kernel. A video call may also lose its audio — the browser \
         asks for camera and microphone together."
    } else {
        "Blocked by the kernel."
    };

    crate::notification::notify_kernel_denial(&app, ev.pid, category, &ev.device, detail).await;
}

/// Last path component, for a readable event log. `/usr/lib/firefox-esr/firefox-esr`
/// becomes `firefox-esr`.
fn short_name(exe_path: &str) -> String {
    exe_path
        .rsplit('/')
        .next()
        .filter(|s| !s.is_empty())
        .unwrap_or(exe_path)
        .to_string()
}

/// Permission the kernel layer would apply, for display purposes.
pub fn kernel_permission_for(allowed: bool) -> Permission {
    if allowed {
        Permission::Allow
    } else {
        Permission::Deny
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_name_takes_the_binary_not_the_path() {
        assert_eq!(short_name("/usr/lib/firefox-esr/firefox-esr"), "firefox-esr");
        assert_eq!(short_name("/usr/bin/ffmpeg"), "ffmpeg");
    }

    #[test]
    fn short_name_survives_odd_inputs() {
        // The helper sends "<dev=.. ino=..>" when the process exited before its
        // path could be read. That must not become an empty label.
        assert_eq!(short_name("<dev=66306 ino=30027059>"), "<dev=66306 ino=30027059>");
        assert_eq!(short_name("noslashes"), "noslashes");
        assert_eq!(short_name("/trailing/"), "/trailing/");
    }

    /// A burst summary must be counted but must NOT notify — otherwise one
    /// camera session produces two popups, which is the defect coalescing
    /// exists to prevent.
    #[test]
    fn a_burst_summary_is_identified_by_pid_zero() {
        let summary = AccessEvent {
            ts_unix: 0,
            exe_path: "/usr/lib/firefox-esr/firefox-esr".into(),
            pid: 0,
            device: "/dev/video*".into(),
            role: "CAMERA".into(),
            denied: true,
            additional_opens: 12,
        };
        assert_eq!(summary.pid, 0, "summaries are marked with pid 0");
        assert!(summary.is_burst());
        assert_eq!(summary.total_opens(), 13);

        let real = AccessEvent { pid: 3271, additional_opens: 0, ..summary };
        assert_ne!(real.pid, 0, "a real access has a real pid and DOES notify");
    }

    #[test]
    fn only_privacy_relevant_roles_map_to_a_device_category() {
        // Playback and control opens must never reach the event log as if they
        // were capture events.
        for role in ["playback", "control", "other", ""] {
            let ev = AccessEvent {
                ts_unix: 0,
                exe_path: "/x".into(),
                pid: 1,
                device: "/dev/snd/pcmC0D0p".into(),
                role: role.into(),
                denied: true,
                additional_opens: 0,
            };
            assert!(
                !matches!(ev.role.as_str(), "CAMERA" | "MIC"),
                "{role} must not be treated as capture"
            );
        }
    }
}
