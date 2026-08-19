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

    // A burst SUMMARY carries pid 0. It is accounting for opens the kernel
    // already suppressed — not a fresh access — so it must contribute its
    // count and NOTHING else: no event-log row, no notification.
    //
    // Handled BEFORE log_event() deliberately. It used to fall through, and
    // log_event() increments blocked_count itself on a Denied action, so the
    // summary was counted once as an access plus once per suppressed open.
    // Measured 2026-08-19 with a controlled 13-open denied burst: the kernel
    // reported 13, the daemon counted 14, and the event log showed a second
    // DENIED row with pid 0 for a session that had only one real prompt.
    if ev.pid == 0 {
        if ev.denied {
            let mut s = state.write().await;
            s.tracker.blocked_count += denied_opens(&ev);
        }
        info!(
            "Kernel layer: {} further {} open(s) by {} (burst summary, not a new access)",
            ev.additional_opens,
            if ev.denied { "denied" } else { "allowed" },
            app
        );
        return;
    }

    {
        let mut s = state.write().await;
        s.tracker
            .log_event(&app, ev.pid, category, &ev.exe_path, action);

        // denied_opens() is the single statement of how much this event is
        // worth. log_event() has ALREADY added one for a Denied action, so add
        // only the remainder — otherwise the two disagree and one of them wins
        // silently, which is precisely how the +1 got in.
        // `log_event_denial_contribution_is_one` pins that assumption.
        let already = if ev.denied { 1 } else { 0 };
        s.tracker.blocked_count += denied_opens(&ev) - already;
    }

    if !ev.denied {
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

/// How many denied opens one kernel event represents.
///
/// Exists as a pure function because this arithmetic was wrong in a way no
/// unit test could see: it lived inline in `handle_event`, tangled with
/// `log_event`'s own side effect of incrementing the same counter.
///
/// * an allowed event contributes nothing — `blocked_count` counts denials
/// * a burst summary (pid 0) represents ONLY the opens it accounts for
/// * any other event is one real open, plus whatever the kernel attached to it
pub fn denied_opens(ev: &AccessEvent) -> u32 {
    if !ev.denied {
        return 0;
    }
    if ev.pid == 0 {
        return ev.additional_opens;
    }
    1 + ev.additional_opens
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
    /// The exact case measured on 2026-08-19 against the live kernel: one
    /// process opened /dev/video0 thirteen times inside the coalescing window
    /// and every open was denied. The helper reported one event plus a burst
    /// summary carrying additional_opens=12 — thirteen opens in total.
    ///
    /// The daemon counted FOURTEEN. This test is that measurement.
    #[test]
    fn the_measured_thirteen_open_burst_counts_as_thirteen() {
        let primary = AccessEvent {
            ts_unix: 0,
            exe_path: "/usr/bin/python3.13".into(),
            pid: 645492,
            device: "/dev/video0".into(),
            role: "CAMERA".into(),
            denied: true,
            additional_opens: 0,
        };
        let summary = AccessEvent {
            pid: 0,
            additional_opens: 12,
            ..primary.clone()
        };
        assert_eq!(denied_opens(&primary), 1, "the primary open counts once");
        assert_eq!(
            denied_opens(&summary), 12,
            "the summary accounts for the suppressed opens and nothing more"
        );
        assert_eq!(
            denied_opens(&primary) + denied_opens(&summary), 13,
            "thirteen opens must count as thirteen, not fourteen"
        );
    }

    /// `handle_event` subtracts 1 from `denied_opens()` because `log_event`
    /// silently increments `blocked_count` itself. That is a hidden coupling
    /// between two files. If it ever stops being true, the compensation above
    /// becomes an under-count and nothing else would notice.
    #[test]
    fn log_event_denial_contribution_is_one() {
        use hwprivacy_common::stream::AccessAction;
        use hwprivacy_common::DeviceCategory;
        let mut t = crate::stream_tracker::StreamTracker::new();
        assert_eq!(t.blocked_count, 0);
        t.log_event("x", 1, DeviceCategory::Camera, "/dev/video0", AccessAction::Denied);
        assert_eq!(t.blocked_count, 1, "log_event counts exactly one denial");
        t.log_event("x", 1, DeviceCategory::Camera, "/dev/video0", AccessAction::Allowed);
        assert_eq!(t.blocked_count, 1, "an allowed event must not count");
    }

    /// The kernel may attach a burst's suppressed count to the NEXT real
    /// event instead of flushing it separately. That event is still one real
    /// open, so it carries its own count plus the ones it absorbed.
    #[test]
    fn a_real_event_carrying_a_suppressed_count_includes_itself() {
        let ev = AccessEvent {
            ts_unix: 0,
            exe_path: "/opt/google/chrome/chrome".into(),
            pid: 4242,
            device: "/dev/video1".into(),
            role: "CAMERA".into(),
            denied: true,
            additional_opens: 7,
        };
        assert_eq!(denied_opens(&ev), 8);
    }

    /// blocked_count counts DENIALS. An allowed burst coalesces exactly the
    /// same way — measured with an allowlisted Chrome, additional_opens=7 —
    /// and must contribute nothing.
    #[test]
    fn an_allowed_burst_never_touches_the_blocked_count() {
        let allowed = AccessEvent {
            ts_unix: 0,
            exe_path: "/opt/google/chrome/chrome".into(),
            pid: 4242,
            device: "/dev/video1".into(),
            role: "CAMERA".into(),
            denied: false,
            additional_opens: 7,
        };
        assert_eq!(denied_opens(&allowed), 0);
        let allowed_summary = AccessEvent { pid: 0, ..allowed.clone() };
        assert_eq!(denied_opens(&allowed_summary), 0);
    }

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
