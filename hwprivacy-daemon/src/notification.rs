use hwprivacy_common::{DeviceCategory, Permission};
use notify_rust::{Hint, Notification, Urgency};
use std::sync::{Arc, Mutex};
use tracing::{info, warn};

/// Icon for each device category
fn device_icon(device: DeviceCategory) -> &'static str {
    match device {
        DeviceCategory::Microphone => "audio-input-microphone",
        DeviceCategory::Camera => "camera-video",
        DeviceCategory::Monitor => "audio-card",
    }
}

/// Human-readable label
fn device_label(device: DeviceCategory) -> &'static str {
    match device {
        DeviceCategory::Microphone => "Microphone",
        DeviceCategory::Camera => "Camera",
        DeviceCategory::Monitor => "Playback Monitor",
    }
}

/// Stage 1: Instant "BLOCKED" notification — fire-and-forget, non-blocking.
/// Shows immediately so the user knows something was caught.
pub async fn notify_blocked(
    app_name: &str,
    pid: u32,
    device: DeviceCategory,
    node_name: &str,
) {
    let summary = format!("BLOCKED: {} → {}", app_name, device_label(device));
    let body = format!(
        "<b>{}</b> (pid:{}) tried to access <b>{}</b>\n\
         Stream: {}\n\
         <i>Access denied. Choose a rule below or use hwprivacy-ctl.</i>",
        app_name, pid, device_label(device), node_name
    );
    let icon = device_icon(device);

    tokio::task::spawn_blocking(move || {
        let result = Notification::new()
            .summary(&summary)
            .body(&body)
            .icon(icon)
            .urgency(Urgency::Critical)
            .hint(Hint::Category("device.error".to_string()))
            .hint(Hint::Transient(true))
            .timeout(5000) // auto-dismiss after 5s
            .show();

        if let Err(e) = result {
            warn!("Failed to send blocked notification: {}", e);
        }
    })
    .await
    .ok();
}

/// Kernel-layer denial notification. Informational only — no action buttons.
///
/// Deliberately NOT routed through [`ask_user_permission`]: that path carries
/// defect b1, where dismissing the prompt writes a permanent `deny` rule. A new
/// event source wired into it would inherit that bug on day one. Kernel camera
/// policy is edited in `config.toml` until b1 is fixed.
///
/// `detail` carries the consequence, not just the fact. For a camera denial it
/// warns that a video call may also lose its audio — measured 2026-08-05, when
/// WhatsApp reported "camera or microphone not found" although only the camera
/// was ever denied. `getUserMedia({audio, video})` fails as a unit.
pub async fn notify_kernel_denial(
    app_name: &str,
    pid: u32,
    device: DeviceCategory,
    device_path: &str,
    detail: &str,
) {
    let summary = format!("BLOCKED (kernel): {} → {}", app_name, device_label(device));
    let body = format!(
        "<b>{}</b> (pid:{}) was denied <b>{}</b>\n\
         Device: {}\n\
         <i>{}</i>",
        app_name,
        pid,
        device_label(device),
        device_path,
        detail
    );
    let icon = device_icon(device);

    tokio::task::spawn_blocking(move || {
        let result = Notification::new()
            .summary(&summary)
            .body(&body)
            .icon(icon)
            .urgency(Urgency::Critical)
            .hint(Hint::Category("device.error".to_string()))
            .hint(Hint::Transient(true))
            .timeout(8000)
            .show();

        if let Err(e) = result {
            warn!("Failed to send kernel denial notification: {}", e);
        }
    })
    .await
    .ok();
}

/// Stage 2: Action notification — asks user to set a permanent rule.
/// Returns the user's chosen permission. Blocks until user responds or timeout.
pub async fn ask_user_permission(
    app_name: &str,
    pid: u32,
    device: DeviceCategory,
    node_name: &str,
    is_per_stream: bool,
) -> Option<Permission> {
    let label = device_label(device);
    let icon = device_icon(device);

    let summary = format!("Set rule for {} → {}", app_name, label);
    let body = if is_per_stream {
        format!(
            "<b>{}</b> (pid:{}) wants <b>{}</b> access.\n\
             Stream: {}\n\
             Choose how to handle <u>this stream</u>:",
            app_name, pid, label, node_name
        )
    } else {
        format!(
            "<b>{}</b> (pid:{}) wants <b>{}</b> access.\n\
             Choose a <u>permanent rule</u> for this app:",
            app_name, pid, label
        )
    };

    let is_per_stream_c = is_per_stream;

    let result = tokio::task::spawn_blocking(move || {
        let chosen = Arc::new(Mutex::new(None::<Permission>));

        let mut notif = Notification::new();
        notif
            .summary(&summary)
            .body(&body)
            .icon(icon)
            .urgency(Urgency::Critical)
            .hint(Hint::Category("device".to_string()))
            .hint(Hint::Resident(true)) // stays until user acts
            .timeout(60000); // 60s timeout

        if is_per_stream_c {
            notif
                .action("allow_stream", "Allow Stream")
                .action("deny_stream", "Deny Stream");
        } else {
            notif
                .action("allow", "Always Allow")
                .action("ask_each", "Ask Each Time")
                .action("while_in_use", "While in Use")
                .action("deny", "Always Deny");
        }

        match notif.show() {
            Ok(handle) => {
                let chosen_c = chosen.clone();
                handle.wait_for_action(|action| {
                    let perm = match action {
                        "allow" | "allow_stream" => Some(Permission::Allow),
                        "ask_each" => Some(Permission::AskEach),
                        "while_in_use" => Some(Permission::WhileInUse),
                        "deny" | "deny_stream" => Some(Permission::Deny),
                        "__closed" => {
                            info!("Notification dismissed — no rule saved, will ask again later");
                            None
                        }
                        other => {
                            warn!("Unknown notification action: {}", other);
                            Some(Permission::Deny)
                        }
                    };
                    *chosen_c.lock().unwrap() = perm;
                });
                chosen.lock().unwrap().take()
            }
            Err(e) => {
                warn!("Failed to show action notification: {}", e);
                Some(Permission::Deny)
            }
        }
    })
    .await;

    match result {
        Ok(perm) => perm.or(Some(Permission::Deny)),
        Err(e) => {
            warn!("Notification task failed: {}", e);
            Some(Permission::Deny)
        }
    }
}
