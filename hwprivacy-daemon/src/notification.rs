use hwprivacy_common::{sanitize_rule_name, DeviceCategory, Permission};
use notify_rust::{Hint, Notification, Urgency};
use std::sync::{Arc, Mutex};
use tracing::{info, warn};

/// What came back from an action notification.
///
/// Three states, not two, and that is the whole of blocker b1. The old return
/// type was `Option<Permission>` ending in `.or(Some(Permission::Deny))`, which
/// collapsed *the user chose deny*, *the user dismissed the popup* and *the
/// notification system is broken* into one indistinguishable value. Months of
/// ignored popups became permanent deny rules the user never chose, and the
/// cooldown machinery written for the dismiss case was unreachable code.
///
/// `Dismissed` and `Failed` are both fail-closed — the link was already
/// destroyed before the prompt was shown — but neither may write a rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PromptOutcome {
    /// The user pressed a button. This is the ONLY variant that may be saved.
    Chosen(Permission),
    /// The user closed or ignored the popup. Block, save nothing, ask later.
    Dismissed,
    /// The notification could never be shown or the task died. Same treatment
    /// as a dismissal: on a headless session, or with no notification daemon
    /// running, the old code turned every single prompt into a permanent deny.
    Failed(String),
}

impl PromptOutcome {
    /// The permission to persist, if any. `None` means **write nothing** — not
    /// "write a deny". Every caller that saves a rule goes through here.
    pub fn permission(&self) -> Option<Permission> {
        match self {
            PromptOutcome::Chosen(p) => Some(*p),
            PromptOutcome::Dismissed | PromptOutcome::Failed(_) => None,
        }
    }
}

/// What the daemon should actually do with a prompt's answer.
///
/// A separate, pure step on purpose. The old logic lived inline inside a
/// `tokio::spawn`, where no test could reach it — so the one thing that had to
/// be true (a dismissal writes nothing) was guarded only by reading the code,
/// and it was wrong for months. `denied_opens` in `lsm_client` was extracted
/// for the same reason after the same kind of bug.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PromptAction {
    /// Write a permanent rule. Reachable ONLY from [`PromptOutcome::Chosen`].
    SavePermanentRule(Permission),
    /// Let this one stream through, save nothing.
    GrantThisStream,
    /// Refuse this one stream, save nothing.
    DenyThisStream,
    /// We still do not know what the user wants. Stay blocked, write nothing,
    /// go quiet for the cooldown, ask again after it.
    SaveNothingAndCooldown,
}

/// Map an outcome to an action.
///
/// The invariant this exists to hold: no input other than
/// [`PromptOutcome::Chosen`] can produce [`PromptAction::SavePermanentRule`].
pub fn decide(outcome: &PromptOutcome, is_per_stream: bool) -> PromptAction {
    let Some(perm) = outcome.permission() else {
        return PromptAction::SaveNothingAndCooldown;
    };
    match (is_per_stream, perm) {
        (true, Permission::Allow) => PromptAction::GrantThisStream,
        (true, _) => PromptAction::DenyThisStream,
        (false, p) => PromptAction::SavePermanentRule(p),
    }
}

/// The string the user should type to write a rule for this app.
///
/// Notification bodies render `{app} (pid:{n})` because the pid is genuinely
/// useful for telling two instances apart. It is also what people select and
/// paste into a rule, where it is dead on arrival. Printing the real key next
/// to it means the pasteable string is the correct one.
fn rule_key_hint(app_name: &str) -> String {
    match sanitize_rule_name(app_name) {
        Some(key) => format!("\nRule name: <b>{key}</b>"),
        None => String::new(),
    }
}

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

/// Label naming WHICH instance, when a node presents more than one —
/// `Microphone (mic2)`.
///
/// This is blocker b3. A stereo capture device is two physical microphones, so
/// two prompts are correct; two prompts both saying "Microphone" is what reads
/// as broken. The category stays in the string so nothing that reads the text
/// loses the device kind.
pub fn device_label_for(device: DeviceCategory, instance: Option<&str>) -> String {
    match instance {
        Some(i) => format!("{} ({})", device_label(device), i),
        None => device_label(device).to_string(),
    }
}

/// Stage 1: Instant "BLOCKED" notification — fire-and-forget, non-blocking.
/// Shows immediately so the user knows something was caught.
pub async fn notify_blocked(
    app_name: &str,
    pid: u32,
    device: DeviceCategory,
    instance: Option<&str>,
    node_name: &str,
) {
    let label = device_label_for(device, instance);
    let summary = format!("BLOCKED: {} → {}", app_name, label);
    let body = format!(
        "<b>{}</b> (pid:{}) tried to access <b>{}</b>\n\
         Stream: {}{}\n\
         <i>Access denied. Choose a rule below or use hwprivacy-ctl.</i>",
        app_name,
        pid,
        label,
        node_name,
        rule_key_hint(app_name)
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

/// "Something used your camera" — the allowed counterpart of
/// [`notify_blocked`]. Informational, no action buttons.
///
/// # Why the wording is in the past tense
///
/// It says *used*, never *is using*. The LSM hook is on `open()` and nothing
/// fires on close, so hwprivacy genuinely does not know when access ends. A
/// message implying a live state would be a claim it cannot support — and the
/// same limit is why there is no tray in-use dot: it would light and never go
/// out.
///
/// `Urgency::Normal`, not Critical. A denial is an alarm; this is a fact.
pub async fn notify_allowed(
    app_name: &str,
    pid: u32,
    device: DeviceCategory,
    instance: Option<&str>,
    detail: &str,
) {
    let label = device_label_for(device, instance);
    let summary = format!("{} used the {}", app_name, label);
    let body = format!(
        "<b>{}</b> (pid:{}) was allowed <b>{}</b> by your rules.\n\
         <i>{}</i>",
        app_name, pid, label, detail
    );
    let icon = device_icon(device);

    tokio::task::spawn_blocking(move || {
        let result = Notification::new()
            .summary(&summary)
            .body(&body)
            .icon(icon)
            .urgency(Urgency::Normal)
            .hint(Hint::Category("device".to_string()))
            .hint(Hint::Transient(true))
            .timeout(6000)
            .show();

        if let Err(e) = result {
            warn!("Failed to send allowed notification: {}", e);
        }
    })
    .await
    .ok();
}

/// Kernel-layer denial notification. Informational only — no action buttons.
///
/// Originally not routed through [`ask_user_permission`] because that path
/// carried b1 (dismissing wrote a permanent deny). **b1 was fixed on
/// 2026-08-21, so that reason has expired** — but the buttons have not been
/// added back, and adding them is a decision rather than a cleanup: granting
/// the camera at the kernel layer means writing an `exe_path`, and a prompt
/// raised from an access event has no way to resolve one. Kernel camera policy
/// is still edited in `config.toml`.
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

/// Stage 2: Action notification — asks the user to set a permanent rule.
///
/// Blocks until the user responds or the popup times out. See [`PromptOutcome`]
/// for why the answer is not an `Option<Permission>`.
pub async fn ask_user_permission(
    app_name: &str,
    pid: u32,
    device: DeviceCategory,
    instance: Option<&str>,
    node_name: &str,
    is_per_stream: bool,
) -> PromptOutcome {
    let label = device_label_for(device, instance);
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
            "<b>{}</b> (pid:{}) wants <b>{}</b> access.{}\n\
             Choose a <u>permanent rule</u> for this app:",
            app_name,
            pid,
            label,
            rule_key_hint(app_name)
        )
    };

    let is_per_stream_c = is_per_stream;

    let result = tokio::task::spawn_blocking(move || -> PromptOutcome {
        let chosen = Arc::new(Mutex::new(None::<Permission>));

        let mut notif = Notification::new();
        notif
            .summary(&summary)
            .body(&body)
            .icon(icon)
            .urgency(Urgency::Critical)
            .hint(Hint::Category("device".to_string()))
            // Stays until the user answers. Decided 2026-08-23: a permission
            // question is a to-do item, not a nag — one that vanishes while you
            // are away leaves the app silently broken with no explanation.
            //
            // `Timeout::Never` rather than the `timeout(60000)` that used to sit
            // here. That was a lie in two directions: Hint::Resident already
            // overrode it, so the 60s never elapsed, and the code downstream
            // was written believing it did — the dismiss cooldown could
            // therefore never start and the same app re-prompted on every new
            // stream (b6). Saying "never" out loud is what makes the rest
            // honest.
            //
            // If a notification daemon closes it anyway, that arrives as
            // "__closed" -> PromptOutcome::Dismissed, which is handled
            // correctly: block, save nothing, cool down, ask again.
            .hint(Hint::Resident(true))
            .timeout(notify_rust::Timeout::Never);

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
                            // An action id we do not recognise is a bug on our
                            // side or a hostile notification daemon. Blocking
                            // is right; SAVING a deny is not — that would put
                            // the b1 defect back through a side door.
                            warn!("Unknown notification action: {}", other);
                            None
                        }
                    };
                    *chosen_c.lock().unwrap() = perm;
                });
                match chosen.lock().unwrap().take() {
                    Some(p) => PromptOutcome::Chosen(p),
                    None => PromptOutcome::Dismissed,
                }
            }
            Err(e) => {
                warn!("Failed to show action notification: {}", e);
                PromptOutcome::Failed(e.to_string())
            }
        }
    })
    .await;

    result.unwrap_or_else(|e| {
        warn!("Notification task failed: {}", e);
        PromptOutcome::Failed(e.to_string())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The pasteable string in a notification body must be a rule key that
    /// actually matches. This is the display half of b4.
    #[test]
    fn the_hint_offers_a_key_that_matching_will_accept() {
        let hint = rule_key_hint("Firefox [pipewire-pulse]");
        assert!(hint.contains("firefox"), "{hint}");
        assert!(
            !hint.contains("pipewire-pulse"),
            "the annotation must not survive into the suggested key: {hint}"
        );
    }

    #[test]
    fn an_unusable_name_offers_no_key_rather_than_a_broken_one() {
        assert_eq!(rule_key_hint(""), "");
        assert_eq!(rule_key_hint("(pid:7)"), "");
    }

    /// b1 in one assertion: the three outcomes must stay distinguishable.
    /// `Dismissed` and `Failed` are not a permission and must never be
    /// convertible into one by accident.
    #[test]
    fn only_a_real_choice_carries_a_permission() {
        assert_eq!(
            PromptOutcome::Chosen(Permission::Allow).permission(),
            Some(Permission::Allow)
        );
        assert_eq!(PromptOutcome::Dismissed.permission(), None);
        assert_eq!(PromptOutcome::Failed("no bus".into()).permission(), None);
    }

    /// **This is blocker b1.** For months, dismissing a prompt wrote a
    /// permanent `deny` rule, because `ask_user_permission` ended in
    /// `.or(Some(Permission::Deny))` and the caller could not tell a dismissal
    /// from a decision. Config silently filled with denials the user never
    /// chose — the single biggest reason daily use "did not work properly".
    ///
    /// The property, stated so it cannot regress quietly: **nothing except a
    /// real button press may reach `SavePermanentRule`.**
    #[test]
    fn no_answer_can_ever_become_a_saved_rule() {
        for outcome in [
            PromptOutcome::Dismissed,
            PromptOutcome::Failed("no notification daemon".into()),
        ] {
            for is_per_stream in [true, false] {
                assert_eq!(
                    decide(&outcome, is_per_stream),
                    PromptAction::SaveNothingAndCooldown,
                    "{outcome:?} (per_stream={is_per_stream}) must write nothing"
                );
            }
        }
    }

    /// A dismissal is not a deny. It must be indistinguishable, in what gets
    /// written, from never having asked — including when the user's answer
    /// would have BEEN deny.
    #[test]
    fn dismissing_differs_from_choosing_deny() {
        assert_ne!(
            decide(&PromptOutcome::Dismissed, false),
            decide(&PromptOutcome::Chosen(Permission::Deny), false)
        );
        assert_eq!(
            decide(&PromptOutcome::Chosen(Permission::Deny), false),
            PromptAction::SavePermanentRule(Permission::Deny),
            "an explicit deny IS saved — that is the user's decision"
        );
    }

    /// Every button on the permanent prompt writes the permission it names.
    #[test]
    fn each_permanent_choice_is_saved_verbatim() {
        for p in [
            Permission::Allow,
            Permission::AskEach,
            Permission::WhileInUse,
            Permission::Deny,
        ] {
            assert_eq!(
                decide(&PromptOutcome::Chosen(p), false),
                PromptAction::SavePermanentRule(p)
            );
        }
    }

    /// The per-stream prompt has two buttons and must never touch config —
    /// that is the whole point of `ask_each` for a browser.
    #[test]
    fn a_per_stream_answer_never_writes_a_rule() {
        assert_eq!(
            decide(&PromptOutcome::Chosen(Permission::Allow), true),
            PromptAction::GrantThisStream
        );
        for p in [Permission::Deny, Permission::AskEach, Permission::WhileInUse] {
            assert_eq!(
                decide(&PromptOutcome::Chosen(p), true),
                PromptAction::DenyThisStream,
                "{p} on a per-stream prompt must not be persisted"
            );
        }
    }
}
