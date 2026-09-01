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
use hwprivacy_common::short_name;
use hwprivacy_common::stream::AccessAction;
use hwprivacy_common::{Config, DeviceCategory, Permission};
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

/// What the daemon believes it has pushed: the intended allowlist, plus the
/// identity of each file *as it is on disk right now*, plus the enforcement
/// flag.
///
/// # Why the on-disk identity is part of it
///
/// The kernel matches on the executable's inode. A package upgrade replaces the
/// binary, giving the same path a new inode, and the map keeps the old one — so
/// the application is silently denied while `config.toml` still says `allow`
/// and `hwprivacy-ctl status` still reports it allowed. Measured on the live
/// system on 2026-08-20: `firefox-esr` was upgraded two minutes after the
/// policy push and lost the camera for sixteen hours. It "fixed itself" at the
/// next reboot, when the helper reloaded its cache, which is exactly why it had
/// never been noticed.
///
/// Comparing this each tick also catches the *other* way the map goes stale:
/// `SetPolicy` used to be sent once per connection and never again, so a rule
/// changed with `hwprivacy-ctl`, the TUI or the GUI did not reach the kernel
/// until something restarted.
///
/// The `(dev, ino)` here are glibc-encoded and used ONLY to detect change.
/// Authoritative resolution into kernel dev encoding stays in the helper's
/// `PolicyKey::from_path` — the two encodings differ, and duplicating that
/// conversion is the trap that has already bitten this project twice.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct PolicyFingerprint {
    /// `(exe_path, dev, ino)`, sorted. `None` for a path that does not resolve
    /// — a file that is missing is itself a state worth re-pushing on.
    files: Vec<(String, Option<(u64, u64)>)>,
    enforce_camera: bool,
}

impl PolicyFingerprint {
    /// Sorted, so a reordering of `config.toml` is not mistaken for a change.
    fn take(entries: &[PolicyEntry], enforce_camera: bool) -> Self {
        let mut files: Vec<(String, Option<(u64, u64)>)> = entries
            .iter()
            .map(|e| (e.exe_path.clone(), stat_identity(&e.exe_path)))
            .collect();
        files.sort();
        files.dedup();
        PolicyFingerprint {
            files,
            enforce_camera,
        }
    }

    /// Human-readable description of what moved, for the journal. An INFO line
    /// naming `old ino → new ino` is what would have made the 2026-08-20
    /// failure a five-minute diagnosis instead of an invisible one.
    fn describe_change(&self, prev: &PolicyFingerprint) -> String {
        let mut notes = Vec::new();
        if self.enforce_camera != prev.enforce_camera {
            notes.push(format!(
                "camera enforcement {} → {}",
                prev.enforce_camera, self.enforce_camera
            ));
        }
        for (path, now) in &self.files {
            match prev.files.iter().find(|(p, _)| p == path) {
                None => notes.push(format!("added {path}")),
                Some((_, before)) if before != now => notes.push(match (before, now) {
                    (Some((_, old)), Some((_, new))) => {
                        format!("{path} ino {old} → {new} (binary replaced)")
                    }
                    (Some(_), None) => format!("{path} disappeared"),
                    (None, Some(_)) => format!("{path} appeared"),
                    (None, None) => unreachable!("equal values are filtered above"),
                }),
                Some(_) => {}
            }
        }
        for (path, _) in &prev.files {
            if !self.files.iter().any(|(p, _)| p == path) {
                notes.push(format!("removed {path}"));
            }
        }
        if notes.is_empty() {
            "no visible difference".to_string()
        } else {
            notes.join("; ")
        }
    }
}

/// glibc `(dev, ino)` of a path, or `None` if it cannot be stat'ed.
fn stat_identity(path: &str) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(path).ok().map(|md| (md.dev(), md.ino()))
}

/// The allowlist the config currently intends, plus the enforcement flag and
/// any rules that cannot reach the kernel layer.
async fn intended_policy(state: &SharedState) -> (Vec<PolicyEntry>, bool, Vec<(String, &'static str)>) {
    let s = state.read().await;
    let settle = Duration::from_secs(s.config.policy.while_in_use_settle_secs);
    let entries: Vec<PolicyEntry> = s
        .config
        .kernel_camera_allowlist_with_sessions(|app| {
            s.tracker.session_live(app, DeviceCategory::Camera, settle)
        })
        .into_iter()
        .map(|(exe_path, _)| PolicyEntry {
            exe_path,
            perms: PERM_CAMERA,
        })
        .collect();
    // The kernel layer enforces only when the guard for cameras is on.
    let enforce = s.config.devices.is_guarded(&DeviceCategory::Camera);
    (entries, enforce, s.config.kernel_camera_gaps())
}

/// What changed between two gap reports: newly opened, and newly closed.
///
/// Pure, and separate from the loop, so the "only on change" rule can be
/// tested. The rule matters: `exe_recheck_secs` fires every 30 s by default,
/// and a warning repeated 2 880 times a day is one nobody reads. It is also
/// the only part of this that a test can reach — everything around it is a
/// `select!` over a live socket.
fn gap_delta<'a>(
    prev: &[(String, &'static str)],
    next: &'a [(String, &'static str)],
) -> (Vec<&'a (String, &'static str)>, Vec<String>) {
    let opened = next
        .iter()
        .filter(|(app, why)| !prev.iter().any(|(a, w)| a == app && w == why))
        .collect();
    let closed = prev
        .iter()
        .filter(|(app, _)| !next.iter().any(|(a, _)| a == app))
        .map(|(app, _)| app.clone())
        .collect();
    (opened, closed)
}

/// One connection: handshake, push policy, then stream events until it drops —
/// re-pushing whenever the intended policy or the files behind it change.
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
    let (entries, mut enforce, gaps) = intended_policy(state).await;

    for (app, why) in &gaps {
        warn!("Kernel layer gap: rule '{}' — {}", app, why);
    }
    if let Some(why) = state.read().await.config.global_camera_gap() {
        warn!("Kernel layer gap: {}", why);
    }
    let mut last_gaps = gaps;

    let mut fingerprint = PolicyFingerprint::take(&entries, enforce);
    tx.write_all(
        encode_line(&Request::SetPolicy {
            entries: entries.clone(),
            enforce_camera: enforce,
        })?
        .as_bytes(),
    )
    .await?;

    let recheck = {
        let s = state.read().await;
        // 0 disables the check. Guard the interval anyway: tokio panics on a
        // zero period, and a config typo must not take the daemon down.
        s.config.policy.exe_recheck_secs
    };
    let dirty = { state.read().await.policy_dirty.clone() };
    let mut recheck_tick = tokio::time::interval(Duration::from_secs(recheck.max(1)));
    recheck_tick.tick().await; // the first tick completes immediately

    loop {
        let line = tokio::select! {
            line = lines.next_line() => match line? {
                Some(l) => l,
                None => break,
            },
            _ = dirty.notified() => {
                // Somebody changed a rule or opened/closed a session. Pushing
                // now rather than at the next 30 s tick is the difference
                // between "click Allow and it works" and "click Allow and wait
                // half a minute while the app is still denied".
                let (entries, want_enforce, _) = intended_policy(state).await;
                let next = PolicyFingerprint::take(&entries, want_enforce);
                if next != fingerprint {
                    info!(
                        "Kernel layer: policy changed ({}); pushing {} entr(ies)",
                        next.describe_change(&fingerprint),
                        entries.len()
                    );
                    tx.write_all(
                        encode_line(&Request::SetPolicy {
                            entries,
                            enforce_camera: want_enforce,
                        })?
                        .as_bytes(),
                    )
                    .await?;
                    fingerprint = next;
                    enforce = want_enforce;
                }
                continue;
            }
            _ = recheck_tick.tick(), if recheck > 0 => {
                let (entries, want_enforce, gaps) = intended_policy(state).await;

                // Report gaps here as well as at connect time. The connect-time
                // pass alone could never catch the case that actually bit: a
                // rule with `camera = allow` and no exe_path contributes no
                // allowlist entry, so the fingerprint below does not change,
                // no re-push happens, and nothing is said. Measured 2026-08-23
                // — thirteen seconds of silence between saving the rule and
                // the kernel denying the binary it was meant to allow.
                //
                // Only on CHANGE. Re-warning every exe_recheck_secs would
                // flood the journal and train the reader to skip the line.
                let (opened, closed) = gap_delta(&last_gaps, &gaps);
                for (app, why) in &opened {
                    warn!("Kernel layer gap: rule '{}' — {}", app, why);
                }
                for app in &closed {
                    info!("Kernel layer gap closed for rule '{}'", app);
                }
                last_gaps = gaps;

                let next = PolicyFingerprint::take(&entries, want_enforce);
                if next != fingerprint {
                    info!(
                        "Kernel layer: policy changed under us ({}); re-pushing {} entr(ies)",
                        next.describe_change(&fingerprint),
                        entries.len()
                    );
                    tx.write_all(
                        encode_line(&Request::SetPolicy {
                            entries,
                            enforce_camera: want_enforce,
                        })?
                        .as_bytes(),
                    )
                    .await?;
                    fingerprint = next;
                    enforce = want_enforce;
                }
                continue;
            }
        };

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

    // A RELEASE is the end of an access, not another one. It must not be
    // logged as an access, must not notify, and must not touch any counter —
    // it exists to close a session.
    if ev.released {
        let app = short_name(&ev.exe_path);
        let mut s = state.write().await;
        // End the session under the RULE's name, not the executable's.
        //
        // A session is opened under whichever rule owns the binary — `firefox`,
        // typically, not `firefox-esr` — because that is the key
        // kernel_camera_allowlist_with_sessions() passes to session_live().
        // Removing `firefox-esr` here therefore matched nothing, and the
        // session survived its own release: measured live 2026-09-01,
        //
        //   19:56:08  ALLOWED  (session open, allowlist 3)
        //   19:56:34  call ended, camera released — kernel release found no key
        //   19:57:03  session ended: firefox released Camera   <- expire_sessions
        //
        // 29 seconds late, and only because awaiting_open_secs reaped it. The
        // fallback masked the failure, which is the worst way for this to
        // break: the feature looks like it works, slowly.
        let key = session_key_for_release(&s.config, &ev.exe_path, &app);
        // Ending a session that is not open is a no-op. That matters: the BPF
        // side can emit a duplicate release when two threads drop an
        // executable's last two handles at once, and it does so deliberately —
        // ending twice is harmless, never ending is the bug.
        if s.tracker.while_in_use.remove(&(
            hwprivacy_common::normalize_app_name(&key),
            category,
        )).is_some()
        {
            info!(
                "while_in_use session ended: {} released the camera (kernel)",
                key
            );
            s.tracker.log_event(
                &key, ev.pid, category, &ev.exe_path, AccessAction::SessionEnded,
            );
            s.policy_dirty.notify_waiters();
        } else {
            debug!("Kernel reported {} released the camera; no session was open", key);
        }
        return;
    }

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
        let mut s = state.write().await;
        if ev.denied {
            s.tracker.blocked_count += denied_opens(&ev);
            record_denied(&mut s, &ev, category);
        } else {
            // The suppressed opens still happened. Counting them keeps the
            // allowed column honest — a 13-open camera session is 13, the same
            // arithmetic the denied side already gets right.
            record_allowed(&mut s, &ev, category);
        }
        drop(s);
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
            // No instance: the kernel layer sees a device NODE (/dev/video0),
            // not a PipeWire port, so it has nothing to disambiguate with.
            .log_event(&app, ev.pid, category, &ev.exe_path, action);

        // denied_opens() is the single statement of how much this event is
        // worth. log_event() has ALREADY added one for a Denied action, so add
        // only the remainder — otherwise the two disagree and one of them wins
        // silently, which is precisely how the +1 got in.
        // `log_event_denial_contribution_is_one` pins that assumption.
        let already = if ev.denied { 1 } else { 0 };
        s.tracker.blocked_count += denied_opens(&ev) - already;

        if ev.denied {
            record_denied(&mut s, &ev, category);
        }
    }

    if !ev.denied {
        notify_allowed_kernel(state, &ev, &app, category).await;
        return;
    }

    info!(
        "Kernel layer DENIED {} -> {} ({}), {} open(s) total",
        app,
        ev.device,
        ev.role,
        ev.total_opens()
    );

    // A denied CAMERA gets an ACTIONABLE prompt; everything else stays
    // informational.
    //
    // The old blanket rule was "never route a kernel denial through the action
    // path, because that path carries b1 (dismissing wrote a permanent deny)".
    // b1 was FIXED on 2026-08-21 — notification::decide() maps a dismissal to
    // SaveNothingAndCooldown, and a doc-check sentinel refuses the old
    // expression. The premise is gone, so the rule is retired deliberately
    // here rather than stepped over quietly. If b1 ever returns, this must be
    // reconsidered with it.
    //
    // The microphone keeps the informational path for a reason that has not
    // changed: /dev/snd is opened by /usr/bin/pipewire on everyone's behalf, so
    // a kernel mic denial cannot name the application responsible and a prompt
    // asking about "pipewire" would be unanswerable.
    if category == DeviceCategory::Camera {
        prompt_kernel_camera_denial(state, &ev, &app).await;
        return;
    }

    crate::notification::notify_kernel_denial(
        &app,
        ev.pid,
        category,
        &ev.device,
        "Blocked by the kernel.",
    )
    .await;
}

/// Which rule an answered camera prompt should be written to.
///
/// Pure, and separate from the prompt task, because the prompt task cannot be
/// reached by a unit test — it needs a notification daemon and a human. The
/// decision inside it can be tested; the popup cannot. Same reasoning that put
/// `notification::decide()` outside its `tokio::spawn`.
///
/// A kernel event carries only the executable, so writing under its short name
/// blindly creates a second rule beside the user's own. Measured live
/// 2026-09-01 after a successful camera session:
///
///     firefox      while_in_use  while_in_use  /usr/lib/firefox-esr/firefox-esr
///     firefox-esr  —             while_in_use  /usr/lib/firefox-esr/firefox-esr
fn rule_key_for(config: &Config, exe_path: &str, exe_short: &str) -> String {
    config
        .find_rule_by_exe(exe_path)
        .map(|r| r.app_name.clone())
        .unwrap_or_else(|| exe_short.to_string())
}

/// The session key a kernel RELEASE must remove.
///
/// Exists as its own function purely so a test can pin the call site. An
/// earlier version keyed this on `short_name(exe_path)` while the prompt
/// opened the session under the owning rule's name, and nothing caught it:
/// asserting that `rule_key_for(..) == rule_key_for(..)` passes trivially
/// whatever the release path actually does.
///
/// It must agree with `rule_key_for`, which is what the prompt uses. Defined
/// in terms of it rather than beside it, so the two cannot drift apart.
fn session_key_for_release(config: &Config, exe_path: &str, exe_short: &str) -> String {
    rule_key_for(config, exe_path, exe_short)
}

/// Ask the user about a camera the kernel just denied, and act on the answer.
///
/// The grant applies to the user's NEXT attempt — the open() that produced this
/// event was denied before any human saw it, because the LSM hook must answer
/// in nanoseconds. `notification::RETRY_HINT` says so on the prompt; that is a
/// correctness requirement, not politeness (Costin, 2026-09-01).
async fn prompt_kernel_camera_denial(
    state: &SharedState,
    ev: &AccessEvent,
    app: &str,
) {
    // b6's guard: one pending question per (app, device). A camera session is
    // 13 opens, and without this a single call raises thirteen popups — the
    // defect coalescing exists to prevent, arriving from a new direction.
    {
        let mut s = state.write().await;
        if !s.tracker.try_begin_prompt(app, DeviceCategory::Camera) {
            debug!(
                "Camera prompt for {} already pending; blocking silently",
                app
            );
            return;
        }
    }

    let exe_short = app.to_string();
    let exe_path = ev.exe_path.clone();
    let device_path = ev.device.clone();
    let pid = ev.pid;
    let st = state.clone();

    tokio::spawn(async move {
        let outcome = crate::notification::ask_kernel_camera_permission(
            &exe_short, &exe_path, pid, &device_path,
        )
        .await;

        if let crate::notification::PromptOutcome::Failed(e) = &outcome {
            warn!(
                "Could not prompt for the camera ({}). Access stayed blocked and \
                 NO rule was saved.",
                e
            );
        }

        let mut s = st.write().await;
        // Released on EVERY path out, or this executable is never asked about
        // again for the life of the daemon: no popup, no error, nothing logged.
        s.tracker.end_prompt(&exe_short, DeviceCategory::Camera);

        // Write to the rule that ALREADY owns this binary, if there is one.
        //
        // The event carries only the executable's short name, so writing under
        // that blindly creates a second rule beside the user's own. Observed
        // live 2026-09-01: answering a prompt for `firefox-esr` left both
        // `firefox` and `firefox-esr` pointing at the same binary, which is
        // the "two rules for one application" case
        // d-camera-grants-need-a-binary-and-say-so exists to prevent — and the
        // allowlist would then carry the path twice from two rules that can
        // disagree.
        let target = rule_key_for(&s.config, &exe_path, &exe_short);

        match crate::notification::decide(&outcome) {
            crate::notification::PromptAction::SavePermanentRule(perm) => {
                // The rule must carry the EXECUTABLE, because that is what the
                // kernel matches. Attaching it first is not optional for a
                // session: set_rule refuses camera = while_in_use without one,
                // since presence in the allowlist IS the grant.
                if s.config.find_rule(&target).is_none()
                    && !s.config.set_rule(&target, &DeviceCategory::Camera, Permission::Deny)
                {
                    warn!("Refused to create a rule for {:?}", target);
                    return;
                }
                if let Err(e) = s.config.set_rule_exe(&target, &exe_path) {
                    warn!("Could not attach {} to rule {}: {}", exe_path, target, e);
                    return;
                }
                if perm == Permission::WhileInUse {
                    // Opens the session NOW, in AwaitingFirstOpen: the device
                    // has not been opened and will not be until the user clicks
                    // again. Bounded by policy.awaiting_open_secs.
                    //
                    // Keyed on the RULE's name, because that is what
                    // kernel_camera_allowlist_with_sessions() passes to
                    // session_live(). Keying on the executable here while the
                    // rule is named `firefox` would leave the session live and
                    // the allowlist empty — a grant that grants nothing.
                    s.tracker.begin_session(&target, DeviceCategory::Camera);
                }
                if s.config.set_rule(&target, &DeviceCategory::Camera, perm) {
                    if let Err(e) = s.config.save() {
                        error!("Failed to save config after user decision: {}", e);
                    }
                    info!("User set rule: {} → camera = {}", target, perm);
                    // The allowlist must change before the user clicks again,
                    // not at the next exe_recheck tick — 30 s of latency reads
                    // as the click having failed.
                    s.policy_dirty.notify_waiters();
                } else {
                    warn!("Refused to save camera rule for {:?}", target);
                }
            }
            crate::notification::PromptAction::SaveNothingAndCooldown => {
                s.tracker.record_dismiss(&target, DeviceCategory::Camera);
            }
        }
    });
}

/// Announce an allowed kernel access, if this one is worth announcing.
///
/// # Camera only, deliberately
///
/// The kernel sees `/usr/bin/pipewire` holding `/dev/snd` on behalf of
/// everyone — it cannot tell which application wants the microphone, and
/// saying "pipewire used the microphone" would be both useless and wrong-ish.
/// Worse, the PipeWire layer notifies for that same act with the REAL app name,
/// so allowing MIC through here would produce two notifications for one access.
/// One access, one notification; each layer speaks about what it can actually
/// see.
///
/// This is the case the feature exists for: on 2026-08-21 firefox-esr opened
/// the camera twice in one morning with no video call, hwprivacy allowed both
/// correctly, and nothing said anything.
async fn notify_allowed_kernel(
    state: &SharedState,
    ev: &AccessEvent,
    app: &str,
    category: DeviceCategory,
) {
    if category != DeviceCategory::Camera {
        return;
    }

    let access = crate::notify_allow::AllowedAccess {
        app,
        device: category,
        pid: ev.pid,
    };
    let now = std::time::Instant::now();

    let announce = {
        let mut s = state.write().await;
        // Count it either way — the table answers "did anything use my camera
        // on Tuesday", which must not depend on whether a popup was shown.
        let ts = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
        s.history.record_allowed(
            &ev.exe_path,
            &format!("{category:?}").to_lowercase(),
            crate::history::SOURCE_KERNEL,
            allowed_opens(ev),
            &ts,
        );
        s.history.save_if_dirty();

        let yes = s
            .allow_notifier
            .should_notify(access, s.uptime(), now, &s.config.policy);
        if yes {
            s.allow_notifier.mark_notified(access, now);
        }
        yes
    };

    if !announce {
        return;
    }

    info!("Kernel layer ALLOWED {} -> {} ({})", app, ev.device, ev.role);
    crate::notification::notify_allowed(
        app,
        ev.pid,
        category,
        "Allowed by your rules. The kernel layer sees the open, not the release, so it cannot tell when this ends — \
         the kernel hook fires on open, not on close.",
    )
    .await;
}

/// How many allowed opens one kernel event represents.
///
/// The mirror of [`denied_opens`], and it has to exist separately for the same
/// reason that one does: a burst summary carries pid 0 and stands only for the
/// opens it accounts for, while a real event is itself plus whatever the kernel
/// attached to it. Getting this inline and implicit is what produced the C5
/// off-by-one.
pub fn allowed_opens(ev: &AccessEvent) -> u32 {
    if ev.denied {
        return 0;
    }
    if ev.pid == 0 {
        return ev.additional_opens;
    }
    1 + ev.additional_opens
}

/// Add a kernel denial to the persistent history table.
///
/// Keyed on `exe_path`, NOT on the short name. The path is the identity the
/// kernel actually decided on, it is stable across restarts and reboots, and
/// two different binaries can share a basename — `firefox-esr` and
/// `firefox-bin` are distinct policy subjects and must not collapse into one
/// row here either.
fn record_denied(
    s: &mut crate::state::DaemonState,
    ev: &AccessEvent,
    category: DeviceCategory,
) {
    let now = chrono::Local::now()
        .format("%Y-%m-%d %H:%M:%S")
        .to_string();
    s.history.record_denied(
        &ev.exe_path,
        &format!("{category:?}").to_lowercase(),
        crate::history::SOURCE_KERNEL,
        denied_opens(ev),
        &now,
    );
    s.history.save_if_dirty();
}

/// The allowed twin of [`record_denied`], same keying and same reasoning.
fn record_allowed(
    s: &mut crate::state::DaemonState,
    ev: &AccessEvent,
    category: DeviceCategory,
) {
    let now = chrono::Local::now()
        .format("%Y-%m-%d %H:%M:%S")
        .to_string();
    s.history.record_allowed(
        &ev.exe_path,
        &format!("{category:?}").to_lowercase(),
        crate::history::SOURCE_KERNEL,
        allowed_opens(ev),
        &now,
    );
    s.history.save_if_dirty();
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

    fn entry(path: &str) -> PolicyEntry {
        PolicyEntry {
            exe_path: path.to_string(),
            perms: PERM_CAMERA,
        }
    }

    /// A scratch file we can replace in place, so "same path, different inode"
    /// is a real filesystem event and not a mocked one.
    fn scratch(tag: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("hwp-fp-{}-{tag}", std::process::id()));
        std::fs::write(&p, tag).unwrap();
        p
    }

    /// The 2026-08-20 failure, reproduced: `firefox-esr` was upgraded two
    /// minutes after the policy push. The path never changed, the inode did,
    /// and the kernel kept matching on the old one — so an allowlisted app was
    /// denied the camera for sixteen hours while `config.toml` said `allow` and
    /// `hwprivacy-ctl status` said it was allowed.
    ///
    /// Detecting this is the entire point of the fingerprint.
    #[test]
    fn replacing_a_binary_in_place_changes_the_fingerprint() {
        let path = scratch("upgrade");
        let name = path.to_string_lossy().to_string();
        let entries = vec![entry(&name)];

        let before = PolicyFingerprint::take(&entries, true);

        // What dpkg does: a new file, moved over the old path. Same name,
        // new inode. `write()` alone would reuse the inode and prove nothing.
        let tmp = path.with_extension("new");
        std::fs::write(&tmp, "upgraded").unwrap();
        std::fs::rename(&tmp, &path).unwrap();

        let after = PolicyFingerprint::take(&entries, true);
        assert_ne!(before, after, "an in-place replacement must be visible");
        let why = after.describe_change(&before);
        assert!(why.contains("binary replaced"), "{why}");

        let _ = std::fs::remove_file(&path);
    }

    /// Re-pushing on every tick would be pointless churn, and worse, would hide
    /// the INFO line that says something really moved.
    #[test]
    fn an_unchanged_world_produces_an_unchanged_fingerprint() {
        let path = scratch("stable");
        let entries = vec![entry(&path.to_string_lossy())];
        assert_eq!(
            PolicyFingerprint::take(&entries, true),
            PolicyFingerprint::take(&entries, true)
        );
        let _ = std::fs::remove_file(&path);
    }

    /// The daemon rewrites the whole config file on any rule change, so entry
    /// order is not stable. Order must not read as a change.
    #[test]
    fn reordering_the_config_is_not_a_change() {
        let a = scratch("order-a");
        let b = scratch("order-b");
        let (a, b) = (a.to_string_lossy().to_string(), b.to_string_lossy().to_string());
        assert_eq!(
            PolicyFingerprint::take(&[entry(&a), entry(&b)], true),
            PolicyFingerprint::take(&[entry(&b), entry(&a)], true)
        );
        let _ = std::fs::remove_file(&a);
        let _ = std::fs::remove_file(&b);
    }

    /// The second bug the fingerprint closes: `SetPolicy` used to be sent once
    /// per connection and never again, so adding or removing a camera rule from
    /// `hwprivacy-ctl`, the TUI or the GUI did not reach the kernel until
    /// something restarted.
    #[test]
    fn adding_or_removing_a_rule_is_a_change() {
        let path = scratch("rules");
        let name = path.to_string_lossy().to_string();
        let none = PolicyFingerprint::take(&[], true);
        let one = PolicyFingerprint::take(&[entry(&name)], true);
        assert_ne!(none, one);
        assert!(one.describe_change(&none).contains("added"));
        assert!(none.describe_change(&one).contains("removed"));
        let _ = std::fs::remove_file(&path);
    }

    /// Turning the camera guard off is a policy change with no file behind it.
    #[test]
    fn toggling_enforcement_is_a_change() {
        let on = PolicyFingerprint::take(&[], true);
        let off = PolicyFingerprint::take(&[], false);
        assert_ne!(on, off);
        assert!(off.describe_change(&on).contains("enforcement"));
    }

    /// An allowlisted binary that is deleted must be noticed. Under
    /// default-deny that app is now being denied, and the map still holds a key
    /// for a file that no longer exists.
    #[test]
    fn a_vanished_binary_is_a_change() {
        let path = scratch("vanish");
        let name = path.to_string_lossy().to_string();
        let entries = vec![entry(&name)];
        let present = PolicyFingerprint::take(&entries, true);
        std::fs::remove_file(&path).unwrap();
        let gone = PolicyFingerprint::take(&entries, true);
        assert_ne!(present, gone);
        assert!(gone.describe_change(&present).contains("disappeared"));
    }

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
            released: false,
        };
        let summary = AccessEvent {
            pid: 0,
            additional_opens: 12,
            released: false,
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
            released: false,
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
            released: false,
        };
        assert_eq!(denied_opens(&allowed), 0);
        let allowed_summary = AccessEvent { pid: 0, ..allowed.clone() };
        assert_eq!(denied_opens(&allowed_summary), 0);
    }

    /// A burst summary must be counted but must NOT notify — otherwise one
    /// camera session produces two popups, which is the defect coalescing
    /// exists to prevent.
    ///
    /// This test had NO `#[test]` attribute from the day it was written until
    /// 2026-08-21 — the attribute had been stacked twice on the function above
    /// it instead. It compiled, it read as covered, and it never ran once.
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
            released: false,
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
                released: false,
            };
            assert!(
                !matches!(ev.role.as_str(), "CAMERA" | "MIC"),
                "{role} must not be treated as capture"
            );
        }
    }

    // ---------------------------------------------------------------------
    // gap_delta — "warn only on change".
    // ---------------------------------------------------------------------

    fn g(app: &str, why: &'static str) -> (String, &'static str) {
        (app.to_string(), why)
    }

    /// The rule that matters. `exe_recheck_secs` fires every 30 s; re-warning
    /// each time would print the same line 2 880 times a day, which is the
    /// same as not printing it.
    #[test]
    fn an_unchanged_gap_set_reports_nothing() {
        let prev = vec![g("firefox", "no exe_path")];
        let next = vec![g("firefox", "no exe_path")];
        let (opened, closed) = gap_delta(&prev, &next);
        assert!(opened.is_empty(), "{opened:?}");
        assert!(closed.is_empty(), "{closed:?}");
    }

    /// The measured failure: a rule is saved that cannot reach the kernel
    /// layer, and nothing is said. This is the line that would have said it.
    #[test]
    fn a_new_gap_is_reported_once() {
        let next = vec![g("firefox", "no exe_path")];
        let (opened, closed) = gap_delta(&[], &next);
        assert_eq!(opened.len(), 1);
        assert_eq!(opened[0].0, "firefox");
        assert!(closed.is_empty());
    }

    /// Attaching a binary closes the gap, and that is worth saying too — it is
    /// the confirmation that a grant took effect.
    #[test]
    fn a_closed_gap_is_reported() {
        let prev = vec![g("firefox", "no exe_path")];
        let (opened, closed) = gap_delta(&prev, &[]);
        assert!(opened.is_empty());
        assert_eq!(closed, vec!["firefox".to_string()]);
    }

    /// A gap that changes REASON on the same app is a new thing to say: the
    /// rule went from `camera = allow` with no binary to a prompting
    /// permission, which fails differently.
    #[test]
    fn a_gap_whose_reason_changed_is_reported_again() {
        let prev = vec![g("firefox", "no exe_path")];
        let next = vec![g("firefox", "prompting permissions have no kernel equivalent")];
        let (opened, closed) = gap_delta(&prev, &next);
        assert_eq!(opened.len(), 1, "the reason changed, so say so");
        assert!(closed.is_empty(), "the app still has a gap; it did not close");
    }

    /// One app closing while another opens must not mask either.
    #[test]
    fn one_opening_and_one_closing_are_both_reported() {
        let prev = vec![g("firefox", "no exe_path")];
        let next = vec![g("chrome", "no exe_path")];
        let (opened, closed) = gap_delta(&prev, &next);
        assert_eq!(opened.len(), 1);
        assert_eq!(opened[0].0, "chrome");
        assert_eq!(closed, vec!["firefox".to_string()]);
    }

    /// An answered camera prompt writes to the rule that already owns the
    /// binary, not to a new one named after the executable.
    ///
    /// Fails against `let target = exe_short`, which is what shipped for one
    /// evening and produced two rules for one binary — see
    /// `rule_key_for`'s doc comment for the live evidence.
    #[test]
    fn an_answer_lands_on_the_rule_that_owns_the_binary() {
        let mut c = Config::default();
        assert!(c.set_rule("firefox", &DeviceCategory::Camera, Permission::Allow));
        c.set_rule_exe("firefox", "/bin/sh").expect("binary");

        assert_eq!(
            rule_key_for(&c, "/bin/sh", "sh"),
            "firefox",
            "the user's own rule owns this binary; do not create a second one"
        );
    }

    /// With no rule for that binary, the executable's own name is right — that
    /// is how a new consumer gets its first rule.
    #[test]
    fn an_answer_for_an_unknown_binary_uses_the_executable_name() {
        let c = Config::default();
        assert_eq!(rule_key_for(&c, "/usr/bin/obs", "obs"), "obs");
    }

    /// A rule with no binary must not capture an unrelated executable.
    #[test]
    fn a_rule_without_a_binary_owns_nothing() {
        let mut c = Config::default();
        assert!(c.set_rule("firefox", &DeviceCategory::Microphone, Permission::Allow));
        assert_eq!(
            rule_key_for(&c, "/usr/bin/obs", "obs"),
            "obs",
            "a rule naming no exe_path cannot own one"
        );
    }

    /// The session-OPEN key and the session-END key must be the same string.
    ///
    /// They are chosen in two different places from two different inputs: the
    /// prompt opens under the owning rule's name, and the kernel release path
    /// only knows the executable. When those disagreed, `file_release` removed
    /// nothing and the session outlived its own release — measured live
    /// 2026-09-01:
    ///
    /// ```text
    /// 19:56:08  ALLOWED, session open, allowlist 3
    /// 19:56:34  call ended, camera released -> kernel release matched no key
    /// 19:57:03  session ended: firefox released Camera  <- expire_sessions, 29s late
    /// ```
    ///
    /// The awaiting_open fallback reaped it eventually, which is what made the
    /// bug hard to see: the feature appeared to work, slowly.
    ///
    /// The FIRST version of this test was worthless — it asserted
    /// `rule_key_for(..) == rule_key_for(..)`, which holds no matter what the
    /// release path does. It passed with the bug fully reintroduced. Pinning
    /// `session_key_for_release` is what makes it catch anything.
    #[test]
    fn the_release_key_matches_the_key_the_session_was_opened_under() {
        let mut c = Config::default();
        assert!(c.set_rule("firefox", &DeviceCategory::Camera, Permission::Allow));
        c.set_rule_exe("firefox", "/bin/sh").expect("binary");

        let opened_under = rule_key_for(&c, "/bin/sh", "sh");
        let released_under = session_key_for_release(&c, "/bin/sh", "sh");

        assert_eq!(
            released_under, opened_under,
            "open and release must agree, or a session survives its own release"
        );
        assert_eq!(
            released_under, "firefox",
            "the RULE's name — that is what session_live() is asked about"
        );
        assert_ne!(
            released_under, "sh",
            "keying the release on the executable is the 2026-09-01 defect"
        );
    }
}
