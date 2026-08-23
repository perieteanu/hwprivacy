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
    let mut recheck_tick = tokio::time::interval(Duration::from_secs(recheck.max(1)));
    recheck_tick.tick().await; // the first tick completes immediately

    loop {
        let line = tokio::select! {
            line = lines.next_line() => match line? {
                Some(l) => l,
                None => break,
            },
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
}
