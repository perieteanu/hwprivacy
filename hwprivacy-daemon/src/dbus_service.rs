use crate::state::DaemonState;
use hwprivacy_common::{DeviceCategory, Permission};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::info;
use zbus::object_server::SignalContext;

pub type SharedState = Arc<RwLock<DaemonState>>;

pub struct HwPrivacyService {
    pub state: SharedState,
}

#[zbus::interface(name = "org.hwprivacy.Daemon")]
impl HwPrivacyService {
    async fn get_devices(&self) -> Vec<(String, String, String, bool)> {
        let state = self.state.read().await;
        state
            .devices
            .iter()
            .map(|d| {
                (
                    d.category.to_string(),
                    d.node_name.clone(),
                    d.description.clone(),
                    d.guarded,
                )
            })
            .collect()
    }

    /// One row per rule: `(app, mic, camera, monitor, exe_path, gap_note)`.
    ///
    /// An unset category comes back as `""`, NOT as "deny" — the frontends
    /// render it as "follows default_action". Flattening the three categories
    /// into three rows, as this used to, made one rule look like three and
    /// left nowhere to report `exe_path` or the kernel-layer gap.
    async fn get_rules(&self) -> Vec<(String, String, String, String, String, String)> {
        let state = self.state.read().await;
        let gaps = state.config.kernel_camera_gaps();
        state
            .config
            .rules
            .iter()
            .map(|rule| {
                let perm = |cat| {
                    rule.get_permission(cat)
                        .map(|p| p.to_string())
                        .unwrap_or_default()
                };
                let note = gaps
                    .iter()
                    .find(|(app, _)| app == &rule.app_name)
                    .map(|(_, why)| why.to_string())
                    .unwrap_or_default();
                (
                    rule.app_name.clone(),
                    perm(&DeviceCategory::Microphone),
                    perm(&DeviceCategory::Camera),
                    perm(&DeviceCategory::Monitor),
                    rule.exe_path.clone().unwrap_or_default(),
                    note,
                )
            })
            .collect()
    }

    async fn set_rule(
        &self,
        #[zbus(signal_context)] ctx: SignalContext<'_>,
        app_name: &str,
        device: &str,
        permission: &str,
    ) -> bool {
        let category: DeviceCategory = match device.parse() {
            Ok(c) => c,
            Err(_) => return false,
        };
        let perm: Permission = match permission.parse() {
            Ok(p) => p,
            Err(_) => return false,
        };

        let mut state = self.state.write().await;

        // Refuse names that could never match anything rather than writing a
        // rule that silently does nothing. Three such rules were sitting in the
        // live config — pasted notification labels ending in "(pid:2332)", and
        // one empty string (blocker b4).
        if !state.config.set_rule(app_name, &category, perm) {
            if category == DeviceCategory::Camera && perm == Permission::WhileInUse {
                tracing::warn!(
                    "Rejected '{}' camera = while_in_use: the kernel layer is attached \
                     to lsm/file_open only, so it never observes the camera being \
                     released and could not end the session. Use allow or deny.",
                    app_name
                );
            } else {
                tracing::warn!(
                    "Rejected rule for {:?}: not a usable rule key. Use the bare app name, \
                     e.g. 'firefox' — not a pasted notification label.",
                    app_name
                );
            }
            return false;
        }

        if let Err(e) = state.config.save() {
            tracing::error!("Failed to save config: {}", e);
        }

        let _ = Self::rule_changed(&ctx, app_name, device, permission).await;
        info!("Rule set: {} → {} = {}", app_name, device, permission);

        // Say so NOW if the rule just written cannot reach the layer it names.
        //
        // The measured failure this closes (2026-08-23): `camera = allow` was
        // saved for firefox, and thirteen seconds later the kernel denied
        // firefox-esr, with nothing in between. The warning existed but only
        // ran at connect time, and the recheck loop could not fire it either —
        // a rule with no exe_path contributes no allowlist entry, so the policy
        // fingerprint never changed.
        let gap = state
            .config
            .kernel_camera_gaps()
            .into_iter()
            .find(|(app, _)| hwprivacy_common::config::normalize_app_name(app)
                == hwprivacy_common::config::normalize_app_name(app_name));
        drop(state);

        if let Some((app, why)) = gap {
            // Logged as well as shown. A popup is invisible to every automated
            // check, and this project has already scored a verification wrong
            // twice because it depended on a human seeing one (C4).
            tracing::warn!("Kernel layer gap: rule '{}' — {}", app, why);
            info!("Announced kernel-gap warning for rule '{}'", app);
            // Informational, no buttons, via the kernel-denial path. NEVER the
            // action path: that one carries b1, and a new event source wired
            // into it inherits that bug on day one.
            crate::notification::notify_kernel_gap(&app, why).await;
        }

        true
    }

    /// Attach the kernel-layer executable to an app's rule, or clear it with
    /// `""`. Returns `(ok, message)`.
    ///
    /// Before this existed there was no way to set `exe_path` from any
    /// frontend, and `kernel_camera_allowlist()` keys on nothing else — so a
    /// camera grant made through `hwprivacy-ctl`, the TUI or the GUI could
    /// never take effect, whatever app name you typed.
    async fn set_rule_exe(
        &self,
        #[zbus(signal_context)] ctx: SignalContext<'_>,
        app_name: &str,
        exe_path: &str,
    ) -> (bool, String) {
        let mut state = self.state.write().await;

        if let Err(why) = state.config.set_rule_exe(app_name, exe_path) {
            tracing::warn!("Refused executable for '{}': {}", app_name, why);
            return (false, why);
        }

        if let Err(e) = state.config.save() {
            tracing::error!("Failed to save config: {}", e);
            return (false, format!("saved nothing: {e}"));
        }
        drop(state);

        let _ = Self::rule_changed(&ctx, app_name, "exe_path", exe_path).await;
        let msg = if exe_path.is_empty() {
            info!("Rule executable cleared for '{}'", app_name);
            format!("cleared the executable for '{app_name}'")
        } else {
            info!("Rule executable set: {} → {}", app_name, exe_path);
            // The push itself is the recheck loop's job: adding a path changes
            // the policy fingerprint, which is what triggers a re-push. Naming
            // the delay beats letting the user wonder whether it worked.
            format!(
                "'{app_name}' now names {exe_path}; the kernel layer picks it \
                 up within exe_recheck_secs"
            )
        };
        (true, msg)
    }

    /// Grant a camera at both layers atomically.
    ///
    /// Order matters and so does the single lock: `set_rule` alone leaves the
    /// rule in the gap state that raises a warning, and doing this as two
    /// D-Bus calls made the successful path announce a failure it was one
    /// call away from fixing.
    async fn allow_camera(
        &self,
        #[zbus(signal_context)] ctx: SignalContext<'_>,
        app_name: &str,
        exe_path: &str,
    ) -> (bool, String) {
        let mut state = self.state.write().await;

        if !state
            .config
            .set_rule(app_name, &DeviceCategory::Camera, Permission::Allow)
        {
            return (
                false,
                format!("'{app_name}' is not a usable rule name"),
            );
        }

        // If the binary is refused, the camera rule must not be left behind:
        // it would be a rule that reads `allow` and denies, which is the
        // state this whole command exists to prevent someone reaching.
        if let Err(why) = state.config.set_rule_exe(app_name, exe_path) {
            state.config.remove_rule(app_name);
            tracing::warn!("Refused camera grant for '{}': {}", app_name, why);
            return (false, why);
        }

        if let Err(e) = state.config.save() {
            tracing::error!("Failed to save config: {}", e);
            return (false, format!("saved nothing: {e}"));
        }
        drop(state);

        let _ = Self::rule_changed(&ctx, app_name, "camera", "allow").await;
        info!(
            "Camera granted: {} → allow, binary {}",
            app_name, exe_path
        );
        (
            true,
            format!("{app_name} → camera = allow, binary {exe_path}"),
        )
    }

    async fn remove_rule(
        &self,
        #[zbus(signal_context)] ctx: SignalContext<'_>,
        app_name: &str,
    ) -> bool {
        let mut state = self.state.write().await;
        let removed = state.config.remove_rule(app_name);
        if removed {
            if let Err(e) = state.config.save() {
                tracing::error!("Failed to save config: {}", e);
            }
            let _ = Self::rule_changed(&ctx, app_name, "*", "removed").await;
            info!("Rules removed for: {}", app_name);
        }
        removed
    }

    async fn get_active_streams(&self) -> Vec<(String, u32, String, String, String, String, bool)> {
        let state = self.state.read().await;
        state
            .tracker
            .active
            .values()
            .map(|c| {
                (
                    c.stream.app_name.clone(),
                    c.stream.pid,
                    c.device_category.to_string(),
                    c.stream.node_name.clone(),
                    c.stream.media_name.clone(),
                    c.permission.to_string(),
                    c.active,
                )
            })
            .collect()
    }

    async fn get_status(&self) -> (bool, u32, u32, u32, u32) {
        let state = self.state.read().await;
        (
            true, // running
            state.devices.iter().filter(|d| d.guarded).count() as u32,
            state.config.rules.len() as u32,
            state.tracker.blocked_count,
            state.tracker.active_count(),
        )
    }

    /// Kernel (eBPF LSM) layer status: (connected, enforcing_camera,
    /// allowed_executables, unresolved_entries, last_error).
    ///
    /// A NEW method rather than a change to GetStatus, whose signature three
    /// frontends already depend on. Additive keeps ctl/tui/gui working
    /// untouched — which was the whole point of routing kernel events through
    /// the existing StreamTracker.
    async fn get_kernel_status(&self) -> (bool, bool, u32, u32, String) {
        let state = self.state.read().await;
        let k = &state.kernel;
        (
            k.connected,
            k.enforcing_camera,
            k.allowed_exes,
            k.unresolved.len() as u32,
            k.last_error.clone().unwrap_or_default(),
        )
    }

    /// Persistent denial counters: (identity, device, source, denied,
    /// first_seen, last_seen), most persistent first.
    ///
    /// Unlike GetEvents, which reads a 500-entry in-memory ring buffer that
    /// dies with the daemon, this survives restarts — it is the answer to
    /// "who has been trying, over days".
    ///
    /// Additive, like GetKernelStatus: GetEvents keeps its signature so the
    /// three frontends stay working untouched.
    async fn get_history(&self) -> Vec<(String, String, String, u32, u32, String, String)> {
        let state = self.state.read().await;
        state
            .history
            .sorted()
            .into_iter()
            .map(|o| {
                (
                    o.identity,
                    o.device,
                    o.source,
                    o.denied,
                    o.allowed,
                    o.first_seen,
                    o.last_seen,
                )
            })
            .collect()
    }

    /// List importable presets: (name, description, entry_count, source_path).
    async fn get_presets(&self) -> Vec<(String, String, u32, String)> {
        let dirs = hwprivacy_common::preset::preset_dirs();
        hwprivacy_common::preset::discover(&dirs)
            .into_iter()
            .filter_map(|(name, path)| {
                let p = hwprivacy_common::preset::load(&name, &dirs).ok()?;
                Some((
                    p.name,
                    p.description,
                    p.apps.len() as u32,
                    path.display().to_string(),
                ))
            })
            .collect()
    }

    /// Plan or apply a preset import: (app, outcome_line, was_added).
    ///
    /// # Why the daemon and not the client
    ///
    /// The daemon owns `config.toml` and rewrites it wholesale, so a client
    /// writing to it would race the next rule change. More to the point,
    /// `SetRule` cannot carry an `exe_path` — which is the entire reason
    /// presets exist.
    ///
    /// # Why `apply` is a parameter and not the default
    ///
    /// A preset granting camera access to a list of binaries is a GRANT. The
    /// safe outcome is the one you get by forgetting the flag, so
    /// `apply = false` plans and writes nothing.
    async fn import_preset(
        &self,
        #[zbus(signal_context)] ctx: SignalContext<'_>,
        name: &str,
        apply: bool,
    ) -> Vec<(String, String, bool)> {
        let dirs = hwprivacy_common::preset::preset_dirs();
        let preset = match hwprivacy_common::preset::load(name, &dirs) {
            Ok(p) => p,
            Err(e) => return vec![(name.to_string(), format!("error: {e:#}"), false)],
        };

        let mut state = self.state.write().await;
        let plan = preset.plan(
            hwprivacy_common::preset::path_exists,
            |app| state.config.find_rule(app).is_some(),
        );

        let report: Vec<(String, String, bool)> = plan
            .entries
            .iter()
            .map(|(app, outcome, _)| (app.clone(), outcome.describe(), outcome.added()))
            .collect();

        if apply {
            let added = state.config.apply_preset(&plan);
            if added > 0 {
                if let Err(e) = state.config.save() {
                    tracing::error!("Failed to save config after preset import: {}", e);
                }
                info!("Imported preset '{}': {} rule(s) added", name, added);
                let _ = Self::rule_changed(&ctx, name, "*", "preset-imported").await;
            } else {
                info!("Preset '{}' added nothing — every entry was skipped", name);
            }
        }

        report
    }

    async fn get_events(&self, last_n: u32) -> Vec<(String, String, String, String)> {
        let state = self.state.read().await;
        state
            .tracker
            .recent_events(last_n as usize)
            .iter()
            .map(|e| {
                (
                    e.timestamp.clone(),
                    e.app_name.clone(),
                    // device_display(), not device_category: two rows for two
                    // different microphones were indistinguishable here, which
                    // is half of what made b3 read as duplicate prompts.
                    e.device_display(),
                    e.action.to_string(),
                )
            })
            .collect()
    }

    async fn block_all(&self) -> bool {
        let mut state = self.state.write().await;
        state.block_all = true;
        info!("EMERGENCY: Block-all mode enabled");
        true
    }

    async fn unblock_all(&self) -> bool {
        let mut state = self.state.write().await;
        state.block_all = false;
        info!("Block-all mode disabled, restoring saved rules");
        true
    }

    // AllowStream / DenyStream were here until 2026-08-23, backing `ask_each`.
    // Removed with the per-stream concept: the grant AllowStream wrote could
    // never take effect, and DenyStream was already a no-op that returned true.
    // See DECISIONS d-no-per-stream-grants.

    // -- Signals --

    #[zbus(signal)]
    async fn access_attempt(
        ctx: &SignalContext<'_>,
        app_name: &str,
        pid: u32,
        device: &str,
        node_name: &str,
        action: &str,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn rule_changed(
        ctx: &SignalContext<'_>,
        app_name: &str,
        device: &str,
        new_permission: &str,
    ) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn stream_event(
        ctx: &SignalContext<'_>,
        app_name: &str,
        device: &str,
        object_serial: u32,
        event_type: &str,
    ) -> zbus::Result<()>;
}
