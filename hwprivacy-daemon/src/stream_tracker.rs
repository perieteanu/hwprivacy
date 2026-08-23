use hwprivacy_common::stream::{AccessAction, AccessEvent, ActiveConnection, StreamInfo};
use hwprivacy_common::{normalize_app_name, DeviceCategory, Permission};
use std::collections::{HashMap, HashSet};
use std::time::Instant;
use tracing::{debug, info};

/// Tracks active streams, pending requests, and event log.
pub struct StreamTracker {
    /// Active connections: link_id → ActiveConnection
    pub active: HashMap<u32, ActiveConnection>,
    /// Live `while_in_use` sessions: (app, device) → when it was granted.
    ///
    /// # Why keyed on (app, device) and not a node id
    ///
    /// The previous per-stream grant was keyed on a PipeWire node id and pruned
    /// the moment that node left the graph. Since the link is destroyed BEFORE
    /// the user is asked, the node was usually gone by the time an answer
    /// arrived — so the grant expired before it could ever be used, and the app
    /// was prompted again forever. Measured live 2026-08-23; it is why
    /// `ask_each` was removed (`d-no-per-stream-grants`).
    ///
    /// (app, device) survives that churn: the app reconnects with a fresh node
    /// and a fresh link, and the session is still the same session.
    pub while_in_use: HashMap<(String, DeviceCategory), Instant>,
    /// Recent events log (ring buffer, max 500)
    pub events: Vec<AccessEvent>,
    /// Counter for blocked access attempts
    pub blocked_count: u32,
    /// Notification cooldown: (app_name, device_category) → last dismiss time.
    /// When a user dismisses a notification, suppress the same prompt for
    /// `policy.dismiss_cooldown_secs` to avoid notification spam.
    pub dismiss_cooldowns: HashMap<(String, DeviceCategory), Instant>,
    /// (app, device) pairs with a prompt already on screen, awaiting an answer.
    ///
    /// Prompts are Resident — they stay until the user answers, which is what
    /// makes them a to-do item rather than something that vanishes while you
    /// are away from the keyboard. The cost is that a second stream from the
    /// same app would stack a second identical popup asking the same question,
    /// and a browser produces those steadily. One pending question per
    /// (app, device); the answer, when it comes, governs what follows.
    ///
    /// This is blocker b6. It was invisible until b1 was fixed, because before
    /// that the popup wrote a permanent deny the moment it was closed.
    pending_prompts: HashSet<(String, DeviceCategory)>,
}

impl StreamTracker {
    pub fn new() -> Self {
        Self {
            active: HashMap::new(),
            while_in_use: HashMap::new(),
            events: Vec::new(),
            blocked_count: 0,
            dismiss_cooldowns: HashMap::new(),
            pending_prompts: HashSet::new(),
        }
    }

    /// Record a dismiss for cooldown purposes.
    pub fn record_dismiss(&mut self, app_name: &str, category: DeviceCategory) {
        self.dismiss_cooldowns
            .insert((app_name.to_string(), category), Instant::now());
    }

    /// Check if a notification for this app+device is in cooldown.
    ///
    /// Unreachable until 2026-08-21: `ask_user_permission` could never return
    /// "dismissed", so this and [`Self::record_dismiss`] were dead code. See
    /// `notification::PromptOutcome`.
    pub fn is_in_cooldown(
        &self,
        app_name: &str,
        category: DeviceCategory,
        cooldown_secs: u64,
    ) -> bool {
        if let Some(dismissed_at) = self.dismiss_cooldowns.get(&(app_name.to_string(), category)) {
            dismissed_at.elapsed().as_secs() < cooldown_secs
        } else {
            false
        }
    }

    /// Claim the right to ask about this (app, device).
    ///
    /// Returns false when a prompt for the same pair is already on screen. The
    /// caller must then block the access as usual and say nothing — the
    /// question has already been asked and is waiting for an answer.
    ///
    /// Keyed on the NORMALISED app name so `Firefox` and
    /// `Firefox [pipewire-pulse]` are one pending question, not two.
    pub fn try_begin_prompt(&mut self, app_name: &str, category: DeviceCategory) -> bool {
        self.pending_prompts
            .insert((normalize_app_name(app_name), category))
    }

    /// Release the claim once the prompt has been answered, dismissed, or
    /// failed to show. MUST run on every path out of the prompt, or that
    /// (app, device) is never asked about again for the life of the daemon.
    pub fn end_prompt(&mut self, app_name: &str, category: DeviceCategory) {
        self.pending_prompts
            .remove(&(normalize_app_name(app_name), category));
    }

    /// Is a prompt for this pair already waiting for an answer?
    pub fn prompt_pending(&self, app_name: &str, category: DeviceCategory) -> bool {
        self.pending_prompts
            .contains(&(normalize_app_name(app_name), category))
    }

    /// Record a new access event.
    ///
    /// `instance` names WHICH device when the node presents several — `mic2`.
    /// Two rows that differ only in that were indistinguishable before b3, and
    /// they are the same two rows the user is being asked about.
    pub fn log_event(
        &mut self,
        app_name: &str,
        pid: u32,
        category: DeviceCategory,
        node_name: &str,
        action: AccessAction,
    ) {
        let event = AccessEvent {
            // Date included, deliberately. This was "%H:%M:%S" — no date at all
            // (gap g4), which is ambiguous the moment a log spans midnight and
            // useless for the thing this log exists for: reading it back days
            // later to see who tried. ISO order rather than the project's usual
            // EU order because these lines get sorted and grepped as text.
            timestamp: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
            app_name: app_name.to_string(),
            pid,
            device_category: category,
            node_name: node_name.to_string(),
            action: action.clone(),
        };

        info!(
            "Event: {} (pid:{}) → {} → {}",
            app_name,
            pid,
            event.device_display(),
            action
        );

        // Keep max 500 events
        if self.events.len() >= 500 {
            self.events.remove(0);
        }
        self.events.push(event);

        if matches!(action, AccessAction::Denied) {
            self.blocked_count += 1;
        }
    }

    /// Track an active connection.
    pub fn add_connection(
        &mut self,
        link_id: u32,
        stream: StreamInfo,
        device_node_name: &str,
        device_category: DeviceCategory,
        permission: Permission,
    ) {
        let conn = ActiveConnection {
            stream,
            device_node_name: device_node_name.to_string(),
            device_category,
            permission,
            link_id: Some(link_id),
            active: true,
        };
        self.active.insert(link_id, conn);
    }

    /// Remove a connection when its link is destroyed.
    pub fn remove_connection(&mut self, link_id: u32) {
        self.active.remove(&link_id);
    }

    // is_one_shot_allowed / grant_one_shot / prune_one_shot lived here until
    // 2026-08-23, backing `ask_each`. They are gone with it: the grant they
    // produced could never be used. The link was destroyed before the user was
    // asked, nothing in link_manager can create one, and the grant was keyed on
    // a node id that got pruned the moment the torn-down stream left the graph.
    // Measured live: allow, nothing happens, asked again — forever.
    // See DECISIONS d-no-per-stream-grants.

    /// Open a `while_in_use` session for (app, device).
    pub fn begin_session(&mut self, app_name: &str, category: DeviceCategory) {
        self.while_in_use
            .insert((normalize_app_name(app_name), category), Instant::now());
    }

    /// Is there a live `while_in_use` session for (app, device)?
    ///
    /// Live means: the app currently holds a link to that device, OR the grant
    /// is younger than `settle` and the app has simply not reconnected yet.
    ///
    /// The settle window is not a convenience. Enforcement destroys the link
    /// before the prompt is shown, so between the user's answer and the
    /// application's retry there are legitimately ZERO links — and without a
    /// window the session would end in that gap and re-prompt immediately, on
    /// a loop. That is exactly how the old per-stream grant failed.
    pub fn session_live(
        &self,
        app_name: &str,
        category: DeviceCategory,
        settle: std::time::Duration,
    ) -> bool {
        let key = (normalize_app_name(app_name), category);
        let Some(granted_at) = self.while_in_use.get(&key) else {
            return false;
        };
        self.has_active_link(&key.0, category) || granted_at.elapsed() < settle
    }

    /// Does the app hold at least one live link to this device category?
    pub fn has_active_link(&self, app_name: &str, category: DeviceCategory) -> bool {
        let key = normalize_app_name(app_name);
        self.active.values().any(|c| {
            c.device_category == category && normalize_app_name(&c.stream.app_name) == key
        })
    }

    /// End every session whose device has been released and whose settle window
    /// has passed. Returns the sessions that ended, for logging.
    ///
    /// This is the whole point of `while_in_use`: the grant must not outlive the
    /// use. Called once per poll, after stale connections have been pruned.
    pub fn expire_sessions(&mut self, settle: std::time::Duration) -> Vec<(String, DeviceCategory)> {
        let ended: Vec<(String, DeviceCategory)> = self
            .while_in_use
            .iter()
            .filter(|((app, cat), granted_at)| {
                !self.has_active_link(app, *cat) && granted_at.elapsed() >= settle
            })
            .map(|(k, _)| k.clone())
            .collect();
        for k in &ended {
            self.while_in_use.remove(k);
        }
        ended
    }

    /// Get recent events.
    pub fn recent_events(&self, n: usize) -> &[AccessEvent] {
        let start = self.events.len().saturating_sub(n);
        &self.events[start..]
    }

    /// Get active connection count.
    pub fn active_count(&self) -> u32 {
        self.active.values().filter(|c| c.active).count() as u32
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// b6. Prompts are Resident and never expire — decided 2026-08-23, a
    /// permission question is a to-do item, not something that vanishes while
    /// you are away. The consequence to contain is stacking: a browser opens
    /// streams steadily, and each one would raise another identical popup
    /// asking the same question.
    #[test]
    fn only_one_prompt_per_app_and_device_can_be_pending() {
        let mut t = StreamTracker::new();
        assert!(t.try_begin_prompt("Firefox", DeviceCategory::Microphone));
        assert!(
            !t.try_begin_prompt("Firefox", DeviceCategory::Microphone),
            "the question is already on screen; do not ask it twice"
        );
        assert!(t.prompt_pending("Firefox", DeviceCategory::Microphone));
    }

    /// Normalised, so the pulse-bridge variant is the same pending question.
    /// Without this a browser would raise one popup as `Firefox` and another as
    /// `Firefox [pipewire-pulse]`, which is the exact stacking being prevented.
    #[test]
    fn a_pending_prompt_is_keyed_on_the_normalised_name() {
        let mut t = StreamTracker::new();
        assert!(t.try_begin_prompt("Firefox [pipewire-pulse]", DeviceCategory::Camera));
        assert!(!t.try_begin_prompt("firefox", DeviceCategory::Camera));
        assert!(t.prompt_pending("FIREFOX", DeviceCategory::Camera));
    }

    /// Different apps and different devices are different questions.
    #[test]
    fn pending_prompts_do_not_block_unrelated_questions() {
        let mut t = StreamTracker::new();
        assert!(t.try_begin_prompt("firefox", DeviceCategory::Microphone));
        assert!(t.try_begin_prompt("obs", DeviceCategory::Microphone), "another app");
        assert!(t.try_begin_prompt("firefox", DeviceCategory::Camera), "another device");
    }

    /// **The failure mode that would be invisible.** If the claim is not
    /// released, that (app, device) is never asked about again for the life of
    /// the daemon — no popup, no error, nothing in the log. It would look like
    /// the tool quietly giving up on one app.
    #[test]
    fn answering_releases_the_claim_so_the_next_stream_can_ask() {
        let mut t = StreamTracker::new();
        assert!(t.try_begin_prompt("firefox", DeviceCategory::Microphone));
        t.end_prompt("firefox", DeviceCategory::Microphone);
        assert!(!t.prompt_pending("firefox", DeviceCategory::Microphone));
        assert!(
            t.try_begin_prompt("Firefox [pipewire-pulse]", DeviceCategory::Microphone),
            "and the release must match the same normalised key it was claimed under"
        );
    }

    /// Releasing something that was never claimed must not panic or corrupt the
    /// set — the prompt task calls this on every exit path, including ones
    /// where the claim was never taken.
    #[test]
    fn releasing_an_unclaimed_prompt_is_harmless() {
        let mut t = StreamTracker::new();
        t.end_prompt("never-asked", DeviceCategory::Camera);
        assert!(!t.prompt_pending("never-asked", DeviceCategory::Camera));
    }

    /// The cooldown is what makes "dismiss saves nothing" bearable: without it
    /// a dismissed prompt would re-fire on the very next poll. It was
    /// unreachable code until b1 was fixed, so this is its first coverage.
    #[test]
    fn a_dismissal_silences_that_app_and_device_only() {
        let mut t = StreamTracker::new();
        t.record_dismiss("firefox", DeviceCategory::Microphone);

        assert!(t.is_in_cooldown("firefox", DeviceCategory::Microphone, 60));
        assert!(
            !t.is_in_cooldown("firefox", DeviceCategory::Camera, 60),
            "a different device must still prompt"
        );
        assert!(
            !t.is_in_cooldown("obs", DeviceCategory::Microphone, 60),
            "a different app must still prompt"
        );
        assert!(
            !t.is_in_cooldown("firefox", DeviceCategory::Microphone, 0),
            "a zero cooldown means ask again immediately"
        );
    }

    // ---------------------------------------------------------------------
    // while_in_use sessions. The grant must not outlive the use — that is the
    // entire difference between this permission and `allow`.
    // ---------------------------------------------------------------------

    use std::time::Duration;

    fn si(app: &str, node_id: u32) -> StreamInfo {
        StreamInfo {
            node_id,
            app_name: app.into(),
            pid: 1,
            node_name: "app".into(),
            media_name: String::new(),
            media_class: "Stream/Input/Audio".into(),
        }
    }

    const SETTLE: Duration = Duration::from_secs(10);

    #[test]
    fn no_session_exists_until_one_is_granted() {
        let t = StreamTracker::new();
        assert!(!t.session_live("firefox", DeviceCategory::Microphone, SETTLE));
    }

    /// The settle window, and why it is not optional. Enforcement destroys the
    /// link BEFORE the prompt, so right after the answer there are legitimately
    /// zero links. Without this the session would end in that gap and prompt
    /// again immediately — the loop that killed the old per-stream grant.
    #[test]
    fn a_fresh_grant_is_live_before_the_app_reconnects() {
        let mut t = StreamTracker::new();
        t.begin_session("firefox", DeviceCategory::Microphone);
        assert!(
            t.session_live("firefox", DeviceCategory::Microphone, SETTLE),
            "no links yet, but the app has not had time to retry"
        );
    }

    /// Once the settle window has passed with no link, the session is over.
    #[test]
    fn a_grant_the_app_never_used_expires() {
        let mut t = StreamTracker::new();
        t.begin_session("firefox", DeviceCategory::Microphone);
        let ended = t.expire_sessions(Duration::ZERO);
        assert_eq!(ended, vec![("firefox".to_string(), DeviceCategory::Microphone)]);
        assert!(!t.session_live("firefox", DeviceCategory::Microphone, SETTLE));
    }

    /// While the app holds a link the session stays live no matter how long
    /// ago it was granted — a call lasting an hour must not be interrupted.
    #[test]
    fn a_session_with_a_live_link_never_expires() {
        let mut t = StreamTracker::new();
        t.begin_session("firefox", DeviceCategory::Microphone);
        t.add_connection(
            7,
            si("Firefox [pipewire-pulse]", 99),
            "alsa_input.analog",
            DeviceCategory::Microphone,
            Permission::WhileInUse,
        );
        assert!(t.expire_sessions(Duration::ZERO).is_empty(), "still in use");
        assert!(t.session_live("firefox", DeviceCategory::Microphone, Duration::ZERO));
    }

    /// Releasing the device ends the session. This is the feature.
    #[test]
    fn releasing_the_device_ends_the_session() {
        let mut t = StreamTracker::new();
        t.begin_session("firefox", DeviceCategory::Microphone);
        t.add_connection(
            7,
            si("Firefox [pipewire-pulse]", 99),
            "alsa_input.analog",
            DeviceCategory::Microphone,
            Permission::WhileInUse,
        );
        assert!(t.expire_sessions(Duration::ZERO).is_empty());

        t.remove_connection(7); // the app closed the microphone
        assert_eq!(
            t.expire_sessions(Duration::ZERO),
            vec![("firefox".to_string(), DeviceCategory::Microphone)],
            "grant must not outlive the use"
        );
        assert!(!t.session_live("firefox", DeviceCategory::Microphone, SETTLE));
    }

    /// A session is per DEVICE. Granting the microphone must not hand over the
    /// monitor, which is a different question about a different device.
    #[test]
    fn a_session_does_not_leak_across_devices() {
        let mut t = StreamTracker::new();
        t.begin_session("firefox", DeviceCategory::Microphone);
        assert!(!t.session_live("firefox", DeviceCategory::Monitor, SETTLE));
    }

    /// And per app — under the normalised name, so `Firefox` and
    /// `Firefox [pipewire-pulse]` are one session and `obs` is not.
    #[test]
    fn a_session_does_not_leak_across_apps() {
        let mut t = StreamTracker::new();
        t.begin_session("Firefox [pipewire-pulse]", DeviceCategory::Microphone);
        assert!(t.session_live("firefox", DeviceCategory::Microphone, SETTLE));
        assert!(!t.session_live("obs", DeviceCategory::Microphone, SETTLE));
    }
}
