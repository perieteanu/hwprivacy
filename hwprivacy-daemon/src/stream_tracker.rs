use hwprivacy_common::stream::{AccessAction, AccessEvent, ActiveConnection, StreamInfo};
use hwprivacy_common::{normalize_app_name, DeviceCategory, Permission};
use std::collections::{HashMap, HashSet};
use std::time::Instant;
use tracing::{debug, info};

/// Tracks active streams, pending requests, and event log.
pub struct StreamTracker {
    /// Active connections: link_id → ActiveConnection
    pub active: HashMap<u32, ActiveConnection>,
    /// Streams allowed with "while_in_use": app_name → set of node ids
    pub while_in_use_streams: HashMap<String, Vec<u32>>,
    /// Recent events log (ring buffer, max 500)
    pub events: Vec<AccessEvent>,
    /// Counter for blocked access attempts
    pub blocked_count: u32,
    /// Session one-shot `ask_each` grants: node id → normalised app name.
    ///
    /// Keyed on BOTH halves deliberately. This was a `Vec<u32>` of node ids
    /// that was never pruned, and PipeWire reuses node ids as soon as a node is
    /// gone — so a grant given to one stream could silently authorise an
    /// unrelated later one. Observed live: a Firefox microphone stream logged
    /// ALLOWED with no prompt while the rule said `ask_each` (blocker b2).
    ///
    /// Pruning alone still leaves a race, because an id can be freed and reused
    /// between two polls. Requiring the app name to match as well closes the
    /// cross-application case, which is the half that matters for security.
    pub one_shot_allowed: HashMap<u32, String>,
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
            while_in_use_streams: HashMap::new(),
            events: Vec::new(),
            blocked_count: 0,
            one_shot_allowed: HashMap::new(),
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
        instance: Option<&str>,
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
            device_instance: instance.map(str::to_string),
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

        if matches!(action, AccessAction::Denied | AccessAction::StreamDenied) {
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

    /// Track a while_in_use stream.
    pub fn track_while_in_use(&mut self, app_name: &str, node_id: u32) {
        self.while_in_use_streams
            .entry(app_name.to_string())
            .or_default()
            .push(node_id);
    }

    /// Check if a stream was one-shot allowed (for `ask_each`).
    ///
    /// The app name must match as well as the node id. A recycled id belonging
    /// to a different application is not a grant.
    pub fn is_one_shot_allowed(&self, node_id: u32, app_name: &str) -> bool {
        self.one_shot_allowed
            .get(&node_id)
            .is_some_and(|granted_to| *granted_to == normalize_app_name(app_name))
    }

    /// Grant a one-shot allow for a stream.
    pub fn grant_one_shot(&mut self, node_id: u32, app_name: &str) {
        self.one_shot_allowed
            .insert(node_id, normalize_app_name(app_name));
    }

    /// Drop grants whose node no longer exists in the graph.
    ///
    /// Without this a grant lives for the daemon's whole lifetime, and node ids
    /// are reused — which is how an approved stream's permission ended up on a
    /// later, unapproved one. Called once per poll from the monitoring loop,
    /// where the live node set has already been captured.
    pub fn prune_one_shot(&mut self, live_node_ids: &HashSet<u32>) {
        let before = self.one_shot_allowed.len();
        self.one_shot_allowed
            .retain(|node_id, _| live_node_ids.contains(node_id));
        let dropped = before - self.one_shot_allowed.len();
        if dropped > 0 {
            debug!("Expired {dropped} one-shot grant(s) whose stream is gone");
        }
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

    /// b2, the security half. PipeWire reuses node ids. A grant given to
    /// Firefox's stream must never authorise a different application that later
    /// happens to land on the same id.
    #[test]
    fn a_grant_does_not_transfer_to_another_app_on_the_same_node_id() {
        let mut t = StreamTracker::new();
        t.grant_one_shot(42, "Firefox [pipewire-pulse]");

        assert!(t.is_one_shot_allowed(42, "Firefox"), "same app, same node");
        assert!(
            t.is_one_shot_allowed(42, "firefox [pipewire-pulse]"),
            "the annotation and case must not matter — normalize_app_name handles both"
        );
        assert!(
            !t.is_one_shot_allowed(42, "obs"),
            "a recycled id belonging to another app is NOT a grant"
        );
        assert!(!t.is_one_shot_allowed(43, "Firefox"), "different node");
    }

    /// b2, the lifetime half. The grant list was never pruned, so a grant
    /// survived for the daemon's whole lifetime — live evidence was an
    /// `ask_each` Firefox microphone stream logged ALLOWED with no prompt.
    #[test]
    fn a_grant_expires_when_its_node_leaves_the_graph() {
        let mut t = StreamTracker::new();
        t.grant_one_shot(42, "firefox");
        t.grant_one_shot(43, "obs");

        let live: HashSet<u32> = [43].into_iter().collect();
        t.prune_one_shot(&live);

        assert!(!t.is_one_shot_allowed(42, "firefox"), "gone node, gone grant");
        assert!(t.is_one_shot_allowed(43, "obs"), "a live node keeps its grant");
    }

    /// Re-granting the same node must not accumulate entries — the old
    /// `Vec<u32>` grew without bound for the process lifetime.
    #[test]
    fn regranting_the_same_node_does_not_accumulate() {
        let mut t = StreamTracker::new();
        t.grant_one_shot(7, "firefox");
        t.grant_one_shot(7, "firefox");
        assert_eq!(t.one_shot_allowed.len(), 1);
    }

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
}
