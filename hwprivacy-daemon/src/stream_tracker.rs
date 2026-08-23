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

    /// Track a while_in_use stream.
    pub fn track_while_in_use(&mut self, app_name: &str, node_id: u32) {
        self.while_in_use_streams
            .entry(app_name.to_string())
            .or_default()
            .push(node_id);
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
}
