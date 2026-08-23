//! When to say "something used your camera".
//!
//! # Why this exists
//!
//! Measured 2026-08-21:
//!
//! ```text
//! 08:48:56  allow  VideoCapture  firefox-esr  /dev/video0
//! 09:14:41  allow  VideoCapture  firefox-esr  /dev/video0
//! ```
//!
//! Two successful camera opens in one morning with no video call, because a
//! website held a standing per-origin grant and a restored tab re-acquired on
//! reload. Both were allowed CORRECTLY — at each layer the question asked was
//! "is this firefox-esr?", and it was — and hwprivacy said nothing.
//!
//! That is the asymmetry this closes: the deny path had a notification and a
//! history row, the allow path had neither. A tool whose job is telling you
//! when your camera turns on was only telling you when it didn't.
//!
//! # Why it is a separate, pure module
//!
//! Every rule in this project that decided whether a user-visible thing happens
//! and lived inline inside a `tokio::spawn` turned out to be wrong and
//! untestable: b1's dismiss handling, and the C5 burst arithmetic before it.
//! The gate is a function that takes values and returns a bool, so the
//! interesting cases can simply be asserted.

use hwprivacy_common::{DeviceCategory, PolicyConfig};
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Remembers when each (app, device) was last announced.
#[derive(Debug, Default)]
pub struct AllowNotifier {
    last: HashMap<(String, DeviceCategory), Instant>,
}

/// Everything the gate needs to know about one allowed access.
#[derive(Debug, Clone, Copy)]
pub struct AllowedAccess<'a> {
    pub app: &'a str,
    pub device: DeviceCategory,
    /// 0 marks a coalesced burst summary — accounting for opens the kernel
    /// already suppressed, not a fresh access.
    pub pid: u32,
}

impl AllowNotifier {
    /// Should this allowed access be announced?
    ///
    /// `uptime` is how long the daemon has been running and `now` is the
    /// current instant — both passed in rather than read here, so the whole
    /// decision is testable without sleeping.
    pub fn should_notify(
        &self,
        access: AllowedAccess<'_>,
        uptime: Duration,
        now: Instant,
        cfg: &PolicyConfig,
    ) -> bool {
        if !cfg.notify_on_allow {
            return false;
        }

        // A burst summary is one event standing for opens that were already
        // accounted for. It must contribute its count and nothing else — no
        // event-log row, no notification. Getting this wrong is how one camera
        // session produced two popups before (C5).
        if access.pid == 0 {
            return false;
        }

        // Boot probes. wireplumber opens the camera about eight seconds after
        // the daemon starts, v4l_id before that. Suppressed by TIME rather than
        // by naming them: an allowlist of system processes would be the
        // per-application coupling this project deliberately does not do, and
        // it would not even work here — wireplumber has a rule in the live
        // config, so "only notify apps with a rule" would have let it through.
        if uptime.as_secs() <= cfg.notify_allow_grace_secs {
            return false;
        }

        match self.last.get(&(access.app.to_string(), access.device)) {
            Some(prev) => {
                now.duration_since(*prev).as_secs() >= cfg.notify_allow_cooldown_secs
            }
            None => true,
        }
    }

    /// Record that we announced this one. Call only after actually notifying,
    /// or the cooldown starts for a notification nobody saw.
    pub fn mark_notified(&mut self, access: AllowedAccess<'_>, now: Instant) {
        self.last
            .insert((access.app.to_string(), access.device), now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> PolicyConfig {
        PolicyConfig::default()
    }

    fn access(app: &str, device: DeviceCategory, pid: u32) -> AllowedAccess<'_> {
        AllowedAccess { app, device, pid }
    }

    fn past(now: Instant, secs: u64) -> Instant {
        now.checked_sub(Duration::from_secs(secs)).unwrap()
    }

    /// The case that prompted the whole feature.
    #[test]
    fn a_first_allowed_access_is_announced() {
        let n = AllowNotifier::default();
        assert!(n.should_notify(
            access("firefox-esr", DeviceCategory::Camera, 3247),
            Duration::from_secs(600),
            Instant::now(),
            &cfg()
        ));
    }

    /// wireplumber opens the camera ~8s after the daemon starts, at every
    /// single boot. Announcing that would train the user to ignore the feature
    /// by the end of the first week.
    #[test]
    fn boot_probes_are_silent() {
        let n = AllowNotifier::default();
        let c = cfg();
        for uptime in [0, 1, 8, 30, c.notify_allow_grace_secs] {
            assert!(
                !n.should_notify(
                    access("wireplumber", DeviceCategory::Camera, 2199),
                    Duration::from_secs(uptime),
                    Instant::now(),
                    &c
                ),
                "uptime {uptime}s is inside the grace window"
            );
        }
        assert!(
            n.should_notify(
                access("wireplumber", DeviceCategory::Camera, 2199),
                Duration::from_secs(c.notify_allow_grace_secs + 1),
                Instant::now(),
                &c
            ),
            "past the window, even wireplumber is worth reporting"
        );
    }

    /// A coalesced burst carries pid 0 and stands for opens already counted.
    /// One camera session is ~13 opens; without this it is ~13 popups.
    #[test]
    fn a_burst_summary_never_notifies() {
        let n = AllowNotifier::default();
        for uptime in [0, 61, 100_000] {
            assert!(!n.should_notify(
                access("firefox-esr", DeviceCategory::Camera, 0),
                Duration::from_secs(uptime),
                Instant::now(),
                &cfg()
            ));
        }
    }

    /// Repeats inside the window are one story; the same app half an hour later
    /// is a second one. Both firefox-esr opens on 2026-08-21 must be reported —
    /// they were 26 minutes apart.
    #[test]
    fn the_cooldown_collapses_a_burst_but_not_a_later_return() {
        let mut n = AllowNotifier::default();
        let c = cfg();
        let now = Instant::now();
        let a = access("firefox-esr", DeviceCategory::Camera, 3247);

        n.mark_notified(a, past(now, 10));
        assert!(
            !n.should_notify(a, Duration::from_secs(600), now, &c),
            "10s later is the same activity"
        );

        // 26 minutes later — the real gap between the two measured opens.
        n.mark_notified(a, past(now, 26 * 60));
        assert!(
            n.should_notify(a, Duration::from_secs(600), now, &c),
            "26 minutes later is a separate access and must be reported"
        );
    }

    /// The cooldown is per (app, device), not global — one app going quiet must
    /// not silence another.
    #[test]
    fn the_cooldown_does_not_leak_between_apps_or_devices() {
        let mut n = AllowNotifier::default();
        let now = Instant::now();
        n.mark_notified(access("firefox-esr", DeviceCategory::Camera, 1), now);

        assert!(n.should_notify(
            access("obs", DeviceCategory::Camera, 2),
            Duration::from_secs(600),
            now,
            &cfg()
        ), "a different app");
        assert!(n.should_notify(
            access("firefox-esr", DeviceCategory::Microphone, 1),
            Duration::from_secs(600),
            now,
            &cfg()
        ), "a different device");
    }

    #[test]
    fn the_knob_turns_it_off_completely() {
        let n = AllowNotifier::default();
        let c = PolicyConfig {
            notify_on_allow: false,
            ..PolicyConfig::default()
        };
        assert!(!n.should_notify(
            access("firefox-esr", DeviceCategory::Camera, 3247),
            Duration::from_secs(100_000),
            Instant::now(),
            &c
        ));
    }

    /// mark_notified is what starts the cooldown, so it must be called only
    /// after a notification really went out. Asserting the ordering here
    /// because the failure mode — cooldown started for a popup nobody saw — is
    /// silent.
    #[test]
    fn marking_is_what_starts_the_cooldown() {
        let mut n = AllowNotifier::default();
        let now = Instant::now();
        let a = access("firefox-esr", DeviceCategory::Camera, 3247);
        assert!(n.should_notify(a, Duration::from_secs(600), now, &cfg()));
        n.mark_notified(a, now);
        assert!(!n.should_notify(a, Duration::from_secs(600), now, &cfg()));
    }
}
