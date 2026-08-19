//! Who has been trying, how often, and since when — across restarts.
//!
//! # Why this exists
//!
//! The event log is a 500-entry in-memory ring buffer. It dies with the daemon,
//! so the question Costin actually asked — *"logs you'll visit later, after a
//! few days, to have a better grasp of who tried to connect"* — could not be
//! answered at all. This is the part that survives.
//!
//! # Why a table and not just more log lines
//!
//! The useful idea borrowed from fail2ban is not banning: it is that
//! **frequency is signal**. One denial is noise; fifty in an hour is an
//! application persistently trying. A flat log cannot express that difference
//! and an offender table can.
//!
//! What does NOT transfer is the ban. Fail2ban blocks an attacker who is
//! otherwise getting through; here a repeat offender is *already* denied on
//! every attempt, so escalation would be meaningless. The escalation is
//! informational.
//!
//! # The direction fail2ban has no analogue for
//!
//! Most entries here will be apps the user *wants* to work. "signal-desktop
//! denied the camera 12 times" means *add an exe_path*, not that Signal is
//! hostile. This table is the discovery loop for building the allowlist, which
//! is probably its more valuable direction day to day.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;
use tracing::{debug, warn};

/// One (identity, device) pair that has been denied at least once.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Offender {
    /// Executable path for kernel-layer denials, normalised application name
    /// for PipeWire ones. See [`Source`] — the two are not interchangeable and
    /// the table says which it is.
    pub identity: String,
    pub device: String,
    pub source: String,
    pub denied: u32,
    pub first_seen: String,
    pub last_seen: String,
}

/// Which layer saw the denial.
///
/// Worth recording because the two identities have different stability.
/// `exe_path` survives restarts and reboots. A PipeWire `application.name` is
/// asserted by the application about itself, and historically carried a pid
/// that changed on every restart — which fragments one app into many rows the
/// longer the window gets (this is blocker b4 getting worse with time).
pub const SOURCE_KERNEL: &str = "kernel";
pub const SOURCE_PIPEWIRE: &str = "pipewire";

#[derive(Debug, Default)]
pub struct Offenders {
    by_key: BTreeMap<(String, String, String), Offender>,
    path: Option<PathBuf>,
    dirty: bool,
}

/// `$XDG_STATE_HOME/hwprivacy/offenders.json`, falling back to
/// `~/.local/state/...`.
///
/// Deliberately user-owned state, not `/var/lib`. The daemon is unprivileged
/// and this table must be readable without joining a group — the raw journal
/// already requires `systemd-journal`, and making the everyday view need
/// privileges too would put it out of reach of the person it is for.
pub fn default_path() -> Option<PathBuf> {
    let base = std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/state")))?;
    Some(base.join("hwprivacy").join("offenders.json"))
}

impl Offenders {
    /// Load from disk, or start empty. A missing file is normal (first run).
    ///
    /// A file that exists but does not parse is logged and then IGNORED rather
    /// than propagated: this is an audit convenience, and refusing to start the
    /// daemon because a statistics file went bad would trade enforcement for
    /// bookkeeping.
    pub fn load(path: Option<PathBuf>) -> Self {
        let mut s = Offenders {
            path,
            ..Default::default()
        };
        let Some(p) = s.path.clone() else {
            return s;
        };
        match std::fs::read_to_string(&p) {
            Ok(text) => match serde_json::from_str::<Vec<Offender>>(&text) {
                Ok(list) => {
                    for o in list {
                        s.by_key.insert(
                            (o.identity.clone(), o.device.clone(), o.source.clone()),
                            o,
                        );
                    }
                    debug!("Offenders: loaded {} entries from {}", s.by_key.len(), p.display());
                }
                Err(e) => warn!(
                    "Offenders: {} exists but could not be parsed ({e}). Starting a fresh \
                     table; the old file is left alone.",
                    p.display()
                ),
            },
            Err(_) => debug!("Offenders: no table at {} yet", p.display()),
        }
        s
    }

    /// Record `count` denials. `count` rather than one, because a coalesced
    /// kernel burst is a single event representing many opens — counting it as
    /// one would under-report exactly the persistent access this table exists
    /// to make visible.
    pub fn record(&mut self, identity: &str, device: &str, source: &str, count: u32, now: &str) {
        if count == 0 {
            return;
        }
        let key = (identity.to_string(), device.to_string(), source.to_string());
        let e = self.by_key.entry(key).or_insert_with(|| Offender {
            identity: identity.to_string(),
            device: device.to_string(),
            source: source.to_string(),
            denied: 0,
            first_seen: now.to_string(),
            last_seen: now.to_string(),
        });
        e.denied = e.denied.saturating_add(count);
        e.last_seen = now.to_string();
        self.dirty = true;
    }

    /// Most persistent first — that ordering is the whole point.
    pub fn sorted(&self) -> Vec<Offender> {
        let mut v: Vec<_> = self.by_key.values().cloned().collect();
        v.sort_by(|a, b| b.denied.cmp(&a.denied).then_with(|| a.identity.cmp(&b.identity)));
        v
    }

    /// Persist if anything changed. Atomic, so a crash mid-write cannot leave a
    /// truncated file that then fails to parse and loses the whole history.
    pub fn save_if_dirty(&mut self) {
        if !self.dirty {
            return;
        }
        let Some(p) = self.path.clone() else {
            return;
        };
        if let Some(dir) = p.parent() {
            if let Err(e) = std::fs::create_dir_all(dir) {
                warn!("Offenders: cannot create {}: {e}", dir.display());
                return;
            }
        }
        let list = self.sorted();
        let json = match serde_json::to_string_pretty(&list) {
            Ok(j) => j,
            Err(e) => {
                warn!("Offenders: cannot serialise: {e}");
                return;
            }
        };
        let tmp = p.with_extension("tmp");
        if let Err(e) = std::fs::write(&tmp, json) {
            warn!("Offenders: cannot write {}: {e}", tmp.display());
            return;
        }
        if let Err(e) = std::fs::rename(&tmp, &p) {
            warn!("Offenders: cannot rename into {}: {e}", p.display());
            return;
        }
        self.dirty = false;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(n: &str) -> String {
        format!("2026-08-19 20:0{n}:00")
    }

    #[test]
    fn repeated_denials_accumulate_and_move_last_seen_only() {
        let mut o = Offenders::default();
        o.record("/usr/bin/x", "camera", SOURCE_KERNEL, 1, &t("1"));
        o.record("/usr/bin/x", "camera", SOURCE_KERNEL, 1, &t("2"));
        let v = o.sorted();
        assert_eq!(v.len(), 1, "same identity+device+source is one row");
        assert_eq!(v[0].denied, 2);
        assert_eq!(v[0].first_seen, t("1"), "first_seen must not move");
        assert_eq!(v[0].last_seen, t("2"));
    }

    /// A coalesced kernel burst arrives as ONE event standing for many opens.
    /// Counting it as a single denial would under-report the persistent access
    /// this table exists to surface.
    #[test]
    fn a_burst_contributes_its_full_count() {
        let mut o = Offenders::default();
        o.record("/usr/bin/x", "camera", SOURCE_KERNEL, 13, &t("1"));
        assert_eq!(o.sorted()[0].denied, 13);
    }

    /// The same program seen by both layers is two rows on purpose: the
    /// identities have different stability and merging them would imply a
    /// confidence the PipeWire name does not have.
    #[test]
    fn the_two_layers_are_counted_separately() {
        let mut o = Offenders::default();
        o.record("/usr/lib/firefox-esr/firefox-esr", "camera", SOURCE_KERNEL, 4, &t("1"));
        o.record("firefox", "microphone", SOURCE_PIPEWIRE, 2, &t("1"));
        assert_eq!(o.sorted().len(), 2);
    }

    #[test]
    fn sorted_puts_the_most_persistent_first() {
        let mut o = Offenders::default();
        o.record("quiet", "camera", SOURCE_KERNEL, 1, &t("1"));
        o.record("noisy", "camera", SOURCE_KERNEL, 50, &t("1"));
        assert_eq!(o.sorted()[0].identity, "noisy");
    }

    #[test]
    fn a_zero_count_records_nothing() {
        let mut o = Offenders::default();
        o.record("/usr/bin/x", "camera", SOURCE_KERNEL, 0, &t("1"));
        assert!(o.sorted().is_empty());
    }

    /// The whole reason this module exists. `tracker.events` is a 500-entry
    /// in-memory ring buffer that a restart wipes, which is why "who tried to
    /// connect, over the last few days" could not be answered at all. If this
    /// does not survive a reload, the feature is decorative.
    #[test]
    fn the_table_survives_a_reload() {
        let dir = std::env::temp_dir().join(format!("hwp-off-{}", std::process::id()));
        let path = dir.join("offenders.json");
        let _ = std::fs::remove_dir_all(&dir);

        let mut a = Offenders::load(Some(path.clone()));
        a.record("/usr/lib/firefox-esr/firefox-esr", "camera", SOURCE_KERNEL, 13, &t("1"));
        a.record("parecord", "microphone", SOURCE_PIPEWIRE, 2, &t("2"));
        a.save_if_dirty();

        let b = Offenders::load(Some(path.clone()));
        let v = b.sorted();
        assert_eq!(v.len(), 2, "both rows must come back: {v:?}");
        assert_eq!(v[0].identity, "/usr/lib/firefox-esr/firefox-esr");
        assert_eq!(v[0].denied, 13);
        assert_eq!(v[0].first_seen, t("1"));

        // And a later denial must ADD to the reloaded count rather than
        // restarting it — otherwise every daemon restart silently resets the
        // history this table exists to accumulate.
        let mut c = Offenders::load(Some(path.clone()));
        c.record("/usr/lib/firefox-esr/firefox-esr", "camera", SOURCE_KERNEL, 1, &t("3"));
        assert_eq!(c.sorted()[0].denied, 14);
        assert_eq!(c.sorted()[0].first_seen, t("1"), "first_seen survives too");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A corrupt table must not take the daemon down with it. Enforcement is
    /// the job; these counters are an audit convenience.
    #[test]
    fn a_corrupt_table_starts_empty_instead_of_failing() {
        let dir = std::env::temp_dir().join(format!("hwp-off-bad-{}", std::process::id()));
        let path = dir.join("offenders.json");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(&path, "{ this is not json").unwrap();

        let o = Offenders::load(Some(path));
        assert!(o.sorted().is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
