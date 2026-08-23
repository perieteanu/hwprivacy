//! Who has touched a device, how often, and since when — across restarts.
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
//!
//! # Why it is no longer called `offenders`
//!
//! Renamed 2026-08-21. It now records ALLOWED access as well as denied, and
//! "offenders" was already the wrong word for the discovery-loop rows above.
//! The allowed column exists because of a measurement: firefox-esr opened the
//! camera twice in one morning with no video call, hwprivacy allowed it
//! correctly, and nothing anywhere recorded that it had happened.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;
use tracing::{debug, info, warn};

/// One (identity, device) pair that has been seen at least once.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryEntry {
    /// Executable path for kernel-layer denials, normalised application name
    /// for PipeWire ones. See [`Source`] — the two are not interchangeable and
    /// the table says which it is.
    pub identity: String,
    pub device: String,
    pub source: String,
    pub denied: u32,
    /// Times this access SUCCEEDED.
    ///
    /// `#[serde(default)]` so tables written before 2026-08-21 — which only
    /// ever counted denials — load with their history intact instead of being
    /// discarded as unparseable.
    #[serde(default)]
    pub allowed: u32,
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
pub struct History {
    by_key: BTreeMap<(String, String, String), HistoryEntry>,
    path: Option<PathBuf>,
    dirty: bool,
}

/// `$XDG_STATE_HOME/hwprivacy/history.json`, falling back to
/// `~/.local/state/...`.
///
/// Deliberately user-owned state, not `/var/lib`. The daemon is unprivileged
/// and this table must be readable without joining a group — the raw journal
/// already requires `systemd-journal`, and making the everyday view need
/// privileges too would put it out of reach of the person it is for.
pub fn default_path() -> Option<PathBuf> {
    Some(state_dir()?.join("history.json"))
}

/// Where the table lived before the 2026-08-21 rename.
///
/// Read once, at load, when the new file does not exist yet. This is not
/// tidiness: the live table holds months of accumulated counts that exist
/// nowhere else — the 500-entry event ring dies with the daemon and the journal
/// rotates. A rename that silently started from zero would destroy the only
/// long-window record the project has.
pub fn legacy_path() -> Option<PathBuf> {
    Some(state_dir()?.join("offenders.json"))
}

fn state_dir() -> Option<PathBuf> {
    let base = std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/state")))?;
    Some(base.join("hwprivacy"))
}

impl History {
    /// Load from disk, falling back to a pre-rename file when the current one
    /// is absent. Starting empty is normal (first run).
    ///
    /// A file that exists but does not parse is logged and then IGNORED rather
    /// than propagated: this is an audit convenience, and refusing to start the
    /// daemon because a statistics file went bad would trade enforcement for
    /// bookkeeping.
    ///
    /// The legacy fallback is READ-ONLY and one-directional: the old file is
    /// left exactly where it is, and the first save writes the new one. If
    /// anything about the migration is wrong, the original is still on disk.
    pub fn load_with_legacy(path: Option<PathBuf>, legacy: Option<PathBuf>) -> Self {
        let mut s = History {
            path,
            ..Default::default()
        };
        let Some(p) = s.path.clone() else {
            return s;
        };

        let (source, text) = match std::fs::read_to_string(&p) {
            Ok(t) => (p.clone(), Some(t)),
            Err(_) => match legacy.as_ref().and_then(|l| {
                std::fs::read_to_string(l).ok().map(|t| (l.clone(), t))
            }) {
                Some((l, t)) => {
                    info!(
                        "History: migrating {} -> {} (the table was renamed on 2026-08-21; \
                         the old file is left in place)",
                        l.display(),
                        p.display()
                    );
                    s.dirty = true; // force a write of the new file
                    (l, Some(t))
                }
                None => {
                    debug!("History: no table at {} yet", p.display());
                    return s;
                }
            },
        };

        match serde_json::from_str::<Vec<HistoryEntry>>(&text.unwrap_or_default()) {
            Ok(list) => {
                for o in list {
                    s.by_key.insert(
                        (o.identity.clone(), o.device.clone(), o.source.clone()),
                        o,
                    );
                }
                debug!("History: loaded {} entries from {}", s.by_key.len(), source.display());
            }
            Err(e) => warn!(
                "History: {} exists but could not be parsed ({e}). Starting a fresh \
                 table; the old file is left alone.",
                source.display()
            ),
        }

        // Write the new file NOW if we just migrated, rather than waiting for
        // the first access to make the table dirty. Nothing is lost either way
        // — the old file stays — but a daemon that says "migrating" in the
        // journal and leaves no new file on disk invites exactly the kind of
        // "did that actually work?" archaeology this project keeps doing.
        s.save_if_dirty();
        s
    }

    /// Record `count` DENIED accesses. `count` rather than one, because a
    /// coalesced kernel burst is a single event representing many opens —
    /// counting it as one would under-report exactly the persistent access this
    /// table exists to make visible.
    pub fn record_denied(&mut self, identity: &str, device: &str, source: &str, count: u32, now: &str) {
        self.record(identity, device, source, count, 0, now)
    }

    /// Record `count` ALLOWED accesses.
    ///
    /// Same shape, different column. An allowed row is not an alarm — it is the
    /// answer to "did anything use my camera on Tuesday", which was
    /// unanswerable while only denials were kept.
    pub fn record_allowed(&mut self, identity: &str, device: &str, source: &str, count: u32, now: &str) {
        self.record(identity, device, source, 0, count, now)
    }

    fn record(
        &mut self,
        identity: &str,
        device: &str,
        source: &str,
        denied: u32,
        allowed: u32,
        now: &str,
    ) {
        if denied == 0 && allowed == 0 {
            return;
        }
        let key = (identity.to_string(), device.to_string(), source.to_string());
        let e = self.by_key.entry(key).or_insert_with(|| HistoryEntry {
            identity: identity.to_string(),
            device: device.to_string(),
            source: source.to_string(),
            denied: 0,
            allowed: 0,
            first_seen: now.to_string(),
            last_seen: now.to_string(),
        });
        e.denied = e.denied.saturating_add(denied);
        e.allowed = e.allowed.saturating_add(allowed);
        e.last_seen = now.to_string();
        self.dirty = true;
    }

    /// Most persistent first — that ordering is the whole point.
    ///
    /// Denials lead, because "frequency is signal" (the one idea worth taking
    /// from fail2ban) is about attempts that were REFUSED. Allowed counts break
    /// the tie so a busy allowed app still sorts above a quiet one.
    pub fn sorted(&self) -> Vec<HistoryEntry> {
        let mut v: Vec<_> = self.by_key.values().cloned().collect();
        v.sort_by(|a, b| {
            b.denied
                .cmp(&a.denied)
                .then_with(|| b.allowed.cmp(&a.allowed))
                .then_with(|| a.identity.cmp(&b.identity))
        });
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
                warn!("History: cannot create {}: {e}", dir.display());
                return;
            }
        }
        let list = self.sorted();
        let json = match serde_json::to_string_pretty(&list) {
            Ok(j) => j,
            Err(e) => {
                warn!("History: cannot serialise: {e}");
                return;
            }
        };
        let tmp = p.with_extension("tmp");
        if let Err(e) = std::fs::write(&tmp, json) {
            warn!("History: cannot write {}: {e}", tmp.display());
            return;
        }
        if let Err(e) = std::fs::rename(&tmp, &p) {
            warn!("History: cannot rename into {}: {e}", p.display());
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
        let mut o = History::default();
        o.record_denied("/usr/bin/x", "camera", SOURCE_KERNEL, 1, &t("1"));
        o.record_denied("/usr/bin/x", "camera", SOURCE_KERNEL, 1, &t("2"));
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
        let mut o = History::default();
        o.record_denied("/usr/bin/x", "camera", SOURCE_KERNEL, 13, &t("1"));
        assert_eq!(o.sorted()[0].denied, 13);
    }

    /// The same program seen by both layers is two rows on purpose: the
    /// identities have different stability and merging them would imply a
    /// confidence the PipeWire name does not have.
    #[test]
    fn the_two_layers_are_counted_separately() {
        let mut o = History::default();
        o.record_denied("/usr/lib/firefox-esr/firefox-esr", "camera", SOURCE_KERNEL, 4, &t("1"));
        o.record_denied("firefox", "microphone", SOURCE_PIPEWIRE, 2, &t("1"));
        assert_eq!(o.sorted().len(), 2);
    }

    #[test]
    fn sorted_puts_the_most_persistent_first() {
        let mut o = History::default();
        o.record_denied("quiet", "camera", SOURCE_KERNEL, 1, &t("1"));
        o.record_denied("noisy", "camera", SOURCE_KERNEL, 50, &t("1"));
        assert_eq!(o.sorted()[0].identity, "noisy");
    }

    #[test]
    fn a_zero_count_records_nothing() {
        let mut o = History::default();
        o.record_denied("/usr/bin/x", "camera", SOURCE_KERNEL, 0, &t("1"));
        assert!(o.sorted().is_empty());
    }

    /// The whole reason this module exists. `tracker.events` is a 500-entry
    /// in-memory ring buffer that a restart wipes, which is why "who tried to
    /// connect, over the last few days" could not be answered at all. If this
    /// does not survive a reload, the feature is decorative.
    #[test]
    fn the_table_survives_a_reload() {
        let dir = std::env::temp_dir().join(format!("hwp-hist-{}", std::process::id()));
        let path = dir.join("offenders.json");
        let _ = std::fs::remove_dir_all(&dir);

        let mut a = History::load_with_legacy(Some(path.clone()), None);
        a.record_denied("/usr/lib/firefox-esr/firefox-esr", "camera", SOURCE_KERNEL, 13, &t("1"));
        a.record_denied("parecord", "microphone", SOURCE_PIPEWIRE, 2, &t("2"));
        a.save_if_dirty();

        let b = History::load_with_legacy(Some(path.clone()), None);
        let v = b.sorted();
        assert_eq!(v.len(), 2, "both rows must come back: {v:?}");
        assert_eq!(v[0].identity, "/usr/lib/firefox-esr/firefox-esr");
        assert_eq!(v[0].denied, 13);
        assert_eq!(v[0].first_seen, t("1"));

        // And a later denial must ADD to the reloaded count rather than
        // restarting it — otherwise every daemon restart silently resets the
        // history this table exists to accumulate.
        let mut c = History::load_with_legacy(Some(path.clone()), None);
        c.record_denied("/usr/lib/firefox-esr/firefox-esr", "camera", SOURCE_KERNEL, 1, &t("3"));
        assert_eq!(c.sorted()[0].denied, 14);
        assert_eq!(c.sorted()[0].first_seen, t("1"), "first_seen survives too");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Allowed and denied are separate columns on ONE row. The same app both
    /// succeeding and being refused is one story about that app, not two.
    #[test]
    fn allowed_and_denied_accumulate_independently() {
        let mut h = History::default();
        h.record_denied("/usr/lib/firefox-esr/firefox-esr", "camera", SOURCE_KERNEL, 4, &t("1"));
        h.record_allowed("/usr/lib/firefox-esr/firefox-esr", "camera", SOURCE_KERNEL, 2, &t("2"));
        let v = h.sorted();
        assert_eq!(v.len(), 1, "one row: {v:?}");
        assert_eq!(v[0].denied, 4);
        assert_eq!(v[0].allowed, 2);
        assert_eq!(v[0].first_seen, t("1"), "first_seen must not move");
        assert_eq!(v[0].last_seen, t("2"));
    }

    /// An allowed access must never inflate the denied column — that column is
    /// the alarming one and the whole sort order depends on it.
    #[test]
    fn an_allowed_access_does_not_count_as_a_denial() {
        let mut h = History::default();
        h.record_allowed("/usr/bin/x", "camera", SOURCE_KERNEL, 9, &t("1"));
        assert_eq!(h.sorted()[0].denied, 0);
        assert_eq!(h.sorted()[0].allowed, 9);
    }

    #[test]
    fn denials_sort_above_allows() {
        let mut h = History::default();
        h.record_allowed("busy-but-allowed", "camera", SOURCE_KERNEL, 500, &t("1"));
        h.record_denied("denied-once", "camera", SOURCE_KERNEL, 1, &t("1"));
        assert_eq!(h.sorted()[0].identity, "denied-once");
    }

    /// **The migration.** The live table on 2026-08-21 held months of counts
    /// that exist nowhere else — the event ring dies with the daemon and the
    /// journal rotates. A rename that quietly started from zero would destroy
    /// the only long-window record the project has, and it would look like
    /// nothing had happened.
    #[test]
    fn a_pre_rename_table_is_migrated_with_its_counts_intact() {
        let dir = std::env::temp_dir().join(format!("hwp-migrate-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let legacy = dir.join("offenders.json");
        let current = dir.join("history.json");

        // Exactly the shape the old code wrote: no `allowed` field at all.
        std::fs::write(&legacy, r#"[
          {"identity":"/home/perieteanu/firefox-developer/firefox-bin",
           "device":"camera","source":"kernel","denied":42,
           "first_seen":"2026-08-20 08:06:49","last_seen":"2026-08-23 15:55:34"}
        ]"#).unwrap();

        let mut h = History::load_with_legacy(Some(current.clone()), Some(legacy.clone()));
        let v = h.sorted();
        assert_eq!(v.len(), 1, "the old row must survive: {v:?}");
        assert_eq!(v[0].denied, 42, "the count is the thing that must not be lost");
        assert_eq!(v[0].allowed, 0, "a column that did not exist reads as zero");
        assert_eq!(v[0].first_seen, "2026-08-20 08:06:49");

        // The first save writes the NEW file and leaves the old one alone, so
        // a bad migration is recoverable.
        h.save_if_dirty();
        assert!(current.exists(), "the new file must be written on migration");
        assert!(legacy.exists(), "the old file must be left in place");

        // And a reload now prefers the new file.
        let again = History::load_with_legacy(Some(current), Some(legacy));
        assert_eq!(again.sorted()[0].denied, 42);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The legacy file must be read ONLY when the current one is absent —
    /// otherwise a stale copy could resurrect and overwrite newer counts.
    #[test]
    fn the_legacy_file_is_ignored_once_the_new_one_exists() {
        let dir = std::env::temp_dir().join(format!("hwp-nomig-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let legacy = dir.join("offenders.json");
        let current = dir.join("history.json");

        std::fs::write(&legacy, r#"[{"identity":"stale","device":"camera",
          "source":"kernel","denied":999,"first_seen":"x","last_seen":"x"}]"#).unwrap();
        std::fs::write(&current, r#"[{"identity":"fresh","device":"camera",
          "source":"kernel","denied":1,"allowed":7,"first_seen":"y","last_seen":"y"}]"#).unwrap();

        let h = History::load_with_legacy(Some(current), Some(legacy));
        let v = h.sorted();
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].identity, "fresh");
        assert_eq!(v[0].allowed, 7);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A corrupt table must not take the daemon down with it. Enforcement is
    /// the job; these counters are an audit convenience.
    #[test]
    fn a_corrupt_table_starts_empty_instead_of_failing() {
        let dir = std::env::temp_dir().join(format!("hwp-hist-bad-{}", std::process::id()));
        let path = dir.join("offenders.json");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(&path, "{ this is not json").unwrap();

        let o = History::load_with_legacy(Some(path), None);
        assert!(o.sorted().is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
