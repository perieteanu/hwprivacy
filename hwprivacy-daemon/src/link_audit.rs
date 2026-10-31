//! Every link is accounted for.
//!
//! # Why this exists
//!
//! From 2026-09-02 to 2026-10-31 a link on a reused id was never evaluated,
//! because `GraphState` dropped every removal and so never called it new. That
//! wrote nothing: a line was only ever produced AFTER a link had been reported
//! new and recognised as touching a device. The defect could not be seen from
//! the journal, and what got through in those two months cannot be reconstructed.
//!
//! So "every live link on a protected device has a recorded decision" is no
//! longer something the loop assumes. This ledger is what it decides from: each
//! graph update, a live link with no decision for its (id, serial) gets one,
//! however it came to be missed, and the miss is reported instead of silent.
//!
//! A DENIED line had the same problem in the other direction. Live, 2026-10-31:
//! DENIED logged, link 110 destroyed, link 96 of the same stream still flowing.
//! [`verify_denial`] checks the graph afterwards.
//!
//! # What it cannot do
//!
//! Nothing is recorded while the daemon is stopped. The journal shows those
//! gaps, and a restart re-seeds and evaluates what is live.

use crate::pipewire_monitor::{GraphSnapshot, NodeInfo, PwLink};
use crate::policy_engine::{classify_link, LinkMatch};
use hwprivacy_common::device::ProtectedDevice;
use std::collections::HashMap;
use std::future::Future;
use std::time::Duration;

/// A link's identity. The id alone is not one: PipeWire reuses ids within
/// seconds, while `object.serial` is never reused.
pub type LinkKey = (u32, Option<u64>);

/// How a link came to need a decision. Anything but `New` means the path that
/// should have delivered it failed, or that it could not be classified in time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecideReason {
    New,
    /// Seen earlier, and only now recognised: its node, its ports or the device
    /// arrived after it did.
    ClassifiedLate,
    /// The id is held by a different serial with no removal seen in between.
    /// This is the 2026-09-02 defect, caught.
    ReusedIdNoRemoval,
    /// Live and undecided, yet the graph never reported it as new.
    NotReportedNew,
}

/// A link the caller must now decide.
#[derive(Debug, Clone)]
pub struct Pending {
    pub key: LinkKey,
    pub link_match: LinkMatch,
    /// The reason is already in the journal line; this is for asserting on.
    #[cfg_attr(not(test), allow(dead_code))]
    pub reason: DecideReason,
}

/// One journal line. Returned rather than logged so a test can assert on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkLine {
    pub warn: bool,
    pub text: String,
}

#[derive(Debug, Default)]
pub struct Reconciled {
    pub pending: Vec<Pending>,
    pub lines: Vec<LinkLine>,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct LinkCounts {
    pub seen: u64,
    pub protected: u64,
    pub decided_late: u64,
    pub denied_alive: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EntryState {
    /// Seen, but one of its nodes is not known yet, so nothing can be said.
    Waiting,
    /// Has its line: neither end is a protected device.
    NotProtected,
    /// Handed to the decision path.
    Decided,
}

#[derive(Debug)]
struct Entry {
    serial: Option<u64>,
    state: EntryState,
}

#[derive(Debug, Default)]
pub struct LinkLedger {
    entries: HashMap<u32, Entry>,
    pub counts: LinkCounts,
}

impl LinkLedger {
    /// A monitor respawn means PipeWire restarted, and ids AND serials start
    /// over with it. A decision kept across that could match a different link
    /// with the same pair. The counts are the daemon's, and stay.
    pub fn forget(&mut self) {
        self.entries.clear();
    }

    /// Bring the ledger up to date with the graph, returning what needs deciding.
    ///
    /// A link is marked decided here, before the decision runs. `destroy_links`
    /// awaits external commands, and the next update must not decide it again.
    pub fn reconcile(
        &mut self,
        snapshot: &GraphSnapshot,
        new_ids: &[u32],
        devices: &[ProtectedDevice],
    ) -> Reconciled {
        let mut out = Reconciled::default();

        let live: HashMap<u32, Option<u64>> =
            snapshot.links.iter().map(|l| (l.link_id, l.serial)).collect();
        self.entries.retain(|id, entry| {
            if live.contains_key(id) {
                return true;
            }
            // Its one line, if it never got as far as having one.
            if entry.state == EntryState::Waiting {
                out.lines.push(LinkLine {
                    warn: false,
                    text: format!(
                        "Link {id} serial {}: ended before its nodes were known",
                        serial_text(entry.serial)
                    ),
                });
            }
            false
        });

        for link in &snapshot.links {
            let prior = self
                .entries
                .get(&link.link_id)
                .map(|e| (e.serial, e.state));
            let reused = matches!(
                (prior.and_then(|p| p.0), link.serial),
                (Some(old), Some(new)) if old != new
            );
            let prior_state = if reused { None } else { prior.map(|p| p.1) };

            if prior_state == Some(EntryState::Decided) {
                continue;
            }

            let first_sighting = prior_state.is_none();
            if first_sighting {
                self.counts.seen += 1;
            }

            let link_match = classify_link(
                link.output_node,
                link.output_port,
                link.input_node,
                link.input_port,
                &snapshot.nodes,
                &snapshot.ports,
                devices,
            );

            let state = if let Some(link_match) = link_match {
                let reason = if reused {
                    DecideReason::ReusedIdNoRemoval
                } else if !first_sighting {
                    DecideReason::ClassifiedLate
                } else if new_ids.contains(&link.link_id) {
                    DecideReason::New
                } else {
                    DecideReason::NotReportedNew
                };
                self.counts.protected += 1;
                if reason != DecideReason::New {
                    self.counts.decided_late += 1;
                }
                out.lines.push(decision_line(link, &link_match, reason, snapshot));
                out.pending.push(Pending {
                    key: (link.link_id, link.serial),
                    link_match,
                    reason,
                });
                EntryState::Decided
            } else if prior_state == Some(EntryState::NotProtected) {
                EntryState::NotProtected
            } else if both_nodes_known(link, snapshot) {
                out.lines.push(LinkLine {
                    warn: false,
                    text: format!(
                        "{}: not a protected device",
                        link_label(link, snapshot)
                    ),
                });
                EntryState::NotProtected
            } else {
                EntryState::Waiting
            };

            self.entries.insert(
                link.link_id,
                Entry {
                    serial: link.serial,
                    state,
                },
            );
        }

        out
    }

    /// Which of these links are still in the graph, as the SAME link. A reused
    /// id with a new serial is somebody else, and must not be destroyed.
    pub fn still_alive(&self, links: &[LinkKey]) -> Vec<LinkKey> {
        links
            .iter()
            .filter(|(id, serial)| {
                self.entries
                    .get(id)
                    .is_some_and(|entry| entry.serial == *serial)
            })
            .copied()
            .collect()
    }
}

/// After destroying denied links: wait, check, retry once, check again. Returns
/// the links that could not be stopped.
///
/// The check and the destroy are passed in because the real ones need the daemon
/// state and a running PipeWire, and a failed destroy cannot be produced live.
pub async fn verify_denial<A, AF, D, DF>(
    grace: Duration,
    links: Vec<LinkKey>,
    mut alive: A,
    mut destroy: D,
) -> Vec<LinkKey>
where
    A: FnMut(Vec<LinkKey>) -> AF,
    AF: Future<Output = Vec<LinkKey>>,
    D: FnMut(Vec<u32>) -> DF,
    DF: Future<Output = ()>,
{
    tokio::time::sleep(grace).await;
    let survivors = alive(links).await;
    if survivors.is_empty() {
        return survivors;
    }
    destroy(survivors.iter().map(|(id, _)| *id).collect()).await;
    tokio::time::sleep(grace).await;
    alive(survivors).await
}

fn serial_text(serial: Option<u64>) -> String {
    serial.map_or_else(|| "?".to_string(), |s| s.to_string())
}

fn both_nodes_known(link: &PwLink, snapshot: &GraphSnapshot) -> bool {
    snapshot.nodes.contains_key(&link.output_node) && snapshot.nodes.contains_key(&link.input_node)
}

/// `media_name` stays out of this on purpose: it holds page and meeting titles,
/// and the journal does not need them to account for a link.
fn node_label(node_id: u32, snapshot: &GraphSnapshot) -> String {
    match snapshot.nodes.get(&node_id) {
        Some(NodeInfo {
            media_class,
            app_name,
            ..
        }) if media_class.starts_with("Stream") && !app_name.is_empty() => app_name.clone(),
        Some(node) => node.node_name.clone(),
        None => format!("node {node_id}"),
    }
}

fn link_label(link: &PwLink, snapshot: &GraphSnapshot) -> String {
    format!(
        "Link {} serial {}: {} → {}",
        link.link_id,
        serial_text(link.serial),
        node_label(link.output_node, snapshot),
        node_label(link.input_node, snapshot)
    )
}

fn decision_line(
    link: &PwLink,
    link_match: &LinkMatch,
    reason: DecideReason,
    snapshot: &GraphSnapshot,
) -> LinkLine {
    let label = link_label(link, snapshot);
    let category = link_match.device.category;
    match reason {
        DecideReason::New => LinkLine {
            warn: false,
            text: format!("{label}: protected ({category:?}), deciding"),
        },
        DecideReason::ClassifiedLate => LinkLine {
            warn: true,
            text: format!(
                "{label}: protected ({category:?}), DECIDED LATE: only now recognised as protected"
            ),
        },
        DecideReason::ReusedIdNoRemoval => LinkLine {
            warn: true,
            text: format!(
                "{label}: protected ({category:?}), DECIDED LATE: id reused with no removal seen"
            ),
        },
        DecideReason::NotReportedNew => LinkLine {
            warn: true,
            text: format!(
                "{label}: protected ({category:?}), DECIDED LATE: the graph never reported it as new"
            ),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hwprivacy_common::DeviceCategory;
    use std::cell::RefCell;
    use std::collections::HashSet;

    const MIC: u32 = 46;
    const APP: u32 = 72;
    const SINK: u32 = 36;

    fn node(id: u32, media_class: &str, node_name: &str, app: &str) -> NodeInfo {
        NodeInfo {
            id,
            media_class: media_class.into(),
            node_name: node_name.into(),
            app_name: app.into(),
            pid: 1234,
            media_name: "private meeting title".into(),
        }
    }

    fn devices() -> Vec<ProtectedDevice> {
        vec![ProtectedDevice {
            category: DeviceCategory::Microphone,
            node_name: "alsa_input.analog-stereo".into(),
            description: "Built-in".into(),
            object_serial: 0,
            guarded: true,
        }]
    }

    fn mic_link(id: u32, serial: u64) -> PwLink {
        PwLink {
            link_id: id,
            serial: Some(serial),
            output_node: MIC,
            output_port: 1,
            input_node: APP,
            input_port: 2,
        }
    }

    fn playback_link(id: u32, serial: u64) -> PwLink {
        PwLink {
            link_id: id,
            serial: Some(serial),
            output_node: APP,
            output_port: 2,
            input_node: SINK,
            input_port: 3,
        }
    }

    fn graph(links: Vec<PwLink>) -> GraphSnapshot {
        GraphSnapshot {
            nodes: HashMap::from([
                (MIC, node(MIC, "Audio/Source", "alsa_input.analog-stereo", "")),
                (APP, node(APP, "Stream/Input/Audio", "firefox-in", "Firefox")),
                (SINK, node(SINK, "Audio/Sink", "alsa_output.analog-stereo", "")),
            ]),
            ports: HashMap::new(),
            links,
        }
    }

    fn reasons(r: &Reconciled) -> Vec<DecideReason> {
        r.pending.iter().map(|p| p.reason).collect()
    }

    #[test]
    fn a_new_link_on_a_protected_device_is_decided_once() {
        let mut ledger = LinkLedger::default();
        let g = graph(vec![mic_link(96, 935)]);

        let first = ledger.reconcile(&g, &[96], &devices());
        assert_eq!(reasons(&first), vec![DecideReason::New]);
        assert_eq!(first.pending[0].key, (96, Some(935)));

        let second = ledger.reconcile(&g, &[], &devices());
        assert!(second.pending.is_empty(), "a decided link is not decided again");
        assert_eq!(ledger.counts.seen, 1);
        assert_eq!(ledger.counts.protected, 1);
        assert_eq!(ledger.counts.decided_late, 0);
    }

    /// The 2026-09-02 defect itself: the removal never arrives, and the same id
    /// comes back as a different link. Evaluated anyway, and reported.
    #[test]
    fn a_reused_id_is_decided_even_if_the_removal_was_lost() {
        let mut ledger = LinkLedger::default();
        ledger.reconcile(&graph(vec![mic_link(96, 935)]), &[96], &devices());

        let again = ledger.reconcile(&graph(vec![mic_link(96, 942)]), &[], &devices());
        assert_eq!(reasons(&again), vec![DecideReason::ReusedIdNoRemoval]);
        assert_eq!(ledger.counts.decided_late, 1);
        assert!(again.lines[0].warn, "a caught miss must not read as routine");
    }

    /// Whatever the reason the graph did not call it new, a live undecided link
    /// on a protected device gets a decision.
    #[test]
    fn a_link_the_graph_never_reported_is_still_decided() {
        let mut ledger = LinkLedger::default();
        let r = ledger.reconcile(&graph(vec![mic_link(96, 935)]), &[], &devices());
        assert_eq!(reasons(&r), vec![DecideReason::NotReportedNew]);
        assert_eq!(ledger.counts.decided_late, 1);
    }

    /// Classified once and never again was a hole of its own: a link seen before
    /// its node was known got no decision, ever.
    #[test]
    fn a_link_seen_before_its_node_is_decided_when_the_node_arrives() {
        let mut ledger = LinkLedger::default();
        let mut early = graph(vec![mic_link(96, 935)]);
        early.nodes.remove(&APP);

        let first = ledger.reconcile(&early, &[96], &devices());
        assert!(first.pending.is_empty());
        assert!(first.lines.is_empty(), "nothing true can be said about it yet");

        let late = ledger.reconcile(&graph(vec![mic_link(96, 935)]), &[], &devices());
        assert_eq!(reasons(&late), vec![DecideReason::ClassifiedLate]);
        assert_eq!(ledger.counts.seen, 1, "the same link, counted once");
    }

    /// A device discovered after the link existed.
    #[test]
    fn a_link_noted_as_unprotected_is_decided_if_its_device_appears() {
        let mut ledger = LinkLedger::default();
        let g = graph(vec![mic_link(96, 935)]);

        let before = ledger.reconcile(&g, &[96], &[]);
        assert!(before.pending.is_empty());

        let after = ledger.reconcile(&g, &[], &devices());
        assert_eq!(reasons(&after), vec![DecideReason::ClassifiedLate]);
    }

    #[test]
    fn every_other_link_gets_one_line_once() {
        let mut ledger = LinkLedger::default();
        let g = graph(vec![playback_link(75, 80)]);

        let first = ledger.reconcile(&g, &[75], &devices());
        assert!(first.pending.is_empty());
        assert_eq!(first.lines.len(), 1);
        assert!(!first.lines[0].warn);
        assert!(first.lines[0].text.contains("Link 75 serial 80"));
        assert!(first.lines[0].text.contains("not a protected device"));

        assert!(ledger.reconcile(&g, &[], &devices()).lines.is_empty());
        assert_eq!(ledger.counts.seen, 1);
        assert_eq!(ledger.counts.protected, 0);
    }

    #[test]
    fn a_link_that_never_resolved_still_leaves_a_line() {
        let mut ledger = LinkLedger::default();
        let mut early = graph(vec![mic_link(96, 935)]);
        early.nodes.remove(&APP);
        ledger.reconcile(&early, &[96], &devices());

        let gone = ledger.reconcile(&graph(vec![]), &[], &devices());
        assert_eq!(gone.lines.len(), 1);
        assert!(gone.lines[0].text.contains("Link 96 serial 935"));
    }

    /// Ids and serials both restart with PipeWire, so a decision surviving that
    /// could match a different link with the same pair and skip it.
    #[test]
    fn a_reseed_forgets_decisions_and_keeps_counts() {
        let mut ledger = LinkLedger::default();
        let g = graph(vec![mic_link(96, 935)]);
        ledger.reconcile(&g, &[96], &devices());

        ledger.forget();
        let r = ledger.reconcile(&g, &[96], &devices());
        assert_eq!(reasons(&r), vec![DecideReason::New]);
        assert_eq!(ledger.counts.protected, 2);
    }

    #[test]
    fn ended_links_leave_the_ledger_so_a_proper_reuse_is_simply_new() {
        let mut ledger = LinkLedger::default();
        ledger.reconcile(&graph(vec![mic_link(96, 935)]), &[96], &devices());
        ledger.reconcile(&graph(vec![]), &[], &devices());

        let r = ledger.reconcile(&graph(vec![mic_link(96, 942)]), &[96], &devices());
        assert_eq!(reasons(&r), vec![DecideReason::New]);
        assert_eq!(ledger.counts.decided_late, 0);
    }

    /// `media_name` carries page and meeting titles.
    #[test]
    fn a_line_never_carries_the_media_name() {
        let mut ledger = LinkLedger::default();
        let r = ledger.reconcile(&graph(vec![mic_link(96, 935)]), &[96], &devices());
        assert!(r.lines.iter().all(|l| !l.text.contains("private meeting title")));
    }

    #[test]
    fn still_alive_tells_a_reused_id_from_the_same_link() {
        let mut ledger = LinkLedger::default();
        ledger.reconcile(&graph(vec![mic_link(96, 942)]), &[96], &devices());

        assert_eq!(ledger.still_alive(&[(96, Some(942))]), vec![(96, Some(942))]);
        assert!(ledger.still_alive(&[(96, Some(935))]).is_empty(), "a reused id");
        assert!(ledger.still_alive(&[(97, Some(942))]).is_empty(), "gone");
    }

    /// Simulates the graph: a destroy that works removes the link.
    async fn run_verify(destroy_works: bool, already_dead: bool) -> (Vec<LinkKey>, usize) {
        let live: RefCell<HashSet<LinkKey>> = RefCell::new(if already_dead {
            HashSet::new()
        } else {
            HashSet::from([(96, Some(942))])
        });
        let destroys = RefCell::new(0);
        let survivors = verify_denial(
            Duration::ZERO,
            vec![(96, Some(942))],
            |keys: Vec<LinkKey>| {
                let found: Vec<LinkKey> = keys
                    .into_iter()
                    .filter(|k| live.borrow().contains(k))
                    .collect();
                async move { found }
            },
            |_ids: Vec<u32>| {
                *destroys.borrow_mut() += 1;
                if destroy_works {
                    live.borrow_mut().clear();
                }
                async {}
            },
        )
        .await;
        let count = *destroys.borrow();
        (survivors, count)
    }

    #[tokio::test]
    async fn a_link_that_died_is_not_touched_again() {
        let (survivors, destroys) = run_verify(true, true).await;
        assert!(survivors.is_empty());
        assert_eq!(destroys, 0);
    }

    #[tokio::test]
    async fn a_surviving_link_gets_one_retry() {
        let (survivors, destroys) = run_verify(true, false).await;
        assert!(survivors.is_empty());
        assert_eq!(destroys, 1);
    }

    #[tokio::test]
    async fn a_link_that_cannot_be_destroyed_is_reported() {
        let (survivors, destroys) = run_verify(false, false).await;
        assert_eq!(survivors, vec![(96, Some(942))]);
        assert_eq!(destroys, 1);
    }
}
