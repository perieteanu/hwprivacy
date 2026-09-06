use anyhow::{Context, Result};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use tokio::process::Command;
use tracing::{debug, info, trace, warn};

/// Represents a PipeWire link between two nodes.
#[derive(Debug, Clone)]
pub struct PwLink {
    pub link_id: u32,
    pub output_node: u32,
    pub output_port: u32,
    pub input_node: u32,
    pub input_port: u32,
}

/// A snapshot of the PipeWire graph relevant to our monitoring.
#[derive(Debug, Default)]
pub struct GraphSnapshot {
    /// All nodes: id → properties
    pub nodes: HashMap<u32, NodeInfo>,
    /// All ports: id → properties. Needed to tell one microphone from another
    /// — a stereo capture device exposes `capture_FL` and `capture_FR`, and the
    /// port is the only thing distinguishing the two links.
    pub ports: HashMap<u32, PortInfo>,
    /// All active links
    pub links: Vec<PwLink>,
}

#[derive(Debug, Clone)]
pub struct NodeInfo {
    pub id: u32,
    pub media_class: String,
    pub node_name: String,
    pub app_name: String,
    pub pid: u32,
    pub media_name: String,
}

/// One port on a node.
///
/// `name` is the stable identity — `capture_FL`, `monitor_FR`. Port **ids** are
/// allocated per session and must never be used to order or identify a port
/// that a rule or a label will refer to.
#[derive(Debug, Clone)]
pub struct PortInfo {
    pub id: u32,
    pub node_id: u32,
    pub name: String,
    /// "in" or "out", as PipeWire reports it.
    pub direction: String,
}

/// The PipeWire graph, maintained incrementally from `pw-dump --monitor`.
///
/// # Why the daemon owns the graph now
///
/// `capture_graph()` spawns `pw-dump`, and spawning it twice a second was
/// **62% of layer 1's entire idle cost** — 1.74% of a core out of 2.70-2.82%,
/// measured 2026-09-01 with no daemon involved. The work is fork/exec plus a
/// PipeWire connect/enumerate/disconnect, not the parsing.
///
/// `pw-dump --monitor` is one long-lived process: **0.031%** idle, a 56x
/// reduction, and it reports a new link **11 ms** after it appears instead of
/// somewhere in a 0-500 ms poll window.
///
/// The cost is that the graph is no longer handed to us complete on every
/// tick. This type is what replaces that.
///
/// # The wire format
///
/// * **block 0** is a COMPLETE snapshot — the same shape `capture_graph()`
///   returns. That is what makes seeding and re-seeding trivial.
/// * every later block carries only changed objects, typically 1-7.
/// * a removal is the object with `"info": null`. There is no other delete
///   signal, and missing one means an object that never goes away — a link
///   that never releases, a session that never ends.
#[derive(Debug, Default)]
pub struct GraphState {
    nodes: HashMap<u32, NodeInfo>,
    ports: HashMap<u32, PortInfo>,
    /// Keyed by link id, unlike `GraphSnapshot::links` which is a Vec. An
    /// incremental stream updates objects by id, so a Vec would accumulate
    /// duplicates on every state change of the same link — and PipeWire emits
    /// several per link (negotiating, then active).
    links: HashMap<u32, PwLink>,
    /// Client props by id, for `parse_node`'s fallback. Kept across blocks
    /// because a later block can carry a Node whose Client arrived in block 0.
    client_props: HashMap<u32, Value>,
}

impl GraphState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Forget everything. Used when the monitor is respawned.
    ///
    /// Re-seeding rather than merging is deliberate: PipeWire object ids are
    /// NOT stable across a server restart, so merging a pre-restart graph into
    /// a post-restart one leaves dead ids that a new object can later reuse.
    /// That is blocker b2 — a stale id eventually authorising somebody else.
    pub fn clear(&mut self) {
        self.nodes.clear();
        self.ports.clear();
        self.links.clear();
        self.client_props.clear();
    }

    /// Apply one block from the monitor stream. Returns the ids of links that
    /// are NEW to the graph, in this block.
    ///
    /// Returning only the new ones is what replaces `diff_links()`: the caller
    /// no longer has a previous snapshot to compare against, and re-reporting a
    /// link that merely changed state would re-prompt for an access already
    /// decided.
    pub fn apply_block(&mut self, objects: &[Value]) -> Vec<u32> {
        // Clients first, within the block, so a Node arriving alongside its
        // Client can still resolve it.
        for obj in objects {
            if obj.get("type").and_then(|t| t.as_str()) == Some("PipeWire:Interface:Client") {
                let id = obj.get("id").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
                match obj.get("info") {
                    Some(Value::Null) | None => {
                        self.client_props.remove(&id);
                    }
                    Some(info) => {
                        if let Some(props) = info.get("props") {
                            self.client_props.insert(id, props.clone());
                        }
                    }
                }
            }
        }

        let clients: HashMap<u32, &Value> =
            self.client_props.iter().map(|(k, v)| (*k, v)).collect();

        let mut new_links = Vec::new();

        for obj in objects {
            let obj_type = obj.get("type").and_then(|t| t.as_str()).unwrap_or("");
            let id = obj.get("id").and_then(|v| v.as_u64()).unwrap_or(0) as u32;

            // `"info": null` is a REMOVAL. Checked before anything else,
            // because every parse_* below would simply return None on it and
            // the object would silently persist forever.
            let removed = matches!(obj.get("info"), Some(Value::Null));

            match obj_type {
                "PipeWire:Interface:Node" => {
                    if removed {
                        self.nodes.remove(&id);
                    } else if let Some(info) = parse_node(id, obj, &clients) {
                        self.nodes.insert(id, info);
                    }
                }
                "PipeWire:Interface:Port" => {
                    if removed {
                        self.ports.remove(&id);
                    } else if let Some(port) = parse_port(id, obj) {
                        self.ports.insert(id, port);
                    }
                }
                "PipeWire:Interface:Link" => {
                    if removed {
                        self.links.remove(&id);
                    } else if let Some(link) = parse_link(id, obj) {
                        // New only if the graph had never seen this id. A link
                        // emits several blocks as it negotiates, and each is an
                        // update, not a new access.
                        if self.links.insert(id, link).is_none() {
                            new_links.push(id);
                        }
                    }
                }
                _ => {}
            }
        }

        new_links
    }

    /// The graph as a snapshot, for code that still wants one.
    ///
    /// Everything downstream — classify_link, group_links, the prune step —
    /// already takes this shape, which is why the substrate could change
    /// without touching policy, enforcement or the frontends.
    pub fn snapshot(&self) -> GraphSnapshot {
        GraphSnapshot {
            nodes: self.nodes.clone(),
            ports: self.ports.clone(),
            links: self.links.values().cloned().collect(),
        }
    }

    pub fn link_ids(&self) -> HashSet<u32> {
        self.links.keys().copied().collect()
    }

    pub fn node_ids(&self) -> HashSet<u32> {
        self.nodes.keys().copied().collect()
    }

    pub fn counts(&self) -> (usize, usize, usize) {
        (self.nodes.len(), self.ports.len(), self.links.len())
    }
}

/// Capture the current PipeWire graph state via pw-dump.
pub async fn capture_graph() -> Result<GraphSnapshot> {
    let output = Command::new("pw-dump")
        .output()
        .await
        .context("Failed to run pw-dump")?;

    if !output.status.success() {
        anyhow::bail!("pw-dump failed: {}", String::from_utf8_lossy(&output.stderr));
    }

    let json: Value = serde_json::from_slice(&output.stdout)
        .context("Failed to parse pw-dump JSON")?;

    let objects = json.as_array().context("pw-dump output is not an array")?;

    let mut snapshot = GraphSnapshot::default();

    // Pass 1: index client objects by id so nodes can fall back to their
    // client's props when node-level identity is thin (common for
    // pipewire-pulse bridge clients).
    let mut clients: HashMap<u32, &Value> = HashMap::new();
    for obj in objects {
        if obj.get("type").and_then(|t| t.as_str()) == Some("PipeWire:Interface:Client") {
            let id = obj.get("id").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
            if let Some(props) = obj.get("info").and_then(|i| i.get("props")) {
                clients.insert(id, props);
            }
        }
    }

    // Pass 2: nodes and links.
    for obj in objects {
        let obj_type = obj.get("type").and_then(|t| t.as_str()).unwrap_or("");
        let id = obj.get("id").and_then(|v| v.as_u64()).unwrap_or(0) as u32;

        match obj_type {
            "PipeWire:Interface:Node" => {
                if let Some(info) = parse_node(id, obj, &clients) {
                    snapshot.nodes.insert(id, info);
                }
            }
            "PipeWire:Interface:Port" => {
                if let Some(port) = parse_port(id, obj) {
                    snapshot.ports.insert(id, port);
                }
            }
            "PipeWire:Interface:Link" => {
                if let Some(link) = parse_link(id, obj) {
                    snapshot.links.push(link);
                }
            }
            _ => {}
        }
    }

    trace!(
        "Graph snapshot: {} nodes, {} ports, {} links",
        snapshot.nodes.len(),
        snapshot.ports.len(),
        snapshot.links.len()
    );

    Ok(snapshot)
}

fn parse_node(id: u32, obj: &Value, clients: &HashMap<u32, &Value>) -> Option<NodeInfo> {
    let node_props = obj.get("info")?.get("props")?;

    // Resolve the owning client's props, if any, so we can fall back to them
    // for fields the node itself doesn't carry.
    let client_props: Option<&Value> = node_props
        .get("client.id")
        .and_then(prop_as_u32)
        .and_then(|cid| clients.get(&cid).copied());

    // Look up `key` on the node first, then on the client.
    let lookup = |key: &str| -> Option<&Value> {
        node_props
            .get(key)
            .or_else(|| client_props.and_then(|p| p.get(key)))
    };

    let media_class = lookup("media.class")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let node_name = lookup("node.name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let media_name = node_props
        .get("media.name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    // PID: accept either a JSON number or a JSON string. `pw-dump` is
    // inconsistent here and older code only handled the string case, which
    // silently reported pid:0. Prefer the server-attested `pipewire.sec.pid`
    // over the client-reported `application.process.id` when present.
    let pid = lookup("pipewire.sec.pid")
        .or_else(|| lookup("application.process.id"))
        .and_then(prop_as_u32)
        .unwrap_or(0);

    // Build the best-effort human label.
    let portal_app = lookup("pipewire.access.portal.app_id")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let pw_app = lookup("application.name")
        .or_else(|| lookup("application.process.binary"))
        .or_else(|| lookup("node.description"))
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(str::to_string);

    // /proc enrichment — cheap, sync, best-effort. Only if we have a PID.
    let (proc_exe, proc_unit) = if pid > 0 {
        (proc_exe_basename(pid), proc_cgroup_unit(pid))
    } else {
        (None, None)
    };

    // Priority: portal app id > pipewire app name > /proc exe > cgroup unit.
    let mut app_name = portal_app
        .or(pw_app)
        .or(proc_exe.clone())
        .or(proc_unit.clone())
        .unwrap_or_default();

    // If we identified via proc but the label is just the unit, keep it;
    // if we had a pipewire name but also know the unit, annotate it so the
    // notification shows e.g. "Firefox [app-flatpak-org.mozilla.firefox]".
    if let Some(unit) = proc_unit.as_deref() {
        if !app_name.is_empty() && !app_name.contains(unit) && Some(&app_name) != proc_unit.as_ref() {
            app_name = format!("{app_name} [{unit}]");
        }
    }

    if app_name.is_empty() {
        debug!(
            node_id = id,
            pid,
            client_id = ?node_props.get("client.id").and_then(prop_as_u32),
            "Node has no identifiable app_name; node props: {}",
            node_props
        );
        app_name = "unknown".to_string();
    }

    Some(NodeInfo {
        id,
        media_class,
        node_name,
        app_name,
        pid,
        media_name,
    })
}

/// Parse a PipeWire prop that may be either a JSON number or a stringified
/// number into a `u32`.
fn prop_as_u32(v: &Value) -> Option<u32> {
    v.as_u64()
        .map(|n| n as u32)
        .or_else(|| v.as_str().and_then(|s| s.parse::<u32>().ok()))
}

/// Best-effort: basename of `/proc/<pid>/exe`. Returns None if the process
/// already exited or the symlink isn't readable (e.g. different user).
fn proc_exe_basename(pid: u32) -> Option<String> {
    let path = std::fs::read_link(format!("/proc/{pid}/exe")).ok()?;
    path.file_name().map(|s| s.to_string_lossy().into_owned())
}

/// Best-effort: systemd unit (or cgroup leaf) for a PID, parsed from
/// `/proc/<pid>/cgroup`. Returns something like `app-flatpak-org.mozilla.firefox-1234`
/// or `firefox.service` when available.
fn proc_cgroup_unit(pid: u32) -> Option<String> {
    let contents = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?;
    // cgroup v2 has a single line `0::/user.slice/.../app-flatpak-....scope`
    // cgroup v1 has multiple lines; we still want the most specific leaf.
    let leaf = contents
        .lines()
        .filter_map(|l| l.rsplit_once('/').map(|(_, tail)| tail.to_string()))
        .filter(|s| !s.is_empty())
        .last()?;
    // Strip trailing `.scope` / `.service` decorations for readability but
    // keep them if the result would otherwise be empty.
    let trimmed = leaf
        .strip_suffix(".scope")
        .or_else(|| leaf.strip_suffix(".service"))
        .unwrap_or(&leaf);
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

/// Parse a `PipeWire:Interface:Port`.
///
/// A port with no `port.name` is dropped rather than given a placeholder: the
/// name is what makes an ordinal stable across reboots, and an ordinal derived
/// from anything else is a claim that will quietly stop being true.
fn parse_port(id: u32, obj: &Value) -> Option<PortInfo> {
    let props = obj.get("info")?.get("props")?;
    let node_id = props.get("node.id").and_then(prop_as_u32)?;
    let name = props.get("port.name").and_then(|v| v.as_str())?.to_string();
    if name.is_empty() {
        return None;
    }
    let direction = props
        .get("port.direction")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    Some(PortInfo {
        id,
        node_id,
        name,
        direction,
    })
}

fn parse_link(id: u32, obj: &Value) -> Option<PwLink> {
    let info = obj.get("info")?;

    let output_node = info.get("output-node-id").and_then(|v| v.as_u64())? as u32;
    let output_port = info.get("output-port-id").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
    let input_node = info.get("input-node-id").and_then(|v| v.as_u64())? as u32;
    let input_port = info.get("input-port-id").and_then(|v| v.as_u64()).unwrap_or(0) as u32;

    Some(PwLink {
        link_id: id,
        output_node,
        output_port,
        input_node,
        input_port,
    })
}

/// Detect new links since last snapshot by comparing link IDs.
pub fn diff_links(
    old_link_ids: &HashSet<u32>,
    new_snapshot: &GraphSnapshot,
) -> Vec<PwLink> {
    new_snapshot
        .links
        .iter()
        .filter(|link| !old_link_ids.contains(&link.link_id))
        .cloned()
        .collect()
}

#[cfg(test)]
mod graph_state_tests {
    use super::*;
    use serde_json::json;

    fn node(id: u32, class: &str, name: &str) -> Value {
        json!({
            "id": id,
            "type": "PipeWire:Interface:Node",
            "info": { "props": {
                "media.class": class,
                "node.name": name,
                "application.name": name,
                "application.process.id": 1234
            }}
        })
    }

    fn link(id: u32, out_node: u32, out_port: u32, in_node: u32, in_port: u32) -> Value {
        json!({
            "id": id,
            "type": "PipeWire:Interface:Link",
            "info": {
                "output-node-id": out_node,
                "output-port-id": out_port,
                "input-node-id": in_node,
                "input-port-id": in_port,
                "state": "active"
            }
        })
    }

    /// A removal is `"info": null` and nothing else. Miss it and the object
    /// lives forever — a link that never releases, so a while_in_use session
    /// that never ends.
    fn removal(id: u32, kind: &str) -> Value {
        json!({ "id": id, "type": format!("PipeWire:Interface:{kind}"), "info": null })
    }

    #[test]
    fn block_zero_seeds_the_whole_graph() {
        let mut g = GraphState::new();
        let new = g.apply_block(&[
            node(10, "Audio/Source", "mic"),
            node(20, "Stream/Input/Audio", "firefox"),
            link(30, 10, 11, 20, 21),
        ]);
        assert_eq!(g.counts(), (2, 0, 1));
        assert_eq!(new, vec![30], "the seed's links are new — nothing was known before");
    }

    /// THE test for the removal signal. Fails against any implementation that
    /// parses first and never checks for null.
    #[test]
    fn a_removal_block_deletes_the_object() {
        let mut g = GraphState::new();
        g.apply_block(&[node(10, "Audio/Source", "mic"), link(30, 10, 11, 20, 21)]);
        assert_eq!(g.counts(), (1, 0, 1));

        g.apply_block(&[removal(30, "Link")]);
        assert_eq!(g.counts().2, 0, "the link must be gone");
        assert!(!g.link_ids().contains(&30));

        g.apply_block(&[removal(10, "Node")]);
        assert_eq!(g.counts().0, 0, "the node must be gone");
    }

    /// A link emits several blocks as it negotiates. Each is an UPDATE, not a
    /// new access — re-reporting it would re-prompt for a decision already made.
    #[test]
    fn an_update_block_replaces_and_is_not_new() {
        let mut g = GraphState::new();
        let first = g.apply_block(&[link(30, 10, 11, 20, 21)]);
        assert_eq!(first, vec![30]);

        let again = g.apply_block(&[link(30, 10, 11, 20, 21)]);
        assert!(again.is_empty(), "a state change is not a new link: {again:?}");
        assert_eq!(g.counts().2, 1, "and must not duplicate");
    }

    /// New link ids come only from the block just applied. Anything else means
    /// every block re-reports the whole graph.
    #[test]
    fn new_link_ids_come_only_from_the_applied_block() {
        let mut g = GraphState::new();
        g.apply_block(&[link(30, 10, 11, 20, 21)]);
        let second = g.apply_block(&[link(31, 12, 13, 22, 23)]);
        assert_eq!(second, vec![31], "only the link in THIS block");
    }

    /// Re-seeding after a monitor respawn must not carry pre-restart ids.
    /// PipeWire ids are not stable across a server restart, so a merged graph
    /// holds dead ids that a new object can later reuse — blocker b2.
    #[test]
    fn a_respawn_rebuilds_rather_than_merges() {
        let mut g = GraphState::new();
        g.apply_block(&[node(10, "Audio/Source", "mic"), link(30, 10, 11, 20, 21)]);

        g.clear();
        assert_eq!(g.counts(), (0, 0, 0), "clear must forget everything");

        let new = g.apply_block(&[link(30, 99, 98, 97, 96)]);
        assert_eq!(
            new,
            vec![30],
            "after a rebuild the same id is a NEW link, not a known one"
        );
        assert_eq!(g.counts().2, 1);
    }

    /// A client's props must survive into later blocks: a Node can arrive long
    /// after the Client it takes its identity from.
    #[test]
    fn client_props_persist_across_blocks() {
        let mut g = GraphState::new();
        g.apply_block(&[json!({
            "id": 5,
            "type": "PipeWire:Interface:Client",
            "info": { "props": { "application.name": "Firefox" } }
        })]);
        g.apply_block(&[json!({
            "id": 10,
            "type": "PipeWire:Interface:Node",
            "info": { "props": { "media.class": "Stream/Input/Audio", "client.id": 5 } }
        })]);
        let snap = g.snapshot();
        let n = snap.nodes.get(&10).expect("node applied");
        assert_eq!(
            n.app_name, "Firefox",
            "the node must resolve its client from an EARLIER block"
        );
    }

    /// The snapshot the rest of the daemon consumes must reflect removals, or
    /// the prune step reads a stale set and a session never expires.
    #[test]
    fn the_snapshot_reflects_removals() {
        let mut g = GraphState::new();
        g.apply_block(&[link(30, 10, 11, 20, 21), link(31, 12, 13, 22, 23)]);
        assert_eq!(g.snapshot().links.len(), 2);

        g.apply_block(&[removal(30, "Link")]);
        let snap = g.snapshot();
        assert_eq!(snap.links.len(), 1);
        assert_eq!(snap.links[0].link_id, 31);
    }
}

// ══════════════════════════════════════════════════════════════════════
// The monitor stream
// ══════════════════════════════════════════════════════════════════════

/// Split a byte stream of concatenated JSON arrays into whole blocks.
///
/// `pw-dump --monitor` writes one pretty-printed array per change, with no
/// framing between them, so a reader has to find the boundaries itself. Depth
/// counting on `[`/`]` is enough because the top level is always an array —
/// but ONLY if brackets inside string literals are ignored, which is why this
/// tracks quotes and escapes rather than counting bare bytes.
///
/// A node name can legitimately contain a bracket: `alsa_output.pci-0000_00_1f.3`
/// does not, but `application.name` is arbitrary text an app chooses, and a
/// single `[` in it would desynchronise a naive counter for the rest of the
/// process's life.
#[derive(Default)]
pub struct BlockSplitter {
    buf: String,
    depth: i32,
    in_string: bool,
    escaped: bool,
}

impl BlockSplitter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed a chunk; get back every COMPLETE block it finished.
    pub fn feed(&mut self, chunk: &str) -> Vec<Vec<Value>> {
        let mut out = Vec::new();
        for ch in chunk.chars() {
            self.buf.push(ch);
            if self.escaped {
                self.escaped = false;
                continue;
            }
            match ch {
                '\\' if self.in_string => self.escaped = true,
                '"' => self.in_string = !self.in_string,
                '[' if !self.in_string => self.depth += 1,
                ']' if !self.in_string => {
                    self.depth -= 1;
                    if self.depth == 0 {
                        let text = std::mem::take(&mut self.buf);
                        match serde_json::from_str::<Vec<Value>>(text.trim()) {
                            Ok(objs) => out.push(objs),
                            // A block we cannot parse is dropped, loudly. It
                            // must not poison the buffer for every block after
                            // it, which is what returning early would do.
                            Err(e) => warn!("Unparseable monitor block dropped: {}", e),
                        }
                    }
                }
                _ => {}
            }
        }
        out
    }
}

/// One update from the monitor: the graph as it now stands, plus the links
/// that are new in this update.
pub struct GraphUpdate {
    pub snapshot: GraphSnapshot,
    pub new_link_ids: Vec<u32>,
    pub link_ids: HashSet<u32>,
    pub node_ids: HashSet<u32>,
}

/// Run `pw-dump --monitor` and call `on_update` for every block it emits.
///
/// # Why this is a supervisor and not a child process
///
/// **`pw-dump --monitor` dies when PipeWire restarts, and exits 0.** Measured
/// 2026-09-01: `systemctl --user restart pipewire wireplumber pipewire-pulse`
/// and the process was gone with status 0. A clean exit is indistinguishable
/// from success, so a bare child would leave the daemon permanently blind
/// while every status surface reported healthy — blocker b5's exact shape.
///
/// The polling design this replaces was immune, because it respawned `pw-dump`
/// every tick. That resilience is being given up deliberately and has to be
/// rebuilt here.
///
/// Three rules follow:
///
/// * **Any exit is an anomaly.** Including 0. The monitor is meant to run for
///   the life of the daemon, so it terminating is always worth a log line.
/// * **Respawn re-seeds, never merges.** `GraphState::clear()` first — see its
///   doc comment for why a merged graph is blocker b2 waiting to happen.
/// * **Silence IS health.** There is deliberately no read timeout. A watchdog
///   here fired 308 times in 8 hours on a working system (2026-09-06): on an
///   idle desktop `pw-dump --monitor` emits its seed burst and then says
///   nothing at all — an 83.7 s gap was measured directly, and a quieter
///   machine exceeds any bound worth setting. Killing a healthy child on a
///   timer is not free: a respawn re-seeds, and a re-seed re-reports every
///   existing link as new (see `apply_block`), so a periodic watchdog turns
///   every live mic or monitor link into a fresh access on a timer. EOF and a
///   read error already cover the failure this supervisor exists for — a dead
///   child cannot stay silent, it closes the pipe.
pub async fn run_monitor<F>(backoff: std::time::Duration, mut on_update: F)
where
    F: FnMut(GraphUpdate),
{
    use tokio::io::{AsyncBufReadExt, BufReader};

    info!("Starting the PipeWire graph monitor (`pw-dump --monitor`)");
    loop {
        let mut child = match Command::new("pw-dump")
            .arg("--monitor")
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .spawn()
        {
            Ok(c) => c,
            Err(e) => {
                warn!("Could not start `pw-dump --monitor`: {e}. Retrying.");
                tokio::time::sleep(backoff).await;
                continue;
            }
        };

        let stdout = match child.stdout.take() {
            Some(s) => s,
            None => {
                warn!("`pw-dump --monitor` gave no stdout. Retrying.");
                tokio::time::sleep(backoff).await;
                continue;
            }
        };

        let mut graph = GraphState::new();
        let mut splitter = BlockSplitter::new();
        let mut reader = BufReader::new(stdout);
        let mut line = String::new();
        let mut blocks_seen: u64 = 0;

        loop {
            line.clear();
            let read = reader.read_line(&mut line).await;

            match read {
                Ok(0) => {
                    // EOF. THE case this supervisor exists for.
                    let status = child.wait().await;
                    warn!(
                        "`pw-dump --monitor` exited ({:?}) after {} block(s). This is \
                         never normal — PipeWire probably restarted. Re-seeding.",
                        status.map(|s| s.code()).unwrap_or(None),
                        blocks_seen
                    );
                    break;
                }
                Err(e) => {
                    warn!("Error reading from `pw-dump --monitor`: {e}. Re-seeding.");
                    let _ = child.kill().await;
                    break;
                }
                Ok(_) => {}
            }

            for objects in splitter.feed(&line) {
                let new_link_ids = graph.apply_block(&objects);
                blocks_seen += 1;
                if blocks_seen == 1 {
                    let (n, p, l) = graph.counts();
                    info!("PipeWire graph seeded: {n} nodes, {p} ports, {l} links");
                }
                on_update(GraphUpdate {
                    snapshot: graph.snapshot(),
                    new_link_ids,
                    link_ids: graph.link_ids(),
                    node_ids: graph.node_ids(),
                });
            }
        }

        tokio::time::sleep(backoff).await;
    }
}

#[cfg(test)]
mod splitter_tests {
    use super::*;

    #[test]
    fn splits_two_concatenated_blocks() {
        let mut s = BlockSplitter::new();
        let out = s.feed(r#"[{"id":1}]  [{"id":2}]"#);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0][0]["id"], 1);
        assert_eq!(out[1][0]["id"], 2);
    }

    #[test]
    fn a_block_split_across_chunks_is_reassembled() {
        let mut s = BlockSplitter::new();
        assert!(s.feed(r#"[{"id":"#).is_empty(), "incomplete: emit nothing");
        assert!(s.feed("1,").is_empty());
        let out = s.feed(r#""t":"x"}]"#);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0][0]["t"], "x");
    }

    /// THE subtle one, and the first version of this test was WORTHLESS.
    ///
    /// It used `"Firefox [pipewire-pulse]"`, where the brackets are BALANCED —
    /// a naive counter's depth returns to zero in the same place, so it parsed
    /// that correctly and the test passed with the bug fully present. Verified
    /// by stripping the string-awareness guards and watching it stay green.
    ///
    /// The hazard is an UNBALANCED bracket. `application.name` is arbitrary
    /// text an app chooses, so a lone `]` truncates the block, and a lone `[`
    /// swallows the rest of the stream — the daemon goes blind for the life of
    /// the process and nothing says so.
    #[test]
    fn an_unbalanced_bracket_in_a_string_does_not_split_the_block() {
        let mut s = BlockSplitter::new();
        let out = s.feed(r#"[{"name":"weird ] name"}] [{"id":7}]"#);
        assert_eq!(out.len(), 2, "a lone ] inside a string must not end the block");
        assert_eq!(out[0][0]["name"], "weird ] name");
        assert_eq!(out[1][0]["id"], 7);
    }

    /// The other direction: a lone `[` inside a string. A naive counter never
    /// returns to depth zero again and emits NOTHING, ever.
    #[test]
    fn a_lone_open_bracket_in_a_string_does_not_swallow_the_stream() {
        let mut s = BlockSplitter::new();
        let out = s.feed(r#"[{"name":"weird [ name"}] [{"id":7}]"#);
        assert_eq!(out.len(), 2, "the stream must keep flowing: {out:?}");
        assert_eq!(out[1][0]["id"], 7);
    }

    /// Balanced brackets are the COMMON case and must still work — this is the
    /// real `application.name` on this machine.
    #[test]
    fn a_balanced_bracket_pair_in_a_string_is_fine() {
        let mut s = BlockSplitter::new();
        let out = s.feed(r#"[{"name":"Firefox [pipewire-pulse]"}]"#);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0][0]["name"], "Firefox [pipewire-pulse]");
    }

    /// And an ESCAPED quote must not be read as ending the string, or the
    /// brackets after it are counted while "inside" one.
    #[test]
    fn an_escaped_quote_does_not_end_the_string() {
        let mut s = BlockSplitter::new();
        let out = s.feed(r#"[{"name":"say \"hi\" [x]"}]"#);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0][0]["name"], r#"say "hi" [x]"#);
    }

    /// A malformed block is dropped without poisoning the buffer. Returning
    /// early instead would mean one bad block blinds the daemon forever.
    #[test]
    fn an_unparseable_block_does_not_break_the_next_one() {
        let mut s = BlockSplitter::new();
        let out = s.feed(r#"[{bad}] [{"id":7}]"#);
        assert_eq!(out.len(), 1, "the good block still arrives");
        assert_eq!(out[0][0]["id"], 7);
    }

    /// Real output from this machine: nested arrays inside an object.
    #[test]
    fn nested_arrays_do_not_end_the_block_early() {
        let mut s = BlockSplitter::new();
        let out = s.feed(r#"[{"id":1,"permissions":["r","x","m"],"info":{"c":[1,2]}}]"#);
        assert_eq!(out.len(), 1, "inner arrays are not block boundaries");
        assert_eq!(out[0][0]["id"], 1);
    }
}

#[cfg(test)]
mod respawn_tests {
    use super::*;

    /// Why this test exists, and why it is not a test of a timeout.
    ///
    /// A watchdog on the read killed a HEALTHY `pw-dump --monitor` every 90 s
    /// (308 times in 8 hours, 2026-09-06) because silence from that stream is
    /// the normal idle state. The log noise was the symptom; THIS is the harm,
    /// and it is what must never come back.
    ///
    /// A respawn starts a fresh `GraphState` — deliberately, because merging
    /// across a PipeWire restart is blocker b2 waiting to happen. The cost of
    /// that correct choice is that every link present after a re-seed is
    /// reported as new, and `main.rs` feeds exactly those to
    /// `classify_link()`. So a re-seed is a re-enforcement of the entire
    /// graph. That is tolerable when it happens on a real PipeWire restart;
    /// on a 90-second timer it turned every live mic or monitor link into a
    /// fresh access, forever.
    ///
    /// This pins the multiplier. If a future change makes a re-seed cheap to
    /// trigger again, the blast radius is measured here rather than
    /// rediscovered in a journal.
    #[test]
    fn a_reseed_reports_every_existing_link_as_new() {
        let block = serde_json::json!([
            {"id": 10, "type": "PipeWire:Interface:Link",
             "info": {"output-node-id": 1, "output-port-id": 2,
                      "input-node-id": 3, "input-port-id": 4}},
            {"id": 11, "type": "PipeWire:Interface:Link",
             "info": {"output-node-id": 5, "output-port-id": 6,
                      "input-node-id": 7, "input-port-id": 8}},
        ]);
        let objects = block.as_array().unwrap().clone();

        let mut graph = GraphState::new();
        let first = graph.apply_block(&objects);
        assert_eq!(first.len(), 2, "the seed reports both links as new");

        // Same block again on the SAME state: a link already known is an
        // update, never a new access. This is what stops a chatty stream from
        // re-prompting.
        let repeat = graph.apply_block(&objects);
        assert!(
            repeat.is_empty(),
            "a known link must not be re-reported as new: {repeat:?}"
        );

        // A respawn. `run_monitor` builds a fresh GraphState per child, so
        // this is exactly what a restart does to link identity.
        let mut after_respawn = GraphState::new();
        let reseeded = after_respawn.apply_block(&objects);
        assert_eq!(
            reseeded.len(),
            2,
            "a re-seed re-reports EVERY existing link as new — so a re-seed \
             must never be triggered on a timer, only by the stream actually \
             ending. See run_monitor: there is no read timeout."
        );
    }
}
