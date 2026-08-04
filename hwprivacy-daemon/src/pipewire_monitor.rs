use anyhow::{Context, Result};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use tokio::process::Command;
use tracing::{debug, trace};

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
            "PipeWire:Interface:Link" => {
                if let Some(link) = parse_link(id, obj) {
                    snapshot.links.push(link);
                }
            }
            _ => {}
        }
    }

    trace!(
        "Graph snapshot: {} nodes, {} links",
        snapshot.nodes.len(),
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
