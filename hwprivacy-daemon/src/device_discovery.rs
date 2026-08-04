use anyhow::{Context, Result};
use hwprivacy_common::device::{DeviceCategory, ProtectedDevice};
use serde_json::Value;
use tokio::process::Command;
use tracing::{debug, info, warn};

/// Discover all protected devices from the PipeWire graph via pw-dump.
pub async fn discover_devices() -> Result<Vec<ProtectedDevice>> {
    let output = Command::new("pw-dump")
        .output()
        .await
        .context("Failed to run pw-dump. Is PipeWire running?")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("pw-dump failed: {}", stderr);
    }

    let json: Value = serde_json::from_slice(&output.stdout)
        .context("Failed to parse pw-dump JSON")?;

    let nodes = json.as_array().context("pw-dump output is not an array")?;
    let mut devices = Vec::new();

    for node in nodes {
        let node_type = node.get("type").and_then(|t| t.as_str()).unwrap_or("");
        if node_type != "PipeWire:Interface:Node" {
            continue;
        }

        let info = match node.get("info") {
            Some(i) => i,
            None => continue,
        };
        let props = match info.get("props") {
            Some(p) => p,
            None => continue,
        };

        let media_class = props
            .get("media.class")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        let node_name = props
            .get("node.name")
            .and_then(|v| v.as_str())
            .unwrap_or("");

        let description = props
            .get("node.description")
            .or_else(|| props.get("node.nick"))
            .and_then(|v| v.as_str())
            .unwrap_or(node_name);

        let object_serial = node
            .get("id")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;

        let category = classify_node(media_class, node_name);

        if let Some(cat) = category {
            debug!(
                "Discovered device: {} ({}) - {:?} [serial={}]",
                description, node_name, cat, object_serial
            );
            devices.push(ProtectedDevice {
                category: cat,
                node_name: node_name.to_string(),
                description: description.to_string(),
                object_serial,
                guarded: true, // default: guard everything
            });
        }
    }

    info!("Discovered {} protected devices", devices.len());
    for dev in &devices {
        info!("  {:?}: {} ({})", dev.category, dev.description, dev.node_name);
    }

    Ok(devices)
}

/// Classify a PipeWire node as a protected device category (or None if not protected).
fn classify_node(media_class: &str, node_name: &str) -> Option<DeviceCategory> {
    match media_class {
        // Audio capture sources = microphones
        "Audio/Source" => {
            if node_name.contains(".monitor") {
                // Explicit monitor source node (some setups expose these)
                Some(DeviceCategory::Monitor)
            } else {
                Some(DeviceCategory::Microphone)
            }
        }

        // Video capture sources = cameras
        "Video/Source" => Some(DeviceCategory::Camera),

        // Audio sinks have an implicit monitor source.
        // When a link goes FROM an Audio/Sink TO a Stream/Input/Audio,
        // that's a monitor tap (app recording what's playing).
        // We register sinks as Monitor devices to catch this pattern.
        "Audio/Sink" => Some(DeviceCategory::Monitor),

        _ => None,
    }
}

/// Re-scan: called periodically or on hotplug to discover new devices.
pub async fn rescan_devices(existing: &[ProtectedDevice]) -> Result<Vec<ProtectedDevice>> {
    let discovered = discover_devices().await?;

    // Merge: keep existing guarded state for known devices, add new ones
    let mut merged = Vec::new();
    for dev in &discovered {
        let guarded = existing
            .iter()
            .find(|e| e.node_name == dev.node_name)
            .map(|e| e.guarded)
            .unwrap_or(true); // new devices default to guarded

        merged.push(ProtectedDevice {
            guarded,
            ..dev.clone()
        });
    }

    Ok(merged)
}
