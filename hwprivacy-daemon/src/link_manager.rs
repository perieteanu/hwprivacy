use anyhow::{Context, Result};
use tokio::process::Command;
use tracing::{info, warn};

/// Destroy a PipeWire link by its link ID.
pub async fn destroy_link(link_id: u32) -> Result<()> {
    let output = Command::new("pw-link")
        .args(["--disconnect", &link_id.to_string()])
        .output()
        .await
        .context("Failed to run pw-link --disconnect")?;

    if !output.status.success() {
        // pw-link might not support --disconnect; try pw-cli
        let output2 = Command::new("pw-cli")
            .args(["destroy", &link_id.to_string()])
            .output()
            .await
            .context("Failed to run pw-cli destroy")?;

        if !output2.status.success() {
            let stderr = String::from_utf8_lossy(&output2.stderr);
            warn!("Failed to destroy link {}: {}", link_id, stderr);
            anyhow::bail!("Failed to destroy link {}: {}", link_id, stderr);
        }
    }

    info!("Destroyed PipeWire link {}", link_id);
    Ok(())
}

/// Destroy every link in a coalesced group.
///
/// Exists because b3's monitor fix coalesces the *prompt* for a sink's
/// `monitor_FL`/`monitor_FR` pair. Coalescing the prompt must never coalesce
/// the enforcement: if only the representative link were destroyed, one channel
/// would keep flowing while the popup said BLOCKED — a worse bug than the
/// double prompt it replaces.
pub async fn destroy_links(link_ids: &[u32]) {
    for id in link_ids {
        if let Err(e) = destroy_link(*id).await {
            warn!("Failed to destroy link {}: {}", id, e);
        }
    }
}

/// Destroy all links connected to a specific node (by node ID).
pub async fn destroy_all_links_to_node(node_id: u32, graph: &super::pipewire_monitor::GraphSnapshot) -> Result<u32> {
    let mut destroyed = 0;

    for link in &graph.links {
        // Links where this node is the source (output) or destination (input)
        if link.output_node == node_id || link.input_node == node_id {
            if let Ok(()) = destroy_link(link.link_id).await {
                destroyed += 1;
            }
        }
    }

    Ok(destroyed)
}
