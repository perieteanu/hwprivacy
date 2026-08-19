use anyhow::Context;
use clap::{Parser, Subcommand};
use hwprivacy_common::dbus_interface::HwPrivacyProxy;

#[derive(Parser)]
#[command(name = "hwprivacy-ctl", about = "HWPrivacy - Hardware Permission Manager")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Show daemon status
    Status,
    /// List discovered protected devices
    Devices,
    /// Manage per-app rules
    Rules {
        #[command(subcommand)]
        action: RulesAction,
    },
    /// Show active streams
    Streams {
        /// Filter by app name
        #[arg(long)]
        app: Option<String>,
    },
    /// Show recent events
    Log {
        /// Number of events to show
        #[arg(long, default_value = "20")]
        last: u32,
    },
    /// Who has been denied, how often, and since when (survives restarts)
    Offenders,
    /// Emergency: deny everything immediately
    BlockAll,
    /// Restore to saved rules
    UnblockAll,
}

#[derive(Subcommand)]
enum RulesAction {
    /// List all rules
    List,
    /// Set a rule: <app> <device> <permission>
    Set {
        /// App name (e.g., "firefox")
        app: String,
        /// Device: mic, cam, monitor
        device: String,
        /// Permission: allow, ask_each, while_in_use, ask, deny
        permission: String,
    },
    /// Remove all rules for an app
    Remove {
        /// App name
        app: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let connection = zbus::Connection::session()
        .await
        .context("Failed to connect to session D-Bus. Is the daemon running?")?;

    let proxy = HwPrivacyProxy::new(&connection)
        .await
        .context("Failed to create D-Bus proxy. Is hwprivacy-daemon running?")?;

    match cli.command {
        Commands::Status => {
            let (running, devices, rules, blocked, streams) = proxy.get_status().await?;
            println!("HWPrivacy Daemon");
            println!("  Running:          {}", if running { "yes" } else { "no" });
            println!("  Guarded devices:  {}", devices);
            println!("  Active rules:     {}", rules);
            println!("  Blocked attempts: {}", blocked);
            println!("  Active streams:   {}", streams);

            // Kernel layer. Reported separately and always — "not connected"
            // is real information, not an absence worth hiding.
            match proxy.get_kernel_status().await {
                Ok((connected, enforcing, allowed, unresolved, err)) => {
                    println!();
                    println!("Kernel layer (eBPF LSM)");
                    if connected {
                        println!("  Connected:        yes");
                        println!(
                            "  Camera enforced:  {}",
                            if enforcing { "yes — non-allowlisted apps get EPERM" } else { "no (observing)" }
                        );
                        println!("  Allowed binaries: {}", allowed);
                        if unresolved > 0 {
                            println!(
                                "  UNUSABLE entries: {}  <- those apps are being denied the camera",
                                unresolved
                            );
                        }
                    } else {
                        // "unknown", NOT "no".
                        //
                        // A disconnected daemon cannot see the kernel state, and
                        // reporting its own default as fact is how this line came
                        // to say "NOT blocked" on 2026-08-19 while the camera was
                        // demonstrably blocked — 3/3 opens denied by a running
                        // hwprivacy-lsm.service that the daemon simply could not
                        // reach. Claiming protection that is absent and denying
                        // protection that is present are the same class of bug,
                        // and both destroy trust in the readout.
                        println!("  Connected:        no");
                        println!(
                            "  Camera enforced:  UNKNOWN — the daemon cannot reach the kernel helper,"
                        );
                        println!(
                            "                    so it cannot see whether the camera is enforced."
                        );
                        println!("                    Check directly with:");
                        println!("                      systemctl is-active hwprivacy-lsm");
                        println!(
                            "                    If that unit is active, the camera IS being enforced"
                        );
                        println!(
                            "                    from /var/lib/hwprivacy/policy regardless of this line."
                        );
                    }
                    if !err.is_empty() {
                        println!("  Last error:       {}", err);
                    }
                }
                Err(_) => {
                    println!();
                    println!("Kernel layer (eBPF LSM)");
                    println!("  Connected:        unknown — daemon predates this feature");
                }
            }
        }

        Commands::Devices => {
            let devices = proxy.get_devices().await?;
            let kernel = proxy.get_kernel_status().await.ok();

            if devices.is_empty() {
                println!("No protected devices discovered.");
            } else {
                println!("{:<12} {:<45} {:<30} {}", "Category", "Node", "Description", "Guard");
                println!("{}", "-".repeat(95));
                for (cat, node, desc, guarded) in &devices {
                    println!(
                        "{:<12} {:<45} {:<30} {}",
                        cat,
                        node,
                        desc,
                        if *guarded { "ON" } else { "OFF" }
                    );
                }
            }

            // The kernel layer guards a device the PipeWire list cannot show.
            //
            // This row exists because of what happened on 2026-08-19: with
            // wireplumber denied the camera, PipeWire had no Video/Source node
            // at all, so this table listed three devices and NO camera —
            // while the camera was in fact the single most strongly protected
            // device on the machine. The tool was silent about it precisely
            // BECAUSE protection was working.
            //
            // Listing devices by what PipeWire happens to expose describes the
            // monitoring substrate, not the hardware. Say what is guarded.
            if let Some((connected, enforcing, allowed, unresolved, _)) = kernel {
                println!();
                println!("Kernel layer (eBPF LSM) — guards device nodes directly, not via PipeWire");
                println!("{}", "-".repeat(95));
                if connected && enforcing {
                    println!(
                        "{:<12} {:<45} {:<30} {}",
                        "camera", "/dev/video* (by executable inode)",
                        format!("{allowed} executable(s) allowed"), "ON"
                    );
                    if unresolved > 0 {
                        println!(
                            "{:<12} {:<45} {:<30} {}",
                            "", "", format!("{unresolved} rule(s) UNUSABLE — those apps are denied"), ""
                        );
                    }
                } else if connected {
                    println!(
                        "{:<12} {:<45} {:<30} {}",
                        "camera", "/dev/video*", "helper connected, observing only", "OFF"
                    );
                } else {
                    println!("  Not connected — this daemon cannot see the kernel layer.");
                    println!("  It may still be enforcing. Check: systemctl is-active hwprivacy-lsm");
                }
                println!();
                println!("A camera absent from the PipeWire list above is not unprotected —");
                println!("it may mean wireplumber was denied, so no PipeWire node exists at all.");
            }
        }

        Commands::Rules { action } => match action {
            RulesAction::List => {
                let rules = proxy.get_rules().await?;
                if rules.is_empty() {
                    println!("No rules configured. Default policy: deny/ask.");
                } else {
                    // Group by app
                    let mut current_app = String::new();
                    println!("{:<25} {:<12} {}", "App", "Device", "Permission");
                    println!("{}", "-".repeat(50));
                    for (app, device, perm) in &rules {
                        if *app != current_app {
                            if !current_app.is_empty() {
                                println!();
                            }
                            current_app = app.clone();
                        }
                        println!("{:<25} {:<12} {}", app, device, perm);
                    }
                }
            }
            RulesAction::Set { app, device, permission } => {
                let ok = proxy.set_rule(&app, &device, &permission).await?;
                if ok {
                    println!("Rule set: {} → {} = {}", app, device, permission);
                } else {
                    eprintln!("Failed to set rule. Check device ({}) and permission ({}) values.", device, permission);
                    std::process::exit(2);
                }
            }
            RulesAction::Remove { app } => {
                let ok = proxy.remove_rule(&app).await?;
                if ok {
                    println!("Rules removed for: {}", app);
                } else {
                    println!("No rules found for: {}", app);
                }
            }
        },

        Commands::Streams { app } => {
            let streams = proxy.get_active_streams().await?;
            let filtered: Vec<_> = if let Some(ref filter) = app {
                streams.iter().filter(|s| s.0.contains(filter.as_str())).collect()
            } else {
                streams.iter().collect()
            };

            if filtered.is_empty() {
                println!("No active streams.");
            } else {
                println!("{:<20} {:<7} {:<12} {:<25} {:<15} {:<12} {}", "App", "PID", "Device", "Node", "Media", "Permission", "Active");
                println!("{}", "-".repeat(100));
                for (app, pid, dev, node, media, perm, active) in &filtered {
                    println!(
                        "{:<20} {:<7} {:<12} {:<25} {:<15} {:<12} {}",
                        app,
                        pid,
                        dev,
                        &node[..node.len().min(25)],
                        &media[..media.len().min(15)],
                        perm,
                        if *active { "yes" } else { "no" }
                    );
                }
            }
        }

        Commands::Log { last } => {
            let events = proxy.get_events(last).await?;
            if events.is_empty() {
                println!("No recent events.");
            } else {
                // 19 wide: timestamps carry a full date now (g4), not just
                // "%H:%M:%S". A 10-wide column silently truncated them.
                println!("{:<19} {:<20} {:<12} {}", "Time", "App", "Device", "Action");
                println!("{}", "-".repeat(64));
                for (ts, app, dev, action) in &events {
                    println!("{:<19} {:<20} {:<12} {}", ts, app, dev, action);
                }
            }
        }

        Commands::Offenders => {
            let rows = proxy.get_offenders().await?;
            if rows.is_empty() {
                println!("Nothing has been denied yet.");
            } else {
                println!(
                    "{:<44} {:<11} {:<9} {:>6}  {:<19} {}",
                    "IDENTITY", "DEVICE", "SOURCE", "DENIED", "FIRST", "LAST"
                );
                println!("{}", "-".repeat(104));
                for (identity, device, source, denied, first, last) in &rows {
                    println!(
                        "{:<44} {:<11} {:<9} {:>6}  {:<19} {}",
                        identity, device, source, denied, first, last
                    );
                }
                println!();
                // Said plainly rather than left for the reader to discover.
                // A table that looks complete but is not is worse than no
                // table: it would quietly under-report anything that happened
                // while the session was down.
                println!(
                    "Counted only while the user daemon was running. Events from before\n\
                     login are in the kernel helper's journal instead:\n\
                     \n    journalctl -u hwprivacy-lsm --since '3 days ago'\n"
                );
                println!(
                    "'kernel' rows are keyed on the executable path and are stable across\n\
                     restarts. 'pipewire' rows are keyed on a name the application declares\n\
                     about itself, which is weaker — treat them as a hint, not an identity."
                );
            }
        }

        Commands::BlockAll => {
            proxy.block_all().await?;
            println!("EMERGENCY: All device access blocked!");
        }

        Commands::UnblockAll => {
            proxy.unblock_all().await?;
            println!("Block-all mode disabled. Saved rules restored.");
        }
    }

    Ok(())
}
